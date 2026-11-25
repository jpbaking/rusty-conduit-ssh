//! Helpers for this crate's unit tests, built only on the public `rusty-conduit-engine` API
//! (the engine's own test helpers are private to it): a captured access logger, a direct
//! dialer, an echo server, a test CA, a TLS origin, and a MITM-trusting TLS client.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::http::mitm_tunnel::client_config_with_roots;
use crate::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use crate::mitm::ca::CaMaterial;
use crate::mitm::crypto_provider;
use crate::mitm::signer::LeafSigner;
use crate::net::{DirectDialer, UpstreamDialer};

/// In-memory async writer capturing access-log output.
#[derive(Clone, Default)]
pub struct Buf(pub Arc<Mutex<Vec<u8>>>);

impl Buf {
    pub fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Wait (up to 5s) until at least `n` lines were logged.
    pub async fn wait_lines(&self, n: usize) -> Vec<String> {
        for _ in 0..500 {
            let lines = self.lines();
            if lines.len() >= n {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("expected {n} access log lines, got {:?}", self.lines());
    }
}

impl AsyncWrite for Buf {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub fn quiet_logger() -> Logger {
    Logger::with_writer(LogLevel::Quiet, Box::new(io::sink()))
}

/// Dialer for isolated tests: connects directly, without a tunnel.
pub fn direct_dialer() -> Arc<dyn UpstreamDialer> {
    Arc::new(DirectDialer::new())
}

/// An access logger (rusty-conduit-ssh schema) dumping text records into the returned buffer.
pub async fn capture_access() -> (AccessLogger, Buf) {
    let buf = Buf::default();
    let cfg = AccessLogConfig {
        format: LogFormat::Text,
        http_access_log: None,
        socks_log: None,
        dump_stdout: true,
        include_routing_fields: false,
    };
    let access = AccessLogger::start_with_stdout(cfg, Box::new(buf.clone()), quiet_logger())
        .await
        .unwrap();
    (access, buf)
}

/// Echo server on `bind` (e.g. `127.0.0.1:0`).
pub async fn spawn_echo(bind: &str) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Send `payload` through an established tunnel, half-close, and read everything back.
pub async fn echo_roundtrip(mut stream: TcpStream, payload: &[u8]) -> Vec<u8> {
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    out
}

/// A self-signed test CA.
pub struct TestCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
}

pub fn test_ca() -> TestCa {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Rusty Conduit SSH Unit Test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let cert = params.self_signed(&key).unwrap();
    TestCa {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().clone(),
    }
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// An HTTP/1.1 TLS origin on 127.0.0.1 (leaf for `localhost`, signed by its own CA) that
/// answers `hit <n> <method> <path> <body-len>`.
pub struct Origin {
    pub addr: SocketAddr,
    pub ca_der: CertificateDer<'static>,
}

pub async fn spawn_origin() -> Origin {
    let ca = test_ca();
    let material =
        CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
    let signer = LeafSigner::new(&material, Duration::from_secs(3600), crypto_provider()).unwrap();
    let leaf = signer
        .sign_at("localhost", OffsetDateTime::now_utc())
        .unwrap();
    let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf.certified)));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |req: Request<Incoming>| {
                    let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                    async move {
                        let method = req.method().to_string();
                        let path = req.uri().path().to_owned();
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                            "hit {n} {method} {path} {}",
                            body.len()
                        )))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Origin {
        addr,
        ca_der: ca.cert_der,
    }
}

/// Open an HTTP `CONNECT` tunnel to `target` through `proxy`.
pub async fn connect_through(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).await.unwrap();
    assert_eq!(status, "HTTP/1.1 200 Connection Established\r\n");
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
    }
    assert!(reader.buffer().is_empty());
    reader.into_inner()
}

/// TLS client trusting only `mitm_ca`.
pub async fn tls_client(
    stream: TcpStream,
    mitm_ca: &TestCa,
    sni: &str,
    alpn: &[&[u8]],
) -> io::Result<TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.add(mitm_ca.cert_der.clone()).unwrap();
    let mut cfg = client_config_with_roots(crypto_provider(), roots).unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(sni.to_string()).unwrap(), stream)
        .await
}
