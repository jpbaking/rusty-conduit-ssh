//! Shared integration-test harness: an in-process mock of the `ssh -D` SOCKS5 listener that
//! records every dial, a real [`Server`] wired through [`Socks5UpstreamDialer`], local origins,
//! protocol clients, and a mock `ssh` executable.
//!
//! The mock SOCKS5 server maps *every* domain to loopback. Tests use reserved `.test` names,
//! which cannot resolve through the OS, so a successful request proves the name was forwarded
//! as `ATYP=0x03` rather than resolved locally.

#![allow(dead_code)]

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

use rusty_conduit_ssh::build_engines;
use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::http::mitm_tunnel::client_config_with_roots;
use rusty_conduit_ssh::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use rusty_conduit_ssh::mitm::ca::CaMaterial;
use rusty_conduit_ssh::mitm::signer::LeafSigner;
use rusty_conduit_ssh::mitm::{crypto_provider, MitmState};
use rusty_conduit_ssh::net::{Socks5UpstreamDialer, TunnelState, UpstreamDialer};
use rusty_conduit_ssh::server::{ListenPlan, ProtocolHandlers, Server, ShutdownReport};
use rusty_conduit_ssh::EngineHandlers;

/// Upper bound for anything a test waits on.
pub const WAIT: Duration = Duration::from_secs(10);

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub fn quiet_logger() -> Logger {
    Logger::with_writer(LogLevel::Quiet, Box::new(io::sink()))
}

/// A fresh, empty, per-test temporary directory.
pub fn temp_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rcs-it-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Mock `ssh -D` SOCKS5 listener
// ---------------------------------------------------------------------------

/// One `CONNECT` received by [`MockSocks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dial {
    pub atyp: u8,
    pub host: String,
    pub port: u16,
}

impl Dial {
    pub fn new(atyp: u8, host: &str, port: u16) -> Self {
        Self {
            atyp,
            host: host.to_owned(),
            port,
        }
    }
}

/// In-process SOCKS5 server standing in for the `ssh -D` listener.
#[derive(Clone)]
pub struct MockSocks {
    pub addr: SocketAddr,
    dials: Arc<Mutex<Vec<Dial>>>,
    up: Arc<AtomicBool>,
}

impl MockSocks {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = Self {
            addr,
            dials: Arc::default(),
            up: Arc::new(AtomicBool::new(true)),
        };
        let server = mock.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                if !server.up.load(Ordering::SeqCst) {
                    drop(sock);
                    continue;
                }
                let dials = Arc::clone(&server.dials);
                tokio::spawn(async move {
                    let _ = serve_socks(sock, dials).await;
                });
            }
        });
        mock
    }

    /// While down, every connection is closed before the SOCKS greeting is answered, so the
    /// supervisor's readiness probe fails deterministically.
    pub fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
    }

    pub fn dials(&self) -> Vec<Dial> {
        self.dials.lock().unwrap().clone()
    }

    /// A production dialer pointed permanently at this listener.
    pub fn dialer(&self) -> Arc<dyn UpstreamDialer> {
        let (_tx, rx) = watch::channel(TunnelState::Ready(self.addr));
        Arc::new(Socks5UpstreamDialer::new(rx))
    }
}

async fn serve_socks(mut sock: TcpStream, dials: Arc<Mutex<Vec<Dial>>>) -> io::Result<()> {
    let mut greeting = [0u8; 2];
    sock.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    // Readiness probes disconnect here and are never recorded as dials.
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await?;
    let (host, ip) = match head[3] {
        ATYP_IPV4 => {
            let mut raw = [0u8; 4];
            sock.read_exact(&mut raw).await?;
            let ip = Ipv4Addr::from(raw);
            (ip.to_string(), IpAddr::V4(ip))
        }
        ATYP_IPV6 => {
            let mut raw = [0u8; 16];
            sock.read_exact(&mut raw).await?;
            let ip = Ipv6Addr::from(raw);
            (ip.to_string(), IpAddr::V6(ip))
        }
        ATYP_DOMAIN => {
            let len = sock.read_u8().await?;
            let mut raw = vec![0u8; usize::from(len)];
            sock.read_exact(&mut raw).await?;
            let name = String::from_utf8(raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            (name, IpAddr::V4(Ipv4Addr::LOCALHOST))
        }
        _ => {
            sock.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };
    let port = sock.read_u16().await?;
    dials.lock().unwrap().push(Dial {
        atyp: head[3],
        host,
        port,
    });

    let Ok(mut upstream) = TcpStream::connect((ip, port)).await else {
        sock.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    };
    sock.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Proxy harness
// ---------------------------------------------------------------------------

/// How to start a [`Proxy`].
pub struct ProxyOptions {
    pub plan: ListenPlan,
    /// Enables MITM, trusting this CA for upstream TLS.
    pub origin_ca: Option<CertificateDer<'static>>,
    pub block_web: bool,
    pub log_format: LogFormat,
}

impl ProxyOptions {
    /// Dedicated HTTP and SOCKS listeners on ephemeral ports.
    pub fn separate() -> Self {
        Self {
            plan: ListenPlan::Separate {
                http: Some("127.0.0.1:0".parse().unwrap()),
                socks: Some("127.0.0.1:0".parse().unwrap()),
            },
            origin_ca: None,
            block_web: false,
            log_format: LogFormat::Text,
        }
    }

    /// One multiplexed listener on an ephemeral port.
    pub fn multiplexed() -> Self {
        Self {
            plan: ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap()),
            ..Self::separate()
        }
    }

    pub fn with_mitm(mut self, origin_ca: CertificateDer<'static>) -> Self {
        self.origin_ca = Some(origin_ca);
        self
    }

    pub fn with_block_web(mut self) -> Self {
        self.block_web = true;
        self
    }
}

/// A running [`Server`] with real engines dialing through the supplied dialer.
pub struct Proxy {
    pub http: SocketAddr,
    pub socks: SocketAddr,
    pub mitm_ca: Option<CertificateDer<'static>>,
    pub state: Option<MitmState>,
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
    access: AccessLogger,
    http_log: PathBuf,
    socks_log: PathBuf,
    dir: PathBuf,
}

impl Proxy {
    pub async fn start(name: &str, opts: ProxyOptions, dialer: Arc<dyn UpstreamDialer>) -> Self {
        let dir = temp_dir(name);
        let (http_log, socks_log) = (dir.join("http.log"), dir.join("socks.log"));
        let mut cfg = Config {
            log_format: opts.log_format,
            http_access_log: Some(http_log.clone()),
            socks_log: Some(socks_log.clone()),
            socks_block_web_in_mitm: opts.block_web,
            ..Config::default()
        };

        let mut mitm_ca = None;
        let state = opts.origin_ca.map(|origin_ca| {
            let ca = test_ca("Rusty Conduit SSH Integration MITM CA");
            let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
            std::fs::write(&cert, &ca.cert_pem).unwrap();
            std::fs::write(&key, &ca.key_pem).unwrap();
            cfg.mitm_ca_cert = Some(cert);
            cfg.mitm_ca_key = Some(key);
            mitm_ca = Some(ca.cert_der.clone());

            let provider = crypto_provider();
            let mut roots = RootCertStore::empty();
            roots.add(origin_ca).unwrap();
            let upstream = client_config_with_roots(Arc::clone(&provider), roots).unwrap();
            MitmState::build(
                &cfg,
                &cfg.ca_source().unwrap(),
                provider,
                upstream,
                Arc::clone(&dialer),
            )
            .unwrap()
        });

        let logger = quiet_logger();
        let access = AccessLogger::start(
            AccessLogConfig::new(
                LogLevel::Info,
                cfg.log_format,
                cfg.http_access_log.clone(),
                cfg.socks_log.clone(),
            ),
            logger.clone(),
        )
        .await
        .unwrap();
        let (http, socks) = build_engines(&cfg, state.as_ref(), &access, &logger, dialer);
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
        let server = Server::bind(opts.plan, handlers, logger.clone())
            .await
            .unwrap();
        let http = server.local_http_addr().unwrap();
        let socks = server.local_socks_addr().unwrap();
        let token = server.shutdown_token();
        let reaper = state
            .as_ref()
            .map(|s| s.cache.spawn_reaper(token.clone(), logger));
        let run = tokio::spawn(server.run());
        Self {
            http,
            socks,
            mitm_ca,
            state,
            token,
            run,
            reaper,
            access,
            http_log,
            socks_log,
            dir,
        }
    }

    async fn wait_lines(&self, path: &Path, n: usize) -> Vec<String> {
        for _ in 0..500 {
            self.access.flush().await.unwrap();
            let lines = read_lines(path);
            if lines.len() >= n {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("expected {n} log lines, got {:?}", read_lines(path));
    }

    pub async fn http_lines(&self, n: usize) -> Vec<String> {
        self.wait_lines(&self.http_log, n).await
    }

    pub async fn socks_lines(&self, n: usize) -> Vec<String> {
        self.wait_lines(&self.socks_log, n).await
    }

    /// Cancel the server and require that every connection drained.
    pub async fn stop(self) {
        self.token.cancel();
        let report = tokio::time::timeout(WAIT, self.run)
            .await
            .expect("server did not stop")
            .unwrap();
        assert!(report.drained, "connections did not drain");
        if let Some(reaper) = self.reaper {
            reaper.await.unwrap();
        }
        self.access.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Local origins
// ---------------------------------------------------------------------------

/// Plain HTTP/1.1 origin answering `hit <n> <method> <path> <body-len>`.
pub struct HttpOrigin {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
}

pub async fn spawn_http_origin() -> HttpOrigin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let counter = Arc::clone(&counter);
                    async move { Ok::<_, Infallible>(origin_respond(req, &counter).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    });
    HttpOrigin { addr, hits }
}

async fn origin_respond(req: Request<Incoming>, counter: &AtomicUsize) -> Response<Full<Bytes>> {
    let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
    let mut seen: Vec<String> = req.headers().keys().map(ToString::to_string).collect();
    seen.sort();
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let version = format!("{:?}", req.version());
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    Response::builder()
        .header("cache-control", "public, max-age=3600")
        .header("x-seen", seen.join(","))
        .header("x-origin-host", host)
        .header("x-origin-version", version)
        .body(Full::new(Bytes::from(format!(
            "hit {n} {method} {path} {}",
            body.len()
        ))))
        .unwrap()
}

/// TCP upstream that optionally sends a banner, then echoes and counts received bytes.
pub struct Upstream {
    pub addr: SocketAddr,
    pub received: Arc<AtomicUsize>,
}

pub async fn spawn_upstream(bind: &str, banner: Option<&'static [u8]>) -> Option<Upstream> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().ok()?;
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                if let Some(b) = banner {
                    if sock.write_all(b).await.is_err() {
                        return;
                    }
                }
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            counter.fetch_add(n, Ordering::SeqCst);
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Some(Upstream { addr, received })
}

pub async fn spawn_echo() -> Upstream {
    spawn_upstream("127.0.0.1:0", None).await.unwrap()
}

/// A loopback port with nothing listening on it.
pub async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Ephemeral CAs and TLS origin
// ---------------------------------------------------------------------------

pub struct TestCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
}

pub fn test_ca(cn: &str) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(30);
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

/// HTTPS origin on loopback with a leaf for `host`, negotiating `h2` or `http/1.1`.
pub struct TlsOrigin {
    pub addr: SocketAddr,
    pub ca_der: CertificateDer<'static>,
    pub hits: Arc<AtomicUsize>,
}

pub async fn spawn_tls_origin(host: &str) -> TlsOrigin {
    let ca = test_ca("Rusty Conduit SSH Origin CA");
    let material =
        CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
    let signer = LeafSigner::new(&material, Duration::from_secs(3600), crypto_provider()).unwrap();
    let leaf = signer.sign_at(host, OffsetDateTime::now_utc()).unwrap();
    let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf.certified)));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let service = service_fn(move |req: Request<Incoming>| {
                    let counter = Arc::clone(&counter);
                    async move { Ok::<_, Infallible>(origin_respond(req, &counter).await) }
                });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                }
            });
        }
    });
    TlsOrigin {
        addr,
        ca_der: ca.cert_der,
        hits,
    }
}

/// Complete a TLS handshake over `tcp`, trusting only `ca`.
pub async fn tls_client(
    tcp: TcpStream,
    ca: &CertificateDer<'static>,
    sni: &str,
    alpn: &[&[u8]],
) -> io::Result<TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut cfg = client_config_with_roots(crypto_provider(), roots).unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    tokio::time::timeout(WAIT, TlsConnector::from(Arc::new(cfg)).connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
}

// ---------------------------------------------------------------------------
// Protocol clients
// ---------------------------------------------------------------------------

/// A parsed HTTP/1.1 response read to EOF.
#[derive(Debug)]
pub struct RawResponse {
    pub status_line: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn status(&self) -> u16 {
        self.status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("bad status line {:?}", self.status_line))
    }
}

/// Send `request` verbatim and read the whole response (use `Connection: close`).
pub async fn raw_exchange(proxy: SocketAddr, request: &str) -> RawResponse {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .expect("response timed out")
        .unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("no header terminator");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap().to_owned();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.trim().to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    RawResponse {
        status_line,
        headers,
        body: body.to_owned(),
    }
}

/// Absolute-form `GET` through the proxy.
pub async fn http_get(proxy: SocketAddr, authority: &str, path: &str) -> RawResponse {
    raw_exchange(
        proxy,
        &format!(
            "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
}

/// Send `CONNECT` and return the stream positioned after the response head, plus the status.
pub async fn http_connect(proxy: SocketAddr, target: &str) -> (TcpStream, u16) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        tokio::time::timeout(WAIT, stream.read_exact(&mut byte))
            .await
            .expect("CONNECT response timed out")
            .unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (stream, status)
}

/// SOCKS4 (`domain = None`) or SOCKS4a `CONNECT`; returns the stream and reply code.
pub async fn socks4(
    proxy: SocketAddr,
    cmd: u8,
    ip: [u8; 4],
    domain: Option<&str>,
    port: u16,
) -> (TcpStream, u8) {
    let mut req = vec![4, cmd];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip);
    req.extend_from_slice(b"integration\0");
    if let Some(d) = domain {
        req.extend_from_slice(d.as_bytes());
        req.push(0);
    }
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&req).await.unwrap();
    let mut reply = [0u8; 8];
    tokio::time::timeout(WAIT, stream.read_exact(&mut reply))
        .await
        .expect("SOCKS4 reply timed out")
        .unwrap();
    assert_eq!(reply[0], 0);
    (stream, reply[1])
}

/// SOCKS5 destination address.
pub enum Socks5Addr<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(&'a str),
}

/// SOCKS5 No-Auth greeting and request; returns the stream and `REP` code.
pub async fn socks5(
    proxy: SocketAddr,
    cmd: u8,
    addr: Socks5Addr<'_>,
    port: u16,
) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0], "No-Auth must be selected");

    let mut req = vec![5, cmd, 0];
    match addr {
        Socks5Addr::V4(ip) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&ip);
        }
        Socks5Addr::V6(ip) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&ip);
        }
        Socks5Addr::Domain(d) => {
            req.push(ATYP_DOMAIN);
            req.push(u8::try_from(d.len()).unwrap());
            req.extend_from_slice(d.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    let mut head = [0u8; 4];
    tokio::time::timeout(WAIT, stream.read_exact(&mut head))
        .await
        .expect("SOCKS5 reply timed out")
        .unwrap();
    assert_eq!(head[0], 5);
    let rest = match head[3] {
        ATYP_IPV4 => 6,
        ATYP_IPV6 => 18,
        other => panic!("unexpected bound ATYP {other}"),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).await.unwrap();
    (stream, head[1])
}

pub async fn roundtrip(stream: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    stream.write_all(payload).await.unwrap();
    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, stream.read_exact(&mut back))
        .await
        .expect("echo timed out")
        .unwrap();
    back
}

/// Read until EOF or a connection error; panics if the peer keeps the connection open.
pub async fn read_until_closed(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut out))
        .await
        .expect("connection was not closed");
    out
}

pub fn find<'a>(lines: &'a [String], needle: &str) -> &'a String {
    lines
        .iter()
        .find(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line containing {needle:?} in {lines:?}"))
}

// ---------------------------------------------------------------------------
// Mock `ssh` executable
// ---------------------------------------------------------------------------

/// A fake `ssh` that records its argv, PID, and `SIGTERM`, then runs until signalled.
#[cfg(unix)]
pub struct MockSsh {
    pub dir: PathBuf,
}

#[cfg(unix)]
impl MockSsh {
    pub fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("mock-ssh");
        let d = dir.display();
        let script = format!(
            "#!/bin/sh\n\
             [ \"$1\" = \"--probe\" ] && exit 0\n\
             trap 'echo term >> \"{d}/terms\"; exit 0' TERM\n\
             printf '%s\\n' \"$@\" > '{d}/args'\n\
             echo \"$$\" >> '{d}/pids'\n\
             while :; do sleep 0.05; done\n"
        );
        let staged = dir.join("ssh.new");
        std::fs::write(&staged, script).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&staged, dir.join("ssh")).unwrap();
        let mock = Self { dir };
        mock.wait_until_executable();
        mock
    }

    /// A concurrent `fork` can briefly inherit the write fd and cause `ETXTBSY`.
    fn wait_until_executable(&self) {
        for _ in 0..400 {
            match std::process::Command::new(self.bin())
                .arg("--probe")
                .status()
            {
                Ok(_) => return,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("mock ssh cannot run: {e}"),
            }
        }
        panic!("mock ssh stayed busy");
    }

    pub fn bin(&self) -> PathBuf {
        self.dir.join("ssh")
    }

    pub fn lines(&self, name: &str) -> Vec<String> {
        read_lines(&self.dir.join(name))
    }

    pub async fn wait_for_pids(&self, count: usize) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let pids = self.lines("pids");
            if pids.len() >= count {
                return pids;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "only {} ssh starts",
                pids.len()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(unix)]
impl Drop for MockSsh {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
pub fn kill_hard(pid: &str) {
    let status = std::process::Command::new("kill")
        .args(["-KILL", pid])
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
pub fn is_alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}
