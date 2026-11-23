//! HTTPS `CONNECT` interception (MITM ON).
//!
//! After the client received `200 Connection Established` ([`super::RequestCtx`] hands the
//! upgraded stream to [`MitmInterceptor`]):
//!
//! 1. `tokio_rustls::LazyConfigAcceptor` reads the client's `ClientHello` (SNI + ALPN).
//!    The leaf host is the SNI, falling back to the `CONNECT` host/IP.
//! 2. A **fresh** upstream TCP + TLS connection is opened to the `CONNECT` target (SNI =
//!    leaf host), verified with the platform verifier (or an injected root store in tests),
//!    offering only the HTTP protocols (`h2`, `http/1.1`) the client offered.
//! 3. The leaf certificate comes from the [`CertCache`] (signed on a miss) and the client
//!    TLS handshake is completed, advertising exactly the ALPN protocol the upstream chose.
//! 4. Decrypted requests are served with `hyper` (HTTP/1.1 or HTTP/2) and forwarded over the
//!    upstream TLS connection, streaming bodies frame by frame — **nothing is cached**. If an
//!    HTTP/1.1 upstream connection closes, the next request dials a fresh one.
//! 5. HTTP/1.1 upgrades (`101 Switching Protocols`, e.g. WebSocket) are forwarded and then
//!    relayed as raw bytes in both directions.
//! 6. One access record per decrypted request: `proto=https mitm=true`, method,
//!    `https://authority/path`, status, bytes, duration. Upstream failures before any
//!    request are logged as one `method=CONNECT` record with `502`/`504`.

use std::convert::Infallible;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::{http1 as client_http1, http2 as client_http2};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::{http1 as server_http1, http2 as server_http2};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_platform_verifier::BuilderVerifierExt;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream as ClientTlsStream, LazyConfigAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::forward::strip_hop_by_hop;
use super::tunnel::CountingStream;
use super::{
    dial_error_status, error_response, AccessGuard, ConnectTarget, CountingBody, MitmConnect,
    MitmHandler, ProxyBody,
};
use crate::logging::{AccessLogger, HttpAccessRecord, Logger, ProxyDirection};
use crate::mitm::cache::CertCache;
use crate::net::{relay_bidirectional, UpstreamDialer, DEFAULT_CONNECT_TIMEOUT};
use crate::server::HandlerFuture;

/// Bound on the client and upstream TLS handshakes.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Upstream TLS client config using the OS / platform certificate verifier.
pub fn platform_client_config(
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth())
}

/// Upstream TLS client config trusting only `roots` (local integration tests, private PKI).
pub fn client_config_with_roots(
    provider: Arc<CryptoProvider>,
    roots: RootCertStore,
) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// The MITM `CONNECT` handler. Cheap to clone.
#[derive(Clone)]
pub struct MitmInterceptor {
    cache: Arc<CertCache>,
    upstream_tls: Arc<ClientConfig>,
    provider: Arc<CryptoProvider>,
    dialer: Arc<dyn UpstreamDialer>,
    connect_timeout: Duration,
}

impl fmt::Debug for MitmInterceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmInterceptor")
            .field("cache", &self.cache)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl MitmHandler for MitmInterceptor {
    fn handle_connect(&self, connect: MitmConnect) -> HandlerFuture {
        let this = self.clone();
        Box::pin(async move { this.intercept(connect).await })
    }
}

/// Serves one fixed leaf certificate (chosen before the handshake from the `ClientHello`).
#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Opens fresh upstream TLS connections to the `CONNECT` target.
#[derive(Clone)]
struct Dialer {
    upstream: Arc<dyn UpstreamDialer>,
    tls: Arc<ClientConfig>,
    target: ConnectTarget,
    server_name: ServerName<'static>,
    timeout: Duration,
}

impl Dialer {
    async fn connect(&self, alpn: Vec<Vec<u8>>) -> io::Result<ClientTlsStream<TcpStream>> {
        let tcp = self
            .upstream
            .connect(&self.target.host, self.target.port, self.timeout)
            .await?;
        let mut cfg = (*self.tls).clone();
        cfg.alpn_protocols = alpn;
        let connector = TlsConnector::from(Arc::new(cfg));
        tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream TLS handshake timed out"))?
    }
}

/// Per-tunnel state shared by every decrypted request.
#[derive(Clone)]
struct Session {
    access: AccessLogger,
    logger: Logger,
    tasks: TaskTracker,
    shutdown: CancellationToken,
    client: SocketAddr,
    direction: ProxyDirection,
    /// Authority used when a request carries neither an absolute URI nor `Host`.
    default_authority: String,
    dialer: Dialer,
}

type H1Sender = client_http1::SendRequest<ProxyBody>;

impl MitmInterceptor {
    pub fn new(
        cache: Arc<CertCache>,
        upstream_tls: Arc<ClientConfig>,
        provider: Arc<CryptoProvider>,
        dialer: Arc<dyn UpstreamDialer>,
    ) -> Self {
        Self {
            cache,
            upstream_tls,
            provider,
            dialer,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Override the upstream TCP connect timeout (default 10s).
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn cache(&self) -> &Arc<CertCache> {
        &self.cache
    }

    async fn intercept(&self, connect: MitmConnect) {
        let MitmConnect {
            upgraded,
            target,
            client,
            direction,
            shutdown,
            access,
            logger,
        } = connect;
        let tasks = TaskTracker::new();
        let connect_guard = |status: StatusCode| {
            let mut g = new_guard(
                &access,
                &tasks,
                client,
                direction,
                "CONNECT",
                target.authority(),
            );
            g.set_status(status);
            g
        };

        // 1. ClientHello: SNI + ALPN.
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), upgraded);
        let start = tokio::select! {
            () = shutdown.cancelled() => return,
            res = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor) => match res {
                Ok(Ok(start)) => start,
                Ok(Err(e)) => {
                    logger.debug(format!("MITM {client} -> {target}: invalid ClientHello: {e}"));
                    return;
                }
                Err(_) => {
                    logger.debug(format!("MITM {client} -> {target}: ClientHello timed out"));
                    return;
                }
            },
        };
        let hello = start.client_hello();
        let sni = hello.server_name().map(str::to_string);
        let client_alpn: Vec<Vec<u8>> = hello
            .alpn()
            .map(|it| it.map(<[u8]>::to_vec).collect())
            .unwrap_or_default();
        let offered: Vec<Vec<u8>> = client_alpn
            .iter()
            .filter(|p| p.as_slice() == ALPN_H2 || p.as_slice() == ALPN_HTTP11)
            .cloned()
            .collect();
        let leaf_host = sni.clone().unwrap_or_else(|| target.host.clone());

        let Ok(server_name) = ServerName::try_from(leaf_host.clone()) else {
            logger.debug(format!(
                "MITM {client} -> {target}: invalid server name {leaf_host:?}"
            ));
            drop(connect_guard(StatusCode::BAD_REQUEST));
            return;
        };
        let dialer = Dialer {
            tls: Arc::clone(&self.upstream_tls),
            target: target.clone(),
            server_name,
            upstream: Arc::clone(&self.dialer),
            timeout: self.connect_timeout,
        };

        // 2. Fresh upstream TLS connection (learn the upstream's ALPN choice first).
        let upstream = tokio::select! {
            () = shutdown.cancelled() => return,
            res = dialer.connect(offered.clone()) => res,
        };
        let upstream = match upstream {
            Ok(s) => s,
            Err(e) => {
                logger.error(format!(
                    "MITM upstream {target} (SNI {leaf_host}) failed: {e}"
                ));
                drop(connect_guard(dial_error_status(&e)));
                return;
            }
        };
        let negotiated = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

        // 3. Leaf certificate + client handshake.
        let leaf = match self.cache.get_or_create(&leaf_host).await {
            Ok(k) => k,
            Err(e) => {
                logger.error(format!("MITM {client} -> {target}: {e}"));
                drop(connect_guard(StatusCode::BAD_GATEWAY));
                return;
            }
        };
        let mut server_cfg = match ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(leaf))),
            Err(e) => {
                logger.error(format!("MITM TLS server config failed: {e}"));
                return;
            }
        };
        server_cfg.alpn_protocols = match &negotiated {
            Some(p) => vec![p.clone()],
            None if offered.iter().any(|p| p == ALPN_HTTP11) => vec![ALPN_HTTP11.to_vec()],
            None => Vec::new(),
        };
        let client_tls = tokio::select! {
            () = shutdown.cancelled() => return,
            res = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, start.into_stream(Arc::new(server_cfg))) => res,
        };
        let client_tls = match client_tls {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                logger.debug(format!(
                    "MITM client TLS handshake with {client} for {leaf_host} failed: {e}"
                ));
                return;
            }
            Err(_) => {
                logger.debug(format!("MITM client TLS handshake with {client} timed out"));
                return;
            }
        };

        let default_authority = if target.port == 443 {
            authority_host(&leaf_host)
        } else {
            format!("{}:{}", authority_host(&leaf_host), target.port)
        };
        let session = Session {
            access,
            logger: logger.clone(),
            tasks: tasks.clone(),
            shutdown: shutdown.clone(),
            client,
            direction,
            default_authority,
            dialer,
        };

        // 4. Serve decrypted HTTP.
        let result = if negotiated.as_deref() == Some(ALPN_H2) {
            session.serve_h2(client_tls, upstream).await
        } else {
            session.serve_h1(client_tls, upstream).await
        };
        if let Err(e) = result {
            logger.debug(format!("MITM session {client} -> {target} ended: {e}"));
        }
        tasks.close();
        tasks.wait().await;
    }
}

fn authority_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn new_guard(
    access: &AccessLogger,
    tasks: &TaskTracker,
    client: SocketAddr,
    direction: ProxyDirection,
    method: &str,
    target: String,
) -> AccessGuard {
    AccessGuard::new(
        access.clone(),
        tasks.clone(),
        HttpAccessRecord {
            ts: OffsetDateTime::now_utc(),
            direction,
            client,
            proto: "https".into(),
            mitm: true,
            method: method.to_string(),
            target,
            status: 0,
            bytes_in: 0,
            bytes_out: 0,
            duration_ms: 0,
        },
    )
}

fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(header::UPGRADE)
        && req
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

impl Session {
    fn guard(&self, method: &str, target: String) -> AccessGuard {
        new_guard(
            &self.access,
            &self.tasks,
            self.client,
            self.direction,
            method,
            target,
        )
    }

    /// `(authority, logged https:// URL)` for a decrypted request.
    fn request_target<B>(&self, req: &Request<B>) -> (String, String) {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                req.headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| self.default_authority.clone());
        let pq = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
        let url = format!("https://{authority}{pq}");
        (authority, url)
    }

    fn spawn_driver<F>(&self, what: &'static str, conn: F)
    where
        F: std::future::Future<Output = Result<(), hyper::Error>> + Send + 'static,
    {
        let shutdown = self.shutdown.clone();
        let logger = self.logger.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                res = conn => {
                    if let Err(e) = res {
                        logger.debug(format!("MITM upstream {what} connection error: {e}"));
                    }
                }
                () = shutdown.cancelled() => {}
            }
        });
    }

    async fn h1_handshake(
        &self,
        tls: ClientTlsStream<TcpStream>,
    ) -> Result<H1Sender, hyper::Error> {
        let (sender, conn) = client_http1::handshake(TokioIo::new(tls)).await?;
        self.spawn_driver("HTTP/1.1", conn.with_upgrades());
        Ok(sender)
    }

    /// The idle upstream HTTP/1.1 sender, or a freshly dialed one if it closed.
    async fn h1_sender(&self, slot: &Mutex<Option<H1Sender>>) -> Result<H1Sender, StatusCode> {
        if let Some(mut s) = slot.lock().await.take() {
            if s.ready().await.is_ok() {
                return Ok(s);
            }
        }
        let tls = self
            .dialer
            .connect(vec![ALPN_HTTP11.to_vec()])
            .await
            .map_err(|e| {
                self.logger.error(format!(
                    "MITM upstream {} redial failed: {e}",
                    self.dialer.target
                ));
                dial_error_status(&e)
            })?;
        self.h1_handshake(tls).await.map_err(|e| {
            self.logger.error(format!(
                "MITM upstream {} handshake failed: {e}",
                self.dialer.target
            ));
            StatusCode::BAD_GATEWAY
        })
    }

    async fn serve_h1(
        &self,
        client_tls: tokio_rustls::server::TlsStream<TokioIo<hyper::upgrade::Upgraded>>,
        upstream: ClientTlsStream<TcpStream>,
    ) -> Result<(), hyper::Error> {
        let first = self.h1_handshake(upstream).await?;
        let slot = Arc::new(Mutex::new(Some(first)));
        let session = self.clone();
        let service = service_fn(move |req| {
            let session = session.clone();
            let slot = Arc::clone(&slot);
            async move { Ok::<_, Infallible>(session.forward_h1(req, &slot).await) }
        });
        let conn = server_http1::Builder::new()
            .serve_connection(TokioIo::new(client_tls), service)
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res,
            () = self.shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                conn.as_mut().await
            }
        }
    }

    async fn forward_h1(
        &self,
        mut req: Request<Incoming>,
        slot: &Mutex<Option<H1Sender>>,
    ) -> Response<ProxyBody> {
        let (authority, url) = self.request_target(&req);
        let mut guard = self.guard(req.method().as_str(), url);
        let upgrade = is_upgrade_request(&req).then(|| {
            let proto = req.headers().get(header::UPGRADE).cloned();
            (hyper::upgrade::on(&mut req), proto)
        });

        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        if let Some((_, Some(proto))) = &upgrade {
            parts.headers.insert(header::UPGRADE, proto.clone());
            parts
                .headers
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        }
        let origin = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
        parts.uri = origin
            .parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("/"));
        parts.version = Version::HTTP_11;
        if !parts.headers.contains_key(header::HOST) {
            match HeaderValue::from_str(&authority) {
                Ok(v) => {
                    parts.headers.insert(header::HOST, v);
                }
                Err(_) => {
                    guard.set_status(StatusCode::BAD_REQUEST);
                    return error_response(StatusCode::BAD_REQUEST, "invalid host");
                }
            }
        }
        let body = CountingBody::new(body, guard.bytes_in(), None).boxed();
        let upstream_req = Request::from_parts(parts, body);

        let mut sender = match self.h1_sender(slot).await {
            Ok(s) => s,
            Err(status) => {
                guard.set_status(status);
                return error_response(status, "upstream connection failed");
            }
        };
        let mut resp = match sender.send_request(upstream_req).await {
            Ok(r) => r,
            Err(e) => {
                self.logger
                    .error(format!("MITM upstream request to {authority} failed: {e}"));
                guard.set_status(StatusCode::BAD_GATEWAY);
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };
        guard.set_status(resp.status());

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            if let Some((client_upgrade, _)) = upgrade {
                // The upstream connection now belongs to the upgraded stream.
                drop(sender);
                let upstream_upgrade = hyper::upgrade::on(&mut resp);
                self.spawn_upgrade_relay(client_upgrade, upstream_upgrade, guard);
                let (parts, _) = resp.into_parts();
                return Response::from_parts(parts, empty_body());
            }
        }
        *slot.lock().await = Some(sender);

        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let bytes_out = guard.bytes_out();
        Response::from_parts(
            parts,
            CountingBody::new(body, bytes_out, Some(guard)).boxed(),
        )
    }

    fn spawn_upgrade_relay(
        &self,
        client: hyper::upgrade::OnUpgrade,
        upstream: hyper::upgrade::OnUpgrade,
        guard: AccessGuard,
    ) {
        let shutdown = self.shutdown.clone();
        let logger = self.logger.clone();
        let peer = self.client;
        self.tasks.spawn(async move {
            let (client, upstream) = match tokio::try_join!(client, upstream) {
                Ok(pair) => pair,
                Err(e) => {
                    logger.debug(format!("MITM upgrade for {peer} failed: {e}"));
                    return;
                }
            };
            let mut client =
                CountingStream::new(TokioIo::new(client), guard.bytes_in(), guard.bytes_out());
            let mut upstream = TokioIo::new(upstream);
            tokio::select! {
                res = relay_bidirectional(&mut client, &mut upstream) => {
                    if let Err(e) = res {
                        logger.debug(format!("MITM upgraded stream for {peer} ended: {e}"));
                    }
                }
                () = shutdown.cancelled() => {}
            }
            drop(guard);
        });
    }

    async fn serve_h2(
        &self,
        client_tls: tokio_rustls::server::TlsStream<TokioIo<hyper::upgrade::Upgraded>>,
        upstream: ClientTlsStream<TcpStream>,
    ) -> Result<(), hyper::Error> {
        let (sender, conn) =
            client_http2::handshake(TokioExecutor::new(), TokioIo::new(upstream)).await?;
        self.spawn_driver("HTTP/2", conn);
        let session = self.clone();
        let service = service_fn(move |req| {
            let session = session.clone();
            let sender = sender.clone();
            async move { Ok::<_, Infallible>(session.forward_h2(req, sender).await) }
        });
        let conn = server_http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(client_tls), service);
        let mut conn = std::pin::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res,
            () = self.shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                conn.as_mut().await
            }
        }
    }

    async fn forward_h2(
        &self,
        req: Request<Incoming>,
        mut sender: client_http2::SendRequest<ProxyBody>,
    ) -> Response<ProxyBody> {
        let (authority, url) = self.request_target(&req);
        let mut guard = self.guard(req.method().as_str(), url.clone());
        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(header::HOST);
        parts.version = Version::HTTP_2;
        parts.uri = match url.parse::<Uri>() {
            Ok(u) => u,
            Err(_) => {
                guard.set_status(StatusCode::BAD_REQUEST);
                return error_response(StatusCode::BAD_REQUEST, "invalid request target");
            }
        };
        let body = CountingBody::new(body, guard.bytes_in(), None).boxed();
        let resp = match sender.send_request(Request::from_parts(parts, body)).await {
            Ok(r) => r,
            Err(e) => {
                self.logger.error(format!(
                    "MITM upstream HTTP/2 request to {authority} failed: {e}"
                ));
                guard.set_status(StatusCode::BAD_GATEWAY);
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };
        guard.set_status(resp.status());
        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let bytes_out = guard.bytes_out();
        Response::from_parts(
            parts,
            CountingBody::new(body, bytes_out, Some(guard)).boxed(),
        )
    }
}

fn empty_body() -> ProxyBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A local TLS origin and MITM proxy wiring for tests.

    use super::*;
    use crate::http::test_support::{capture_access, quiet_logger, spawn_proxy, Buf};
    use crate::http::HttpProxy;
    use crate::mitm::ca::test_support::{test_ca, TestCa};
    use crate::mitm::ca::CaMaterial;
    use crate::mitm::crypto_provider;
    use crate::mitm::signer::LeafSigner;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http_body_util::Full;
    use rustls::pki_types::CertificateDer;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// A TLS origin on 127.0.0.1 (leaf for `localhost`, signed by its own CA)
    /// that answers `hit <n> <method> <path> <body-len>` with a cacheable header, and echoes
    /// raw bytes after a `101` for `Upgrade` requests.
    pub struct Origin {
        pub addr: SocketAddr,
        pub ca_der: CertificateDer<'static>,
        pub hits: Arc<AtomicUsize>,
    }

    pub async fn spawn_origin() -> Origin {
        let ca = test_ca();
        let ca_material =
            CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
        let signer =
            LeafSigner::new(&ca_material, Duration::from_secs(3600), crypto_provider()).unwrap();
        let leaf = signer
            .sign_at("localhost", OffsetDateTime::now_utc())
            .unwrap();
        let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(leaf.certified)));
        cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let counter = Arc::clone(&counter);
                        async move { Ok::<_, Infallible>(origin_respond(req, &counter).await) }
                    });
                    if h2 {
                        let _ = server_http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    } else {
                        let _ = server_http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), service)
                            .with_upgrades()
                            .await;
                    }
                });
            }
        });
        Origin {
            addr,
            ca_der: CertificateDer::from(ca.cert_der.clone()),
            hits,
        }
    }

    async fn origin_respond(
        mut req: Request<Incoming>,
        counter: &AtomicUsize,
    ) -> Response<Full<Bytes>> {
        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
        if is_upgrade_request(&req) {
            let on = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(up) = on.await {
                    let mut io = TokioIo::new(up);
                    let mut buf = [0u8; 1024];
                    while let Ok(k) = io.read(&mut buf).await {
                        if k == 0 || io.write_all(&buf[..k]).await.is_err() {
                            break;
                        }
                    }
                }
            });
            return Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "echo")
                .body(Full::new(Bytes::new()))
                .unwrap();
        }
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let version = format!("{:?}", req.version());
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header("x-origin-version", version)
            .body(Full::new(Bytes::from(format!(
                "hit {n} {method} {path} {}",
                body.len()
            ))))
            .unwrap()
    }

    pub struct MitmProxy {
        pub addr: SocketAddr,
        pub log: Buf,
        pub mitm_ca: TestCa,
        pub cache: Arc<CertCache>,
    }

    /// An HTTP proxy with MITM on, trusting `origin_ca` upstream.
    pub async fn spawn_mitm_proxy(origin_ca: &CertificateDer<'static>) -> MitmProxy {
        let mitm_ca = test_ca();
        let material = CaMaterial::from_pem(
            mitm_ca.cert_pem.as_bytes(),
            mitm_ca.key_pem.as_bytes(),
            None,
        )
        .unwrap()
        .validate()
        .unwrap();
        let provider = crypto_provider();
        let signer =
            LeafSigner::new(&material, Duration::from_secs(3600), Arc::clone(&provider)).unwrap();
        let cache = Arc::new(CertCache::new(Arc::new(signer), Duration::from_secs(3600)));
        let mut roots = RootCertStore::empty();
        roots.add(origin_ca.clone()).unwrap();
        let upstream = client_config_with_roots(Arc::clone(&provider), roots).unwrap();
        let interceptor = MitmInterceptor::new(
            Arc::clone(&cache),
            Arc::new(upstream),
            provider,
            crate::http::test_support::direct_dialer(),
        );
        let (access, log) = capture_access().await;
        let proxy = HttpProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        )
        .with_mitm(Arc::new(interceptor));
        MitmProxy {
            addr: spawn_proxy(proxy).await,
            log,
            mitm_ca,
            cache,
        }
    }

    /// `CONNECT target` through `proxy`; returns the raw stream after `200`.
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

    /// TLS client trusting only the MITM CA.
    pub async fn tls_client(
        stream: TcpStream,
        mitm_ca: &TestCa,
        sni: &str,
        alpn: &[&[u8]],
    ) -> io::Result<ClientTlsStream<TcpStream>> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(mitm_ca.cert_der.clone()))
            .unwrap();
        let mut cfg = client_config_with_roots(crypto_provider(), roots).unwrap();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        TlsConnector::from(Arc::new(cfg))
            .connect(ServerName::try_from(sni.to_string()).unwrap(), stream)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    use bytes::Bytes;
    use http_body_util::Full;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    async fn h1_client(tls: ClientTlsStream<TcpStream>) -> client_http1::SendRequest<Full<Bytes>> {
        let (sender, conn) = client_http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        sender
    }

    async fn body_string(resp: Response<Incoming>) -> String {
        String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn intercepts_http11_logs_requests_and_never_caches() {
        let origin = spawn_origin().await;
        let proxy = spawn_mitm_proxy(&origin.ca_der).await;
        let target = format!("localhost:{}", origin.addr.port());

        let tcp = connect_through(proxy.addr, &target).await;
        let tls = tls_client(tcp, &proxy.mitm_ca, "localhost", &[b"http/1.1"])
            .await
            .expect("client trusts the MITM CA leaf");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(ALPN_HTTP11));
        // The served chain is our dynamically signed leaf + the MITM CA.
        let chain = tls.get_ref().1.peer_certificates().unwrap();
        assert_eq!(chain[1].as_ref(), proxy.mitm_ca.cert_der.as_slice());
        let mut sender = h1_client(tls).await;

        // Same cacheable GET twice: both reach the origin (zero caching).
        for expected in ["hit 1 GET /cacheable 0", "hit 2 GET /cacheable 0"] {
            sender.ready().await.unwrap();
            let req = Request::get("/cacheable?q=1")
                .header(header::HOST, &target)
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = sender.send_request(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(body_string(resp).await, expected);
        }
        sender.ready().await.unwrap();
        let req = Request::post("/submit")
            .header(header::HOST, &target)
            .body(Full::new(Bytes::from_static(b"hello world")))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(body_string(resp).await, "hit 3 POST /submit 11");
        assert_eq!(origin.hits.load(std::sync::atomic::Ordering::SeqCst), 3);
        drop(sender);

        let lines = proxy.log.wait_lines(3).await;
        let get = format!(
            "proto=https mitm=true method=GET target=\"https://{target}/cacheable?q=1\" status=200"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains(&get)).count(),
            2,
            "{lines:?}"
        );
        let post =
            format!("proto=https mitm=true method=POST target=https://{target}/submit status=200");
        let post_line = lines
            .iter()
            .find(|l| l.contains(&post))
            .expect("POST logged");
        assert!(
            post_line.contains("bytes_in=11 bytes_out=21"),
            "{post_line}"
        );
        // Exactly one leaf was signed for the host and it is the only cache.
        assert_eq!(proxy.cache.len(), 1);
    }

    #[tokio::test]
    async fn intercepts_http2_when_negotiated() {
        let origin = spawn_origin().await;
        let proxy = spawn_mitm_proxy(&origin.ca_der).await;
        let target = format!("localhost:{}", origin.addr.port());

        let tcp = connect_through(proxy.addr, &target).await;
        let tls = tls_client(tcp, &proxy.mitm_ca, "localhost", &[b"h2", b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(ALPN_H2));
        let (mut sender, conn) = client_http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::get(format!("https://{target}/two"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.version(), Version::HTTP_2);
        assert_eq!(resp.headers()["x-origin-version"], "HTTP/2.0");
        assert_eq!(body_string(resp).await, "hit 1 GET /two 0");

        let lines = proxy.log.wait_lines(1).await;
        assert!(
            lines[0].contains(&format!(
                "proto=https mitm=true method=GET target=https://{target}/two status=200"
            )),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn passes_through_101_upgrades() {
        let origin = spawn_origin().await;
        let proxy = spawn_mitm_proxy(&origin.ca_der).await;
        let target = format!("localhost:{}", origin.addr.port());

        let tcp = connect_through(proxy.addr, &target).await;
        let mut tls = tls_client(tcp, &proxy.mitm_ca, "localhost", &[b"http/1.1"])
            .await
            .unwrap();
        tls.write_all(
            format!(
                "GET /ws HTTP/1.1\r\nHost: {target}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut reader = BufReader::new(tls);
        let mut status = String::new();
        reader.read_line(&mut status).await.unwrap();
        assert!(status.starts_with("HTTP/1.1 101"), "{status}");
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
        }
        reader.get_mut().write_all(b"ping-pong").await.unwrap();
        let mut echoed = [0u8; 9];
        reader.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping-pong");
        drop(reader);

        let lines = proxy.log.wait_lines(1).await;
        assert!(
            lines[0].contains(&format!(
                "mitm=true method=GET target=https://{target}/ws status=101"
            )),
            "{lines:?}"
        );
        assert!(lines[0].contains("bytes_in=9 bytes_out=9"), "{lines:?}");
    }

    #[tokio::test]
    async fn untrusted_upstream_and_unreachable_targets_are_logged() {
        let origin = spawn_origin().await;
        // Proxy trusting a different CA: upstream verification must fail.
        let other = crate::mitm::ca::test_support::test_ca();
        let proxy = spawn_mitm_proxy(&CertificateDerExt::der(&other)).await;
        let target = format!("localhost:{}", origin.addr.port());
        let tcp = connect_through(proxy.addr, &target).await;
        assert!(tls_client(tcp, &proxy.mitm_ca, "localhost", &[b"http/1.1"])
            .await
            .is_err());

        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let tcp = connect_through(proxy.addr, &closed.to_string()).await;
        assert!(tls_client(tcp, &proxy.mitm_ca, "localhost", &[])
            .await
            .is_err());

        let lines = proxy.log.wait_lines(2).await;
        assert!(
            lines[0].contains(&format!(
                "mitm=true method=CONNECT target={target} status=502"
            )),
            "{lines:?}"
        );
        assert!(
            lines[1].contains(&format!(
                "mitm=true method=CONNECT target={closed} status=502"
            )),
            "{lines:?}"
        );
        assert_eq!(origin.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    trait CertificateDerExt {
        fn der(&self) -> rustls::pki_types::CertificateDer<'static>;
    }

    impl CertificateDerExt for crate::mitm::ca::test_support::TestCa {
        fn der(&self) -> rustls::pki_types::CertificateDer<'static> {
            rustls::pki_types::CertificateDer::from(self.cert_der.clone())
        }
    }
}
