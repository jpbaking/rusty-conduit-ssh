//! HTTP/HTTPS proxy connection dispatcher.
//!
//! Every accepted HTTP connection is served by `hyper` 1.x (`http1` server, upgrades
//! enabled). Each request is dispatched by method:
//!
//! * `CONNECT host:port` → [`tunnel`] (opaque TCP tunnel, MITM OFF), or — when a
//!   [`MitmHandler`] is installed with [`HttpProxy::with_mitm`] — the MITM handler receives
//!   the upgraded client stream after `200 Connection Established` is sent.
//! * anything else → [`forward`] (plain HTTP forward proxy).
//!
//! Nothing is cached: every request/tunnel opens a fresh upstream connection, bodies are
//! streamed frame by frame, and nothing is retained after the exchange.

pub mod forward;
pub mod mitm_tunnel;
pub mod tunnel;

use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::logging::{AccessLogger, HttpAccessRecord, Logger, ProxyDirection};
use crate::net::{UpstreamDialer, DEFAULT_CONNECT_TIMEOUT};
use crate::server::{Connection, HandlerFuture};

/// Boxed error type used by proxied bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Response body type produced by the proxy (streamed, never buffered in full).
pub type ProxyBody = BoxBody<Bytes, BoxError>;

/// A validated `CONNECT` target (`host:port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    /// Hostname or IP literal (IPv6 without brackets).
    pub host: String,
    pub port: u16,
}

impl ConnectTarget {
    /// Parse a `CONNECT` authority (`host:port`, `[v6]:port`). The port is mandatory and
    /// must be non-zero; userinfo, paths, and whitespace are rejected.
    pub fn parse(authority: &str) -> Option<Self> {
        let (host, port) = authority.rsplit_once(':')?;
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        let host = match host.strip_prefix('[') {
            Some(rest) => rest.strip_suffix(']')?,
            None if host.contains(':') => return None,
            None => host,
        };
        let invalid = |c: char| c.is_whitespace() || matches!(c, '/' | '@' | '[' | ']');
        if host.is_empty() || host.chars().any(invalid) {
            return None;
        }
        Some(Self {
            host: host.to_string(),
            port,
        })
    }

    /// `host:port`, bracketing IPv6 literals.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority())
    }
}

/// An intercepted `CONNECT`, handed to a [`MitmHandler`] after the client received
/// `200 Connection Established`.
pub struct MitmConnect {
    /// The upgraded client stream (raw bytes after the `CONNECT` response).
    pub upgraded: TokioIo<Upgraded>,
    pub target: ConnectTarget,
    pub client: SocketAddr,
    pub direction: ProxyDirection,
    /// Cancelled on server shutdown.
    pub shutdown: CancellationToken,
    pub access: AccessLogger,
    pub logger: Logger,
}

impl fmt::Debug for MitmConnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmConnect")
            .field("target", &self.target)
            .field("client", &self.client)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

/// Hook for HTTPS interception (Phase 5 `mitm_tunnel`). When installed, it replaces the
/// opaque [`tunnel`] for every `CONNECT`.
pub trait MitmHandler: Send + Sync + 'static {
    fn handle_connect(&self, connect: MitmConnect) -> HandlerFuture;
}

/// The HTTP/HTTPS proxy engine. Cheap to clone.
#[derive(Clone)]
pub struct HttpProxy {
    access: AccessLogger,
    logger: Logger,
    dialer: Arc<dyn UpstreamDialer>,
    direction: ProxyDirection,
    connect_timeout: Duration,
    mitm: Option<Arc<dyn MitmHandler>>,
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxy")
            .field("direction", &self.direction)
            .field("connect_timeout", &self.connect_timeout)
            .field("mitm", &self.mitm.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpProxy {
    pub fn new(access: AccessLogger, logger: Logger, dialer: Arc<dyn UpstreamDialer>) -> Self {
        Self {
            access,
            logger,
            dialer,
            direction: ProxyDirection::Forward,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            mitm: None,
        }
    }

    /// Tag access log records emitted by this proxy with `direction`.
    pub fn with_direction(mut self, direction: ProxyDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Route every `CONNECT` through `handler` instead of the opaque tunnel.
    pub fn with_mitm(mut self, handler: Arc<dyn MitmHandler>) -> Self {
        self.mitm = Some(handler);
        self
    }

    /// Override the upstream connect timeout (default [`DEFAULT_CONNECT_TIMEOUT`]).
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Serve one client connection until it closes or the server shuts down. Tunnels and
    /// upstream connection drivers spawned for this connection are awaited before returning,
    /// so the server's drain accounting covers them.
    pub async fn serve(&self, conn: Connection) {
        let Connection {
            stream,
            peer,
            shutdown,
            ..
        } = conn;
        let tasks = TaskTracker::new();
        let ctx = RequestCtx {
            proxy: self.clone(),
            peer,
            shutdown: shutdown.clone(),
            tasks: tasks.clone(),
        };
        let service = service_fn(move |req| {
            let ctx = ctx.clone();
            async move { Ok::<_, Infallible>(ctx.dispatch(req).await) }
        });
        let conn = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);
        let result = tokio::select! {
            res = conn.as_mut() => res,
            () = shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                conn.as_mut().await
            }
        };
        if let Err(e) = result {
            self.logger
                .debug(format!("HTTP connection from {peer} ended with error: {e}"));
        }
        tasks.close();
        tasks.wait().await;
    }
}

/// Per-connection request context shared by [`forward`] and [`tunnel`].
#[derive(Clone)]
pub(crate) struct RequestCtx {
    pub(crate) proxy: HttpProxy,
    pub(crate) peer: SocketAddr,
    pub(crate) shutdown: CancellationToken,
    pub(crate) tasks: TaskTracker,
}

impl RequestCtx {
    async fn dispatch(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        if req.method() != Method::CONNECT {
            return forward::handle(self, req).await;
        }
        match self.proxy.mitm.clone() {
            Some(mitm) => self.mitm_connect(mitm, req),
            None => tunnel::handle(self, req).await,
        }
    }

    fn mitm_connect(
        &self,
        mitm: Arc<dyn MitmHandler>,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let authority = req.uri().authority().map(|a| a.as_str().to_string());
        let Some(target) = authority.as_deref().and_then(ConnectTarget::parse) else {
            let mut guard =
                self.access_guard("https", true, "CONNECT", authority.unwrap_or_default());
            guard.set_status(StatusCode::BAD_REQUEST);
            return error_response(StatusCode::BAD_REQUEST, "invalid CONNECT target");
        };
        let connect_base = (
            target,
            self.peer,
            self.shutdown.clone(),
            self.proxy.access.clone(),
            self.proxy.logger.clone(),
        );
        let direction = self.proxy.direction;
        self.tasks.spawn(async move {
            let (target, client, shutdown, access, logger) = connect_base;
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    mitm.handle_connect(MitmConnect {
                        upgraded: TokioIo::new(upgraded),
                        target,
                        client,
                        direction,
                        shutdown,
                        access,
                        logger,
                    })
                    .await
                }
                Err(e) => logger.debug(format!("CONNECT upgrade from {client} failed: {e}")),
            }
        });
        connect_established()
    }

    /// Start an access record for this request; it is emitted when the guard drops.
    pub(crate) fn access_guard(
        &self,
        proto: &str,
        mitm: bool,
        method: &str,
        target: String,
    ) -> AccessGuard {
        AccessGuard::new(
            self.proxy.access.clone(),
            self.tasks.clone(),
            HttpAccessRecord {
                ts: OffsetDateTime::now_utc(),
                direction: self.proxy.direction,
                client: self.peer,
                proto: proto.to_string(),
                mitm,
                method: method.to_string(),
                target,
                status: 0,
                bytes_in: 0,
                bytes_out: 0,
                duration_ms: 0,
            },
        )
    }
}

/// Emits one [`HttpAccessRecord`] when dropped, filling in byte counters and duration.
///
/// The guard travels with the streamed response body, so the record is written once the
/// body has been fully delivered (or abandoned by the client).
pub struct AccessGuard {
    access: AccessLogger,
    tasks: TaskTracker,
    record: Option<HttpAccessRecord>,
    started: Instant,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
}

impl AccessGuard {
    pub fn new(access: AccessLogger, tasks: TaskTracker, record: HttpAccessRecord) -> Self {
        Self {
            access,
            tasks,
            record: Some(record),
            started: Instant::now(),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_status(&mut self, status: StatusCode) {
        if let Some(r) = self.record.as_mut() {
            r.status = status.as_u16();
        }
    }

    /// Counter for bytes received from the client.
    pub fn bytes_in(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes_in)
    }

    /// Counter for bytes sent to the client.
    pub fn bytes_out(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes_out)
    }
}

impl Drop for AccessGuard {
    fn drop(&mut self) {
        let Some(mut record) = self.record.take() else {
            return;
        };
        record.bytes_in = self.bytes_in.load(Ordering::Relaxed);
        record.bytes_out = self.bytes_out.load(Ordering::Relaxed);
        record.duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if !self.access.http_enabled() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let access = self.access.clone();
        self.tasks
            .spawn(async move { access.log_http(&record).await });
    }
}

/// Streams an inner body unchanged while counting data bytes; optionally owns an
/// [`AccessGuard`] so the access record is emitted when the body finishes.
pub struct CountingBody<B> {
    inner: B,
    counter: Arc<AtomicU64>,
    _guard: Option<AccessGuard>,
}

impl<B> CountingBody<B> {
    pub fn new(inner: B, counter: Arc<AtomicU64>, guard: Option<AccessGuard>) -> Self {
        Self {
            inner,
            counter,
            _guard: guard,
        }
    }
}

impl<B> Body for CountingBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    self.counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// `200 Connection Established` with an empty body.
pub fn connect_established() -> Response<ProxyBody> {
    let mut resp = Response::new(empty_body());
    resp.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Connection Established",
        ));
    resp
}

/// A short `text/plain` error response generated by the proxy itself.
pub fn error_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(format!("{msg}\n")))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn empty_body() -> ProxyBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

/// Map an upstream dial error to the proxy status code (`403` when filtered, `504` on timeout,
/// else `502`).
pub(crate) fn dial_error_status(e: &std::io::Error) -> StatusCode {
    if crate::filter::is_access_denied(e) {
        StatusCode::FORBIDDEN
    } else if e.kind() == std::io::ErrorKind::TimedOut {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared helpers for HTTP proxy tests.

    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::AsyncWrite;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use crate::net::{DirectDialer, UpstreamDialer};

    /// Dialer for isolated tests: connects directly, without a tunnel.
    pub(crate) fn direct_dialer() -> Arc<dyn UpstreamDialer> {
        Arc::new(DirectDialer::default())
    }

    use super::HttpProxy;
    use crate::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
    use crate::server::Connection;

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
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
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

    /// An access logger dumping text records into the returned buffer.
    pub async fn capture_access() -> (AccessLogger, Buf) {
        let buf = Buf::default();
        let cfg = AccessLogConfig {
            format: LogFormat::Text,
            http_access_log: None,
            socks_log: None,
            dump_stdout: true,
        };
        let access = AccessLogger::start_with_stdout(cfg, Box::new(buf.clone()), quiet_logger())
            .await
            .unwrap();
        (access, buf)
    }

    /// Run `proxy` on an ephemeral loopback port.
    pub async fn spawn_proxy(proxy: HttpProxy) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    return;
                };
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    proxy
                        .serve(Connection {
                            stream,
                            peer,
                            local: addr,
                            shutdown: CancellationToken::new(),
                        })
                        .await;
                });
            }
        });
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_target_parsing() {
        assert_eq!(
            ConnectTarget::parse("example.com:443"),
            Some(ConnectTarget {
                host: "example.com".into(),
                port: 443
            })
        );
        let v6 = ConnectTarget::parse("[::1]:8443").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("::1", 8443));
        assert_eq!(v6.authority(), "[::1]:8443");
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:99999",
            ":443",
            "::1:443",
            "[::1:443",
            "user@host:443",
            "host/path:443",
        ] {
            assert_eq!(ConnectTarget::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn connect_established_has_reason_phrase() {
        let resp = connect_established();
        assert_eq!(resp.status(), StatusCode::OK);
        let reason = resp.extensions().get::<hyper::ext::ReasonPhrase>().unwrap();
        assert_eq!(reason.as_bytes(), b"Connection Established");
    }
}
