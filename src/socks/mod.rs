//! SOCKS4/4a/5 `CONNECT` engine.
//!
//! * [`v4`] implements SOCKS4 and SOCKS4a (remote DNS when the IPv4 field is `0.0.0.x`).
//! * [`v5`] implements RFC 1928 SOCKS5 with No-Auth and `CONNECT` for IPv4, IPv6, and
//!   domain targets.
//!
//! [`SocksProxy`] is the shared engine: it is either handed pre-classified streams by the
//! server ([`SocksProxy::serve_v4`] / [`SocksProxy::serve_v5`], first byte still unread) or
//! sniffs the version byte itself ([`SocksProxy::serve`]).
//!
//! Every upstream connection is a fresh dial through [`crate::net::UpstreamDialer`] (OS
//! resolver per request, zero DNS caching). One [`SocksLogRecord`] is emitted per handled
//! request when the session ends.
//!
//! # Relay guard hook
//!
//! An optional [`RelayGuard`] can be installed with [`SocksProxy::with_guard`]. After the
//! SOCKS handshake succeeds and the upstream is connected, upstream → client bytes flow
//! immediately (server-speaks-first protocols are never delayed), but the **first**
//! client → upstream chunk is passed to [`RelayGuard::inspect`] before being forwarded. A
//! [`GuardVerdict::Block`] closes both sockets without forwarding it and records the
//! verdict's status label. Afterwards the relay switches to plain `copy_bidirectional`.
//!
//! [`web_guard::WebGuard`] is the guard used for `--socks-block-web-in-mitm`.

pub mod v4;
pub mod v5;
pub mod web_guard;

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::http::tunnel::CountingStream;
use crate::logging::{AccessLogger, Logger, ProxyDirection, SocksLogRecord};
use crate::mux::{self, DetectedProtocol};
use crate::net::{relay_bidirectional, UpstreamDialer, DEFAULT_CONNECT_TIMEOUT};
use crate::server::Connection;

/// Default bound on how long a client may take to complete the SOCKS handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum length accepted for SOCKS4 user IDs and SOCKS4a domain names.
pub(crate) const MAX_CSTRING_LEN: usize = 255;

/// Size of the buffers used while waiting for the first client chunk under a guard.
const GUARD_BUF_SIZE: usize = 16 * 1024;

/// Destination host requested by a SOCKS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    Ip(IpAddr),
    /// Domain name resolved by the proxy (SOCKS4a / SOCKS5 `ATYP=0x03`).
    Domain(String),
}

/// Destination requested by a SOCKS client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: TargetHost,
    pub port: u16,
}

impl SocksTarget {
    /// Host string suitable for [`crate::net::UpstreamDialer`].
    pub fn dial_host(&self) -> String {
        match &self.host {
            TargetHost::Ip(ip) => ip.to_string(),
            TargetHost::Domain(d) => d.clone(),
        }
    }
}

impl fmt::Display for SocksTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            TargetHost::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            TargetHost::Ip(IpAddr::V4(ip)) => write!(f, "{ip}:{}", self.port),
            TargetHost::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

/// Decision returned by a [`RelayGuard`] for the first client → upstream chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Forward the chunk and continue relaying.
    Allow,
    /// Drop the chunk, close both sockets, and log `status` (e.g. `blocked_web_in_mitm`).
    Block { status: String },
}

/// Inspector for the first client → upstream payload chunk of a SOCKS session.
pub trait RelayGuard: Send + Sync + 'static {
    fn inspect(&self, target: &SocksTarget, first_chunk: &[u8]) -> GuardVerdict;
}

/// Why a SOCKS request failed; maps to SOCKS5 reply codes and log status labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    General,
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Failure {
    /// Classify an upstream dial error.
    pub fn from_dial_error(e: &io::Error) -> Self {
        if crate::filter::is_access_denied(e) {
            return Self::NotAllowed;
        }
        match e.kind() {
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut | io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            _ => Self::General,
        }
    }

    /// RFC 1928 `REP` code.
    pub fn socks5_reply(self) -> u8 {
        match self {
            Self::General => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }

    /// Status label written to the SOCKS log.
    pub fn label(self) -> &'static str {
        match self {
            Self::General => "general_failure",
            Self::NotAllowed => "not_allowed",
            Self::NetworkUnreachable => "network_unreachable",
            Self::HostUnreachable => "host_unreachable",
            Self::ConnectionRefused => "connection_refused",
            Self::CommandNotSupported => "command_not_supported",
            Self::AddressTypeNotSupported => "address_type_not_supported",
        }
    }
}

/// SOCKS4/4a/5 proxy engine. Cheap to clone.
#[derive(Clone)]
pub struct SocksProxy {
    pub(crate) access: AccessLogger,
    pub(crate) logger: Logger,
    pub(crate) dialer: Arc<dyn UpstreamDialer>,
    pub(crate) direction: ProxyDirection,
    pub(crate) connect_timeout: Duration,
    pub(crate) handshake_timeout: Duration,
    pub(crate) guard: Option<Arc<dyn RelayGuard>>,
}

impl fmt::Debug for SocksProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksProxy")
            .field("direction", &self.direction)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("guard", &self.guard.is_some())
            .finish_non_exhaustive()
    }
}

impl SocksProxy {
    pub fn new(access: AccessLogger, logger: Logger, dialer: Arc<dyn UpstreamDialer>) -> Self {
        Self {
            access,
            logger,
            dialer,
            direction: ProxyDirection::Forward,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            guard: None,
        }
    }

    /// Tag SOCKS log records emitted by this proxy with `direction`.
    pub fn with_direction(mut self, direction: ProxyDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Install a first-chunk relay guard (used by `--socks-block-web-in-mitm`).
    pub fn with_guard(mut self, guard: Arc<dyn RelayGuard>) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Override the upstream connect timeout (default 10s).
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the client handshake timeout (default 10s).
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Serve a connection whose SOCKS version byte has not been classified yet: peek it and
    /// dispatch to SOCKS4/4a or SOCKS5. Other first bytes close the connection.
    pub async fn serve(&self, conn: Connection) {
        let sniffed = tokio::select! {
            () = conn.shutdown.cancelled() => return,
            res = mux::sniff_protocol(&conn.stream, self.handshake_timeout) => res,
        };
        match sniffed {
            Ok(DetectedProtocol::Socks4) => self.serve_v4(conn).await,
            Ok(DetectedProtocol::Socks5) => self.serve_v5(conn).await,
            Ok(DetectedProtocol::Http) => self.logger.debug(format!(
                "rejected SOCKS connection from {}: HTTP request on SOCKS port",
                conn.peer
            )),
            Ok(DetectedProtocol::Unknown(b)) => self.logger.debug(format!(
                "rejected SOCKS connection from {}: unknown version byte 0x{b:02x}",
                conn.peer
            )),
            Err(e) => self
                .logger
                .debug(format!("rejected SOCKS connection from {}: {e}", conn.peer)),
        }
    }

    /// Serve a SOCKS4/4a connection (first byte `0x04`, unread).
    pub async fn serve_v4(&self, conn: Connection) {
        v4::serve(self, conn).await;
    }

    /// Serve a SOCKS5 connection (first byte `0x05`, unread).
    pub async fn serve_v5(&self, conn: Connection) {
        v5::serve(self, conn).await;
    }

    /// Run a handshake future bounded by the handshake timeout and the shutdown token.
    /// Returns `None` (after logging) on timeout or shutdown.
    pub(crate) async fn bounded<T>(
        &self,
        shutdown: &CancellationToken,
        peer: SocketAddr,
        what: &str,
        fut: impl std::future::Future<Output = T>,
    ) -> Option<T> {
        tokio::select! {
            () = shutdown.cancelled() => {
                self.logger.debug(format!("{what} from {peer} aborted by shutdown"));
                None
            }
            res = tokio::time::timeout(self.handshake_timeout, fut) => match res {
                Ok(v) => Some(v),
                Err(_) => {
                    self.logger.debug(format!(
                        "{what} from {peer} timed out after {}",
                        humantime::format_duration(self.handshake_timeout)
                    ));
                    None
                }
            },
        }
    }

    /// Relay an established session (optionally through the guard) and return the final
    /// `(status, bytes_in, bytes_out)`. `bytes_in` counts client → proxy payload bytes,
    /// `bytes_out` proxy → client payload bytes (handshake bytes excluded).
    pub(crate) async fn relay(
        &self,
        conn: &mut Connection,
        mut upstream: TcpStream,
        target: &SocksTarget,
    ) -> (String, u64, u64) {
        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));
        let peer = conn.peer;
        let shutdown = conn.shutdown.clone();
        let mut client = CountingStream::new(&mut conn.stream, bytes_in.clone(), bytes_out.clone());
        let guard = self.guard.clone();

        let work = async {
            if let Some(guard) = guard {
                if let GuardVerdict::Block { status } =
                    guarded_first_chunk(&mut client, &mut upstream, guard.as_ref(), target).await?
                {
                    return Ok(Some(status));
                }
            }
            relay_bidirectional(&mut client, &mut upstream).await?;
            Ok::<_, io::Error>(None)
        };
        let status = tokio::select! {
            res = work => match res {
                Ok(Some(blocked)) => {
                    self.logger.info(format!(
                        "SOCKS session {peer} -> {target} blocked: {blocked}"
                    ));
                    blocked
                }
                Ok(None) => "ok".to_string(),
                Err(e) => {
                    self.logger.debug(format!("SOCKS session {peer} -> {target} ended: {e}"));
                    "ok".to_string()
                }
            },
            () = shutdown.cancelled() => {
                self.logger.debug(format!("SOCKS session {peer} -> {target} closed by shutdown"));
                "ok".to_string()
            }
        };
        (
            status,
            bytes_in.load(Ordering::Relaxed),
            bytes_out.load(Ordering::Relaxed),
        )
    }
}

/// Forward upstream → client data while waiting for the first client chunk, then ask the
/// guard about it. Allowed chunks are written upstream before returning.
async fn guarded_first_chunk<C, U>(
    client: &mut C,
    upstream: &mut U,
    guard: &dyn RelayGuard,
    target: &SocksTarget,
) -> io::Result<GuardVerdict>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut cbuf = vec![0u8; GUARD_BUF_SIZE];
    let mut ubuf = vec![0u8; GUARD_BUF_SIZE];
    let mut upstream_eof = false;
    loop {
        tokio::select! {
            n = client.read(&mut cbuf) => {
                let n = n?;
                if n == 0 {
                    // Client half-closed without sending data: nothing to inspect.
                    return Ok(GuardVerdict::Allow);
                }
                let chunk = &cbuf[..n];
                let verdict = guard.inspect(target, chunk);
                if verdict == GuardVerdict::Allow {
                    upstream.write_all(chunk).await?;
                }
                return Ok(verdict);
            }
            n = upstream.read(&mut ubuf), if !upstream_eof => {
                let n = n?;
                if n == 0 {
                    upstream_eof = true;
                    client.shutdown().await?;
                } else {
                    client.write_all(&ubuf[..n]).await?;
                }
            }
        }
    }
}

/// Collects the fields of one [`SocksLogRecord`] across a session.
pub(crate) struct Session {
    ts: OffsetDateTime,
    start: Instant,
    direction: ProxyDirection,
    client: SocketAddr,
    pub(crate) proto: &'static str,
    pub(crate) cmd: String,
    pub(crate) target: String,
}

impl Session {
    pub(crate) fn new(client: SocketAddr, proto: &'static str, direction: ProxyDirection) -> Self {
        Self {
            ts: OffsetDateTime::now_utc(),
            start: Instant::now(),
            direction,
            client,
            proto,
            cmd: "-".into(),
            target: "-".into(),
        }
    }

    /// Emit the session's log record.
    pub(crate) async fn finish(self, access: &AccessLogger, status: &str, bin: u64, bout: u64) {
        let record = SocksLogRecord {
            ts: self.ts,
            direction: self.direction,
            client: self.client,
            proto: self.proto.into(),
            cmd: self.cmd,
            target: self.target,
            status: status.into(),
            bytes_in: bin,
            bytes_out: bout,
            duration_ms: u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        access.log_socks(&record).await;
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared helpers for SOCKS engine tests.

    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    use super::SocksProxy;
    use crate::server::Connection;

    /// Echo server on `bind` (e.g. `127.0.0.1:0` or `[::1]:0`).
    pub async fn spawn_echo(bind: &str) -> SocketAddr {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    /// Run `proxy.serve` (version sniffing) on an ephemeral loopback port.
    pub async fn spawn_socks(proxy: SocksProxy) -> SocketAddr {
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

    /// Send `payload` through an established tunnel, half-close, and read everything back.
    pub async fn echo_roundtrip(mut stream: TcpStream, payload: &[u8]) -> Vec<u8> {
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    }

    /// Unused port on 127.0.0.1 (bound then released).
    pub async fn closed_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::http::test_support::{capture_access, quiet_logger};

    use std::net::Ipv6Addr;

    struct BlockPrefix(&'static [u8]);

    impl RelayGuard for BlockPrefix {
        fn inspect(&self, _: &SocksTarget, first_chunk: &[u8]) -> GuardVerdict {
            if first_chunk.starts_with(self.0) {
                GuardVerdict::Block {
                    status: "blocked_web_in_mitm".into(),
                }
            } else {
                GuardVerdict::Allow
            }
        }
    }

    async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [5, 0]);
        let SocketAddr::V4(t) = target else { panic!() };
        let mut req = vec![5, 1, 0, 1];
        req.extend_from_slice(&t.ip().octets());
        req.extend_from_slice(&t.port().to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);
        s
    }

    #[test]
    fn target_display_and_dial_host() {
        let v6 = SocksTarget {
            host: TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: 22,
        };
        assert_eq!(v6.to_string(), "[::1]:22");
        assert_eq!(v6.dial_host(), "::1");
        let d = SocksTarget {
            host: TargetHost::Domain("example.com".into()),
            port: 443,
        };
        assert_eq!(d.to_string(), "example.com:443");
    }

    #[test]
    fn dial_error_classification() {
        use io::ErrorKind::*;
        let f = |k| Failure::from_dial_error(&io::Error::from(k));
        assert_eq!(f(ConnectionRefused).socks5_reply(), 0x05);
        assert_eq!(f(TimedOut).socks5_reply(), 0x04);
        assert_eq!(f(HostUnreachable).socks5_reply(), 0x04);
        assert_eq!(f(NetworkUnreachable).socks5_reply(), 0x03);
        assert_eq!(f(PermissionDenied).socks5_reply(), 0x01);
    }

    #[tokio::test]
    async fn guard_blocks_matching_first_chunk() {
        let echo = spawn_echo("127.0.0.1:0").await;
        let (access, log) = capture_access().await;
        let proxy = SocksProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        )
        .with_guard(Arc::new(BlockPrefix(b"GET ")));
        let addr = spawn_socks(proxy).await;

        let s = socks5_connect(addr, echo).await;
        let out = echo_roundtrip(s, b"GET / HTTP/1.1\r\n\r\n").await;
        assert!(out.is_empty(), "blocked chunk must not be echoed: {out:?}");
        let lines = log.wait_lines(1).await;
        assert!(lines[0].contains("status=blocked_web_in_mitm"), "{lines:?}");
    }

    #[tokio::test]
    async fn guard_allows_other_traffic_and_server_first_bytes() {
        // Server-speaks-first upstream: sends a banner before reading anything.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let banner_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-test\r\n").await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
        });
        let (access, log) = capture_access().await;
        let proxy = SocksProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        )
        .with_guard(Arc::new(BlockPrefix(b"GET ")));
        let addr = spawn_socks(proxy).await;

        let mut s = socks5_connect(addr, banner_addr).await;
        let mut banner = [0u8; 14];
        s.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-test\r\n");
        let out = echo_roundtrip(s, b"SSH-2.0-client\r\n").await;
        assert_eq!(out, b"SSH-2.0-client\r\n");
        let lines = log.wait_lines(1).await;
        assert!(lines[0].contains("status=ok"), "{lines:?}");
        assert!(lines[0].contains("bytes_in=16 bytes_out=30"), "{lines:?}");
    }
}
