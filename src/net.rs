//! Shared upstream dial and relay utilities.
//!
//! Every upstream TCP connection goes through an [`UpstreamDialer`]. In production that is
//! [`Socks5UpstreamDialer`], which speaks RFC 1928 to the local `ssh -D` listener and sends
//! hostnames as `ATYP=0x03`, so DNS is resolved on the SSH target and never locally.
//! [`DirectDialer`] connects from this machine using its resolver. It backs the reverse proxy
//! (`ssh -R`), whose clients egress locally, and isolated tests.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::filter::{access_denied_error, normalize_domain, AccessDenied, HostFilter};

/// Default timeout for establishing an upstream TCP connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Live state of the SSH dynamic tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// `ssh` is starting and its SOCKS listener is not yet usable.
    Connecting,
    /// The SOCKS listener at this address is accepting connections.
    Ready(SocketAddr),
    /// The tunnel is down, for the given reason.
    Disconnected(String),
}

/// Boxed future returned by [`UpstreamDialer::connect`].
pub type DialFuture<'a> = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'a>>;

/// Opens upstream TCP connections.
pub trait UpstreamDialer: Send + Sync {
    /// Connect to `host:port`, bounding the whole operation by `timeout`.
    ///
    /// `host` may be a DNS name or an IP literal (IPv6 with or without brackets).
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_>;
}

/// Dials targets directly from this machine using the OS resolver.
///
/// Used for reverse proxy egress, where routing through [`Socks5UpstreamDialer`] would loop
/// traffic back to the SSH target, and by isolated tests. When a [`HostFilter`] is attached,
/// both domain names and resolved IP addresses are checked before connecting.
#[derive(Debug, Clone, Default)]
pub struct DirectDialer {
    filter: Option<Arc<HostFilter>>,
}

impl DirectDialer {
    /// Create a direct dialer that enforces `filter` on both domain names and resolved IPs.
    pub fn with_filter(filter: Arc<HostFilter>) -> Self {
        Self {
            filter: Some(filter),
        }
    }
}

impl UpstreamDialer for DirectDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = strip_brackets(host).to_owned();
        let filter = self.filter.clone();
        Box::pin(async move {
            let Some(filter) = filter else {
                let stream =
                    tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port)))
                        .await
                        .map_err(|_| timed_out(&host, port, timeout))??;
                stream.set_nodelay(true)?;
                return Ok(stream);
            };

            let deadline = Instant::now() + timeout;
            if let Ok(ip) = host.parse::<IpAddr>() {
                filter.check_ip(ip).map_err(access_denied_error)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                let stream =
                    tokio::time::timeout(remaining, TcpStream::connect(SocketAddr::new(ip, port)))
                        .await
                        .map_err(|_| timed_out(&host, port, timeout))??;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }

            let domain = normalize_domain(&host);
            let domain_matched = filter.matches_domain(&domain);
            match filter.as_ref() {
                HostFilter::Block(_) if domain_matched => {
                    return Err(access_denied_error(AccessDenied(format!(
                        "destination {host} is blocklisted"
                    ))));
                }
                HostFilter::Allow(_) if !domain_matched && !filter.has_ip_rules() => {
                    return Err(access_denied_error(AccessDenied(format!(
                        "destination {host} is not in allowlist"
                    ))));
                }
                _ => {}
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let resolved: Vec<SocketAddr> =
                tokio::time::timeout(remaining, lookup_host((host.as_str(), port)))
                    .await
                    .map_err(|_| timed_out(&host, port, timeout))??
                    .collect();
            if resolved.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("DNS returned no addresses for {host}"),
                ));
            }

            let candidates: Vec<SocketAddr> = match filter.as_ref() {
                HostFilter::Block(_) => {
                    if let Some(blocked) = resolved.iter().find(|a| filter.matches_ip(a.ip())) {
                        return Err(access_denied_error(AccessDenied(format!(
                            "destination {host} resolved to blocklisted IP {}",
                            blocked.ip()
                        ))));
                    }
                    resolved
                }
                HostFilter::Allow(_) if domain_matched => resolved,
                HostFilter::Allow(_) => {
                    let allowed: Vec<SocketAddr> = resolved
                        .into_iter()
                        .filter(|a| filter.matches_ip(a.ip()))
                        .collect();
                    if allowed.is_empty() {
                        return Err(access_denied_error(AccessDenied(format!(
                            "destination {host} is not in allowlist"
                        ))));
                    }
                    allowed
                }
            };

            let mut last_err = None;
            for addr in candidates {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(timed_out(&host, port, timeout));
                }
                match tokio::time::timeout(remaining, TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => {
                        stream.set_nodelay(true)?;
                        return Ok(stream);
                    }
                    Ok(Err(e)) => last_err = Some(e),
                    Err(_) => return Err(timed_out(&host, port, timeout)),
                }
            }
            Err(last_err.unwrap_or_else(|| timed_out(&host, port, timeout)))
        })
    }
}

/// Wraps an [`UpstreamDialer`] and enforces a [`HostFilter`] on the requested host before
/// dialing (without performing any local DNS lookups).
pub struct FilteredDialer {
    inner: Arc<dyn UpstreamDialer>,
    filter: Arc<HostFilter>,
}

impl FilteredDialer {
    pub fn new(inner: Arc<dyn UpstreamDialer>, filter: Arc<HostFilter>) -> Self {
        Self { inner, filter }
    }
}

impl UpstreamDialer for FilteredDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        if let Err(denied) = self.filter.check_host(host) {
            return Box::pin(async move { Err(access_denied_error(denied)) });
        }
        self.inner.connect(host, port, timeout)
    }
}

/// Dials targets through the SOCKS5 listener published by the SSH supervisor.
#[derive(Debug, Clone)]
pub struct Socks5UpstreamDialer {
    state: watch::Receiver<TunnelState>,
}

impl Socks5UpstreamDialer {
    /// Create a dialer that follows the given tunnel state.
    pub fn new(state: watch::Receiver<TunnelState>) -> Self {
        Self { state }
    }
}

impl UpstreamDialer for Socks5UpstreamDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_owned();
        Box::pin(async move {
            let current = self.state.borrow().clone();
            let proxy = match current {
                TunnelState::Ready(addr) => addr,
                TunnelState::Connecting => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "SSH tunnel is still connecting",
                    ));
                }
                TunnelState::Disconnected(reason) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        format!("SSH tunnel is disconnected: {reason}"),
                    ));
                }
            };
            let request = encode_connect_request(&host, port)?;
            tokio::time::timeout(timeout, socks5_connect(proxy, &request))
                .await
                .map_err(|_| timed_out(&host, port, timeout))?
        })
    }
}

/// Relay bytes in both directions until both sides reach EOF (or either side errors).
///
/// Returns `(bytes_in, bytes_out)`: bytes read from `client` and written to `upstream`, and
/// bytes read from `upstream` and written to `client`. Data is never retained.
pub async fn relay_bidirectional<C, U>(client: &mut C, upstream: &mut U) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin + ?Sized,
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional(client, upstream).await
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

fn timed_out(host: &str, port: u16, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "connect to {host}:{port} timed out after {}",
            humantime::format_duration(timeout)
        ),
    )
}

/// Build the RFC 1928 `CONNECT` request. Non-literal hosts are always sent as `ATYP=0x03`.
fn encode_connect_request(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    let bracketed = host.starts_with('[') || host.ends_with(']');
    let bare = strip_brackets(host);
    if bracketed && bare.parse::<Ipv6Addr>().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid bracketed IPv6 literal: {host:?}"),
        ));
    }
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let len = u8::try_from(bare.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("SOCKS5 domain must be 1-255 bytes, got {}", bare.len()),
                    )
                })?;
            request.push(ATYP_DOMAIN);
            request.push(len);
            request.extend_from_slice(bare.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// Map a non-zero SOCKS5 reply code to an [`io::Error`].
fn reply_error(code: u8) -> io::Error {
    let (kind, message) = match code {
        0x01 => (io::ErrorKind::Other, "general SOCKS server failure"),
        0x02 => (
            io::ErrorKind::PermissionDenied,
            "connection not allowed by ruleset",
        ),
        0x03 => (io::ErrorKind::NetworkUnreachable, "network unreachable"),
        0x04 => (io::ErrorKind::HostUnreachable, "host unreachable"),
        0x05 => (io::ErrorKind::ConnectionRefused, "connection refused"),
        0x06 => (io::ErrorKind::TimedOut, "TTL expired"),
        0x07 => (io::ErrorKind::Unsupported, "command not supported"),
        0x08 => (io::ErrorKind::Unsupported, "address type not supported"),
        _ => (io::ErrorKind::Other, "unknown SOCKS5 reply"),
    };
    io::Error::new(kind, format!("SOCKS5 upstream: {message} (0x{code:02x})"))
}

async fn socks5_connect(proxy: SocketAddr, request: &[u8]) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;

    stream
        .write_all(&[SOCKS_VERSION, 0x01, METHOD_NO_AUTH])
        .await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "unexpected SOCKS version 0x{:02x} in method reply",
            choice[0]
        )));
    }
    if choice[1] != METHOD_NO_AUTH {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("SOCKS5 proxy refused no-auth method (0x{:02x})", choice[1]),
        ));
    }

    stream.write_all(request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "unexpected SOCKS version 0x{:02x} in connect reply",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(reply_error(head[1]));
    }

    // Consume BND.ADDR and BND.PORT so the caller's stream starts at the first payload byte.
    let addr_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => usize::from(stream.read_u8().await?),
        other => {
            return Err(invalid_data(format!(
                "unknown SOCKS5 bound address type 0x{other:02x}"
            )));
        }
    };
    let mut bound = [0u8; 257];
    stream.read_exact(&mut bound[..addr_len + 2]).await?;
    Ok(stream)
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    const T: Duration = Duration::from_secs(5);

    /// One-shot SOCKS5 server: returns the raw CONNECT request it received.
    async fn mock_socks(reply: Vec<u8>) -> (SocketAddr, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = vec![0u8; 4];
            sock.read_exact(&mut request).await.unwrap();
            let rest = match request[3] {
                ATYP_IPV4 => 6,
                ATYP_IPV6 => 18,
                ATYP_DOMAIN => {
                    let len = sock.read_u8().await.unwrap();
                    request.push(len);
                    usize::from(len) + 2
                }
                other => panic!("bad atyp {other}"),
            };
            let start = request.len();
            request.resize(start + rest, 0);
            sock.read_exact(&mut request[start..]).await.unwrap();

            sock.write_all(&reply).await.unwrap();
            sock.write_all(b"hello").await.unwrap();
            sock.shutdown().await.unwrap();
            request
        });
        (addr, task)
    }

    fn dialer(addr: SocketAddr) -> (watch::Sender<TunnelState>, Socks5UpstreamDialer) {
        let (tx, rx) = watch::channel(TunnelState::Ready(addr));
        (tx, Socks5UpstreamDialer::new(rx))
    }

    fn ok_reply() -> Vec<u8> {
        vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]
    }

    async fn assert_payload(mut stream: TcpStream) {
        assert!(stream.nodelay().unwrap());
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn dials_ipv4_literal_with_atyp_1() {
        let (addr, server) = mock_socks(ok_reply()).await;
        let (_tx, d) = dialer(addr);
        assert_payload(d.connect("192.0.2.7", 443, T).await.unwrap()).await;
        assert_eq!(
            server.await.unwrap(),
            [5, 1, 0, 1, 192, 0, 2, 7, 0x01, 0xbb]
        );
    }

    #[tokio::test]
    async fn dials_ipv6_literal_with_atyp_4() {
        for host in ["2001:db8::1", "[2001:db8::1]"] {
            let (addr, server) = mock_socks(ok_reply()).await;
            let (_tx, d) = dialer(addr);
            assert_payload(d.connect(host, 80, T).await.unwrap()).await;
            let mut expected = vec![5, 1, 0, 4];
            expected.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            expected.extend_from_slice(&[0, 80]);
            assert_eq!(server.await.unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn sends_hostname_as_atyp_3_for_remote_dns() {
        let (addr, server) = mock_socks(ok_reply()).await;
        let (_tx, d) = dialer(addr);
        // `.invalid` can never resolve locally, so success proves no local lookup happened.
        assert_payload(d.connect("target.invalid", 8080, T).await.unwrap()).await;
        let mut expected = vec![5, 1, 0, 3, 14];
        expected.extend_from_slice(b"target.invalid");
        expected.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(server.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn consumes_every_bound_address_form() {
        let mut domain = vec![0x05, 0x00, 0x00, 0x03, 4];
        domain.extend_from_slice(b"bind\x00\x50");
        let mut v6 = vec![0x05, 0x00, 0x00, 0x04];
        v6.extend_from_slice(&[0u8; 18]);
        for reply in [domain, v6] {
            let (addr, server) = mock_socks(reply).await;
            let (_tx, d) = dialer(addr);
            assert_payload(d.connect("example.test", 80, T).await.unwrap()).await;
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn maps_reply_codes_to_error_kinds() {
        let cases = [
            (0x01, io::ErrorKind::Other),
            (0x02, io::ErrorKind::PermissionDenied),
            (0x03, io::ErrorKind::NetworkUnreachable),
            (0x04, io::ErrorKind::HostUnreachable),
            (0x05, io::ErrorKind::ConnectionRefused),
            (0x06, io::ErrorKind::TimedOut),
            (0x07, io::ErrorKind::Unsupported),
            (0x08, io::ErrorKind::Unsupported),
            (0x7f, io::ErrorKind::Other),
        ];
        for (code, kind) in cases {
            let (addr, server) = mock_socks(vec![0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            let (_tx, d) = dialer(addr);
            let err = d.connect("example.test", 80, T).await.unwrap_err();
            assert_eq!(err.kind(), kind, "reply 0x{code:02x}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_refused_auth_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            sock.write_all(&[0x05, 0xff]).await.unwrap();
        });
        let (_tx, d) = dialer(addr);
        let err = d.connect("example.test", 80, T).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn times_out_on_silent_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (_tx, d) = dialer(addr);
        let err = d
            .connect("example.test", 80, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(listener);
    }

    #[tokio::test]
    async fn errors_when_tunnel_is_not_ready() {
        for state in [
            TunnelState::Connecting,
            TunnelState::Disconnected("ssh exited".into()),
        ] {
            let (_tx, rx) = watch::channel(state);
            let d = Socks5UpstreamDialer::new(rx);
            let err = d.connect("example.test", 80, T).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        }
    }

    #[test]
    fn rejects_unencodable_hosts() {
        for host in [String::new(), "a".repeat(256), "[not-ipv6]".to_owned()] {
            let err = encode_connect_request(&host, 80).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(encode_connect_request(&"a".repeat(255), 80).is_ok());
    }

    #[tokio::test]
    async fn direct_dialer_and_relay_count_bytes() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            sock.write_all(&[b'r'; 2500]).await.unwrap();
            sock.shutdown().await.unwrap();
            received
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (mut client, _) = front.accept().await.unwrap();
            let mut up = DirectDialer::default()
                .connect("127.0.0.1", upstream_addr.port(), T)
                .await
                .unwrap();
            assert!(up.nodelay().unwrap());
            relay_bidirectional(&mut client, &mut up).await.unwrap()
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(&[b'q'; 1234]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();

        assert_eq!(relay.await.unwrap(), (1234, 2500));
        assert_eq!(upstream_task.await.unwrap(), vec![b'q'; 1234]);
        assert_eq!(reply, vec![b'r'; 2500]);
    }
}
