//! SOCKS5 (RFC 1928) `CONNECT` with No-Auth.
//!
//! 1. Greeting `VER=0x05 | NMETHODS | METHODS…`: method `0x00` (No Authentication) is
//!    selected; if the client does not offer it the reply is `0x05 0xFF` and the
//!    connection is closed.
//! 2. Request `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT` with `ATYP` IPv4 (`0x01`),
//!    Domain (`0x03`), or IPv6 (`0x04`). Only `CONNECT` (`0x01`) is supported; `BIND` and
//!    `UDP ASSOCIATE` get `0x07`, unknown address types `0x08`.
//! 3. Reply `VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`; upstream dial failures map to
//!    `0x01` general, `0x03` network unreachable, `0x04` host unreachable, or `0x05`
//!    connection refused.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Failure, Session, SocksProxy, SocksTarget, TargetHost};
use crate::server::Connection;

pub const VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const REPLY_SUCCEEDED: u8 = 0x00;

/// Malformed SOCKS5 handshakes.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("unexpected SOCKS version 0x{0:02x}")]
    Version(u8),
    #[error("address type 0x{0:02x} not supported")]
    AddressType(u8),
    #[error("domain name is empty or not valid UTF-8")]
    BadDomain,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A parsed SOCKS5 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub cmd: u8,
    pub target: SocksTarget,
}

/// Read the method-selection greeting; returns `true` if No-Auth was offered.
pub async fn read_greeting<R: AsyncRead + Unpin>(r: &mut R) -> Result<bool, RequestError> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(RequestError::Version(head[0]));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    r.read_exact(&mut methods).await?;
    Ok(methods.contains(&METHOD_NO_AUTH))
}

/// Read a request. On [`RequestError::AddressType`] the command byte is returned alongside.
pub async fn read_request<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Request, (Option<u8>, RequestError)> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head)
        .await
        .map_err(|e| (None, e.into()))?;
    if head[0] != VERSION {
        return Err((None, RequestError::Version(head[0])));
    }
    let cmd = head[1];
    let wrap = |e: io::Error| (Some(cmd), RequestError::from(e));
    let host = match head[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a).await.map_err(wrap)?;
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::from(a)))
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a).await.map_err(wrap)?;
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::from(a)))
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await.map_err(wrap)?;
            let mut d = vec![0u8; usize::from(len)];
            r.read_exact(&mut d).await.map_err(wrap)?;
            match String::from_utf8(d) {
                Ok(d) if !d.is_empty() => TargetHost::Domain(d),
                _ => return Err((Some(cmd), RequestError::BadDomain)),
            }
        }
        other => return Err((Some(cmd), RequestError::AddressType(other))),
    };
    let port = r.read_u16().await.map_err(wrap)?;
    Ok(Request {
        cmd,
        target: SocksTarget { host, port },
    })
}

/// Encode a reply with the given `REP` code and bound address (`0.0.0.0:0` if `None`).
pub fn reply(rep: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let bound = bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut out = vec![VERSION, rep, 0x00];
    match bound.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    out
}

fn cmd_label(cmd: u8) -> String {
    match cmd {
        CMD_CONNECT => "CONNECT".into(),
        CMD_BIND => "BIND".into(),
        CMD_UDP_ASSOCIATE => "UDP_ASSOCIATE".into(),
        other => format!("0x{other:02x}"),
    }
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) {
    let _ = w.write_all(bytes).await;
}

pub(super) async fn serve(proxy: &SocksProxy, mut conn: Connection) {
    let peer = conn.peer;
    let logger = &proxy.logger;
    let shutdown = conn.shutdown.clone();
    let mut session = Session::new(peer, "socks5");

    // Method negotiation + request, bounded together by the handshake timeout.
    let handshake = async {
        let stream = &mut conn.stream;
        match read_greeting(stream).await {
            Ok(true) => {}
            Ok(false) => {
                send(stream, &[VERSION, METHOD_NONE_ACCEPTABLE]).await;
                return Err(Some("no_acceptable_auth"));
            }
            Err(e) => {
                logger.debug(format!("invalid SOCKS5 greeting from {peer}: {e}"));
                return Err(None);
            }
        }
        if stream.write_all(&[VERSION, METHOD_NO_AUTH]).await.is_err() {
            return Err(None);
        }
        match read_request(stream).await {
            Ok(req) => Ok(req),
            Err((cmd, e)) => {
                logger.debug(format!("invalid SOCKS5 request from {peer}: {e}"));
                let failure = match e {
                    RequestError::AddressType(_) => Failure::AddressTypeNotSupported,
                    RequestError::BadDomain => Failure::General,
                    _ => return Err(None),
                };
                send(stream, &reply(failure.socks5_reply(), None)).await;
                session.cmd = cmd.map_or_else(|| "-".into(), cmd_label);
                Err(Some(failure.label()))
            }
        }
    };
    let req = match proxy
        .bounded(&shutdown, peer, "SOCKS5 handshake", handshake)
        .await
    {
        None | Some(Err(None)) => return,
        Some(Err(Some(status))) => {
            session.finish(&proxy.access, status, 0, 0).await;
            return;
        }
        Some(Ok(req)) => req,
    };

    session.cmd = cmd_label(req.cmd);
    session.target = req.target.to_string();
    logger.debug(format!("socks5 {} {} from {peer}", session.cmd, req.target));

    if req.cmd != CMD_CONNECT {
        let failure = Failure::CommandNotSupported;
        send(&mut conn.stream, &reply(failure.socks5_reply(), None)).await;
        session.finish(&proxy.access, failure.label(), 0, 0).await;
        return;
    }

    let dial_host = req.target.dial_host();
    let dial = proxy
        .dialer
        .connect(&dial_host, req.target.port, proxy.connect_timeout);
    let upstream = tokio::select! {
        () = shutdown.cancelled() => return,
        res = dial => res,
    };
    let upstream = match upstream {
        Ok(u) => u,
        Err(e) => {
            logger.error(format!("SOCKS5 upstream {} failed: {e}", req.target));
            let failure = Failure::from_dial_error(&e);
            send(&mut conn.stream, &reply(failure.socks5_reply(), None)).await;
            session.finish(&proxy.access, failure.label(), 0, 0).await;
            return;
        }
    };
    if let Err(e) = conn
        .stream
        .write_all(&reply(REPLY_SUCCEEDED, upstream.local_addr().ok()))
        .await
    {
        logger.debug(format!("SOCKS5 reply to {peer} failed: {e}"));
        session.finish(&proxy.access, "ok", 0, 0).await;
        return;
    }
    let (status, bin, bout) = proxy.relay(&mut conn, upstream, &req.target).await;
    session.finish(&proxy.access, &status, bin, bout).await;
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::http::test_support::{capture_access, quiet_logger};

    use tokio::net::TcpStream;

    async fn negotiate(proxy: SocketAddr) -> TcpStream {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(&[VERSION, 2, 0x02, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [VERSION, METHOD_NO_AUTH]);
        s
    }

    /// Send a request and read the reply (whose length depends on its ATYP).
    async fn request(s: &mut TcpStream, cmd: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut req = vec![VERSION, cmd, 0, atyp];
        req.extend_from_slice(addr);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let alen = if head[3] == ATYP_IPV6 { 16 } else { 4 };
        let mut rest = vec![0u8; alen + 2];
        s.read_exact(&mut rest).await.unwrap();
        let mut out = head.to_vec();
        out.extend(rest);
        out
    }

    async fn setup() -> (SocketAddr, crate::http::test_support::Buf) {
        let (access, log) = capture_access().await;
        (
            spawn_socks(SocksProxy::new(
                access,
                quiet_logger(),
                crate::http::test_support::direct_dialer(),
            ))
            .await,
            log,
        )
    }

    #[test]
    fn reply_encoding() {
        assert_eq!(reply(0x07, None), vec![5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        let v6 = reply(0, Some("[::1]:258".parse().unwrap()));
        assert_eq!(v6.len(), 22);
        assert_eq!((v6[3], &v6[20..]), (ATYP_IPV6, &[1u8, 2][..]));
    }

    #[tokio::test]
    async fn socks5_ipv4_connect() {
        let echo = spawn_echo("127.0.0.1:0").await;
        let (addr, log) = setup().await;
        let mut s = negotiate(addr).await;
        let rep = request(&mut s, CMD_CONNECT, ATYP_IPV4, &[127, 0, 0, 1], echo.port()).await;
        assert_eq!(rep[1], REPLY_SUCCEEDED);
        assert_eq!(echo_roundtrip(s, b"ipv4 data").await, b"ipv4 data");
        let lines = log.wait_lines(1).await;
        let expected = format!(
            "proto=socks5 cmd=CONNECT target=127.0.0.1:{} status=ok bytes_in=9 bytes_out=9",
            echo.port()
        );
        assert!(lines[0].contains(&expected), "{lines:?}");
    }

    #[tokio::test]
    async fn socks5_ipv6_connect() {
        let echo = spawn_echo("[::1]:0").await;
        let (addr, log) = setup().await;
        let mut s = negotiate(addr).await;
        let rep = request(
            &mut s,
            CMD_CONNECT,
            ATYP_IPV6,
            &Ipv6Addr::LOCALHOST.octets(),
            echo.port(),
        )
        .await;
        assert_eq!(rep[1], REPLY_SUCCEEDED);
        assert_eq!(echo_roundtrip(s, b"ipv6 data").await, b"ipv6 data");
        let lines = log.wait_lines(1).await;
        let expected = format!("cmd=CONNECT target=[::1]:{} status=ok", echo.port());
        assert!(lines[0].contains(&expected), "{lines:?}");
    }

    #[tokio::test]
    async fn socks5_domain_connect() {
        let echo = spawn_echo("127.0.0.1:0").await;
        let (addr, log) = setup().await;
        let mut s = negotiate(addr).await;
        let mut dom = vec![9u8];
        dom.extend_from_slice(b"localhost");
        let rep = request(&mut s, CMD_CONNECT, ATYP_DOMAIN, &dom, echo.port()).await;
        assert_eq!(rep[1], REPLY_SUCCEEDED);
        assert_eq!(echo_roundtrip(s, b"domain").await, b"domain");
        let lines = log.wait_lines(1).await;
        let expected = format!("target=localhost:{} status=ok", echo.port());
        assert!(lines[0].contains(&expected), "{lines:?}");
    }

    #[tokio::test]
    async fn socks5_udp_associate_and_bind_not_supported() {
        let (addr, log) = setup().await;
        for cmd in [CMD_UDP_ASSOCIATE, CMD_BIND] {
            let mut s = negotiate(addr).await;
            let rep = request(&mut s, cmd, ATYP_IPV4, &[127, 0, 0, 1], 53).await;
            assert_eq!(rep[1], 0x07);
        }
        let lines = log.wait_lines(2).await;
        assert!(
            lines.iter().any(|l| l
                .contains("cmd=UDP_ASSOCIATE target=127.0.0.1:53 status=command_not_supported")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("cmd=BIND target=127.0.0.1:53 status=command_not_supported")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn socks5_rejects_without_no_auth_method() {
        let (addr, log) = setup().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[VERSION, 1, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [VERSION, METHOD_NONE_ACCEPTABLE]);
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        let lines = log.wait_lines(1).await;
        assert!(lines[0].contains("status=no_acceptable_auth"), "{lines:?}");
    }

    #[tokio::test]
    async fn socks5_unknown_address_type() {
        let (addr, log) = setup().await;
        let mut s = negotiate(addr).await;
        s.write_all(&[VERSION, CMD_CONNECT, 0, 0x09]).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x08);
        let lines = log.wait_lines(1).await;
        assert!(
            lines[0].contains("cmd=CONNECT target=- status=address_type_not_supported"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn socks5_connection_refused() {
        let port = closed_port().await;
        let (addr, log) = setup().await;
        let mut s = negotiate(addr).await;
        let rep = request(&mut s, CMD_CONNECT, ATYP_IPV4, &[127, 0, 0, 1], port).await;
        assert_eq!(rep[1], 0x05);
        let lines = log.wait_lines(1).await;
        assert!(lines[0].contains("status=connection_refused"), "{lines:?}");
    }
}
