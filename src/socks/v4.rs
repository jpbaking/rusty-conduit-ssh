//! SOCKS4 and SOCKS4a `CONNECT`.
//!
//! Request: `VN=0x04 | CD | DSTPORT(2) | DSTIP(4) | USERID | 0x00`, followed for SOCKS4a
//! (`DSTIP = 0.0.0.x`, `x != 0`) by `DOMAIN | 0x00`. The user ID is metadata only (never
//! authenticated). Only `CD=0x01` (`CONNECT`) is supported; everything else, and every
//! upstream failure, is answered with `0x5B` (request rejected or failed).
//!
//! Reply: `VN=0x00 | CD (0x5A granted / 0x5B rejected) | DSTPORT(2) | DSTIP(4)`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::{Failure, Session, SocksProxy, SocksTarget, TargetHost, MAX_CSTRING_LEN};
use crate::server::Connection;

pub const VERSION: u8 = 0x04;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const REPLY_GRANTED: u8 = 0x5A;
pub const REPLY_REJECTED: u8 = 0x5B;

/// A parsed SOCKS4/4a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub cmd: u8,
    pub target: SocksTarget,
    pub user_id: String,
    /// `true` when the domain-name (SOCKS4a) form was used.
    pub socks4a: bool,
}

/// Malformed SOCKS4 handshakes.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("unexpected SOCKS version 0x{0:02x}")]
    Version(u8),
    #[error("{0} exceeds {MAX_CSTRING_LEN} bytes")]
    TooLong(&'static str),
    #[error("SOCKS4a domain name is empty or not valid UTF-8")]
    BadDomain,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Read a null-terminated string byte by byte so no post-handshake payload is consumed.
async fn read_cstring<R: AsyncRead + Unpin>(
    r: &mut R,
    what: &'static str,
) -> Result<Vec<u8>, RequestError> {
    let mut out = Vec::new();
    loop {
        let b = r.read_u8().await?;
        if b == 0 {
            return Ok(out);
        }
        if out.len() == MAX_CSTRING_LEN {
            return Err(RequestError::TooLong(what));
        }
        out.push(b);
    }
}

/// Read one SOCKS4/4a request (including the version byte).
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request, RequestError> {
    let mut head = [0u8; 8];
    r.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(RequestError::Version(head[0]));
    }
    let cmd = head[1];
    let port = u16::from_be_bytes([head[2], head[3]]);
    let ip = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
    let user_id = String::from_utf8_lossy(&read_cstring(r, "user ID").await?).into_owned();
    let socks4a = head[4..7] == [0, 0, 0] && head[7] != 0;
    let host = if socks4a {
        let raw = read_cstring(r, "SOCKS4a domain").await?;
        match String::from_utf8(raw) {
            Ok(d) if !d.is_empty() => TargetHost::Domain(d),
            _ => return Err(RequestError::BadDomain),
        }
    } else {
        TargetHost::Ip(IpAddr::V4(ip))
    };
    Ok(Request {
        cmd,
        target: SocksTarget { host, port },
        user_id,
        socks4a,
    })
}

/// Encode a SOCKS4 reply.
pub fn reply(code: u8, bound: Option<SocketAddr>) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[1] = code;
    if let Some(SocketAddr::V4(a)) = bound {
        out[2..4].copy_from_slice(&a.port().to_be_bytes());
        out[4..8].copy_from_slice(&a.ip().octets());
    }
    out
}

fn cmd_label(cmd: u8) -> String {
    match cmd {
        CMD_CONNECT => "CONNECT".into(),
        CMD_BIND => "BIND".into(),
        other => format!("0x{other:02x}"),
    }
}

pub(super) async fn serve(proxy: &SocksProxy, mut conn: Connection) {
    let peer = conn.peer;
    let logger = &proxy.logger;
    let shutdown = conn.shutdown.clone();
    let handshake = read_request(&mut conn.stream);
    let req = match proxy
        .bounded(&shutdown, peer, "SOCKS4 handshake", handshake)
        .await
    {
        None => return,
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            logger.debug(format!("invalid SOCKS4 request from {peer}: {e}"));
            let _ = conn.stream.write_all(&reply(REPLY_REJECTED, None)).await;
            return;
        }
    };

    let mut session = Session::new(
        peer,
        if req.socks4a { "socks4a" } else { "socks4" },
        proxy.direction,
    );
    session.cmd = cmd_label(req.cmd);
    session.target = req.target.to_string();
    logger.debug(format!(
        "{} {} {} from {peer} (user id {:?})",
        session.proto, session.cmd, req.target, req.user_id
    ));

    if req.cmd != CMD_CONNECT {
        let _ = conn.stream.write_all(&reply(REPLY_REJECTED, None)).await;
        session
            .finish(&proxy.access, Failure::CommandNotSupported.label(), 0, 0)
            .await;
        return;
    }

    let dial_host = req.target.dial_host();
    let dial = proxy
        .dialer
        .connect(&dial_host, req.target.port, proxy.connect_timeout);
    let upstream = tokio::select! {
        () = conn.shutdown.cancelled() => return,
        res = dial => res,
    };
    let upstream = match upstream {
        Ok(u) => u,
        Err(e) => {
            logger.error(format!("SOCKS4 upstream {} failed: {e}", req.target));
            let _ = conn.stream.write_all(&reply(REPLY_REJECTED, None)).await;
            session
                .finish(&proxy.access, Failure::from_dial_error(&e).label(), 0, 0)
                .await;
            return;
        }
    };
    if let Err(e) = conn
        .stream
        .write_all(&reply(REPLY_GRANTED, upstream.local_addr().ok()))
        .await
    {
        logger.debug(format!("SOCKS4 reply to {peer} failed: {e}"));
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

    fn v4_request(cmd: u8, port: u16, ip: [u8; 4], user: &[u8], domain: Option<&[u8]>) -> Vec<u8> {
        let mut req = vec![VERSION, cmd];
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip);
        req.extend_from_slice(user);
        req.push(0);
        if let Some(d) = domain {
            req.extend_from_slice(d);
            req.push(0);
        }
        req
    }

    async fn send(proxy: std::net::SocketAddr, req: &[u8]) -> (TcpStream, [u8; 8]) {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut rep = [0u8; 8];
        s.read_exact(&mut rep).await.unwrap();
        (s, rep)
    }

    #[tokio::test]
    async fn parses_socks4a_request() {
        let raw = v4_request(1, 80, [0, 0, 0, 7], b"alice", Some(b"example.com"));
        let req = read_request(&mut raw.as_slice()).await.unwrap();
        assert!(req.socks4a);
        assert_eq!(req.user_id, "alice");
        assert_eq!(req.target.to_string(), "example.com:80");
        // 0.0.0.0 is a plain (invalid) IPv4 target, not SOCKS4a.
        let raw = v4_request(1, 80, [0, 0, 0, 0], b"", None);
        assert!(!read_request(&mut raw.as_slice()).await.unwrap().socks4a);
        let long = vec![b'a'; 300];
        let raw = v4_request(1, 80, [1, 2, 3, 4], &long, None);
        assert!(matches!(
            read_request(&mut raw.as_slice()).await,
            Err(RequestError::TooLong(_))
        ));
    }

    #[tokio::test]
    async fn socks4_ipv4_connect_relays_and_logs() {
        let echo = spawn_echo("127.0.0.1:0").await;
        let (access, log) = capture_access().await;
        let addr = spawn_socks(SocksProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let req = v4_request(CMD_CONNECT, echo.port(), [127, 0, 0, 1], b"bob", None);
        let (s, rep) = send(addr, &req).await;
        assert_eq!(rep[0], 0x00);
        assert_eq!(rep[1], REPLY_GRANTED);
        assert_eq!(echo_roundtrip(s, b"hello socks4").await, b"hello socks4");

        let lines = log.wait_lines(1).await;
        let expected = format!(
            "proto=socks4 cmd=CONNECT target=127.0.0.1:{} status=ok",
            echo.port()
        );
        assert!(lines[0].contains("kind=socks"), "{lines:?}");
        assert!(lines[0].contains(&expected), "{lines:?}");
        assert!(lines[0].contains("bytes_in=12 bytes_out=12"), "{lines:?}");
    }

    #[tokio::test]
    async fn socks4a_domain_connect_relays_and_logs() {
        let echo = spawn_echo("127.0.0.1:0").await;
        let (access, log) = capture_access().await;
        let addr = spawn_socks(SocksProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let req = v4_request(
            CMD_CONNECT,
            echo.port(),
            [0, 0, 0, 1],
            b"",
            Some(b"localhost"),
        );
        let (s, rep) = send(addr, &req).await;
        assert_eq!(rep[1], REPLY_GRANTED);
        assert_eq!(echo_roundtrip(s, b"via 4a").await, b"via 4a");

        let lines = log.wait_lines(1).await;
        let expected = format!(
            "proto=socks4a cmd=CONNECT target=localhost:{} status=ok",
            echo.port()
        );
        assert!(lines[0].contains(&expected), "{lines:?}");
    }

    #[tokio::test]
    async fn socks4_rejects_non_connect_commands() {
        let (access, log) = capture_access().await;
        let addr = spawn_socks(SocksProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let req = v4_request(CMD_BIND, 80, [127, 0, 0, 1], b"", None);
        let (_s, rep) = send(addr, &req).await;
        assert_eq!(rep[1], REPLY_REJECTED);
        let lines = log.wait_lines(1).await;
        assert!(
            lines[0]
                .contains("proto=socks4 cmd=BIND target=127.0.0.1:80 status=command_not_supported"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn socks4_rejects_unreachable_upstream() {
        let port = closed_port().await;
        let (access, log) = capture_access().await;
        let addr = spawn_socks(SocksProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let req = v4_request(CMD_CONNECT, port, [127, 0, 0, 1], b"", None);
        let (_s, rep) = send(addr, &req).await;
        assert_eq!(rep[1], REPLY_REJECTED);
        let lines = log.wait_lines(1).await;
        assert!(lines[0].contains("status=connection_refused"), "{lines:?}");
    }
}
