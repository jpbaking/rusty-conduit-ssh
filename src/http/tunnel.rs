//! Non-MITM HTTPS `CONNECT` tunnel: an opaque TCP relay.
//!
//! The `CONNECT` authority is validated as `host:port`, the upstream is dialed (fresh
//! connection, OS resolver), the client receives `200 Connection Established`, and after
//! `hyper::upgrade::on` the two streams are relayed with [`relay_bidirectional`]. One access
//! record (`proto=https`, `mitm=false`, `method=CONNECT`) is emitted when the tunnel closes.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    connect_established, dial_error_status, error_response, ConnectTarget, ProxyBody, RequestCtx,
};
use crate::net::relay_bidirectional;

/// Handle a `CONNECT` request without interception.
pub(crate) async fn handle(ctx: &RequestCtx, req: Request<Incoming>) -> Response<ProxyBody> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_default();
    let mut guard = ctx.access_guard("https", false, "CONNECT", authority.clone());
    let logger = ctx.proxy.logger.clone();

    let Some(target) = ConnectTarget::parse(&authority) else {
        guard.set_status(StatusCode::BAD_REQUEST);
        logger.debug(format!(
            "rejected CONNECT from {}: invalid target {authority:?}",
            ctx.peer
        ));
        return error_response(StatusCode::BAD_REQUEST, "CONNECT target must be host:port");
    };

    let dial = ctx
        .proxy
        .dialer
        .connect(&target.host, target.port, ctx.proxy.connect_timeout);
    let mut upstream = match dial.await {
        Ok(s) => s,
        Err(e) => {
            let status = dial_error_status(&e);
            guard.set_status(status);
            logger.error(format!("CONNECT upstream {target} failed: {e}"));
            return error_response(status, "upstream connection failed");
        }
    };

    guard.set_status(StatusCode::OK);
    let shutdown = ctx.shutdown.clone();
    let peer = ctx.peer;
    ctx.tasks.spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                logger.debug(format!("CONNECT upgrade from {peer} failed: {e}"));
                return;
            }
        };
        let mut client =
            CountingStream::new(TokioIo::new(upgraded), guard.bytes_in(), guard.bytes_out());
        tokio::select! {
            res = relay_bidirectional(&mut client, &mut upstream) => {
                if let Err(e) = res {
                    logger.debug(format!("CONNECT tunnel {peer} -> {target} ended: {e}"));
                }
            }
            () = shutdown.cancelled() => {
                logger.debug(format!("CONNECT tunnel {peer} -> {target} closed by shutdown"));
            }
        }
        drop(guard);
    });
    connect_established()
}

/// Wraps the client side of a tunnel, counting bytes read from (`bytes_in`) and written to
/// (`bytes_out`) the client so totals survive errors and shutdown.
pub struct CountingStream<S> {
    inner: S,
    read: Arc<AtomicU64>,
    written: Arc<AtomicU64>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, read: Arc<AtomicU64>, written: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            read,
            written,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let n = buf.filled().len() - before;
        self.read.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        self.written.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::http::test_support::{capture_access, quiet_logger, spawn_proxy};
    use crate::http::HttpProxy;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// Echo server: echoes everything until EOF, then closes.
    async fn spawn_echo() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        addr
    }

    /// Send `CONNECT`, return the buffered stream positioned after the response head and
    /// the status line.
    async fn connect(proxy: std::net::SocketAddr, target: &str) -> (BufReader<TcpStream>, String) {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).await.unwrap();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        (reader, status)
    }

    #[tokio::test]
    async fn tunnels_raw_bytes_and_counts_them() {
        let echo = spawn_echo().await;
        let (access, log) = capture_access().await;
        let proxy = spawn_proxy(HttpProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let (mut reader, status) = connect(proxy, &echo.to_string()).await;
        assert_eq!(status, "HTTP/1.1 200 Connection Established\r\n");

        // Arbitrary binary (non-HTTP) payload, including bytes that look like HTTP.
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut sent = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        sent.extend_from_slice(&payload);
        reader.get_mut().write_all(&sent).await.unwrap();
        reader.get_mut().shutdown().await.unwrap();
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, sent);

        let lines = log.wait_lines(1).await;
        let line = &lines[0];
        assert!(line.contains("kind=http"), "{line}");
        assert!(
            line.contains(&format!(
                "proto=https mitm=false method=CONNECT target={echo} status=200"
            )),
            "{line}"
        );
        let n = sent.len();
        assert!(
            line.contains(&format!("bytes_in={n} bytes_out={n}")),
            "{line}"
        );
    }

    #[tokio::test]
    async fn rejects_invalid_and_unreachable_targets() {
        let (access, log) = capture_access().await;
        let proxy = spawn_proxy(HttpProxy::new(
            access,
            quiet_logger(),
            crate::http::test_support::direct_dialer(),
        ))
        .await;

        let (_, status) = connect(proxy, "no-port.example").await;
        assert!(status.starts_with("HTTP/1.1 400"), "{status}");

        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let (_, status) = connect(proxy, &closed.to_string()).await;
        assert!(status.starts_with("HTTP/1.1 502"), "{status}");

        let lines = log.wait_lines(2).await;
        assert!(lines[0].contains("method=CONNECT"), "{lines:?}");
        assert!(lines[0].contains("status=400"), "{lines:?}");
        assert!(lines[1].contains("status=502"), "{lines:?}");
    }
}
