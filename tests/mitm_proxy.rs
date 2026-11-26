//! End-to-end HTTPS MITM tests (HTTP/1.1 and HTTP/2) and `--socks-block-web-in-mitm`, routed
//! through the production SOCKS5 dialer to a mock `ssh -D` listener.

mod common;

use std::sync::atomic::Ordering;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use x509_parser::extensions::GeneralName;

use common::*;

const ORIGIN_HOST: &str = "origin.test";
const CONNECT: u8 = 1;

async fn mitm_tunnel(proxy: &Proxy, target: &str, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
    let (tcp, status) = http_connect(proxy.http, target).await;
    assert_eq!(status, 200);
    tls_client(tcp, proxy.mitm_ca.as_ref().unwrap(), ORIGIN_HOST, alpn)
        .await
        .expect("client must trust the MITM leaf")
}

type H1Sender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

async fn h1_sender(tls: TlsStream<TcpStream>) -> H1Sender {
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    sender
}

async fn h1_get(sender: &mut H1Sender, authority: &str, path: &str) -> (String, String) {
    let req = Request::get(path)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let version = origin_version(resp.headers());
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (String::from_utf8(body.to_vec()).unwrap(), version)
}

fn origin_version(headers: &hyper::HeaderMap) -> String {
    headers
        .get("x-origin-version")
        .expect("origin version header")
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn http1_is_intercepted_and_resolved_remotely() {
    let origin = spawn_tls_origin(ORIGIN_HOST).await;
    let socks = MockSocks::start().await;
    let opts = ProxyOptions::separate().with_mitm(origin.ca_der.clone());
    let proxy = Proxy::start("mitm-h1", opts, socks.dialer()).await;
    let port = origin.addr.port();
    let target = format!("{ORIGIN_HOST}:{port}");

    let tls = mitm_tunnel(&proxy, &target, &[b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));

    let certs = tls.get_ref().1.peer_certificates().unwrap();
    assert_eq!(certs.len(), 2, "leaf + CA");
    let (_, leaf) = x509_parser::parse_x509_certificate(&certs[0]).unwrap();
    assert!(
        leaf.issuer()
            .to_string()
            .contains("Rusty Conduit SSH Integration MITM CA"),
        "{}",
        leaf.issuer()
    );
    let san = leaf.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        san.value.general_names,
        vec![GeneralName::DNSName(ORIGIN_HOST)]
    );

    // Two keep-alive requests both reach the origin even though it marks them cacheable.
    let mut sender = h1_sender(tls).await;
    let (body, version) = h1_get(&mut sender, &target, "/a").await;
    assert_eq!(body, "hit 1 GET /a 0");
    assert_eq!(version, "HTTP/1.1");
    let (body, _) = h1_get(&mut sender, &target, "/a").await;
    assert_eq!(body, "hit 2 GET /a 0");
    drop(sender);

    assert_eq!(origin.hits.load(Ordering::SeqCst), 2);
    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);
    assert_eq!(proxy.state.as_ref().unwrap().cache.len(), 1);

    let lines = proxy.http_lines(2).await;
    let needle = format!("proto=https mitm=true method=GET target=https://{target}/a status=200");
    assert_eq!(
        lines.iter().filter(|l| l.contains(&needle)).count(),
        2,
        "{lines:?}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn http2_is_intercepted_and_resolved_remotely() {
    let origin = spawn_tls_origin(ORIGIN_HOST).await;
    let socks = MockSocks::start().await;
    let opts = ProxyOptions::separate().with_mitm(origin.ca_der.clone());
    let proxy = Proxy::start("mitm-h2", opts, socks.dialer()).await;
    let port = origin.addr.port();
    let target = format!("{ORIGIN_HOST}:{port}");

    let tls = mitm_tunnel(&proxy, &target, &[b"h2", b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);

    let req = Request::get(format!("https://{target}/h2"))
        .version(Version::HTTP_2)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.version(), Version::HTTP_2);
    assert_eq!(origin_version(resp.headers()), "HTTP/2.0");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hit 1 GET /h2 0");
    drop(sender);

    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);
    let lines = proxy.http_lines(1).await;
    find(
        &lines,
        &format!("proto=https mitm=true method=GET target=https://{target}/h2 status=200"),
    );
    proxy.stop().await;
}

#[tokio::test]
async fn untrusted_upstream_certificate_is_rejected() {
    let origin = spawn_tls_origin(ORIGIN_HOST).await;
    let socks = MockSocks::start().await;
    // The proxy trusts an unrelated CA, so the origin's certificate must fail verification.
    let unrelated = test_ca("Unrelated CA").cert_der;
    let opts = ProxyOptions::separate().with_mitm(unrelated);
    let proxy = Proxy::start("mitm-untrusted", opts, socks.dialer()).await;
    let target = format!("{ORIGIN_HOST}:{}", origin.addr.port());

    let (tcp, status) = http_connect(proxy.http, &target).await;
    assert_eq!(status, 200);
    let ca = proxy.mitm_ca.clone().unwrap();
    assert!(tls_client(tcp, &ca, ORIGIN_HOST, &[b"http/1.1"])
        .await
        .is_err());
    assert_eq!(origin.hits.load(Ordering::SeqCst), 0);

    let lines = proxy.http_lines(1).await;
    find(&lines, "status=502");
    proxy.stop().await;
}

#[tokio::test]
async fn block_web_rejects_plain_http_over_socks() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let opts = ProxyOptions::separate()
        .with_mitm(test_ca("Unused Origin CA").cert_der)
        .with_block_web();
    let proxy = Proxy::start("block-http", opts, socks.dialer()).await;
    let port = echo.addr.port();

    let (mut s, rep) = socks5(proxy.socks, CONNECT, Socks5Addr::Domain(ORIGIN_HOST), port).await;
    assert_eq!(rep, 0);
    tokio::io::AsyncWriteExt::write_all(&mut s, b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
        .await
        .unwrap();
    assert!(read_until_closed(&mut s).await.is_empty());

    let lines = proxy.socks_lines(1).await;
    find(&lines, "status=blocked_web_in_mitm");
    assert_eq!(echo.received.load(Ordering::SeqCst), 0);
    proxy.stop().await;
}

#[tokio::test]
async fn block_web_rejects_tls_client_hello_over_socks() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let ca = test_ca("Unused Origin CA").cert_der;
    let opts = ProxyOptions::separate()
        .with_mitm(ca.clone())
        .with_block_web();
    let proxy = Proxy::start("block-tls", opts, socks.dialer()).await;

    let (s, rep) = socks5(
        proxy.socks,
        CONNECT,
        Socks5Addr::Domain(ORIGIN_HOST),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0);
    assert!(tls_client(s, &ca, ORIGIN_HOST, &[b"h2", b"http/1.1"])
        .await
        .is_err());

    let lines = proxy.socks_lines(1).await;
    find(&lines, "status=blocked_web_in_mitm");
    assert_eq!(echo.received.load(Ordering::SeqCst), 0);
    proxy.stop().await;
}

#[tokio::test]
async fn block_web_allows_raw_tcp_and_server_speaks_first() {
    const BANNER: &[u8] = b"220 smtp.test ESMTP ready\r\n";
    let echo = spawn_echo().await;
    let banner = spawn_upstream("127.0.0.1:0", Some(BANNER)).await.unwrap();
    let socks = MockSocks::start().await;
    let opts = ProxyOptions::separate()
        .with_mitm(test_ca("Unused Origin CA").cert_der)
        .with_block_web();
    let proxy = Proxy::start("block-allow", opts, socks.dialer()).await;

    let (mut s, rep) = socks5(
        proxy.socks,
        CONNECT,
        Socks5Addr::V4([127, 0, 0, 1]),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0);
    let raw = b"\x00\x01binary-protocol\xfe\xff";
    assert_eq!(roundtrip(&mut s, raw).await, raw);
    drop(s);

    let (mut s, code) = socks4(
        proxy.socks,
        CONNECT,
        [127, 0, 0, 1],
        None,
        banner.addr.port(),
    )
    .await;
    assert_eq!(code, 0x5A);
    let mut got = vec![0u8; BANNER.len()];
    tokio::time::timeout(WAIT, s.read_exact(&mut got))
        .await
        .expect("banner must not be delayed by the guard")
        .unwrap();
    assert_eq!(got, BANNER);
    assert_eq!(roundtrip(&mut s, b"EHLO c\r\n").await, b"EHLO c\r\n");
    drop(s);

    let lines = proxy.socks_lines(2).await;
    assert!(lines.iter().all(|l| l.contains("status=ok")), "{lines:?}");
    proxy.stop().await;
}

#[tokio::test]
async fn block_web_flag_is_active_without_mitm() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let opts = ProxyOptions::separate().with_block_web();
    let proxy = Proxy::start("block-without-mitm", opts, socks.dialer()).await;

    let (mut s, rep) = socks5(
        proxy.socks,
        CONNECT,
        Socks5Addr::V4([127, 0, 0, 1]),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0);
    let req = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    s.write_all(req).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    assert!(buf.is_empty(), "blocked HTTP request must receive no reply");
    drop(s);

    let lines = proxy.socks_lines(1).await;
    find(&lines, "status=blocked_web_in_mitm");
    assert_eq!(echo.received.load(Ordering::SeqCst), 0);
    proxy.stop().await;
}
