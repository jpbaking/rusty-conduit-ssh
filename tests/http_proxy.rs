//! End-to-end HTTP/HTTPS proxy tests (MITM off), routed through the production SOCKS5 dialer
//! to a mock `ssh -D` listener.

mod common;

use std::sync::atomic::Ordering;

use common::*;

const ORIGIN_HOST: &str = "origin.test";

#[tokio::test]
async fn plain_http_hostname_is_resolved_remotely() {
    let origin = spawn_http_origin().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-domain", ProxyOptions::separate(), socks.dialer()).await;
    let port = origin.addr.port();
    let authority = format!("{ORIGIN_HOST}:{port}");

    let resp = http_get(proxy.http, &authority, "/hello?x=1").await;
    assert_eq!(resp.status(), 200, "{resp:?}");
    assert_eq!(resp.body, "hit 1 GET /hello 0");
    assert_eq!(resp.header("x-origin-host"), Some(authority.as_str()));
    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);

    let lines = proxy.http_lines(1).await;
    find(
        &lines,
        &format!(
            "proto=http mitm=false method=GET target=\"http://{authority}/hello?x=1\" status=200"
        ),
    );
    proxy.stop().await;
}

#[tokio::test]
async fn plain_http_post_forwards_body() {
    let origin = spawn_http_origin().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-post", ProxyOptions::separate(), socks.dialer()).await;
    let authority = format!("{ORIGIN_HOST}:{}", origin.addr.port());
    let body = "name=conduit&kind=proxy";

    let resp = raw_exchange(
        proxy.http,
        &format!(
            "POST http://{authority}/submit HTTP/1.1\r\nHost: {authority}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(resp.status(), 200, "{resp:?}");
    assert_eq!(resp.body, format!("hit 1 POST /submit {}", body.len()));
    proxy.stop().await;
}

#[tokio::test]
async fn ipv4_literal_uses_atyp_1() {
    let origin = spawn_http_origin().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-ipv4", ProxyOptions::separate(), socks.dialer()).await;

    let resp = http_get(proxy.http, &origin.addr.to_string(), "/ip").await;
    assert_eq!(resp.status(), 200, "{resp:?}");
    assert_eq!(
        socks.dials(),
        [Dial::new(ATYP_IPV4, "127.0.0.1", origin.addr.port())]
    );
    proxy.stop().await;
}

#[tokio::test]
async fn responses_are_never_cached() {
    let origin = spawn_http_origin().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-no-cache", ProxyOptions::separate(), socks.dialer()).await;
    let authority = format!("{ORIGIN_HOST}:{}", origin.addr.port());

    for n in 1..=3 {
        let resp = http_get(proxy.http, &authority, "/same").await;
        assert_eq!(resp.body, format!("hit {n} GET /same 0"));
    }
    assert_eq!(origin.hits.load(Ordering::SeqCst), 3);
    assert_eq!(socks.dials().len(), 3, "each request dials upstream afresh");
    proxy.stop().await;
}

#[tokio::test]
async fn hop_by_hop_request_headers_are_stripped() {
    let origin = spawn_http_origin().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-hop", ProxyOptions::separate(), socks.dialer()).await;
    let authority = format!("{ORIGIN_HOST}:{}", origin.addr.port());

    let resp = raw_exchange(
        proxy.http,
        &format!(
            "GET http://{authority}/hop HTTP/1.1\r\nHost: {authority}\r\n\
             Connection: close, x-client-hop\r\nX-Client-Hop: secret\r\n\
             Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\
             X-Client-Keep: yes\r\n\r\n"
        ),
    )
    .await;
    let seen: Vec<&str> = resp.header("x-seen").unwrap().split(',').collect();
    assert!(seen.contains(&"x-client-keep"), "{seen:?}");
    for hop in ["x-client-hop", "proxy-connection", "proxy-authorization"] {
        assert!(!seen.contains(&hop), "{hop} forwarded upstream: {seen:?}");
    }
    proxy.stop().await;
}

#[tokio::test]
async fn connect_tunnel_is_opaque_and_resolves_remotely() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-connect", ProxyOptions::separate(), socks.dialer()).await;
    let port = echo.addr.port();
    let target = format!("{ORIGIN_HOST}:{port}");

    let (mut stream, status) = http_connect(proxy.http, &target).await;
    assert_eq!(status, 200);
    let payload = b"\x16\x03\x01opaque-bytes\x00\xff";
    assert_eq!(roundtrip(&mut stream, payload).await, payload);
    drop(stream);

    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);
    let lines = proxy.http_lines(1).await;
    find(
        &lines,
        &format!("proto=https mitm=false method=CONNECT target={target} status=200"),
    );
    proxy.stop().await;
}

#[tokio::test]
async fn upstream_refusal_maps_to_502() {
    let port = closed_port().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("http-refused", ProxyOptions::separate(), socks.dialer()).await;
    let target = format!("{ORIGIN_HOST}:{port}");

    assert_eq!(http_get(proxy.http, &target, "/").await.status(), 502);
    let (_stream, status) = http_connect(proxy.http, &target).await;
    assert_eq!(status, 502);
    assert_eq!(socks.dials().len(), 2);
    proxy.stop().await;
}
