//! End-to-end single-port multiplexing tests: HTTP, HTTPS `CONNECT`, MITM, SOCKS4/4a, and
//! SOCKS5 on one listener, routed through the production SOCKS5 dialer.

mod common;

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::*;

const ORIGIN_HOST: &str = "origin.test";
const CONNECT: u8 = 1;

/// Whether the peer closes the connection without answering `probe`.
async fn closed_without_reply(addr: SocketAddr, probe: &[u8]) -> bool {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let _ = stream.write_all(probe).await;
    let mut out = Vec::new();
    match tokio::time::timeout(WAIT, stream.read_to_end(&mut out)).await {
        Ok(_) => out.is_empty(),
        Err(_) => false,
    }
}

#[tokio::test]
async fn one_port_serves_every_protocol_through_the_tunnel() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("mux-all", ProxyOptions::multiplexed(), socks.dialer()).await;
    assert_eq!(proxy.http, proxy.socks, "one shared listener");
    let addr = proxy.http;
    let port = echo.addr.port();
    let tunnel_target = format!("{ORIGIN_HOST}:{port}");

    let authority = format!("{ORIGIN_HOST}:{}", origin.addr.port());
    let resp = http_get(addr, &authority, "/mux").await;
    assert_eq!(resp.status(), 200, "{resp:?}");
    assert_eq!(resp.body, "hit 1 GET /mux 0");

    let (mut s, status) = http_connect(addr, &tunnel_target).await;
    assert_eq!(status, 200);
    assert_eq!(roundtrip(&mut s, b"tunnelled").await, b"tunnelled");
    drop(s);

    let (mut s, code) = socks4(addr, CONNECT, [127, 0, 0, 1], None, port).await;
    assert_eq!(code, 0x5A);
    assert_eq!(roundtrip(&mut s, b"via socks4").await, b"via socks4");
    drop(s);

    let (mut s, code) = socks4(addr, CONNECT, [0, 0, 0, 1], Some(ORIGIN_HOST), port).await;
    assert_eq!(code, 0x5A);
    assert_eq!(roundtrip(&mut s, b"via socks4a").await, b"via socks4a");
    drop(s);

    let (mut s, rep) = socks5(addr, CONNECT, Socks5Addr::Domain(ORIGIN_HOST), port).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"via socks5").await, b"via socks5");
    drop(s);

    assert_eq!(
        socks.dials(),
        [
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, origin.addr.port()),
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port),
            Dial::new(ATYP_IPV4, "127.0.0.1", port),
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port),
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port),
        ]
    );

    let http = proxy.http_lines(2).await;
    find(&http, "proto=http mitm=false method=GET");
    find(&http, "proto=https mitm=false method=CONNECT");
    let socks_log = proxy.socks_lines(3).await;
    find(&socks_log, "proto=socks4 cmd=CONNECT");
    find(&socks_log, "proto=socks4a cmd=CONNECT");
    find(&socks_log, "proto=socks5 cmd=CONNECT");
    proxy.stop().await;
}

#[tokio::test]
async fn concurrent_mixed_clients_share_the_port() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start(
        "mux-concurrent",
        ProxyOptions::multiplexed(),
        socks.dialer(),
    )
    .await;
    let addr = proxy.http;
    let port = echo.addr.port();
    let authority = format!("{ORIGIN_HOST}:{}", origin.addr.port());
    let tunnel_target = format!("{ORIGIN_HOST}:{port}");

    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let authority = authority.clone();
        let tunnel_target = tunnel_target.clone();
        tasks.push(tokio::spawn(async move {
            let mut stream = match i % 4 {
                0 => {
                    let (s, status) = http_connect(addr, &tunnel_target).await;
                    assert_eq!(status, 200);
                    s
                }
                1 => {
                    let (s, code) = socks4(addr, CONNECT, [127, 0, 0, 1], None, port).await;
                    assert_eq!(code, 0x5A);
                    s
                }
                2 => {
                    let (s, rep) =
                        socks5(addr, CONNECT, Socks5Addr::Domain(ORIGIN_HOST), port).await;
                    assert_eq!(rep, 0);
                    s
                }
                _ => {
                    let resp = http_get(addr, &authority, "/concurrent").await;
                    assert_eq!(resp.status(), 200, "{resp:?}");
                    return;
                }
            };
            let msg = [b'c', i];
            assert_eq!(roundtrip(&mut stream, &msg).await, msg);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(socks.dials().len(), 16);
    proxy.stop().await;
}

#[tokio::test]
async fn unknown_protocols_are_dropped_without_dialing() {
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("mux-unknown", ProxyOptions::multiplexed(), socks.dialer()).await;

    assert!(closed_without_reply(proxy.http, b"\x16\x03\x01\x00\x05hello").await);
    assert!(closed_without_reply(proxy.http, b"\x00\x00\x00\x08\x04\xd2\x16\x2f").await);
    assert!(socks.dials().is_empty());
    proxy.stop().await;
}

#[tokio::test]
async fn mitm_works_on_the_multiplexed_port() {
    let origin = spawn_tls_origin(ORIGIN_HOST).await;
    let socks = MockSocks::start().await;
    let opts = ProxyOptions::multiplexed().with_mitm(origin.ca_der.clone());
    let proxy = Proxy::start("mux-mitm", opts, socks.dialer()).await;
    let port = origin.addr.port();
    let target = format!("{ORIGIN_HOST}:{port}");

    let (tcp, status) = http_connect(proxy.http, &target).await;
    assert_eq!(status, 200);
    let ca = proxy.mitm_ca.clone().unwrap();
    let tls = tls_client(tcp, &ca, ORIGIN_HOST, &[b"http/1.1"])
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::get("/mux-mitm")
        .header(hyper::header::HOST, &target)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hit 1 GET /mux-mitm 0");
    drop(sender);

    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);
    let lines = proxy.http_lines(1).await;
    find(
        &lines,
        &format!("proto=https mitm=true method=GET target=https://{target}/mux-mitm status=200"),
    );
    proxy.stop().await;
}
