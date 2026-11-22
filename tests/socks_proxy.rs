//! End-to-end SOCKS4/4a/5 tests, routed through the production SOCKS5 dialer to a mock
//! `ssh -D` listener.

mod common;

use std::sync::atomic::Ordering;

use common::*;

const ORIGIN_HOST: &str = "origin.test";
const CONNECT: u8 = 1;
const BIND: u8 = 2;
const UDP_ASSOCIATE: u8 = 3;
const V4_GRANTED: u8 = 0x5A;
const V4_REJECTED: u8 = 0x5B;

#[tokio::test]
async fn socks4_ip_target_uses_atyp_1() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("socks4", ProxyOptions::separate(), socks.dialer()).await;
    let port = echo.addr.port();

    let (mut s, code) = socks4(proxy.socks, CONNECT, [127, 0, 0, 1], None, port).await;
    assert_eq!(code, V4_GRANTED);
    assert_eq!(roundtrip(&mut s, b"socks4").await, b"socks4");
    drop(s);

    assert_eq!(socks.dials(), [Dial::new(ATYP_IPV4, "127.0.0.1", port)]);
    let lines = proxy.socks_lines(1).await;
    find(
        &lines,
        &format!("proto=socks4 cmd=CONNECT target=127.0.0.1:{port} status=ok"),
    );
    proxy.stop().await;
}

#[tokio::test]
async fn socks4a_hostname_is_resolved_remotely() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("socks4a", ProxyOptions::separate(), socks.dialer()).await;
    let port = echo.addr.port();

    let (mut s, code) = socks4(proxy.socks, CONNECT, [0, 0, 0, 1], Some(ORIGIN_HOST), port).await;
    assert_eq!(code, V4_GRANTED);
    assert_eq!(roundtrip(&mut s, b"socks4a").await, b"socks4a");
    drop(s);

    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);
    let lines = proxy.socks_lines(1).await;
    find(
        &lines,
        &format!("proto=socks4a cmd=CONNECT target={ORIGIN_HOST}:{port} status=ok"),
    );
    proxy.stop().await;
}

#[tokio::test]
async fn socks5_ipv4_target_uses_atyp_1() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("socks5-v4", ProxyOptions::separate(), socks.dialer()).await;
    let port = echo.addr.port();

    let (mut s, rep) = socks5(proxy.socks, CONNECT, Socks5Addr::V4([127, 0, 0, 1]), port).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"ipv4").await, b"ipv4");
    drop(s);
    assert_eq!(socks.dials(), [Dial::new(ATYP_IPV4, "127.0.0.1", port)]);
    proxy.stop().await;
}

#[tokio::test]
async fn socks5_hostname_is_resolved_remotely() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("socks5-domain", ProxyOptions::separate(), socks.dialer()).await;
    let port = echo.addr.port();

    let (mut s, rep) = socks5(proxy.socks, CONNECT, Socks5Addr::Domain(ORIGIN_HOST), port).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"domain").await, b"domain");
    drop(s);

    assert_eq!(socks.dials(), [Dial::new(ATYP_DOMAIN, ORIGIN_HOST, port)]);
    let lines = proxy.socks_lines(1).await;
    find(
        &lines,
        &format!("proto=socks5 cmd=CONNECT target={ORIGIN_HOST}:{port} status=ok"),
    );
    proxy.stop().await;
}

#[tokio::test]
async fn socks5_ipv6_target_uses_atyp_4() {
    // IPv6 loopback may be unavailable in some sandboxes; only then is this case skipped.
    let Some(echo) = spawn_upstream("[::1]:0", None).await else {
        eprintln!("IPv6 loopback unavailable: skipping SOCKS5 ATYP=0x04 case");
        return;
    };
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("socks5-v6", ProxyOptions::separate(), socks.dialer()).await;
    let port = echo.addr.port();
    let mut ip = [0u8; 16];
    ip[15] = 1;

    let (mut s, rep) = socks5(proxy.socks, CONNECT, Socks5Addr::V6(ip), port).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"ipv6").await, b"ipv6");
    drop(s);
    assert_eq!(socks.dials(), [Dial::new(ATYP_IPV6, "::1", port)]);
    proxy.stop().await;
}

#[tokio::test]
async fn unsupported_commands_never_reach_the_tunnel() {
    let echo = spawn_echo().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start(
        "socks-unsupported",
        ProxyOptions::separate(),
        socks.dialer(),
    )
    .await;
    let port = echo.addr.port();

    for cmd in [BIND, UDP_ASSOCIATE] {
        let (mut s, rep) = socks5(proxy.socks, cmd, Socks5Addr::V4([127, 0, 0, 1]), port).await;
        assert_eq!(rep, 0x07, "cmd {cmd}");
        assert!(read_until_closed(&mut s).await.is_empty());
    }
    let (mut s, code) = socks4(proxy.socks, BIND, [127, 0, 0, 1], None, port).await;
    assert_eq!(code, V4_REJECTED);
    assert!(read_until_closed(&mut s).await.is_empty());

    assert!(socks.dials().is_empty());
    assert_eq!(echo.received.load(Ordering::SeqCst), 0);
    proxy.stop().await;
}

#[tokio::test]
async fn upstream_refusal_maps_to_socks_errors() {
    let port = closed_port().await;
    let socks = MockSocks::start().await;
    let proxy = Proxy::start("socks-refused", ProxyOptions::separate(), socks.dialer()).await;

    let (_s, rep) = socks5(proxy.socks, CONNECT, Socks5Addr::Domain(ORIGIN_HOST), port).await;
    assert_eq!(rep, 0x05, "connection refused");
    let (_s, code) = socks4(proxy.socks, CONNECT, [0, 0, 0, 1], Some(ORIGIN_HOST), port).await;
    assert_eq!(code, V4_REJECTED);
    assert_eq!(socks.dials().len(), 2);
    proxy.stop().await;
}
