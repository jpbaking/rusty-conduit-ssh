//! Reverse proxy (`ssh -R`) through the real application lifecycle, with a mock `ssh`.
//!
//! The mock does not forward anything, so tests connect to the local listener named by the
//! `-R` argument. [`MockSocks`] records every dial through the `ssh -D` path, so an empty
//! record proves reverse traffic egressed directly and could not loop to the SSH target.

#![cfg(unix)]

mod common;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::run_until;

use common::*;

const CONNECT: u8 = 1;
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

fn base_config(mock: &MockSsh, socks: &MockSocks) -> Config {
    Config {
        ssh_target: Some("user@tunnel.test".into()),
        ssh_bin: mock.bin(),
        ssh_socks_port: socks.addr.port(),
        http_port: 0,
        socks_port: 0,
        reconnect_initial_delay: Duration::from_millis(20),
        reconnect_max_delay: Duration::from_millis(100),
        ssh_startup_timeout: WAIT,
        ..Config::default()
    }
}

struct App {
    mock: MockSsh,
    socks: MockSocks,
    stop: CancellationToken,
    run: JoinHandle<ExitCode>,
}

impl App {
    async fn start(mock: MockSsh, socks_up: bool, tweak: impl FnOnce(&mut Config)) -> Self {
        let socks = MockSocks::start().await;
        socks.set_up(socks_up);
        let mut cfg = base_config(&mock, &socks);
        tweak(&mut cfg);
        let stop = CancellationToken::new();
        let run = tokio::spawn(run_until(cfg, quiet_logger(), stop.clone()));
        mock.wait_for_pids(1).await;
        Self {
            mock,
            socks,
            stop,
            run,
        }
    }

    /// The `-R` arguments of the most recent `ssh` start.
    fn specs(&self) -> Vec<String> {
        self.mock
            .lines("args")
            .windows(2)
            .filter(|w| w[0] == "-R")
            .map(|w| w[1].clone())
            .collect()
    }

    async fn stop(self) {
        self.stop.cancel();
        let code = tokio::time::timeout(WAIT * 2, self.run)
            .await
            .expect("application did not stop")
            .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

/// Split `<remote-ip>:<remote-port>:127.0.0.1:<local-port>` and return the remote port and
/// the local listener address.
fn parse_spec(spec: &str) -> (u16, SocketAddr) {
    let (remote, local) = spec
        .rsplit_once(":127.0.0.1:")
        .unwrap_or_else(|| panic!("-R target is not local loopback: {spec}"));
    let remote_port = remote.rsplit_once(':').unwrap().1.parse().unwrap();
    let local_port: u16 = local.parse().unwrap();
    assert_ne!(local_port, 0, "{spec}");
    (remote_port, SocketAddr::from((LOOPBACK, local_port)))
}

fn listener_for(specs: &[String], remote_port: u16) -> SocketAddr {
    specs
        .iter()
        .map(|s| parse_spec(s))
        .find(|(port, _)| *port == remote_port)
        .unwrap_or_else(|| panic!("no -R for remote port {remote_port}: {specs:?}"))
        .1
}

async fn assert_http_egress(proxy: SocketAddr, origin: SocketAddr, echo: SocketAddr) {
    let resp = http_get(proxy, &origin.to_string(), "/direct").await;
    assert_eq!(resp.status(), 200, "{resp:?}");
    assert!(resp.body.ends_with("GET /direct 0"), "{resp:?}");

    let (mut stream, status) = http_connect(proxy, &echo.to_string()).await;
    assert_eq!(status, 200);
    assert_eq!(roundtrip(&mut stream, b"connect").await, b"connect");
}

async fn assert_socks_egress(proxy: SocketAddr, echo: SocketAddr) {
    let (mut stream, rep) = socks5(proxy, CONNECT, Socks5Addr::V4(LOOPBACK), echo.port()).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut stream, b"socks5").await, b"socks5");

    let (mut stream, code) = socks4(proxy, CONNECT, LOOPBACK, None, echo.port()).await;
    assert_eq!(code, 0x5A);
    assert_eq!(roundtrip(&mut stream, b"socks4").await, b"socks4");
}

async fn wait_connectable(addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while TcpStream::connect(addr).await.is_err() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{addr} never opened"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_term(mock: &MockSsh) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while mock.lines("terms").is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ssh never got SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn disabled_by_default_adds_no_reverse_forward() {
    let forward_port = closed_port().await;
    let app = App::start(MockSsh::new(), true, |cfg| cfg.http_port = forward_port).await;
    wait_connectable(SocketAddr::from((LOOPBACK, forward_port))).await;
    assert!(app.specs().is_empty());
    app.stop().await;
}

#[tokio::test]
async fn separate_listeners_egress_directly_while_tunnel_is_down() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let app = App::start(MockSsh::new(), false, |cfg| {
        cfg.reverse_http_port = 8888;
        cfg.reverse_socks_port = 1081;
    })
    .await;

    let specs = app.specs();
    assert_eq!(specs.len(), 2, "{specs:?}");
    assert!(
        specs[0].starts_with("127.0.0.1:8888:127.0.0.1:"),
        "{specs:?}"
    );
    assert!(
        specs[1].starts_with("127.0.0.1:1081:127.0.0.1:"),
        "{specs:?}"
    );
    let http = listener_for(&specs, 8888);
    let socks = listener_for(&specs, 1081);
    assert_ne!(http, socks);

    assert_http_egress(http, origin.addr, echo.addr).await;
    assert_socks_egress(socks, echo.addr).await;
    assert!(app.socks.dials().is_empty(), "reverse traffic used ssh -D");
    app.stop().await;
}

#[tokio::test]
async fn multiplexed_port_serves_http_and_socks() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.reverse_http_port = 8888;
        cfg.reverse_socks_port = 8888;
    })
    .await;

    let specs = app.specs();
    assert_eq!(specs.len(), 1, "{specs:?}");
    let proxy = listener_for(&specs, 8888);
    assert_http_egress(proxy, origin.addr, echo.addr).await;
    assert_socks_egress(proxy, echo.addr).await;
    assert!(app.socks.dials().is_empty(), "reverse traffic used ssh -D");
    app.stop().await;
}

#[tokio::test]
async fn single_enabled_port_and_ipv6_remote_bind() {
    let echo = spawn_echo().await;
    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.reverse_bind = "::1".parse().unwrap();
        cfg.reverse_socks_port = 1081;
    })
    .await;

    let specs = app.specs();
    assert_eq!(specs.len(), 1, "{specs:?}");
    assert!(specs[0].starts_with("[::1]:1081:127.0.0.1:"), "{specs:?}");
    assert_socks_egress(listener_for(&specs, 1081), echo.addr).await;
    app.stop().await;
}

#[tokio::test]
async fn forward_and_reverse_use_their_own_paths() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let forward_port = closed_port().await;
    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.http_port = forward_port;
        cfg.reverse_http_port = 8888;
    })
    .await;
    let forward = SocketAddr::from((LOOPBACK, forward_port));
    wait_connectable(forward).await;

    let reverse = listener_for(&app.specs(), 8888);
    assert_http_egress(reverse, origin.addr, echo.addr).await;
    assert!(app.socks.dials().is_empty(), "reverse traffic used ssh -D");

    let authority = format!("origin.test:{}", origin.addr.port());
    assert_eq!(http_get(forward, &authority, "/").await.status(), 200);
    assert_eq!(
        app.socks.dials(),
        [Dial::new(ATYP_DOMAIN, "origin.test", origin.addr.port())]
    );
    app.stop().await;
}

#[tokio::test]
async fn reverse_ports_are_stable_across_reconnects() {
    let echo = spawn_echo().await;
    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.reverse_http_port = 8888;
        cfg.reverse_socks_port = 8888;
    })
    .await;
    let before = app.specs();

    let first = app.mock.wait_for_pids(1).await[0].clone();
    kill_hard(&first);
    app.mock.wait_for_pids(2).await;

    assert_eq!(app.specs(), before);
    assert_socks_egress(listener_for(&before, 8888), echo.addr).await;
    app.stop().await;
}

/// With MITM on, the reverse interceptor must dial the origin itself. The forward state would
/// instead show up as a dial on [`MockSocks`].
#[tokio::test]
async fn reverse_mitm_dials_directly() {
    let dir = temp_dir("reverse-mitm");
    let ca = test_ca("Rusty Conduit SSH Reverse MITM CA");
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
    std::fs::write(&cert, &ca.cert_pem).unwrap();
    std::fs::write(&key, &ca.key_pem).unwrap();

    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((sock, _)) = origin.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(sock);
        }
    });

    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.reverse_http_port = 8888;
        cfg.mitm_ca_cert = Some(cert);
        cfg.mitm_ca_key = Some(key);
    })
    .await;
    let proxy = listener_for(&app.specs(), 8888);

    let target = format!("localhost:{}", origin_addr.port());
    let (tcp, status) = http_connect(proxy, &target).await;
    assert_eq!(status, 200);
    // The origin closes immediately, so only the upstream dial matters here.
    let _ = tls_client(tcp, &ca.cert_der, "localhost", &[b"http/1.1"]).await;

    let deadline = tokio::time::Instant::now() + WAIT;
    while accepted.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "MITM never dialed the origin directly"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(app.socks.dials().is_empty(), "reverse MITM used ssh -D");
    app.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reverse_only_mode_exits_cleanly_when_tunnel_is_lost() {
    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.reverse_http_port = 8888;
        cfg.no_reconnect = true;
    })
    .await;
    let proxy = listener_for(&app.specs(), 8888);
    wait_connectable(proxy).await;
    // Let the supervisor observe readiness, so the drop is not a startup failure.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let pid = app.mock.wait_for_pids(1).await[0].clone();
    kill_hard(&pid);
    let code = tokio::time::timeout(WAIT, app.run)
        .await
        .expect("application did not exit")
        .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(TcpStream::connect(proxy).await.is_err());
}

/// Forward drains first, the reverse proxy outlives `ssh` termination, then everything closes.
#[tokio::test]
async fn shutdown_drains_forward_then_ssh_then_reverse() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let forward_port = closed_port().await;
    let app = App::start(MockSsh::with_term_delay("1"), true, |cfg| {
        cfg.http_port = forward_port;
        cfg.reverse_http_port = 8888;
    })
    .await;
    let forward = SocketAddr::from((LOOPBACK, forward_port));
    wait_connectable(forward).await;
    let reverse = listener_for(&app.specs(), 8888);
    let (mut in_flight, status) = http_connect(reverse, &echo.addr.to_string()).await;
    assert_eq!(status, 200);

    let App {
        mock,
        stop,
        run,
        socks: _socks,
    } = app;
    stop.cancel();
    wait_for_term(&mock).await;

    // `ssh` is terminating: the forward side is gone, the reverse side still works.
    assert!(
        TcpStream::connect(forward).await.is_err(),
        "forward must drain before ssh stops"
    );
    assert_eq!(roundtrip(&mut in_flight, b"held").await, b"held");
    let resp = http_get(reverse, &origin.addr.to_string(), "/late").await;
    assert_eq!(resp.status(), 200, "{resp:?}");

    let code = tokio::time::timeout(WAIT, run)
        .await
        .expect("application did not stop")
        .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(TcpStream::connect(reverse).await.is_err());
    read_until_closed(&mut in_flight).await;
}

#[tokio::test]
async fn access_logs_tag_forward_and_reverse_direction() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let forward_port = closed_port().await;
    let dir = std::env::temp_dir().join(format!(
        "rc-ssh-direction-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let http_log = dir.join("http.log");
    let socks_log = dir.join("socks.log");

    let app = App::start(MockSsh::new(), true, |cfg| {
        cfg.http_port = forward_port;
        cfg.socks_port = forward_port;
        cfg.reverse_http_port = 8888;
        cfg.reverse_socks_port = 8888;
        cfg.http_access_log = Some(http_log.clone());
        cfg.socks_log = Some(socks_log.clone());
    })
    .await;

    let forward = SocketAddr::from((LOOPBACK, forward_port));
    wait_connectable(forward).await;
    let reverse = listener_for(&app.specs(), 8888);

    // Forward HTTP + SOCKS5
    let authority = format!("origin.test:{}", origin.addr.port());
    assert_eq!(http_get(forward, &authority, "/fwd").await.status(), 200);
    let (mut s, rep) = socks5(
        forward,
        CONNECT,
        Socks5Addr::Domain("origin.test"),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"f").await, b"f");
    drop(s);

    // Reverse HTTP + SOCKS5
    assert_eq!(
        http_get(reverse, &origin.addr.to_string(), "/rev")
            .await
            .status(),
        200
    );
    let (mut s, rep) = socks5(reverse, CONNECT, Socks5Addr::V4(LOOPBACK), echo.addr.port()).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"r").await, b"r");
    drop(s);

    app.stop().await;

    let http_lines = std::fs::read_to_string(&http_log).unwrap();
    let socks_lines = std::fs::read_to_string(&socks_log).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        http_lines
            .lines()
            .any(|l| l.contains("direction=forward") && l.contains("/fwd")),
        "missing forward HTTP log:\n{http_lines}"
    );
    assert!(
        http_lines
            .lines()
            .any(|l| l.contains("direction=reverse") && l.contains("/rev")),
        "missing reverse HTTP log:\n{http_lines}"
    );
    assert!(
        socks_lines
            .lines()
            .any(|l| l.contains("direction=forward") && l.contains("origin.test:")),
        "missing forward SOCKS log:\n{socks_lines}"
    );
    assert!(
        socks_lines
            .lines()
            .any(|l| l.contains("direction=reverse") && l.contains("127.0.0.1:")),
        "missing reverse SOCKS log:\n{socks_lines}"
    );
}
