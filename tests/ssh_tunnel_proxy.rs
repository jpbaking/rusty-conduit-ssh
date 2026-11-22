//! Full [`SshSupervisor`] + [`Server`] integration with a mock `ssh` executable: readiness,
//! end-to-end forwarding, failures while the tunnel is down, automatic reconnect, and clean
//! shutdown of the child process.
//!
//! The down window is controlled, not timed: [`MockSocks`] is switched off *before* the child
//! is killed, so readiness cannot return until the test switches it back on.

#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::net::{Socks5UpstreamDialer, TunnelState, UpstreamDialer};
use rusty_conduit_ssh::ssh::{SshError, SshHandle, SshSupervisor, SshTunnelConfig};

use common::*;

const ORIGIN_HOST: &str = "origin.test";
const SSH_TARGET: &str = "user@tunnel.test";
const CONNECT: u8 = 1;

fn tunnel_config(mock: &MockSsh, socks: &MockSocks, no_reconnect: bool) -> SshTunnelConfig {
    let cfg = Config {
        ssh_target: Some(SSH_TARGET.into()),
        ssh_bin: mock.bin(),
        ssh_socks_port: socks.addr.port(),
        no_reconnect,
        reconnect_initial_delay: Duration::from_millis(20),
        reconnect_max_delay: Duration::from_millis(100),
        ssh_startup_timeout: WAIT,
        ..Config::default()
    };
    let mut tunnel = SshTunnelConfig::from_config(&cfg).unwrap();
    tunnel.inherit_stdio = false;
    tunnel
}

struct Tunnel {
    mock: MockSsh,
    socks: MockSocks,
    handle: SshHandle,
    state: watch::Receiver<TunnelState>,
    app: CancellationToken,
}

impl Tunnel {
    async fn start(socks_up: bool, no_reconnect: bool) -> Self {
        let mock = MockSsh::new();
        let socks = MockSocks::start().await;
        socks.set_up(socks_up);
        let app = CancellationToken::new();
        let (handle, state) = SshSupervisor::spawn(
            tunnel_config(&mock, &socks, no_reconnect),
            quiet_logger(),
            app.clone(),
        );
        Self {
            mock,
            socks,
            handle,
            state,
            app,
        }
    }

    fn dialer(&self) -> Arc<dyn UpstreamDialer> {
        Arc::new(Socks5UpstreamDialer::new(self.state.clone()))
    }

    async fn wait_not_ready(&mut self) {
        tokio::time::timeout(
            WAIT,
            self.state.wait_for(|s| !matches!(s, TunnelState::Ready(_))),
        )
        .await
        .expect("tunnel never left Ready")
        .unwrap();
    }
}

async fn assert_traffic_flows(proxy: &Proxy, origin_port: u16, echo_port: u16) {
    let authority = format!("{ORIGIN_HOST}:{origin_port}");
    let resp = http_get(proxy.http, &authority, "/through-tunnel").await;
    assert_eq!(resp.status(), 200, "{resp:?}");
    assert!(resp.body.ends_with("GET /through-tunnel 0"), "{resp:?}");

    let target = format!("{ORIGIN_HOST}:{echo_port}");
    let (mut s, status) = http_connect(proxy.http, &target).await;
    assert_eq!(status, 200);
    assert_eq!(roundtrip(&mut s, b"connect").await, b"connect");
    drop(s);

    let (mut s, rep) = socks5(
        proxy.socks,
        CONNECT,
        Socks5Addr::Domain(ORIGIN_HOST),
        echo_port,
    )
    .await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"socks5").await, b"socks5");
    drop(s);
}

async fn assert_tunnel_errors(proxy: &Proxy, origin_port: u16, echo_port: u16) {
    let authority = format!("{ORIGIN_HOST}:{origin_port}");
    assert_eq!(http_get(proxy.http, &authority, "/").await.status(), 502);

    let target = format!("{ORIGIN_HOST}:{echo_port}");
    let (_s, status) = http_connect(proxy.http, &target).await;
    assert_eq!(status, 502);

    let (_s, rep) = socks5(
        proxy.socks,
        CONNECT,
        Socks5Addr::Domain(ORIGIN_HOST),
        echo_port,
    )
    .await;
    assert_eq!(rep, 0x01, "general SOCKS failure");

    let (_s, code) = socks4(
        proxy.socks,
        CONNECT,
        [0, 0, 0, 1],
        Some(ORIGIN_HOST),
        echo_port,
    )
    .await;
    assert_eq!(code, 0x5B);
}

#[tokio::test]
async fn ready_only_once_socks_answers_and_argv_is_correct() {
    let tunnel = Tunnel::start(false, false).await;
    tunnel.mock.wait_for_pids(1).await;

    let short = Duration::from_millis(300);
    assert_eq!(
        tunnel.handle.wait_ready(short).await,
        Err(SshError::StartupTimeout(short))
    );
    assert_eq!(*tunnel.state.borrow(), TunnelState::Connecting);

    tunnel.socks.set_up(true);
    assert_eq!(tunnel.handle.wait_ready(WAIT).await, Ok(tunnel.socks.addr));

    let args = tunnel.mock.lines("args");
    let bind = tunnel.socks.addr.to_string();
    assert_eq!(&args[..5], ["-N", "-T", "-4", "-D", bind.as_str()]);
    assert!(
        args.iter().any(|a| a == "ExitOnForwardFailure=yes"),
        "{args:?}"
    );
    assert_eq!(&args[args.len() - 2..], ["--", SSH_TARGET]);
    tunnel.handle.shutdown().await;
}

#[tokio::test]
async fn forwards_all_protocols_end_to_end() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let tunnel = Tunnel::start(true, false).await;
    tunnel.handle.wait_ready(WAIT).await.unwrap();
    let proxy = Proxy::start("ssh-forward", ProxyOptions::separate(), tunnel.dialer()).await;

    assert_traffic_flows(&proxy, origin.addr.port(), echo.addr.port()).await;
    assert_eq!(
        tunnel.socks.dials(),
        [
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, origin.addr.port()),
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, echo.addr.port()),
            Dial::new(ATYP_DOMAIN, ORIGIN_HOST, echo.addr.port()),
        ]
    );
    proxy.stop().await;
    tunnel.handle.shutdown().await;
}

#[tokio::test]
async fn tunnel_drop_fails_requests_then_reconnect_restores_traffic() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let (origin_port, echo_port) = (origin.addr.port(), echo.addr.port());
    let mut tunnel = Tunnel::start(true, false).await;
    tunnel.handle.wait_ready(WAIT).await.unwrap();
    let proxy = Proxy::start("ssh-reconnect", ProxyOptions::separate(), tunnel.dialer()).await;
    assert_traffic_flows(&proxy, origin_port, echo_port).await;
    let dials_before = tunnel.socks.dials().len();

    // Keep the listener down so the respawned ssh cannot become ready yet.
    tunnel.socks.set_up(false);
    let first = tunnel.mock.wait_for_pids(1).await[0].clone();
    kill_hard(&first);
    tunnel.wait_not_ready().await;
    assert_tunnel_errors(&proxy, origin_port, echo_port).await;

    // The supervisor restarts ssh, but the tunnel stays unusable until SOCKS answers.
    let pids = tunnel.mock.wait_for_pids(2).await;
    assert_ne!(pids[0], pids[1]);
    assert_tunnel_errors(&proxy, origin_port, echo_port).await;
    assert_eq!(
        tunnel.socks.dials().len(),
        dials_before,
        "no request may be dialed while the tunnel is down"
    );

    tunnel.socks.set_up(true);
    assert_eq!(tunnel.handle.wait_ready(WAIT).await, Ok(tunnel.socks.addr));
    assert_traffic_flows(&proxy, origin_port, echo_port).await;

    proxy.stop().await;
    let last = tunnel.mock.lines("pids").last().unwrap().clone();
    tunnel.handle.shutdown().await;
    assert!(!is_alive(&last));
}

#[tokio::test]
async fn survives_repeated_tunnel_drops() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let tunnel = Tunnel::start(true, false).await;
    tunnel.handle.wait_ready(WAIT).await.unwrap();
    let proxy = Proxy::start("ssh-repeat", ProxyOptions::separate(), tunnel.dialer()).await;

    for generation in 1..=3 {
        let pids = tunnel.mock.wait_for_pids(generation).await;
        kill_hard(&pids[generation - 1]);
        // A new PID is only recorded after the state left the old Ready.
        tunnel.mock.wait_for_pids(generation + 1).await;
        tunnel.handle.wait_ready(WAIT).await.unwrap();
        assert_traffic_flows(&proxy, origin.addr.port(), echo.addr.port()).await;
    }

    proxy.stop().await;
    let last = tunnel.mock.lines("pids").last().unwrap().clone();
    tunnel.handle.shutdown().await;
    assert!(!is_alive(&last));
}

#[tokio::test]
async fn clean_shutdown_terminates_the_child() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let tunnel = Tunnel::start(true, false).await;
    tunnel.handle.wait_ready(WAIT).await.unwrap();
    let proxy = Proxy::start("ssh-shutdown", ProxyOptions::separate(), tunnel.dialer()).await;
    assert_traffic_flows(&proxy, origin.addr.port(), echo.addr.port()).await;
    let pid = tunnel.mock.wait_for_pids(1).await[0].clone();
    assert!(is_alive(&pid));

    // Same order as the application: drain the server first, then stop ssh.
    proxy.stop().await;
    assert!(is_alive(&pid), "ssh must outlive the server drain");
    let Tunnel {
        mock,
        handle,
        state,
        app,
        ..
    } = tunnel;
    tokio::time::timeout(WAIT, handle.shutdown())
        .await
        .expect("supervisor did not stop");

    assert_eq!(mock.lines("terms").len(), 1, "ssh must receive SIGTERM");
    assert!(!is_alive(&pid));
    assert!(matches!(*state.borrow(), TunnelState::Disconnected(_)));
    assert!(!app.is_cancelled());
}

#[tokio::test]
async fn shutdown_while_connecting_terminates_the_child() {
    let tunnel = Tunnel::start(false, false).await;
    let pid = tunnel.mock.wait_for_pids(1).await[0].clone();
    assert!(is_alive(&pid));

    let Tunnel { mock, handle, .. } = tunnel;
    tokio::time::timeout(WAIT, handle.shutdown())
        .await
        .expect("supervisor did not stop");
    assert_eq!(mock.lines("terms").len(), 1);
    assert!(!is_alive(&pid));
}

#[tokio::test]
async fn no_reconnect_signals_the_app_and_stays_down() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let mut tunnel = Tunnel::start(true, true).await;
    tunnel.handle.wait_ready(WAIT).await.unwrap();
    let proxy = Proxy::start(
        "ssh-no-reconnect",
        ProxyOptions::separate(),
        tunnel.dialer(),
    )
    .await;
    assert_traffic_flows(&proxy, origin.addr.port(), echo.addr.port()).await;
    assert!(!tunnel.app.is_cancelled());

    let pid = tunnel.mock.wait_for_pids(1).await[0].clone();
    kill_hard(&pid);
    tokio::time::timeout(WAIT, tunnel.app.cancelled())
        .await
        .expect("app token was not cancelled");
    tunnel.wait_not_ready().await;
    assert_tunnel_errors(&proxy, origin.addr.port(), echo.addr.port()).await;
    assert_eq!(tunnel.mock.lines("pids").len(), 1, "ssh must not restart");

    proxy.stop().await;
    tunnel.handle.shutdown().await;
}
