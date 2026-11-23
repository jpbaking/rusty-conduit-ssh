//! End-to-end tests for destination allowlist/blocklist filtering on forward and reverse paths.

#![cfg(unix)]

mod common;

use std::net::SocketAddr;
use std::process::ExitCode;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::filter::FilterRule;
use rusty_conduit_ssh::run_until;

use common::*;

const CONNECT: u8 = 1;
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

fn rules(list: &[&str]) -> Vec<FilterRule> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

fn reverse_specs(args: &[String]) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == "-R")
        .map(|w| w[1].clone())
        .collect()
}

fn listener_for(specs: &[String], remote_port: u16) -> SocketAddr {
    let needle = format!(":{remote_port}:");
    let spec = specs
        .iter()
        .find(|s| s.contains(&needle))
        .unwrap_or_else(|| panic!("no -R for port {remote_port} in {specs:?}"));
    let (_, local) = spec.split_once(&needle).unwrap();
    local.parse().unwrap()
}

async fn wait_connectable(addr: SocketAddr) {
    tokio::time::timeout(WAIT, async {
        while TcpStream::connect(addr).await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("listener {addr} never came up"));
}

async fn socks4a_connect(proxy: SocketAddr, host: &str, port: u16) -> u8 {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let mut req = vec![4, 1];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&[0, 0, 0, 1, 0]);
    req.extend_from_slice(host.as_bytes());
    req.push(0);
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 8];
    s.read_exact(&mut rep).await.unwrap();
    rep[1]
}

struct App {
    mock: MockSsh,
    socks: MockSocks,
    stop: CancellationToken,
    run: JoinHandle<ExitCode>,
}

impl App {
    async fn start(configure: impl FnOnce(&mut Config)) -> Self {
        let mock = MockSsh::new();
        let socks = MockSocks::start().await;
        socks.set_up(true);
        let mut cfg = Config {
            ssh_target: Some("user@filter.test".into()),
            ssh_bin: mock.bin(),
            ssh_socks_port: socks.addr.port(),
            http_port: 0,
            socks_port: 0,
            ssh_startup_timeout: WAIT,
            ..Config::default()
        };
        configure(&mut cfg);
        cfg.validate().unwrap();
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

    fn specs(&self) -> Vec<String> {
        reverse_specs(&self.mock.lines("args"))
    }

    async fn stop(self) {
        self.stop.cancel();
        let code = tokio::time::timeout(WAIT, self.run)
            .await
            .expect("application did not stop")
            .unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn forward_blocklist_rejects_matching_hosts_without_dialing_tunnel() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let port = closed_port().await;

    let app = App::start(|cfg| {
        cfg.http_port = port;
        cfg.socks_port = port;
        cfg.block = rules(&["*.blocked.test", "127.0.0.0/8"]);
    })
    .await;
    let proxy = SocketAddr::from((LOOPBACK, port));
    wait_connectable(proxy).await;

    // Blocked wildcard FQDN over HTTP GET, HTTPS CONNECT, SOCKS5, SOCKS4a
    let blocked_http = format!("api.blocked.test:{}", origin.addr.port());
    assert_eq!(http_get(proxy, &blocked_http, "/").await.status(), 403);
    let (_, status) = http_connect(proxy, &blocked_http).await;
    assert_eq!(status, 403);
    let (_, rep) = socks5(
        proxy,
        CONNECT,
        Socks5Addr::Domain("api.blocked.test"),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0x02);
    assert_eq!(
        socks4a_connect(proxy, "api.blocked.test", echo.addr.port()).await,
        0x5B
    );

    // Blocked CIDR literal IP
    let (_, rep) = socks5(proxy, CONNECT, Socks5Addr::V4(LOOPBACK), echo.addr.port()).await;
    assert_eq!(rep, 0x02);

    // None of the blocked requests should ever have touched ssh -D
    assert!(app.socks.dials().is_empty(), "{:?}", app.socks.dials());

    // Bare apex `blocked.test` is NOT matched by `*.blocked.test`, and `ok.test` is allowed
    let allowed = format!("ok.test:{}", origin.addr.port());
    assert_eq!(http_get(proxy, &allowed, "/").await.status(), 200);
    assert_eq!(app.socks.dials().len(), 1);

    app.stop().await;
}

#[tokio::test]
async fn forward_allowlist_permits_only_listed_hosts() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;
    let port = closed_port().await;

    let app = App::start(|cfg| {
        cfg.http_port = port;
        cfg.socks_port = port;
        cfg.allow = rules(&["*.allowed.test", "127.0.0.1/32"]);
    })
    .await;
    let proxy = SocketAddr::from((LOOPBACK, port));
    wait_connectable(proxy).await;

    // Unlisted domain and unlisted IP are rejected before touching ssh -D
    let denied = format!("other.test:{}", origin.addr.port());
    assert_eq!(http_get(proxy, &denied, "/").await.status(), 403);
    let (_, rep) = socks5(
        proxy,
        CONNECT,
        Socks5Addr::V4([10, 0, 0, 1]),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0x02);
    assert!(app.socks.dials().is_empty());

    // Listed wildcard domain and listed IP succeed
    let ok = format!("sub.allowed.test:{}", origin.addr.port());
    assert_eq!(http_get(proxy, &ok, "/").await.status(), 200);
    let (mut s, rep) = socks5(proxy, CONNECT, Socks5Addr::V4(LOOPBACK), echo.addr.port()).await;
    assert_eq!(rep, 0);
    assert_eq!(roundtrip(&mut s, b"ok").await, b"ok");
    drop(s);

    app.stop().await;
}

#[tokio::test]
async fn reverse_blocklist_blocks_loopback_ip_and_dns_resolving_to_loopback() {
    let origin = spawn_http_origin().await;
    let echo = spawn_echo().await;

    let app = App::start(|cfg| {
        cfg.reverse_http_port = 8888;
        cfg.reverse_socks_port = 8888;
        cfg.reverse_block = rules(&["127.0.0.0/8", "::1"]);
    })
    .await;
    let reverse = listener_for(&app.specs(), 8888);

    // Literal loopback IP is blocked
    assert_eq!(
        http_get(reverse, &origin.addr.to_string(), "/")
            .await
            .status(),
        403
    );
    let (_, rep) = socks5(reverse, CONNECT, Socks5Addr::V4(LOOPBACK), echo.addr.port()).await;
    assert_eq!(rep, 0x02);

    // Hostname `localhost` resolves locally to 127.0.0.1 / ::1 and is ALSO blocked!
    let localhost_origin = format!("localhost:{}", origin.addr.port());
    assert_eq!(
        http_get(reverse, &localhost_origin, "/").await.status(),
        403
    );
    let (_, rep) = socks5(
        reverse,
        CONNECT,
        Socks5Addr::Domain("localhost"),
        echo.addr.port(),
    )
    .await;
    assert_eq!(rep, 0x02);

    app.stop().await;
}

#[tokio::test]
async fn forward_and_reverse_filters_are_independent() {
    let origin = spawn_http_origin().await;
    let forward_port = closed_port().await;

    let app = App::start(|cfg| {
        cfg.http_port = forward_port;
        cfg.reverse_http_port = 8888;
        // Forward blocks `127.0.0.1`, reverse allows `127.0.0.1`
        cfg.block = rules(&["127.0.0.1"]);
        cfg.reverse_allow = rules(&["127.0.0.0/8"]);
    })
    .await;
    let forward = SocketAddr::from((LOOPBACK, forward_port));
    wait_connectable(forward).await;
    let reverse = listener_for(&app.specs(), 8888);

    assert_eq!(
        http_get(forward, &origin.addr.to_string(), "/")
            .await
            .status(),
        403
    );
    assert_eq!(
        http_get(reverse, &origin.addr.to_string(), "/")
            .await
            .status(),
        200
    );

    app.stop().await;
}
