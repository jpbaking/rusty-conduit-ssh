//! rusty-conduit-ssh: HTTP/HTTPS and SOCKS4/4a/5 proxy server routed through an SSH tunnel.

pub mod config;
pub mod http;
pub mod logging;
pub mod mitm;
pub mod mux;
pub mod net;
pub mod server;
pub mod socks;
pub mod ssh;

use std::process::ExitCode;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use config::{CliInput, Config};
use http::HttpProxy;
use logging::{AccessLogConfig, AccessLogger, LogLevel, Logger};
use mitm::MitmState;
use net::{Socks5UpstreamDialer, UpstreamDialer};
use server::{Connection, HandlerFuture, ProtocolHandlers, Server};
use socks::SocksProxy;
use ssh::{SshHandle, SshSupervisor, SshTunnelConfig};

/// Exit code used for `FATAL` startup errors.
pub const EXIT_FATAL: u8 = 1;

/// Protocol engines wired into the [`Server`]: the HTTP/HTTPS proxy for HTTP connections
/// and the SOCKS4/4a/5 engine for SOCKS connections (dedicated and multiplexed listeners).
#[derive(Debug, Clone)]
pub struct EngineHandlers {
    http: HttpProxy,
    socks: SocksProxy,
}

impl EngineHandlers {
    pub fn new(http: HttpProxy, socks: SocksProxy) -> Self {
        Self { http, socks }
    }
}

impl ProtocolHandlers for EngineHandlers {
    fn http(&self, conn: Connection) -> HandlerFuture {
        let proxy = self.http.clone();
        Box::pin(async move { proxy.serve(conn).await })
    }
    fn socks4(&self, conn: Connection) -> HandlerFuture {
        let proxy = self.socks.clone();
        Box::pin(async move { proxy.serve_v4(conn).await })
    }
    fn socks5(&self, conn: Connection) -> HandlerFuture {
        let proxy = self.socks.clone();
        Box::pin(async move { proxy.serve_v5(conn).await })
    }
}

/// Merge and validate configuration from parsed CLI/env input.
///
/// On failure returns the error together with the best-known log level (the merged level if
/// merging succeeded, otherwise the CLI/env level, otherwise the default `INFO`), so the
/// `FATAL` message can still honour `--log-level QUIET`.
pub fn load_config(cli: CliInput) -> Result<Config, (config::ConfigError, LogLevel)> {
    let fallback_level = cli.args.log_level.unwrap_or(LogLevel::Info);
    let cfg = Config::from_cli(cli).map_err(|e| (e, fallback_level))?;
    cfg.validate().map_err(|e| (e, cfg.log_level))?;
    Ok(cfg)
}

/// Emit the startup banner, configuration summary, and any `INFO` notices.
pub fn log_startup(cfg: &Config, logger: &Logger) {
    logger.info(format!(
        "rusty-conduit-ssh v{} starting",
        env!("CARGO_PKG_VERSION")
    ));
    logger.info(format!("config: {}", cfg.summary()));
    for notice in cfg.notices() {
        logger.info(notice);
    }
}

/// Run with an already-validated configuration. Returns the process exit code.
///
/// Starts the SSH tunnel, serves until a signal arrives or the tunnel drops under
/// `--no-reconnect`, then drains the server *before* stopping `ssh` so in-flight connections
/// keep their tunnel. Must be called inside a Tokio runtime.
pub async fn run(cfg: Config, logger: Logger) -> ExitCode {
    log_startup(&cfg, &logger);

    let tunnel_cfg = match SshTunnelConfig::from_config(&cfg) {
        Ok(c) => c,
        Err(e) => {
            logger.fatal(e);
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let access = match AccessLogger::start(
        AccessLogConfig::new(
            cfg.log_level,
            cfg.log_format,
            cfg.http_access_log.clone(),
            cfg.socks_log.clone(),
        ),
        logger.clone(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            logger.fatal(format!("failed to open access log: {e}"));
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };

    // Deliberately separate tokens: a signal must not stop `ssh` until the server has drained,
    // so only the supervisor cancels `tunnel_lost`, and only signals cancel `interrupted`.
    let tunnel_lost = CancellationToken::new();
    let interrupted = CancellationToken::new();
    let (ssh, tunnel_state) = SshSupervisor::spawn(tunnel_cfg, logger.clone(), tunnel_lost.clone());
    let dialer: Arc<dyn UpstreamDialer> = Arc::new(Socks5UpstreamDialer::new(tunnel_state));

    let signal_token = interrupted.clone();
    let signal_logger = logger.clone();
    let signals = tokio::spawn(async move {
        shutdown_signal(&signal_logger).await;
        signal_token.cancel();
    });

    let outcome = serve(
        &cfg,
        &logger,
        &access,
        &ssh,
        dialer,
        &tunnel_lost,
        &interrupted,
    )
    .await;
    signals.abort();
    ssh.shutdown().await;

    logger.info("shutting down");
    let mut code = ExitCode::SUCCESS;
    if let Err(message) = outcome {
        logger.fatal(message);
        code = ExitCode::from(EXIT_FATAL);
    }
    if let Err(e) = access.shutdown().await {
        logger.error(format!("failed to flush access logs: {e}"));
        code = ExitCode::from(EXIT_FATAL);
    }
    logger.flush();
    code
}

/// Wait for the tunnel, then bind and run the server until it has drained. An `Err` is a
/// `FATAL` startup failure; a signal during startup is a clean exit.
async fn serve(
    cfg: &Config,
    logger: &Logger,
    access: &AccessLogger,
    ssh: &SshHandle,
    dialer: Arc<dyn UpstreamDialer>,
    tunnel_lost: &CancellationToken,
    interrupted: &CancellationToken,
) -> Result<(), String> {
    // Built before waiting so a bad CA fails without sitting through SSH authentication.
    let mitm = MitmState::from_config(cfg, Arc::clone(&dialer))
        .map_err(|e| format!("MITM setup failed: {e}"))?;
    if let Some(m) = &mitm {
        m.cache.set_logger(logger.clone());
    }

    tokio::select! {
        biased;
        () = interrupted.cancelled() => return Ok(()),
        ready = ssh.wait_ready(cfg.ssh_startup_timeout) => {
            ready.map_err(|e| e.to_string())?;
        }
    }

    let (http, socks) = build_engines(cfg, mitm.as_ref(), access, logger, dialer);
    let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
    let server = Server::from_config(cfg, handlers, logger.clone())
        .await
        .map_err(|e| e.to_string())?;
    // The leaf-certificate reaper runs only when MITM is enabled and stops on shutdown.
    let reaper = mitm.as_ref().map(|m| {
        m.cache
            .spawn_reaper(server.shutdown_token(), logger.clone())
    });
    for (role, addr) in server.listeners() {
        logger.info(format!("{role} proxy listening on {addr}"));
    }

    let token = server.shutdown_token();
    let (lost, signal) = (tunnel_lost.clone(), interrupted.clone());
    tokio::spawn(async move {
        tokio::select! {
            () = signal.cancelled() => token.cancel(),
            () = lost.cancelled() => token.cancel(),
            () = token.cancelled() => {}
        }
    });
    let report = server.run().await;
    if report.drained {
        logger.debug("all connections drained");
    }
    if let Some(reaper) = reaper {
        let _ = reaper.await;
    }
    Ok(())
}

/// Build the HTTP and SOCKS engines, all dialing through `dialer`, enabling HTTPS interception
/// when `mitm` is present and the SOCKS web guard when additionally
/// `--socks-block-web-in-mitm` is set.
pub fn build_engines(
    cfg: &Config,
    mitm: Option<&MitmState>,
    access: &AccessLogger,
    logger: &Logger,
    dialer: Arc<dyn UpstreamDialer>,
) -> (HttpProxy, SocksProxy) {
    let mut http = HttpProxy::new(access.clone(), logger.clone(), Arc::clone(&dialer));
    let mut socks = SocksProxy::new(access.clone(), logger.clone(), dialer);
    if let Some(m) = mitm {
        logger.info(format!(
            "MITM enabled: CA \"{}\" valid until {}; leaf certificate TTL {}",
            m.ca_subject,
            logging::format_timestamp(m.ca_not_after),
            humantime::format_duration(cfg.mitm_cert_ttl)
        ));
        http = http.with_mitm(Arc::new(m.interceptor.clone()));
        if cfg.socks_block_web_in_mitm {
            logger.info("SOCKS web blocking enabled: HTTP/HTTPS over SOCKS is rejected");
            socks = socks.with_guard(Arc::new(socks::web_guard::WebGuard));
        }
    }
    (http, socks)
}

/// Resolve when the process receives `Ctrl+C` (all platforms) or `SIGTERM` (Unix).
///
/// If a signal handler cannot be installed the error is logged and that source is ignored.
pub async fn shutdown_signal(logger: &Logger) {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => logger.info("received Ctrl+C"),
            Err(e) => {
                logger.error(format!("failed to listen for Ctrl+C: {e}"));
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                logger.info("received SIGTERM");
            }
            Err(e) => {
                logger.error(format!("failed to listen for SIGTERM: {e}"));
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Full CLI entrypoint: parse args/env (help/version/usage errors exit inside `clap`),
/// load and validate config, then run on a multi-threaded Tokio runtime.
pub fn main_entry() -> ExitCode {
    let cli = CliInput::parse();
    let cfg = match load_config(cli) {
        Ok(cfg) => cfg,
        Err((e, level)) => {
            let logger = Logger::stderr(level);
            logger.fatal(e);
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let logger = Logger::stderr(cfg.log_level);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            logger.fatal(format!("failed to start async runtime: {e}"));
            return ExitCode::from(EXIT_FATAL);
        }
    };
    runtime.block_on(run(cfg, logger))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::test_support::{capture_access, direct_dialer, quiet_logger, Buf};
    use crate::server::ListenPlan;
    use crate::socks::test_support::{echo_roundtrip, spawn_echo};

    use std::net::SocketAddr;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    /// Origin replying with a fixed HTTP/1.1 response and then closing.
    async fn spawn_origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(&mut sock);
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    sock.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
                    )
                    .await
                    .unwrap();
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    async fn proxied_get(proxy: SocketAddr, origin: SocketAddr) -> String {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET http://{origin}/x HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        out
    }

    async fn check_plan(plan: ListenPlan) {
        let origin = spawn_origin().await;
        let (server, log) = engine_server(plan).await;
        let addr = server.local_http_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());

        let resp = proxied_get(addr, origin).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("origin"), "{resp}");
        let lines = log.wait_lines(1).await;
        assert!(
            lines[0].contains("proto=http mitm=false method=GET"),
            "{lines:?}"
        );

        token.cancel();
        assert!(run.await.unwrap().drained);
    }

    async fn engine_server(plan: ListenPlan) -> (Server, Buf) {
        let (access, log) = capture_access().await;
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(
            HttpProxy::new(access.clone(), quiet_logger(), direct_dialer()),
            SocksProxy::new(access, quiet_logger(), direct_dialer()),
        ));
        let server = Server::bind(plan, handlers, quiet_logger()).await.unwrap();
        (server, log)
    }

    /// SOCKS4 (IPv4), SOCKS4a (domain), and SOCKS5 (IPv4) round trips through the server.
    async fn check_socks_plan(plan: ListenPlan) {
        let echo = spawn_echo("127.0.0.1:0").await;
        let (server, log) = engine_server(plan).await;
        let addr = server.local_socks_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());
        let port = echo.port().to_be_bytes();

        let mut v4 = vec![4, 1, port[0], port[1], 127, 0, 0, 1, 0];
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&v4).await.unwrap();
        let mut rep = [0u8; 8];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x5A);
        assert_eq!(echo_roundtrip(s, b"four").await, b"four");

        v4.truncate(4);
        v4.extend_from_slice(&[0, 0, 0, 1, 0]);
        v4.extend_from_slice(b"localhost\0");
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&v4).await.unwrap();
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x5A);
        assert_eq!(echo_roundtrip(s, b"four-a").await, b"four-a");

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [5, 0]);
        s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .await
            .unwrap();
        let mut rep5 = [0u8; 10];
        s.read_exact(&mut rep5).await.unwrap();
        assert_eq!(rep5[1], 0x00);
        assert_eq!(echo_roundtrip(s, b"five").await, b"five");

        let lines = log.wait_lines(3).await;
        for proto in ["socks4", "socks4a", "socks5"] {
            let needle = format!("proto={proto} cmd=CONNECT");
            assert!(lines.iter().any(|l| l.contains(&needle)), "{lines:?}");
        }
        assert!(lines.iter().all(|l| l.contains("status=ok")), "{lines:?}");

        token.cancel();
        assert!(run.await.unwrap().drained);
    }

    #[tokio::test]
    async fn socks_active_on_dedicated_socks_listener() {
        check_socks_plan(ListenPlan::Separate {
            http: None,
            socks: Some("127.0.0.1:0".parse().unwrap()),
        })
        .await;
    }

    #[tokio::test]
    async fn socks_active_on_multiplexed_listener() {
        check_socks_plan(ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap())).await;
    }

    #[tokio::test]
    async fn http_proxy_active_on_dedicated_http_listener() {
        check_plan(ListenPlan::Separate {
            http: Some("127.0.0.1:0".parse().unwrap()),
            socks: None,
        })
        .await;
    }

    /// MITM wiring through `build_engines` + the real server on a multiplexed port.
    #[tokio::test]
    async fn mitm_active_through_server_wiring() {
        use crate::http::mitm_tunnel::{client_config_with_roots, test_support as mt};
        use crate::mitm::ca::test_support::test_ca;
        use http_body_util::BodyExt;

        let origin = mt::spawn_origin().await;
        let dir = std::env::temp_dir().join(format!("rc-lib-mitm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = test_ca();
        let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
        std::fs::write(&cert, &ca.cert_pem).unwrap();
        std::fs::write(&key, &ca.key_pem).unwrap();
        let cfg = Config {
            mitm_ca_cert: Some(cert),
            mitm_ca_key: Some(key),
            ..Config::default()
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(origin.ca_der.clone()).unwrap();
        let provider = crate::mitm::crypto_provider();
        let upstream = client_config_with_roots(provider.clone(), roots).unwrap();
        let state = MitmState::build(
            &cfg,
            &cfg.ca_source().unwrap(),
            provider,
            upstream,
            direct_dialer(),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        let (access, log) = capture_access().await;
        let (http, socks) = build_engines(
            &cfg,
            Some(&state),
            &access,
            &quiet_logger(),
            direct_dialer(),
        );
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
        let server = Server::bind(
            ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap()),
            handlers,
            quiet_logger(),
        )
        .await
        .unwrap();
        let addr = server.local_http_addr().unwrap();
        let token = server.shutdown_token();
        let reaper = state.cache.spawn_reaper(token.clone(), quiet_logger());
        let run = tokio::spawn(server.run());

        let target = format!("localhost:{}", origin.addr.port());
        let tcp = mt::connect_through(addr, &target).await;
        let tls = mt::tls_client(tcp, &ca, "localhost", &[b"http/1.1"])
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::get("/wired")
            .header(hyper::header::HOST, &target)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hit 1 GET /wired 0");
        drop(sender);

        let lines = log.wait_lines(1).await;
        assert!(
            lines[0].contains(&format!(
                "proto=https mitm=true method=GET target=https://{target}/wired status=200"
            )),
            "{lines:?}"
        );
        assert_eq!(state.cache.len(), 1);

        token.cancel();
        run.await.unwrap();
        reaper.await.unwrap();
    }

    #[tokio::test]
    async fn socks_web_guard_installed_only_with_mitm_and_flag() {
        use crate::http::mitm_tunnel::client_config_with_roots;
        use crate::mitm::ca::test_support::test_ca;

        let dir = std::env::temp_dir().join(format!("rc-lib-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = test_ca();
        let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
        std::fs::write(&cert, &ca.cert_pem).unwrap();
        std::fs::write(&key, &ca.key_pem).unwrap();
        let mut cfg = Config {
            mitm_ca_cert: Some(cert),
            mitm_ca_key: Some(key),
            socks_block_web_in_mitm: true,
            ..Config::default()
        };
        let provider = crate::mitm::crypto_provider();
        let upstream =
            client_config_with_roots(provider.clone(), rustls::RootCertStore::empty()).unwrap();
        let state = MitmState::build(
            &cfg,
            &cfg.ca_source().unwrap(),
            provider,
            upstream,
            direct_dialer(),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let (access, _log) = capture_access().await;
        let logger = quiet_logger();
        let guarded = |http: &HttpProxy, socks: &SocksProxy| {
            (
                format!("{http:?}").contains("mitm: true"),
                format!("{socks:?}").contains("guard: true"),
            )
        };

        let (h, s) = build_engines(&cfg, Some(&state), &access, &logger, direct_dialer());
        assert_eq!(guarded(&h, &s), (true, true));
        let (h, s) = build_engines(&cfg, None, &access, &logger, direct_dialer());
        assert_eq!(guarded(&h, &s), (false, false), "MITM off: flag inactive");
        cfg.socks_block_web_in_mitm = false;
        let (h, s) = build_engines(&cfg, Some(&state), &access, &logger, direct_dialer());
        assert_eq!(guarded(&h, &s), (true, false));
    }

    #[tokio::test]
    async fn run_is_fatal_when_tunnel_exits_with_no_reconnect() {
        let cfg = Config {
            ssh_target: Some("user@example.invalid".into()),
            ssh_bin: "/nonexistent/rusty-conduit-ssh-test-ssh".into(),
            no_reconnect: true,
            ..Config::default()
        };
        assert_eq!(run(cfg, quiet_logger()).await, ExitCode::from(EXIT_FATAL));
    }

    #[tokio::test]
    async fn http_proxy_active_on_multiplexed_listener() {
        check_plan(ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap())).await;
    }
}
