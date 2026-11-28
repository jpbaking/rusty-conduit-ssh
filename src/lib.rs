//! rusty-conduit-ssh: HTTP/HTTPS and SOCKS4/4a/5 proxy server routed through an SSH tunnel.
//!
//! The protocol front end (listeners, mux, HTTP/HTTPS, SOCKS4/4a/5, MITM, filter, logging)
//! is `rusty-conduit-engine`, re-exported here under the historical module paths. This
//! crate keeps the CLI/TOML layer ([`config`]), the `ssh` supervisor ([`ssh`]), the tunnel
//! dialer ([`net::Socks5UpstreamDialer`], registered as the API-only `external` engine
//! profile [`TUNNEL_PROFILE`] that every forward connection routes to), and the reverse
//! proxy ([`reverse`]: a second engine server with direct egress, exposed via `ssh -R`).

pub mod config;
pub mod fdlimit;
pub mod net;
pub mod preflight;
pub mod reverse;
pub mod ssh;
#[cfg(test)]
mod test_support;

pub use rusty_conduit_engine::{
    filter, http, logging, mitm, mux, router, routing, server, socks, upstream,
};
pub use server::EngineHandlers;

use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use config::{CliInput, Command, Config};
use http::{ErrorPageTemplate, HttpProxy};
use logging::{AccessLogConfig, AccessLogger, LogLevel, Logger, ProxyDirection};
use mitm::MitmState;
use net::{Socks5UpstreamDialer, UpstreamDialer, DEFAULT_CONNECT_TIMEOUT};
use reverse::ReverseProxy;
use routing::{
    OneOrMany, ProfileConfig, ProfileType, RoutingConfig, RoutingInput, RoutingSetupError,
    RoutingState, SharedRouting,
};
use server::{ProtocolHandlers, Server};
use socks::SocksProxy;
use ssh::{SshHandle, SshSupervisor, SshTunnelConfig};
use upstream::DialerOptions;

/// Exit code used for `FATAL` startup errors.
pub const EXIT_FATAL: u8 = 1;

/// Name of the API-only `external` engine profile that carries all forward traffic through
/// the `ssh -D` tunnel. Never shown in logs (routing fields are disabled).
pub const TUNNEL_PROFILE: &str = "ssh-tunnel";

/// Access-log settings: the rusty-conduit-ssh schema has no `rule` / `profile` / `upstream`
/// fields (there is no user-visible routing), and tags each record with `direction`.
pub fn access_log_config(cfg: &Config) -> AccessLogConfig {
    AccessLogConfig::new(
        cfg.log_level,
        cfg.log_format,
        cfg.http_access_log.clone(),
        cfg.socks_log.clone(),
    )
    .with_routing_fields(false)
}

/// Forward routing: every request goes to [`TUNNEL_PROFILE`] (served by `dialer`), with the
/// forward allow/block filter checked on the requested name or IP literal by the router (no
/// local DNS), the configured keepalive, and the default connect timeout.
pub fn forward_routing(
    cfg: &Config,
    dialer: Arc<dyn UpstreamDialer>,
) -> Result<RoutingState, RoutingSetupError> {
    let profiles = BTreeMap::from([(
        TUNNEL_PROFILE.to_string(),
        ProfileConfig::of_kind(ProfileType::External),
    )]);
    let input = RoutingInput {
        profiles,
        routing: RoutingConfig {
            default: OneOrMany::One(TUNNEL_PROFILE.to_string()),
            ..RoutingConfig::default()
        },
        filter: cfg.forward_filter(),
        mitm_enabled: cfg.mitm_enabled(),
        listeners: Vec::new(),
        keepalive: cfg.tcp_keepalive_settings(),
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
    };
    RoutingState::from_input(
        &input,
        DialerOptions::default().with_external(TUNNEL_PROFILE, dialer),
    )
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

/// Emit the startup banner, configuration summary, `INFO` notices, and MITM upstream-TLS warnings.
pub fn log_startup(cfg: &Config, logger: &Logger) {
    logger.info(format!(
        "rusty-conduit-ssh v{} starting",
        config::app_version()
    ));
    logger.info(format!("config: {}", cfg.summary()));
    for notice in cfg.notices() {
        logger.info(notice);
    }
    for warning in cfg.mitm_tls_warnings() {
        logger.info(warning);
    }
}

/// Connections the open-file limit must hold, and the flag(s) to name in the NOTICE.
fn fd_budget(cfg: &Config) -> (usize, &'static str) {
    match (cfg.forward_enabled(), cfg.reverse_enabled()) {
        (true, true) => {
            let cap = if cfg.max_connections == 0 || cfg.reverse_max_connections == 0 {
                0
            } else {
                cfg.max_connections
                    .saturating_add(cfg.reverse_max_connections)
            };
            (cap, "--max-connections + --reverse-max-connections")
        }
        (false, true) => (cfg.reverse_max_connections, "--reverse-max-connections"),
        _ => (cfg.max_connections, "--max-connections"),
    }
}

/// Run with an already-validated configuration until a process signal arrives or the tunnel
/// drops under `--no-reconnect`. Returns the process exit code. Must be called inside a Tokio
/// runtime.
pub async fn run(cfg: Config, logger: Logger) -> ExitCode {
    let interrupted = CancellationToken::new();
    let signal_token = interrupted.clone();
    let signal_logger = logger.clone();
    let signals = tokio::spawn(async move {
        shutdown_signal(&signal_logger).await;
        signal_token.cancel();
    });
    let code = run_until(cfg, logger, interrupted).await;
    signals.abort();
    code
}

/// Like [`run`], but shuts down when `interrupted` is cancelled instead of on process signals.
///
/// Shutdown order: drain the forward server while `ssh -D` is still up, stop `ssh` (ending
/// `-R` forwarding), drain the reverse server, then flush the access logs.
pub async fn run_until(cfg: Config, logger: Logger, interrupted: CancellationToken) -> ExitCode {
    log_startup(&cfg, &logger);
    let (fd_connections, fd_flag) = fd_budget(&cfg);
    fdlimit::apply(&logger, fd_connections, fd_flag);

    let mut tunnel_cfg = match SshTunnelConfig::from_config(&cfg) {
        Ok(c) => c,
        Err(e) => {
            logger.fatal(e);
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let access = match AccessLogger::start(access_log_config(&cfg), logger.clone()).await {
        Ok(a) => a,
        Err(e) => {
            logger.fatal(format!("failed to open access log: {e}"));
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };

    // Fail on local problems before `ssh` starts, so a bad error page, CA, key, or SSH
    // config never costs a connection attempt (or a retry loop) against the SSH server.
    let error_page = match cfg.error_page_template() {
        Ok(t) => t,
        Err(e) => {
            logger.fatal(format!("config invalid: {e}"));
            if let Err(e) = access.shutdown().await {
                logger.error(format!("failed to flush access logs: {e}"));
            }
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    if let Err(e) = preflight_before_ssh(&cfg, &tunnel_cfg) {
        logger.fatal(e);
        if let Err(e) = access.shutdown().await {
            logger.error(format!("failed to flush access logs: {e}"));
        }
        logger.flush();
        return ExitCode::from(EXIT_FATAL);
    }

    // Bound before `ssh` starts so the `-R` targets are known and survive reconnects.
    let reverse = match ReverseProxy::start(&cfg, &access, &logger, &error_page).await {
        Ok(reverse) => reverse,
        Err(message) => {
            logger.fatal(message);
            if let Err(e) = access.shutdown().await {
                logger.error(format!("failed to flush access logs: {e}"));
            }
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    if let Some(reverse) = &reverse {
        tunnel_cfg.reverse_forwards = reverse.forwards().to_vec();
    }

    // Deliberately separate tokens: a signal must not stop `ssh` until the server has drained,
    // so only the supervisor cancels `tunnel_lost`, and only signals cancel `interrupted`.
    let tunnel_lost = CancellationToken::new();
    let (ssh, tunnel_state) = SshSupervisor::spawn(tunnel_cfg, logger.clone(), tunnel_lost.clone());
    let dialer: Arc<dyn UpstreamDialer> = Arc::new(Socks5UpstreamDialer::new(tunnel_state));

    let outcome = serve(
        &cfg,
        &logger,
        &access,
        &ssh,
        ForwardInputs {
            dialer,
            error_page: &error_page,
        },
        &tunnel_lost,
        &interrupted,
    )
    .await;
    ssh.shutdown().await;
    if let Some(reverse) = reverse {
        if reverse.shutdown().await.drained {
            logger.debug("all reverse proxy connections drained");
        }
    }

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

/// What the forward engines are built from: the tunnel dialer and the loaded error page.
struct ForwardInputs<'a> {
    dialer: Arc<dyn UpstreamDialer>,
    error_page: &'a ErrorPageTemplate,
}

/// Wait for the tunnel, then bind and run the server until it has drained. An `Err` is a
/// `FATAL` startup failure; a signal during startup is a clean exit.
async fn serve(
    cfg: &Config,
    logger: &Logger,
    access: &AccessLogger,
    ssh: &SshHandle,
    forward: ForwardInputs<'_>,
    tunnel_lost: &CancellationToken,
    interrupted: &CancellationToken,
) -> Result<(), String> {
    // Built before waiting so a bad CA fails without sitting through SSH authentication.
    let mitm = if cfg.forward_enabled() {
        MitmState::from_options(&cfg.mitm_options())
            .map_err(|e| format!("MITM setup failed: {e}"))?
    } else {
        None
    };
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

    // Reverse-only mode: no forward listeners, so just keep the tunnel up.
    if !cfg.forward_enabled() {
        tokio::select! {
            () = interrupted.cancelled() => {}
            () = tunnel_lost.cancelled() => {}
        }
        return Ok(());
    }

    let routing = forward_routing(cfg, forward.dialer)
        .map_err(|e| format!("forward routing setup failed: {e}"))?
        .shared();
    let access = access.clone().with_direction(ProxyDirection::Forward);
    let (http, socks) = build_engines_with(
        cfg,
        mitm.as_ref(),
        &access,
        logger,
        routing,
        forward.error_page.clone(),
    );
    let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
    let server = Server::from_options(&cfg.server_options(), handlers, logger.clone())
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

/// Build the forward HTTP and SOCKS engines, all dialing through `dialer` (see
/// [`forward_routing`]) and logging with `direction=forward`, enabling HTTPS interception
/// when `mitm` is present and the SOCKS web guard when additionally
/// `--socks-block-web` is set, and the `--error-page` template (or the built-in page) for
/// proxy-generated HTTP errors.
///
/// # Panics
///
/// If the `--error-page` file cannot be read; [`run`] reports that error via
/// [`Config::error_page_template`] instead.
pub fn build_engines(
    cfg: &Config,
    mitm: Option<&MitmState>,
    access: &AccessLogger,
    logger: &Logger,
    dialer: Arc<dyn UpstreamDialer>,
) -> (HttpProxy, SocksProxy) {
    let routing = forward_routing(cfg, dialer)
        .expect("the fixed single-profile forward routing always compiles")
        .shared();
    let access = access.clone().with_direction(ProxyDirection::Forward);
    let error_page = cfg.error_page_template().unwrap_or_else(|e| panic!("{e}"));
    build_engines_with(cfg, mitm, &access, logger, routing, error_page)
}

/// Build the HTTP and SOCKS engines over `routing`, logging through `access` (already tagged
/// with its direction) in the rusty-conduit-ssh schema (no routing fields), with MITM, the
/// SOCKS web guard, and the loaded `error_page` as for [`build_engines`].
pub(crate) fn build_engines_with(
    cfg: &Config,
    mitm: Option<&MitmState>,
    access: &AccessLogger,
    logger: &Logger,
    routing: SharedRouting,
    error_page: ErrorPageTemplate,
) -> (HttpProxy, SocksProxy) {
    let access = access.clone().with_routing_fields(false);
    if let Some(path) = &cfg.error_page {
        logger.info(format!("custom error page enabled: {}", path.display()));
    }
    // Only proxy-generated errors use the template; upstream responses pass through untouched.
    let engines =
        EngineHandlers::from_routing(routing, access, logger.clone()).with_error_page(error_page);
    let mut http = engines.http_engine().clone();
    let mut socks = engines.socks_engine().clone();
    if let Some(m) = mitm {
        logger.info(format!(
            "MITM enabled: CA \"{}\" valid until {}; leaf certificate TTL {}",
            m.ca_subject,
            logging::format_timestamp(m.ca_not_after),
            humantime::format_duration(cfg.mitm_cert_ttl)
        ));
        http = http.with_mitm(Arc::new(m.interceptor.clone()));
    }
    if cfg.socks_block_web {
        logger.info("SOCKS web blocking enabled: HTTP/HTTPS over SOCKS is rejected");
        socks = socks.with_guard(Arc::new(socks::web_guard::WebGuard));
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

/// The offline checks startup would fail on before launching `ssh` (see [`preflight`]):
/// the MITM CA and the `ssh` setup. Nothing connects to the SSH server.
pub fn preflight_before_ssh(cfg: &Config, tunnel: &SshTunnelConfig) -> Result<(), String> {
    preflight::check_mitm(&cfg.mitm_options())?;
    ssh::check_ssh_setup(tunnel)
}

/// Every offline check startup would fail on, in startup order: the access logs, the
/// `--error-page` template, then [`preflight_before_ssh`].
pub fn preflight_checks(cfg: &Config) -> Result<(), String> {
    let tunnel = SshTunnelConfig::from_config(cfg).map_err(|e| e.to_string())?;
    if let Some(path) = &cfg.http_access_log {
        preflight::check_log_path("--http-access-log", path)?;
    }
    if let Some(path) = &cfg.socks_log {
        preflight::check_log_path("--socks-log", path)?;
    }
    cfg.error_page_template()?;
    preflight_before_ssh(cfg, &tunnel)
}

/// `validate [TARGET] [--settings-only]`: exit 0 when the configuration is valid, 1 otherwise.
///
/// Without `--settings-only`, it also runs the [`preflight_checks`] and reports the
/// open-file limit as startup would.
pub fn cmd_validate(mut cli: CliInput, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut settings_only = false;
    if let Some(Command::Validate {
        target,
        settings_only: only,
    }) = cli.args.command.take()
    {
        settings_only = only;
        if let Some(t) = target {
            cli.args.target = Some(t);
        }
    }
    match load_config(cli) {
        Ok(cfg) => {
            if !settings_only {
                if let Err(e) = preflight_checks(&cfg) {
                    let _ = writeln!(err, "config invalid: {e}");
                    return EXIT_FATAL;
                }
            }
            let path = cfg
                .config_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string());
            let target = cfg.ssh_target.as_deref().unwrap_or("none");
            let _ = writeln!(out, "config OK: {path} target={target}");
            for notice in cfg.notices() {
                let _ = writeln!(out, "{notice}");
            }
            for warning in cfg.mitm_tls_warnings() {
                let _ = writeln!(out, "{warning}");
            }
            if !settings_only {
                let (connections, flag) = fd_budget(&cfg);
                if let Some(notice) = preflight::fd_limit_notice(connections, flag) {
                    let _ = writeln!(out, "{notice}");
                }
            }
            0
        }
        Err((e, _)) => {
            let _ = writeln!(err, "config invalid: {e}");
            EXIT_FATAL
        }
    }
}

/// Full CLI entrypoint: parse args/env (help/version/usage errors exit inside `clap`),
/// load and validate config, then run on a multi-threaded Tokio runtime.
pub fn main_entry() -> ExitCode {
    let cli = CliInput::parse();
    if matches!(cli.args.command, Some(Command::Validate { .. })) {
        return ExitCode::from(cmd_validate(
            cli,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        ));
    }
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
    use crate::server::ListenPlan;
    use crate::test_support::{
        capture_access, direct_dialer, echo_roundtrip, quiet_logger, spawn_echo, Buf,
    };

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
        let (http, socks) = build_engines(
            &Config::default(),
            None,
            &access,
            &quiet_logger(),
            direct_dialer(),
        );
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
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
        use crate::http::mitm_tunnel::client_config_with_roots;
        use crate::test_support::{self as mt, test_ca};
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
            &cfg.mitm_options(),
            &cfg.ca_source().unwrap(),
            provider,
            upstream,
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
        use crate::test_support::test_ca;

        let dir = std::env::temp_dir().join(format!("rc-lib-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = test_ca();
        let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
        std::fs::write(&cert, &ca.cert_pem).unwrap();
        std::fs::write(&key, &ca.key_pem).unwrap();
        let mut cfg = Config {
            mitm_ca_cert: Some(cert),
            mitm_ca_key: Some(key),
            socks_block_web: true,
            ..Config::default()
        };
        let provider = crate::mitm::crypto_provider();
        let upstream =
            client_config_with_roots(provider.clone(), rustls::RootCertStore::empty()).unwrap();
        let state = MitmState::build(
            &cfg.mitm_options(),
            &cfg.ca_source().unwrap(),
            provider,
            upstream,
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
        assert_eq!(
            guarded(&h, &s),
            (false, true),
            "MITM off: SOCKS web guard still active when flag is set"
        );
        cfg.socks_block_web = false;
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

    #[test]
    fn fd_budget_forward_only_defaults() {
        let cfg = Config::default();
        assert_eq!(fd_budget(&cfg), (4096, "--max-connections"));
    }

    #[test]
    fn fd_budget_forward_and_reverse_sums_caps() {
        let cfg = Config {
            reverse_http_port: 9,
            reverse_max_connections: 10,
            ..Config::default()
        };
        assert_eq!(
            fd_budget(&cfg),
            (4106, "--max-connections + --reverse-max-connections")
        );
    }

    #[test]
    fn fd_budget_forward_and_reverse_zero_disables() {
        let cfg = Config {
            max_connections: 0,
            reverse_http_port: 9,
            reverse_max_connections: 10,
            ..Config::default()
        };
        assert_eq!(
            fd_budget(&cfg),
            (0, "--max-connections + --reverse-max-connections")
        );
    }

    #[test]
    fn fd_budget_reverse_only() {
        let cfg = Config {
            http_port: 0,
            socks_port: 0,
            reverse_socks_port: 9,
            ..Config::default()
        };
        assert_eq!(
            fd_budget(&cfg),
            (cfg.reverse_max_connections, "--reverse-max-connections")
        );
    }

    /// Write sink shared with the test, for reading back `Logger` output.
    #[derive(Clone, Default)]
    struct SharedOut(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedOut {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn missing_error_page() -> std::path::PathBuf {
        std::env::temp_dir().join("rusty-conduit-ssh-missing-error-page.html")
    }

    #[test]
    fn missing_error_page_fails_preflight_naming_the_path() {
        let missing = missing_error_page();
        let cfg = Config {
            ssh_target: Some("user@example.invalid".into()),
            error_page: Some(missing.clone()),
            ..Config::default()
        };
        cfg.validate()
            .expect("settings alone stay valid (--settings-only)");
        let err = preflight_checks(&cfg).unwrap_err();
        assert!(
            err.starts_with(&format!("cannot read --error-page {}", missing.display())),
            "{err}"
        );
    }

    #[tokio::test]
    async fn missing_error_page_fails_startup_with_fatal_exit() {
        let missing = missing_error_page();
        let cfg = Config {
            ssh_target: Some("user@example.invalid".into()),
            ssh_bin: "/nonexistent/rusty-conduit-ssh-test-ssh".into(),
            no_reconnect: true,
            error_page: Some(missing.clone()),
            ..Config::default()
        };
        let out = SharedOut::default();
        let logger = Logger::with_writer(LogLevel::Fatal, Box::new(out.clone()));
        assert_eq!(run(cfg, logger).await, ExitCode::from(EXIT_FATAL));
        let log = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        // The error page is checked before the `ssh` setup, so it is the reported failure.
        assert!(
            log.contains(&format!(
                "config invalid: cannot read --error-page {}",
                missing.display()
            )),
            "{log}"
        );
    }

    #[tokio::test]
    async fn build_engines_installs_the_error_page() {
        let page = std::env::temp_dir().join(format!(
            "rusty-conduit-ssh-error-page-{}.html",
            std::process::id()
        ));
        std::fs::write(&page, "<p>custom {{status}} {{reason}} [{{target}}]</p>").unwrap();
        let cfg = Config {
            error_page: Some(page.clone()),
            ..Config::default()
        };
        let (access, _buf) = capture_access().await;
        let (http, _socks) = build_engines(&cfg, None, &access, &quiet_logger(), direct_dialer());
        assert!(!http.error_page().is_builtin());
        assert_eq!(
            http.error_page().as_str(),
            "<p>custom {{status}} {{reason}} [{{target}}]</p>"
        );
        let (http, _socks) = build_engines(
            &Config::default(),
            None,
            &access,
            &quiet_logger(),
            direct_dialer(),
        );
        assert!(http.error_page().is_builtin());
        let _ = std::fs::remove_file(&page);
    }

    /// The reverse proxy renders its own errors with the template; origin responses pass
    /// through untouched.
    #[tokio::test]
    async fn reverse_proxy_uses_the_error_page() {
        let origin = spawn_origin().await;
        let cfg = Config {
            reverse_http_port: 18080,
            reverse_block: vec!["blocked.invalid".parse().unwrap()],
            ..Config::default()
        };
        let template = ErrorPageTemplate::from_template("<p>custom {{status}} [{{target}}]</p>");
        let (access, _log) = capture_access().await;
        let reverse = ReverseProxy::start(&cfg, &access, &quiet_logger(), &template)
            .await
            .unwrap()
            .expect("reverse proxy enabled");
        let addr = reverse.forwards()[0].local;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET http://blocked.invalid/x HTTP/1.1\r\nHost: blocked.invalid\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
        assert!(
            resp.ends_with("<p>custom 403 [blocked.invalid]</p>"),
            "{resp}"
        );

        let resp = proxied_get(addr, origin).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("origin"), "{resp}");
        reverse.shutdown().await;
    }
}
