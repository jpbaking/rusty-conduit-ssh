//! Supervisor for the system `ssh -N -T -D` dynamic tunnel.
//!
//! [`SshSupervisor::spawn`] runs `ssh`, probes its SOCKS listener for readiness, publishes
//! [`TunnelState`] over a `watch` channel, and restarts the process with exponential backoff.
//! With `--no-reconnect` it instead cancels the application shutdown token when the tunnel
//! drops. Stdin and stderr are inherited by default so interactive SSH auth keeps working.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ConfigError, SshIpVersion};
use crate::logging::Logger;
use crate::net::TunnelState;

/// How long `ssh` gets to exit after `SIGTERM` before it is killed.
const TERMINATE_GRACE: Duration = Duration::from_secs(3);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// With `-R`, the `-D` probe can pass before sshd has answered the remote bind request, so a
/// tunnel must stay up this long before a drop resets the reconnect backoff.
const REVERSE_STABLE_UPTIME: Duration = Duration::from_secs(5);

/// One `ssh -R` forward: `remote` is bound on the SSH target and connects back to `local`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReverseForward {
    pub remote: SocketAddr,
    pub local: SocketAddr,
}

impl ReverseForward {
    /// The `-R` argument. `SocketAddr` formatting brackets IPv6 as OpenSSH requires.
    pub fn spec(&self) -> String {
        format!("{}:{}", self.remote, self.local)
    }
}

/// Settings for the supervised `ssh` process.
#[derive(Clone, PartialEq, Eq)]
pub struct SshTunnelConfig {
    pub ssh_bin: PathBuf,
    pub target: String,
    pub socks_bind: IpAddr,
    /// Local `-D` port (`0` = pick a free port for each attempt).
    pub socks_port: u16,
    pub ip_version: SshIpVersion,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub jump: Option<String>,
    pub server_alive_interval: Duration,
    pub server_alive_count_max: u32,
    pub no_reconnect: bool,
    pub reconnect_initial_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub startup_timeout: Duration,
    /// Passed to `ssh` verbatim; may carry sensitive values, so never logged.
    pub extra_args: Vec<String>,
    /// Reverse forwards passed as `-R`; empty when the reverse proxy is disabled.
    pub reverse_forwards: Vec<ReverseForward>,
    /// Inherit stdin/stderr for interactive auth. When false both are discarded.
    pub inherit_stdio: bool,
}

impl fmt::Debug for SshTunnelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshTunnelConfig")
            .field("ssh_bin", &self.ssh_bin)
            .field("target", &self.target)
            .field("socks_bind", &self.socks_bind)
            .field("socks_port", &self.socks_port)
            .field("ip_version", &self.ip_version)
            .field("port", &self.port)
            .field("identity", &self.identity)
            .field("config_file", &self.config_file)
            .field("jump", &self.jump)
            .field("server_alive_interval", &self.server_alive_interval)
            .field("server_alive_count_max", &self.server_alive_count_max)
            .field("no_reconnect", &self.no_reconnect)
            .field("reconnect_initial_delay", &self.reconnect_initial_delay)
            .field("reconnect_max_delay", &self.reconnect_max_delay)
            .field("startup_timeout", &self.startup_timeout)
            .field(
                "extra_args",
                &format_args!("<{} redacted>", self.extra_args.len()),
            )
            .field("reverse_forwards", &self.reverse_forwards)
            .field("inherit_stdio", &self.inherit_stdio)
            .finish()
    }
}

impl SshTunnelConfig {
    /// Build tunnel settings from the merged configuration.
    pub fn from_config(cfg: &Config) -> Result<Self, ConfigError> {
        let target = cfg
            .ssh_target
            .clone()
            .ok_or(ConfigError::MissingSshTarget)?;
        if target.trim().is_empty() {
            return Err(ConfigError::EmptySshTarget);
        }
        Ok(Self {
            ssh_bin: cfg.ssh_bin.clone(),
            target,
            socks_bind: cfg.ssh_socks_bind,
            socks_port: cfg.ssh_socks_port,
            ip_version: cfg.ssh_ip_version,
            port: cfg.ssh_port,
            identity: cfg.ssh_identity.clone(),
            config_file: cfg.ssh_config.clone(),
            jump: cfg.ssh_jump.clone(),
            server_alive_interval: cfg.ssh_server_alive_interval,
            server_alive_count_max: cfg.ssh_server_alive_count_max,
            no_reconnect: cfg.no_reconnect,
            reconnect_initial_delay: cfg.reconnect_initial_delay,
            reconnect_max_delay: cfg.reconnect_max_delay,
            startup_timeout: cfg.ssh_startup_timeout,
            extra_args: cfg.ssh_extra_args.clone(),
            reverse_forwards: Vec::new(),
            inherit_stdio: true,
        })
    }
}

/// Errors reported while waiting for the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SshError {
    #[error("SSH tunnel not ready after {}", humantime::format_duration(*.0))]
    StartupTimeout(Duration),
    #[error("SSH tunnel stopped: {0}")]
    Stopped(String),
}

/// Ask the OS for a free TCP port on `ip`.
///
/// The port is released before returning, so `ssh` may lose a race for it. In that case
/// `ExitOnForwardFailure=yes` makes `ssh` exit and the next attempt picks a new port.
pub fn pick_loopback_port(ip: IpAddr) -> io::Result<u16> {
    Ok(TcpListener::bind((ip, 0))?.local_addr()?.port())
}

/// Build the `ssh` argument vector. `--` always precedes the target, so a target starting
/// with `-` can never be parsed as an option.
pub fn build_ssh_args(cfg: &SshTunnelConfig, socks_addr: SocketAddr) -> Vec<String> {
    let mut args: Vec<String> = vec!["-N".into(), "-T".into()];
    match cfg.ip_version {
        SshIpVersion::V4 => args.push("-4".into()),
        SshIpVersion::V6 => args.push("-6".into()),
        SshIpVersion::Auto => {}
    }
    args.extend([
        "-D".to_owned(),
        socks_addr.to_string(),
        "-o".to_owned(),
        "ExitOnForwardFailure=yes".to_owned(),
        "-o".to_owned(),
        format!(
            "ServerAliveInterval={}",
            whole_seconds(cfg.server_alive_interval)
        ),
        "-o".to_owned(),
        format!("ServerAliveCountMax={}", cfg.server_alive_count_max),
    ]);
    for forward in &cfg.reverse_forwards {
        args.extend(["-R".to_owned(), forward.spec()]);
    }
    if let Some(port) = cfg.port {
        args.extend(["-p".to_owned(), port.to_string()]);
    }
    if let Some(identity) = &cfg.identity {
        args.extend(["-i".to_owned(), identity.to_string_lossy().into_owned()]);
    }
    if let Some(config_file) = &cfg.config_file {
        args.extend(["-F".to_owned(), config_file.to_string_lossy().into_owned()]);
    }
    if let Some(jump) = &cfg.jump {
        args.extend(["-J".to_owned(), jump.clone()]);
    }
    args.extend(cfg.extra_args.iter().cloned());
    args.push("--".into());
    args.push(cfg.target.clone());
    args
}

/// How long `ssh -G` may take; a `Match exec` block in the SSH config can run commands.
const SSH_CONFIG_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Offline checks of the `ssh` setup, run by `validate` and before the first `ssh` starts:
/// the program exists, the `-i` and `-F` files can be read, and `ssh -G` accepts the
/// configuration for the target. Nothing connects to the SSH server.
pub fn check_ssh_setup(cfg: &SshTunnelConfig) -> Result<(), String> {
    let program = find_program(&cfg.ssh_bin)?;
    if let Some(identity) = &cfg.identity {
        std::fs::File::open(identity)
            .map_err(|e| format!("cannot read --ssh-identity {}: {e}", identity.display()))?;
    }
    if let Some(config_file) = &cfg.config_file {
        std::fs::File::open(config_file)
            .map_err(|e| format!("cannot read --ssh-config {}: {e}", config_file.display()))?;
    }
    check_ssh_config(&program, cfg)
}

/// Resolve the `ssh` program the supervisor will run: a path is checked as is, and a bare
/// name is searched for on `PATH`.
fn find_program(bin: &Path) -> Result<PathBuf, String> {
    if bin.components().count() > 1 {
        return if is_executable(bin) {
            Ok(bin.to_path_buf())
        } else if bin.exists() {
            Err(format!("--ssh-bin {} is not executable", bin.display()))
        } else {
            Err(format!("--ssh-bin {} does not exist", bin.display()))
        };
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
        if cfg!(windows) && candidate.extension().is_none() {
            let exe = candidate.with_extension("exe");
            if is_executable(&exe) {
                return Ok(exe);
            }
        }
    }
    Err(format!(
        "`{}` was not found on PATH; install an OpenSSH client or set --ssh-bin",
        bin.display()
    ))
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

/// Run `ssh -G` with the same arguments as the real launch. It evaluates the SSH config for
/// the target and exits without connecting.
fn check_ssh_config(program: &Path, cfg: &SshTunnelConfig) -> Result<(), String> {
    let placeholder = SocketAddr::new(cfg.socks_bind, 1);
    let mut child = std::process::Command::new(program)
        .arg("-G")
        .args(build_ssh_args(cfg, placeholder))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", program.display()))?;
    let deadline = std::time::Instant::now() + SSH_CONFIG_CHECK_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "`ssh -G` did not finish within {}s while checking the SSH configuration",
                    SSH_CONFIG_CHECK_TIMEOUT.as_secs()
                ));
            }
            Err(e) => return Err(format!("`ssh -G` failed: {e}")),
        }
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read;
        let _ = pipe.read_to_string(&mut stderr);
    }
    let detail = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    Err(if detail.is_empty() {
        format!("`ssh -G` rejected the SSH configuration ({status})")
    } else {
        format!("`ssh -G` rejected the SSH configuration: {detail}")
    })
}

/// Round up, because `ssh` takes whole seconds and `0` would disable keepalives.
fn whole_seconds(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

fn next_delay(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

/// Whether a drop after `uptime` should reset the backoff. A rejected `-R` bind exits `ssh`
/// just after the `-D` probe passes, and must not retry at the initial delay forever.
fn resets_backoff(cfg: &SshTunnelConfig, uptime: Duration) -> bool {
    cfg.reverse_forwards.is_empty() || uptime >= REVERSE_STABLE_UPTIME
}

/// Handle to a running supervisor.
#[derive(Debug)]
pub struct SshHandle {
    state: watch::Receiver<TunnelState>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl SshHandle {
    /// Wait until the tunnel is ready, returning its SOCKS address.
    ///
    /// Fails early if the supervisor stops (for example `--no-reconnect` after a failure).
    pub async fn wait_ready(&self, timeout: Duration) -> Result<SocketAddr, SshError> {
        let mut state = self.state.clone();
        let wait = async {
            loop {
                let current = state.borrow_and_update().clone();
                if let TunnelState::Ready(addr) = current {
                    return Ok(addr);
                }
                if state.changed().await.is_err() {
                    return match state.borrow().clone() {
                        TunnelState::Ready(addr) => Ok(addr),
                        TunnelState::Disconnected(reason) => Err(SshError::Stopped(reason)),
                        TunnelState::Connecting => {
                            Err(SshError::Stopped("supervisor exited".into()))
                        }
                    };
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or(Err(SshError::StartupTimeout(timeout)))
    }

    /// Stop the supervisor, terminate `ssh`, and wait for both to finish.
    ///
    /// This does not cancel the application token passed to [`SshSupervisor::spawn`].
    pub async fn shutdown(self) {
        self.stop.cancel();
        let _ = self.task.await;
    }
}

/// Spawns and supervises the `ssh` process.
#[derive(Debug, Clone, Copy)]
pub struct SshSupervisor;

impl SshSupervisor {
    /// Start supervising. Must be called within a Tokio runtime.
    ///
    /// Cancelling `shutdown` stops the tunnel. With `no_reconnect`, the supervisor cancels
    /// `shutdown` itself when the tunnel drops, which is how the application learns to exit.
    pub fn spawn(
        cfg: SshTunnelConfig,
        logger: Logger,
        shutdown: CancellationToken,
    ) -> (SshHandle, watch::Receiver<TunnelState>) {
        let (tx, rx) = watch::channel(TunnelState::Connecting);
        let stop = shutdown.child_token();
        let task = tokio::spawn(supervise(cfg, logger, tx, stop.clone(), shutdown));
        let handle = SshHandle {
            state: rx.clone(),
            stop,
            task,
        };
        (handle, rx)
    }
}

enum Attempt {
    Stopped,
    Dropped { reason: String, was_ready: bool },
}

async fn supervise(
    cfg: SshTunnelConfig,
    logger: Logger,
    state: watch::Sender<TunnelState>,
    stop: CancellationToken,
    app_shutdown: CancellationToken,
) {
    let mut delay = cfg.reconnect_initial_delay;
    while !stop.is_cancelled() {
        state.send_replace(TunnelState::Connecting);
        let (reason, was_ready) = match run_attempt(&cfg, &logger, &state, &stop).await {
            Attempt::Stopped => break,
            Attempt::Dropped { reason, was_ready } => (reason, was_ready),
        };
        state.send_replace(TunnelState::Disconnected(reason.clone()));

        if cfg.no_reconnect {
            logger.error(format!("SSH tunnel down, not reconnecting: {reason}"));
            app_shutdown.cancel();
            return;
        }
        if was_ready {
            delay = cfg.reconnect_initial_delay;
        }
        logger.error(format!(
            "SSH tunnel down: {reason}; reconnecting in {}",
            humantime::format_duration(delay)
        ));
        tokio::select! {
            () = stop.cancelled() => break,
            () = tokio::time::sleep(delay) => {}
        }
        delay = next_delay(delay, cfg.reconnect_max_delay);
    }
    state.send_replace(TunnelState::Disconnected("shut down".into()));
}

async fn run_attempt(
    cfg: &SshTunnelConfig,
    logger: &Logger,
    state: &watch::Sender<TunnelState>,
    stop: &CancellationToken,
) -> Attempt {
    let dropped = |reason: String, was_ready| Attempt::Dropped { reason, was_ready };

    let port = if cfg.socks_port == 0 {
        match pick_loopback_port(cfg.socks_bind) {
            Ok(port) => port,
            Err(e) => return dropped(format!("cannot pick local SOCKS port: {e}"), false),
        }
    } else {
        cfg.socks_port
    };
    let addr = SocketAddr::new(cfg.socks_bind, port);

    let stdio = |inherit| {
        if inherit {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    };
    let mut child = match Command::new(&cfg.ssh_bin)
        .args(build_ssh_args(cfg, addr))
        .stdin(stdio(cfg.inherit_stdio))
        .stdout(Stdio::null())
        .stderr(stdio(cfg.inherit_stdio))
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return dropped(
                format!("failed to start {}: {e}", cfg.ssh_bin.display()),
                false,
            );
        }
    };

    let deadline = Instant::now() + cfg.startup_timeout;
    tokio::select! {
        biased;
        () = stop.cancelled() => {
            terminate(&mut child).await;
            return Attempt::Stopped;
        }
        status = child.wait() => return dropped(exit_reason(status), false),
        () = tokio::time::sleep_until(deadline) => {
            terminate(&mut child).await;
            return dropped(
                format!(
                    "SOCKS listener not ready within {}",
                    humantime::format_duration(cfg.startup_timeout)
                ),
                false,
            );
        }
        () = wait_for_socks(addr) => {}
    }

    state.send_replace(TunnelState::Ready(addr));
    logger.info(format!("SSH tunnel ready on {addr}"));
    let ready_at = Instant::now();

    tokio::select! {
        biased;
        () = stop.cancelled() => {
            terminate(&mut child).await;
            Attempt::Stopped
        }
        status = child.wait() => {
            dropped(exit_reason(status), resets_backoff(cfg, ready_at.elapsed()))
        }
    }
}

fn exit_reason(status: io::Result<ExitStatus>) -> String {
    match status {
        Ok(status) => format!("ssh exited with {status}"),
        Err(e) => format!("failed to wait for ssh: {e}"),
    }
}

async fn wait_for_socks(addr: SocketAddr) {
    while !probe_socks5(addr).await {
        tokio::time::sleep(PROBE_INTERVAL).await;
    }
}

/// A plain TCP connect could be satisfied by an unrelated process, so require a SOCKS5
/// method-selection reply.
async fn probe_socks5(addr: SocketAddr) -> bool {
    let probe = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        Ok::<_, io::Error>(reply == [0x05, 0x00])
    };
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, probe).await,
        Ok(Ok(true))
    )
}

/// Stop `ssh`: `SIGTERM` first on Unix so it can restore the terminal, then kill.
async fn terminate(child: &mut Child) {
    if request_terminate(child).await
        && tokio::time::timeout(TERMINATE_GRACE, child.wait())
            .await
            .is_ok()
    {
        return;
    }
    let _ = child.kill().await;
}

/// Send `SIGTERM` using the system `kill`, which avoids a libc dependency. The child has not
/// been reaped while we hold it, so its PID cannot have been reused.
#[cfg(unix)]
async fn request_terminate(child: &Child) -> bool {
    let Some(pid) = child.id() else {
        return false;
    };
    Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

#[cfg(not(unix))]
async fn request_terminate(_child: &Child) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogLevel;
    use std::net::Ipv4Addr;

    fn base_config() -> SshTunnelConfig {
        let cfg = Config {
            ssh_target: Some("user@host".into()),
            ..Config::default()
        };
        SshTunnelConfig::from_config(&cfg).unwrap()
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn from_config_requires_a_target() {
        assert!(matches!(
            SshTunnelConfig::from_config(&Config::default()),
            Err(ConfigError::MissingSshTarget)
        ));
        let blank = Config {
            ssh_target: Some("  ".into()),
            ..Config::default()
        };
        assert!(matches!(
            SshTunnelConfig::from_config(&blank),
            Err(ConfigError::EmptySshTarget)
        ));
    }

    #[test]
    fn from_config_copies_settings_and_inherits_stdio() {
        let cfg = Config {
            ssh_target: Some("h".into()),
            ssh_port: Some(2222),
            no_reconnect: true,
            ssh_extra_args: vec!["-v".into()],
            ..Config::default()
        };
        let t = SshTunnelConfig::from_config(&cfg).unwrap();
        assert_eq!(t.target, "h");
        assert_eq!(t.port, Some(2222));
        assert!(t.no_reconnect);
        assert_eq!(t.extra_args, ["-v"]);
        assert!(t.inherit_stdio);
    }

    #[test]
    fn debug_redacts_extra_args() {
        let mut cfg = base_config();
        cfg.extra_args = vec!["-oProxyCommand=secret".into()];
        let text = format!("{cfg:?}");
        assert!(!text.contains("secret"));
        assert!(text.contains("<1 redacted>"));
    }

    #[test]
    fn argv_defaults() {
        let mut cfg = base_config();
        cfg.ip_version = SshIpVersion::V4;
        assert_eq!(
            build_ssh_args(&cfg, addr(1081)),
            [
                "-N",
                "-T",
                "-4",
                "-D",
                "127.0.0.1:1081",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
                "--",
                "user@host",
            ]
        );
    }

    #[test]
    fn argv_with_all_options() {
        let mut cfg = base_config();
        cfg.ip_version = SshIpVersion::V6;
        cfg.port = Some(2222);
        cfg.identity = Some("/k/id".into());
        cfg.config_file = Some("/k/config".into());
        cfg.jump = Some("bastion".into());
        cfg.server_alive_interval = Duration::from_millis(1500);
        cfg.server_alive_count_max = 9;
        cfg.extra_args = vec!["-v".into(), "-C".into()];
        let bind = SocketAddr::new("::1".parse().unwrap(), 1081);
        assert_eq!(
            build_ssh_args(&cfg, bind),
            [
                "-N",
                "-T",
                "-6",
                "-D",
                "[::1]:1081",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=2",
                "-o",
                "ServerAliveCountMax=9",
                "-p",
                "2222",
                "-i",
                "/k/id",
                "-F",
                "/k/config",
                "-J",
                "bastion",
                "-v",
                "-C",
                "--",
                "user@host",
            ]
        );
    }

    #[test]
    fn argv_auto_ip_version_has_no_family_flag() {
        let mut cfg = base_config();
        cfg.ip_version = SshIpVersion::Auto;
        let args = build_ssh_args(&cfg, addr(1081));
        assert!(!args.iter().any(|a| a == "-4" || a == "-6"));
    }

    #[test]
    fn argv_keeps_dash_target_after_separator() {
        let mut cfg = base_config();
        cfg.target = "-oProxyCommand=evil".into();
        let args = build_ssh_args(&cfg, addr(1081));
        assert_eq!(&args[args.len() - 2..], ["--", "-oProxyCommand=evil"]);
    }

    fn reverse(remote: &str, local: &str) -> ReverseForward {
        ReverseForward {
            remote: remote.parse().unwrap(),
            local: local.parse().unwrap(),
        }
    }

    fn reverse_specs(args: &[String]) -> Vec<&str> {
        args.windows(2)
            .filter(|w| w[0] == "-R")
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn argv_has_no_reverse_forward_by_default() {
        let args = build_ssh_args(&base_config(), addr(1081));
        assert!(!args.iter().any(|a| a == "-R"), "{args:?}");
    }

    #[test]
    fn argv_multiplexed_ipv4_reverse_forward() {
        let mut cfg = base_config();
        cfg.reverse_forwards = vec![reverse("127.0.0.1:8888", "127.0.0.1:54321")];
        let args = build_ssh_args(&cfg, addr(1081));
        assert_eq!(reverse_specs(&args), ["127.0.0.1:8888:127.0.0.1:54321"]);
        assert!(args.iter().any(|a| a == "ExitOnForwardFailure=yes"));
        let separator = args.iter().position(|a| a == "--").unwrap();
        let flag = args.iter().position(|a| a == "-R").unwrap();
        assert!(flag < separator, "{args:?}");
    }

    #[test]
    fn argv_separate_ipv6_reverse_forwards() {
        let mut cfg = base_config();
        cfg.reverse_forwards = vec![
            reverse("[::1]:8888", "127.0.0.1:54321"),
            reverse("[::1]:1081", "127.0.0.1:54322"),
        ];
        let args = build_ssh_args(&cfg, addr(1081));
        assert_eq!(
            reverse_specs(&args),
            ["[::1]:8888:127.0.0.1:54321", "[::1]:1081:127.0.0.1:54322"]
        );
    }

    #[test]
    fn backoff_reset_requires_stable_uptime_only_with_reverse() {
        let mut cfg = base_config();
        assert!(resets_backoff(&cfg, Duration::ZERO));
        cfg.reverse_forwards = vec![reverse("127.0.0.1:8888", "127.0.0.1:54321")];
        assert!(!resets_backoff(&cfg, Duration::from_millis(100)));
        assert!(resets_backoff(&cfg, REVERSE_STABLE_UPTIME));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let max = Duration::from_secs(5);
        let mut d = Duration::from_secs(1);
        let mut seen = Vec::new();
        for _ in 0..5 {
            d = next_delay(d, max);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, [2, 4, 5, 5, 5]);
    }

    #[test]
    fn picks_a_bindable_port() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let port = pick_loopback_port(ip).unwrap();
        assert_ne!(port, 0);
        TcpListener::bind((ip, port)).unwrap();
    }

    #[cfg(unix)]
    mod process {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::net::TcpListener as AsyncListener;

        const WAIT: Duration = Duration::from_secs(10);
        static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

        /// A fake `ssh` that records its PID, argv, and any `SIGTERM` it handles.
        struct MockSsh {
            dir: PathBuf,
        }

        impl MockSsh {
            fn new(term_handler: &str) -> Self {
                let dir = std::env::temp_dir().join(format!(
                    "rcs-mock-ssh-{}-{}",
                    std::process::id(),
                    NEXT_DIR.fetch_add(1, Ordering::Relaxed)
                ));
                fs::create_dir_all(&dir).unwrap();
                let d = dir.display();
                let script = format!(
                    "#!/bin/sh\n\
                     [ \"$1\" = \"--probe\" ] && exit 0\n\
                     trap '{term_handler}' TERM\n\
                     printf '%s\\n' \"$@\" > '{d}/args'\n\
                     echo \"$$\" >> '{d}/pids'\n\
                     while :; do sleep 0.05; done\n"
                );
                let bin = dir.join("ssh");
                fs::write(&bin, script).unwrap();
                fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
                let mock = Self { dir };
                mock.wait_until_executable();
                mock
            }

            fn graceful() -> Self {
                let probe = Self::new("");
                let d = probe.dir.display().to_string();
                let handler = format!("echo term >> \"{d}/terms\"; exit 0");
                let script = fs::read_to_string(probe.bin())
                    .unwrap()
                    .replace("trap '' TERM", &format!("trap '{handler}' TERM"));
                let replacement = probe.dir.join("ssh.new");
                fs::write(&replacement, script).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
                fs::rename(&replacement, probe.bin()).unwrap();
                probe.wait_until_executable();
                probe
            }

            /// Another test's `fork` can briefly hold our write fd and cause `ETXTBSY`.
            fn wait_until_executable(&self) {
                for _ in 0..200 {
                    match std::process::Command::new(self.bin())
                        .arg("--probe")
                        .status()
                    {
                        Ok(_) => return,
                        Err(e) if e.raw_os_error() == Some(26) => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("mock ssh cannot run: {e}"),
                    }
                }
                panic!("mock ssh stayed busy");
            }

            fn bin(&self) -> PathBuf {
                self.dir.join("ssh")
            }

            fn lines(&self, name: &str) -> Vec<String> {
                read_lines(&self.dir.join(name))
            }

            async fn wait_for_pids(&self, count: usize) -> Vec<String> {
                let deadline = Instant::now() + WAIT;
                loop {
                    let pids = self.lines("pids");
                    if pids.len() >= count {
                        return pids;
                    }
                    assert!(Instant::now() < deadline, "only {} ssh starts", pids.len());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }

            fn config(&self, port: u16) -> SshTunnelConfig {
                let mut cfg = base_config();
                cfg.ssh_bin = self.bin();
                cfg.socks_port = port;
                cfg.inherit_stdio = false;
                cfg.reconnect_initial_delay = Duration::from_millis(20);
                cfg.reconnect_max_delay = Duration::from_millis(100);
                cfg.startup_timeout = WAIT;
                cfg
            }
        }

        impl Drop for MockSsh {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }

        fn read_lines(path: &Path) -> Vec<String> {
            fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn logger() -> Logger {
            Logger::with_writer(LogLevel::Quiet, Box::new(io::sink()))
        }

        fn kill_hard(pid: &str) {
            let status = std::process::Command::new("kill")
                .args(["-KILL", pid])
                .status()
                .unwrap();
            assert!(status.success());
        }

        fn is_alive(pid: &str) -> bool {
            std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        }

        /// In-process stand-in for the `ssh -D` listener.
        async fn socks_listener() -> (u16, JoinHandle<()>) {
            let listener = AsyncListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            (port, tokio::spawn(serve_greetings(listener)))
        }

        async fn serve_greetings(listener: AsyncListener) {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    if sock.read_exact(&mut greeting).await.is_ok() {
                        let _ = sock.write_all(&[0x05, 0x00]).await;
                    }
                });
            }
        }

        #[tokio::test]
        async fn ready_only_after_socks_listener_answers() {
            let mock = MockSsh::graceful();
            let port = pick_loopback_port(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
            let (handle, rx) =
                SshSupervisor::spawn(mock.config(port), logger(), CancellationToken::new());
            mock.wait_for_pids(1).await;

            let short = Duration::from_millis(250);
            assert_eq!(
                handle.wait_ready(short).await,
                Err(SshError::StartupTimeout(short))
            );
            assert_eq!(*rx.borrow(), TunnelState::Connecting);

            let listener = AsyncListener::bind(addr(port)).await.unwrap();
            let server = tokio::spawn(serve_greetings(listener));
            assert_eq!(handle.wait_ready(WAIT).await, Ok(addr(port)));
            assert_eq!(*rx.borrow(), TunnelState::Ready(addr(port)));

            let args = mock.lines("args");
            assert_eq!(&args[args.len() - 2..], ["--", "user@host"]);
            handle.shutdown().await;
            server.abort();
        }

        #[tokio::test]
        async fn non_socks_listener_is_not_ready() {
            let mock = MockSsh::graceful();
            let listener = AsyncListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let _ = sock.write_all(b"SSH-2.0-nope\r\n").await;
                }
            });
            let (handle, _rx) =
                SshSupervisor::spawn(mock.config(port), logger(), CancellationToken::new());
            mock.wait_for_pids(1).await;
            assert!(matches!(
                handle.wait_ready(Duration::from_millis(300)).await,
                Err(SshError::StartupTimeout(_))
            ));
            handle.shutdown().await;
            server.abort();
        }

        #[tokio::test]
        async fn reconnects_after_forced_child_kill() {
            let mock = MockSsh::graceful();
            let (port, server) = socks_listener().await;
            let (handle, mut rx) =
                SshSupervisor::spawn(mock.config(port), logger(), CancellationToken::new());
            handle.wait_ready(WAIT).await.unwrap();
            let first = mock.wait_for_pids(1).await[0].clone();

            rx.borrow_and_update();
            kill_hard(&first);
            tokio::time::timeout(
                WAIT,
                rx.wait_for(|s| matches!(s, TunnelState::Disconnected(_))),
            )
            .await
            .unwrap()
            .unwrap();

            let pids = mock.wait_for_pids(2).await;
            assert_ne!(pids[0], pids[1]);
            assert_eq!(handle.wait_ready(WAIT).await, Ok(addr(port)));
            handle.shutdown().await;
            assert!(!is_alive(&pids[1]));
            server.abort();
        }

        #[tokio::test]
        async fn no_reconnect_cancels_app_token_and_stays_down() {
            let mock = MockSsh::graceful();
            let (port, server) = socks_listener().await;
            let mut cfg = mock.config(port);
            cfg.no_reconnect = true;
            let app = CancellationToken::new();
            let (handle, rx) = SshSupervisor::spawn(cfg, logger(), app.clone());
            handle.wait_ready(WAIT).await.unwrap();
            let pid = mock.wait_for_pids(1).await[0].clone();
            assert!(!app.is_cancelled());

            kill_hard(&pid);
            tokio::time::timeout(WAIT, app.cancelled()).await.unwrap();
            match rx.borrow().clone() {
                TunnelState::Disconnected(reason) => assert!(reason.contains("ssh exited")),
                other => panic!("unexpected state {other:?}"),
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(mock.lines("pids").len(), 1);
            handle.shutdown().await;
            server.abort();
        }

        #[tokio::test]
        async fn no_reconnect_reports_spawn_failure() {
            let mock = MockSsh::graceful();
            let mut cfg = mock.config(1);
            cfg.ssh_bin = mock.dir.join("missing-ssh");
            cfg.no_reconnect = true;
            let app = CancellationToken::new();
            let (handle, _rx) = SshSupervisor::spawn(cfg, logger(), app.clone());
            match handle.wait_ready(WAIT).await {
                Err(SshError::Stopped(reason)) => assert!(reason.contains("failed to start")),
                other => panic!("unexpected result {other:?}"),
            }
            assert!(app.is_cancelled());
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn startup_timeout_terminates_child() {
            let mock = MockSsh::graceful();
            let port = pick_loopback_port(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
            let mut cfg = mock.config(port);
            cfg.no_reconnect = true;
            cfg.startup_timeout = Duration::from_millis(400);
            let (handle, _rx) = SshSupervisor::spawn(cfg, logger(), CancellationToken::new());
            match handle.wait_ready(WAIT).await {
                Err(SshError::Stopped(reason)) => assert!(reason.contains("not ready")),
                other => panic!("unexpected result {other:?}"),
            }
            assert_eq!(mock.lines("terms").len(), 1);
            handle.shutdown().await;
        }

        #[tokio::test]
        async fn shutdown_sends_sigterm_and_reaps_child() {
            let mock = MockSsh::graceful();
            let (port, server) = socks_listener().await;
            let app = CancellationToken::new();
            let (handle, rx) = SshSupervisor::spawn(mock.config(port), logger(), app.clone());
            handle.wait_ready(WAIT).await.unwrap();
            let pid = mock.wait_for_pids(1).await[0].clone();

            handle.shutdown().await;
            assert_eq!(mock.lines("terms").len(), 1);
            assert!(!is_alive(&pid));
            assert!(!app.is_cancelled(), "handle shutdown must not stop the app");
            assert!(matches!(*rx.borrow(), TunnelState::Disconnected(_)));
            server.abort();
        }

        #[tokio::test]
        async fn app_token_stops_the_tunnel() {
            let mock = MockSsh::graceful();
            let (port, server) = socks_listener().await;
            let app = CancellationToken::new();
            let (handle, _rx) = SshSupervisor::spawn(mock.config(port), logger(), app.clone());
            handle.wait_ready(WAIT).await.unwrap();
            let pid = mock.wait_for_pids(1).await[0].clone();

            app.cancel();
            tokio::time::timeout(WAIT, handle.shutdown()).await.unwrap();
            assert!(!is_alive(&pid));
            server.abort();
        }

        #[tokio::test]
        async fn escalates_to_kill_when_sigterm_is_ignored() {
            let mock = MockSsh::new("");
            let (port, server) = socks_listener().await;
            let (handle, _rx) =
                SshSupervisor::spawn(mock.config(port), logger(), CancellationToken::new());
            handle.wait_ready(WAIT).await.unwrap();
            let pid = mock.wait_for_pids(1).await[0].clone();

            handle.shutdown().await;
            assert!(!is_alive(&pid));
            server.abort();
        }
    }
}
