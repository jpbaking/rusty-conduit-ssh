//! Configuration loading and validation.
//!
//! Sources are merged with strict precedence:
//! **CLI flags > `RUSTY_CONDUIT_SSH_*` environment variables > optional `--config` TOML file > defaults**.
//!
//! CLI flags and environment variables are both handled by `clap` (each flag declares its
//! `env` fallback, and `clap` itself prefers the flag over the variable). The resulting
//! [`CliInput`] is then layered over an optional [`FileConfig`] and the built-in defaults
//! by [`Config::merge`], and checked by [`Config::validate`].

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use clap::error::ErrorKind;
use clap::parser::ValueSource;
use clap::{ArgAction, ArgMatches, CommandFactory, FromArgMatches, Parser};
use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;

use crate::filter::{FilterRule, HostFilter};
use crate::logging::{LogFormat, LogLevel};
use crate::mitm::MitmOptions;
use crate::net::KeepaliveSettings;
use crate::server::ServerOptions;

/// Default bind address.
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default HTTP/HTTPS proxy port.
pub const DEFAULT_HTTP_PORT: u16 = 3128;
/// Default SOCKS4/5 proxy port.
pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// Default remote bind address of the reverse proxy (`ssh -R`).
pub const DEFAULT_REVERSE_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default in-memory TTL for generated MITM leaf certificates.
pub const DEFAULT_MITM_CERT_TTL: Duration = Duration::from_secs(60 * 60);
/// Smallest accepted MITM leaf certificate TTL.
pub const MIN_MITM_CERT_TTL: Duration = Duration::from_secs(10);
/// Default cap on concurrent client connections (`0` = unlimited).
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;
/// Largest accepted TCP keepalive idle time / probe interval (Linux caps both at 32767s).
pub const MAX_TCP_KEEPALIVE_DURATION: Duration = Duration::from_secs(32_767);
/// Largest accepted TCP keepalive probe count (Linux caps `TCP_KEEPCNT` at 127).
pub const MAX_TCP_KEEPALIVE_RETRIES: u32 = 127;
/// Default cap on cached MITM leaf certificates (`0` = unlimited).
pub const DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES: usize = 10_000;
/// Default `ssh` executable.
pub const DEFAULT_SSH_BIN: &str = "ssh";
/// Default bind address of the local `ssh -D` SOCKS listener.
pub const DEFAULT_SSH_SOCKS_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default `ssh -D` port (`0` = pick an ephemeral port).
pub const DEFAULT_SSH_SOCKS_PORT: u16 = 0;
/// Default `ServerAliveInterval`.
pub const DEFAULT_SSH_SERVER_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Default `ServerAliveCountMax`.
pub const DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX: u32 = 3;
/// Default delay before the first reconnect attempt.
pub const DEFAULT_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(1);
/// Default upper bound of the reconnect backoff.
pub const DEFAULT_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);
/// Default time allowed for the tunnel to become ready.
pub const DEFAULT_SSH_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// IP family used by the `ssh` client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshIpVersion {
    /// Force IPv4 (`ssh -4`).
    V4,
    /// Force IPv6 (`ssh -6`).
    V6,
    /// Let `ssh` choose.
    Auto,
}

impl SshIpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
            Self::Auto => "auto",
        }
    }
}

impl fmt::Display for SshIpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SshIpVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "4" => Ok(Self::V4),
            "6" => Ok(Self::V6),
            "auto" => Ok(Self::Auto),
            _ => Err(format!(
                "invalid SSH IP version {s:?} (expected 4, 6, or auto)"
            )),
        }
    }
}

/// Accepts TOML `ip_version = 4`, `ip_version = "4"`, and `ip_version = "auto"`.
impl<'de> Deserialize<'de> for SshIpVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IpVersionVisitor;

        impl Visitor<'_> for IpVersionVisitor {
            type Value = SshIpVersion;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("4, 6, or \"auto\"")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                v.to_string().parse().map_err(E::custom)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(IpVersionVisitor)
    }
}

/// Errors raised while loading or validating configuration. Every variant is `FATAL`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {message}")]
    ParseFile { path: PathBuf, message: String },
    #[error("invalid value for `{key}` in config file: {message}")]
    InvalidFileValue { key: &'static str, message: String },
    #[error(
        "http_port, socks_port, reverse_http_port, and reverse_socks_port are all 0: at least one listener must be enabled"
    )]
    NoListeners,
    #[error(
        "ambiguous MITM CA source: --mitm-ca-p12 cannot be combined with --mitm-ca-cert or --mitm-ca-key"
    )]
    AmbiguousCaSource,
    #[error("incomplete PEM MITM CA: --mitm-ca-cert and --mitm-ca-key must be provided together")]
    IncompletePemCa,
    #[error(
        "conflicting passphrase sources: use only one of --mitm-ca-passphrase and --mitm-ca-passphrase-file"
    )]
    ConflictingPassphrase,
    #[error("--mitm-cert-ttl must be at least 10s (got {})", humantime::format_duration(*.0))]
    CertTtlTooShort(Duration),
    #[error("failed to read passphrase file {path}: {source}")]
    ReadPassphraseFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "missing SSH target: pass [TARGET], --target, RUSTY_CONDUIT_SSH_TARGET, or ssh.target"
    )]
    MissingSshTarget,
    #[error("SSH target must not be empty")]
    EmptySshTarget,
    #[error(
        "--reconnect-initial-delay ({}) must not exceed --reconnect-max-delay ({})",
        humantime::format_duration(*.initial),
        humantime::format_duration(*.max)
    )]
    ReconnectDelayOrder { initial: Duration, max: Duration },
    #[error("invalid TCP keepalive setting: {0}")]
    InvalidKeepalive(String),
}

/// Raw command-line / environment input (`clap` derive with `env` fallbacks).
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "rusty-conduit-ssh",
    version,
    about = "Lightweight HTTP/HTTPS and SOCKS4/4a/5 proxy server with optional HTTPS MITM inspection",
    long_about = "Lightweight HTTP/HTTPS and SOCKS4/4a/5 proxy server with optional HTTPS MITM inspection.\n\n\
                  Precedence: CLI flags > RUSTY_CONDUIT_SSH_* environment variables > --config TOML file > defaults."
)]
pub struct CliArgs {
    /// SSH destination, as accepted by `ssh` (host, user@host, or a ~/.ssh/config alias)
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// SSH destination, as an option (alternative to the positional TARGET)
    #[arg(
        long = "target",
        value_name = "TARGET",
        env = "RUSTY_CONDUIT_SSH_TARGET"
    )]
    pub target_option: Option<String>,

    /// Optional TOML configuration file path
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_CONFIG")]
    pub config: Option<PathBuf>,

    /// IPv4 or IPv6 address to bind listeners to [default: 127.0.0.1]
    #[arg(long, value_name = "IP", env = "RUSTY_CONDUIT_SSH_BIND")]
    pub bind: Option<IpAddr>,

    /// HTTP/HTTPS proxy port, 0 to disable [default: 3128]
    #[arg(long, value_name = "PORT", env = "RUSTY_CONDUIT_SSH_HTTP_PORT")]
    pub http_port: Option<u16>,

    /// SOCKS4/5 proxy port, 0 to disable [default: 1080]
    #[arg(long, value_name = "PORT", env = "RUSTY_CONDUIT_SSH_SOCKS_PORT")]
    pub socks_port: Option<u16>,

    /// Maximum concurrent client connections; excess connections are closed immediately, 0 = unlimited [default: 4096]
    #[arg(long, value_name = "N", env = "RUSTY_CONDUIT_SSH_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,

    /// Idle time before TCP keepalive probes start on forward and reverse client and upstream sockets, 0 = disabled [default: 60s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_TCP_KEEPALIVE",
        value_parser = humantime::parse_duration
    )]
    pub tcp_keepalive: Option<Duration>,

    /// Time between unanswered TCP keepalive probes [default: 10s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_TCP_KEEPALIVE_INTERVAL",
        value_parser = humantime::parse_duration
    )]
    pub tcp_keepalive_interval: Option<Duration>,

    /// Unanswered TCP keepalive probes before the connection is closed [default: 5]
    #[arg(
        long,
        value_name = "N",
        env = "RUSTY_CONDUIT_SSH_TCP_KEEPALIVE_RETRIES"
    )]
    pub tcp_keepalive_retries: Option<u32>,

    /// Allowlist of destinations for the forward proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated
    #[arg(
        long,
        value_name = "RULE",
        value_delimiter = ',',
        env = "RUSTY_CONDUIT_SSH_ALLOW"
    )]
    pub allow: Vec<FilterRule>,

    /// Blocklist of destinations for the forward proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated
    #[arg(
        long,
        value_name = "RULE",
        value_delimiter = ',',
        env = "RUSTY_CONDUIT_SSH_BLOCK"
    )]
    pub block: Vec<FilterRule>,

    /// Remote bind IP on the SSH target for the reverse proxy (ssh -R) [default: 127.0.0.1]
    #[arg(long, value_name = "IP", env = "RUSTY_CONDUIT_SSH_REVERSE_BIND")]
    pub reverse_bind: Option<IpAddr>,

    /// Remote HTTP/HTTPS proxy port on the SSH target (egress via this machine), 0 to disable [default: 0]
    #[arg(long, value_name = "PORT", env = "RUSTY_CONDUIT_SSH_REVERSE_HTTP_PORT")]
    pub reverse_http_port: Option<u16>,

    /// Remote SOCKS4/4a/5 proxy port on the SSH target (egress via this machine), 0 to disable [default: 0]
    #[arg(
        long,
        value_name = "PORT",
        env = "RUSTY_CONDUIT_SSH_REVERSE_SOCKS_PORT"
    )]
    pub reverse_socks_port: Option<u16>,

    /// Maximum concurrent reverse proxy client connections, 0 = unlimited [default: same as --max-connections]
    #[arg(
        long,
        value_name = "N",
        env = "RUSTY_CONDUIT_SSH_REVERSE_MAX_CONNECTIONS"
    )]
    pub reverse_max_connections: Option<usize>,

    /// Allowlist of destinations for the reverse proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated
    #[arg(
        long,
        value_name = "RULE",
        value_delimiter = ',',
        env = "RUSTY_CONDUIT_SSH_REVERSE_ALLOW"
    )]
    pub reverse_allow: Vec<FilterRule>,

    /// Blocklist of destinations for the reverse proxy (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated
    #[arg(
        long,
        value_name = "RULE",
        value_delimiter = ',',
        env = "RUSTY_CONDUIT_SSH_REVERSE_BLOCK"
    )]
    pub reverse_block: Vec<FilterRule>,

    /// Path to PEM-encoded CA certificate (enables MITM together with --mitm-ca-key)
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_MITM_CA_CERT")]
    pub mitm_ca_cert: Option<PathBuf>,

    /// Path to PEM-encoded CA private key
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_MITM_CA_KEY")]
    pub mitm_ca_key: Option<PathBuf>,

    /// Path to PKCS#12 (.p12/.pfx) CA bundle (enables MITM)
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_MITM_CA_P12")]
    pub mitm_ca_p12: Option<PathBuf>,

    /// Passphrase for the PKCS#12 bundle or encrypted PEM key (prefer the env var or a passphrase file)
    #[arg(
        long,
        value_name = "STR",
        env = "RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE",
        hide_env_values = true
    )]
    pub mitm_ca_passphrase: Option<String>,

    /// File containing the CA passphrase (trailing newline is trimmed)
    #[arg(
        long,
        value_name = "PATH",
        env = "RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE_FILE"
    )]
    pub mitm_ca_passphrase_file: Option<PathBuf>,

    /// In-memory TTL for generated MITM leaf certs, e.g. 30m, 1h, 3600s [default: 1h]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_MITM_CERT_TTL",
        value_parser = humantime::parse_duration
    )]
    pub mitm_cert_ttl: Option<Duration>,

    /// Maximum cached MITM leaf certificates; expired then oldest entries are evicted, 0 = unlimited [default: 10000]
    #[arg(
        long,
        value_name = "N",
        env = "RUSTY_CONDUIT_SSH_MITM_CERT_CACHE_MAX_ENTRIES"
    )]
    pub mitm_cert_cache_max_entries: Option<usize>,

    /// Reject HTTP/HTTPS traffic over SOCKS4/5 (works with or without MITM)
    #[arg(
        long,
        env = "RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB",
        action = ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub socks_block_web: bool,

    /// Backwards-compatible alias for --socks-block-web
    #[arg(
        long = "socks-block-web-in-mitm",
        hide = true,
        env = "RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB_IN_MITM",
        action = ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub socks_block_web_in_mitm: bool,

    /// Log level: QUIET, FATAL, ERROR, INFO, DEBUG, VERBOSE (case-insensitive) [default: INFO]
    #[arg(long, value_name = "LEVEL", env = "RUSTY_CONDUIT_SSH_LOG_LEVEL")]
    pub log_level: Option<LogLevel>,

    /// Access/SOCKS log format: text (logfmt) or json (NDJSON) [default: text]
    #[arg(long, value_name = "FMT", env = "RUSTY_CONDUIT_SSH_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// Optional file path for HTTP/HTTPS access logs
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_HTTP_ACCESS_LOG")]
    pub http_access_log: Option<PathBuf>,

    /// Optional file path for SOCKS4/5 connection logs
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_SOCKS_LOG")]
    pub socks_log: Option<PathBuf>,

    /// Path or name of the ssh executable [default: ssh]
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SSH_SSH_BIN")]
    pub ssh_bin: Option<PathBuf>,

    /// Local bind address for the ssh -D SOCKS listener [default: 127.0.0.1]
    #[arg(long, value_name = "IP", env = "RUSTY_CONDUIT_SSH_SSH_SOCKS_BIND")]
    pub ssh_socks_bind: Option<IpAddr>,

    /// Local port for the ssh -D SOCKS listener, 0 = ephemeral [default: 0]
    #[arg(long, value_name = "PORT", env = "RUSTY_CONDUIT_SSH_SSH_SOCKS_PORT")]
    pub ssh_socks_port: Option<u16>,

    /// IP family for the ssh client: 4, 6, or auto [default: 4]
    #[arg(long, value_name = "VERSION", env = "RUSTY_CONDUIT_SSH_SSH_IP_VERSION")]
    pub ssh_ip_version: Option<SshIpVersion>,

    /// Remote SSH port (ssh -p)
    #[arg(
        short = 'p',
        long,
        value_name = "PORT",
        env = "RUSTY_CONDUIT_SSH_SSH_PORT"
    )]
    pub ssh_port: Option<u16>,

    /// SSH identity file (ssh -i)
    #[arg(
        short = 'i',
        long,
        value_name = "PATH",
        env = "RUSTY_CONDUIT_SSH_SSH_IDENTITY"
    )]
    pub ssh_identity: Option<PathBuf>,

    /// SSH client config file (ssh -F)
    #[arg(
        short = 'F',
        long,
        value_name = "PATH",
        env = "RUSTY_CONDUIT_SSH_SSH_CONFIG"
    )]
    pub ssh_config: Option<PathBuf>,

    /// SSH jump host(s) (ssh -J)
    #[arg(
        short = 'J',
        long,
        value_name = "HOST",
        env = "RUSTY_CONDUIT_SSH_SSH_JUMP"
    )]
    pub ssh_jump: Option<String>,

    /// SSH ServerAliveInterval, e.g. 15s [default: 15s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_SSH_SERVER_ALIVE_INTERVAL",
        value_parser = humantime::parse_duration
    )]
    pub ssh_server_alive_interval: Option<Duration>,

    /// SSH ServerAliveCountMax [default: 3]
    #[arg(
        long,
        value_name = "N",
        env = "RUSTY_CONDUIT_SSH_SSH_SERVER_ALIVE_COUNT_MAX"
    )]
    pub ssh_server_alive_count_max: Option<u32>,

    /// Exit when the SSH tunnel drops instead of reconnecting
    #[arg(
        long,
        env = "RUSTY_CONDUIT_SSH_NO_RECONNECT",
        action = ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub no_reconnect: bool,

    /// Delay before the first reconnect attempt [default: 1s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_RECONNECT_INITIAL_DELAY",
        value_parser = humantime::parse_duration
    )]
    pub reconnect_initial_delay: Option<Duration>,

    /// Upper bound of the reconnect backoff [default: 30s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_RECONNECT_MAX_DELAY",
        value_parser = humantime::parse_duration
    )]
    pub reconnect_max_delay: Option<Duration>,

    /// Time allowed for the SSH tunnel to become ready [default: 30s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SSH_SSH_STARTUP_TIMEOUT",
        value_parser = humantime::parse_duration
    )]
    pub ssh_startup_timeout: Option<Duration>,

    /// Extra arguments passed to ssh verbatim (after `--`)
    #[arg(last = true, value_name = "SSH_ARGS")]
    pub ssh_args: Vec<String>,
}

/// Parsed CLI/env input plus the provenance details that `clap` alone does not expose.
#[derive(Debug, Clone, Default)]
pub struct CliInput {
    pub args: CliArgs,
    /// `--mitm-ca-passphrase` came from an actual command-line argument (not the env var).
    pub passphrase_from_cli: bool,
    /// `--socks-block-web` (or alias `--socks-block-web-in-mitm`) was explicitly provided (CLI or env).
    pub socks_block_web_explicit: bool,
    /// Resolved CLI/env value for `--socks-block-web` when `socks_block_web_explicit` is true.
    pub socks_block_web_value: bool,
    /// `--no-reconnect` was explicitly provided (CLI or env), so it overrides TOML.
    pub no_reconnect_explicit: bool,
}

impl CliInput {
    /// Parse the process arguments and environment; prints help/version or usage errors and exits.
    pub fn parse() -> Self {
        let matches = CliArgs::command().get_matches();
        Self::from_matches(&matches).unwrap_or_else(|e| e.exit())
    }

    /// Parse an explicit argument list (the environment is still consulted for `env` fallbacks).
    pub fn try_parse_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = CliArgs::command().try_get_matches_from(args)?;
        Self::from_matches(&matches)
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        if matches.value_source("target") == Some(ValueSource::CommandLine)
            && matches.value_source("target_option") == Some(ValueSource::CommandLine)
        {
            return Err(CliArgs::command().error(
                ErrorKind::ArgumentConflict,
                "the positional TARGET cannot be combined with --target",
            ));
        }
        let args = CliArgs::from_arg_matches(matches)?;
        let passphrase_from_cli =
            matches.value_source("mitm_ca_passphrase") == Some(ValueSource::CommandLine);
        let primary_src = matches.value_source("socks_block_web");
        let legacy_src = matches.value_source("socks_block_web_in_mitm");
        let (socks_block_web_explicit, socks_block_web_value) = match (primary_src, legacy_src) {
            (Some(ValueSource::CommandLine), _) => (true, args.socks_block_web),
            (_, Some(ValueSource::CommandLine)) => (true, args.socks_block_web_in_mitm),
            (Some(ValueSource::EnvVariable), _) => (true, args.socks_block_web),
            (_, Some(ValueSource::EnvVariable)) => (true, args.socks_block_web_in_mitm),
            _ => (false, false),
        };
        let no_reconnect_explicit = matches!(
            matches.value_source("no_reconnect"),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        );
        Ok(Self {
            args,
            passphrase_from_cli,
            socks_block_web_explicit,
            socks_block_web_value,
            no_reconnect_explicit,
        })
    }
}

/// Top-level TOML configuration file layout.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub bind: Option<IpAddr>,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub max_connections: Option<usize>,
    /// Human-readable duration such as `60s` or `2m`; `"0"` disables keepalive.
    pub tcp_keepalive: Option<String>,
    /// Human-readable duration such as `10s`.
    pub tcp_keepalive_interval: Option<String>,
    pub tcp_keepalive_retries: Option<u32>,
    pub allow: Option<Vec<String>>,
    pub block: Option<Vec<String>>,
    /// Reject HTTP/HTTPS traffic over SOCKS4/5 (works with or without MITM).
    pub socks_block_web: Option<bool>,
    #[serde(default)]
    pub mitm: FileMitmConfig,
    #[serde(default)]
    pub logging: FileLoggingConfig,
    #[serde(default)]
    pub ssh: FileSshConfig,
    #[serde(default)]
    pub reverse: FileReverseConfig,
}

/// `[reverse]` table of the TOML configuration file.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileReverseConfig {
    pub bind: Option<IpAddr>,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    /// Unset means the forward `max_connections` applies.
    pub max_connections: Option<usize>,
    pub allow: Option<Vec<String>>,
    pub block: Option<Vec<String>>,
}

/// `[mitm]` table of the TOML configuration file.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileMitmConfig {
    pub ca_cert: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
    pub ca_p12: Option<PathBuf>,
    pub ca_passphrase: Option<String>,
    pub ca_passphrase_file: Option<PathBuf>,
    /// Human-readable duration such as `30m`, `1h`, or `3600s`.
    pub cert_ttl: Option<String>,
    pub cert_cache_max_entries: Option<usize>,
    pub socks_block_web: Option<bool>,
}

/// `[logging]` table of the TOML configuration file.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileLoggingConfig {
    pub level: Option<String>,
    pub format: Option<String>,
    pub http_access_log: Option<PathBuf>,
    pub socks_log: Option<PathBuf>,
}

/// `[ssh]` table of the TOML configuration file.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileSshConfig {
    pub target: Option<String>,
    pub bin: Option<PathBuf>,
    pub socks_bind: Option<IpAddr>,
    pub socks_port: Option<u16>,
    pub ip_version: Option<SshIpVersion>,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub jump: Option<String>,
    /// Human-readable duration such as `15s`.
    pub server_alive_interval: Option<String>,
    pub server_alive_count_max: Option<u32>,
    pub no_reconnect: Option<bool>,
    /// Human-readable duration such as `1s`.
    pub reconnect_initial_delay: Option<String>,
    /// Human-readable duration such as `30s`.
    pub reconnect_max_delay: Option<String>,
    /// Human-readable duration such as `30s`.
    pub startup_timeout: Option<String>,
    pub extra_args: Option<Vec<String>>,
}

/// Parse an optional list of filter rules from the TOML file.
fn file_filter_rules(
    key: &'static str,
    values: Option<Vec<String>>,
) -> Result<Vec<FilterRule>, ConfigError> {
    match values {
        None => Ok(Vec::new()),
        Some(list) => list
            .into_iter()
            .map(|raw| {
                raw.parse::<FilterRule>()
                    .map_err(|message| ConfigError::InvalidFileValue { key, message })
            })
            .collect(),
    }
}

/// Parse an optional human-readable duration from the TOML file.
fn file_duration(key: &'static str, value: Option<&str>) -> Result<Option<Duration>, ConfigError> {
    value
        .map(|s| {
            humantime::parse_duration(s).map_err(|e| ConfigError::InvalidFileValue {
                key,
                message: format!("{s:?}: {e}"),
            })
        })
        .transpose()
}

impl FileConfig {
    /// Parse TOML text.
    pub fn from_toml_str(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::ParseFile {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Read and parse a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text, path)
    }
}

/// Where the MITM CA comes from (only present when MITM mode is ON).
pub use crate::mitm::CaSource;

/// Fully merged configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub config_path: Option<PathBuf>,
    pub bind: IpAddr,
    pub http_port: u16,
    pub socks_port: u16,
    /// Maximum concurrent client connections (`0` = unlimited).
    pub max_connections: usize,
    /// Idle time before TCP keepalive probes start (`0` = keepalive disabled). Applies to
    /// both the forward and reverse proxies.
    pub tcp_keepalive: Duration,
    /// Time between unanswered TCP keepalive probes.
    pub tcp_keepalive_interval: Duration,
    /// Unanswered TCP keepalive probes before the OS closes the connection.
    pub tcp_keepalive_retries: u32,
    /// Forward proxy destination allowlist (mutually exclusive with `block`).
    pub allow: Vec<FilterRule>,
    /// Forward proxy destination blocklist (mutually exclusive with `allow`).
    pub block: Vec<FilterRule>,
    /// Remote bind address for `ssh -R` on the SSH target.
    pub reverse_bind: IpAddr,
    /// Remote HTTP/HTTPS reverse proxy port (`0` = disabled).
    pub reverse_http_port: u16,
    /// Remote SOCKS4/4a/5 reverse proxy port (`0` = disabled).
    pub reverse_socks_port: u16,
    /// Maximum concurrent reverse proxy client connections (`0` = unlimited). When no layer
    /// sets it, it takes the resolved `max_connections`.
    pub reverse_max_connections: usize,
    /// Reverse proxy destination allowlist (mutually exclusive with `reverse_block`).
    pub reverse_allow: Vec<FilterRule>,
    /// Reverse proxy destination blocklist (mutually exclusive with `reverse_allow`).
    pub reverse_block: Vec<FilterRule>,
    pub mitm_ca_cert: Option<PathBuf>,
    pub mitm_ca_key: Option<PathBuf>,
    pub mitm_ca_p12: Option<PathBuf>,
    pub mitm_ca_passphrase: Option<String>,
    pub mitm_ca_passphrase_file: Option<PathBuf>,
    pub mitm_cert_ttl: Duration,
    /// Maximum cached MITM leaf certificates (`0` = unlimited).
    pub mitm_cert_cache_max_entries: usize,
    pub socks_block_web_in_mitm: bool,
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub http_access_log: Option<PathBuf>,
    pub socks_log: Option<PathBuf>,
    /// The passphrase was supplied as a CLI argument (triggers an `INFO` notice).
    pub passphrase_from_cli: bool,
    /// SSH destination; required by [`Config::validate`].
    pub ssh_target: Option<String>,
    pub ssh_bin: PathBuf,
    pub ssh_socks_bind: IpAddr,
    /// Local `ssh -D` port (`0` = ephemeral).
    pub ssh_socks_port: u16,
    pub ssh_ip_version: SshIpVersion,
    pub ssh_port: Option<u16>,
    pub ssh_identity: Option<PathBuf>,
    pub ssh_config: Option<PathBuf>,
    pub ssh_jump: Option<String>,
    pub ssh_server_alive_interval: Duration,
    pub ssh_server_alive_count_max: u32,
    pub no_reconnect: bool,
    pub reconnect_initial_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub ssh_startup_timeout: Duration,
    /// Arguments passed to `ssh` verbatim; may carry sensitive values, so never logged.
    pub ssh_extra_args: Vec<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("config_path", &self.config_path)
            .field("bind", &self.bind)
            .field("http_port", &self.http_port)
            .field("socks_port", &self.socks_port)
            .field("max_connections", &self.max_connections)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .field("tcp_keepalive_interval", &self.tcp_keepalive_interval)
            .field("tcp_keepalive_retries", &self.tcp_keepalive_retries)
            .field("reverse_bind", &self.reverse_bind)
            .field("reverse_http_port", &self.reverse_http_port)
            .field("reverse_socks_port", &self.reverse_socks_port)
            .field("reverse_max_connections", &self.reverse_max_connections)
            .field("mitm_ca_cert", &self.mitm_ca_cert)
            .field("mitm_ca_key", &self.mitm_ca_key)
            .field("mitm_ca_p12", &self.mitm_ca_p12)
            .field(
                "mitm_ca_passphrase",
                &self.mitm_ca_passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("mitm_ca_passphrase_file", &self.mitm_ca_passphrase_file)
            .field("mitm_cert_ttl", &self.mitm_cert_ttl)
            .field(
                "mitm_cert_cache_max_entries",
                &self.mitm_cert_cache_max_entries,
            )
            .field("socks_block_web_in_mitm", &self.socks_block_web_in_mitm)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("http_access_log", &self.http_access_log)
            .field("socks_log", &self.socks_log)
            .field("passphrase_from_cli", &self.passphrase_from_cli)
            .field("ssh_target", &self.ssh_target)
            .field("ssh_bin", &self.ssh_bin)
            .field("ssh_socks_bind", &self.ssh_socks_bind)
            .field("ssh_socks_port", &self.ssh_socks_port)
            .field("ssh_ip_version", &self.ssh_ip_version)
            .field("ssh_port", &self.ssh_port)
            .field("ssh_identity", &self.ssh_identity)
            .field("ssh_config", &self.ssh_config)
            .field("ssh_jump", &self.ssh_jump)
            .field("ssh_server_alive_interval", &self.ssh_server_alive_interval)
            .field(
                "ssh_server_alive_count_max",
                &self.ssh_server_alive_count_max,
            )
            .field("no_reconnect", &self.no_reconnect)
            .field("reconnect_initial_delay", &self.reconnect_initial_delay)
            .field("reconnect_max_delay", &self.reconnect_max_delay)
            .field("ssh_startup_timeout", &self.ssh_startup_timeout)
            .field(
                "ssh_extra_args",
                &format_args!("<{} redacted>", self.ssh_extra_args.len()),
            )
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_path: None,
            bind: DEFAULT_BIND,
            http_port: DEFAULT_HTTP_PORT,
            socks_port: DEFAULT_SOCKS_PORT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            tcp_keepalive: KeepaliveSettings::DEFAULT.idle,
            tcp_keepalive_interval: KeepaliveSettings::DEFAULT.interval,
            tcp_keepalive_retries: KeepaliveSettings::DEFAULT.retries,
            allow: Vec::new(),
            block: Vec::new(),
            reverse_bind: DEFAULT_REVERSE_BIND,
            reverse_http_port: 0,
            reverse_socks_port: 0,
            reverse_max_connections: DEFAULT_MAX_CONNECTIONS,
            reverse_allow: Vec::new(),
            reverse_block: Vec::new(),
            mitm_ca_cert: None,
            mitm_ca_key: None,
            mitm_ca_p12: None,
            mitm_ca_passphrase: None,
            mitm_ca_passphrase_file: None,
            mitm_cert_ttl: DEFAULT_MITM_CERT_TTL,
            mitm_cert_cache_max_entries: DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES,
            socks_block_web_in_mitm: false,
            log_level: LogLevel::Info,
            log_format: LogFormat::Text,
            http_access_log: None,
            socks_log: None,
            passphrase_from_cli: false,
            ssh_target: None,
            ssh_bin: PathBuf::from(DEFAULT_SSH_BIN),
            ssh_socks_bind: DEFAULT_SSH_SOCKS_BIND,
            ssh_socks_port: DEFAULT_SSH_SOCKS_PORT,
            ssh_ip_version: SshIpVersion::V4,
            ssh_port: None,
            ssh_identity: None,
            ssh_config: None,
            ssh_jump: None,
            ssh_server_alive_interval: DEFAULT_SSH_SERVER_ALIVE_INTERVAL,
            ssh_server_alive_count_max: DEFAULT_SSH_SERVER_ALIVE_COUNT_MAX,
            no_reconnect: false,
            reconnect_initial_delay: DEFAULT_RECONNECT_INITIAL_DELAY,
            reconnect_max_delay: DEFAULT_RECONNECT_MAX_DELAY,
            ssh_startup_timeout: DEFAULT_SSH_STARTUP_TIMEOUT,
            ssh_extra_args: Vec::new(),
        }
    }
}

impl Config {
    /// Load the TOML file named by `--config` (if any) and merge it under the CLI/env input.
    /// Does not validate; call [`Config::validate`] afterwards.
    pub fn from_cli(cli: CliInput) -> Result<Self, ConfigError> {
        let file = match &cli.args.config {
            Some(path) => Some(FileConfig::load(path)?),
            None => None,
        };
        Self::merge(cli, file)
    }

    /// Merge CLI/env input over an optional file config over defaults. Does not validate.
    pub fn merge(cli: CliInput, file: Option<FileConfig>) -> Result<Self, ConfigError> {
        let file = file.unwrap_or_default();
        let d = Config::default();
        let a = cli.args;

        let file_ttl = file
            .mitm
            .cert_ttl
            .as_deref()
            .map(|s| {
                humantime::parse_duration(s).map_err(|e| ConfigError::InvalidFileValue {
                    key: "mitm.cert_ttl",
                    message: format!("{s:?}: {e}"),
                })
            })
            .transpose()?;
        let file_level = file
            .logging
            .level
            .as_deref()
            .map(|s| {
                s.parse::<LogLevel>()
                    .map_err(|e| ConfigError::InvalidFileValue {
                        key: "logging.level",
                        message: e,
                    })
            })
            .transpose()?;
        let file_format = file
            .logging
            .format
            .as_deref()
            .map(|s| {
                s.parse::<LogFormat>()
                    .map_err(|e| ConfigError::InvalidFileValue {
                        key: "logging.format",
                        message: e,
                    })
            })
            .transpose()?;

        let socks_block_web_in_mitm = if cli.socks_block_web_explicit {
            cli.socks_block_web_value
        } else {
            file.socks_block_web
                .or(file.mitm.socks_block_web)
                .unwrap_or(d.socks_block_web_in_mitm)
        };

        let file_alive = file_duration(
            "ssh.server_alive_interval",
            file.ssh.server_alive_interval.as_deref(),
        )?;
        let file_initial = file_duration(
            "ssh.reconnect_initial_delay",
            file.ssh.reconnect_initial_delay.as_deref(),
        )?;
        let file_max = file_duration(
            "ssh.reconnect_max_delay",
            file.ssh.reconnect_max_delay.as_deref(),
        )?;
        let file_startup =
            file_duration("ssh.startup_timeout", file.ssh.startup_timeout.as_deref())?;
        let file_keepalive = file_duration("tcp_keepalive", file.tcp_keepalive.as_deref())?;
        let file_keepalive_interval = file_duration(
            "tcp_keepalive_interval",
            file.tcp_keepalive_interval.as_deref(),
        )?;
        let no_reconnect = if cli.no_reconnect_explicit {
            a.no_reconnect
        } else {
            file.ssh.no_reconnect.unwrap_or(d.no_reconnect)
        };
        let file_allow = file_filter_rules("allow", file.allow)?;
        let file_block = file_filter_rules("block", file.block)?;
        let file_reverse_allow = file_filter_rules("reverse.allow", file.reverse.allow)?;
        let file_reverse_block = file_filter_rules("reverse.block", file.reverse.block)?;
        let allow = if a.allow.is_empty() {
            file_allow
        } else {
            a.allow
        };
        let block = if a.block.is_empty() {
            file_block
        } else {
            a.block
        };
        let reverse_allow = if a.reverse_allow.is_empty() {
            file_reverse_allow
        } else {
            a.reverse_allow
        };
        let reverse_block = if a.reverse_block.is_empty() {
            file_reverse_block
        } else {
            a.reverse_block
        };

        let ssh_extra_args = if a.ssh_args.is_empty() {
            file.ssh.extra_args.unwrap_or_default()
        } else {
            a.ssh_args
        };

        let max_connections = a
            .max_connections
            .or(file.max_connections)
            .unwrap_or(d.max_connections);
        Ok(Config {
            config_path: a.config,
            bind: a.bind.or(file.bind).unwrap_or(d.bind),
            http_port: a.http_port.or(file.http_port).unwrap_or(d.http_port),
            socks_port: a.socks_port.or(file.socks_port).unwrap_or(d.socks_port),
            max_connections,
            tcp_keepalive: a
                .tcp_keepalive
                .or(file_keepalive)
                .unwrap_or(d.tcp_keepalive),
            tcp_keepalive_interval: a
                .tcp_keepalive_interval
                .or(file_keepalive_interval)
                .unwrap_or(d.tcp_keepalive_interval),
            tcp_keepalive_retries: a
                .tcp_keepalive_retries
                .or(file.tcp_keepalive_retries)
                .unwrap_or(d.tcp_keepalive_retries),
            allow,
            block,
            reverse_bind: a
                .reverse_bind
                .or(file.reverse.bind)
                .unwrap_or(d.reverse_bind),
            reverse_http_port: a
                .reverse_http_port
                .or(file.reverse.http_port)
                .unwrap_or(d.reverse_http_port),
            reverse_socks_port: a
                .reverse_socks_port
                .or(file.reverse.socks_port)
                .unwrap_or(d.reverse_socks_port),
            // Each layer's own reverse value wins; otherwise follow the forward cap.
            reverse_max_connections: a
                .reverse_max_connections
                .or(file.reverse.max_connections)
                .unwrap_or(max_connections),
            reverse_allow,
            reverse_block,
            mitm_ca_cert: a.mitm_ca_cert.or(file.mitm.ca_cert),
            mitm_ca_key: a.mitm_ca_key.or(file.mitm.ca_key),
            mitm_ca_p12: a.mitm_ca_p12.or(file.mitm.ca_p12),
            mitm_ca_passphrase: a.mitm_ca_passphrase.or(file.mitm.ca_passphrase),
            mitm_ca_passphrase_file: a.mitm_ca_passphrase_file.or(file.mitm.ca_passphrase_file),
            mitm_cert_ttl: a.mitm_cert_ttl.or(file_ttl).unwrap_or(d.mitm_cert_ttl),
            mitm_cert_cache_max_entries: a
                .mitm_cert_cache_max_entries
                .or(file.mitm.cert_cache_max_entries)
                .unwrap_or(d.mitm_cert_cache_max_entries),
            socks_block_web_in_mitm,
            log_level: a.log_level.or(file_level).unwrap_or(d.log_level),
            log_format: a.log_format.or(file_format).unwrap_or(d.log_format),
            http_access_log: a.http_access_log.or(file.logging.http_access_log),
            socks_log: a.socks_log.or(file.logging.socks_log),
            passphrase_from_cli: cli.passphrase_from_cli,
            ssh_target: a.target.or(a.target_option).or(file.ssh.target),
            ssh_bin: a.ssh_bin.or(file.ssh.bin).unwrap_or(d.ssh_bin),
            ssh_socks_bind: a
                .ssh_socks_bind
                .or(file.ssh.socks_bind)
                .unwrap_or(d.ssh_socks_bind),
            ssh_socks_port: a
                .ssh_socks_port
                .or(file.ssh.socks_port)
                .unwrap_or(d.ssh_socks_port),
            ssh_ip_version: a
                .ssh_ip_version
                .or(file.ssh.ip_version)
                .unwrap_or(d.ssh_ip_version),
            ssh_port: a.ssh_port.or(file.ssh.port),
            ssh_identity: a.ssh_identity.or(file.ssh.identity),
            ssh_config: a.ssh_config.or(file.ssh.config),
            ssh_jump: a.ssh_jump.or(file.ssh.jump),
            ssh_server_alive_interval: a
                .ssh_server_alive_interval
                .or(file_alive)
                .unwrap_or(d.ssh_server_alive_interval),
            ssh_server_alive_count_max: a
                .ssh_server_alive_count_max
                .or(file.ssh.server_alive_count_max)
                .unwrap_or(d.ssh_server_alive_count_max),
            no_reconnect,
            reconnect_initial_delay: a
                .reconnect_initial_delay
                .or(file_initial)
                .unwrap_or(d.reconnect_initial_delay),
            reconnect_max_delay: a
                .reconnect_max_delay
                .or(file_max)
                .unwrap_or(d.reconnect_max_delay),
            ssh_startup_timeout: a
                .ssh_startup_timeout
                .or(file_startup)
                .unwrap_or(d.ssh_startup_timeout),
            ssh_extra_args,
        })
    }

    /// Apply the `FATAL` startup validation rules.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.forward_enabled() && !self.reverse_enabled() {
            return Err(ConfigError::NoListeners);
        }
        if self.mitm_ca_p12.is_some() && (self.mitm_ca_cert.is_some() || self.mitm_ca_key.is_some())
        {
            return Err(ConfigError::AmbiguousCaSource);
        }
        if self.mitm_ca_cert.is_some() != self.mitm_ca_key.is_some() {
            return Err(ConfigError::IncompletePemCa);
        }
        if self.mitm_ca_passphrase.is_some() && self.mitm_ca_passphrase_file.is_some() {
            return Err(ConfigError::ConflictingPassphrase);
        }
        if self.mitm_cert_ttl < MIN_MITM_CERT_TTL {
            return Err(ConfigError::CertTtlTooShort(self.mitm_cert_ttl));
        }
        match self.ssh_target.as_deref() {
            None => return Err(ConfigError::MissingSshTarget),
            Some(target) if target.trim().is_empty() => return Err(ConfigError::EmptySshTarget),
            Some(_) => {}
        }
        if self.reconnect_initial_delay > self.reconnect_max_delay {
            return Err(ConfigError::ReconnectDelayOrder {
                initial: self.reconnect_initial_delay,
                max: self.reconnect_max_delay,
            });
        }
        if !self.tcp_keepalive.is_zero() {
            let secs = Duration::from_secs(1)..=MAX_TCP_KEEPALIVE_DURATION;
            let fmt = |d: Duration| humantime::format_duration(d).to_string();
            if !secs.contains(&self.tcp_keepalive) {
                return Err(ConfigError::InvalidKeepalive(format!(
                    "--tcp-keepalive must be 0 (disabled) or between 1s and {}s (got {})",
                    MAX_TCP_KEEPALIVE_DURATION.as_secs(),
                    fmt(self.tcp_keepalive)
                )));
            }
            if !secs.contains(&self.tcp_keepalive_interval) {
                return Err(ConfigError::InvalidKeepalive(format!(
                    "--tcp-keepalive-interval must be between 1s and {}s (got {})",
                    MAX_TCP_KEEPALIVE_DURATION.as_secs(),
                    fmt(self.tcp_keepalive_interval)
                )));
            }
            if !(1..=MAX_TCP_KEEPALIVE_RETRIES).contains(&self.tcp_keepalive_retries) {
                return Err(ConfigError::InvalidKeepalive(format!(
                    "--tcp-keepalive-retries must be between 1 and {MAX_TCP_KEEPALIVE_RETRIES} (got {})",
                    self.tcp_keepalive_retries
                )));
            }
        }
        Ok(())
    }

    /// The configured forward destination filter, or `None` when unfiltered.
    pub fn forward_filter(&self) -> Option<HostFilter> {
        HostFilter::from_lists(self.allow.clone(), self.block.clone())
    }

    /// The configured reverse destination filter, or `None` when unfiltered.
    pub fn reverse_filter(&self) -> Option<HostFilter> {
        HostFilter::from_lists(self.reverse_allow.clone(), self.reverse_block.clone())
    }

    /// The configured MITM CA source, or `None` when MITM mode is OFF.
    pub fn ca_source(&self) -> Option<CaSource> {
        match (&self.mitm_ca_p12, &self.mitm_ca_cert, &self.mitm_ca_key) {
            (Some(path), None, None) => Some(CaSource::Pkcs12 { path: path.clone() }),
            (None, Some(cert), Some(key)) => Some(CaSource::Pem {
                cert: cert.clone(),
                key: key.clone(),
            }),
            _ => None,
        }
    }

    /// Whether HTTPS MITM inspection is enabled (a complete CA source is configured).
    pub fn mitm_enabled(&self) -> bool {
        self.ca_source().is_some()
    }

    /// Whether both listeners share one port (single-port first-byte multiplexing).
    pub fn is_multiplexed(&self) -> bool {
        self.http_port > 0 && self.http_port == self.socks_port
    }

    /// Whether at least one forward (`ssh -D`) listener is enabled.
    pub fn forward_enabled(&self) -> bool {
        self.http_port != 0 || self.socks_port != 0
    }

    /// Whether at least one reverse (`ssh -R`) listener is enabled.
    pub fn reverse_enabled(&self) -> bool {
        self.reverse_http_port != 0 || self.reverse_socks_port != 0
    }

    /// Whether both reverse listeners share one port (first-byte multiplexing).
    pub fn is_reverse_multiplexed(&self) -> bool {
        self.reverse_http_port > 0 && self.reverse_http_port == self.reverse_socks_port
    }

    /// Whether the bind address is reachable beyond the local host.
    pub fn is_non_loopback_bind(&self) -> bool {
        !self.bind.is_loopback()
    }

    /// Resolve the CA passphrase from the inline value or the passphrase file
    /// (trailing `\n` / `\r\n` trimmed).
    pub fn resolve_passphrase(&self) -> Result<Option<String>, ConfigError> {
        if let Some(p) = &self.mitm_ca_passphrase {
            return Ok(Some(p.clone()));
        }
        match &self.mitm_ca_passphrase_file {
            Some(path) => {
                let text =
                    fs::read_to_string(path).map_err(|source| ConfigError::ReadPassphraseFile {
                        path: path.clone(),
                        source,
                    })?;
                let trimmed = text
                    .strip_suffix("\r\n")
                    .or_else(|| text.strip_suffix('\n'))
                    .unwrap_or(&text);
                Ok(Some(trimmed.to_string()))
            }
            None => Ok(None),
        }
    }

    /// Startup `INFO` notices (security and configuration hints), in display order.
    pub fn notices(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.is_non_loopback_bind() {
            out.push(format!(
                "SECURITY NOTICE: binding to non-loopback address {}; rusty-conduit-ssh v1 has NO \
                 authentication, so anyone who can reach this address can use the proxy",
                self.bind
            ));
        }
        if self.reverse_enabled() && !self.reverse_bind.is_loopback() {
            out.push(format!(
                "SECURITY NOTICE: reverse proxy binds to non-loopback address {} on the SSH \
                 target (requires sshd GatewayPorts); it has NO authentication, so anyone who \
                 can reach that address can egress through this machine and reach its local \
                 services",
                self.reverse_bind
            ));
        }
        if self.passphrase_from_cli {
            out.push(
                "NOTICE: --mitm-ca-passphrase was passed on the command line, where it may be \
                 visible to other users and shell history; prefer RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE \
                 or --mitm-ca-passphrase-file"
                    .to_string(),
            );
        }
        out
    }

    /// Forward (`ssh -D`) listener settings for the engine [`Server`](crate::server::Server).
    pub fn server_options(&self) -> ServerOptions {
        ServerOptions {
            bind: self.bind,
            http_port: self.http_port,
            socks_port: self.socks_port,
            max_connections: self.max_connections,
            keepalive: self.tcp_keepalive_settings(),
        }
    }

    /// MITM settings for the engine ([`MitmState`](crate::mitm::MitmState)).
    pub fn mitm_options(&self) -> MitmOptions {
        MitmOptions {
            ca: self.ca_source(),
            passphrase: self.mitm_ca_passphrase.clone(),
            passphrase_file: self.mitm_ca_passphrase_file.clone(),
            cert_ttl: self.mitm_cert_ttl,
            cert_cache_max: self.mitm_cert_cache_max_entries,
        }
    }

    /// The configured TCP keepalive parameters, or `None` when keepalive is disabled.
    pub fn tcp_keepalive_settings(&self) -> Option<KeepaliveSettings> {
        (!self.tcp_keepalive.is_zero()).then_some(KeepaliveSettings {
            idle: self.tcp_keepalive,
            interval: self.tcp_keepalive_interval,
            retries: self.tcp_keepalive_retries,
        })
    }

    /// One-line configuration summary for the startup banner (never includes secrets).
    pub fn summary(&self) -> String {
        fn port(p: u16) -> String {
            if p == 0 {
                "disabled".to_string()
            } else {
                p.to_string()
            }
        }
        fn path(p: &Option<PathBuf>) -> String {
            p.as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        }
        fn cap(n: usize) -> String {
            if n == 0 {
                "unlimited".to_string()
            } else {
                n.to_string()
            }
        }
        let mitm = match self.ca_source() {
            Some(CaSource::Pem { .. }) => "on(pem)",
            Some(CaSource::Pkcs12 { .. }) => "on(pkcs12)",
            None => "off",
        };
        let keepalive = match self.tcp_keepalive_settings() {
            Some(ka) => format!(
                "{}/{}x{}",
                humantime::format_duration(ka.idle),
                humantime::format_duration(ka.interval),
                ka.retries
            ),
            None => "off".to_string(),
        };
        let filter = self
            .forward_filter()
            .map(|f| format!(" filter={}({})", f.mode_str(), f.len()))
            .unwrap_or_default();
        let reverse = if self.reverse_enabled() {
            let reverse_filter = self
                .reverse_filter()
                .map(|f| format!(" reverse_filter={}({})", f.mode_str(), f.len()))
                .unwrap_or_default();
            format!(
                " reverse_bind={} reverse_http_port={} reverse_socks_port={} reverse_multiplexed={} \
                 reverse_max_connections={}{reverse_filter}",
                self.reverse_bind,
                port(self.reverse_http_port),
                port(self.reverse_socks_port),
                self.is_reverse_multiplexed(),
                cap(self.reverse_max_connections),
            )
        } else {
            String::new()
        };
        format!(
            "bind={} http_port={} socks_port={} multiplexed={} max_connections={} tcp_keepalive={keepalive} mitm={} \
             mitm_cert_ttl={} mitm_cert_cache_max_entries={} socks_block_web_in_mitm={} log_level={} log_format={} http_access_log={} socks_log={} \
             config={} ssh_target={} ssh_bin={} ssh_socks_bind={} ssh_socks_port={} \
             ssh_ip_version={} ssh_server_alive_interval={} ssh_server_alive_count_max={} \
             no_reconnect={} reconnect_initial_delay={} reconnect_max_delay={} \
             ssh_startup_timeout={} ssh_extra_args={}{filter}{reverse}",
            self.bind,
            port(self.http_port),
            port(self.socks_port),
            self.is_multiplexed(),
            cap(self.max_connections),
            mitm,
            humantime::format_duration(self.mitm_cert_ttl),
            cap(self.mitm_cert_cache_max_entries),
            self.socks_block_web_in_mitm,
            self.log_level,
            self.log_format,
            path(&self.http_access_log),
            path(&self.socks_log),
            path(&self.config_path),
            self.ssh_target.as_deref().unwrap_or("none"),
            self.ssh_bin.display(),
            self.ssh_socks_bind,
            if self.ssh_socks_port == 0 {
                "ephemeral".to_string()
            } else {
                self.ssh_socks_port.to_string()
            },
            self.ssh_ip_version,
            humantime::format_duration(self.ssh_server_alive_interval),
            self.ssh_server_alive_count_max,
            self.no_reconnect,
            humantime::format_duration(self.reconnect_initial_delay),
            humantime::format_duration(self.reconnect_max_delay),
            humantime::format_duration(self.ssh_startup_timeout),
            self.ssh_extra_args.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that read or mutate process environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const ENV_VARS: &[&str] = &[
        "RUSTY_CONDUIT_SSH_CONFIG",
        "RUSTY_CONDUIT_SSH_BIND",
        "RUSTY_CONDUIT_SSH_HTTP_PORT",
        "RUSTY_CONDUIT_SSH_SOCKS_PORT",
        "RUSTY_CONDUIT_SSH_MAX_CONNECTIONS",
        "RUSTY_CONDUIT_SSH_TCP_KEEPALIVE",
        "RUSTY_CONDUIT_SSH_TCP_KEEPALIVE_INTERVAL",
        "RUSTY_CONDUIT_SSH_TCP_KEEPALIVE_RETRIES",
        "RUSTY_CONDUIT_SSH_ALLOW",
        "RUSTY_CONDUIT_SSH_BLOCK",
        "RUSTY_CONDUIT_SSH_REVERSE_BIND",
        "RUSTY_CONDUIT_SSH_REVERSE_HTTP_PORT",
        "RUSTY_CONDUIT_SSH_REVERSE_SOCKS_PORT",
        "RUSTY_CONDUIT_SSH_REVERSE_MAX_CONNECTIONS",
        "RUSTY_CONDUIT_SSH_REVERSE_ALLOW",
        "RUSTY_CONDUIT_SSH_REVERSE_BLOCK",
        "RUSTY_CONDUIT_SSH_MITM_CERT_CACHE_MAX_ENTRIES",
        "RUSTY_CONDUIT_SSH_MITM_CA_CERT",
        "RUSTY_CONDUIT_SSH_MITM_CA_KEY",
        "RUSTY_CONDUIT_SSH_MITM_CA_P12",
        "RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE",
        "RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE_FILE",
        "RUSTY_CONDUIT_SSH_MITM_CERT_TTL",
        "RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB",
        "RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB_IN_MITM",
        "RUSTY_CONDUIT_SSH_LOG_LEVEL",
        "RUSTY_CONDUIT_SSH_LOG_FORMAT",
        "RUSTY_CONDUIT_SSH_HTTP_ACCESS_LOG",
        "RUSTY_CONDUIT_SSH_SOCKS_LOG",
        "RUSTY_CONDUIT_SSH_TARGET",
        "RUSTY_CONDUIT_SSH_SSH_BIN",
        "RUSTY_CONDUIT_SSH_SSH_SOCKS_BIND",
        "RUSTY_CONDUIT_SSH_SSH_SOCKS_PORT",
        "RUSTY_CONDUIT_SSH_SSH_IP_VERSION",
        "RUSTY_CONDUIT_SSH_SSH_PORT",
        "RUSTY_CONDUIT_SSH_SSH_IDENTITY",
        "RUSTY_CONDUIT_SSH_SSH_CONFIG",
        "RUSTY_CONDUIT_SSH_SSH_JUMP",
        "RUSTY_CONDUIT_SSH_SSH_SERVER_ALIVE_INTERVAL",
        "RUSTY_CONDUIT_SSH_SSH_SERVER_ALIVE_COUNT_MAX",
        "RUSTY_CONDUIT_SSH_NO_RECONNECT",
        "RUSTY_CONDUIT_SSH_RECONNECT_INITIAL_DELAY",
        "RUSTY_CONDUIT_SSH_RECONNECT_MAX_DELAY",
        "RUSTY_CONDUIT_SSH_SSH_STARTUP_TIMEOUT",
    ];

    /// Holds the env lock and restores a clean `RUSTY_CONDUIT_SSH_*` environment on drop.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new(vars: &[(&str, &str)]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            for v in ENV_VARS {
                std::env::remove_var(v);
            }
            for (k, v) in vars {
                std::env::set_var(k, v);
            }
            Self { _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for v in ENV_VARS {
                std::env::remove_var(v);
            }
        }
    }

    fn temp_file(contents: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rusty-conduit-ssh-config-test-{}-{}.toml",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, contents).unwrap();
        path
    }

    fn cli(args: &[&str]) -> CliInput {
        let mut full = vec!["rusty-conduit-ssh"];
        full.extend_from_slice(args);
        CliInput::try_parse_from(full).expect("cli parse")
    }

    /// Load with a valid `--target`, for tests about other options.
    fn load(args: &[&str]) -> Result<Config, ConfigError> {
        let mut full = vec!["--target", "test-host"];
        full.extend_from_slice(args);
        load_exact(&full)
    }

    /// Load with exactly `args`.
    fn load_exact(args: &[&str]) -> Result<Config, ConfigError> {
        let cfg = Config::from_cli(cli(args))?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[]).unwrap();
        assert_eq!(
            cfg,
            Config {
                ssh_target: Some("test-host".to_string()),
                ..Config::default()
            }
        );
        assert_eq!(cfg.bind, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 3128);
        assert_eq!(cfg.socks_port, 1080);
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(3600));
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert_eq!(cfg.log_format, LogFormat::Text);
        assert!(!cfg.socks_block_web_in_mitm);
        assert!(!cfg.mitm_enabled());
        assert!(!cfg.is_multiplexed());
        assert!(cfg.notices().is_empty());
    }

    const FULL_TOML: &str = r#"
bind = "10.0.0.1"
http_port = 1111
socks_port = 2222

[mitm]
ca_p12 = "/file/ca.p12"
ca_passphrase_file = "/file/pass"
cert_ttl = "30m"
socks_block_web = true

[logging]
level = "debug"
format = "json"
http_access_log = "/file/http.log"
socks_log = "/file/socks.log"
"#;

    #[test]
    fn toml_overrides_defaults() {
        let _env = EnvGuard::new(&[]);
        let path = temp_file(FULL_TOML);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.bind, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 1111);
        assert_eq!(cfg.socks_port, 2222);
        assert_eq!(cfg.mitm_ca_p12, Some(PathBuf::from("/file/ca.p12")));
        assert_eq!(
            cfg.mitm_ca_passphrase_file,
            Some(PathBuf::from("/file/pass"))
        );
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(1800));
        assert!(cfg.socks_block_web_in_mitm);
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.http_access_log, Some(PathBuf::from("/file/http.log")));
        assert_eq!(cfg.socks_log, Some(PathBuf::from("/file/socks.log")));
        assert_eq!(
            cfg.ca_source(),
            Some(CaSource::Pkcs12 {
                path: PathBuf::from("/file/ca.p12")
            })
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn env_overrides_toml() {
        let path = temp_file(FULL_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_CONFIG", path.to_str().unwrap()),
            ("RUSTY_CONDUIT_SSH_BIND", "::1"),
            ("RUSTY_CONDUIT_SSH_HTTP_PORT", "3333"),
            ("RUSTY_CONDUIT_SSH_SOCKS_PORT", "4444"),
            ("RUSTY_CONDUIT_SSH_MITM_CERT_TTL", "2h"),
            ("RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB_IN_MITM", "false"),
            ("RUSTY_CONDUIT_SSH_LOG_LEVEL", "VERBOSE"),
            ("RUSTY_CONDUIT_SSH_LOG_FORMAT", "text"),
            ("RUSTY_CONDUIT_SSH_HTTP_ACCESS_LOG", "/env/http.log"),
            ("RUSTY_CONDUIT_SSH_SOCKS_LOG", "/env/socks.log"),
            ("RUSTY_CONDUIT_SSH_MITM_CA_P12", "/env/ca.p12"),
        ]);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.config_path, Some(path.clone()));
        assert_eq!(cfg.bind, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 3333);
        assert_eq!(cfg.socks_port, 4444);
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(7200));
        assert!(
            !cfg.socks_block_web_in_mitm,
            "env false overrides toml true"
        );
        assert_eq!(cfg.log_level, LogLevel::Verbose);
        assert_eq!(cfg.log_format, LogFormat::Text);
        assert_eq!(cfg.http_access_log, Some(PathBuf::from("/env/http.log")));
        assert_eq!(cfg.socks_log, Some(PathBuf::from("/env/socks.log")));
        assert_eq!(cfg.mitm_ca_p12, Some(PathBuf::from("/env/ca.p12")));
        // Not set in env: falls through to TOML.
        assert_eq!(
            cfg.mitm_ca_passphrase_file,
            Some(PathBuf::from("/file/pass"))
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn cli_overrides_env_and_toml() {
        let path = temp_file(FULL_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_CONFIG", path.to_str().unwrap()),
            ("RUSTY_CONDUIT_SSH_BIND", "::1"),
            ("RUSTY_CONDUIT_SSH_HTTP_PORT", "3333"),
            ("RUSTY_CONDUIT_SSH_LOG_LEVEL", "VERBOSE"),
            ("RUSTY_CONDUIT_SSH_LOG_FORMAT", "text"),
            ("RUSTY_CONDUIT_SSH_MITM_CERT_TTL", "2h"),
        ]);
        let cfg = load(&[
            "--bind",
            "127.0.0.2",
            "--http-port",
            "5555",
            "--socks-port",
            "6666",
            "--log-level",
            "error",
            "--log-format",
            "JSON",
            "--mitm-cert-ttl",
            "3600s",
            "--http-access-log",
            "/cli/http.log",
        ])
        .unwrap();
        assert_eq!(cfg.bind, "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 5555);
        assert_eq!(cfg.socks_port, 6666);
        assert_eq!(cfg.log_level, LogLevel::Error);
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(3600));
        assert_eq!(cfg.http_access_log, Some(PathBuf::from("/cli/http.log")));
        // Not on CLI or env: from TOML.
        assert_eq!(cfg.socks_log, Some(PathBuf::from("/file/socks.log")));
        fs::remove_file(path).ok();
    }

    #[test]
    fn cli_config_path_overrides_env_config_path() {
        let env_path = temp_file("http_port = 1\n");
        let cli_path = temp_file("http_port = 2\n");
        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_CONFIG", env_path.to_str().unwrap())]);
        let cfg = load(&["--config", cli_path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.http_port, 2);
        fs::remove_file(env_path).ok();
        fs::remove_file(cli_path).ok();
    }

    #[test]
    fn socks_block_web_flag_and_env() {
        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB", "true")]);
        let c = cli(&[]);
        assert!(c.socks_block_web_explicit);
        assert!(Config::merge(c, None).unwrap().socks_block_web_in_mitm);
        drop(_env);

        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_SOCKS_BLOCK_WEB_IN_MITM", "true")]);
        let c = cli(&[]);
        assert!(c.socks_block_web_explicit);
        assert!(Config::merge(c, None).unwrap().socks_block_web_in_mitm);
        drop(_env);

        let _env = EnvGuard::new(&[]);
        let c = cli(&["--socks-block-web"]);
        assert!(c.socks_block_web_explicit);
        assert!(Config::merge(c, None).unwrap().socks_block_web_in_mitm);

        let c = cli(&["--socks-block-web-in-mitm"]);
        assert!(c.socks_block_web_explicit);
        assert!(Config::merge(c, None).unwrap().socks_block_web_in_mitm);

        let c = cli(&[]);
        assert!(!c.socks_block_web_explicit);
        let file = FileConfig {
            socks_block_web: Some(true),
            ..Default::default()
        };
        assert!(
            Config::merge(c.clone(), Some(file))
                .unwrap()
                .socks_block_web_in_mitm
        );

        let legacy_file = FileConfig {
            mitm: FileMitmConfig {
                socks_block_web: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            Config::merge(c, Some(legacy_file))
                .unwrap()
                .socks_block_web_in_mitm
        );
    }

    #[test]
    fn passphrase_provenance() {
        let _env = EnvGuard::new(&[]);
        let cfg = Config::merge(cli(&["--mitm-ca-passphrase", "s3cret"]), None).unwrap();
        assert!(cfg.passphrase_from_cli);
        assert_eq!(cfg.mitm_ca_passphrase.as_deref(), Some("s3cret"));
        assert!(cfg
            .notices()
            .iter()
            .any(|n| n.contains("--mitm-ca-passphrase")));
        assert!(!format!("{cfg:?}").contains("s3cret"), "Debug must redact");
        drop(_env);

        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE", "s3cret")]);
        let cfg = Config::merge(cli(&[]), None).unwrap();
        assert!(!cfg.passphrase_from_cli);
        assert_eq!(cfg.mitm_ca_passphrase.as_deref(), Some("s3cret"));
        assert!(cfg.notices().is_empty());
    }

    #[test]
    fn passphrase_file_trims_trailing_newline() {
        let path = temp_file("hunter2\n");
        let cfg = Config {
            mitm_ca_passphrase_file: Some(path.clone()),
            ..Config::default()
        };
        assert_eq!(
            cfg.resolve_passphrase().unwrap().as_deref(),
            Some("hunter2")
        );
        fs::write(&path, "hunter2\r\n").unwrap();
        assert_eq!(
            cfg.resolve_passphrase().unwrap().as_deref(),
            Some("hunter2")
        );
        fs::write(&path, "with space ").unwrap();
        assert_eq!(
            cfg.resolve_passphrase().unwrap().as_deref(),
            Some("with space ")
        );
        fs::remove_file(path).ok();
    }

    // ---- FATAL validation rules ----

    #[test]
    fn fatal_both_ports_disabled() {
        let _env = EnvGuard::new(&[]);
        let err = load(&["--http-port", "0", "--socks-port", "0"]).unwrap_err();
        assert!(matches!(err, ConfigError::NoListeners));
        // Disabling only one is fine.
        load(&["--http-port", "0"]).unwrap();
        load(&["--socks-port", "0"]).unwrap();
    }

    #[test]
    fn fatal_p12_combined_with_pem() {
        let _env = EnvGuard::new(&[]);
        let err = load(&["--mitm-ca-p12", "a.p12", "--mitm-ca-cert", "c.pem"]).unwrap_err();
        assert!(matches!(err, ConfigError::AmbiguousCaSource));
        let err = load(&["--mitm-ca-p12", "a.p12", "--mitm-ca-key", "k.pem"]).unwrap_err();
        assert!(matches!(err, ConfigError::AmbiguousCaSource));
        let err = load(&[
            "--mitm-ca-p12",
            "a.p12",
            "--mitm-ca-cert",
            "c.pem",
            "--mitm-ca-key",
            "k.pem",
        ])
        .unwrap_err();
        assert!(matches!(err, ConfigError::AmbiguousCaSource));
    }

    #[test]
    fn fatal_ambiguous_ca_across_sources() {
        let path = temp_file("[mitm]\nca_cert = \"c.pem\"\nca_key = \"k.pem\"\n");
        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_MITM_CA_P12", "a.p12")]);
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::AmbiguousCaSource));
        fs::remove_file(path).ok();
    }

    #[test]
    fn fatal_incomplete_pem_pair() {
        let _env = EnvGuard::new(&[]);
        let err = load(&["--mitm-ca-cert", "c.pem"]).unwrap_err();
        assert!(matches!(err, ConfigError::IncompletePemCa));
        let err = load(&["--mitm-ca-key", "k.pem"]).unwrap_err();
        assert!(matches!(err, ConfigError::IncompletePemCa));
        let cfg = load(&["--mitm-ca-cert", "c.pem", "--mitm-ca-key", "k.pem"]).unwrap();
        assert!(cfg.mitm_enabled());
        assert_eq!(
            cfg.ca_source(),
            Some(CaSource::Pem {
                cert: "c.pem".into(),
                key: "k.pem".into()
            })
        );
    }

    #[test]
    fn fatal_both_passphrase_sources() {
        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_MITM_CA_PASSPHRASE_FILE", "/pass")]);
        let err = load(&["--mitm-ca-passphrase", "x"]).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingPassphrase));
    }

    #[test]
    fn fatal_cert_ttl_below_10s() {
        let _env = EnvGuard::new(&[]);
        let err = load(&["--mitm-cert-ttl", "9s"]).unwrap_err();
        assert!(matches!(err, ConfigError::CertTtlTooShort(d) if d == Duration::from_secs(9)));
        let err = load(&["--mitm-cert-ttl", "9999ms"]).unwrap_err();
        assert!(matches!(err, ConfigError::CertTtlTooShort(_)));
        let cfg = load(&["--mitm-cert-ttl", "10s"]).unwrap();
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(10));
    }

    #[test]
    fn fatal_cert_ttl_below_10s_from_toml() {
        let path = temp_file("[mitm]\ncert_ttl = \"5s\"\n");
        let _env = EnvGuard::new(&[]);
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::CertTtlTooShort(_)));
        fs::remove_file(path).ok();
    }

    #[test]
    fn fatal_bad_config_file() {
        let _env = EnvGuard::new(&[]);
        let err = load(&["--config", "/definitely/not/here.toml"]).unwrap_err();
        assert!(matches!(err, ConfigError::ReadFile { .. }));

        let path = temp_file("unknown_key = 1\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::ParseFile { .. }));
        fs::remove_file(path).ok();

        let path = temp_file("[logging]\nlevel = \"loud\"\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidFileValue {
                key: "logging.level",
                ..
            }
        ));
        fs::remove_file(path).ok();

        let path = temp_file("[mitm]\ncert_ttl = \"forever\"\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidFileValue {
                key: "mitm.cert_ttl",
                ..
            }
        ));
        fs::remove_file(path).ok();
    }

    #[test]
    fn invalid_cli_values_are_rejected() {
        let _env = EnvGuard::new(&[]);
        for args in [
            &["rusty-conduit-ssh", "--log-level", "loud"][..],
            &["rusty-conduit-ssh", "--log-format", "xml"][..],
            &["rusty-conduit-ssh", "--bind", "not-an-ip"][..],
            &["rusty-conduit-ssh", "--http-port", "70000"][..],
            &["rusty-conduit-ssh", "--mitm-cert-ttl", "soon"][..],
        ] {
            assert!(CliInput::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    // ---- INFO notices ----

    #[test]
    fn notice_non_loopback_bind() {
        let _env = EnvGuard::new(&[]);
        for bind in ["0.0.0.0", "192.168.1.10", "::"] {
            let cfg = load(&["--bind", bind]).unwrap();
            assert!(cfg.is_non_loopback_bind(), "{bind}");
            assert!(cfg.notices()[0].contains("NO authentication"), "{bind}");
        }
        for bind in ["127.0.0.1", "::1"] {
            let cfg = load(&["--bind", bind]).unwrap();
            assert!(!cfg.is_non_loopback_bind(), "{bind}");
            assert!(cfg.notices().is_empty(), "{bind}");
        }
    }

    #[test]
    fn socks_block_web_works_without_mitm_no_inactive_notice() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--socks-block-web"]).unwrap();
        assert!(cfg.socks_block_web_in_mitm);
        assert!(cfg.notices().is_empty());

        let cfg = load(&["--socks-block-web-in-mitm"]).unwrap();
        assert!(cfg.socks_block_web_in_mitm);
        assert!(cfg.notices().is_empty());
    }

    #[test]
    fn multiplexed_when_ports_equal() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--http-port", "8080", "--socks-port", "8080"]).unwrap();
        assert!(cfg.is_multiplexed());
        assert!(cfg.summary().contains("multiplexed=true"));
    }

    // ---- Resource caps ----

    const CAPS_TOML: &str = "max_connections = 11\n[mitm]\ncert_cache_max_entries = 22\n";

    #[test]
    fn caps_defaults() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.max_connections, 4096);
        assert_eq!(cfg.mitm_cert_cache_max_entries, 10_000);
        let s = cfg.summary();
        assert!(s.contains("max_connections=4096"), "{s}");
        assert!(s.contains("mitm_cert_cache_max_entries=10000"), "{s}");
    }

    #[test]
    fn caps_from_toml() {
        let path = temp_file(CAPS_TOML);
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.max_connections, 11);
        assert_eq!(cfg.mitm_cert_cache_max_entries, 22);
        fs::remove_file(path).ok();
    }

    #[test]
    fn caps_env_overrides_toml() {
        let path = temp_file(CAPS_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_MAX_CONNECTIONS", "33"),
            ("RUSTY_CONDUIT_SSH_MITM_CERT_CACHE_MAX_ENTRIES", "44"),
        ]);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.max_connections, 33);
        assert_eq!(cfg.mitm_cert_cache_max_entries, 44);
        fs::remove_file(path).ok();
    }

    #[test]
    fn caps_cli_overrides_env_and_toml() {
        let path = temp_file(CAPS_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_MAX_CONNECTIONS", "33"),
            ("RUSTY_CONDUIT_SSH_MITM_CERT_CACHE_MAX_ENTRIES", "44"),
        ]);
        let cfg = load(&[
            "--config",
            path.to_str().unwrap(),
            "--max-connections",
            "55",
            "--mitm-cert-cache-max-entries",
            "66",
        ])
        .unwrap();
        assert_eq!(cfg.max_connections, 55);
        assert_eq!(cfg.mitm_cert_cache_max_entries, 66);
        fs::remove_file(path).ok();
    }

    #[test]
    fn reverse_cap_follows_forward_cap_when_unset() {
        let _env = EnvGuard::new(&[]);
        assert_eq!(load(&[]).unwrap().reverse_max_connections, 4096);

        let path = temp_file(CAPS_TOML);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.reverse_max_connections, 11);
        let cfg = load(&[
            "--config",
            path.to_str().unwrap(),
            "--max-connections",
            "55",
        ])
        .unwrap();
        assert_eq!(
            cfg.reverse_max_connections, 55,
            "follows the winning forward layer"
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn reverse_cap_layers_override_forward_cap() {
        let path = temp_file("max_connections = 11\n[reverse]\nmax_connections = 22\n");
        let env = EnvGuard::new(&[]);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!((cfg.max_connections, cfg.reverse_max_connections), (11, 22));
        drop(env);

        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_REVERSE_MAX_CONNECTIONS", "33")]);
        let cfg = load(&[
            "--config",
            path.to_str().unwrap(),
            "--max-connections",
            "55",
        ])
        .unwrap();
        assert_eq!((cfg.max_connections, cfg.reverse_max_connections), (55, 33));

        let cfg = load(&[
            "--config",
            path.to_str().unwrap(),
            "--reverse-max-connections",
            "0",
        ])
        .unwrap();
        assert_eq!(
            (cfg.max_connections, cfg.reverse_max_connections),
            (11, 0),
            "CLI beats env"
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn caps_zero_means_unlimited_at_every_layer() {
        let path = temp_file("max_connections = 0\n[mitm]\ncert_cache_max_entries = 0\n");
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.max_connections, 0);
        assert_eq!(cfg.mitm_cert_cache_max_entries, 0);
        let s = cfg.summary();
        assert!(s.contains("max_connections=unlimited"), "{s}");
        assert!(s.contains("mitm_cert_cache_max_entries=unlimited"), "{s}");
        fs::remove_file(path).ok();
        drop(_env);

        // An explicit CLI 0 beats a non-zero env value rather than falling through.
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_MAX_CONNECTIONS", "33"),
            ("RUSTY_CONDUIT_SSH_MITM_CERT_CACHE_MAX_ENTRIES", "44"),
        ]);
        let cfg = load(&[
            "--max-connections",
            "0",
            "--mitm-cert-cache-max-entries",
            "0",
        ])
        .unwrap();
        assert_eq!(cfg.max_connections, 0);
        assert_eq!(cfg.mitm_cert_cache_max_entries, 0);
    }

    #[test]
    fn caps_reject_invalid_values() {
        let _env = EnvGuard::new(&[]);
        for args in [
            &["rusty-conduit-ssh", "--max-connections", "-1"][..],
            &["rusty-conduit-ssh", "--max-connections", "many"][..],
            &["rusty-conduit-ssh", "--mitm-cert-cache-max-entries", "-1"][..],
            &["rusty-conduit-ssh", "--mitm-cert-cache-max-entries", "many"][..],
        ] {
            assert!(CliInput::try_parse_from(args).is_err(), "{args:?}");
        }
        let path = temp_file("max_connections = -1\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::ParseFile { .. }), "{err}");
        fs::remove_file(path).ok();
    }

    #[test]
    fn summary_never_contains_passphrase() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--mitm-ca-p12", "a.p12", "--mitm-ca-passphrase", "s3cret"]).unwrap();
        let s = cfg.summary();
        assert!(s.contains("mitm=on(pkcs12)"));
        assert!(!s.contains("s3cret"));
    }

    // ---- SSH tunnel options ----

    const SSH_TOML: &str = r#"
[ssh]
target = "file-host"
bin = "/file/ssh"
socks_bind = "127.0.0.2"
socks_port = 1111
ip_version = 6
port = 2201
identity = "/file/id"
config = "/file/ssh_config"
jump = "file-jump"
server_alive_interval = "20s"
server_alive_count_max = 4
no_reconnect = true
reconnect_initial_delay = "2s"
reconnect_max_delay = "40s"
startup_timeout = "50s"
extra_args = ["-o", "Compression=yes"]
"#;

    #[test]
    fn clap_definition_is_valid() {
        CliArgs::command().debug_assert();
    }

    #[test]
    fn ssh_defaults() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.ssh_target.as_deref(), Some("test-host"));
        assert_eq!(cfg.ssh_bin, PathBuf::from("ssh"));
        assert_eq!(cfg.ssh_socks_bind, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.ssh_socks_port, 0);
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V4);
        assert_eq!(cfg.ssh_port, None);
        assert_eq!(cfg.ssh_identity, None);
        assert_eq!(cfg.ssh_config, None);
        assert_eq!(cfg.ssh_jump, None);
        assert_eq!(cfg.ssh_server_alive_interval, Duration::from_secs(15));
        assert_eq!(cfg.ssh_server_alive_count_max, 3);
        assert!(!cfg.no_reconnect);
        assert_eq!(cfg.reconnect_initial_delay, Duration::from_secs(1));
        assert_eq!(cfg.reconnect_max_delay, Duration::from_secs(30));
        assert_eq!(cfg.ssh_startup_timeout, Duration::from_secs(30));
        assert!(cfg.ssh_extra_args.is_empty());
    }

    #[test]
    fn ssh_toml_overrides_defaults() {
        let path = temp_file(SSH_TOML);
        let _env = EnvGuard::new(&[]);
        let cfg = load_exact(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.ssh_target.as_deref(), Some("file-host"));
        assert_eq!(cfg.ssh_bin, PathBuf::from("/file/ssh"));
        assert_eq!(cfg.ssh_socks_bind, "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.ssh_socks_port, 1111);
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V6);
        assert_eq!(cfg.ssh_port, Some(2201));
        assert_eq!(cfg.ssh_identity, Some(PathBuf::from("/file/id")));
        assert_eq!(cfg.ssh_config, Some(PathBuf::from("/file/ssh_config")));
        assert_eq!(cfg.ssh_jump.as_deref(), Some("file-jump"));
        assert_eq!(cfg.ssh_server_alive_interval, Duration::from_secs(20));
        assert_eq!(cfg.ssh_server_alive_count_max, 4);
        assert!(cfg.no_reconnect);
        assert_eq!(cfg.reconnect_initial_delay, Duration::from_secs(2));
        assert_eq!(cfg.reconnect_max_delay, Duration::from_secs(40));
        assert_eq!(cfg.ssh_startup_timeout, Duration::from_secs(50));
        assert_eq!(cfg.ssh_extra_args, ["-o", "Compression=yes"]);
        fs::remove_file(path).ok();
    }

    #[test]
    fn ssh_env_overrides_toml() {
        let path = temp_file(SSH_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_CONFIG", path.to_str().unwrap()),
            ("RUSTY_CONDUIT_SSH_TARGET", "env-host"),
            ("RUSTY_CONDUIT_SSH_SSH_BIN", "/env/ssh"),
            ("RUSTY_CONDUIT_SSH_SSH_SOCKS_BIND", "::1"),
            ("RUSTY_CONDUIT_SSH_SSH_SOCKS_PORT", "2222"),
            ("RUSTY_CONDUIT_SSH_SSH_IP_VERSION", "auto"),
            ("RUSTY_CONDUIT_SSH_SSH_PORT", "2202"),
            ("RUSTY_CONDUIT_SSH_SSH_IDENTITY", "/env/id"),
            ("RUSTY_CONDUIT_SSH_SSH_CONFIG", "/env/ssh_config"),
            ("RUSTY_CONDUIT_SSH_SSH_JUMP", "env-jump"),
            ("RUSTY_CONDUIT_SSH_SSH_SERVER_ALIVE_INTERVAL", "21s"),
            ("RUSTY_CONDUIT_SSH_SSH_SERVER_ALIVE_COUNT_MAX", "5"),
            ("RUSTY_CONDUIT_SSH_NO_RECONNECT", "false"),
            ("RUSTY_CONDUIT_SSH_RECONNECT_INITIAL_DELAY", "3s"),
            ("RUSTY_CONDUIT_SSH_RECONNECT_MAX_DELAY", "41s"),
            ("RUSTY_CONDUIT_SSH_SSH_STARTUP_TIMEOUT", "51s"),
        ]);
        let cfg = load_exact(&[]).unwrap();
        assert_eq!(cfg.config_path, Some(path.clone()));
        assert_eq!(cfg.ssh_target.as_deref(), Some("env-host"));
        assert_eq!(cfg.ssh_bin, PathBuf::from("/env/ssh"));
        assert_eq!(cfg.ssh_socks_bind, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.ssh_socks_port, 2222);
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::Auto);
        assert_eq!(cfg.ssh_port, Some(2202));
        assert_eq!(cfg.ssh_identity, Some(PathBuf::from("/env/id")));
        assert_eq!(cfg.ssh_config, Some(PathBuf::from("/env/ssh_config")));
        assert_eq!(cfg.ssh_jump.as_deref(), Some("env-jump"));
        assert_eq!(cfg.ssh_server_alive_interval, Duration::from_secs(21));
        assert_eq!(cfg.ssh_server_alive_count_max, 5);
        assert!(!cfg.no_reconnect, "env false overrides toml true");
        assert_eq!(cfg.reconnect_initial_delay, Duration::from_secs(3));
        assert_eq!(cfg.reconnect_max_delay, Duration::from_secs(41));
        assert_eq!(cfg.ssh_startup_timeout, Duration::from_secs(51));
        // No env form: falls through to TOML.
        assert_eq!(cfg.ssh_extra_args, ["-o", "Compression=yes"]);
        fs::remove_file(path).ok();
    }

    #[test]
    fn ssh_cli_overrides_env_and_toml() {
        let path = temp_file(SSH_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_CONFIG", path.to_str().unwrap()),
            ("RUSTY_CONDUIT_SSH_TARGET", "env-host"),
            ("RUSTY_CONDUIT_SSH_SSH_BIN", "/env/ssh"),
            ("RUSTY_CONDUIT_SSH_SSH_PORT", "2202"),
            ("RUSTY_CONDUIT_SSH_SSH_IDENTITY", "/env/id"),
            ("RUSTY_CONDUIT_SSH_SSH_CONFIG", "/env/ssh_config"),
            ("RUSTY_CONDUIT_SSH_SSH_JUMP", "env-jump"),
            ("RUSTY_CONDUIT_SSH_NO_RECONNECT", "false"),
        ]);
        let cfg = load_exact(&[
            "cli-host",
            "--ssh-bin",
            "/cli/ssh",
            "--ssh-socks-bind",
            "127.0.0.3",
            "--ssh-socks-port",
            "3333",
            "--ssh-ip-version",
            "4",
            "-p",
            "2203",
            "-i",
            "/cli/id",
            "-F",
            "/cli/ssh_config",
            "-J",
            "cli-jump",
            "--ssh-server-alive-interval",
            "22s",
            "--ssh-server-alive-count-max",
            "6",
            "--no-reconnect",
            "--reconnect-initial-delay",
            "4s",
            "--reconnect-max-delay",
            "42s",
            "--ssh-startup-timeout",
            "52s",
            "--",
            "-o",
            "LogLevel=ERROR",
        ])
        .unwrap();
        assert_eq!(cfg.ssh_target.as_deref(), Some("cli-host"));
        assert_eq!(cfg.ssh_bin, PathBuf::from("/cli/ssh"));
        assert_eq!(cfg.ssh_socks_bind, "127.0.0.3".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.ssh_socks_port, 3333);
        assert_eq!(cfg.ssh_ip_version, SshIpVersion::V4);
        assert_eq!(cfg.ssh_port, Some(2203));
        assert_eq!(cfg.ssh_identity, Some(PathBuf::from("/cli/id")));
        assert_eq!(cfg.ssh_config, Some(PathBuf::from("/cli/ssh_config")));
        assert_eq!(cfg.ssh_jump.as_deref(), Some("cli-jump"));
        assert_eq!(cfg.ssh_server_alive_interval, Duration::from_secs(22));
        assert_eq!(cfg.ssh_server_alive_count_max, 6);
        assert!(cfg.no_reconnect);
        assert_eq!(cfg.reconnect_initial_delay, Duration::from_secs(4));
        assert_eq!(cfg.reconnect_max_delay, Duration::from_secs(42));
        assert_eq!(cfg.ssh_startup_timeout, Duration::from_secs(52));
        assert_eq!(cfg.ssh_extra_args, ["-o", "LogLevel=ERROR"]);
        fs::remove_file(path).ok();
    }

    #[test]
    fn target_forms_and_precedence() {
        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_TARGET", "env-host")]);
        let positional = load_exact(&["pos-host"]).unwrap();
        assert_eq!(positional.ssh_target.as_deref(), Some("pos-host"));
        let option = load_exact(&["--target", "opt-host"]).unwrap();
        assert_eq!(option.ssh_target.as_deref(), Some("opt-host"));
        let env = load_exact(&[]).unwrap();
        assert_eq!(env.ssh_target.as_deref(), Some("env-host"));

        let err =
            CliInput::try_parse_from(["rusty-conduit-ssh", "a", "--target", "b"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn ip_version_parsing() {
        for (s, v) in [
            ("4", SshIpVersion::V4),
            ("6", SshIpVersion::V6),
            ("auto", SshIpVersion::Auto),
            ("AUTO", SshIpVersion::Auto),
        ] {
            assert_eq!(s.parse::<SshIpVersion>().unwrap(), v);
        }
        assert!("5".parse::<SshIpVersion>().is_err());

        let _env = EnvGuard::new(&[]);
        for (toml, expected) in [
            ("[ssh]\nip_version = 4\n", SshIpVersion::V4),
            ("[ssh]\nip_version = \"6\"\n", SshIpVersion::V6),
            ("[ssh]\nip_version = \"auto\"\n", SshIpVersion::Auto),
        ] {
            let path = temp_file(toml);
            let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
            assert_eq!(cfg.ssh_ip_version, expected, "{toml}");
            fs::remove_file(path).ok();
        }
        let path = temp_file("[ssh]\nip_version = 5\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::ParseFile { .. }), "{err}");
        fs::remove_file(path).ok();
    }

    #[test]
    fn fatal_missing_target() {
        let _env = EnvGuard::new(&[]);
        let err = load_exact(&[]).unwrap_err();
        assert!(matches!(err, ConfigError::MissingSshTarget), "{err}");
    }

    #[test]
    fn fatal_empty_target_from_every_source() {
        let _env = EnvGuard::new(&[]);
        for args in [&[""][..], &["   "][..], &["--target", ""][..]] {
            let err = load_exact(args).unwrap_err();
            assert!(matches!(err, ConfigError::EmptySshTarget), "{args:?}");
        }
        let path = temp_file("[ssh]\ntarget = \"\"\n");
        let err = load_exact(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::EmptySshTarget), "{err}");
        fs::remove_file(path).ok();
        drop(_env);

        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SSH_TARGET", " ")]);
        let err = load_exact(&[]).unwrap_err();
        assert!(matches!(err, ConfigError::EmptySshTarget), "{err}");
    }

    #[test]
    fn fatal_reconnect_delay_order() {
        let _env = EnvGuard::new(&[]);
        let err = load(&[
            "--reconnect-initial-delay",
            "31s",
            "--reconnect-max-delay",
            "30s",
        ])
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::ReconnectDelayOrder { initial, max }
                    if initial == Duration::from_secs(31) && max == Duration::from_secs(30)
            ),
            "{err}"
        );
        load(&[
            "--reconnect-initial-delay",
            "30s",
            "--reconnect-max-delay",
            "30s",
        ])
        .unwrap();
    }

    #[test]
    fn fatal_invalid_ssh_durations_in_toml() {
        let _env = EnvGuard::new(&[]);
        for (toml, expected) in [
            (
                "[ssh]\nserver_alive_interval = \"x\"\n",
                "ssh.server_alive_interval",
            ),
            (
                "[ssh]\nreconnect_initial_delay = \"x\"\n",
                "ssh.reconnect_initial_delay",
            ),
            (
                "[ssh]\nreconnect_max_delay = \"x\"\n",
                "ssh.reconnect_max_delay",
            ),
            ("[ssh]\nstartup_timeout = \"x\"\n", "ssh.startup_timeout"),
        ] {
            let path = temp_file(toml);
            let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidFileValue { key, .. } if key == expected),
                "{err}"
            );
            fs::remove_file(path).ok();
        }
    }

    #[test]
    fn invalid_ssh_cli_values_are_rejected() {
        let _env = EnvGuard::new(&[]);
        for args in [
            &["rusty-conduit-ssh", "--ssh-ip-version", "5"][..],
            &["rusty-conduit-ssh", "--ssh-socks-bind", "nope"][..],
            &["rusty-conduit-ssh", "--ssh-socks-port", "70000"][..],
            &["rusty-conduit-ssh", "-p", "70000"][..],
            &["rusty-conduit-ssh", "--ssh-server-alive-count-max", "-1"][..],
            &["rusty-conduit-ssh", "--reconnect-max-delay", "soon"][..],
        ] {
            assert!(CliInput::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    // ---- Reverse proxy ----

    const REVERSE_TOML: &str =
        "[reverse]\nbind = \"127.0.0.2\"\nhttp_port = 7001\nsocks_port = 7002\n";

    #[test]
    fn reverse_is_disabled_by_default() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.reverse_bind, DEFAULT_REVERSE_BIND);
        assert_eq!((cfg.reverse_http_port, cfg.reverse_socks_port), (0, 0));
        assert!(!cfg.reverse_enabled());
        assert!(!cfg.is_reverse_multiplexed());
        assert!(!cfg.summary().contains("reverse_"));
    }

    #[test]
    fn reverse_toml_env_cli_precedence() {
        let path = temp_file(REVERSE_TOML);
        let config = path.to_str().unwrap();
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--config", config]).unwrap();
        assert_eq!(cfg.reverse_bind, "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            (cfg.reverse_http_port, cfg.reverse_socks_port),
            (7001, 7002)
        );
        drop(_env);

        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_REVERSE_BIND", "::1"),
            ("RUSTY_CONDUIT_SSH_REVERSE_HTTP_PORT", "7101"),
        ]);
        let cfg = load(&["--config", config]).unwrap();
        assert_eq!(cfg.reverse_bind, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            (cfg.reverse_http_port, cfg.reverse_socks_port),
            (7101, 7002)
        );

        let cfg = load(&[
            "--config",
            config,
            "--reverse-bind",
            "127.0.0.3",
            "--reverse-http-port",
            "0",
            "--reverse-socks-port",
            "7202",
        ])
        .unwrap();
        assert_eq!(cfg.reverse_bind, "127.0.0.3".parse::<IpAddr>().unwrap());
        assert_eq!((cfg.reverse_http_port, cfg.reverse_socks_port), (0, 7202));
        fs::remove_file(path).ok();
    }

    #[test]
    fn reverse_rejects_invalid_values() {
        let _env = EnvGuard::new(&[]);
        for args in [
            &["rusty-conduit-ssh", "--reverse-bind", "nope"][..],
            &["rusty-conduit-ssh", "--reverse-http-port", "70000"][..],
            &["rusty-conduit-ssh", "--reverse-socks-port", "-1"][..],
        ] {
            assert!(CliInput::try_parse_from(args).is_err(), "{args:?}");
        }
        let path = temp_file("[reverse]\nunknown = 1\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(err, ConfigError::ParseFile { .. }), "{err}");
        fs::remove_file(path).ok();
    }

    #[test]
    fn reverse_only_mode_passes_validation() {
        let _env = EnvGuard::new(&[]);
        for flag in ["--reverse-http-port", "--reverse-socks-port"] {
            let cfg = load(&["--http-port", "0", "--socks-port", "0", flag, "8888"]).unwrap();
            assert!(!cfg.forward_enabled());
            assert!(cfg.reverse_enabled());
        }
        let err = load(&[
            "--http-port",
            "0",
            "--socks-port",
            "0",
            "--reverse-http-port",
            "0",
            "--reverse-socks-port",
            "0",
        ])
        .unwrap_err();
        assert!(matches!(err, ConfigError::NoListeners));
    }

    #[test]
    fn reverse_multiplexing_and_summary() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[
            "--reverse-http-port",
            "8888",
            "--reverse-socks-port",
            "8888",
        ])
        .unwrap();
        assert!(cfg.is_reverse_multiplexed());
        let s = cfg.summary();
        assert!(s.contains("reverse_bind=127.0.0.1"), "{s}");
        assert!(s.contains("reverse_http_port=8888"), "{s}");
        assert!(s.contains("reverse_max_connections=4096"), "{s}");
        assert!(s.contains("reverse_socks_port=8888"), "{s}");
        assert!(s.contains("reverse_multiplexed=true"), "{s}");

        let cfg = load(&["--reverse-socks-port", "8889"]).unwrap();
        assert!(!cfg.is_reverse_multiplexed());
        let s = cfg.summary();
        assert!(s.contains("reverse_http_port=disabled"), "{s}");
        assert!(s.contains("reverse_socks_port=8889"), "{s}");
    }

    #[test]
    fn reverse_notice_only_for_enabled_non_loopback_bind() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--reverse-bind", "0.0.0.0", "--reverse-http-port", "8888"]).unwrap();
        let notices = cfg.notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("reverse proxy"), "{notices:?}");
        assert!(notices[0].contains("NO authentication"), "{notices:?}");

        // Set but disabled, or loopback: nothing to warn about.
        assert!(load(&["--reverse-bind", "0.0.0.0"])
            .unwrap()
            .notices()
            .is_empty());
        for bind in ["127.0.0.1", "::1"] {
            let cfg = load(&["--reverse-bind", bind, "--reverse-http-port", "8888"]).unwrap();
            assert!(cfg.notices().is_empty(), "{bind}");
        }
    }

    #[test]
    fn ssh_extra_args_are_never_logged() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--", "-o", "ProxyCommand=s3cret"]).unwrap();
        assert_eq!(cfg.ssh_extra_args.len(), 2);
        assert!(!format!("{cfg:?}").contains("s3cret"), "Debug must redact");
        let s = cfg.summary();
        assert!(!s.contains("s3cret"), "{s}");
        assert!(s.contains("ssh_extra_args=2"), "{s}");
        assert!(s.contains("ssh_target=test-host"), "{s}");
        assert!(s.contains("ssh_socks_port=ephemeral"), "{s}");
    }

    #[test]
    fn filter_cli_env_toml_and_conflict_validation() {
        let _env = EnvGuard::new(&[]);
        // CLI repeatable + comma-separated
        let cfg = load(&[
            "--allow",
            "*.example.com,10.0.0.0/8",
            "--allow",
            "127.0.0.1",
            "--reverse-http-port",
            "8888",
            "--reverse-block",
            "127.0.0.0/8,::1,*.internal",
        ])
        .unwrap();
        assert_eq!(cfg.allow.len(), 3);
        assert!(cfg.block.is_empty());
        assert_eq!(cfg.reverse_block.len(), 3);
        assert!(cfg.reverse_allow.is_empty());
        let s = cfg.summary();
        assert!(s.contains("filter=allow(3)"), "{s}");
        assert!(s.contains("reverse_filter=block(3)"), "{s}");

        // Combined forward allow + block: allowlist serves as exceptions to blocklist
        let cfg = load(&["--allow", "test.domain.net", "--block", "*.domain.net"]).unwrap();
        assert!(matches!(
            cfg.forward_filter(),
            Some(HostFilter::BlockExcept { .. })
        ));
        assert!(cfg.summary().contains("filter=block-except(2)"));

        // Combined reverse allow + block: allowlist serves as exceptions to blocklist
        let cfg = load(&[
            "--reverse-http-port",
            "8888",
            "--reverse-allow",
            "test.domain.net",
            "--reverse-block",
            "*.domain.net",
        ])
        .unwrap();
        assert!(matches!(
            cfg.reverse_filter(),
            Some(HostFilter::BlockExcept { .. })
        ));
        assert!(cfg.summary().contains("reverse_filter=block-except(2)"));

        // TOML parsing + env override
        let toml_path = temp_file(
            r#"
allow = ["example.com", "192.168.0.0/16"]
[ssh]
target = "toml-host"
[reverse]
http_port = 8888
block = ["127.0.0.0/8", "::1"]
"#,
        );
        let cli = CliInput::try_parse_from([
            "rusty-conduit-ssh",
            "--config",
            toml_path.to_str().unwrap(),
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.allow.len(), 2);
        assert_eq!(cfg.reverse_block.len(), 2);

        // Cross-source combination (TOML allow + CLI block) produces BlockExcept
        let cli = CliInput::try_parse_from([
            "rusty-conduit-ssh",
            "--config",
            toml_path.to_str().unwrap(),
            "--block",
            "10.0.0.0/8",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli).unwrap();
        cfg.validate().unwrap();
        assert!(matches!(
            cfg.forward_filter(),
            Some(HostFilter::BlockExcept { .. })
        ));
        let _ = fs::remove_file(&toml_path);
    }

    // ---- TCP keepalive ----

    #[test]
    fn keepalive_defaults() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[]).unwrap();
        assert_eq!(
            cfg.tcp_keepalive_settings(),
            Some(KeepaliveSettings::DEFAULT)
        );
        assert_eq!(KeepaliveSettings::DEFAULT.idle, Duration::from_secs(60));
        assert_eq!(KeepaliveSettings::DEFAULT.interval, Duration::from_secs(10));
        assert_eq!(KeepaliveSettings::DEFAULT.retries, 5);
        let s = cfg.summary();
        assert!(s.contains("tcp_keepalive=1m/10sx5"), "{s}");
    }

    #[test]
    fn keepalive_precedence_cli_over_env_over_toml() {
        let path = temp_file(
            "tcp_keepalive = \"2m\"\ntcp_keepalive_interval = \"20s\"\ntcp_keepalive_retries = 3\n",
        );
        let p = path.to_str().unwrap();

        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--config", p]).unwrap();
        assert_eq!(
            cfg.tcp_keepalive_settings(),
            Some(KeepaliveSettings {
                idle: Duration::from_secs(120),
                interval: Duration::from_secs(20),
                retries: 3,
            })
        );
        drop(_env);

        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SSH_TCP_KEEPALIVE", "90s"),
            ("RUSTY_CONDUIT_SSH_TCP_KEEPALIVE_RETRIES", "7"),
        ]);
        let cfg = load(&["--config", p, "--tcp-keepalive-retries", "9"]).unwrap();
        assert_eq!(cfg.tcp_keepalive, Duration::from_secs(90));
        assert_eq!(cfg.tcp_keepalive_interval, Duration::from_secs(20));
        assert_eq!(cfg.tcp_keepalive_retries, 9);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn keepalive_zero_disables() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&["--tcp-keepalive", "0"]).unwrap();
        assert_eq!(cfg.tcp_keepalive_settings(), None);
        assert!(cfg.summary().contains("tcp_keepalive=off"));
        // Interval / retries are not validated while keepalive is off.
        let cfg = load(&["--tcp-keepalive", "0", "--tcp-keepalive-retries", "0"]).unwrap();
        assert_eq!(cfg.tcp_keepalive_settings(), None);

        let path = temp_file("tcp_keepalive = \"0s\"\n");
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.tcp_keepalive_settings(), None);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn fatal_invalid_keepalive() {
        let _env = EnvGuard::new(&[]);
        for args in [
            &["--tcp-keepalive", "500ms"][..],
            &["--tcp-keepalive", "10h"][..],
            &["--tcp-keepalive-interval", "0s"][..],
            &["--tcp-keepalive-retries", "0"][..],
            &["--tcp-keepalive-retries", "128"][..],
        ] {
            let err = load(args).unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidKeepalive(_)),
                "{args:?}: {err}"
            );
        }
        let path = temp_file("tcp_keepalive = \"soon\"\n");
        let err = load(&["--config", path.to_str().unwrap()]).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidFileValue {
                key: "tcp_keepalive",
                ..
            }
        ));
        let _ = fs::remove_file(&path);
    }
}
