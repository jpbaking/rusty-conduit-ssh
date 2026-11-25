//! Reverse proxy: a local HTTP/HTTPS + SOCKS4/4a/5 server published on the SSH target with
//! `ssh -R`, so clients there egress through this machine.
//!
//! It is a second engine [`Server`] whose [`RoutingState`] egresses through the built-in
//! `direct` profile only. The forward path's tunnel profile must never be used here because
//! that would send traffic straight back to the SSH target. MITM therefore gets its own state
//! and certificate cache.
//!
//! The reverse allow/block filter is handed to the direct dialer only (through
//! [`DialerOptions`], not [`RoutingInput::filter`]): the dialer checks the requested name and
//! every locally resolved IP, so an IP/CIDR-only allowlist still admits a hostname that
//! resolves into it, and DNS-to-blocked-IP bypasses are refused.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::logging::{AccessLogger, Logger, ProxyDirection};
use crate::mitm::MitmState;
use crate::net::DEFAULT_CONNECT_TIMEOUT;
use crate::routing::{RoutingInput, RoutingSetupError, RoutingState};
use crate::server::{ListenPlan, ListenerRole, ProtocolHandlers, Server, ShutdownReport};
use crate::ssh::ReverseForward;
use crate::upstream::DialerOptions;
use crate::{build_engines_with, EngineHandlers};

/// Plan for the reverse proxy: ephemeral loopback ports, never reachable directly from the
/// network. They are bound once, so `ssh -R` targets stay stable across reconnects.
pub fn reverse_listen_plan(cfg: &Config) -> ListenPlan {
    let ephemeral = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    if cfg.is_reverse_multiplexed() {
        return ListenPlan::Multiplexed(ephemeral);
    }
    ListenPlan::Separate {
        http: (cfg.reverse_http_port > 0).then_some(ephemeral),
        socks: (cfg.reverse_socks_port > 0).then_some(ephemeral),
    }
}

/// Reverse routing: every request egresses through `direct` (local DNS), with the reverse
/// allow/block filter enforced by the direct dialer, the configured keepalive, and the
/// default connect timeout.
pub fn reverse_routing(cfg: &Config) -> Result<RoutingState, RoutingSetupError> {
    let input = RoutingInput {
        filter: None,
        mitm_enabled: cfg.mitm_enabled(),
        keepalive: cfg.tcp_keepalive_settings(),
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        ..RoutingInput::default()
    };
    let opts = DialerOptions {
        filter: cfg.reverse_filter().map(Arc::new),
        ..DialerOptions::default()
    };
    RoutingState::from_input(&input, opts)
}

/// A running reverse proxy server.
#[derive(Debug)]
pub struct ReverseProxy {
    forwards: Vec<ReverseForward>,
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
}

impl ReverseProxy {
    /// Bind and start serving, or return `Ok(None)` when no reverse port is configured.
    ///
    /// Call this before starting `ssh`, so [`Self::forwards`] can be passed as `-R` arguments.
    /// An `Err` is a `FATAL` startup failure.
    pub async fn start(
        cfg: &Config,
        access: &AccessLogger,
        logger: &Logger,
    ) -> Result<Option<Self>, String> {
        if !cfg.reverse_enabled() {
            return Ok(None);
        }

        let keepalive = cfg.tcp_keepalive_settings();
        let routing = reverse_routing(cfg)
            .map_err(|e| format!("reverse proxy routing setup failed: {e}"))?
            .shared();
        let mitm = MitmState::from_options(&cfg.mitm_options())
            .map_err(|e| format!("reverse proxy MITM setup failed: {e}"))?;
        if let Some(m) = &mitm {
            m.cache.set_logger(logger.clone());
        }

        let access = access.clone().with_direction(ProxyDirection::Reverse);
        let (http, socks) = build_engines_with(cfg, mitm.as_ref(), &access, logger, routing);
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
        let server = Server::bind(reverse_listen_plan(cfg), handlers, logger.clone())
            .await
            .map_err(|e| format!("reverse proxy: {e}"))?
            .with_max_connections(cfg.reverse_max_connections)
            .with_tcp_keepalive(keepalive);

        let mut forwards = Vec::new();
        for (role, local) in server.listeners() {
            let port = match role {
                ListenerRole::Http | ListenerRole::Multiplexed => cfg.reverse_http_port,
                ListenerRole::Socks => cfg.reverse_socks_port,
            };
            let remote = SocketAddr::new(cfg.reverse_bind, port);
            logger.info(format!(
                "reverse {role} proxy listening on {local}, exposed on SSH target at {remote} \
                 (ssh -R {remote}:{local})"
            ));
            forwards.push(ReverseForward { remote, local });
        }

        let token = server.shutdown_token();
        let reaper = mitm
            .as_ref()
            .map(|m| m.cache.spawn_reaper(token.clone(), logger.clone()));
        let run = tokio::spawn(server.run());
        Ok(Some(Self {
            forwards,
            token,
            run,
            reaper,
        }))
    }

    /// The `ssh -R` forwards for the bound listeners.
    pub fn forwards(&self) -> &[ReverseForward] {
        &self.forwards
    }

    /// Stop accepting, drain in-flight connections, and join the certificate reaper.
    pub async fn shutdown(self) -> ShutdownReport {
        self.token.cancel();
        let report = self.run.await.unwrap_or(ShutdownReport { drained: false });
        if let Some(reaper) = self.reaper {
            let _ = reaper.await;
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn forward_plan_from_config() {
        let mut cfg = Config {
            http_port: 3128,
            socks_port: 1080,
            ..Config::default()
        };
        assert_eq!(
            ListenPlan::from_options(&cfg.server_options()),
            ListenPlan::Separate {
                http: Some(SocketAddr::new(cfg.bind, 3128)),
                socks: Some(SocketAddr::new(cfg.bind, 1080)),
            }
        );
        cfg.socks_port = 0;
        assert_eq!(
            ListenPlan::from_options(&cfg.server_options()),
            ListenPlan::Separate {
                http: Some(SocketAddr::new(cfg.bind, 3128)),
                socks: None,
            }
        );
        cfg.http_port = 0;
        cfg.socks_port = 1080;
        assert_eq!(
            ListenPlan::from_options(&cfg.server_options()),
            ListenPlan::Separate {
                http: None,
                socks: Some(SocketAddr::new(cfg.bind, 1080)),
            }
        );
        cfg.http_port = 8080;
        cfg.socks_port = 8080;
        assert_eq!(
            ListenPlan::from_options(&cfg.server_options()),
            ListenPlan::Multiplexed(SocketAddr::new(cfg.bind, 8080))
        );
    }

    #[test]
    fn reverse_plan_uses_ephemeral_loopback() {
        let ephemeral = loopback(0);
        let plan = |reverse_http_port, reverse_socks_port| {
            reverse_listen_plan(&Config {
                // The remote bind must never leak into the local listener address.
                reverse_bind: "0.0.0.0".parse().unwrap(),
                reverse_http_port,
                reverse_socks_port,
                ..Config::default()
            })
        };
        assert_eq!(plan(8888, 8888), ListenPlan::Multiplexed(ephemeral));
        assert_eq!(
            plan(8888, 1081),
            ListenPlan::Separate {
                http: Some(ephemeral),
                socks: Some(ephemeral),
            }
        );
        assert_eq!(
            plan(8888, 0),
            ListenPlan::Separate {
                http: Some(ephemeral),
                socks: None,
            }
        );
        assert_eq!(
            plan(0, 1081),
            ListenPlan::Separate {
                http: None,
                socks: Some(ephemeral),
            }
        );
    }

    /// Route and dial `host:port` through `state` the way the engines do.
    async fn dial(state: &RoutingState, host: &str, port: u16) -> std::io::Result<()> {
        use crate::router::RouteRequest;
        use crate::routing::{Inbound, RouteResolver};

        let decision = state
            .resolve(&RouteRequest {
                inbound: Inbound::Http,
                host,
                port,
                scheme: None,
                url: None,
            })
            .map_err(crate::filter::access_denied_error)?;
        let chain = state.registry.chain_for(&decision.targets).unwrap();
        chain
            .dial(host, port, std::time::Duration::from_secs(5))
            .await
            .map(drop)
    }

    #[tokio::test]
    async fn reverse_filter_checks_resolved_ips_for_hostnames() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let rules = |r: &[&str]| r.iter().map(|r| r.parse().unwrap()).collect::<Vec<_>>();

        // An IP/CIDR-only allowlist admits a hostname that resolves into it.
        let allow = reverse_routing(&Config {
            reverse_allow: rules(&["127.0.0.0/8"]),
            ..Config::default()
        })
        .unwrap();
        dial(&allow, "localhost", port).await.unwrap();
        dial(&allow, "127.0.0.1", port).await.unwrap();

        // A blocklist refuses a hostname that resolves to a blocked IP (DNS-to-loopback).
        let block = reverse_routing(&Config {
            reverse_block: rules(&["127.0.0.0/8", "::1"]),
            ..Config::default()
        })
        .unwrap();
        let err = dial(&block, "localhost", port).await.unwrap_err();
        assert!(crate::filter::is_access_denied(&err), "{err}");
    }
}
