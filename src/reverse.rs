//! Reverse proxy: a local HTTP/HTTPS + SOCKS4/4a/5 server published on the SSH target with
//! `ssh -R`, so clients there egress through this machine.
//!
//! Every upstream connection uses [`DirectDialer`]. The forward path's SOCKS dialer, and any
//! [`MitmState`] wrapping it, must never be used here because that would send traffic straight
//! back to the SSH target. MITM therefore gets its own state and certificate cache.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::logging::{AccessLogger, Logger, ProxyDirection};
use crate::mitm::MitmState;
use crate::net::{DirectDialer, UpstreamDialer};
use crate::server::{ListenPlan, ListenerRole, ProtocolHandlers, Server, ShutdownReport};
use crate::ssh::ReverseForward;
use crate::{build_engines, EngineHandlers};

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
        let direct = match cfg.reverse_filter() {
            Some(filter) => DirectDialer::with_filter(Arc::new(filter)),
            None => DirectDialer::default(),
        };
        let dialer: Arc<dyn UpstreamDialer> = Arc::new(direct.with_tcp_keepalive(keepalive));
        let mitm = MitmState::from_config(cfg, Arc::clone(&dialer))
            .map_err(|e| format!("reverse proxy MITM setup failed: {e}"))?;
        if let Some(m) = &mitm {
            m.cache.set_logger(logger.clone());
        }

        let (http, socks) = build_engines(cfg, mitm.as_ref(), access, logger, dialer);
        let http = http.with_direction(ProxyDirection::Reverse);
        let socks = socks.with_direction(ProxyDirection::Reverse);
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(EngineHandlers::new(http, socks));
        let server = Server::bind(
            ListenPlan::reverse_from_config(cfg),
            handlers,
            logger.clone(),
        )
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
