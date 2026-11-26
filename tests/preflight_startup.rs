//! Startup runs the offline pre-flight checks before launching `ssh`, so a local mistake
//! never costs a connection attempt against the SSH server.

#![cfg(unix)]

mod common;

use std::process::ExitCode;

use tokio_util::sync::CancellationToken;

use rusty_conduit_ssh::config::Config;
use rusty_conduit_ssh::run_until;

use common::*;

#[tokio::test]
async fn bad_mitm_ca_stops_startup_before_ssh_runs() {
    let mock = MockSsh::new();
    let cfg = Config {
        ssh_target: Some("user@tunnel.test".into()),
        ssh_bin: mock.bin(),
        mitm_ca_cert: Some("/nonexistent/ca.pem".into()),
        mitm_ca_key: Some("/nonexistent/ca.key".into()),
        ..Config::default()
    };
    let code = run_until(cfg, quiet_logger(), CancellationToken::new()).await;
    assert_eq!(code, ExitCode::from(1));
    // The mock records its argv only when it runs as the tunnel (`ssh -G` exits first).
    assert!(
        !mock.dir.join("args").exists(),
        "ssh was launched: {:?}",
        mock.lines("args")
    );
}

#[tokio::test]
async fn unreadable_identity_stops_startup_before_ssh_runs() {
    let mock = MockSsh::new();
    let cfg = Config {
        ssh_target: Some("user@tunnel.test".into()),
        ssh_bin: mock.bin(),
        ssh_identity: Some("/nonexistent/id_ed25519".into()),
        ..Config::default()
    };
    let code = run_until(cfg, quiet_logger(), CancellationToken::new()).await;
    assert_eq!(code, ExitCode::from(1));
    assert!(!mock.dir.join("args").exists(), "ssh was launched");
}
