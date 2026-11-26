//! Binary tests for the `validate` subcommand and CLI usage exit codes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str, body: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rusty-conduit-ssh-validate-{tag}-{}-{n}.toml",
            std::process::id()
        ));
        fs::write(&path, body).unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let bin = env!("CARGO_BIN_EXE_rusty-conduit-ssh");
    let out = Command::new(bin)
        .args(args)
        .env_remove("RUSTY_CONDUIT_SSH_TARGET")
        .env_remove("RUSTY_CONDUIT_SSH_CONFIG")
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn validate_with_target_exits_zero() {
    let (code, out, err) = run(&["validate", "example.test"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("config OK: none target=example.test"), "{out}");
}

#[test]
fn validate_without_target_exits_one() {
    let (code, _, err) = run(&["validate"]);
    assert_eq!(code, Some(1));
    assert!(err.contains("config invalid:"), "{err}");
    assert!(err.contains("missing SSH target"), "{err}");
}

#[test]
fn validate_with_invalid_toml_exits_one() {
    let bad = TempFile::new("bad-toml", "http_port = \"nope\"\n");
    let (code, _, err) = run(&["validate", "example.test", "--config", bad.path()]);
    assert_eq!(code, Some(1));
    assert!(err.contains("config invalid:"), "{err}");
}

#[test]
fn unknown_flag_exits_two() {
    let (code, _, _) = run(&["example.test", "--no-such-flag"]);
    assert_eq!(code, Some(2));
}

fn ssh_on_path() -> bool {
    Command::new("ssh").arg("-V").output().is_ok()
}

#[test]
fn validate_checks_the_ssh_program_unless_settings_only() {
    let args = ["--ssh-bin", "/nonexistent/ssh", "validate", "example.test"];
    let (code, _, err) = run(&args);
    assert_eq!(code, Some(1));
    assert!(
        err.starts_with("config invalid: --ssh-bin /nonexistent/ssh does not exist"),
        "{err}"
    );
    let (code, _, err) = run(&[&args[..], &["--settings-only"]].concat());
    assert_eq!(code, Some(0), "{err}");
}

#[test]
fn validate_checks_the_identity_file() {
    if !ssh_on_path() {
        return;
    }
    let (code, _, err) = run(&["-i", "/nonexistent/id_ed25519", "validate", "example.test"]);
    assert_eq!(code, Some(1));
    assert!(
        err.starts_with("config invalid: cannot read --ssh-identity /nonexistent/id_ed25519"),
        "{err}"
    );
}

#[test]
fn validate_runs_ssh_g_on_the_ssh_config() {
    if !ssh_on_path() {
        return;
    }
    let bad = TempFile::new("bad-ssh-config", "Host x\n    Bogus yes\n");
    let (code, _, err) = run(&["-F", bad.path(), "validate", "x"]);
    assert_eq!(code, Some(1));
    assert!(
        err.starts_with("config invalid: `ssh -G` rejected the SSH configuration:"),
        "{err}"
    );
    assert!(err.to_lowercase().contains("bogus"), "{err}");

    let good = TempFile::new("good-ssh-config", "Host x\n    HostName example.test\n");
    let (code, out, err) = run(&["-F", good.path(), "validate", "x"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.starts_with("config OK: none target=x"), "{out}");
}

#[test]
fn validate_checks_the_mitm_ca_files_unless_settings_only() {
    let ca = [
        "--mitm-ca-cert",
        "/nonexistent/ca.pem",
        "--mitm-ca-key",
        "/nonexistent/ca.key",
    ];
    let (code, _, err) = run(&[&ca[..], &["validate", "example.test"]].concat());
    assert_eq!(code, Some(1));
    assert!(
        err.starts_with("config invalid: MITM setup failed:"),
        "{err}"
    );
    let (code, _, err) = run(&[&ca[..], &["validate", "example.test", "--settings-only"]].concat());
    assert_eq!(code, Some(0), "{err}");
}
