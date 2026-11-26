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
