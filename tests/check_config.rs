//! End-to-end tests for `netwatch --check-config`.
//!
//! These drive the real binary rather than the library, because the contract
//! that matters is the *exit code*: `deploy/install.sh` and the documented
//! `--check-config && systemctl restart` idiom both gate on it. A config that
//! netwatch cannot parse takes DNS down for the whole network, so "did it exit
//! non-zero" is the behaviour worth pinning, not the internal error type.

use std::path::PathBuf;
use std::process::{Command, Output};

const EXAMPLE: &str = include_str!("../config.example.toml");

/// A config file in a unique temp path, removed when the test ends.
struct TempConfig(PathBuf);

impl TempConfig {
    fn new(name: &str, body: &str) -> Self {
        // Unique per process and per name so parallel test threads cannot
        // collide on the same path.
        let path = std::env::temp_dir().join(format!(
            "netwatch-check-{}-{}-{name}.toml",
            std::process::id(),
            name.len()
        ));
        std::fs::write(&path, body).expect("write temp config");
        Self(path)
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn check(path: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_netwatch"))
        .args([
            "--config".as_ref(),
            path.as_os_str(),
            "--check-config".as_ref(),
        ])
        .output()
        .expect("run netwatch --check-config")
}

#[test]
fn the_shipped_example_config_passes() {
    let cfg = TempConfig::new("valid", EXAMPLE);
    let out = check(&cfg.0);
    assert!(
        out.status.success(),
        "example config must validate, got {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("config OK"),
        "expected a readable verdict on stdout"
    );
}

/// The exact failure that took a live network down: appending a key that was
/// already set. TOML rejects it, netwatch exits, systemd restarts into the same
/// file forever.
#[test]
fn a_duplicate_key_fails_with_a_nonzero_exit() {
    let body = format!("{EXAMPLE}\n[web]\nadmin_token = \"aaaa\"\nadmin_token = \"bbbb\"\n");
    let cfg = TempConfig::new("duplicate", &body);
    let out = check(&cfg.0);

    assert_eq!(
        out.status.code(),
        Some(1),
        "a config netwatch cannot parse must exit 1 so a shell `&&` stops there"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("duplicate key"),
        "must say what is wrong: {stderr}"
    );
    assert!(
        stderr.contains("INVALID"),
        "must be greppable as a failure: {stderr}"
    );
}

/// Parsing is not enough — a file can be valid TOML and still be a config
/// netwatch refuses to start with.
#[test]
fn a_semantically_invalid_config_also_fails() {
    // Valid TOML, but the dashboard is off-loopback with no admin token.
    let body = "[web]\nlisten = \"0.0.0.0:8080\"\n";
    let cfg = TempConfig::new("novalidate", body);
    let out = check(&cfg.0);

    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("admin_token"),
        "must name the key that needs fixing: {stderr}"
    );
}

/// A mistyped path must not be reported as OK. netwatch would start on
/// built-in defaults, which is a legitimate outcome, but silently answering
/// "OK" to `--config /etc/netwtach/config.toml` hides a typo.
#[test]
fn a_missing_file_says_so_rather_than_claiming_ok() {
    let missing = std::env::temp_dir().join("netwatch-check-definitely-not-here.toml");
    let _ = std::fs::remove_file(&missing);
    let out = check(&missing);

    assert!(out.status.success(), "defaults are a valid configuration");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not found"),
        "must distinguish 'missing' from 'valid': {stdout}"
    );
}
