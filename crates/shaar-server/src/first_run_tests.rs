//! First-run CLI grammar and provisioning flow tests. Fixture directories
//! live under `target/` with pid+counter names and clean up via `Drop`;
//! the process environment is never mutated.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{FirstRunState, Invocation, first_run_state, parse_invocation};

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/shaar-server-first-run-fixtures");
        std::fs::create_dir_all(&base).expect("fixture parent");
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("fixture directory: {err}"),
            }
        }
        panic!("fixture namespace exhausted");
    }

    fn server_dir(&self) -> PathBuf {
        self.0.join("server")
    }

    fn config_path(&self) -> PathBuf {
        self.server_dir().join("server.ktav")
    }

    fn read_bytes(&self) -> Vec<u8> {
        std::fs::read(self.config_path()).expect("server.ktav readable")
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn os(value: &str) -> OsString {
    OsString::from(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Forward-slash form so the path embeds as a single-line ktav value.
fn ktav_value(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn parse_config_flag_preserves_the_path() {
    let invocation =
        parse_invocation([os("shaar-server"), os("--config"), os("C:/cfg/server.ktav")])
            .expect("valid --config invocation");
    match invocation {
        Invocation::Config(path) => {
            assert_eq!(path, PathBuf::from("C:/cfg/server.ktav"));
        }
        other => panic!("expected Config, got {other:?}"),
    }
}

#[test]
fn parse_no_arguments_is_first_run_without_target() {
    match parse_invocation([os("shaar-server")]).expect("valid bare invocation") {
        Invocation::FirstRun { target } => assert_eq!(target, None),
        other => panic!("expected FirstRun, got {other:?}"),
    }
}

#[test]
fn parse_single_positional_is_first_run_with_target() {
    match parse_invocation([os("shaar-server"), os("127.0.0.1:8080")]).expect("valid positional") {
        Invocation::FirstRun { target } => assert_eq!(target.as_deref(), Some("127.0.0.1:8080")),
        other => panic!("expected FirstRun, got {other:?}"),
    }
}

#[test]
fn parse_two_positionals_is_a_usage_error() {
    let err = parse_invocation([os("shaar-server"), os("a"), os("b")]).expect_err("usage error");
    assert!(err.contains("usage: shaar-server"), "unexpected: {err}");
}

#[test]
fn parse_config_without_value_is_a_usage_error() {
    let err = parse_invocation([os("shaar-server"), os("--config")]).expect_err("usage error");
    assert!(err.contains("usage: shaar-server"), "unexpected: {err}");
}

#[test]
fn parse_config_with_extra_argument_is_a_usage_error() {
    let err = parse_invocation([os("shaar-server"), os("--config"), os("a"), os("b")])
        .expect_err("usage error");
    assert!(err.contains("usage: shaar-server"), "unexpected: {err}");
}

#[test]
fn parse_unknown_flag_is_a_usage_error() {
    let err = parse_invocation([os("shaar-server"), os("-x")]).expect_err("usage error");
    assert!(err.contains("usage: shaar-server"), "unexpected: {err}");
}

#[tokio::test]
async fn first_run_with_target_provisions_and_announces() {
    let dir = FixtureDir::new();
    let state = first_run_state(&dir.0, Some("127.0.0.1:8080".to_owned()))
        .await
        .expect("first run ready");
    let FirstRunState::Ready {
        config,
        identity,
        keys,
        block,
    } = state
    else {
        panic!("expected Ready");
    };
    assert!(dir.server_dir().join("server.ktav").exists());
    assert!(dir.server_dir().join("shaar.key").exists());
    assert!(dir.server_dir().join("allowed.txt").exists());
    assert_eq!(config.target().to_string(), "127.0.0.1:8080");
    assert!(keys.is_empty(), "template allowlist loads zero keys");
    assert_eq!(
        block[block.len() - 3],
        "clients connect direct: give each client this public key and this machine's address with the bound port"
    );
    assert_eq!(
        block[block.len() - 2],
        format!(
            "allowlist {}: empty - append each client's public key as one line, then restart the server to admit it",
            config.allowlist_path().display()
        )
    );
    assert_eq!(block[block.len() - 1], "forward target: 127.0.0.1:8080");
    let summary_len = block.len() - 3;
    assert_eq!(
        block[summary_len - 1],
        format!("public_key={}", hex(&identity.public_key_bytes()))
    );
    // The template names the key and allowlist as absolute paths and never
    // carries an uncommented target line.
    let text = String::from_utf8(dir.read_bytes()).expect("utf-8 template");
    let mut key_line = false;
    let mut allowlist_line = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("key_file:: ") {
            key_line = true;
            assert_eq!(Path::new(value), config.key_file());
        }
        if let Some(value) = line.strip_prefix("allowlist_path:: ") {
            allowlist_line = true;
            assert_eq!(Path::new(value), config.allowlist_path());
        }
        assert!(
            !line.starts_with("target:") && !line.starts_with("target:: "),
            "template must not set a target: {line}"
        );
    }
    assert!(key_line && allowlist_line);
}

#[tokio::test]
async fn second_first_run_keeps_files_and_key() {
    let dir = FixtureDir::new();
    let first = first_run_state(&dir.0, Some("127.0.0.1:8080".to_owned()))
        .await
        .expect("first run");
    let bytes = dir.read_bytes();
    let FirstRunState::Ready {
        identity: first_identity,
        ..
    } = first
    else {
        panic!("expected Ready");
    };
    let first_key = first_identity.public_key_bytes();

    let second = first_run_state(&dir.0, Some("127.0.0.1:8080".to_owned()))
        .await
        .expect("second run");
    assert_eq!(dir.read_bytes(), bytes, "server.ktav must not be rewritten");
    let FirstRunState::Ready {
        block, identity, ..
    } = second
    else {
        panic!("expected Ready");
    };
    assert_eq!(identity.public_key_bytes(), first_key);
    assert!(
        block.iter().any(|line| line.starts_with("kept: ")),
        "expected kept: lines in {block:?}"
    );
    assert!(
        block[0].contains("(reused)"),
        "directory line must say reused: {}",
        block[0]
    );
}

#[tokio::test]
async fn first_run_without_target_reports_missing_target() {
    let dir = FixtureDir::new();
    let state = first_run_state(&dir.0, None)
        .await
        .expect("provisioning itself succeeds");
    let FirstRunState::MissingTarget { block, error } = state else {
        panic!("expected MissingTarget");
    };
    assert_eq!(block.len(), 7, "summary(5) + two next-step lines");
    assert!(block[4].starts_with("public_key="));
    assert_eq!(block[5], "no forward target configured");
    assert_eq!(
        block[6],
        format!(
            "next step: run shaar-server <target:port> or set target: in {}",
            dir.server_dir().join("server.ktav").display()
        )
    );
    assert_eq!(
        error,
        "invalid configuration value for field `target` (MissingRequired)"
    );
}

#[tokio::test]
async fn first_run_never_overwrites_a_pre_existing_config() {
    let dir = FixtureDir::new();
    // The sentinel is a fully valid config (with a distinct target) so the
    // Ready branch is still reachable through the override.
    std::fs::create_dir_all(dir.server_dir()).expect("server dir");
    let sentinel = format!(
        "target: 127.0.0.1:9999\nkey_file:: {}\nallowlist_path:: {}\n",
        ktav_value(&dir.server_dir().join("shaar.key")),
        ktav_value(&dir.server_dir().join("allowed.txt")),
    );
    std::fs::write(dir.config_path(), &sentinel).expect("sentinel write");

    let state = first_run_state(&dir.0, Some("127.0.0.1:8080".to_owned()))
        .await
        .expect("first run ready");
    let FirstRunState::Ready { config, .. } = state else {
        panic!("expected Ready");
    };
    assert_eq!(
        std::fs::read(dir.config_path()).expect("sentinel readable"),
        sentinel.as_bytes(),
        "pre-existing config bytes must not change"
    );
    // The positional target overrides the file's own target.
    assert_eq!(config.target().to_string(), "127.0.0.1:8080");
}

#[tokio::test]
async fn first_run_rejects_an_invalid_positional_target() {
    let dir = FixtureDir::new();
    let Err(err) = first_run_state(&dir.0, Some("not-an-address".to_owned())).await else {
        panic!("invalid target must fail");
    };
    assert!(err.contains("field `target`"), "unexpected: {err}");
}

#[tokio::test]
async fn positional_target_overrides_a_configured_target_line() {
    let dir = FixtureDir::new();
    std::fs::create_dir_all(dir.server_dir()).expect("server dir");
    let file_text = format!(
        "target: 127.0.0.1:9999\nkey_file:: {}\nallowlist_path:: {}\n",
        ktav_value(&dir.server_dir().join("shaar.key")),
        ktav_value(&dir.server_dir().join("allowed.txt")),
    );
    std::fs::write(dir.config_path(), &file_text).expect("config write");

    let state = first_run_state(&dir.0, Some("127.0.0.1:8080".to_owned()))
        .await
        .expect("first run ready");
    let FirstRunState::Ready { config, .. } = state else {
        panic!("expected Ready");
    };
    assert_eq!(
        config.target().to_string(),
        "127.0.0.1:8080",
        "positional target must override the file target"
    );
    assert_eq!(
        std::fs::read(dir.config_path()).expect("config readable"),
        file_text.as_bytes(),
        "file bytes must remain untouched"
    );
}
