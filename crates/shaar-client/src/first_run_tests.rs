//! First-run CLI grammar and client provisioning tests. Fixture directories
//! live under `target/` with pid+counter names and clean up via `Drop`;
//! the process environment is never mutated.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/shaar-client-first-run-fixtures");
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

    fn client_dir(&self) -> PathBuf {
        self.0.join("client")
    }

    fn config_path(&self) -> PathBuf {
        self.client_dir().join("client.ktav")
    }

    fn read_bytes(&self) -> Vec<u8> {
        std::fs::read(self.config_path()).expect("client.ktav readable")
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Forward-slash form so the path embeds as a single-line ktav value.
fn ktav_value(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn parse_two_positionals_is_first_run_with_server_and_address() {
    assert_eq!(
        parse_invocation(["client".into(), "a".into(), "b".into()]),
        Ok(Invocation::FirstRun {
            server: Some("a".to_owned()),
            server_address: Some("b".to_owned())
        })
    );
}

#[test]
fn parse_config_flag_without_value_is_a_usage_error() {
    assert!(parse_invocation(["client".into(), "--config".into()]).is_err());
}

#[test]
fn parse_three_positionals_is_a_usage_error() {
    assert!(parse_invocation(["client".into(), "a".into(), "b".into(), "c".into()]).is_err());
}

#[test]
fn parse_flag_in_positional_pair_is_a_usage_error() {
    assert!(parse_invocation(["client".into(), "-k".into(), "a".into()]).is_err());
}

#[tokio::test]
async fn legacy_config_present_detects_existing_and_missing_files() {
    let dir = FixtureDir::new();
    std::fs::write(dir.config_path(), b"").expect("write legacy config");
    assert!(legacy_config_present(&dir.config_path()).await.unwrap());
    let absent = dir.client_dir().join("absent.ktav");
    assert!(!legacy_config_present(&absent).await.unwrap());
}

#[tokio::test]
async fn first_run_without_arguments_reports_missing_key() {
    let dir = FixtureDir::new();
    let state = first_run_state(&dir.0, None, None)
        .await
        .expect("first run MissingKey");
    let FirstRunState::MissingKey { block, error } = state else {
        panic!("expected MissingKey");
    };
    assert_eq!(block.len(), 6, "summary(4) + two next-step lines");
    assert!(block[3].starts_with("public_key="));
    assert_eq!(block[4], "no server key configured");
    assert_eq!(
        block[5],
        "next step: run shaar-client <server-public-key> <server-address>"
    );
    assert_eq!(
        error,
        "invalid configuration value for field `server` (MissingRequired)"
    );
    assert!(dir.client_dir().join("client.ktav").exists());
    assert!(dir.client_dir().join("shaar.key").exists());
    assert!(!dir.client_dir().join("allowed.txt").exists());
    let text = String::from_utf8(dir.read_bytes()).expect("utf-8 template");
    let expected = format!(
        "key_file:: {}",
        ktav_value(&dir.client_dir().join("shaar.key"))
    );
    assert!(
        text.lines().any(|line| line == expected),
        "client.ktav must name the absolute key path: {text}"
    );
}

#[tokio::test]
async fn first_run_with_key_but_no_address_reports_missing_address() {
    let dir = FixtureDir::new();
    let key_hex = hex(&Identity::from_seed([9; 32]).public_key_bytes());
    let state = first_run_state(&dir.0, Some(key_hex.clone()), None)
        .await
        .expect("first run MissingAddress");
    let FirstRunState::MissingAddress { block, error } = state else {
        panic!("expected MissingAddress");
    };
    assert_eq!(block[4], "no server address configured");
    assert_eq!(
        block[5],
        format!("next step: run shaar-client {key_hex} <server-address>")
    );
    assert_eq!(
        error,
        "server_address is required for direct-only operation without network settings"
    );
}

#[tokio::test]
async fn first_run_ready_pins_server_and_announces_the_allowlist_key() {
    let dir = FixtureDir::new();
    let key_hex = hex(&Identity::from_seed([9; 32]).public_key_bytes());
    let state = first_run_state(
        &dir.0,
        Some(key_hex.clone()),
        Some("127.0.0.1:9".to_owned()),
    )
    .await
    .expect("first run Ready");
    let FirstRunState::Ready {
        config,
        identity,
        block,
    } = state
    else {
        panic!("expected Ready");
    };
    assert_eq!(
        config.server_key_bytes(),
        &Identity::from_seed([9; 32]).public_key_bytes()
    );
    assert_eq!(
        block[4],
        format!(
            "your public key for the server allowlist: public_key={}",
            hex(&identity.public_key_bytes())
        )
    );
    assert!(
        block[5].contains("pinned server: public_key=")
            && block[5].ends_with("address=127.0.0.1:9"),
        "pinned server line: {}",
        block[5]
    );
    assert_eq!(
        block[6],
        "add your key as one line to the server allowlist file, then restart the server"
    );
}

#[tokio::test]
async fn second_first_run_reuses_the_provisioned_directory_and_config() {
    let dir = FixtureDir::new();
    let key_hex = hex(&Identity::from_seed([9; 32]).public_key_bytes());
    let first = first_run_state(
        &dir.0,
        Some(key_hex.clone()),
        Some("127.0.0.1:9".to_owned()),
    )
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

    let second = first_run_state(&dir.0, Some(key_hex), Some("127.0.0.1:9".to_owned()))
        .await
        .expect("second run");
    assert_eq!(dir.read_bytes(), bytes, "client.ktav must not be rewritten");
    let FirstRunState::Ready {
        block, identity, ..
    } = second
    else {
        panic!("expected Ready");
    };
    assert_eq!(identity.public_key_bytes(), first_key);
    assert!(
        block[0].contains("(reused)"),
        "directory line must say reused: {}",
        block[0]
    );
    assert!(
        block.iter().any(|line| line.starts_with("kept: ")),
        "expected kept: lines in {block:?}"
    );
}

#[tokio::test]
async fn first_run_never_overwrites_a_pre_existing_config() {
    let dir = FixtureDir::new();
    // The sentinel is a fully valid config so the Ready branch is reachable;
    // the positional key overrides it without rewriting the file.
    let pinned_hex = hex(&Identity::from_seed([9; 32]).public_key_bytes());
    let override_hex = hex(&Identity::from_seed([8; 32]).public_key_bytes());
    let sentinel = format!(
        "server: {pinned_hex}\nserver_address: 127.0.0.1:9\nkey_file:: {}\n",
        ktav_value(&dir.client_dir().join("shaar.key"))
    );
    std::fs::create_dir_all(dir.client_dir()).expect("client dir");
    std::fs::write(dir.config_path(), &sentinel).expect("sentinel write");
    let state = first_run_state(
        &dir.0,
        Some(override_hex.clone()),
        Some("127.0.0.1:9".to_owned()),
    )
    .await
    .expect("first run Ready");
    let FirstRunState::Ready { config, .. } = state else {
        panic!("expected Ready");
    };
    assert_eq!(
        std::fs::read(dir.config_path()).expect("sentinel readable"),
        sentinel.as_bytes(),
        "pre-existing config bytes must not change"
    );
    assert_eq!(
        config.server_key_bytes(),
        &Identity::from_seed([8; 32]).public_key_bytes(),
        "positional server key must override the file"
    );
}

#[tokio::test]
async fn first_run_rejects_an_invalid_server_key() {
    let dir = FixtureDir::new();
    let Err(error) = first_run_state(
        &dir.0,
        Some("not-a-key".to_owned()),
        Some("127.0.0.1:9".to_owned()),
    )
    .await
    else {
        panic!("invalid key must fail");
    };
    assert!(error.contains("field `server`"), "unexpected: {error}");
}

#[tokio::test]
async fn first_run_rejects_a_digit_only_server_key() {
    let dir = FixtureDir::new();
    let Err(error) =
        first_run_state(&dir.0, Some("1".repeat(64)), Some("127.0.0.1:9".to_owned())).await
    else {
        panic!("digit-only key must fail Ed25519 validation");
    };
    assert!(error.contains("field `server`"), "unexpected: {error}");
}
