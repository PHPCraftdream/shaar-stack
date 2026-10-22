#![forbid(unsafe_code)]
//! Integration tests for bounded file loading and the async `load_*`
//! entry points (overrides merged from real files).

use std::path::{Path, PathBuf};

use shaar::config::{
    ClientOverrides, ConfigError, Fallback, MAX_CONFIG_BYTES, ServerOverrides, load_client,
    load_server,
};

const RFC8032_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_PUB2_HEX: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

const SERVER_FIXTURE: &str = include_str!("fixtures/server.ktav");
const CLIENT_FIXTURE: &str = include_str!("fixtures/client.ktav");

fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shaar-config-load-{}-{}.ktav",
        tag,
        std::process::id()
    ));
    std::fs::write(&p, bytes).unwrap();
    p
}

fn unique_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shaar-config-load-{}-{}.ktav",
        tag,
        std::process::id()
    ));
    p
}

#[tokio::test]
async fn load_server_fixture_applies_all_overrides() {
    let over = ServerOverrides {
        target: Some("127.0.0.1:9100".to_string()),
        key_file: Some(PathBuf::from("over.key")),
        allowlist_path: Some(PathBuf::from("over.txt")),
        fallback: Some(Fallback::Standby),
    };
    let p = temp_file("srv-over", SERVER_FIXTURE.as_bytes());
    let cfg = load_server(&p, &over).await.unwrap();
    assert_eq!(cfg.target().to_string(), "127.0.0.1:9100");
    assert_eq!(cfg.key_file(), Path::new("over.key"));
    assert_eq!(cfg.allowlist_path(), Path::new("over.txt"));
    assert_eq!(cfg.fallback(), Fallback::Standby);
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_client_fixture_applies_all_overrides() {
    let over = ClientOverrides {
        server: Some(RFC8032_PUB2_HEX.to_string()),
        listen: Some("127.0.0.1:2400".to_string()),
        key_file: Some(PathBuf::from("over.key")),
        fallback: Some(Fallback::Signal),
    };
    let p = temp_file("cli-over", CLIENT_FIXTURE.as_bytes());
    let cfg = load_client(&p, &over).await.unwrap();
    assert_eq!(
        cfg.server_key_bytes(),
        RFC8032_PUB2_HEX
            .parse::<iroh_base::PublicKey>()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(cfg.listen().port(), 2400);
    assert_eq!(cfg.key_file(), Path::new("over.key"));
    assert_eq!(cfg.fallback(), Fallback::Signal);
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_required_fields_solely_from_overrides() {
    // Empty file, everything from the CLI — server…
    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        ..Default::default()
    };
    let p = temp_file("srv-empty", b"");
    let cfg = load_server(&p, &over).await.unwrap();
    assert_eq!(cfg.target().to_string(), "127.0.0.1:80");
    assert_eq!(cfg.fallback(), Fallback::Standby);
    std::fs::remove_file(&p).ok();

    // …and client.
    let over = ClientOverrides {
        server: Some(RFC8032_PUB_HEX.to_string()),
        ..Default::default()
    };
    let p = temp_file("cli-empty", b"");
    let cfg = load_client(&p, &over).await.unwrap();
    assert_eq!(cfg.listen().to_string(), "127.0.0.1:2222");
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_repairs_invalid_file_fallback_with_override() {
    let p = temp_file("bad-fallback", b"target: 127.0.0.1:9000\nfallback: bogus\n");
    let over = ServerOverrides {
        fallback: Some(Fallback::Signal),
        ..Default::default()
    };
    let cfg = load_server(&p, &over).await.unwrap();
    assert_eq!(cfg.fallback(), Fallback::Signal);

    // Without the override the same file must fail with a
    // fallback-attributed validation error.
    let err = load_server(&p, &ServerOverrides::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "fallback",
            kind: shaar::config::ValidationKind::InvalidEnum
        }
    ));
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_malformed_document_rejected_despite_complete_overrides() {
    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        ..Default::default()
    };
    let p = temp_file("malformed", b"target:127.0.0.1:9000\n");
    let err = load_server(&p, &over).await.err().unwrap();
    match &err {
        ConfigError::Parsing { kind: "syntax", .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_unknown_field_rejection_retained() {
    let p = temp_file("unknown", b"target: 127.0.0.1:9000\nzz_sentinel_zz: v\n");
    let err = load_server(&p, &ServerOverrides::default())
        .await
        .err()
        .unwrap();
    match &err {
        ConfigError::Parsing { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
    let d = err.to_string();
    assert!(!d.contains("zz_sentinel_zz"), "leaked: {d}");
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_missing_file_is_loading_error() {
    let p = unique_path("does-not-exist");
    let err = load_server(&p, &ServerOverrides::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Loading {
            kind: shaar::config::LoadKind::Io,
            ..
        }
    ));
    let d = err.to_string();
    assert!(!d.contains("does-not-exist"), "leaked: {d}");
}

#[tokio::test]
async fn load_size_bound_exact_and_plus_one() {
    // Exactly MAX_CONFIG_BYTES: accepted by the load bound (the
    // subsequent parse fails only on the missing target).
    let line = "## abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno\n"; // 55 bytes
    let count = MAX_CONFIG_BYTES / line.len();
    let mut text = line.repeat(count);
    while text.len() < MAX_CONFIG_BYTES {
        text.push('\n');
    }
    assert_eq!(text.len(), MAX_CONFIG_BYTES);
    let p = temp_file("bound", text.as_bytes());
    let err = load_server(&p, &ServerOverrides::default())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, ConfigError::Validation { .. }),
        "expected validation error past the load bound, got {err:?}"
    );
    std::fs::remove_file(&p).ok();

    // Bound + 1 byte: rejected at load, before parsing.
    let text2 = format!("{text}#");
    assert_eq!(text2.len(), MAX_CONFIG_BYTES + 1);
    let p = temp_file("over", text2.as_bytes());
    let err = load_server(&p, &ServerOverrides::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Loading {
            kind: shaar::config::LoadKind::TooLarge,
            ..
        }
    ));
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_invalid_utf8_rejected_at_load() {
    let mut bytes = b"target: 127.0.0.1:9000\n".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    let p = temp_file("utf8", &bytes);
    let err = load_server(&p, &ServerOverrides::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Loading {
            kind: shaar::config::LoadKind::InvalidUtf8,
            ..
        }
    ));
    std::fs::remove_file(&p).ok();
}

#[tokio::test]
async fn load_both_fallback_modes_end_to_end() {
    let p1 = temp_file("fb-signal", b"target: 127.0.0.1:9000\nfallback: signal\n");
    let cfg = load_server(&p1, &ServerOverrides::default()).await.unwrap();
    assert_eq!(cfg.fallback(), Fallback::Signal);
    std::fs::remove_file(&p1).ok();

    let p2 = temp_file("fb-standby", b"target: 127.0.0.1:9000\nfallback: standby\n");
    let cfg = load_server(&p2, &ServerOverrides::default()).await.unwrap();
    assert_eq!(cfg.fallback(), Fallback::Standby);
    std::fs::remove_file(&p2).ok();
}
