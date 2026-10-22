#![forbid(unsafe_code)]
//! Integration tests for the SDK startup configuration layer:
//! schema, merging, validation, redaction, and key fixtures.
//! (File-loading/bound tests live in `config_load.rs`.)

use std::path::{Path, PathBuf};

use shaar::config::{
    ClientConfig, ClientOverrides, ConfigError, Fallback, MAX_CONFIG_BYTES, ServerConfig,
    ServerOverrides, ValidationKind,
};

// RFC 8032 § 7.1 test-vector 1 Ed25519 public key.
const RFC8032_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
// RFC 8032 § 7.1 test-vector 2 Ed25519 public key (a DIFFERENT valid key).
const RFC8032_PUB2_HEX: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const RFC8032_PUB2: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];
// Canonical INVALID Edwards compressed point: y = 2, sign bit 0. y = 2 is
// a quadratic non-residue mod p, so no curve point has this compressed
// form; the real upstream parser (iroh-base 1.3.0 `PublicKey::from_str`
// → `VerifyingKey::from_bytes` decompression) must reject it.
const INVALID_POINT_HEX: &str = "0200000000000000000000000000000000000000000000000000000000000000";

const SERVER_FIXTURE: &str = include_str!("fixtures/server.ktav");
const CLIENT_FIXTURE: &str = include_str!("fixtures/client.ktav");

fn assert_redacted(err: &ConfigError, forbidden: &[&str]) {
    assert!(
        !forbidden.is_empty(),
        "redaction check with an empty forbidden list is vacuous"
    );
    let d = err.to_string();
    let b = format!("{err:?}");
    for f in forbidden {
        assert!(!d.contains(f), "Display leaked {f:?}: {d}");
        assert!(!b.contains(f), "Debug leaked {f:?}: {b}");
    }
}

#[test]
fn server_fixture_parses_with_concrete_values() {
    let cfg = ServerConfig::from_text(SERVER_FIXTURE, &ServerOverrides::default()).unwrap();
    assert_eq!(cfg.target().to_string(), "127.0.0.1:9000");
    assert_eq!(cfg.key_file(), Path::new("keys/identity.key"));
    assert_eq!(cfg.allowlist_path(), Path::new("conf/allowed.txt"));
    assert_eq!(cfg.fallback(), Fallback::Signal);
}

#[test]
fn client_fixture_parses_with_concrete_values() {
    let cfg = ClientConfig::from_text(CLIENT_FIXTURE, &ClientOverrides::default()).unwrap();
    assert_eq!(cfg.server_key_bytes(), &RFC8032_PUB);
    assert_eq!(cfg.listen().to_string(), "127.0.0.1:2300");
    assert_eq!(cfg.key_file(), Path::new("shaar.key"));
    assert_eq!(cfg.fallback(), Fallback::Standby);
}

#[test]
fn all_overrides_win_over_file_values() {
    // key_file / allowlist_path / fallback / target for the server.
    let file =
        "target: 127.0.0.1:9000\nkey_file: file.key\nallowlist_path: file.txt\nfallback: signal\n";
    let over = ServerOverrides {
        target: Some("127.0.0.1:9100".to_string()),
        key_file: Some(PathBuf::from("over.key")),
        allowlist_path: Some(PathBuf::from("over.txt")),
        fallback: Some(Fallback::Standby),
    };
    let cfg = ServerConfig::from_text(file, &over).unwrap();
    assert_eq!(cfg.target().port(), 9100);
    assert_eq!(cfg.key_file(), Path::new("over.key"));
    assert_eq!(cfg.allowlist_path(), Path::new("over.txt"));
    assert_eq!(cfg.fallback(), Fallback::Standby);

    // server / listen / key_file / fallback for the client.
    let file = format!(
        "server: {RFC8032_PUB_HEX}\nlisten: 127.0.0.1:2300\nkey_file: file.key\nfallback: signal\n"
    );
    let over = ClientOverrides {
        server: Some(RFC8032_PUB2_HEX.to_string()),
        listen: Some("127.0.0.1:2400".to_string()),
        key_file: Some(PathBuf::from("over.key")),
        fallback: Some(Fallback::Standby),
    };
    let cfg = ClientConfig::from_text(&file, &over).unwrap();
    assert_eq!(cfg.server_key_bytes(), &RFC8032_PUB2);
    assert_eq!(cfg.listen().port(), 2400);
    assert_eq!(cfg.key_file(), Path::new("over.key"));
    assert_eq!(cfg.fallback(), Fallback::Standby);
}

#[test]
fn required_fields_supplied_solely_by_overrides() {
    // Comment-only document: every required field comes from the CLI.
    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        ..Default::default()
    };
    let cfg = ServerConfig::from_text("## empty\n", &over).unwrap();
    assert_eq!(cfg.target().to_string(), "127.0.0.1:80");

    let over = ClientOverrides {
        server: Some(RFC8032_PUB_HEX.to_string()),
        ..Default::default()
    };
    let cfg = ClientConfig::from_text("## empty\n", &over).unwrap();
    assert_eq!(cfg.server_key_bytes(), &RFC8032_PUB);
}

#[test]
fn invalid_file_fallback_is_repaired_by_valid_override() {
    // `bogus` is syntactically valid ktav (a string scalar), so the
    // document parses; the invalid enum spelling must only be
    // validated AFTER the typed CLI override replaces it.
    let file = "target: 127.0.0.1:9000\nfallback: bogus\n";
    let over = ServerOverrides {
        fallback: Some(Fallback::Signal),
        ..Default::default()
    };
    let cfg = ServerConfig::from_text(file, &over).unwrap();
    assert_eq!(cfg.fallback(), Fallback::Signal);

    // Without the override the same file value must fail with a
    // fallback-attributed validation error.
    let err = ServerConfig::from_text(file, &ServerOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "fallback",
            kind: ValidationKind::InvalidEnum
        }
    ));
    assert_redacted(&err, &["bogus"]);
}

#[test]
fn malformed_document_rejected_even_with_complete_overrides() {
    // A stray closing brace is a structured parser error in ktav 0.8.0,
    // unlike a bare root scalar, which instead fails schema validation.
    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        ..Default::default()
    };
    let err = ServerConfig::from_text("target: 127.0.0.1:9000\n}\n", &over)
        .err()
        .unwrap();
    match &err {
        ConfigError::Parsing { kind: "syntax", .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(err.line(), Some(2));
    assert_redacted(&err, &["127.0.0.1", "target"]);
}

#[test]
fn root_scalar_schema_error_is_not_repaired_by_overrides() {
    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        ..Default::default()
    };
    let err = ServerConfig::from_text("target:127.0.0.1:9000\n", &over).unwrap_err();
    assert!(matches!(err, ConfigError::Parsing { kind: "schema", .. }));
    assert_redacted(&err, &["127.0.0.1", "target"]);
}

#[test]
fn unknown_field_rejection_is_retained() {
    let sentinel = "zz_sentinel_unknown_zz";
    let file = format!("target: 127.0.0.1:9000\n{sentinel}: x\n");
    let err = ServerConfig::from_text(&file, &ServerOverrides::default())
        .err()
        .unwrap();
    match &err {
        ConfigError::Parsing { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert_redacted(&err, &[sentinel]);
}

#[test]
fn server_target_must_be_loopback_and_nonzero_port() {
    let sentinel = "zz_sentinel_addr_zz";
    let err = ServerConfig::from_text("target: 192.168.1.5:8000\n", &ServerOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "target",
            kind: ValidationKind::NotLoopback
        }
    ));

    let err = ServerConfig::from_text("target: 127.0.0.1:0\n", &ServerOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "target",
            kind: ValidationKind::InvalidPort
        }
    ));

    // Invalid KNOWN field value: the sentinel value text must not leak.
    let file = format!("target: {sentinel}:8000\n");
    let err = ServerConfig::from_text(&file, &ServerOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "target",
            kind: ValidationKind::InvalidAddress
        }
    ));
    assert_redacted(&err, &[sentinel]);
}

#[test]
fn client_listen_rules() {
    let file = format!("server: {RFC8032_PUB_HEX}\nlisten: 10.0.0.1:2222\n");
    let err = ClientConfig::from_text(&file, &ClientOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "listen",
            kind: ValidationKind::NotLoopback
        }
    ));

    // Port 0 is an ordinary OS ephemeral port for the client listener
    // (the server target port 0 remains rejected).
    let file = format!("server: {RFC8032_PUB_HEX}\nlisten: 127.0.0.1:0\n");
    let cfg = ClientConfig::from_text(&file, &ClientOverrides::default()).unwrap();
    assert_eq!(cfg.listen().port(), 0);
}

#[test]
fn both_fallback_modes_accepted_end_to_end() {
    let base = "target: 127.0.0.1:9000\n";
    let cfg =
        ServerConfig::from_text(&format!("{base}fallback: signal\n"), &Default::default()).unwrap();
    assert_eq!(cfg.fallback(), Fallback::Signal);
    let cfg = ServerConfig::from_text(&format!("{base}fallback: standby\n"), &Default::default())
        .unwrap();
    assert_eq!(cfg.fallback(), Fallback::Standby);
    // CLI-side, both modes too.
    let cfg = ServerConfig::from_text(
        base,
        &ServerOverrides {
            fallback: Some(Fallback::Signal),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(cfg.fallback(), Fallback::Signal);
}

#[test]
fn empty_path_values_rejected_after_merging() {
    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        key_file: Some(PathBuf::from("")),
        ..Default::default()
    };
    let err = ServerConfig::from_text("## empty\n", &over).err().unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "key_file",
            kind: ValidationKind::EmptyPath
        }
    ));

    let over = ServerOverrides {
        target: Some("127.0.0.1:80".to_string()),
        allowlist_path: Some(PathBuf::from("")),
        ..Default::default()
    };
    let err = ServerConfig::from_text("## empty\n", &over).err().unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "allowlist_path",
            kind: ValidationKind::EmptyPath
        }
    ));

    // Empty value coming from the file itself, merged against no
    // override, is likewise rejected.
    let err = ServerConfig::from_text(
        "target: 127.0.0.1:80\nkey_file: \n",
        &ServerOverrides::default(),
    )
    .err()
    .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "key_file",
            kind: ValidationKind::EmptyPath
        }
    ));
}

#[test]
fn two_different_valid_keys_produce_different_outputs() {
    // Anti-constant control: two DIFFERENT valid RFC 8032 keys must
    // produce DIFFERENT exact 32-byte outputs.
    let cfg1 = ClientConfig::from_text(
        &format!("server: {RFC8032_PUB_HEX}\n"),
        &ClientOverrides::default(),
    )
    .unwrap();
    let cfg2 = ClientConfig::from_text(
        &format!("server: {RFC8032_PUB2_HEX}\n"),
        &ClientOverrides::default(),
    )
    .unwrap();
    assert_ne!(cfg1.server_key_bytes(), cfg2.server_key_bytes());
    assert_eq!(cfg1.server_key_bytes(), &RFC8032_PUB);
    assert_eq!(cfg2.server_key_bytes(), &RFC8032_PUB2);
    assert_eq!(RFC8032_PUB.len(), 32);
    assert_eq!(RFC8032_PUB2.len(), 32);
}

#[test]
fn invalid_edwards_point_rejected_by_real_upstream_parser() {
    // 64 hex chars decode cleanly; rejection happens at point
    // decompression inside iroh-base's FromStr path.
    assert_eq!(INVALID_POINT_HEX.len(), 64);
    let file = format!("server: {INVALID_POINT_HEX}\n");
    let err = ClientConfig::from_text(&file, &ClientOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "server",
            kind: ValidationKind::InvalidKey
        }
    ));
    assert_redacted(&err, &[&INVALID_POINT_HEX[..12]]);
}

#[test]
fn invalid_keys_rejected_with_real_parser() {
    // Uppercase hex fails the lowercase-hex decode (HEXLOWER).
    let file = format!("server: {}\n", RFC8032_PUB_HEX.to_uppercase());
    let err = ClientConfig::from_text(&file, &ClientOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "server",
            kind: ValidationKind::InvalidKey
        }
    ));
    assert_redacted(&err, &[&RFC8032_PUB_HEX[..10]]);

    // Wrong length: 63 hex chars fall into the base32 branch and fail.
    let short = &RFC8032_PUB_HEX[..63];
    let file = format!("server: {short}\n");
    let err = ClientConfig::from_text(&file, &ClientOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "server",
            kind: ValidationKind::InvalidKey
        }
    ));
    assert_redacted(&err, &[&short[..10]]);

    // Non-encoding characters.
    let sentinel = "zzzz";
    let file = format!("server: {}\n", sentinel.repeat(16));
    let err = ClientConfig::from_text(&file, &ClientOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "server",
            kind: ValidationKind::InvalidKey
        }
    ));
    assert_redacted(&err, &[sentinel]);
}

#[test]
fn redaction_sentinels_in_malformed_and_unknown_input() {
    // Malformed syntax carrying a sentinel fragment of the input.
    let sentinel = "zz_sentinel_body_zz";
    let file = format!("target:{sentinel}\n");
    let err = ServerConfig::from_text(&file, &ServerOverrides::default())
        .err()
        .unwrap();
    assert_redacted(&err, &[sentinel]);

    // Unknown field carrying a sentinel name.
    let sentinel2 = "zz_sentinel_field_zz";
    let file = format!("target: 127.0.0.1:9000\n{sentinel2}: v\n");
    let err = ServerConfig::from_text(&file, &ServerOverrides::default())
        .err()
        .unwrap();
    assert_redacted(&err, &[sentinel2]);

    // Invalid KNOWN enum value carrying a sentinel body.
    let sentinel3 = "zz_sentinel_enum_zz";
    let file = format!("target: 127.0.0.1:9000\nfallback: {sentinel3}\n");
    let err = ServerConfig::from_text(&file, &ServerOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "fallback",
            ..
        }
    ));
    assert_redacted(&err, &[sentinel3]);
}

#[test]
fn loading_error_carries_numeric_location_only() {
    // Parsing errors keep only the static class and safe numbers.
    let p = ConfigError::Parsing {
        kind: "syntax",
        line: Some(3),
        offset: Some(17),
    };
    let d = p.to_string();
    assert!(d.contains("line 3") && d.contains("offset 17"));
    assert_eq!(p.line(), Some(3));

    // Loading error must not leak the file path or OS message.
    let l = ConfigError::Loading {
        path: PathBuf::from("/home/user/zz_secret_name.ktav"),
        kind: shaar::config::LoadKind::Io,
    };
    assert_redacted(&l, &["zz_secret_name", "/home/user"]);

    // The in-memory size bound reports an empty path.
    let big = "#".repeat(MAX_CONFIG_BYTES + 1);
    let err = ServerConfig::from_text(&big, &ServerOverrides::default())
        .err()
        .unwrap();
    assert!(matches!(
        err,
        ConfigError::Loading {
            kind: shaar::config::LoadKind::TooLarge,
            ..
        }
    ));
    assert_eq!(big.len(), MAX_CONFIG_BYTES + 1);
    let err = ClientConfig::from_text(&big, &ClientOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Loading {
            kind: shaar::config::LoadKind::TooLarge,
            ..
        }
    ));
}

#[test]
fn server_requires_target() {
    let err = ServerConfig::from_text("", &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "target",
            kind: ValidationKind::MissingRequired
        }
    ));
}

#[test]
fn client_requires_server() {
    let err = ClientConfig::from_text("", &ClientOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "server",
            kind: ValidationKind::MissingRequired
        }
    ));
}

#[test]
fn server_defaults_apply() {
    let cfg =
        ServerConfig::from_text("target: 127.0.0.1:80\n", &ServerOverrides::default()).unwrap();
    assert_eq!(cfg.key_file(), Path::new("shaar.key"));
    assert_eq!(cfg.allowlist_path(), Path::new("allowed.txt"));
    assert_eq!(cfg.fallback(), Fallback::Standby);
}

#[test]
fn client_defaults_apply() {
    let cfg = ClientConfig::from_text(
        &format!("server: {RFC8032_PUB_HEX}\n"),
        &ClientOverrides::default(),
    )
    .unwrap();
    assert_eq!(cfg.server_key_bytes(), &RFC8032_PUB);
    assert_eq!(cfg.listen().to_string(), "127.0.0.1:2222");
    assert_eq!(cfg.key_file(), Path::new("shaar.key"));
    assert_eq!(cfg.fallback(), Fallback::Standby);
}

#[test]
fn pure_apis_accept_exact_byte_bound() {
    let mut server = String::from("target: 127.0.0.1:80\n");
    server.extend(std::iter::repeat_n('\n', MAX_CONFIG_BYTES - server.len()));
    assert_eq!(server.len(), MAX_CONFIG_BYTES);
    assert!(ServerConfig::from_text(&server, &ServerOverrides::default()).is_ok());
    let mut client = format!("server: {RFC8032_PUB_HEX}\n");
    client.extend(std::iter::repeat_n('\n', MAX_CONFIG_BYTES - client.len()));
    assert_eq!(client.len(), MAX_CONFIG_BYTES);
    assert!(ClientConfig::from_text(&client, &ClientOverrides::default()).is_ok());
}
