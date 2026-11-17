//! Configuration edits: one key changes, every comment survives, an invalid result is refused.

use super::*;
use crate::config::{ConfigError, ValidationKind};

const SERVER: &str = "## Sha'ar Server configuration\n## keep me\ntarget: 127.0.0.1:8080\nkey_file:: server.key\nallowlist_path:: allowed.txt\n";
const CLIENT: &str = "## client file\nserver:: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\nserver_address:: 198.51.100.8:49152\nkey_file:: shaar.key\n";

fn invalid(error: ConfigEditError) -> (&'static str, ValidationKind) {
    match error {
        ConfigEditError::Invalid(ConfigError::Validation { field, kind }) => (field, kind),
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

#[test]
fn setting_a_value_replaces_it_and_keeps_the_comments() {
    let edited = set_config_value(Role::Server, SERVER, "target", "127.0.0.1:9000").unwrap();
    assert!(edited.contains("## keep me"));
    assert!(edited.contains("target:: 127.0.0.1:9000"));
    assert!(!edited.contains("8080"));
    assert!(edited.contains("key_file") && edited.contains("allowlist_path"));
    check_config_text(Role::Server, &edited, true).unwrap();
}

#[test]
fn setting_an_absent_key_appends_it_once() {
    let edited = set_config_value(Role::Server, SERVER, "fallback", "signal").unwrap();
    assert_eq!(edited.matches("fallback").count(), 1);
    assert!(edited.contains("fallback:: signal"));
    // Setting it again changes the same line.
    let again = set_config_value(Role::Server, &edited, "fallback", "standby").unwrap();
    assert_eq!(again.matches("fallback").count(), 1);
    assert!(again.contains("fallback:: standby"));
}

#[test]
fn a_file_without_its_required_value_can_be_edited_step_by_step() {
    let fresh = "## generated\nkey_file:: server.key\nallowlist_path:: allowed.txt\n";
    assert!(check_config_text(Role::Server, fresh, true).is_err());
    assert!(check_config_text(Role::Server, fresh, false).is_ok());
    let with_bind = set_config_value(Role::Server, fresh, "bind", "127.0.0.1:7000").unwrap();
    assert!(with_bind.contains("bind:: 127.0.0.1:7000"));
    let with_target =
        set_config_value(Role::Server, &with_bind, "target", "127.0.0.1:8080").unwrap();
    check_config_text(Role::Server, &with_target, true).unwrap();
    let keyless = "## client\nkey_file:: shaar.key\n";
    assert!(check_config_text(Role::Client, keyless, true).is_err());
    let edited = set_config_value(
        Role::Client,
        keyless,
        "server",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    )
    .unwrap();
    check_config_text(Role::Client, &edited, false).unwrap();
}

fn refused(result: Result<(), ConfigError>) -> (&'static str, ValidationKind) {
    match result {
        Err(ConfigError::Validation { field, kind }) => (field, kind),
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

fn composed_server() -> String {
    set_config_network(Role::Server, SERVER, NetworkChoice::Public).unwrap()
}

#[test]
fn the_encrypted_pair_can_be_set_in_either_order_and_the_strict_check_wants_both() {
    let base = composed_server();
    let mode = set_config_value(Role::Server, &base, "publish_address", "encrypted").unwrap();
    assert_eq!(
        refused(check_config_text(Role::Server, &mode, true)),
        ("address_key_file", ValidationKind::MissingRequired)
    );
    let both =
        set_config_value(Role::Server, &mode, "address_key_file", "/keys/address.key").unwrap();
    check_config_text(Role::Server, &both, true).unwrap();

    let key =
        set_config_value(Role::Server, &base, "address_key_file", "/keys/address.key").unwrap();
    assert_eq!(
        refused(check_config_text(Role::Server, &key, true)),
        ("address_key_file", ValidationKind::NotApplicable)
    );
    let other_order = set_config_value(Role::Server, &key, "publish_address", "encrypted").unwrap();
    check_config_text(Role::Server, &other_order, true).unwrap();
    assert!(other_order.contains("## keep me"));
    assert_eq!(other_order.matches("address_key_file").count(), 1);
}

#[test]
fn a_half_set_pair_does_not_hide_other_invalid_values() {
    let base = composed_server();
    let half = set_config_value(Role::Server, &base, "publish_address", "encrypted").unwrap();
    let bad_target = set_config_value(Role::Server, &half, "target", "8.8.8.8:80").unwrap_err();
    assert_eq!(invalid(bad_target), ("target", ValidationKind::NotLoopback));
    let misspelt =
        set_config_value(Role::Server, &base, "publish_address", "Encrypted").unwrap_err();
    assert_eq!(
        invalid(misspelt),
        ("publish_address", ValidationKind::InvalidEnum)
    );
}

#[test]
fn unsetting_one_half_of_the_pair_is_allowed_and_the_strict_check_still_refuses_it() {
    let base = composed_server();
    let mode = set_config_value(Role::Server, &base, "publish_address", "encrypted").unwrap();
    let both =
        set_config_value(Role::Server, &mode, "address_key_file", "/keys/address.key").unwrap();
    let without_mode = unset_config_key(Role::Server, &both, "publish_address").unwrap();
    assert_eq!(
        refused(check_config_text(Role::Server, &without_mode, true)),
        ("address_key_file", ValidationKind::NotApplicable)
    );
    let clean = unset_config_key(Role::Server, &without_mode, "address_key_file").unwrap();
    check_config_text(Role::Server, &clean, true).unwrap();
}

#[test]
fn a_client_key_file_without_a_network_object_stays_refused() {
    let error = set_config_value(
        Role::Client,
        CLIENT,
        "address_key_file",
        "/keys/address.key",
    )
    .unwrap_err();
    assert_eq!(
        invalid(error),
        ("address_key_file", ValidationKind::NotApplicable)
    );
}

#[test]
fn an_invalid_result_is_refused_with_the_field_and_kind() {
    assert_eq!(
        invalid(set_config_value(Role::Server, SERVER, "target", "192.0.2.1:80").unwrap_err()),
        ("target", ValidationKind::NotLoopback)
    );
    assert_eq!(
        invalid(set_config_value(Role::Server, SERVER, "fallback", "bogus").unwrap_err()),
        ("fallback", ValidationKind::InvalidEnum)
    );
    assert_eq!(
        invalid(set_config_value(Role::Server, SERVER, "publish_address", "sealed").unwrap_err()),
        ("publish_address", ValidationKind::InvalidEnum)
    );
    assert_eq!(
        invalid(set_config_value(Role::Client, CLIENT, "listen", "192.0.2.1:2222").unwrap_err()),
        ("listen", ValidationKind::NotLoopback)
    );
    assert_eq!(
        invalid(set_config_value(Role::Client, CLIENT, "server", "not a key").unwrap_err()),
        ("server", ValidationKind::InvalidKey)
    );
}

#[test]
fn unknown_keys_and_control_characters_are_refused_before_any_change() {
    assert!(matches!(
        set_config_value(Role::Server, SERVER, "network", "x"),
        Err(ConfigEditError::UnknownKey)
    ));
    assert!(matches!(
        set_config_value(Role::Server, SERVER, "listen", "127.0.0.1:1"),
        Err(ConfigEditError::UnknownKey)
    ));
    assert!(matches!(
        set_config_value(Role::Client, CLIENT, "target", "127.0.0.1:1"),
        Err(ConfigEditError::UnknownKey)
    ));
    assert!(matches!(
        set_config_value(Role::Server, SERVER, "target", "127.0.0.1:1\nfallback: x"),
        Err(ConfigEditError::ControlCharacter)
    ));
    assert!(matches!(
        unset_config_key(Role::Server, SERVER, "nope"),
        Err(ConfigEditError::UnknownKey)
    ));
    assert!(matches!(
        set_config_value(Role::Server, "target: {", "bind", "127.0.0.1:1"),
        Err(ConfigEditError::Syntax)
    ));
    assert!(editable_keys(Role::Server).contains(&"publish_address"));
    assert!(editable_keys(Role::Client).contains(&"server_address"));
}

#[test]
fn unsetting_removes_the_entry_and_is_idempotent() {
    let with_address = set_config_value(Role::Client, CLIENT, "listen", "127.0.0.1:3000").unwrap();
    assert!(with_address.contains("listen:: 127.0.0.1:3000"));
    let without = unset_config_key(Role::Client, &with_address, "listen").unwrap();
    assert!(!without.contains("listen"));
    assert!(without.contains("## client file") && without.contains("server_address"));
    let again = unset_config_key(Role::Client, &without, "listen").unwrap();
    assert_eq!(again, without);
    // A required key may be removed while editing; the strict check then names it.
    let keyless = unset_config_key(Role::Client, CLIENT, "server").unwrap();
    assert!(matches!(
        check_config_text(Role::Client, &keyless, true),
        Err(ConfigError::Validation {
            field: "server",
            kind: ValidationKind::MissingRequired
        })
    ));
}

#[test]
fn the_network_shape_switches_between_public_and_private() {
    let public = set_config_network(Role::Server, SERVER, NetworkChoice::Public).unwrap();
    assert!(public.contains("network: {") && public.contains("dht.libtorrent.org:25401"));
    assert!(public.contains("## keep me"));
    let parsed = crate::config::ServerConfig::from_text(&public, &Default::default()).unwrap();
    assert!(parsed.network().is_some());
    // Switching to public twice leaves one network object.
    let twice = set_config_network(Role::Server, &public, NetworkChoice::Public).unwrap();
    assert_eq!(twice.matches("network: {").count(), 1);
    let private = set_config_network(Role::Server, &twice, NetworkChoice::Private).unwrap();
    assert!(!private.contains("network"));
    assert!(private.contains("target") && private.contains("## keep me"));
    // A key edit keeps a network object that is already there.
    let kept = set_config_value(Role::Server, &public, "fallback", "signal").unwrap();
    assert!(kept.contains("network: {") && kept.contains("fallback:: signal"));
    // The composed shape refuses an explicit bind, so the edit is refused as a file would be.
    let bound = set_config_value(Role::Server, &public, "bind", "127.0.0.1:7000").unwrap_err();
    assert_eq!(invalid(bound), ("bind", ValidationKind::NotApplicable));
}

#[tokio::test]
async fn writing_replaces_the_file_atomically_and_keeps_one_backup() {
    let dir = std::env::current_dir()
        .unwrap()
        .join("target/provision-admin-fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("edit-{}.ktav", std::process::id()));
    let _ = std::fs::remove_file(&path);
    write_replacing(&path, "one\n".to_owned(), true)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\n");
    let backup = dir.join(format!("edit-{}.ktav.bak", std::process::id()));
    assert!(!backup.exists(), "nothing to back up on the first write");
    write_replacing(&path, "two\n".to_owned(), true)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), "one\n");
    write_replacing(&path, "three\n".to_owned(), false)
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), "one\n");
    assert!(
        !dir.join(format!("edit-{}.ktav.tmp", std::process::id()))
            .exists()
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&backup);
}

fn fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::current_dir()
        .unwrap()
        .join("target/provision-admin-fixtures")
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn the_config_command_shows_edits_and_checks_a_server_file() {
    let dir = fixture("command");
    let key = dir.join("server.key");
    let identity = crate::identity::Identity::create_new(&key).await.unwrap();
    let allowed = dir.join("allowed.txt");
    std::fs::write(&allowed, "# nobody yet\n").unwrap();
    let path = dir.join("server.ktav");
    let text = format!(
        "## keep\nkey_file:: {}\nallowlist_path:: {}\n",
        key.display(),
        allowed.display()
    );
    std::fs::write(&path, &text).unwrap();

    let shown = config_command(Role::Server, &path, ConfigAction::Show)
        .await
        .unwrap();
    assert_eq!(shown.join("\n") + "\n", text);
    // Not yet startable: the strict check names the missing target.
    let missing = config_command(Role::Server, &path, ConfigAction::Check)
        .await
        .unwrap_err();
    assert!(missing.contains("target"), "{missing}");

    let set = ConfigAction::Set {
        key: "target".to_owned(),
        value: "127.0.0.1:8080".to_owned(),
    };
    let done = config_command(Role::Server, &path, set.clone())
        .await
        .unwrap();
    assert!(
        done[0].starts_with("updated: ") && done[1].contains(".bak"),
        "{done:?}"
    );
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("target:: 127.0.0.1:8080")
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("server.ktav.bak")).unwrap(),
        text
    );
    let again = config_command(Role::Server, &path, set).await.unwrap();
    assert!(again[0].starts_with("unchanged: "), "{again:?}");

    let checked = config_command(Role::Server, &path, ConfigAction::Check)
        .await
        .unwrap();
    assert!(checked[0].starts_with("ok: "));
    assert_eq!(
        checked[1],
        format!(
            "public_key={}",
            crate::startup::facade::PeerKey::of(&identity)
        )
    );
    let refused = config_command(
        Role::Server,
        &path,
        ConfigAction::Set {
            key: "target".to_owned(),
            value: "192.0.2.1:80".to_owned(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        refused.starts_with("target: ") && refused.contains("NotLoopback"),
        "{refused}"
    );
    let network = config_command(
        Role::Server,
        &path,
        ConfigAction::Network(NetworkChoice::Public),
    )
    .await
    .unwrap();
    assert!(network[0].starts_with("updated: "));
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("dht.libtorrent.org")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_config_command_reports_a_missing_file_a_missing_key_and_an_oversized_file() {
    let dir = fixture("errors");
    let missing = config_command(Role::Client, &dir.join("none.ktav"), ConfigAction::Show)
        .await
        .unwrap_err();
    assert_eq!(missing, "could not read the configuration");
    let path = dir.join("client.ktav");
    std::fs::write(
        &path,
        "server:: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\nkey_file:: absent.key\n",
    )
    .unwrap();
    let unloadable = config_command(Role::Client, &path, ConfigAction::Check)
        .await
        .unwrap_err();
    assert_eq!(unloadable, "could not load configured identity key");
    std::fs::write(&path, "#".repeat(crate::config::MAX_CONFIG_BYTES + 1)).unwrap();
    let big = config_command(Role::Client, &path, ConfigAction::Show)
        .await
        .unwrap_err();
    assert_eq!(big, "configuration exceeds size limit");
    let _ = std::fs::remove_dir_all(&dir);
}
