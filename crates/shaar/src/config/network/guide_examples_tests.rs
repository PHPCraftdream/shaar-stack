//! The example configurations of `docs/guide/` are loaded verbatim, and the
//! validation messages quoted by `docs/guide/configuration.md` are produced
//! from them by single-field mutations.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;

use crate::config::{
    ClientConfig, ClientOverrides, Fallback, MAX_CONFIG_BYTES, NetworkSettings, ServerConfig,
    ServerOverrides,
};

const SERVER_DIRECT: &str = include_str!("../../../../../docs/guide/examples/server-direct.ktav");
const CLIENT_DIRECT: &str = include_str!("../../../../../docs/guide/examples/client-direct.ktav");
const SERVER_COMPOSED: &str =
    include_str!("../../../../../docs/guide/examples/server-composed.ktav");
const CLIENT_COMPOSED: &str =
    include_str!("../../../../../docs/guide/examples/client-composed.ktav");

// RFC 8032 section 7.1 test-vector 1 public key used by the examples.
const SERVER_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const SERVER_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RELAY_ID: &str = "12D3KooWRhxsqdyvN1Cy4HDzPjKtdscPa9XUyqoqJwHSsGY8LQTQ";

fn server(text: &str) -> ServerConfig {
    ServerConfig::from_text(text, &ServerOverrides::default()).expect("server example parses")
}

fn client(text: &str) -> ClientConfig {
    ClientConfig::from_text(text, &ClientOverrides::default()).expect("client example parses")
}

fn replaced(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "example no longer contains {from:?}");
    text.replacen(from, to, 1)
}

fn server_error(text: &str) -> String {
    ServerConfig::from_text(text, &ServerOverrides::default())
        .unwrap_err()
        .to_string()
}

fn client_error(text: &str) -> String {
    ClientConfig::from_text(text, &ClientOverrides::default())
        .unwrap_err()
        .to_string()
}

fn invalid(field: &str, kind: &str) -> String {
    format!("invalid configuration value for field `{field}` ({kind})")
}

fn assert_composed_network(network: &NetworkSettings) {
    let mainline = network.mainline().expect("mainline section");
    assert_eq!(
        mainline.bind(),
        "0.0.0.0:0".parse::<SocketAddrV4>().unwrap()
    );
    let bootstrap: Vec<String> = mainline.bootstrap().iter().map(|a| a.to_string()).collect();
    assert_eq!(bootstrap, ["192.0.2.10:6881", "192.0.2.11:6881"]);
    let signaling = network.signaling().expect("signaling section");
    assert_eq!(signaling.bind(), "0.0.0.0:0".parse::<SocketAddr>().unwrap());
    assert_eq!(signaling.relay_peer_id().to_string(), RELAY_ID);
    assert_eq!(
        signaling.relay_address(),
        "192.0.2.20:4001".parse::<SocketAddr>().unwrap()
    );
    let ygg = network.ygg().expect("ygg section");
    assert_eq!(
        ygg.peers(),
        ["tcp://192.0.2.30:1514", "tls://192.0.2.31:1515"]
    );
}

#[test]
fn direct_server_example_parses_with_documented_values() {
    let config = server(SERVER_DIRECT);
    assert_eq!(config.target().to_string(), "127.0.0.1:8080");
    assert_eq!(config.bind().to_string(), "0.0.0.0:0");
    assert_eq!(config.key_file(), Path::new("server.key"));
    assert_eq!(config.allowlist_path(), Path::new("allowed.txt"));
    assert_eq!(config.fallback(), Fallback::Signal);
    assert!(config.network().is_none());
}

#[test]
fn direct_client_example_parses_with_documented_values() {
    let config = client(CLIENT_DIRECT);
    assert_eq!(config.server_key_bytes(), &SERVER_KEY);
    assert_eq!(
        config.server_address(),
        Some("198.51.100.8:49152".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(config.listen().to_string(), "127.0.0.1:2222");
    assert_eq!(config.key_file(), Path::new("client.key"));
    assert_eq!(config.fallback(), Fallback::Signal);
    assert!(config.network().is_none());
}

#[test]
fn composed_server_example_parses_with_documented_values() {
    let config = server(SERVER_COMPOSED);
    assert_eq!(config.target().to_string(), "127.0.0.1:8080");
    assert_eq!(config.key_file(), Path::new("server.key"));
    assert_eq!(config.fallback(), Fallback::Standby);
    assert_composed_network(config.network().expect("network object"));
}

#[test]
fn composed_client_example_parses_with_documented_values() {
    let config = client(CLIENT_COMPOSED);
    assert_eq!(config.server_key_bytes(), &SERVER_KEY);
    assert_eq!(config.server_address(), None, "key-only client");
    assert_eq!(config.listen().to_string(), "127.0.0.1:2222");
    assert_eq!(config.fallback(), Fallback::Standby);
    assert_composed_network(config.network().expect("network object"));
}

#[test]
fn documented_defaults_apply_to_minimal_files() {
    let config = server("target: 127.0.0.1:8080\n");
    assert_eq!(config.bind().to_string(), "0.0.0.0:0");
    assert_eq!(config.key_file(), Path::new("shaar.key"));
    assert_eq!(config.allowlist_path(), Path::new("allowed.txt"));
    assert_eq!(config.fallback(), Fallback::Standby);
    assert!(config.network().is_none());

    let config = client(&format!("server: {SERVER_KEY_HEX}\n"));
    assert_eq!(config.listen().to_string(), "127.0.0.1:2222");
    assert_eq!(config.server_address(), None);
    assert_eq!(config.key_file(), Path::new("shaar.key"));
    assert_eq!(config.fallback(), Fallback::Standby);
    assert!(config.network().is_none());
}

#[test]
fn documented_server_validation_messages() {
    let cases = [
        (
            "target: 127.0.0.1:8080",
            "target: 192.0.2.1:8080",
            invalid("target", "NotLoopback"),
        ),
        (
            "target: 127.0.0.1:8080",
            "target: 127.0.0.1:0",
            invalid("target", "InvalidPort"),
        ),
        (
            "target: 127.0.0.1:8080",
            "target: localhost:8080",
            invalid("target", "InvalidAddress"),
        ),
        (
            "bind: 0.0.0.0:0",
            "bind: not-an-address",
            invalid("bind", "InvalidAddress"),
        ),
        (
            "fallback: signal",
            "fallback: bogus",
            invalid("fallback", "InvalidEnum"),
        ),
        (
            "key_file:: server.key",
            "key_file: ",
            invalid("key_file", "EmptyPath"),
        ),
        (
            "allowlist_path:: allowed.txt",
            "allowlist_path: ",
            invalid("allowlist_path", "EmptyPath"),
        ),
    ];
    for (from, to, expected) in cases {
        assert_eq!(
            server_error(&replaced(SERVER_DIRECT, from, to)),
            expected,
            "{to}"
        );
    }
    let without_target = replaced(SERVER_DIRECT, "target: 127.0.0.1:8080\n", "");
    assert_eq!(
        server_error(&without_target),
        invalid("target", "MissingRequired")
    );
}

#[test]
fn documented_client_validation_messages() {
    let key_line = format!("server: {SERVER_KEY_HEX}");
    let cases = [
        (
            key_line.as_str(),
            "server: not-a-key",
            invalid("server", "InvalidKey"),
        ),
        (
            "listen: 127.0.0.1:2222",
            "listen: 192.0.2.1:2222",
            invalid("listen", "NotLoopback"),
        ),
        (
            "listen: 127.0.0.1:2222",
            "listen: nope",
            invalid("listen", "InvalidAddress"),
        ),
        (
            "198.51.100.8:49152",
            "0.0.0.0:49152",
            invalid("server_address", "InvalidAddress"),
        ),
        (
            "198.51.100.8:49152",
            "198.51.100.8:0",
            invalid("server_address", "InvalidAddress"),
        ),
        (
            "198.51.100.8:49152",
            "224.0.0.1:49152",
            invalid("server_address", "InvalidAddress"),
        ),
        (
            "198.51.100.8:49152",
            "example.org:49152",
            invalid("server_address", "InvalidAddress"),
        ),
        (
            "server_address: 198.51.100.8:49152",
            "server_address:: [fd15:70a:510b::1]:49152",
            invalid("server_address", "InvalidAddress"),
        ),
        (
            "fallback: signal",
            "fallback: Standby",
            invalid("fallback", "InvalidEnum"),
        ),
    ];
    for (from, to, expected) in cases {
        assert_eq!(
            client_error(&replaced(CLIENT_DIRECT, from, to)),
            expected,
            "{to}"
        );
    }
    let without_key = replaced(CLIENT_DIRECT, &format!("{key_line}\n"), "");
    assert_eq!(
        client_error(&without_key),
        invalid("server", "MissingRequired")
    );
}

#[test]
fn documented_network_validation_messages() {
    let many = "192.0.2.11:6881\n            192.0.2.12:6881\n            192.0.2.13:6881\n            192.0.2.14:6881\n            192.0.2.15:6881\n";
    let bootstrap = "network.mainline.bootstrap";
    let cases = [
        (
            "bootstrap: [\n            192.0.2.10:6881\n            192.0.2.11:6881\n        ]",
            "bootstrap: []",
            invalid(bootstrap, "TooFew"),
        ),
        ("192.0.2.11:6881\n", many, invalid(bootstrap, "TooMany")),
        (
            "192.0.2.10:6881",
            "192.0.2.10:0",
            invalid(bootstrap, "InvalidPort"),
        ),
        (
            "192.0.2.10:6881",
            "0.0.0.0:6881",
            invalid(bootstrap, "InvalidAddress"),
        ),
        (
            "192.0.2.10:6881",
            "dht.example.org:6881",
            invalid(bootstrap, "InvalidAddress"),
        ),
        (
            "relay: 12D3",
            "relay: 0OIl12D3",
            invalid("network.signaling.relay", "InvalidKey"),
        ),
        (
            "192.0.2.20:4001",
            "0.0.0.0:4001",
            invalid("network.signaling.relay_address", "InvalidAddress"),
        ),
        (
            "tcp://192.0.2.30:1514",
            "udp://192.0.2.30:1514",
            invalid("network.ygg.peers", "InvalidUri"),
        ),
        (
            "tcp://192.0.2.30:1514",
            "tcp://192.0.2.30",
            invalid("network.ygg.peers", "InvalidUri"),
        ),
        (
            "tcp://192.0.2.30:1514",
            "tcp://192.0.2.30:0",
            invalid("network.ygg.peers", "InvalidUri"),
        ),
    ];
    for (from, to, expected) in cases {
        let text = replaced(SERVER_COMPOSED, from, to);
        assert_eq!(server_error(&text), expected, "{to}");
        let text = replaced(CLIENT_COMPOSED, from, to);
        assert_eq!(client_error(&text), expected, "{to}");
    }
}

#[test]
fn network_sections_are_all_required_and_report_the_first_missing_one() {
    let signaling_start = SERVER_COMPOSED.find("    signaling: {").unwrap();
    let ygg_start = SERVER_COMPOSED.find("    ygg: {").unwrap();
    let end = SERVER_COMPOSED.rfind("}\n").unwrap();
    let without_signaling = format!(
        "{}{}}}\n",
        &SERVER_COMPOSED[..signaling_start],
        &SERVER_COMPOSED[ygg_start..end]
    );
    assert_eq!(
        server_error(&without_signaling),
        invalid("network.signaling", "MissingRequired")
    );
    let without_ygg = format!("{}}}\n", &SERVER_COMPOSED[..ygg_start]);
    assert_eq!(
        server_error(&without_ygg),
        invalid("network.ygg", "MissingRequired")
    );
}

#[test]
fn documented_parse_and_size_errors() {
    for message in [
        server_error(&format!("{SERVER_DIRECT}colour: red\n")),
        client_error(&format!("{CLIENT_DIRECT}colour: red\n")),
    ] {
        assert!(
            message.starts_with("configuration parse error (schema"),
            "{message}"
        );
        assert!(
            !message.contains("colour"),
            "unknown field names are not echoed"
        );
    }
    let oversized = "#".repeat(MAX_CONFIG_BYTES + 1);
    assert_eq!(
        server_error(&oversized),
        "configuration file loading failed (TooLarge)"
    );
    assert_eq!(
        client_error(&oversized),
        "configuration file loading failed (TooLarge)"
    );
}
