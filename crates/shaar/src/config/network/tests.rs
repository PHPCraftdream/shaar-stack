//! Regression tests for the shared `network` settings schema (both roles).
//!
//! Oracles follow `tests/config.rs`: exact field strings and validation
//! kinds, plus Display/Debug redaction checks. All values are RFC 5737 /
//! RFC 8032 fixtures; nothing binds ports, touches the clock, or the
//! filesystem.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;

use libp2p_identity::PeerId;

use crate::config::{
    ClientConfig, ClientOverrides, ConfigError, Fallback, NetworkSettings, ServerConfig,
    ServerOverrides, ValidationKind,
};

// RFC 8032 § 7.1 test-vector 1 Ed25519 public key.
const RFC8032_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// `mainline` section without an explicit bind (defaults to 0.0.0.0:0).
const MAINLINE_DEFAULT: &str = "    mainline: {\n        bootstrap: [\n            192.0.2.10:6881\n            192.0.2.11:6881\n        ]\n    }\n";
/// `ygg` section with two supported peer URIs.
const YGG_TWO_PEERS: &str = "    ygg: {\n        peers: [\n            tcp://127.0.0.1:9001\n            tls://127.0.0.1:9002\n        ]\n    }\n";

fn assert_redacted(err: &ConfigError, forbidden: &[&str]) {
    assert!(
        !forbidden.is_empty(),
        "redaction check with an empty forbidden list is vacuous"
    );
    let display = err.to_string();
    let debug = format!("{err:?}");
    for f in forbidden {
        assert!(!display.contains(f), "Display leaked {f:?}: {display}");
        assert!(!debug.contains(f), "Debug leaked {f:?}: {debug}");
    }
}

/// Derive a real base58btc PeerId text via the upstream encoder; never
/// hand-write a base58 literal.
fn relay_peer_id_text() -> String {
    let mut mh = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    mh.extend_from_slice(&RFC8032_PUB);
    PeerId::from_bytes(&mh)
        .expect("valid identity multihash")
        .to_string()
}

/// Same bytes as [`relay_peer_id_text`], for the equality oracle.
fn relay_peer_id() -> PeerId {
    let mut mh = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    mh.extend_from_slice(&RFC8032_PUB);
    PeerId::from_bytes(&mh).expect("valid identity multihash")
}

/// Assemble a server config text from preformatted section blocks.
fn network_text(mainline: &str, signaling: &str, ygg: &str) -> String {
    format!("target: 127.0.0.1:9000\nnetwork: {{\n{mainline}{signaling}{ygg}}}\n")
}

/// Assemble a client config text from preformatted section blocks.
fn client_network_text(mainline: &str, signaling: &str, ygg: &str) -> String {
    format!("server: {RFC8032_PUB_HEX}\nnetwork: {{\n{mainline}{signaling}{ygg}}}\n")
}

fn signaling_with_relay(bind_line: Option<&str>) -> String {
    let relay = relay_peer_id_text();
    let mut s = String::from("    signaling: {\n");
    if let Some(b) = bind_line {
        s.push_str(b);
    }
    s.push_str(&format!("        relay: {relay}\n"));
    s.push_str("        relay_address: 192.0.2.20:7000\n    }\n");
    s
}

fn assert_shared(network: &NetworkSettings) {
    let ml = network.mainline().expect("mainline always present");
    assert_eq!(
        ml.bind(),
        SocketAddrV4::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 0)
    );
    assert_eq!(
        ml.bootstrap(),
        [
            SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 10), 6881),
            SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 11), 6881)
        ]
    );
    let sig = network.signaling().expect("signaling always present");
    assert_eq!(
        sig.bind(),
        SocketAddr::from(([0, 0, 0, 0], 0)),
        "default signaling bind"
    );
    assert_eq!(sig.relay_peer_id(), &relay_peer_id());
    assert_eq!(
        sig.relay_address(),
        SocketAddr::from(([192, 0, 2, 20], 7000))
    );
    let y = network.ygg().expect("ygg always present");
    assert_eq!(
        y.peers(),
        [
            "tcp://127.0.0.1:9001".to_string(),
            "tls://127.0.0.1:9002".to_string()
        ]
    );
}

#[test]
fn full_network_object_parses_for_server() {
    let text = network_text(MAINLINE_DEFAULT, &signaling_with_relay(None), YGG_TWO_PEERS);
    let cfg = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap();
    let network = cfg.network().expect("network object present");
    assert_shared(network);

    // Explicit binds: an IPv6 value starting with `[` needs the `::`
    // literal-string marker (ktav 0.8 pinned syntax).
    let mainline = "    mainline: {\n        bind: 192.0.2.5:30000\n        bootstrap: [\n            192.0.2.10:6881\n            192.0.2.11:6881\n        ]\n    }\n";
    let text = network_text(
        mainline,
        &signaling_with_relay(Some("        bind:: [::1]:0\n")),
        YGG_TWO_PEERS,
    );
    let cfg = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap();
    let network = cfg.network().unwrap();
    let ml = network.mainline().unwrap();
    assert_eq!(
        ml.bind(),
        SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 5), 30000)
    );
    let sig = network.signaling().unwrap();
    assert_eq!(
        sig.bind(),
        "[::1]:0"
            .parse::<SocketAddr>()
            .expect("static IPv6 literal")
    );
}

#[test]
fn full_network_object_parses_for_client() {
    let text = client_network_text(MAINLINE_DEFAULT, &signaling_with_relay(None), YGG_TWO_PEERS);
    let cfg = ClientConfig::from_text(&text, &ClientOverrides::default()).unwrap();
    let network = cfg.network().expect("network object present");
    assert_shared(network);
}

#[test]
fn legacy_text_without_network_parses_for_both_roles() {
    let server = ServerConfig::from_text("target: 127.0.0.1:9000\n", &ServerOverrides::default())
        .expect("legacy server text parses");
    assert!(
        server.network().is_none(),
        "legacy shape has no network object"
    );

    let client_text =
        format!("server: {RFC8032_PUB_HEX}\nlisten: 127.0.0.1:2300\nfallback: standby\n");
    let client = ClientConfig::from_text(&client_text, &ClientOverrides::default())
        .expect("legacy client text parses");
    assert!(
        client.network().is_none(),
        "legacy shape has no network object"
    );
}

#[test]
fn missing_sections_are_rejected_per_field() {
    // Only mainline -> the NEXT missing section (signaling) is named.
    let text = network_text(MAINLINE_DEFAULT, "", "");
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.signaling",
            kind: ValidationKind::MissingRequired
        }
    ));

    // Mainline + signaling -> ygg is named.
    let text = network_text(MAINLINE_DEFAULT, &signaling_with_relay(None), "");
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.ygg",
            kind: ValidationKind::MissingRequired
        }
    ));

    // All three sections present but empty -> the section parses, then the
    // first field check (mainline's required bootstrap) fails.
    let text = network_text("    mainline: {}\n", "    signaling: {}\n", "    ygg: {}\n");
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.mainline.bootstrap",
            kind: ValidationKind::MissingRequired
        }
    ));

    // True section-level miss: the `network` object exists but is empty,
    // so the mainline SECTION itself is the required field that is missing.
    let text = "target: 127.0.0.1:9000\nnetwork: {}\n".to_string();
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.mainline",
            kind: ValidationKind::MissingRequired
        }
    ));
}

#[test]
fn bootstrap_bounds_and_values_are_enforced() {
    const FIELD: &str = "network.mainline.bootstrap";
    let signaling = signaling_with_relay(None);
    let ygg = YGG_TWO_PEERS;

    let cases: [(String, ValidationKind); 10] = [
        // Bootstrap key entirely absent.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n    }\n".to_string(),
            ValidationKind::MissingRequired,
        ),
        // Present but empty array.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: []\n    }\n".to_string(),
            ValidationKind::TooFew,
        ),
        // Five entries exceed the 1..=4 bound.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:6881\n            192.0.2.11:6881\n            192.0.2.12:6881\n            192.0.2.13:6881\n            192.0.2.14:6881\n        ]\n    }\n".to_string(),
            ValidationKind::TooMany,
        ),
        // Missing port.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidAddress,
        ),
        // Non-numeric port.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:abc\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidAddress,
        ),
        // IPv6 entry (literal-string marker for the leading `[`).
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            :: [::1]:44\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidAddress,
        ),
        // Port 0.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:0\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidPort,
        ),
        // Wildcard address.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            0.0.0.0:53\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidAddress,
        ),
        // Multicast address.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            224.0.0.1:53\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidAddress,
        ),
        // Broadcast address.
        (
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            255.255.255.255:53\n        ]\n    }\n".to_string(),
            ValidationKind::InvalidAddress,
        ),
    ];

    for (mainline, kind) in cases {
        let text = network_text(&mainline, &signaling, ygg);
        let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Validation {
                    field: FIELD,
                    kind: _
                }
            ),
            "mainline block {mainline:?} -> {err:?} (wanted {kind:?})"
        );
        assert_eq!(kind_of(&err), Some(kind));
        // Rejected bootstrap values must never be echoed.
        assert_redacted(
            &err,
            &["192.0.2.10", "224.0.0.1", "255.255.255.255", "[::1]"],
        );
    }
}

fn kind_of(err: &ConfigError) -> Option<ValidationKind> {
    match err {
        ConfigError::Validation { kind, .. } => Some(*kind),
        _ => None,
    }
}

#[test]
fn signaling_fields_are_enforced() {
    let mainline = MAINLINE_DEFAULT;
    let ygg = YGG_TWO_PEERS;
    let relay = relay_peer_id_text();

    let make = |signaling: String| network_text(mainline, &signaling, ygg);

    // relay missing.
    let text =
        make("    signaling: {\n        relay_address: 192.0.2.20:7000\n    }\n".to_string());
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.signaling.relay",
            kind: ValidationKind::MissingRequired
        }
    ));

    // relay with characters outside the base58btc alphabet.
    let text = make(
        "    signaling: {\n        relay: not-a-peerid!!\n        relay_address: 192.0.2.20:7000\n    }\n".to_owned()
    );
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.signaling.relay",
            kind: ValidationKind::InvalidKey
        }
    ));
    assert_redacted(&err, &["not-a-peerid"]);

    // relay containing excluded base58 digits 0/O/I/l.
    let text = make(
        "    signaling: {\n        relay: 12D3KooW0OIl\n        relay_address: 192.0.2.20:7000\n    }\n"
            .to_string(),
    );
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.signaling.relay",
            kind: ValidationKind::InvalidKey
        }
    ));

    // relay_address missing (relay itself valid).
    let text = make(format!(
        "    signaling: {{\n        relay: {relay}\n    }}\n"
    ));
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.signaling.relay_address",
            kind: ValidationKind::MissingRequired
        }
    ));

    // Dial-destination contract: port 0 is InvalidAddress, not InvalidPort.
    for bad in ["192.0.2.20:0", "not-an-address", "255.255.255.255:7000"] {
        let text = make(format!(
            "    signaling: {{\n        relay: {relay}\n        relay_address: {bad}\n    }}\n"
        ));
        let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Validation {
                    field: "network.signaling.relay_address",
                    kind: ValidationKind::InvalidAddress
                }
            ),
            "relay_address {bad} -> {err:?}"
        );
        assert_redacted(&err, &[bad]);
    }
}

#[test]
fn ygg_peer_bounds_are_enforced() {
    const FIELD: &str = "network.ygg.peers";
    let signaling = signaling_with_relay(None);
    let make = |ygg: &str| network_text(MAINLINE_DEFAULT, &signaling, ygg);

    // peers missing.
    let err =
        ServerConfig::from_text(&make("    ygg: {}\n"), &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: FIELD,
            kind: ValidationKind::MissingRequired
        }
    ));

    // Empty array.
    let err = ServerConfig::from_text(
        &make("    ygg: {\n        peers: []\n    }\n"),
        &ServerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: FIELD,
            kind: ValidationKind::TooFew
        }
    ));

    // Five entries exceed the 1..=4 bound.
    let five = "    ygg: {\n        peers: [\n            tcp://127.0.0.1:9001\n            tcp://127.0.0.1:9002\n            tcp://127.0.0.1:9003\n            tcp://127.0.0.1:9004\n            tcp://127.0.0.1:9005\n        ]\n    }\n";
    let err = ServerConfig::from_text(&make(five), &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: FIELD,
            kind: ValidationKind::TooMany
        }
    ));
}

#[test]
fn four_entry_bounds_and_malformed_bind_are_handled() {
    let signaling = signaling_with_relay(None);
    // Positive four-entry boundaries on both bounded lists.
    let bootstrap_four = "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:6881\n            192.0.2.11:6881\n            192.0.2.12:6881\n            192.0.2.13:6881\n        ]\n    }\n";
    let ygg_four = "    ygg: {\n        peers: [\n            tcp://127.0.0.1:9001\n            tls://127.0.0.1:9002\n            tcp://127.0.0.1:9003\n            tls://127.0.0.1:9004\n        ]\n    }\n";
    let text = network_text(bootstrap_four, &signaling, ygg_four);
    let cfg = ServerConfig::from_text(&text, &ServerOverrides::default())
        .expect("four entries are the accepted bound");
    assert_eq!(
        cfg.network().unwrap().mainline().unwrap().bootstrap().len(),
        4
    );
    assert_eq!(cfg.network().unwrap().ygg().unwrap().peers().len(), 4);

    // A malformed mainline bind is named by its own field.
    let bad_bind = "    mainline: {\n        bind: not-an-address\n        bootstrap: [\n            192.0.2.10:6881\n        ]\n    }\n";
    let err = ServerConfig::from_text(
        &network_text(bad_bind, &signaling, YGG_TWO_PEERS),
        &ServerOverrides::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.mainline.bind",
            kind: ValidationKind::InvalidAddress
        }
    ));
}

#[test]
fn unknown_fields_are_rejected_schema_wide() {
    let signaling = signaling_with_relay(None);
    let relay = relay_peer_id_text();

    let cases = [
        // Unknown key at the `network` level, inside a complete body.
        network_text(
            MAINLINE_DEFAULT,
            &signaling,
            &format!("{YGG_TWO_PEERS}    extra: 1\n"),
        ),
        // Inside mainline.
        network_text(
            "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:6881\n            192.0.2.11:6881\n        ]\n        extra: 1\n    }\n",
            &signaling,
            YGG_TWO_PEERS,
        ),
        // Inside signaling.
        network_text(
            MAINLINE_DEFAULT,
            &format!(
                "    signaling: {{\n        relay: {relay}\n        relay_address: 192.0.2.20:7000\n        extra: 1\n    }}\n"
            ),
            YGG_TWO_PEERS,
        ),
        // Inside ygg.
        network_text(
            MAINLINE_DEFAULT,
            &signaling,
            "    ygg: {\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n        extra: 1\n    }\n",
        ),
    ];

    for text in &cases {
        let err = ServerConfig::from_text(text, &ServerOverrides::default()).unwrap_err();
        assert!(
            matches!(err, ConfigError::Parsing { kind: "schema", .. }),
            "unknown field -> {err:?}"
        );
    }
}

#[test]
fn diagnostics_never_echo_rejected_values() {
    let signaling = signaling_with_relay(None);

    // Secret-looking ygg peer URI is rejected and never echoed.
    let text = network_text(
        MAINLINE_DEFAULT,
        &signaling,
        "    ygg: {\n        peers: [\n            tcp://127.0.0.1:notaport\n        ]\n    }\n",
    );
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.ygg.peers",
            kind: ValidationKind::InvalidUri
        }
    ));
    assert_redacted(&err, &["notaport"]);

    // Rejected bootstrap entry (port 0) is never echoed either.
    let text = network_text(
        "    mainline: {\n        bind: 0.0.0.0:0\n        bootstrap: [\n            10.9.9.9:0\n        ]\n    }\n",
        &signaling,
        YGG_TWO_PEERS,
    );
    let err = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::Validation {
            field: "network.mainline.bootstrap",
            kind: ValidationKind::InvalidPort
        }
    ));
    assert_redacted(&err, &["10.9.9.9:0"]);

    // Debug of a VALID config redacts peer URIs (count only) but keeps
    // the public relay address.
    let text = network_text(MAINLINE_DEFAULT, &signaling, YGG_TWO_PEERS);
    let cfg = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap();
    let debug = format!("{cfg:?}");
    assert!(
        !debug.contains("tcp://"),
        "ygg peer URI leaked in Debug: {debug}"
    );
    assert!(
        !debug.contains("127.0.0.1:9001"),
        "ygg peer URI leaked in Debug: {debug}"
    );
    assert!(
        debug.contains("192.0.2.20:7000"),
        "public relay address must stay visible in Debug: {debug}"
    );
}

#[test]
fn overrides_and_legacy_fields_interoperate() {
    // Legacy server fields coexist with a network object in one file.
    let text = format!(
        "{}fallback: signal\nkey_file: keys/identity.key\n",
        network_text(MAINLINE_DEFAULT, &signaling_with_relay(None), YGG_TWO_PEERS)
    );
    let cfg = ServerConfig::from_text(&text, &ServerOverrides::default()).unwrap();
    assert_eq!(cfg.fallback(), Fallback::Signal);
    assert_eq!(cfg.key_file(), Path::new("keys/identity.key"));
    assert!(
        cfg.network().is_some(),
        "network object survives legacy fields"
    );

    // A client listen override wins over the file even when a network
    // object is also present.
    let text = client_network_text(MAINLINE_DEFAULT, &signaling_with_relay(None), YGG_TWO_PEERS);
    let over = ClientOverrides {
        listen: Some("127.0.0.1:2345".to_string()),
        ..Default::default()
    };
    let cfg = ClientConfig::from_text(&text, &over).unwrap();
    assert_eq!(cfg.listen().to_string(), "127.0.0.1:2345");
    assert!(cfg.network().is_some(), "network object survives overrides");
}
