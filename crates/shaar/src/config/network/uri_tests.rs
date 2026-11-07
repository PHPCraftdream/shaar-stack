//! Peer-URI grammar oracles for the shared `network.ygg.peers` setting,
//! exercised through the real `ServerConfig::from_text` path. The validator
//! uses the backend's actual URL parser with DECODED `query_pairs()` values,
//! so these oracles cover exactly that surface: percent-encoded known option
//! names, decoded invalid/valid values, valueless known keys, fragment
//! exclusion before and after `?`, UTF-8 byte password caps, malformed
//! hosts and zero ports. Accepted entries are stored raw, unchanged;
//! rejected values never reach diagnostics.

use libp2p_identity::PeerId;

use crate::config::{ConfigError, ServerConfig, ServerOverrides, ValidationKind};

// RFC 8032 § 7.1 test-vector 1 Ed25519 public key (fixture only).
const RFC8032_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Real upstream base58btc PeerId text; never a hand-written literal.
fn relay_peer_id_text() -> String {
    let mut mh = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    mh.extend_from_slice(&RFC8032_PUB);
    PeerId::from_bytes(&mh)
        .expect("valid identity multihash")
        .to_string()
}

/// A server config whose only varying part is the ygg peers block; every
/// entry is pre-indented like the pinned ktav fixtures.
fn network_text(peers_block: &str) -> String {
    format!(
        "target: 127.0.0.1:9000\nnetwork: {{\n    mainline: {{\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:6881\n        ]\n    }}\n    signaling: {{\n        relay: {}\n        relay_address: 192.0.2.20:7000\n    }}\n    ygg: {{\n        peers: [\n{}        ]\n    }}\n}}\n",
        relay_peer_id_text(),
        peers_block,
    )
}

fn peer_entry(uri: &str) -> String {
    format!("            {uri}\n")
}

fn rejected(uri: &str) {
    let text = network_text(&peer_entry(uri));
    let err = match ServerConfig::from_text(&text, &ServerOverrides::default()) {
        Ok(cfg) => panic!("expected rejection of {uri:?}, got {cfg:?}"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            ConfigError::Validation {
                field: "network.ygg.peers",
                kind: ValidationKind::InvalidUri
            }
        ),
        "peer {uri:?} -> {err:?}"
    );
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains(uri), "rejected URI echoed: {rendered}");
}

fn accepted(uri: &str) {
    let text = network_text(&peer_entry(uri));
    let cfg = match ServerConfig::from_text(&text, &ServerOverrides::default()) {
        Ok(cfg) => cfg,
        Err(error) => panic!("expected acceptance of {uri:?}, got {error:?}"),
    };
    let peers = cfg
        .network()
        .expect("network object present")
        .ygg()
        .expect("ygg section present")
        .peers();
    assert_eq!(peers, [uri.to_string()], "entry must be stored raw");
}

#[test]
fn decoded_query_names_and_values_are_validated() {
    // An encoded option NAME reaches the validator decoded: `%70riority` is
    // `priority`, so the backend's u8 rule applies.
    rejected("tcp://127.0.0.1:9001?%70riority=256");
    accepted("tcp://127.0.0.1:9001?%70riority=3");
    // `+` decodes to a space before the value parse, exactly as the backend
    // observes the pair; an encoded `%2B` stays a plus sign, which Rust's
    // u8 parse accepts just like the backend's `value.parse()`.
    rejected("tcp://127.0.0.1:9001?priority=+3");
    accepted("tcp://127.0.0.1:9001?priority=%2B3");
    // A percent-encoded VALUE decodes before the known-key checks.
    accepted(
        "tcp://127.0.0.1:9001?key=%6475a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
}

#[test]
fn valueless_known_keys_are_rejected_and_unknown_ignored() {
    // The backend's decoded pair is ("key", "") -> not 32 bytes -> error.
    rejected("tcp://127.0.0.1:9001?key");
    rejected("tcp://127.0.0.1:9001?priority");
    // Valueless UNKNOWN keys are ignored by the backend and accepted here.
    accepted("tcp://127.0.0.1:9001?unknownflag");
    // An empty password value is within the byte cap for both sides.
    accepted("tcp://127.0.0.1:9001?password=");
}

#[test]
fn fragments_never_enter_the_query() {
    // The query ends at the fragment: priority=3 is valid.
    accepted("tcp://127.0.0.1:9001?priority=3#fragment");
    // A `?` inside the fragment is fragment text, not a query.
    accepted("tcp://127.0.0.1:9001#fragment?priority=256");
    // Paths are ignored for tcp/tls dialing; options still validated.
    accepted("tcp://127.0.0.1:9001/some/path?priority=3");
    rejected("tcp://127.0.0.1:9001/some/path?priority=256");
}

#[test]
fn password_cap_counts_decoded_utf8_bytes() {
    let at_cap_ascii = format!("tcp://127.0.0.1:9001?password={}", "x".repeat(64));
    let over_cap_ascii = format!("tcp://127.0.0.1:9001?password={}", "x".repeat(65));
    // `é` is two UTF-8 bytes: 32 chars hit the 64-byte cap, 33 exceed it.
    let at_cap_utf8 = format!("tcp://127.0.0.1:9001?password={}", "\u{e9}".repeat(32));
    let over_cap_utf8 = format!("tcp://127.0.0.1:9001?password={}", "\u{e9}".repeat(33));
    accepted(at_cap_ascii.as_str());
    accepted(at_cap_utf8.as_str());
    rejected(over_cap_ascii.as_str());
    rejected(over_cap_utf8.as_str());
}

#[test]
fn url_parser_host_port_and_scheme_grammar_is_enforced() {
    let bad = [
        "http://127.0.0.1:9",
        "tcp://",
        "tcp://127.0.0.1 :9",
        "tcp://[",
        "tcp://127.0.0.1:notaport",
        "tcp://127.0.0.1",
        "tcp://:9001",
        "tcp://foo]:9001",
        "tcp://[garbage%]:9001",
        "tcp://127.0.0.1:00",
        "tcp://127.0.0.1:9001?priority=256",
        "tcp://127.0.0.1:9001?key=zz",
        "tcp://127.0.0.1:9001?maxbackoff=3s",
        "tcp://127.0.0.1:9001?maxbackoff=abc",
        "tcp://127.0.0.1:9001?maxbackoff=5m30",
    ];
    for uri in bad {
        rejected(uri);
    }

    let good = [
        "tcp://127.0.0.1:9001",
        "TLS://127.0.0.1:9",
        "tcp://[2001:db8::1]:9001",
        "tcp://127.0.0.1:080",
        "tcp://127.0.0.1:9001?password=hunter2",
        "tcp://127.0.0.1:9001?key=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a&priority=3&maxbackoff=5m&password=p&sni=peer.example",
        "tcp://example.org:9001",
        // tcp/tls use URL's opaque host grammar, not IPv4 validation.
        "tcp://127.0.0.999:9001",
    ];
    for uri in good {
        accepted(uri);
    }
}

#[test]
fn plain_plus_prefixed_maxbackoff_mirrors_the_backend() {
    // Raw '+' decodes to space; only an encoded plus reaches u64 parsing.
    rejected("tcp://127.0.0.1:9001?maxbackoff=+5");
    accepted("tcp://127.0.0.1:9001?maxbackoff=%2B5");
    rejected("tcp://127.0.0.1:9001?maxbackoff=%2B4");
    accepted("tcp://127.0.0.1:9001?maxbackoff=5s");
    accepted("tcp://127.0.0.1:9001?maxbackoff=300");
    accepted("tcp://127.0.0.1:9001?maxbackoff=5m");
}
