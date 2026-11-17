//! Host-name bootstrap entries: accepted shapes, rejected shapes, the shared
//! 1..=4 bound and redaction. Parsing only; nothing is resolved here.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::config::{ConfigError, ServerConfig, ServerOverrides, ValidationKind};

use super::bootstrap::host_for_tests;

const FIELD: &str = "network.mainline.bootstrap";
const REST: &str = "    signaling: {\n        bind: 0.0.0.0:0\n    }\n    ygg: {\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n    }\n";

fn text(entries: &[&str]) -> String {
    let mut lines = String::new();
    for entry in entries {
        lines.push_str(&format!("            {entry}\n"));
    }
    format!(
        "target: 127.0.0.1:9000\nnetwork: {{\n    mainline: {{\n        bootstrap: [\n{lines}        ]\n    }}\n{REST}}}\n"
    )
}

fn parse(entries: &[&str]) -> Result<ServerConfig, ConfigError> {
    ServerConfig::from_text(&text(entries), &ServerOverrides::default())
}

fn rejected(entry: &str) -> ValidationKind {
    match parse(&[entry]) {
        Err(ConfigError::Validation { field, kind }) => {
            assert_eq!(field, FIELD, "{entry}");
            kind
        }
        other => panic!("{entry} must be rejected, got {other:?}"),
    }
}

#[test]
fn host_names_and_numeric_entries_are_kept_apart_in_order() {
    let config = parse(&[
        "router.bittorrent.com:6881",
        "192.0.2.10:6881",
        "dht.libtorrent.org:25401",
        "localhost:6881",
    ])
    .unwrap();
    let mainline = config.network().unwrap().mainline().unwrap();
    assert_eq!(
        mainline.bootstrap(),
        [SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 6881)]
    );
    assert_eq!(
        mainline.hosts(),
        [
            host_for_tests("router.bittorrent.com", 6881),
            host_for_tests("dht.libtorrent.org", 25401),
            host_for_tests("localhost", 6881),
        ]
    );
}

#[test]
fn numeric_only_entries_have_no_hosts() {
    let config = parse(&["192.0.2.10:6881"]).unwrap();
    assert!(
        config
            .network()
            .unwrap()
            .mainline()
            .unwrap()
            .hosts()
            .is_empty()
    );
}

#[test]
fn malformed_host_names_are_rejected_without_echo() {
    let long_label = format!("{}.example:1", "a".repeat(64));
    let long_name = format!("{}example:1", "abcdefghi.".repeat(25));
    for entry in [
        "-bad.example:6881",
        "bad-.example:6881",
        "bad..example:6881",
        "bad.example.:6881",
        "bad_host.example:6881",
        "1.2.3:6881",
        "999.1.1.1:6881",
        "host.example:",
        "host.example:+5",
        "host.example:65536",
        "host.example",
        long_label.as_str(),
        long_name.as_str(),
    ] {
        assert_eq!(rejected(entry), ValidationKind::InvalidAddress, "{entry}");
    }
    let err = parse(&["bad_host.example:6881"]).unwrap_err();
    for shown in [err.to_string(), format!("{err:?}")] {
        assert!(!shown.contains("bad_host"), "{shown}");
    }
}

#[test]
fn a_host_with_port_zero_is_an_invalid_port() {
    assert_eq!(
        rejected("router.bittorrent.com:0"),
        ValidationKind::InvalidPort
    );
}

#[test]
fn label_and_name_bounds_are_inclusive() {
    let label = format!("{}.example:1", "a".repeat(63));
    assert!(parse(&[label.as_str()]).is_ok());
    // 253 bytes: 25 labels of nine letters and a dot, then a 3-byte label.
    let name = format!("{}abc:1", "abcdefghi.".repeat(25));
    assert_eq!(name.len() - 2, 253);
    assert!(parse(&[name.as_str()]).is_ok());
}

#[test]
fn hosts_count_toward_the_four_entry_bound() {
    let five = [
        "a.example:1",
        "b.example:1",
        "192.0.2.10:6881",
        "c.example:1",
        "d.example:1",
    ];
    assert!(matches!(
        parse(&five),
        Err(ConfigError::Validation {
            field: FIELD,
            kind: ValidationKind::TooMany
        })
    ));
    assert!(parse(&five[..4]).is_ok());
}
