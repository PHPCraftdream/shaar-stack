//! `network.mainline.pkarr_relays` (leaf PKARR-2): the default (none), accepted and rejected
//! entries, the bound of four, repeated entries, redaction and the resolved copy. Parsing only.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::config::{
    ClientConfig, ClientOverrides, ConfigError, ServerConfig, ServerOverrides, ValidationKind,
};
use crate::native_discovery::runtime::publisher::relay::{MAX_RELAYS, RelayUrl};

const FIELD: &str = "network.mainline.pkarr_relays";
const REST: &str = "    signaling: {\n        bind: 0.0.0.0:0\n    }\n    ygg: {\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n    }\n";
const BOOTSTRAP: &str = "        bootstrap: [\n            192.0.2.10:6881\n            router.example.org:6881\n        ]\n";
const PUBKY: &str = "https://pkarr.pubky.app";
const PKARR_ORG: &str = "https://relay.pkarr.org";

/// The `mainline` block; `None` leaves the key out, `Some(&[])` writes an empty list.
fn mainline(relays: Option<&[&str]>) -> String {
    let relays = relays.map_or_else(String::new, |entries| {
        let items: String = entries
            .iter()
            .map(|entry| format!("            {entry}\n"))
            .collect();
        format!("        pkarr_relays: [\n{items}        ]\n")
    });
    format!("    mainline: {{\n{BOOTSTRAP}{relays}    }}\n")
}

fn server_text(relays: Option<&[&str]>) -> String {
    format!(
        "target: 127.0.0.1:9000\nnetwork: {{\n{}{REST}}}\n",
        mainline(relays)
    )
}

fn parse(relays: Option<&[&str]>) -> Result<ServerConfig, ConfigError> {
    ServerConfig::from_text(&server_text(relays), &ServerOverrides::default())
}

fn relays_of(config: &ServerConfig) -> Vec<RelayUrl> {
    config
        .network()
        .expect("network object")
        .mainline()
        .expect("mainline section")
        .pkarr_relays()
        .to_vec()
}

fn url(text: &str) -> RelayUrl {
    RelayUrl::parse(text).expect("valid relay address")
}

#[test]
fn no_key_and_an_empty_list_both_mean_no_relay() {
    assert!(relays_of(&parse(None).unwrap()).is_empty());
    assert!(relays_of(&parse(Some(&[])).unwrap()).is_empty());
    let inline = server_text(None).replace(
        "        ]\n    }\n    signaling",
        "        ]\n        pkarr_relays: []\n    }\n    signaling",
    );
    let config = ServerConfig::from_text(&inline, &ServerOverrides::default()).unwrap();
    assert!(relays_of(&config).is_empty());
}

#[test]
fn listed_relays_are_kept_in_order() {
    let config = parse(Some(&[PUBKY, PKARR_ORG, "http://127.0.0.1:8080"])).unwrap();
    assert_eq!(
        relays_of(&config),
        [url(PUBKY), url(PKARR_ORG), url("http://127.0.0.1:8080")]
    );
}

#[test]
fn a_repeated_relay_is_kept_once() {
    let config = parse(Some(&[PUBKY, PKARR_ORG, PUBKY])).unwrap();
    assert_eq!(relays_of(&config), [url(PUBKY), url(PKARR_ORG)]);
}

#[test]
fn four_relays_are_the_most() {
    assert_eq!(MAX_RELAYS, 4);
    let four = [
        "https://a.example.org",
        "https://b.example.org",
        "https://c.example.org",
        "https://d.example.org",
    ];
    assert_eq!(relays_of(&parse(Some(&four)).unwrap()).len(), 4);
    let five = [four[0], four[1], four[2], four[3], "https://e.example.org"];
    assert!(matches!(
        parse(Some(&five)),
        Err(ConfigError::Validation {
            field: FIELD,
            kind: ValidationKind::TooMany
        })
    ));
}

#[test]
fn a_malformed_relay_names_the_field_and_is_never_echoed() {
    for bad in [
        "not a url",
        "http://example.com",
        "http://10.0.0.1:80",
        "https://1.2.3.4",
        "https://user:secret@example.com",
        "https://example.com/some/path",
        "https://example.com/?token=secret",
        "ftp://example.com",
    ] {
        let error = parse(Some(&[PUBKY, bad])).expect_err(bad);
        assert!(
            matches!(
                error,
                ConfigError::Validation {
                    field: FIELD,
                    kind: ValidationKind::InvalidUri
                }
            ),
            "{bad}: {error:?}"
        );
        for shown in [error.to_string(), format!("{error:?}")] {
            for secret in ["secret", "example.com", "10.0.0.1", "not a url"] {
                assert!(!shown.contains(secret), "{bad} leaked {secret}: {shown}");
            }
        }
    }
}

#[test]
fn resolving_the_bootstrap_hosts_keeps_the_relays() {
    let config = parse(Some(&[PUBKY])).unwrap();
    let mainline = config.network().unwrap().mainline().unwrap();
    let resolved = mainline.with_resolved(&[SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 77), 6881)]);
    assert_eq!(resolved.pkarr_relays(), [url(PUBKY)]);
    assert!(resolved.hosts().is_empty());
}

#[test]
fn the_shared_section_accepts_the_key_in_a_client_file_too() {
    const KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let text = format!(
        "server: {KEY}\nnetwork: {{\n{}{REST}}}\n",
        mainline(Some(&[PUBKY]))
    );
    let config = ClientConfig::from_text(&text, &ClientOverrides::default()).unwrap();
    let relays = config
        .network()
        .expect("network object")
        .mainline()
        .expect("mainline section")
        .pkarr_relays()
        .to_vec();
    assert_eq!(relays, [url(PUBKY)]);
}
