//! Pure preflight oracles: field-specific redacted errors, the raw
//! application-peer bound (duplicates and distinct entries), and
//! identity-role conflicts by exact PeerId-bytes equality for the local,
//! configured-service and infrastructure roles. No ports, no clock, no
//! filesystem.

use iroh_base::PublicKey;
use libp2p_identity::PeerId;

use crate::config::{ClientConfig, ClientOverrides, ServerConfig, ServerOverrides};
use crate::identity::Identity;
use crate::startup::{MAX_STARTUP_APP_PEERS, StartupError, preflight_client, preflight_server};

/// Fixed distinct test identities (test fixtures only, never production).
const LOCAL_SEED: [u8; 32] = [0x51; 32];
const RELAY_SEED: [u8; 32] = [0x52; 32];
const PEER_A_SEED: [u8; 32] = [0x54; 32];
const PEER_B_SEED: [u8; 32] = [0x55; 32];
/// RFC 8032 § 7.1 test-vector 1 public key hex: the CLIENT's configured service
/// key in every client fixture (never equal to any seed-derived identity).
const RFC8032_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SERVICE_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn local_identity() -> Identity {
    Identity::from_seed(LOCAL_SEED)
}

fn relay_identity() -> Identity {
    Identity::from_seed(RELAY_SEED)
}

fn peer_identity(seed: [u8; 32]) -> Identity {
    Identity::from_seed(seed)
}

/// Real upstream encoder; never a hand-written base58 literal.
fn peer_id_text(identity: &Identity) -> String {
    PeerId::from_bytes(&identity.peer_id_bytes())
        .expect("identity multihash is a valid PeerId")
        .to_string()
}

/// The configured service key's PeerId, derived exactly like the preflight does.
fn service_peer_id() -> PeerId {
    let public = service_public_key();
    let ed25519 = libp2p_identity::ed25519::PublicKey::try_from_bytes(public.as_bytes())
        .expect("Ed25519 public key");
    libp2p_identity::PublicKey::from(ed25519).to_peer_id()
}

fn service_public_key() -> PublicKey {
    // The configured key already passed Ed25519 point decompression at
    // config parse (client.rs FromStr path), so this is a fixture rebuild.
    PublicKey::from_bytes(&SERVICE_PUB).expect("fixture key is a valid public key")
}

/// A valid server config whose pinned relay is `relay`.
fn server_config(relay: &Identity) -> ServerConfig {
    let text = format!(
        "target: 127.0.0.1:9000\nnetwork: {{\n    mainline: {{\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:6881\n        ]\n    }}\n    signaling: {{\n        relay: {}\n        relay_address: 192.0.2.20:7000\n    }}\n    ygg: {{\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n    }}\n}}\n",
        peer_id_text(relay)
    );
    ServerConfig::from_text(&text, &ServerOverrides::default())
        .expect("valid composed server config")
}

/// A valid client config with service key SERVICE_PUB and pinned relay `relay`.
fn client_config(relay_text: &str) -> ClientConfig {
    client_config_with(relay_text, RFC8032_PUB_HEX)
}

/// A valid client config with explicit pinned-relay and service-key texts.
fn client_config_with(relay_text: &str, service_hex: &str) -> ClientConfig {
    let text = format!(
        "server: {}\nnetwork: {{\n    mainline: {{\n        bind: 0.0.0.0:0\n        bootstrap: [\n            192.0.2.10:6881\n        ]\n    }}\n    signaling: {{\n        relay: {}\n        relay_address: 192.0.2.20:7000\n    }}\n    ygg: {{\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n    }}\n}}\n",
        service_hex, relay_text
    );
    ClientConfig::from_text(&text, &ClientOverrides::default())
        .expect("valid composed client config")
}

fn app_peer(identity: &Identity) -> PublicKey {
    identity.transport_key().public()
}

fn assert_redacted(error: &StartupError, forbidden: &[String]) {
    assert!(
        !forbidden.is_empty(),
        "redaction check with an empty forbidden list is vacuous"
    );
    let display = error.to_string();
    let debug = format!("{error:?}");
    for secret in forbidden {
        assert!(
            !display.contains(secret),
            "Display leaked {secret:?}: {display}"
        );
        assert!(!debug.contains(secret), "Debug leaked {secret:?}: {debug}");
    }
}

fn key_material() -> Vec<String> {
    let local = local_identity();
    let relay = relay_identity();
    vec![
        hex(&local.public_key_bytes()),
        hex(&relay.public_key_bytes()),
        peer_id_text(&local),
        peer_id_text(&relay),
        service_peer_id().to_string(),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn valid_server_plan_exposes_network_and_raw_peers() {
    let config = server_config(&relay_identity());
    let identity = local_identity();
    // Neither entry is the local identity or the pinned relay.
    let peers = [
        app_peer(&peer_identity(PEER_A_SEED)),
        app_peer(&peer_identity(PEER_B_SEED)),
    ];
    let plan = preflight_server(&config, &identity, &peers).expect("valid preflight");
    assert_eq!(
        plan.network()
            .signaling()
            .expect("signaling present")
            .relay_address()
            .to_string(),
        "192.0.2.20:7000"
    );
    assert_eq!(plan.app_peers().len(), 2);
}

#[test]
fn valid_client_plan_exposes_network() {
    let config = client_config(&peer_id_text(&relay_identity()));
    let identity = local_identity();
    let peers = [app_peer(&peer_identity(PEER_A_SEED))];
    let plan = preflight_client(&config, &identity, &peers).expect("valid preflight");
    assert_eq!(plan.app_peers().len(), 1);
}

#[test]
fn legacy_config_is_refused_without_silent_direct_only_fallback() {
    let identity = local_identity();
    let peers = [app_peer(&peer_identity(PEER_A_SEED))];
    let server = ServerConfig::from_text("target: 127.0.0.1:9000\n", &ServerOverrides::default())
        .expect("legacy text still parses");
    let error = preflight_server(&server, &identity, &peers).expect_err("legacy config refused");
    assert!(matches!(error, StartupError::NetworkRequired));
    let client_text = format!("server: {RFC8032_PUB_HEX}\nlisten: 127.0.0.1:2300\n");
    let client = ClientConfig::from_text(&client_text, &ClientOverrides::default())
        .expect("legacy client text still parses");
    let error = preflight_client(&client, &identity, &peers).expect_err("legacy config refused");
    assert!(matches!(error, StartupError::NetworkRequired));
    assert_redacted(&error, &key_material());
}

#[test]
fn raw_app_peer_bound_counts_duplicates_and_distinct_entries() {
    let config = server_config(&relay_identity());
    let identity = local_identity();
    // At the bound with ALL-DUPLICATE entries: raw count is what matters.
    let duplicated = vec![app_peer(&peer_identity(PEER_A_SEED)); MAX_STARTUP_APP_PEERS];
    preflight_server(&config, &identity, &duplicated)
        .expect("16 raw entries (all duplicates) pass");
    // At the bound with DISTINCT entries.
    let distinct: Vec<PublicKey> = (0x60u8..0x70u8)
        .map(|byte| app_peer(&peer_identity([byte; 32])))
        .collect();
    assert_eq!(distinct.len(), MAX_STARTUP_APP_PEERS);
    preflight_server(&config, &identity, &distinct).expect("16 distinct entries pass");
    // One more distinct entry is refused before any networking.
    let mut over = distinct;
    over.push(app_peer(&peer_identity([0x70u8; 32])));
    let error =
        preflight_server(&config, &identity, &over).expect_err("17 distinct entries are refused");
    match error {
        StartupError::TooManyAppPeers { count } => assert_eq!(count, 17),
        other => panic!("wrong error: {other:?}"),
    }
    assert_redacted(&error, &key_material());
}

#[test]
fn pinned_relay_equal_to_local_identity_is_a_relay_role_conflict() {
    let config = server_config(&local_identity());
    let identity = local_identity();
    let peers = [app_peer(&peer_identity(PEER_A_SEED))];
    let error = preflight_server(&config, &identity, &peers).expect_err("self-relay refused");
    assert!(matches!(
        error,
        StartupError::IdentityConflict { role: "relay" }
    ));
    assert_redacted(&error, &key_material());
}

#[test]
fn application_peer_equal_to_pinned_relay_is_an_application_role_conflict() {
    let config = server_config(&relay_identity());
    let identity = local_identity();
    let peers = [
        app_peer(&peer_identity(PEER_A_SEED)),
        app_peer(&relay_identity()),
    ];
    let error = preflight_server(&config, &identity, &peers)
        .expect_err("infrastructure identity as application peer is refused");
    assert!(matches!(
        error,
        StartupError::IdentityConflict {
            role: "application"
        }
    ));
    assert_redacted(&error, &key_material());
}

#[test]
fn application_peer_equal_to_local_identity_is_an_application_role_conflict() {
    let config = server_config(&relay_identity());
    let identity = local_identity();
    let peers = [app_peer(&identity)];
    let error = preflight_server(&config, &identity, &peers)
        .expect_err("the local identity is not its own application peer");
    assert!(matches!(
        error,
        StartupError::IdentityConflict {
            role: "application"
        }
    ));
    assert_redacted(&error, &key_material());
}

#[test]
fn client_service_key_equal_to_relay_is_a_relay_role_conflict() {
    // The configured service key IS the pinned relay identity.
    let config = client_config(&service_peer_id().to_string());
    let identity = local_identity();
    let peers = [app_peer(&peer_identity(PEER_A_SEED))];
    let error = preflight_client(&config, &identity, &peers)
        .expect_err("configured service identity cannot be pinned infrastructure");
    assert!(matches!(
        error,
        StartupError::IdentityConflict { role: "relay" }
    ));
    assert_redacted(&error, &key_material());
}

#[test]
fn configured_service_key_as_application_peer_is_accepted() {
    // The pinned service key is a legitimate application peer: existing
    // endpoint admission allowlists exactly this peer on the client.
    let config = client_config(&peer_id_text(&relay_identity()));
    let identity = local_identity();
    let peers = [service_public_key()];
    let plan = preflight_client(&config, &identity, &peers)
        .expect("service key is accepted as an application peer");
    assert_eq!(plan.app_peers().len(), 1);
}

#[test]
fn client_service_key_equal_to_local_identity_is_a_service_role_conflict() {
    // The client cannot pin itself as its own service; detected even with
    // an empty application-peer slice.
    let local_hex = hex(&local_identity().public_key_bytes());
    let config = client_config_with(&peer_id_text(&relay_identity()), &local_hex);
    let identity = local_identity();
    let error = preflight_client(&config, &identity, &[])
        .expect_err("self-configured service identity is refused");
    assert!(matches!(
        error,
        StartupError::IdentityConflict { role: "service" }
    ));
    assert_redacted(&error, &key_material());
}
