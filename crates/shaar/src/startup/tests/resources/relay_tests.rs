//! A separately owned real relay fixture (with its own generated peer
//! identity) accepts a configured reservation through the retained resources.
//! Reservation changes only relay readiness, not native/Ygg ownership.

use std::net::SocketAddrV4;
use std::time::Duration;

use shaar_p2p::RelayAddr;

use crate::network::RelayFixture;
use crate::startup::SharedResourcesStart;
use crate::startup::YggPhase;
use crate::startup::resources::SharedResources;

use super::{
    BUDGET, identity, parse_server_config, probe_claim_free, server_config_text, start_composition,
    start_listener, wait_admitted,
};

// Unique per test (parallel #[tokio::test]s must never share an
// identity/transit seed — the backend enforces a process-wide same-key
// exclusion): identity 0xE1, transit 0xE2.
const SEED: u8 = 0xE1;
const TRANSIT_SEED: u8 = 0xE2;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_reservation_succeeds_and_readiness_stays_truthful() {
    let fixture = RelayFixture::start().await;
    let relay: RelayAddr = fixture.address;

    let (transit, transit_port) = start_listener(TRANSIT_SEED).await;
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
        &[SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 9)],
        "127.0.0.1:0".parse().expect("signaling bind"),
        &[format!("tcp://127.0.0.1:{transit_port}")],
        None,
    );
    // Replace only the helper's default relay settings with this fixture's
    // independently owned, actually listening relay endpoint.
    let text = text
        .replace(
            &format!("relay: {}", super::relay_peer_id_text()),
            &format!("relay: {}", relay.peer_id()),
        )
        .replace(
            "relay_address: 192.0.2.20:7000",
            &format!("relay_address: {}", relay.socket_addr()),
        );
    let config = parse_server_config(&text);
    let identity = identity(SEED);
    let mut start: SharedResourcesStart = start_composition(&identity, &config, &[]);
    let resources: SharedResources = wait_admitted(&mut start).await;

    let before = resources.readiness().await;
    assert!(!before.relay_reserved, "configured relay starts unreserved");
    assert!(before.native_bound, "native endpoint remains bound");
    assert_eq!(before.ygg, YggPhase::BridgeOnly);
    let endpoint_id = resources
        .endpoint_for_tests(|endpoint| endpoint.id())
        .expect("composition owns its native endpoint");

    let lease = tokio::time::timeout(BUDGET, resources.reserve_configured_relay())
        .await
        .expect("reservation finishes within the bound")
        .expect("configured real relay reservation succeeds");
    assert_eq!(lease.relay(), relay, "the lease names the real relay");

    let reserved = resources.readiness().await;
    assert!(reserved.relay_reserved, "actual reservation is observable");
    assert_eq!(reserved.native_bound, before.native_bound);
    assert_eq!(reserved.native_transferred, before.native_transferred);
    assert_eq!(reserved.signal_bound, before.signal_bound);
    assert_eq!(reserved.ygg, before.ygg);
    assert_eq!(
        resources.endpoint_for_tests(|endpoint| endpoint.id()),
        Some(endpoint_id),
        "relay reservation does not change the native endpoint identity"
    );

    tokio::time::timeout(BUDGET, resources.release_configured_relay())
        .await
        .expect("release finishes within the bound")
        .expect("configured reservation released");
    let released = resources.readiness().await;
    assert!(
        !released.relay_reserved,
        "release clears reservation readiness"
    );
    assert_eq!(released.native_bound, before.native_bound);
    assert_eq!(released.native_transferred, before.native_transferred);
    assert_eq!(released.signal_bound, before.signal_bound);
    assert_eq!(released.ygg, before.ygg);
    assert_eq!(
        resources.endpoint_for_tests(|endpoint| endpoint.id()),
        Some(endpoint_id),
        "release preserves the native endpoint identity"
    );

    tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .expect("shutdown joins within the budget")
        .expect("shutdown is clean");
    let closed = tokio::time::timeout(Duration::from_secs(10), transit.close()).await;
    assert!(
        closed.is_ok() && closed.expect("checked").is_ok(),
        "transit close"
    );
    fixture.close().await;
    probe_claim_free(SEED, "identity claim released").await;
    probe_claim_free(TRANSIT_SEED, "transit claim released").await;
}
