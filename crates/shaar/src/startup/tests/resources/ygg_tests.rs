//! Yggdrasil decision matrix of the NEW retained composition, driven through
//! the production constructor with THIRD independent transit cores:
//! (a) two DISTINCT identities peering through one transit, Standby+peers =>
//!     BOTH `Admitted`, with an authenticated bridge probe round trip
//!     between them through the transit; (b) Signal mode with NONEMPTY
//!     peers => `BridgeOnly` — the payload endpoint is NEVER built
//!     (control-only); (c) Standby with an EMPTY peer set => `BridgeOnly`
//!     (deferred, no fake peer invented). Clean shutdowns release every
//!     claim.

use std::net::SocketAddrV4;
use std::time::Duration;

use iroh_base::PublicKey;
use shaar_ygg::YggTransport;

use crate::startup::SharedResourcesStart;
use crate::startup::YggPhase;
use crate::startup::resources::SharedResources;

use super::{
    BUDGET, PROBE, identity, parse_server_config, probe_claim_free, server_config_text,
    start_composition, start_listener, wait_admitted,
};

// Identity seeds are unique per composition; transit seeds are UNIQUE PER
// TEST (parallel #[tokio::test]s must never share an identity/transit seed —
// the backend enforces a process-wide same-key exclusion).
// (a) identities 0xDA/0xDB, transit 0xDE; (b) identity 0xDC, transit 0xDF;
// (c) identity 0xDD, transit 0xE0.
const SEED_A: u8 = 0xDA;
const SEED_B: u8 = 0xDB;
const SEED_SIGNAL: u8 = 0xDC;
const SEED_BRIDGE_ONLY: u8 = 0xDD;

async fn compose_start(
    seed: u8,
    transit_uri: &str,
    app_peers: &[PublicKey],
    fallback: Option<&str>,
) -> (SharedResourcesStart, SharedResources) {
    // A freshly dropped loopback socket is the dead bootstrap endpoint:
    // Mainline operational failures degrade readiness only, never the Ygg
    // composition under test, and no public peer is ever contacted.
    let bootstrap = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("ephemeral dead bootstrap socket");
    let bootstrap_address = match bootstrap.local_addr().expect("local address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("bootstrap must be IPv4 loopback"),
    };
    drop(bootstrap);
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_address],
        "127.0.0.1:0".parse().expect("signaling bind"),
        &[transit_uri.to_string()],
        fallback,
    );
    let config = parse_server_config(&text);
    let identity = identity(seed);
    let mut start = start_composition(&identity, &config, app_peers);
    let resources = wait_admitted(&mut start).await;
    (start, resources)
}

fn public_key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&identity(seed).public_key_bytes()).expect("fixture key")
}

async fn shutdown_clean(start: &mut SharedResourcesStart, who: &str) {
    tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .unwrap_or_else(|_| panic!("{who}: shutdown joins within the budget"))
        .unwrap_or_else(|error| panic!("{who}: shutdown is clean: {error:?}"));
}

async fn close_transit(transit: YggTransport) {
    let closed = tokio::time::timeout(Duration::from_secs(10), transit.close()).await;
    assert!(
        closed.is_ok() && closed.expect("checked").is_ok(),
        "transit close"
    );
}

#[tokio::test]
async fn distinct_identities_admit_through_transit_and_probe_round_trips() {
    let (transit, transit_port) = start_listener(0xDE).await;
    let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
    let (mut start_a, composition_a) =
        compose_start(SEED_A, &transit_uri, &[public_key(SEED_B)], None).await;
    let (mut start_b, composition_b) =
        compose_start(SEED_B, &transit_uri, &[public_key(SEED_A)], None).await;

    // Distinct identities, BOTH admitted (Standby + nonempty app-peer sets).
    let readiness_a = composition_a.readiness().await;
    let readiness_b = composition_b.readiness().await;
    assert_eq!(
        readiness_a.ygg,
        YggPhase::Admitted,
        "composition A admitted"
    );
    assert_eq!(
        readiness_b.ygg,
        YggPhase::Admitted,
        "composition B admitted"
    );
    assert_ne!(
        identity(SEED_A).public_key_bytes(),
        identity(SEED_B).public_key_bytes(),
        "the two compositions use distinct identities"
    );

    let duration = tokio::time::timeout(
        PROBE,
        composition_a.ygg_bridge_probe_for_tests(identity(SEED_B).public_key_bytes(), PROBE),
    )
    .await
    .expect("probe round trip inside the test budget")
    .expect("authenticated probe through the transit");
    assert!(duration <= PROBE, "probe answered within its deadline");

    let readiness_before_transfer = composition_a.readiness().await;
    let native_a = composition_a
        .transfer_native()
        .await
        .expect("quiesced native transfer")
        .expect("native owner transfers once");
    assert_eq!(native_a.id(), identity(SEED_A).transport_key().public());
    let readiness_after_native = composition_a.readiness().await;
    assert!(!readiness_after_native.native_bound);
    assert!(
        readiness_after_native.native_transferred,
        "successful transfer is observable"
    );
    assert_eq!(readiness_after_native.ygg, readiness_before_transfer.ygg);
    assert!(
        composition_a
            .transfer_native()
            .await
            .expect("second quiesced transfer")
            .is_none(),
        "native transfers only once"
    );
    let readiness_after_second_native = composition_a.readiness().await;
    assert!(!readiness_after_second_native.native_bound);
    assert!(readiness_after_second_native.native_transferred);
    assert_eq!(
        readiness_after_second_native.ygg,
        readiness_after_native.ygg
    );
    assert_eq!(
        readiness_after_second_native.signal_bound,
        readiness_after_native.signal_bound
    );
    assert_eq!(
        readiness_after_second_native.relay_reserved,
        readiness_after_native.relay_reserved
    );

    let (mut payload_endpoint, mut payload_pump) = composition_a
        .take_ygg_payload()
        .expect("Standby payload owners transfer together");
    assert_eq!(composition_a.ygg_phase(), YggPhase::PayloadTransferred);
    assert!(
        composition_a.take_ygg_payload().is_none(),
        "payload transfers only once"
    );
    assert_eq!(composition_a.ygg_phase(), YggPhase::PayloadTransferred);
    native_a
        .close()
        .await
        .expect("transferred native endpoint closes");
    payload_endpoint
        .close(&mut payload_pump)
        .await
        .expect("transferred Ygg payload pair closes");
    assert_eq!(composition_a.ygg_phase(), YggPhase::PayloadTransferred);
    let readiness_after_close = composition_a.readiness().await;
    assert!(
        readiness_after_close.publication.is_none(),
        "no stale publication after watcher quiesce and native close: {:?}",
        readiness_after_close.publication
    );
    // Independent publisher-watch oracle: the retained owner itself no longer
    // reports Published after withdrawal quiesce.
    let publisher_state = composition_a
        .mainline_publication_status_for_tests()
        .expect("retained Mainline owner after quiesce");
    assert!(
        !matches!(
            publisher_state,
            crate::native_discovery::runtime::publisher::PublicationStatus::Published { .. }
        ),
        "publisher watch must not report Published after withdrawal quiesce: {publisher_state:?}"
    );

    let handoff_probe = tokio::time::timeout(
        PROBE,
        composition_b.ygg_bridge_probe_for_tests(identity(SEED_A).public_key_bytes(), PROBE),
    )
    .await
    .expect("bridge remains active after both payload owners transfer")
    .expect("the other composition still reaches A's retained bridge");
    assert!(handoff_probe <= PROBE);

    shutdown_clean(&mut start_a, "A shutdown").await;
    assert_eq!(
        composition_b.readiness().await.ygg,
        YggPhase::Admitted,
        "B remains admitted after A closes its remaining bridge"
    );
    shutdown_clean(&mut start_b, "B shutdown").await;
    assert_eq!(composition_b.readiness().await.ygg, YggPhase::None);
    close_transit(transit).await;
    probe_claim_free(SEED_A, "A claim released").await;
    probe_claim_free(SEED_B, "B claim released").await;
    probe_claim_free(0xDE, "transit claim released").await;
}

#[tokio::test]
async fn signal_mode_with_peers_never_builds_the_payload() {
    let (transit, transit_port) = start_listener(0xDF).await;
    let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
    // `fallback: signal` in the fixture schema with a NONEMPTY peer set: the
    // mode decision alone keeps the bridge control-only (the YggEndpoint
    // payload pair is NEVER constructed even though peers are configured).
    let (mut start, resources) = compose_start(
        SEED_SIGNAL,
        &transit_uri,
        &[public_key(SEED_B)],
        Some("signal"),
    )
    .await;

    let readiness = resources.readiness().await;
    assert_eq!(
        readiness.ygg,
        YggPhase::BridgeOnly,
        "Signal mode is control-only: payload endpoint never built"
    );
    assert_eq!(
        resources.ygg_phase(),
        YggPhase::BridgeOnly,
        "synchronous phase accessor agrees"
    );
    assert!(resources.take_ygg_payload().is_none());
    assert_eq!(resources.ygg_phase(), YggPhase::BridgeOnly);

    shutdown_clean(&mut start, "signal-mode shutdown").await;
    let readiness = resources.readiness().await;
    assert_eq!(readiness.ygg, YggPhase::None, "ygg cleared after shutdown");
    close_transit(transit).await;
    probe_claim_free(SEED_SIGNAL, "signal-mode claim released").await;
    probe_claim_free(0xDF, "transit claim released").await;
}

#[tokio::test]
async fn standby_with_empty_peers_stays_bridge_only_without_payload() {
    let (transit, transit_port) = start_listener(0xE0).await;
    let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
    // Zero application peers in Standby mode: payload acquisition is
    // deferred and NO fake peer is invented — the readiness phase proves
    // the YggEndpoint is never constructed.
    let (mut start, resources) = compose_start(SEED_BRIDGE_ONLY, &transit_uri, &[], None).await;

    let readiness = resources.readiness().await;
    assert_eq!(readiness.ygg, YggPhase::BridgeOnly, "deferred payload");
    assert!(resources.take_ygg_payload().is_none());
    assert_eq!(resources.ygg_phase(), YggPhase::BridgeOnly);

    shutdown_clean(&mut start, "bridge-only shutdown").await;
    let readiness = resources.readiness().await;
    assert_eq!(readiness.ygg, YggPhase::None, "ygg cleared after shutdown");
    close_transit(transit).await;
    probe_claim_free(SEED_BRIDGE_ONLY, "bridge-only claim released").await;
    probe_claim_free(0xE0, "transit claim released").await;
}
