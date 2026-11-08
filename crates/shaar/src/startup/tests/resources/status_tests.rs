//! Status/readiness contracts over the production retained composition.
//!
//! All publication and resolution traffic below crosses the real loopback
//! Mainline UDP actor. Test-only Submit commands replace watcher snapshots only
//! after the initial native watcher snapshot is Published and stable; they do
//! not pretend to control the native watcher itself.

use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::time::Duration;

use iroh::{EndpointAddr, TransportAddr, Watcher as _};
use iroh_base::EndpointId;
use n0_future::StreamExt as _;
use n0_mainline::MutableItem;

use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::native_discovery::runtime::publisher::PublicationStatus;
use crate::startup::SharedResourcesStart;
use crate::startup::resources::SharedResources;

use super::{
    BUDGET, PROBE, identity, parse_server_config, probe_claim_free, server_config_text,
    start_composition, start_listener, wait_admitted,
};

pub(super) type SubmitFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<(), crate::native_discovery::runtime::owner::RuntimeError>> + 'a,
    >,
>;

pub(super) async fn new_composition(
    peer: &LoopbackPeer,
    identity_seed: u8,
    transit_seed: u8,
    app_peers: &[iroh_base::PublicKey],
) -> (
    SharedResourcesStart,
    crate::identity::Identity,
    shaar_ygg::YggTransport,
) {
    let (transit, transit_port) = start_listener(transit_seed).await;
    let (start, local_identity) = new_composition_on_transit(
        peer,
        identity_seed,
        &format!("tcp://127.0.0.1:{transit_port}"),
        app_peers,
    )
    .await;
    (start, local_identity, transit)
}

/// Composition over an EXISTING transit core: authorized counterparties that
/// must reach each other dial the SAME listener, so one real transit serves
/// both.
async fn new_composition_on_transit(
    peer: &LoopbackPeer,
    identity_seed: u8,
    transit_uri: &str,
    app_peers: &[iroh_base::PublicKey],
) -> (SharedResourcesStart, crate::identity::Identity) {
    let bootstrap = match peer.address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("loopback Mainline peer must bind IPv4"),
    };
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, super::reserve_udp_port()),
        &[bootstrap],
        format!("127.0.0.1:{}", super::reserve_tcp_port())
            .parse()
            .expect("reserved signaling bind"),
        &[transit_uri.to_string()],
        Some("signal"),
    );
    let config = parse_server_config(&text);
    let local_identity = identity(identity_seed);
    let start = start_composition(&local_identity, &config, app_peers);
    (start, local_identity)
}

async fn watcher_addresses(resources: &SharedResources) -> Vec<SocketAddr> {
    let watcher = resources
        .endpoint_for_tests(|endpoint| endpoint.native_addr_watcher())
        .expect("retained native endpoint");
    let mut updates = watcher.stream();
    updates
        .next()
        .await
        .expect("native watcher snapshot")
        .ip_addrs()
        .copied()
        .collect()
}

/// The publisher watch satisfies this barrier; Pending and Unavailable may
/// precede it.
pub(super) async fn published(resources: &SharedResources) -> u64 {
    match super::published_on_watch(resources).await {
        PublicationStatus::Published { generation, .. } => generation,
        other => panic!("publication watch left Published: {other:?}"),
    }
}

pub(super) async fn stable_published(resources: &SharedResources, generation: u64) {
    for _ in 0..3 {
        let status = resources.readiness().await.publication;
        assert!(
            matches!(status, Some(PublicationStatus::Published { generation: found, .. }) if found == generation),
            "Published remains stable across readiness queries: {status:?}"
        );
    }
}

pub(super) async fn current_publication(resources: &SharedResources) -> PublicationStatus {
    resources
        .readiness()
        .await
        .publication
        .expect("live publication status")
}

fn submit_snapshot<'a>(resources: &'a SharedResources, address: EndpointAddr) -> SubmitFuture<'a> {
    Box::pin(resources.submit_watcher_snapshot_for_tests(address))
}

/// Concurrently retain both required initial observations. Neither a winner
/// from `select!` nor a completed future causes the other operation to drop.
async fn admit_and_capture_initial(
    start: &mut SharedResourcesStart,
    peer: &mut LoopbackPeer,
) -> (
    SharedResources,
    (
        SocketAddr,
        Vec<u8>,
        iroh_dns::pkarr::SignedPacket,
        MutableItem,
    ),
) {
    let mut admission = Box::pin(start.wait());
    let mut capture = Box::pin(peer.capture_put_record());
    let mut admitted = None;
    let mut held = None;
    tokio::time::timeout(BUDGET, async {
        while admitted.is_none() || held.is_none() {
            tokio::select! {
                result = &mut admission, if admitted.is_none() => admitted = Some(result),
                result = &mut capture, if held.is_none() => held = Some(result),
            }
        }
    })
    .await
    .expect("admission and actual initial PUT are both observed");
    drop(admission);
    drop(capture);
    (
        admitted
            .expect("admission result retained")
            .expect("composition admitted"),
        held.expect("actual PUT capture retained"),
    )
}

pub(super) async fn acknowledge_initial(
    resources: &SharedResources,
    peer: &mut LoopbackPeer,
) -> (iroh_dns::pkarr::SignedPacket, MutableItem) {
    let (source, transaction, signed, item) =
        tokio::time::timeout(BUDGET, peer.capture_put_record())
            .await
            .expect("initial real PUT captured");
    peer.acknowledge(source, &transaction).await;
    let generation = published(resources).await;
    stable_published(resources, generation).await;
    (signed, item)
}

pub(super) fn endpoint_id(identity: &crate::identity::Identity) -> EndpointId {
    EndpointId::from_bytes(&identity.public_key_bytes()).expect("identity key is an EndpointId")
}

pub(super) fn valid_snapshot(identity: &crate::identity::Identity, address: &str) -> EndpointAddr {
    EndpointAddr::from_parts(
        endpoint_id(identity),
        [TransportAddr::Ip(
            address.parse().expect("snapshot socket address"),
        )],
    )
}

/// Captures the real PUT, then queries readiness while Submit remains driven.
pub(super) async fn hold_snapshot<'a>(
    resources: &'a SharedResources,
    peer: &mut LoopbackPeer,
    address: EndpointAddr,
    previous_generation: u64,
) -> (
    SubmitFuture<'a>,
    (
        SocketAddr,
        Vec<u8>,
        iroh_dns::pkarr::SignedPacket,
        MutableItem,
    ),
    PublicationStatus,
) {
    let mut submit = submit_snapshot(resources, address);
    let mut capture = Box::pin(peer.capture_put_record());
    let captured = tokio::time::timeout(BUDGET, async {
        tokio::select! {
            biased;
            result = &mut submit => panic!("Submit completed before its held PUT was captured: {result:?}"),
            captured = &mut capture => captured,
        }
    })
    .await
    .expect("actual snapshot PUT captured while Submit remains pending");

    let readiness = tokio::time::timeout(BUDGET, async {
        tokio::select! {
            biased;
            result = &mut submit => panic!("Submit completed while its captured PUT remained held: {result:?}"),
            readiness = resources.readiness() => readiness,
        }
    })
    .await
    .expect("post-capture readiness query completes");
    let status = readiness
        .publication
        .expect("live publication status after actual PUT capture");
    assert!(
        matches!(status, PublicationStatus::Pending { .. }),
        "captured real PUT remains Pending: {status:?}"
    );
    assert_ne!(
        status.generation(),
        previous_generation,
        "captured flight uses a new definitive generation"
    );
    (submit, captured, status)
}

/// Drives Submit and the publisher watch together. A Pending status for a
/// valid address proves actor admission; invalid/empty/over-cap snapshots
/// instead complete locally with Unavailable and do not issue a network PUT.
pub(super) async fn drive_snapshot<'a>(
    resources: &'a SharedResources,
    address: EndpointAddr,
    previous_generation: u64,
) -> (
    SubmitFuture<'a>,
    PublicationStatus,
    Option<Result<(), crate::native_discovery::runtime::owner::RuntimeError>>,
) {
    let mut submit = submit_snapshot(resources, address);
    let mut result = None;
    let mut admission_seen = false;
    let mut publication = resources
        .publication_watch_for_tests()
        .expect("publisher watch seam for submission driving");
    let status = tokio::time::timeout(BUDGET, async {
        loop {
            let current = publication.borrow().current(tokio::time::Instant::now());
            if admission_seen || current.generation() != previous_generation {
                return current;
            }
            tokio::select! {
                biased;
                completed = &mut submit, if result.is_none() => {
                    result = Some(completed);
                    admission_seen = true;
                }
                changed = publication.changed() => {
                    if changed.is_err() {
                        panic!("publisher watch closed before submission admission");
                    }
                }
            }
        }
    })
    .await
    .expect("Submit admission and real publication state both observed");
    assert_ne!(
        status.generation(),
        previous_generation,
        "actual Submit admission advances the publication generation"
    );
    (submit, status, result)
}

pub(super) async fn finish_submit(
    submit: SubmitFuture<'_>,
    completed: Option<Result<(), crate::native_discovery::runtime::owner::RuntimeError>>,
) -> Result<(), crate::native_discovery::runtime::owner::RuntimeError> {
    match completed {
        Some(result) => result,
        None => tokio::time::timeout(BUDGET, submit)
            .await
            .expect("submitted snapshot reaches a terminal result"),
    }
}

pub(super) async fn shutdown_composition(start: &mut SharedResourcesStart, identity_seed: u8) {
    tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .expect("retained startup owner shuts down")
        .expect("ordered composition shutdown succeeds");
    probe_claim_free(identity_seed, "composition identity claim released").await;
}

pub(super) async fn close_composition(
    start: &mut SharedResourcesStart,
    transit: shaar_ygg::YggTransport,
    identity_seed: u8,
    transit_seed: u8,
) {
    shutdown_composition(start, identity_seed).await;
    tokio::time::timeout(BUDGET, transit.close())
        .await
        .expect("owned transit closes")
        .expect("transit close succeeds");
    probe_claim_free(transit_seed, "transit identity claim released").await;
}

const SCENARIO_ONE_IDENTITY: u8 = 0xE9;
const SCENARIO_ONE_TRANSIT: u8 = 0xEA;

// Mutation caught: replacing the real endpoint watcher snapshot with a
// declaration-only/fake publisher, acknowledging without waiting for the
// publisher completion barrier, or making readiness queries emit extra PUTs.
#[tokio::test(flavor = "current_thread")]
async fn initial_watcher_put_is_signed_published_and_readiness_is_observational() {
    let mut peer = LoopbackPeer::bind().await;
    let (mut start, identity, transit) =
        new_composition(&peer, SCENARIO_ONE_IDENTITY, SCENARIO_ONE_TRANSIT, &[]).await;
    let (resources, (source, transaction, signed, _item)) =
        admit_and_capture_initial(&mut start, &mut peer).await;
    let pending = resources.readiness().await.publication;
    assert!(
        matches!(pending, Some(PublicationStatus::Pending { .. })),
        "the actually held initial UDP PUT is Pending: {pending:?}"
    );

    // The initial watcher is live: equality below is an observation, not a
    // frozen-snapshot guarantee under address churn.
    let watcher = watcher_addresses(&resources).await;
    // This is a live watcher; a concurrent address update can change it after
    // the captured PUT was signed, so exact equality is intentionally an observation.
    assert!(
        !watcher.is_empty(),
        "actual endpoint watcher has IP candidates"
    );
    let record = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("captured actual signed endpoint record");
    assert_eq!(record.endpoint_id, endpoint_id(&identity));
    let published_addresses = record.ip_addrs().copied().collect::<Vec<_>>();
    assert_eq!(
        published_addresses, watcher,
        "signed UDP PUT carries the actual native watcher snapshot"
    );
    assert!(
        published_addresses
            .iter()
            .all(|address| { !address.ip().is_unspecified() && address.port() != 0 })
    );

    peer.acknowledge(source, &transaction).await;
    let generation = published(&resources).await;
    stable_published(&resources, generation).await;
    // The readiness calls above are real maintenance actor queries/barriers.
    // This bounded real-UDP observation catches extra PUTs; it is a negative
    // observation window, not proof that PUTs are impossible at all times.
    peer.assert_no_put_for(Duration::from_millis(100)).await;

    close_composition(
        &mut start,
        transit,
        SCENARIO_ONE_IDENTITY,
        SCENARIO_ONE_TRANSIT,
    )
    .await;
}

const SCENARIO_THREE_SERVICE: u8 = 0xB0;
const SCENARIO_THREE_CLIENT: u8 = 0xBD;
// ONE transit core is shared by BOTH authorized compositions.
const SCENARIO_THREE_TRANSIT: u8 = 0xBF;

// Mutation caught: resolving through a fake/duplicate decoder or the service's
// own local publication cache instead of a second production composition's
// actual Mainline GET and an independently captured, signed service PUT.
#[tokio::test]
async fn independent_compositions_resolve_the_actual_service_watcher_record() {
    let mut service_peer = LoopbackPeer::bind().await;
    let mut resolver_peer = LoopbackPeer::bind().await;
    // Each composition admits the other as an authorized app peer: the live
    // Signal-mode contract is exercised between two REAL authorized
    // counterparties, not an empty allowlist.
    let service_key = endpoint_id(&identity(SCENARIO_THREE_SERVICE));
    let client_key = endpoint_id(&identity(SCENARIO_THREE_CLIENT));
    let service_public =
        iroh_base::PublicKey::from_bytes(service_key.as_bytes()).expect("fixture service key");
    let client_public =
        iroh_base::PublicKey::from_bytes(client_key.as_bytes()).expect("fixture client key");
    // ONE real transit core serves BOTH authorized compositions (the
    // ygg_tests shared-listener pattern): each composition dials the same
    // listener, so the control probe below has a configured real path.
    let (shared_transit, transit_port) = start_listener(SCENARIO_THREE_TRANSIT).await;
    let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
    let (mut service_start, _service_identity) = new_composition_on_transit(
        &service_peer,
        SCENARIO_THREE_SERVICE,
        &transit_uri,
        &[client_public],
    )
    .await;
    let (mut client_start, _client_identity) = new_composition_on_transit(
        &resolver_peer,
        SCENARIO_THREE_CLIENT,
        &transit_uri,
        &[service_public],
    )
    .await;
    let service_resources = wait_admitted(&mut service_start).await;
    let client_resources = wait_admitted(&mut client_start).await;

    // Signal mode keeps the control bridge without a payload owner on BOTH
    // authorized compositions.
    assert_eq!(
        service_resources.readiness().await.ygg,
        crate::startup::YggPhase::BridgeOnly,
        "signal mode keeps the control bridge without a payload owner (service)"
    );
    assert_eq!(
        client_resources.readiness().await.ygg,
        crate::startup::YggPhase::BridgeOnly,
        "signal mode keeps the control bridge without a payload owner (client)"
    );

    // Live authorized-counterpart operation: an authenticated control probe
    // round trip through the shared transit before any resolve.
    let client_key_bytes = *client_key.as_bytes();
    let probe = tokio::time::timeout(
        PROBE,
        service_resources.ygg_bridge_probe_for_tests(client_key_bytes, PROBE),
    )
    .await
    .expect("control probe round trip inside the probe budget")
    .expect("service control bridge reaches the authorized client through the transit");
    assert!(probe <= PROBE, "control probe answered within its deadline");

    // The watcher is live: equality below is an observation, not a frozen
    // snapshot guarantee under address churn.
    let service_watcher = watcher_addresses(&service_resources).await;
    assert!(
        !service_watcher.is_empty(),
        "service native watcher has candidates"
    );
    let (service_signed, service_item) =
        acknowledge_initial(&service_resources, &mut service_peer).await;
    let service_record =
        iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&service_signed)
            .expect("service's actual captured PUT is signed");
    assert_eq!(service_record.endpoint_id, service_key);
    assert_eq!(
        service_record.ip_addrs().copied().collect::<Vec<_>>(),
        service_watcher,
        "service PUT matches its own actual native watcher snapshot"
    );
    let service_item_key =
        EndpointId::from_bytes(service_item.key()).expect("captured mutable key");
    assert_eq!(
        service_item_key, service_key,
        "GET key is the service endpoint identity"
    );

    // The client owns an independent resolver peer and first completes its
    // own initial publication, so the serving peer never mistakes a PUT for a
    // GET while answering the actual lookup below.
    let _client_records = acknowledge_initial(&client_resources, &mut resolver_peer).await;
    let resolved = tokio::time::timeout(BUDGET, async {
        tokio::select! {
            result = client_resources.resolve(service_key) => result,
            _ = resolver_peer.serve_record(&service_item) => {
                panic!("actual resolver record server unexpectedly terminated")
            }
        }
    })
    .await
    .expect("independent actual GET completes within its bound")
    .expect("signed service record passes the real resolver");
    assert_eq!(
        resolved.addresses(),
        service_watcher.as_slice(),
        "the independent GET returns exactly the service's actual watcher IP snapshot"
    );

    drop(resolved);
    shutdown_composition(&mut service_start, SCENARIO_THREE_SERVICE).await;
    shutdown_composition(&mut client_start, SCENARIO_THREE_CLIENT).await;
    tokio::time::timeout(BUDGET, shared_transit.close())
        .await
        .expect("shared transit closes")
        .expect("shared transit close succeeds");
    probe_claim_free(SCENARIO_THREE_TRANSIT, "shared transit claim released").await;
}
