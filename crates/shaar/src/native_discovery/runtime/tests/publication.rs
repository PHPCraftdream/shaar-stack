// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::fixture::LoopbackPeer;
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::TestClock;
use crate::native_discovery::runtime::owner::RuntimeOwner;
use crate::native_discovery::runtime::publisher::PublicationStatus;
use crate::network::{Limits, SignaledEndpoint};
use iroh::Watcher as _;
use iroh_base::TransportAddr;

#[tokio::test]
async fn initial_put_uses_the_native_endpoint_address_watcher() {
    use n0_future::StreamExt as _;

    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let identity = Identity::from_seed([0x51; 32]);
    let native = SignaledEndpoint::bind(
        &identity,
        "0.0.0.0:0".parse().expect("wildcard native bind"),
        "127.0.0.1:0".parse().expect("signaling bind"),
        &[],
        Limits::default(),
    )
    .await
    .expect("single native endpoint and signaling owner");
    let mut owner = RuntimeOwner::start(
        identity.clone(),
        "127.0.0.1:0".parse().expect("Mainline bind"),
        &[bootstrap],
    )
    .expect("separate Mainline runtime");
    let actor_handle = owner.dht_handle().expect("owned Mainline handle");
    let local_address = actor_handle.info().await.expect("actor bound").local_addr();

    let watcher = native.native_addr_watcher();
    let mut updates = watcher.stream();
    let snapshot = updates.next().await.expect("actual endpoint snapshot");
    let expected = snapshot.ip_addrs().copied().collect::<Vec<_>>();
    assert!(
        !expected.is_empty(),
        "wildcard bind provides concrete IP candidates"
    );
    let mut replacement =
        Box::pin(owner.replace(expected.iter().copied().map(TransportAddr::Ip).collect()));
    let (source, transaction, captured) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replacement => panic!("real PUT ended before hold: {result:?}"),
    };
    let status = owner.publication_status();
    assert!(matches!(status, PublicationStatus::Pending { .. }));
    peer.acknowledge(source, &transaction).await;
    replacement.await.expect("actual PUT acknowledged");
    let status = owner.publication_status();
    assert!(matches!(status, PublicationStatus::Published { .. }));

    let signed = iroh_dns::pkarr::SignedPacket::from_bytes(&signed_envelope(&captured))
        .expect("captured signature verifies");
    let record = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("actual signed record decodes");
    assert_eq!(
        record.endpoint_id,
        super::super::endpoint_key(&identity).expect("identity key")
    );
    let actual = record.ip_addrs().copied().collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "PUT contains watcher candidates without substitute addresses"
    );
    assert!(actual.iter().all(|address| !address.ip().is_unspecified()));
    assert!(actual.iter().all(|address| address.port() != 0));

    owner.withdraw().await.expect("local generation withdraws");
    let status = owner.publication_status();
    assert!(matches!(status, PublicationStatus::Unavailable { .. }));
    owner
        .close()
        .await
        .expect("Mainline publisher and actor joined");
    native
        .close()
        .await
        .expect("native and signaling owners joined");
    assert!(actor_handle.info().await.is_err());
    let rebound = tokio::net::UdpSocket::bind(local_address)
        .await
        .expect("UDP released");
    drop(rebound);
}

#[tokio::test]
async fn rejected_put_does_not_persist_and_owner_can_publish_replacement() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let identity = Identity::from_seed([0x52; 32]);
    let mut owner = RuntimeOwner::start(
        identity,
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT binds on loopback");
    let actor_handle = owner.dht_handle().expect("sender-only actor handle");
    let local_address = actor_handle
        .info()
        .await
        .expect("actor bound before publication")
        .local_addr();

    let first = TransportAddr::Ip("127.0.0.1:9002".parse().expect("first published address"));
    let mut replace = Box::pin(owner.replace(vec![first]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replace => panic!("unexpected PUT result before peer captured it: {result:?}"),
    };
    peer.reject(source, &transaction).await;
    let result = replace.await;
    let Err(super::super::RuntimeError::Put(n0_mainline::OwnedPutError::Put(
        n0_mainline::errors::PutError::Query(n0_mainline::errors::PutQueryError::ErrorResponse(
            error,
        )),
    ))) = result
    else {
        panic!("wire KRPC rejection must preserve its typed PUT error: {result:?}");
    };
    assert_eq!(error.code, 201);
    assert_eq!(error.description, "PUT rejected");
    let cleanup = owner
        .barrier()
        .await
        .expect("publisher remains responsive after rejection");
    assert!(!cleanup.active, "rejected initial PUT was not persisted");

    let second = TransportAddr::Ip("127.0.0.1:9003".parse().expect("replacement address"));
    let mut replace = Box::pin(owner.replace(vec![second]));
    let (source, transaction, captured) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replace => panic!("later real PUT completed before capture: {result:?}"),
    };
    peer.acknowledge(source, &transaction).await;
    replace
        .await
        .expect("later replacement acknowledged after rejection");
    let signed = iroh_dns::pkarr::SignedPacket::from_bytes(&signed_envelope(&captured))
        .expect("replacement PUT signature verifies");
    let endpoint = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("replacement PUT decodes");
    let expected_address: std::net::SocketAddr = "127.0.0.1:9003"
        .parse()
        .expect("expected replacement address");
    assert_eq!(
        endpoint
            .ip_addrs()
            .copied()
            .collect::<Vec<std::net::SocketAddr>>(),
        vec![expected_address]
    );

    owner
        .close()
        .await
        .expect("publisher and actor joins observed");
    assert!(owner.dht.is_none());
    assert!(actor_handle.info().await.is_err());
    let rebound = tokio::net::UdpSocket::bind(local_address)
        .await
        .expect("joined actor released UDP socket");
    drop(rebound);
}

// Regression: a superseded PUT's stale completion must not promote its own
// generation to Published while a replacement generation is pending, and an
// acknowledged replacement must remain Published instead of being overwritten.
// Catches: completed-but-revoked flights promoting Published, and the defect
// where every completed PUT was immediately overwritten with Unavailable.
#[tokio::test]
async fn superseded_pending_put_completion_cannot_mark_published() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let identity = Identity::from_seed([0x53; 32]);
    let mut owner = RuntimeOwner::start(
        identity,
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT binds on loopback");

    let first_address = TransportAddr::Ip("127.0.0.1:9012".parse().expect("first address"));
    let mut first = Box::pin(owner.replace(vec![first_address]));
    let (source_a, transaction_a, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut first => panic!("initial PUT ended before hold: {result:?}"),
    };
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Pending { .. }
    ));

    // Poll replace(B) while A is held, and keep its future alive while the
    // actor cancels and cleans A. Receiving B's real PUT proves the request was
    // driven and the actor admitted it; constructing the future alone would
    // not prove either step.
    let second_address = TransportAddr::Ip("127.0.0.1:9013".parse().expect("second address"));
    let mut second = Box::pin(owner.replace(vec![second_address]));
    let (source_b, transaction_b, captured_b) = tokio::select! {
        held = tokio::time::timeout(std::time::Duration::from_secs(10), peer.capture_put()) =>
            held.expect("replacement PUT arrives within the bounded admission window"),
        result = &mut second => panic!("replacement ended before its real PUT was captured: {result:?}"),
    };
    let pending_generation = match owner.publication_status() {
        PublicationStatus::Pending { generation } => generation,
        status => panic!("B must be Pending after its PUT was captured: {status:?}"),
    };
    let signed_b = iroh_dns::pkarr::SignedPacket::from_bytes(&signed_envelope(&captured_b))
        .expect("captured B signature verifies");
    let record_b = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed_b)
        .expect("captured B record decodes");
    let expected_b: std::net::SocketAddr = "127.0.0.1:9013".parse().expect("B address");
    assert_eq!(
        record_b.ip_addrs().copied().collect::<Vec<_>>(),
        vec![expected_b],
        "the admitted replacement PUT contains B's actual snapshot"
    );

    // This is a late wire reply for A, after B has become the actor's active
    // generation. It must not restore A or dislodge B's Pending claim.
    peer.acknowledge(source_a, &transaction_a).await;
    let superseded = first
        .await
        .expect_err("superseded PUT must not report success");
    assert!(
        matches!(
            superseded,
            super::super::RuntimeError::Closed | super::super::RuntimeError::DeadlineExceeded
        ),
        "superseded PUT reports a closed-style error: {superseded:?}"
    );
    assert_eq!(
        owner.publication_status(),
        PublicationStatus::Pending {
            generation: pending_generation
        },
        "late A acknowledgment cannot change B's Pending generation"
    );

    // Retain B's future through the stale A reply, then complete B and cross
    // the actor barrier before requiring the stable Published state.
    peer.acknowledge(source_b, &transaction_b).await;
    second.await.expect("replacement PUT acknowledged");
    owner.barrier().await.expect("publisher status barrier");
    let status = owner.publication_status();
    let PublicationStatus::Published { generation, .. } = status else {
        panic!("acknowledged replacement must be Published: {status:?}");
    };
    assert_eq!(
        generation, pending_generation,
        "Published status retains B's independently captured Pending generation"
    );

    owner
        .close()
        .await
        .expect("publisher and actor joins observed");
}

// Regression: an actual rejected refresh PUT clears the Published claim. The
// controlled wall/monotonic clock supplies the signed-record clock while the
// current-thread Tokio clock drives only the 60s refresh timer; both are
// advanced explicitly. The initial PUT completes while time is running, and
// actor barriers establish timer setup and subsequent responsiveness.
#[tokio::test]
async fn refresh_failure_clears_published() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let clock = TestClock::new(1_700_000_000_000_000);
    let mut owner = RuntimeOwner::start_controlled(
        Identity::from_seed([0xE3; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
        clock.clone(),
    )
    .expect("owned DHT binds on loopback");

    let address = TransportAddr::Ip("127.0.0.1:9200".parse().expect("published address"));
    let mut put = Box::pin(owner.replace(vec![address]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut put => panic!("initial PUT ended before hold: {result:?}"),
    };
    peer.acknowledge(source, &transaction).await;
    put.await
        .expect("initial PUT acknowledged while time is running");
    let initial_generation = match owner.publication_status() {
        PublicationStatus::Published { generation, .. } => generation,
        status => panic!("initial PUT must be Published before refresh: {status:?}"),
    };
    owner
        .barrier()
        .await
        .expect("initial completion and timer setup are observable");

    let mut updates = owner.publication_updates();
    assert!(matches!(
        *updates.borrow_and_update(),
        PublicationStatus::Published { .. }
    ));
    clock.set_wall(1_700_000_060_000_000);
    clock.set_monotonic(60_000_000);
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    tokio::time::resume();

    // Resume real network work before capturing and rejecting the refresh PUT.
    let (source, transaction, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), peer.capture_put())
            .await
            .expect("refresh PUT arrives within the bounded observation window");
    peer.reject(source, &transaction).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), updates.changed())
        .await
        .expect("publisher processes the rejected refresh within the bounded wait")
        .expect("publication watch remains open");
    assert_eq!(
        *updates.borrow_and_update(),
        PublicationStatus::Unavailable {
            generation: initial_generation
        }
    );
    let receipt = owner
        .barrier()
        .await
        .expect("publisher remains responsive after refresh rejection");
    assert!(
        receipt.refresh_count > 0,
        "refresh timer fired before rejection"
    );

    owner
        .close()
        .await
        .expect("Mainline publisher and actor joined");
}

// Regression: a delayed real PUT acknowledgment must not extend the
// Published freshness horizon beyond 300 seconds from packet signing.
#[tokio::test]
async fn delayed_put_ack_does_not_extend_signed_freshness() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let clock = TestClock::new(1_700_000_000_000_000);
    let mut owner = RuntimeOwner::start_controlled(
        Identity::from_seed([0xF5; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
        clock.clone(),
    )
    .expect("owned DHT binds on loopback");

    let address = TransportAddr::Ip("127.0.0.1:9201".parse().expect("published address"));
    let mut put = Box::pin(owner.replace(vec![address]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut put => panic!("initial PUT ended before hold: {result:?}"),
    };
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Pending { .. }
    ));
    // Packet signing necessarily preceded this independent capture instant.
    let before_ack = tokio::time::Instant::now();
    clock.set_wall(1_700_000_005_000_000);
    clock.set_monotonic(5_000_000);
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    tokio::time::resume();
    peer.acknowledge(source, &transaction).await;
    put.await.expect("delayed PUT acknowledgment succeeds");

    let PublicationStatus::Published { expires_at, .. } = owner.publication_status() else {
        panic!("acknowledged PUT must be Published");
    };
    assert!(
        expires_at <= before_ack + std::time::Duration::from_secs(300),
        "PUT acknowledgment delay cannot extend signed freshness past 300s"
    );
    owner
        .close()
        .await
        .expect("publisher and actor joins observed");
}

fn signed_envelope(put: &super::fixture::CapturedPut) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(104 + put.value.len());
    envelope.extend_from_slice(&put.key);
    envelope.extend_from_slice(&put.signature);
    envelope.extend_from_slice(&put.sequence.to_be_bytes());
    envelope.extend_from_slice(&put.value);
    envelope
}
