// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::{PublisherState, RuntimeError, RuntimeOwner, endpoint_key, to_mutable};
use super::fixture::{CapturedPut, LoopbackPeer};
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::ClockSample;
use iroh_base::TransportAddr;
use std::future::Future;
use std::time::Duration;

fn address(port: u16) -> TransportAddr {
    TransportAddr::Ip(
        format!("127.0.0.1:{port}")
            .parse()
            .expect("loopback address"),
    )
}

fn bootstrap(peer: &LoopbackPeer) -> std::net::SocketAddrV4 {
    match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    }
}

#[tokio::test]
async fn expired_absolute_deadline_does_not_enqueue_or_change_cleanup_state() {
    let peer = LoopbackPeer::bind().await;
    let mut owner = RuntimeOwner::start(
        Identity::from_seed([0xa1; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap(&peer)],
    )
    .expect("owned loopback DHT");
    let before = owner
        .barrier()
        .await
        .expect("initial actual cleanup receipt");
    let result = owner
        .replace_until(vec![address(9120)], tokio::time::Instant::now())
        .await;
    assert!(matches!(result, Err(RuntimeError::DeadlineExceeded)));
    let after = owner
        .barrier()
        .await
        .expect("owner responds after expired request");
    assert_eq!(
        after, before,
        "expired caller did not change actual cleanup state"
    );
    assert!(!after.active);
    owner.close().await.expect("owner and actor joined");
}

#[tokio::test]
async fn cancelled_real_put_cleanup_allows_later_real_publication() {
    let mut peer = LoopbackPeer::bind().await;
    let mut owner = RuntimeOwner::start(
        Identity::from_seed([0xa2; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap(&peer)],
    )
    .expect("owned loopback DHT");
    let mut old = Box::pin(owner.replace(vec![address(9121)]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut old => panic!("PUT terminated before held fixture reply: {result:?}"),
    };
    drop(old);
    let cleanup = owner
        .barrier()
        .await
        .expect("actual old PUT cleanup barrier");
    assert!(
        !cleanup.active,
        "cancelled requester did not leave an active generation"
    );
    let (result, receipt) =
        tokio::join!(owner.replace(vec![address(9122)]), peer.serve_until_put());
    assert!(
        result.is_ok(),
        "later production replacement receives actual PUT acknowledgement"
    );
    assert_eq!(
        receipt.key,
        Identity::from_seed([0xa2; 32]).public_key_bytes()
    );
    peer.acknowledge(source, &transaction).await;
    owner.close().await.expect("owner and actor joined");
}

#[tokio::test]
async fn periodic_refresh_observes_one_fresh_put_after_elapsed_intervals() {
    let mut peer = LoopbackPeer::bind().await;
    let clock = super::super::TestClock::new(1_700_000_000_000_000);
    let mut owner = RuntimeOwner::start_controlled(
        Identity::from_seed([0xa3; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap(&peer)],
        clock.clone(),
    )
    .expect("owned loopback DHT");
    let (first_result, initial) =
        tokio::join!(owner.replace(vec![address(9123)]), peer.serve_until_put());
    assert!(first_result.is_ok());
    let initial_receipt = owner.barrier().await.expect("initial publication receipt");
    assert_eq!(initial_receipt.refresh_count, 0);

    tokio::time::pause();
    clock.set(initial.sequence + 180_000_000);
    clock.set_monotonic(180_000_000);
    tokio::time::advance(Duration::from_secs(180)).await;
    tokio::time::resume();
    let refreshed = peer.serve_until_put().await;
    assert!(refreshed.sequence > initial.sequence);
    assert_ne!(refreshed.signature, initial.signature);
    assert_eq!(refreshed.value, initial.value);
    let stable = owner.barrier().await.expect("refresh cleanup observation");
    assert!(
        stable.active,
        "successful production refresh remains published"
    );
    assert_eq!(
        stable.refresh_count, 1,
        "one refresh completed on the production path"
    );
    owner.close().await.expect("owner and actor joined");
}

#[tokio::test]
async fn queued_replace_keeps_original_deadline_through_held_cleanup() {
    let mut peer = LoopbackPeer::bind().await;
    let identity = Identity::from_seed([0xc1; 32]);
    let mut owner = RuntimeOwner::start(
        identity.clone(),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap(&peer)],
    )
    .expect("owned loopback DHT");
    let mut old = Box::pin(owner.replace(vec![address(9401)]));
    let held = peer.capture_put();
    let (source, transaction, initial) = tokio::select! {
        held = held => held,
        result = &mut old => panic!("initial PUT ended before held reply: {result:?}"),
    };
    let handle = owner.dht_handle().expect("actual owned DHT handle");
    let observer = handle.publication_observer();
    let old_cleanup = observer.hold_cleanup().expect("hold actual PUT cleanup");
    drop(old);
    let mut cleanup_wait = Box::pin(observer.wait_cleanup_held());
    cleanup_wait.as_mut().await;

    tokio::time::pause();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut queued = Box::pin(owner.replace_until(vec![address(9402)], deadline));
    std::future::poll_fn(|cx| {
        assert!(
            queued.as_mut().poll(cx).is_pending(),
            "queued caller remains pending while cleanup is held"
        );
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(matches!(
        (&mut queued).await,
        Err(RuntimeError::DeadlineExceeded)
    ));
    drop(queued);
    old_cleanup.release();
    drop(cleanup_wait);
    tokio::time::resume();

    let cleanup = owner
        .barrier()
        .await
        .expect("old generation cleanup receipt");
    assert!(cleanup.cleanup_count > 0);
    assert!(!cleanup.active);
    let (result, replacement) =
        tokio::join!(owner.replace(vec![address(9403)]), peer.serve_until_put());
    assert!(
        result.is_ok(),
        "owner remains usable after queued deadline expires"
    );
    let expected = Identity::from_seed([0xc1; 32]);
    assert_eq!(replacement.key, expected.public_key_bytes());
    assert_eq!(
        decoded_addresses(&replacement),
        vec!["127.0.0.1:9403".parse().expect("published endpoint")]
    );
    peer.acknowledge(source, &transaction).await;
    owner.close().await.expect("publisher and actor joined");
}

fn decoded_addresses(captured: &CapturedPut) -> Vec<std::net::SocketAddr> {
    use iroh_dns::endpoint_info::EndpointInfo;
    use iroh_dns::pkarr::SignedPacket;
    let mut envelope = Vec::with_capacity(104 + captured.value.len());
    envelope.extend_from_slice(&captured.key);
    envelope.extend_from_slice(&captured.signature);
    envelope.extend_from_slice(&captured.sequence.to_be_bytes());
    envelope.extend_from_slice(&captured.value);
    let packet = SignedPacket::from_bytes(&envelope).expect("captured PUT signature verifies");
    EndpointInfo::from_pkarr_signed_packet(&packet)
        .expect("captured PUT decodes as endpoint info")
        .ip_addrs()
        .copied()
        .collect()
}

#[tokio::test]
async fn request_budget_capacity_recovers_after_admission_cleanup() {
    let mut peer = LoopbackPeer::bind().await;
    let mut owner = RuntimeOwner::start(
        Identity::from_seed([0xb0; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap(&peer)],
    )
    .expect("owned loopback DHT");
    let handle = owner.dht_handle().expect("actual owned DHT handle");
    let mut admissions = Vec::with_capacity(24);
    for index in 0..24u8 {
        let identity = Identity::from_seed([index + 1; 32]);
        let mut publisher =
            PublisherState::new(endpoint_key(&identity).expect("valid identity key"));
        let sample = ClockSample {
            wall_us: 1_700_000_000_000_000,
            monotonic_before_us: 0,
            monotonic_after_us: 0,
        };
        let (_, snapshot) = publisher
            .replace(&identity, &[address(9300 + u16::from(index))], sample)
            .expect("signed mutable item");
        let item = to_mutable(&snapshot.expect("nonempty snapshot")).expect("convert signed item");
        admissions.push(
            handle
                .put_mutable_until(item, tokio::time::Instant::now() + Duration::from_secs(10))
                .expect("admission acquires request budget before polling"),
        );
    }

    let result = owner.replace(vec![address(9200)]).await;
    assert!(matches!(result, Err(RuntimeError::PutAdmission(error))
        if error.error == n0_mainline::ResourceError::OperationLimit
            && error.cleanup == n0_mainline::OwnedPutCleanup::Clean));
    let receipt = owner
        .barrier()
        .await
        .expect("owner remains responsive after local rejection");
    assert!(!receipt.active);

    for mut admission in admissions {
        assert_eq!(
            admission.cancel_and_wait().await,
            n0_mainline::OwnedPutCleanup::Clean
        );
    }
    let (result, receipt) =
        tokio::join!(owner.replace(vec![address(9201)]), peer.serve_until_put());
    assert!(
        result.is_ok(),
        "request capacity recovers for a real acknowledged publication"
    );
    assert_eq!(
        receipt.key,
        Identity::from_seed([0xb0; 32]).public_key_bytes()
    );
    owner.close().await.expect("publisher and actor joined");
}
