// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::fixture::LoopbackPeer;
use crate::identity::Identity;
use iroh_base::TransportAddr;
use std::future::Future;

#[tokio::test]
async fn requester_cancellation_revokes_a_held_initial_put() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let mut owner = super::super::RuntimeOwner::start(
        Identity::from_seed([0x92; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT");

    let before = owner.barrier().await.expect("owner barrier before request");
    assert_eq!(before.cleanup_count, 0);

    let mut request = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9012".parse().expect("published address"),
    )]));
    let held = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut request => panic!("replace acknowledged before held PUT release: {result:?}"),
    };
    drop(request);

    let after = owner
        .barrier()
        .await
        .expect("owner observes requester cancellation cleanup");
    assert!(!after.active, "cancelled initial generation is revoked");
    assert!(
        after.cleanup_count > before.cleanup_count,
        "actor cleanup receipt observed"
    );
    assert_eq!(after.refresh_count, 0, "no periodic refresh occurred");
    peer.acknowledge(held.0, &held.1).await;
    owner
        .close()
        .await
        .expect("publisher and DHT joins observed");
}

#[tokio::test]
async fn empty_replacement_withdraws_held_publication_and_owner_stays_live() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let mut owner = super::super::RuntimeOwner::start(
        Identity::from_seed([0x94; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT");

    let mut initial = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9014".parse().expect("initial address"),
    )]));
    let held = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut initial => panic!("initial replace finished before held PUT: {result:?}"),
    };
    let withdrawal = owner.replace(Vec::new());
    let (initial_result, withdrawal_result) = tokio::join!(initial, withdrawal);
    assert!(
        initial_result.is_err(),
        "withdrawal revokes held publication"
    );
    withdrawal_result.expect("empty replacement withdraws publication");
    peer.acknowledge(held.0, &held.1).await;
    owner
        .withdraw()
        .await
        .expect("owner remains usable after withdrawal");
    owner
        .close()
        .await
        .expect("publisher and DHT joins observed");
}

#[tokio::test]
async fn valid_replacement_publishes_new_signed_generation_after_old_cleanup() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let mut owner = super::super::RuntimeOwner::start(
        Identity::from_seed([0x95; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT");
    let observer = owner
        .dht_handle()
        .expect("actual owned DHT handle")
        .publication_observer();
    let mut initial = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9015".parse().expect("initial address"),
    )]));
    let old = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut initial => panic!("initial replace finished before held PUT: {result:?}"),
    };
    let mut replacement = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9016".parse().expect("replacement address"),
    )]));
    let (old_result, new) = tokio::join!(initial, async {
        tokio::select! {
            held = peer.capture_put() => held,
            result = &mut replacement => panic!("replacement acknowledged before new PUT: {result:?}"),
        }
    },);
    assert!(
        old_result.is_err(),
        "revoked publication cannot acknowledge"
    );
    assert!(
        new.2.sequence > old.2.sequence,
        "replacement has newer sequence"
    );
    assert_ne!(
        new.2.value, old.2.value,
        "replacement carries new signed addresses"
    );

    let cursor = observer.cursor();
    peer.acknowledge(old.0, &old.1).await;
    let transaction = u32::from_be_bytes(
        old.1
            .as_slice()
            .try_into()
            .expect("four-byte Mainline transaction"),
    );
    observer
        .wait_processed_after(cursor, transaction)
        .await
        .expect("actual stale reply processed");
    let mut replacement = replacement;
    std::future::poll_fn(|cx| {
        assert!(
            std::future::Future::poll(replacement.as_mut(), cx).is_pending(),
            "stale reply cannot complete replacement"
        );
        std::task::Poll::Ready(())
    })
    .await;
    peer.acknowledge(new.0, &new.1).await;
    replacement
        .await
        .expect("new generation acknowledged by real peer");
    owner
        .close()
        .await
        .expect("publisher and DHT joins observed");
}

#[tokio::test]
async fn deadline_expiring_during_real_put_cleans_generation_and_owner_recovers() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let mut owner = super::super::RuntimeOwner::start(
        Identity::from_seed([0x97; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT");
    let observer = owner
        .dht_handle()
        .expect("actual owned DHT handle")
        .publication_observer();
    let hold = observer
        .hold_cleanup()
        .expect("retain actual PUT cleanup through caller deadline");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut request = Box::pin(owner.replace_until(
        vec![TransportAddr::Ip(
            "127.0.0.1:9020".parse().expect("published address"),
        )],
        deadline,
    ));
    let held = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut request => panic!("replace completed before real peer held its PUT: {result:?}"),
    };

    std::future::poll_fn(|cx| {
        assert!(
            request.as_mut().poll(cx).is_pending(),
            "cleanup hold keeps the caller pending"
        );
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::pause();
    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    let result = request.await;
    assert!(
        matches!(&result, Err(super::super::RuntimeError::DeadlineExceeded)),
        "original caller deadline must win while actual cleanup is held: {result:?}"
    );
    observer.wait_cleanup_held().await;
    hold.release();
    tokio::time::resume();
    let cleanup = owner
        .barrier()
        .await
        .expect("actual actor cleanup receipt after deadline");
    assert!(!cleanup.active, "expired held publication is revoked");
    assert!(
        cleanup.cleanup_count > 0,
        "real cancelled PUT cleanup was observed"
    );

    peer.acknowledge(held.0, &held.1).await;
    let replacement = owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9021".parse().expect("recovery address"),
    )]);
    let receipt = peer.serve_until_put();
    let (result, receipt) = tokio::join!(replacement, receipt);
    result.expect("owner accepts later real publication");
    assert!(
        receipt.sequence > held.2.sequence,
        "recovery uses a newer signed generation"
    );
    owner
        .close()
        .await
        .expect("publisher and DHT joins observed");
}

#[tokio::test]
async fn close_timeout_and_cancellation_retain_real_resources_until_cleanup_joins() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let mut owner = super::super::RuntimeOwner::start(
        Identity::from_seed([0x98; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT");
    let actor_handle = owner.dht_handle().expect("actual owned DHT handle");
    let observer = actor_handle.publication_observer();
    let hold = observer
        .hold_cleanup()
        .expect("hold production actor cleanup");
    let local_address = actor_handle.info().await.expect("actor bound").local_addr();

    let mut request = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9022".parse().expect("published address"),
    )]));
    let _held_put = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut request => panic!("replace completed before real peer held its PUT: {result:?}"),
    };
    drop(request);
    observer.wait_cleanup_held().await;

    tokio::time::pause();
    {
        let mut closing = Box::pin(owner.close());
        std::future::poll_fn(|cx| {
            assert!(
                closing.as_mut().poll(cx).is_pending(),
                "close waits for retained publisher cleanup"
            );
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        assert!(matches!(
            closing.await,
            Err(super::super::RuntimeError::CloseTimeout)
        ));
    }
    assert!(owner.publisher.is_some());
    assert!(owner.dht.is_some());
    assert!(
        tokio::net::UdpSocket::bind(local_address).await.is_err(),
        "actual DHT socket remains bound"
    );

    {
        let mut closing = Box::pin(owner.close());
        std::future::poll_fn(|cx| {
            assert!(
                closing.as_mut().poll(cx).is_pending(),
                "second close still waits for cleanup"
            );
            std::task::Poll::Ready(())
        })
        .await;
    }
    assert!(owner.publisher.is_some());
    assert!(owner.dht.is_some());

    hold.release();
    tokio::time::resume();
    owner
        .close()
        .await
        .expect("released actor cleanup joins publisher and DHT");
    owner.close().await.expect("completed close is idempotent");
    assert!(
        actor_handle.info().await.is_err(),
        "joined actor handle is closed"
    );
    let rebound = tokio::net::UdpSocket::bind(local_address)
        .await
        .expect("joined actor released UDP socket");
    drop(rebound);
}

#[tokio::test]
async fn wall_clock_rollback_remains_terminal_after_wall_time_catches_up() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let identity = Identity::from_seed([0x96; 32]);
    let clock = super::super::TestClock::new(1_700_000_000_000_000);
    let mut owner = super::super::RuntimeOwner::start_controlled(
        identity,
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
        clock.clone(),
    )
    .expect("owned DHT");
    let initial = owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9017".parse().expect("published address"),
    )]);
    let initial_put = peer.serve_until_put();
    let (result, _) = tokio::join!(initial, initial_put);
    result.expect("initial publication acknowledged");

    clock.set(1_699_999_999_999_999);
    assert!(matches!(
        owner
            .replace(vec![TransportAddr::Ip(
                "127.0.0.1:9018".parse().expect("replacement address"),
            )])
            .await,
        Err(super::super::RuntimeError::Publish(
            crate::native_discovery::runtime::publisher::PublishError::ClockFault
        ))
    ));
    clock.set(1_700_000_000_000_001);
    assert!(
        matches!(
            owner
                .replace(vec![TransportAddr::Ip(
                    "127.0.0.1:9019".parse().expect("later address"),
                )])
                .await,
            Err(super::super::RuntimeError::Closed)
        ),
        "wall-clock catch-up does not resume a faulted publisher"
    );
    owner
        .close()
        .await
        .expect("publisher and DHT joins observed");
}

#[tokio::test]
async fn invalid_replacement_revokes_held_generation_before_validation() {
    use crate::native_discovery::address::SnapshotError;
    use crate::native_discovery::runtime::publisher::PublishError;

    for (snapshot, expected) in [
        (
            vec![TransportAddr::Ip("127.0.0.1:0".parse().expect("zero port"))],
            SnapshotError::InvalidAddress,
        ),
        (
            vec![TransportAddr::Relay(
                "https://relay.invalid/".parse().expect("relay fixture"),
            )],
            SnapshotError::UnsupportedTransport,
        ),
        (
            vec![TransportAddr::Custom(iroh_base::CustomAddr::from_parts(
                0x5348, &[0; 16],
            ))],
            SnapshotError::UnsupportedTransport,
        ),
    ] {
        let mut peer = LoopbackPeer::bind().await;
        let bootstrap = match peer.address {
            std::net::SocketAddr::V4(address) => address,
            std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
        };
        let mut owner = super::super::RuntimeOwner::start(
            Identity::from_seed([0x93; 32]),
            "127.0.0.1:0".parse().expect("loopback bind"),
            &[bootstrap],
        )
        .expect("owned DHT");
        let observer = owner
            .dht_handle()
            .expect("actual actor handle")
            .publication_observer();
        let hold = observer
            .hold_cleanup()
            .expect("hold actual generation cleanup");

        let mut initial = Box::pin(owner.replace(vec![TransportAddr::Ip(
            "127.0.0.1:9013".parse().expect("initial address"),
        )]));
        let held = tokio::select! {
            held = peer.capture_put() => held,
            result = &mut initial => panic!("initial replace acknowledged before held PUT release: {result:?}"),
        };
        let mut invalid = Box::pin(owner.replace(snapshot));
        tokio::select! {
            biased;
            result = &mut invalid => panic!("replacement replied before actual cleanup: {result:?}"),
            _ = observer.wait_cleanup_held() => {}
        }
        hold.release();
        let (old_result, invalid_result) = tokio::join!(initial, invalid);
        assert!(old_result.is_err(), "revoked generation cannot acknowledge");
        assert!(
            matches!(
                &invalid_result,
                Err(super::super::RuntimeError::Publish(PublishError::Snapshot(error))) if *error == expected
            ),
            "invalid snapshot returns the exact validation error: {invalid_result:?}"
        );

        peer.acknowledge(held.0, &held.1).await;
        owner.withdraw().await.expect("publisher remains available");
        owner
            .close()
            .await
            .expect("publisher and DHT joins observed");
    }
}
