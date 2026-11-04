// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use n0_mainline::{
    Id, MutableItem, OwnedDht, OwnedDhtHandle, OwnedPutOperation, ResourceError,
};

fn loopback_bootstrap() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral loopback bootstrap socket");
    let addr = match socket.local_addr().expect("bootstrap socket address") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("loopback bootstrap socket is IPv4"),
    };
    (socket, addr)
}

fn mutable_item(sequence: i64) -> MutableItem {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x25; 32]);
    MutableItem::new(&signer, b"owned API test", sequence, None)
}

#[tokio::test]
async fn owned_api_handle_is_limited_and_reports_shutdown() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained: OwnedDhtHandle = owner.handle();
    let info = retained.info().await.expect("actor info before shutdown");
    let actor_addr = info.local_addr();
    assert_eq!(
        info.id(),
        owner.handle().info().await.expect("same actor info").id()
    );

    drop(bootstrap);
    owner.close().await.expect("join owned actor");
    assert!(matches!(
        retained.resolve_mutable(Id::random()).await,
        Err(ResourceError::QueryCancelled)
    ));
    assert!(matches!(
        retained.info().await,
        Err(ResourceError::QueryCancelled)
    ));
    assert!(matches!(
        retained.put_mutable(mutable_item(1)).await,
        Err(ResourceError::QueryCancelled)
    ));

    let rebound = UdpSocket::bind(actor_addr).expect("owned actor released its bound socket after join");
    drop(rebound);
}

#[tokio::test]
async fn owned_api_put_cancellation_finishes_operation() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained = owner.handle();
    let mut operation: OwnedPutOperation = retained
        .put_mutable(mutable_item(1))
        .await
        .expect("admit mutable put");
    operation.cancel_and_wait().await.expect("cancel and clean up operation");
    assert!(retained.info().await.expect("actor remains live").local_addr().port() > 0);
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_put_rejects_invalid_profiles() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained = owner.handle();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x26; 32]);

    let invalid_items = [
        MutableItem::new(&signer, &vec![0; 1001], 1, None),
        MutableItem::new(&signer, b"negative", -1, None),
        MutableItem::new(&signer, b"salted", 1, Some(b"salt")),
    ];
    for item in invalid_items {
        assert!(matches!(
            retained.put_mutable(item).await,
            Err(ResourceError::InvalidMutableItem)
        ));
    }

    let valid = MutableItem::new(&signer, b"valid", 1, None);
    let mut sig = *valid.signature();
    sig[0] ^= 1;
    let invalid_signature = MutableItem::new_signed_unchecked(
        *valid.key(),
        sig,
        valid.value(),
        valid.seq(),
        None,
    );
    assert!(matches!(
        retained.put_mutable(invalid_signature).await,
        Err(ResourceError::InvalidMutableItem)
    ));

    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_absolute_deadline_reports_clean_pre_enqueue_failure() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    bootstrap
        .set_nonblocking(true)
        .expect("set bootstrap socket nonblocking");
    let mut owner = OwnedDht::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_addr],
    )
    .expect("bind owned DHT");
    let retained = owner.handle();
    let expired = tokio::time::Instant::now();
    let error = retained
        .put_mutable_until(mutable_item(1), expired)
        .expect_err("expired absolute deadline");
    assert_eq!(error.error, ResourceError::DeadlineExceeded);
    assert_eq!(error.cleanup, n0_mainline::OwnedPutCleanup::Clean);
    let mut bytes = [0u8; 2048];
    assert_eq!(
        bootstrap
            .recv_from(&mut bytes)
            .expect_err("expired admission sent no datagram")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_admission_can_be_cancelled_before_poll() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_addr],
    )
    .expect("bind owned DHT");
    let retained = owner.handle();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut admission = retained
        .put_mutable_until(mutable_item(2), deadline)
        .expect("start bounded admission");
    assert_eq!(
        admission.cancel_and_wait().await,
        n0_mainline::OwnedPutCleanup::Clean,
    );
    assert!(retained.info().await.is_ok(), "actor remains usable");
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_cleanup_hold_observes_real_actor_cleanup() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_addr],
    )
    .expect("bind owned DHT");
    let retained = owner.handle();
    let observer = retained.publication_observer();
    let mut item = mutable_item(3);
    let target = *item.target();
    let hold = observer
        .hold_cleanup_for_target(target)
        .expect("acquire target-specific cleanup hold");
    assert!(observer.hold_cleanup_for_target(target).is_err(), "cleanup hold is bounded to one");

    let mut admission = retained
        .put_mutable_until(item, tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .expect("start bounded PUT admission");
    admission.wait().await.expect("admit PUT operation");
    let mut operation = admission.take_operation().expect("admitted operation retained");
    let mut cleanup = Box::pin(operation.cancel_and_wait());
    std::future::poll_fn(|cx| {
        assert!(cleanup.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    observer.wait_cleanup_held().await;
    std::future::poll_fn(|cx| {
        assert!(cleanup.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;

    hold.release();
    cleanup.await.expect("cleanup completes after releasing hold");
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test(start_paused = true)]
async fn owned_api_far_future_unpolled_admission_is_clamped_before_enqueue() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_addr],
    )
    .expect("bind owned DHT");
    let retained = owner.handle();
    let entry = tokio::time::Instant::now();
    let mut admission = retained
        .put_mutable_until(mutable_item(4), entry + Duration::from_secs(3600))
        .expect("create bounded admission");
    let mut other_admissions: Vec<_> = (0..23)
        .map(|index| {
            retained
                .put_mutable_until(
                    mutable_item(100 + index),
                    entry + Duration::from_secs(3600),
                )
                .expect("create additional bounded admission")
        })
        .collect();
    let error = retained
        .put_mutable_until(mutable_item(200), entry + Duration::from_secs(3600))
        .expect_err("25th admission exceeds capacity");
    assert_eq!(error.error, ResourceError::OperationLimit);
    assert_eq!(error.cleanup, n0_mainline::OwnedPutCleanup::Clean);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(tokio::time::Instant::now(), entry + Duration::from_secs(10));

    let mut wait = Box::pin(admission.wait());
    std::future::poll_fn(|cx| {
        match wait.as_mut().poll(cx) {
            std::task::Poll::Ready(Err(error)) => {
                assert_eq!(error.error, ResourceError::DeadlineExceeded);
                assert_eq!(error.cleanup, n0_mainline::OwnedPutCleanup::Clean);
            }
            std::task::Poll::Ready(Ok(())) => panic!("expired admission unexpectedly succeeded"),
            std::task::Poll::Pending => panic!("expired admission enqueued and remained pending"),
        }
        std::task::Poll::Ready(())
    })
    .await;
    drop(wait);
    let mut replacement = retained
        .put_mutable_until(
            mutable_item(201),
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .expect("expired principal lease was released");
    assert_eq!(
        replacement.cancel_and_wait().await,
        n0_mainline::OwnedPutCleanup::Clean
    );
    for other in &mut other_admissions {
        assert_eq!(
            other.cancel_and_wait().await,
            n0_mainline::OwnedPutCleanup::Clean
        );
    }
    assert_eq!(admission.cancel_and_wait().await, n0_mainline::OwnedPutCleanup::Clean);
    assert_eq!(admission.cancel_and_wait().await, n0_mainline::OwnedPutCleanup::Clean);

    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test(start_paused = true)]
async fn owned_api_shorter_deadline_expires_before_default_clamp() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_addr],
    )
    .expect("bind owned DHT");
    let retained = owner.handle();
    let entry = tokio::time::Instant::now();
    let mut admission = retained
        .put_mutable_until(mutable_item(5), entry + Duration::from_secs(3))
        .expect("create short bounded admission");
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(tokio::time::Instant::now(), entry + Duration::from_secs(3));

    let mut wait = Box::pin(admission.wait());
    std::future::poll_fn(|cx| {
        match wait.as_mut().poll(cx) {
            std::task::Poll::Ready(Err(error)) => {
                assert_eq!(error.error, ResourceError::DeadlineExceeded);
                assert_eq!(error.cleanup, n0_mainline::OwnedPutCleanup::Clean);
            }
            std::task::Poll::Ready(Ok(())) => panic!("expired admission unexpectedly succeeded"),
            std::task::Poll::Pending => panic!("expired admission enqueued and remained pending"),
        }
        std::task::Poll::Ready(())
    })
    .await;
    drop(wait);
    assert_eq!(
        admission.cancel_and_wait().await,
        n0_mainline::OwnedPutCleanup::Clean
    );

    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_put_accepts_maximum_value_size() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        &[bootstrap_addr],
    )
    .expect("bind owned DHT");
    let retained = owner.handle();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x26; 32]);
    let mut operation = retained
        .put_mutable(MutableItem::new(&signer, &vec![0; 1000], 1, None))
        .await
        .expect("admit maximum-size mutable item");
    operation.cancel_and_wait().await.expect("cancel and clean up operation");
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_get_expired_absolute_deadline_never_enqueues() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    bootstrap.set_nonblocking(true).expect("nonblocking peer");
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("owned loopback DHT");
    let handle = owner.handle();
    assert!(matches!(
        handle
            .resolve_mutable_until(Id::random(), tokio::time::Instant::now())
            .await,
        Err(ResourceError::DeadlineExceeded)
    ));
    let mut bytes = [0; 2048];
    assert_eq!(
        bootstrap
            .recv_from(&mut bytes)
            .expect_err("expired GET sent no packet")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    owner.close().await.expect("actual actor joined");
}

#[tokio::test(start_paused = true)]
async fn owned_api_get_original_deadline_precedes_budget_admission_after_waiting() {
    for elapsed in [0, 3] {
        let (bootstrap, bootstrap_addr) = loopback_bootstrap();
        let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
            .expect("owned loopback DHT");
        let handle = owner.handle();
        let entry = tokio::time::Instant::now();
        let mut admissions: Vec<_> = (0..24)
            .map(|index| {
                handle
                    .put_mutable_until(mutable_item(300 + index), entry + Duration::from_secs(10))
                    .expect("retain actual request budget before polling")
            })
            .collect();
        let mut request = Box::pin(
            handle.resolve_mutable_until(Id::random(), entry + Duration::from_secs(elapsed)),
        );
        if elapsed != 0 {
            tokio::time::advance(Duration::from_secs(elapsed)).await;
        }
        std::future::poll_fn(|cx| {
            match request.as_mut().poll(cx) {
                std::task::Poll::Ready(Err(ResourceError::DeadlineExceeded)) => {}
                other => panic!("original deadline must precede full-budget admission: {other:?}"),
            }
            std::task::Poll::Ready(())
        })
        .await;
        drop(request);
        for admission in &mut admissions {
            assert_eq!(
                admission.cancel_and_wait().await,
                n0_mainline::OwnedPutCleanup::Clean
            );
        }
        drop(bootstrap);
        owner.close().await.expect("actual actor joined");
    }
}

#[tokio::test(start_paused = true)]
async fn owned_api_get_short_and_far_future_deadlines_keep_the_effective_bound() {
    for (requested, effective) in [(3, 3), (3600, 10)] {
        let (bootstrap, bootstrap_addr) = loopback_bootstrap();
        let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
            .expect("owned loopback DHT");
        let handle = owner.handle();
        let local = handle.info().await.expect("actual actor info").local_addr();
        let entry = tokio::time::Instant::now();
        let mut request = Box::pin(
            handle.resolve_mutable_until(Id::random(), entry + Duration::from_secs(requested)),
        );
        std::future::poll_fn(|cx| {
            assert!(
                request.as_mut().poll(cx).is_pending(),
                "GET admission is pending"
            );
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(effective)).await;
        std::future::poll_fn(|cx| {
            match request.as_mut().poll(cx) {
                std::task::Poll::Ready(Err(ResourceError::DeadlineExceeded)) => {}
                other => panic!("GET must expire at its effective original bound: {other:?}"),
            }
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(
            tokio::time::Instant::now(),
            entry + Duration::from_secs(effective)
        );
        drop(request);
        drop(bootstrap);
        owner.close().await.expect("actual actor joined");
        drop(UdpSocket::bind(local).expect("joined actor released its real socket"));
    }
}
