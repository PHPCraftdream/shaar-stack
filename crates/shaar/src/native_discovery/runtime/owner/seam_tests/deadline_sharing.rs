// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{RuntimeError, WALL, capture_get, record, setup};
use iroh_base::{EndpointId, TransportAddr};
use n0_mainline::MutableItem;
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn held_sample_command_and_slow_get_share_one_absolute_deadline() {
    let (mut peer, mut owner, _clock) = setup(0x7d).await;
    let observer = owner
        .dht_handle()
        .expect("actual actor handle")
        .publication_observer();
    let hold = observer.hold_cleanup().expect("hold actual PUT cleanup");

    // Initial publication with the PUT held at the peer.
    let mut replace = Box::pin(owner.replace_until(
        vec![TransportAddr::Ip(
            "127.0.0.1:9005".parse().expect("published address"),
        )],
        Instant::now() + Duration::from_secs(30),
    ));
    let held_put = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replace => panic!("replacement completed before the peer saw a PUT: {result:?}"),
    };
    // Withdraw while the PUT is in flight: the publisher starts held cleanup
    // and stops answering commands until the cleanup receipt is released.
    let mut withdrawal = Box::pin(owner.withdraw());
    std::future::poll_fn(|cx| {
        assert!(
            withdrawal.as_mut().poll(cx).is_pending(),
            "withdrawal cannot complete while cleanup is held",
        );
        std::task::Poll::Ready(())
    })
    .await;
    observer.wait_cleanup_held().await;
    // Drain the held PUT so no late PUT traffic reaches the peer below.
    peer.acknowledge(held_put.0, &held_put.1).await;

    // Pause first, then fix the ORIGINAL absolute deadline from the paused
    // clock: every later assertion is anchored to this one instant.
    tokio::time::pause();
    let deadline = Instant::now() + Duration::from_secs(10);

    let item = record(0x7e, WALL);
    let key = EndpointId::from_bytes(item.key()).expect("record key");
    let target = MutableItem::target_from_key(item.key(), None);
    drop(replace);
    drop(withdrawal);
    let mut request = Box::pin(owner.resolve_until(key, deadline));
    std::future::poll_fn(|cx| {
        assert!(
            request.as_mut().poll(cx).is_pending(),
            "held cleanup keeps the clock-sample command pending",
        );
        std::task::Poll::Ready(())
    })
    .await;

    // The held sample-command wait consumes part of the one caller budget.
    tokio::time::advance(Duration::from_millis(50)).await;
    std::future::poll_fn(|cx| {
        assert!(
            request.as_mut().poll(cx).is_pending(),
            "the sample wait is still pending after consumed budget",
        );
        std::task::Poll::Ready(())
    })
    .await;

    // Release the cleanup: the sample is answered and the GET starts under
    // the SAME original absolute deadline.
    hold.release();
    let (get_source, get_transaction) = capture_get(&mut peer, target, &mut request).await;

    // Advancing exactly to the original absolute deadline must fail the GET.
    // The outer bound is 1 ms: a deadline reset at GET start would expire only
    // about 50 ms later, so the request would still be pending and time out here.
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    let result = tokio::time::timeout(Duration::from_millis(1), request)
        .await
        .expect("the request ends at the original absolute deadline, not a reset one");
    assert!(
        matches!(result, Err(RuntimeError::DeadlineExceeded)),
        "the GET fails at the original absolute deadline: {result:?}"
    );
    tokio::time::resume();

    // The late response cannot commit cache state: a later resolve issues a
    // fresh GET with a new transaction.
    peer.reply_get(get_source, &get_transaction, &item).await;
    let mut retry = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (retry_source, retry_transaction) = capture_get(&mut peer, target, &mut retry).await;
    assert_ne!(
        retry_transaction, get_transaction,
        "no cache commit after the expired shared deadline",
    );
    peer.reply_get(retry_source, &retry_transaction, &item)
        .await;
    let recovered = tokio::time::timeout(Duration::from_secs(10), retry)
        .await
        .expect("bounded real resolution")
        .expect("the fresh GET completes");
    assert_eq!(recovered.addresses().len(), 1);
    drop(recovered);
    owner
        .close()
        .await
        .expect("actual joins after the shared deadline");
}
