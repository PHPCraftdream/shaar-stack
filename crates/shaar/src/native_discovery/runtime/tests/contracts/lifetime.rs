// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::fixture::{ClockSample, OwnedUdpPeer, RuntimeError, TestOwner};
use std::time::Duration;
use tokio::task::JoinHandle;

fn clock() -> ClockSample {
    ClockSample {
        wall_unix_micros: 1_000_000_000,
        monotonic_micros: 0,
    }
}
async fn join<T>(task: JoinHandle<T>) -> T {
    task.await.expect("task joined")
}

#[tokio::test]
async fn absolute_deadline_covers_actual_queue_and_bootstrap_work() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let handle = owner.handle();
    let admission = probe.hold_admission();
    let mut active = Vec::new();
    for index in 100..108 {
        active.push(
            handle
                .enqueue_resolve(super::fixture::peer(&super::fixture::indexed_key(index)))
                .await
                .expect("active slot"),
        );
    }
    admission.wait_active(8).await;
    let peer = super::fixture::peer(&super::fixture::indexed_key(1));
    let deadline = probe.clock().monotonic_micros() + 10_000_000;
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve_until(peer, deadline).await });
    probe.wait_queued_operations(1).await;
    let bootstrap = probe.hold(super::fixture::HoldPoint::Bootstrap);
    probe.clock().advance(Duration::from_secs(9), 0).await;
    for ticket in active {
        ticket.cancel().await;
    }
    admission.release_all().await;
    bootstrap.entered().await;
    probe.clock().advance(Duration::from_secs(1), 0).await;
    assert_eq!(join(task).await, Err(RuntimeError::Deadline));
    bootstrap.release().await;
    probe.wait_cleanup_finished().await;
    assert_eq!(owner.limits().operation_charges, 0);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn cancellation_before_enqueue_starts_no_operation_and_is_joined() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let enqueue = probe.hold(super::fixture::HoldPoint::Enqueue);
    let h = owner.handle();
    let peer = super::fixture::peer(&super::fixture::indexed_key(2));
    let task = tokio::spawn(async move { h.resolve(peer).await });
    enqueue.entered().await;
    task.abort();
    assert!(
        task.await
            .expect_err("cancelled before enqueue")
            .is_cancelled()
    );
    enqueue.release().await;
    probe.wait_cleanup_finished().await;
    assert_eq!(owner.limits().active_operations, 0);
    assert_eq!(owner.limits().queued_operations, 0);
    assert!(probe.receipts().is_empty());
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn admitted_cancel_retains_charge_until_triggered_cleanup_completes() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let peer = super::fixture::peer(&super::fixture::indexed_key(3));
    let query = probe.query(peer);
    let cleanup = probe.hold_next_cleanup();
    let h = owner.handle();
    let task = tokio::spawn(async move { h.resolve(peer).await });
    query.entered().await;
    task.abort();
    assert!(
        task.await
            .expect_err("cancelled admitted request")
            .is_cancelled()
    );
    query.release_without_response().await;
    let operation = cleanup.entered().await;
    assert_eq!(owner.limits().operation_charges, 1);
    assert_eq!(owner.limits().operation_charge(operation.operation_id), 1);
    cleanup.release().await;
    probe.wait_cleanup_finished().await;
    assert_eq!(owner.limits().operation_charges, 0);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn deadline_return_does_not_release_charge_while_triggered_cleanup_is_held() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let peer = super::fixture::peer(&super::fixture::indexed_key(4));
    let deadline = probe.clock().monotonic_micros() + 10_000_000;
    let query = probe.query(peer);
    let cleanup = probe.hold_next_cleanup();
    let h = owner.handle();
    let task = tokio::spawn(async move { h.resolve_until(peer, deadline).await });
    query.entered().await;
    probe.clock().advance(Duration::from_secs(10), 0).await;
    assert_eq!(join(task).await, Err(RuntimeError::Deadline));
    query.release_without_response().await;
    let operation = cleanup.entered().await;
    assert_eq!(owner.limits().operation_charge(operation.operation_id), 1);
    cleanup.release().await;
    probe.wait_cleanup_finished().await;
    assert_eq!(owner.limits().operation_charge(operation.operation_id), 0);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn stop_during_real_flush_and_failed_close_retains_join_socket_and_charges() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let key = super::fixture::peer(&super::fixture::indexed_key(5));
    let query = probe.query(key);
    let flush = probe.flush();
    let h = owner.handle();
    let resolve = tokio::spawn(async move { h.resolve(key).await });
    let _operation = probe.wait_operation_admitted(key).await;
    flush.entered().await;
    assert!(owner.runtime().pending_datagrams > 0);
    owner.request_stop_out_of_band();
    probe.wait_stop_observed().await;
    assert_eq!(owner.limits().actor_charges, 1);
    let mut closing_owner = owner;
    let close_task = tokio::spawn(async move {
        let result = closing_owner.close().await;
        (closing_owner, result)
    });
    probe.close_started().await;
    probe.clock().advance(Duration::from_secs(5), 0).await;
    let (mut owner, result) = join(close_task).await;
    assert_eq!(result.unwrap_err(), super::fixture::CloseError::NotJoined);
    assert!(owner.runtime().join_handle_retained);
    assert!(!owner.runtime().socket_dropped);
    assert_eq!(owner.limits().actor_charges, 1);
    assert!(owner.handle().resolve(key).await.is_err());
    assert_eq!(owner.limits().actor_charges, 1);
    flush.release().await;
    query.release_without_response().await;
    assert!(join(resolve).await.is_err());
    probe.wait_actor_joined().await;
    probe.wait_socket_dropped().await;
    assert!(probe.rebind().await.is_ok());
    assert!(owner.handle().resolve(key).await.is_err());
    owner.close().await.expect("close after actual join");
    assert_eq!(owner.limits().operation_charges, 0);
}

#[tokio::test]
async fn successful_close_joins_drops_socket_and_inerts_retained_handle() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let retained = owner.handle();
    let receipt = owner.close().await.expect("joined close");
    assert!(receipt.actor_joined && receipt.socket_dropped);
    assert!(probe.rebind().await.is_ok());
    assert!(
        retained
            .resolve(super::fixture::peer(&super::fixture::indexed_key(6)))
            .await
            .is_err()
    );
    assert!(probe.receipts().is_empty());
}
