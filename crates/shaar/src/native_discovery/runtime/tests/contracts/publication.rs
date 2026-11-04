// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::fixture::{ClockSample, OwnedUdpPeer, PublishError, Snapshot, TestOwner, address};
use std::time::Duration;
use tokio::task::JoinHandle;

fn clock(wall: i64) -> ClockSample {
    ClockSample {
        wall_unix_micros: wall,
        monotonic_micros: 0,
    }
}
async fn join<T>(task: JoinHandle<T>) -> T {
    task.await.expect("task joined")
}

#[tokio::test]
async fn replacement_withdrawal_and_invalid_input_revoke_held_old_generation() {
    for replacement in [
        None,
        Some(Snapshot::new(vec![])),
        Some(Snapshot::new(vec![address(0)])),
    ] {
        let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
        let (mut owner, probe) = TestOwner::start(clock(1_000_000_000), wire.socket())
            .await
            .expect("owner");
        let handle = owner.handle();
        let first = probe.put_send_next();
        let h = handle.clone();
        let update = tokio::spawn(async move {
            h.update(Some(Snapshot::new(vec![wire.destination()])))
                .await
        });
        let initial = first.entered().await;
        join(update).await.expect("initial generation");
        first.release().await;
        probe
            .wait_put_attempt_finished(initial.operation_id, initial.attempt)
            .await;
        let generation = initial.generation;
        let cursor = probe.put_receipts().len();
        let send = probe.put_send(generation);
        probe
            .clock()
            .advance(Duration::from_secs(60), 60_000_000)
            .await;
        let held = send.entered().await;
        assert_eq!(held.generation, generation);
        let invalid = replacement
            .as_ref()
            .is_some_and(Snapshot::contains_zero_port);
        let h = handle.clone();
        let task = tokio::spawn(async move { h.update(replacement).await });
        probe.wait_generation_revoked(generation).await;
        assert!(
            !task.is_finished(),
            "replacement ack waits for old send cleanup"
        );
        send.release().await;
        if invalid {
            assert_eq!(join(task).await, Err(PublishError::InvalidSnapshot));
        } else {
            join(task).await.expect("replacement ack");
        }
        probe.wait_outbox_drained().await;
        assert!(
            !probe.put_receipts()[cursor..]
                .iter()
                .any(|p| p.generation == generation)
        );
        assert_eq!(owner.publisher().active_generation(), None);
        owner.close().await.expect("joined close");
    }
}

#[tokio::test]
async fn scheduled_retries_keep_operation_deadline_stop_at_three_and_coalesce_refresh() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(2_000_000_000), wire.socket())
        .await
        .expect("owner");
    let handle = owner.handle();
    let mut gates = probe.put_sends(5);
    let first = gates.remove(0);
    let second = gates.remove(0);
    let third = gates.remove(0);
    let refresh = gates.remove(0);
    let coalesced = gates.remove(0);
    probe.script_put_replies(vec![
        super::fixture::PutReply::Reject,
        super::fixture::PutReply::Reject,
        super::fixture::PutReply::Reject,
        super::fixture::PutReply::Accept,
        super::fixture::PutReply::Accept,
    ]);
    handle
        .update(Some(Snapshot::new(vec![wire.destination()])))
        .await
        .expect("owner accepted snapshot");
    let p1 = first.entered().await;
    first.release().await;
    probe.wait_put_attempt_finished(p1.operation_id, 1).await;
    let r1 = probe.retry_scheduled(p1.operation_id).await;
    assert!(r1.delay <= Duration::from_millis(100));
    probe.clock().advance(r1.delay, 0).await;
    let p2 = second.entered().await;
    assert_eq!(
        (p2.operation_id, p2.attempt, p2.deadline_monotonic_micros),
        (p1.operation_id, 2, p1.deadline_monotonic_micros)
    );
    second.release().await;
    probe.wait_put_attempt_finished(p1.operation_id, 2).await;
    let r2 = probe.retry_scheduled(p1.operation_id).await;
    assert!(r2.delay <= Duration::from_millis(200));
    probe.clock().advance(r2.delay, 0).await;
    let p3 = third.entered().await;
    assert_eq!(
        (p3.operation_id, p3.attempt, p3.deadline_monotonic_micros),
        (p1.operation_id, 3, p1.deadline_monotonic_micros)
    );
    third.release().await;
    probe.wait_put_attempt_finished(p1.operation_id, 3).await;
    assert_eq!(
        probe.publication_terminal(p1.operation_id).await,
        Err(PublishError::RetryExhausted)
    );
    assert_eq!(probe.put_receipts_for_operation(p1.operation_id).len(), 3);
    probe.clock().advance(Duration::from_secs(10), 0).await;
    probe
        .wait_retry_budget_elapsed(p1.operation_id, p1.deadline_monotonic_micros)
        .await;
    assert_eq!(probe.put_receipts_for_operation(p1.operation_id).len(), 3);
    let remaining = 60_000_000 - probe.clock().monotonic_micros();
    probe
        .clock()
        .advance(Duration::from_micros(remaining), 60_000_000)
        .await;
    let p4 = refresh.entered().await;
    assert_ne!(p4.operation_id, p1.operation_id);
    assert_eq!(p4.attempt, 1);
    refresh.release().await;
    probe
        .wait_put_attempt_finished(p4.operation_id, p4.attempt)
        .await;
    probe.wait_outbox_drained().await;
    probe
        .clock()
        .advance(Duration::from_secs(180), 180_000_000)
        .await;
    let coalesced_put = coalesced.entered().await;
    assert_ne!(coalesced_put.operation_id, p4.operation_id);
    assert_eq!(coalesced_put.attempt, 1);
    coalesced.release().await;
    probe
        .wait_put_attempt_finished(coalesced_put.operation_id, coalesced_put.attempt)
        .await;
    probe.wait_outbox_drained().await;
    assert_eq!(probe.put_receipts().len(), 5);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn requester_cancellation_before_ack_revokes_but_owner_keeps_acknowledged_snapshot() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(3_000_000_000), wire.socket())
        .await
        .expect("owner");
    let sender = owner.handle();
    let gate = probe.hold_next_publish_ack();
    let dest = wire.destination();
    let h = sender.clone();
    let task = tokio::spawn(async move { h.update(Some(Snapshot::new(vec![dest]))).await });
    gate.entered().await;
    task.abort();
    assert!(task.await.expect_err("cancelled requester").is_cancelled());
    gate.release().await;
    probe.wait_generation_revoked_after_cancel().await;
    assert_eq!(owner.publisher().active_generation(), None);
    let ack = sender
        .update(Some(Snapshot::new(vec![wire.destination()])))
        .await
        .expect("owner transfer");
    let generation = ack.generation;
    drop(sender);
    let send = probe.put_send(generation);
    probe
        .clock()
        .advance(Duration::from_secs(60), 60_000_000)
        .await;
    let put = send.entered().await;
    assert_eq!(put.generation, generation);
    send.release().await;
    probe
        .wait_put_attempt_finished(put.operation_id, put.attempt)
        .await;
    assert!(probe.put_receipts().iter().any(|receipt| {
        receipt.operation_id == put.operation_id && receipt.generation == generation
    }));
    let h = owner.handle();
    let withdrawn = tokio::spawn(async move { h.update(None).await });
    probe.wait_generation_revoked(generation).await;
    withdrawn
        .await
        .expect("withdraw task")
        .expect("withdraw ack");
    probe.wait_outbox_drained().await;
    let cursor = probe.put_receipts().len();
    probe
        .clock()
        .advance(Duration::from_secs(60), 60_000_000)
        .await;
    assert!(
        !probe.put_receipts()[cursor..]
            .iter()
            .any(|r| r.generation == generation)
    );
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn timestamps_decode_from_actual_signed_puts_and_follow_two_clocks() {
    for wall_delta in [60_000_000, 0] {
        let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
        let (mut owner, probe) = TestOwner::start(clock(4_000_000_000), wire.socket())
            .await
            .expect("owner");
        let mut gates = probe.put_sends(2);
        let first_gate = gates.remove(0);
        let refresh = gates.remove(0);
        let ack = owner
            .handle()
            .update(Some(Snapshot::new(vec![wire.destination()])))
            .await
            .expect("snapshot");
        let first = first_gate.entered().await;
        first_gate.release().await;
        probe
            .wait_put_attempt_finished(first.operation_id, first.attempt)
            .await;
        let first_receipt = probe.next_signed_put(ack.generation).await;
        let t1 = super::fixture::signed_timestamp(&first_receipt.signed_packet_bytes);
        probe
            .clock()
            .advance(Duration::from_secs(60), wall_delta)
            .await;
        let second = refresh.entered().await;
        refresh.release().await;
        probe
            .wait_put_attempt_finished(second.operation_id, second.attempt)
            .await;
        let second_receipt = probe.next_signed_put(ack.generation).await;
        let t2 = super::fixture::signed_timestamp(&second_receipt.signed_packet_bytes);
        assert!(second.generation == ack.generation && t2 > t1);
        assert_eq!(
            t2,
            probe.clock().wall_unix_micros().max(t1 as i64 + 1) as u64
        );
        assert!(t2 <= probe.clock().wall_unix_micros() as u64 + 30_000_000);
        owner.close().await.expect("joined close");
    }
}

#[tokio::test]
async fn rollback_is_terminal_after_recovery_and_preserves_resolver_watermark() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture");
    let (mut owner, probe) = TestOwner::start(clock(1_000_000_000), wire.socket())
        .await
        .expect("owner");
    let secret = super::fixture::indexed_key(88);
    let key = super::fixture::peer(&secret);
    let query = probe.query(key);
    let h = owner.handle();
    let task = tokio::spawn(async move { h.resolve(key).await });
    query.entered().await;
    query
        .release_correlated(vec![super::fixture::record(
            &secret,
            999_999_999,
            wire.destination(),
        )])
        .await;
    join(task).await.expect("resolver winner");
    let winner = owner.inspect(key).winner_bytes;
    let destination = wire.destination();
    let mut gates = probe.put_sends(2);
    let first = gates.remove(0);
    let refresh = gates.remove(0);
    let h = owner.handle();
    let update =
        tokio::spawn(async move { h.update(Some(Snapshot::new(vec![destination]))).await });
    let ack = join(update).await.expect("publish");
    let p1 = first.entered().await;
    first.release().await;
    probe
        .wait_put_attempt_finished(p1.operation_id, p1.attempt)
        .await;
    probe
        .clock()
        .advance(Duration::from_secs(60), 60_000_000)
        .await;
    let p2 = refresh.entered().await;
    refresh.release().await;
    probe
        .wait_put_attempt_finished(p2.operation_id, p2.attempt)
        .await;
    probe.wait_outbox_drained().await;
    let cursor = probe.put_receipts().len();
    probe.clock().set_wall(999_000_000).await;

    assert_eq!(
        owner
            .handle()
            .update(Some(Snapshot::new(vec![wire.destination()])))
            .await,
        Err(PublishError::ClockFault)
    );
    probe
        .clock()
        .advance(Duration::from_secs(60), 2_000_000_000)
        .await;
    assert_eq!(
        owner
            .handle()
            .update(Some(Snapshot::new(vec![wire.destination()])))
            .await,
        Err(PublishError::ClockFault)
    );
    assert_eq!(owner.inspect(key).winner_bytes, winner);
    assert_eq!(owner.inspect(key).watermark, Some(999_999_999));
    assert_eq!(owner.inspect(key).cache_expiry_monotonic_micros, None);
    assert!(
        !probe.put_receipts()[cursor..]
            .iter()
            .any(|r| r.generation == ack.generation)
    );
    owner.close().await.expect("joined close");
}
