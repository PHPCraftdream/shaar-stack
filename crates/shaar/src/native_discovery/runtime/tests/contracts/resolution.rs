// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::fixture::{
    ClockSample, InvalidRecord, OwnedUdpPeer, RuntimeError, SnapshotError, TestOwner, address,
    indexed_key, invalid_record, peer, record, validate_snapshot,
};
use std::time::Duration;
use tokio::task::JoinHandle;

const WALL: i64 = 11;
fn clock() -> ClockSample {
    ClockSample {
        wall_unix_micros: WALL,
        monotonic_micros: 0,
    }
}
async fn owner() -> (OwnedUdpPeer, TestOwner, super::fixture::Probe) {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture socket");
    let (owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("runtime owner");
    (wire, owner, probe)
}
async fn join<T>(task: JoinHandle<T>) -> T {
    task.await.expect("task joined")
}

#[tokio::test]
async fn correlated_release_maps_zero_one_and_two_records_to_two_real_rpcs() {
    for value_count in 0..=2 {
        let (wire, mut owner, probe) = owner().await;
        let handle = owner.handle();
        let secret = indexed_key(70 + value_count as u64);
        let key = peer(&secret);
        let barrier = probe.query(key);
        let h = handle.clone();
        let task = tokio::spawn(async move { h.resolve(key).await });

        let query = barrier.entered().await;
        let rpc0 = barrier.rpc(0).await;
        let rpc1 = barrier.rpc(1).await;
        assert_eq!(rpc0.operation_id, query.operation_id);
        assert_eq!(rpc1.operation_id, query.operation_id);
        assert_eq!(rpc0.query_id, query.query_id);
        assert_eq!(rpc1.query_id, query.query_id);
        assert_ne!(rpc0.transaction_id, rpc1.transaction_id);
        assert_ne!(rpc0.expected_source, rpc1.expected_source);

        let records = (0..value_count)
            .map(|index| record(&secret, 10 + index as u64, wire.destination()))
            .collect();
        barrier.release_correlated(records).await;

        let events = barrier.rpc_events().await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].rpc, rpc0);
        assert_eq!(events[0].outcome, super::fixture::RpcOutcome::Accepted);
        assert_eq!(events[1].rpc, rpc1);
        assert_eq!(events[1].outcome, super::fixture::RpcOutcome::Accepted);
        assert_eq!(probe.clock().monotonic_micros(), 0);

        match value_count {
            0 => {
                assert_eq!(
                    join(task).await,
                    Err(RuntimeError::Resolve(
                        crate::native_discovery::runtime::ResolveError::NoValidRecords
                    ))
                );
                assert_eq!(owner.inspect(key).winner_bytes, None);
            }
            1 => assert_eq!(
                join(task).await.expect("one mapped mutable value").sequence,
                10
            ),
            2 => assert_eq!(
                join(task)
                    .await
                    .expect("two mapped mutable values")
                    .sequence,
                11
            ),
            _ => unreachable!(),
        }
        assert_eq!(owner.inspect(key).completed_network_queries, 1);
        owner.close().await.expect("joined close");
    }
}
#[tokio::test]
async fn checked_signed_winner_is_pinned_to_expected_peer_and_dial() {
    let (wire, mut owner, probe) = owner().await;
    let handle = owner.handle();
    let secret = indexed_key(7);
    let key = peer(&secret);
    let native = probe
        .native_endpoint(&secret)
        .await
        .expect("owned native endpoint");
    let barrier = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve_and_connect(key).await });
    let query = barrier.entered().await;
    barrier
        .release_correlated(vec![record(&secret, 10, native)])
        .await;
    let result = join(task).await.expect("resolved and admitted");
    assert_eq!(
        (result.peer, result.sequence, result.address),
        (key, 10, native)
    );
    assert_eq!(
        owner.inspect(key).winner_bytes,
        Some(record(&secret, 10, native))
    );
    assert_eq!(owner.inspect(key).watermark, Some(10));
    assert_eq!(
        probe.dials(),
        vec![super::fixture::DialReceipt {
            operation_id: query.operation_id,
            peer: key,
            address: native
        }]
    );
    assert_eq!(
        probe.admissions(),
        vec![super::fixture::AdmissionReceipt { peer: key }]
    );
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn signed_winners_choose_greatest_sequence_in_both_response_orders() {
    for order in [[10, 11], [11, 10]] {
        let (wire, mut owner, probe) = owner().await;
        let handle = owner.handle();
        let secret = indexed_key(11);
        let key = peer(&secret);
        let barrier = probe.query(key);
        let h = handle.clone();
        let task = tokio::spawn(async move { h.resolve(key).await });
        let query = barrier.entered().await;
        let rpc0 = barrier.rpc(0).await;
        let rpc1 = barrier.rpc(1).await;
        assert_eq!(rpc0.operation_id, query.operation_id);
        assert_eq!(rpc0.query_id, query.query_id);
        assert_eq!(rpc0.operation_id, rpc1.operation_id);
        assert_eq!(rpc0.query_id, rpc1.query_id);
        assert_ne!(rpc0.transaction_id, rpc1.transaction_id);
        assert_ne!(rpc0.expected_source, rpc1.expected_source);
        for (rpc, seq) in [(rpc0, order[0]), (rpc1, order[1])] {
            barrier
                .deliver(rpc, record(&secret, seq, wire.destination()))
                .await;
        }
        barrier.finish().await;
        assert_eq!(join(task).await.expect("resolved").sequence, 11);
        assert_eq!(
            owner.inspect(key).winner_bytes,
            Some(record(&secret, 11, wire.destination()))
        );
        assert_eq!(owner.inspect(key).watermark, Some(11));
        owner.close().await.expect("joined close");
    }
}

#[tokio::test]
async fn equal_identical_then_expired_conflict_clears_cache_and_greater_recovers() {
    let (wire, mut owner, probe) = owner().await;
    let handle = owner.handle();
    let secret = indexed_key(12);
    let key = peer(&secret);
    let first = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let q1 = first.entered().await;
    first
        .release_correlated(vec![
            record(&secret, 10, wire.destination()),
            record(&secret, 10, wire.destination()),
        ])
        .await;
    let initial = join(task).await.expect("resolve");
    assert_eq!(owner.inspect(key).watermark, Some(10));
    assert!(!owner.inspect(key).conflicted);

    probe.clock().advance(Duration::from_secs(31), 0).await;
    let expired_deadline = owner
        .inspect(key)
        .cache_expiry_monotonic_micros
        .expect("retained expiry");
    assert!(expired_deadline <= probe.clock().monotonic_micros());
    let conflict = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let q2 = conflict.entered().await;
    assert!(q2.query_id > q1.query_id);
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        Some(expired_deadline)
    );
    conflict
        .release_correlated(vec![record(&secret, 10, address(4567))])
        .await;
    assert_eq!(
        join(task).await,
        Err(RuntimeError::Resolve(
            crate::native_discovery::runtime::ResolveError::EqualSequenceConflict
        ))
    );
    assert!(owner.inspect(key).conflicted);
    assert_eq!(owner.inspect(key).cache_expiry_monotonic_micros, None);

    let recovery = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let q3 = recovery.entered().await;
    assert!(q3.query_id > q2.query_id);
    recovery
        .release_correlated(vec![record(&secret, 11, wire.destination())])
        .await;
    let greater = join(task).await.expect("greater recovery");
    assert_eq!(greater.sequence, 11);
    assert!(!owner.inspect(key).conflicted);
    assert_eq!(
        owner.inspect(key).winner_bytes,
        Some(record(&secret, 11, wire.destination()))
    );
    assert!(greater.cache_expiry_monotonic_micros > initial.cache_expiry_monotonic_micros);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn duplicate_replay_cache_and_local_put_do_not_renew_exact_deadline_or_query_count() {
    let (wire, mut owner, probe) = owner().await;
    let handle = owner.handle();
    let secret = indexed_key(13);
    let key = peer(&secret);
    let barrier = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let first = barrier.entered().await;
    let rpc0 = barrier.rpc(0).await;
    let rpc1 = barrier.rpc(1).await;
    assert_eq!(
        (rpc0.operation_id, rpc0.query_id),
        (rpc1.operation_id, rpc1.query_id)
    );
    assert_ne!(rpc0.transaction_id, rpc1.transaction_id);
    assert_ne!(rpc0.expected_source, rpc1.expected_source);
    probe.clock().advance(Duration::from_micros(1), 0).await;
    barrier
        .deliver(rpc0, record(&secret, 10, wire.destination()))
        .await;
    probe.clock().advance(Duration::from_micros(1), 0).await;
    barrier
        .duplicate(rpc0, record(&secret, 10, wire.destination()))
        .await;
    probe.clock().advance(Duration::from_micros(1), 0).await;
    barrier
        .deliver(rpc1, record(&secret, 10, wire.destination()))
        .await;
    let events = barrier.rpc_events().await;
    assert_eq!(
        events,
        vec![
            super::fixture::RpcEvent {
                rpc: rpc0,
                outcome: super::fixture::RpcOutcome::Accepted
            },
            super::fixture::RpcEvent {
                rpc: rpc0,
                outcome: super::fixture::RpcOutcome::RejectedUnexpectedTransaction
            },
            super::fixture::RpcEvent {
                rpc: rpc1,
                outcome: super::fixture::RpcOutcome::Accepted
            }
        ]
    );
    let first_rpc = rpc0;

    assert_eq!(owner.inspect(key).cache_expiry_monotonic_micros, None);
    assert_eq!(owner.inspect(key).completed_network_queries, 0);
    let before_finish = owner.inspect(key);
    assert_eq!(before_finish.cache_expiry_monotonic_micros, None);
    assert_eq!(before_finish.completed_network_queries, 0);
    probe.clock().advance(Duration::from_micros(1), 0).await;
    barrier.finish().await;
    let resolved = join(task).await.expect("completed query");
    let deadline = resolved.cache_expiry_monotonic_micros;
    assert_eq!(deadline, 30_000_004);
    let count = owner.inspect(key).completed_network_queries;
    assert_eq!(count, 1);
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        Some(deadline)
    );

    probe.clock().advance(Duration::from_secs(5), 0).await;
    probe
        .replay_transaction(first_rpc, record(&secret, 10, wire.destination()))
        .await;
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        Some(deadline)
    );
    assert_eq!(owner.inspect(key).completed_network_queries, count);
    probe.clock().advance(Duration::from_secs(5), 0).await;
    assert_eq!(handle.resolve(key).await.expect("cache hit").sequence, 10);
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        Some(deadline)
    );
    assert_eq!(owner.inspect(key).completed_network_queries, count);
    probe.clock().advance(Duration::from_secs(5), 0).await;
    probe
        .replay_local_put(key, record(&secret, 10, wire.destination()))
        .await;
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        Some(deadline)
    );
    assert_eq!(owner.inspect(key).completed_network_queries, count);

    let delta = deadline - probe.clock().monotonic_micros() + 1;
    probe.clock().advance(Duration::from_micros(delta), 0).await;
    let expired_deadline = owner.inspect(key).cache_expiry_monotonic_micros;
    assert_eq!(expired_deadline, Some(deadline));
    probe.clock().advance(Duration::from_micros(1), 0).await;
    probe
        .replay_cached_value(key, record(&secret, 10, wire.destination()))
        .await;
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        expired_deadline
    );
    assert_eq!(owner.inspect(key).completed_network_queries, count);
    probe.clock().advance(Duration::from_micros(1), 0).await;
    probe
        .replay_local_put(key, record(&secret, 10, wire.destination()))
        .await;
    assert_eq!(
        owner.inspect(key).cache_expiry_monotonic_micros,
        expired_deadline
    );
    assert_eq!(owner.inspect(key).completed_network_queries, count);

    let next = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let second_query = next.entered().await;
    assert!(second_query.query_id > first.query_id);
    next.release_correlated(vec![record(&secret, 10, wire.destination())])
        .await;
    let renewed = join(task).await.expect("actual query recovery");
    assert_eq!(
        renewed.cache_expiry_monotonic_micros,
        probe.clock().monotonic_micros() + 30_000_000
    );
    assert_eq!(owner.inspect(key).completed_network_queries, count + 1);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn invalid_signed_bytes_and_wrong_peer_never_become_winner_or_dial() {
    for kind in [
        InvalidRecord::WrongKey,
        InvalidRecord::CorruptSignature,
        InvalidRecord::Oversize,
        InvalidRecord::Truncated,
        InvalidRecord::ByteFlipped,
        InvalidRecord::Stale,
        InvalidRecord::TooFarFuture,
        InvalidRecord::Empty,
    ] {
        let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture socket");
        let negative_clock = ClockSample {
            wall_unix_micros: 1_000_000_000,
            monotonic_micros: 0,
        };
        let (mut owner, probe) = TestOwner::start(negative_clock, wire.socket())
            .await
            .expect("owner");
        let handle = owner.handle();
        let secret = indexed_key(14);
        let key = peer(&secret);
        let native = probe
            .native_endpoint(&secret)
            .await
            .expect("owned native endpoint");
        let sample = invalid_record(&secret, kind, 1_000_000_000, native);
        if matches!(
            kind,
            InvalidRecord::Stale | InvalidRecord::TooFarFuture | InvalidRecord::WrongKey
        ) {
            let packet = iroh_dns::pkarr::SignedPacket::from_bytes(&sample)
                .expect("valid signed timestamp fixture");
            let expected_timestamp = match kind {
                InvalidRecord::Stale => 699_999_999,
                InvalidRecord::TooFarFuture => 1_030_000_001,
                _ => 1_000_000_000,
            };
            assert_eq!(packet.timestamp().as_micros(), expected_timestamp);
        }
        assert!(
            handle
                .resolve_record_and_connect(key, sample)
                .await
                .is_err()
        );
        assert_eq!(owner.inspect(key).winner_bytes, None);
        assert!(probe.dials().is_empty());
        owner.close().await.expect("joined close");
    }
    let (wire, mut owner, probe) = owner().await;
    let handle = owner.handle();
    let expected = peer(&indexed_key(15));
    assert!(
        handle
            .resolve_record_and_connect(expected, record(&indexed_key(16), 10, wire.destination()))
            .await
            .is_err()
    );
    assert!(owner.inspect(expected).winner_bytes.is_none());
    assert!(probe.dials().is_empty());
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn age_three_hundred_seconds_is_immediate_only_then_requires_new_query() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("fixture socket");
    let clock = ClockSample {
        wall_unix_micros: 300_000_000,
        monotonic_micros: 0,
    };
    let (mut owner, probe) = TestOwner::start(clock, wire.socket()).await.expect("owner");
    let handle = owner.handle();
    let secret = indexed_key(17);
    let key = peer(&secret);
    let query = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let query_receipt = query.entered().await;
    query
        .release_correlated(vec![record(&secret, 0, wire.destination())])
        .await;
    let result = join(task).await.expect("inclusive 300s result");
    assert_eq!(result.sequence, 0);
    assert!(result.cache_expiry_monotonic_micros <= probe.clock().monotonic_micros());
    let next = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let q = next.entered().await;
    assert!(q.query_id > query_receipt.query_id);
    next.release_empty().await;
    assert!(join(task).await.is_err());
    assert_eq!(owner.inspect(key).completed_network_queries, 2);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn cancelling_waiter_before_response_cannot_cache_or_dial_late_record() {
    let (wire, mut owner, probe) = owner().await;
    let handle = owner.handle();
    let secret = indexed_key(18);
    let key = peer(&secret);
    let native = probe
        .native_endpoint(&secret)
        .await
        .expect("owned native endpoint");
    let barrier = probe.query(key);
    let h = handle.clone();
    let task = tokio::spawn(async move { h.resolve_and_connect(key).await });
    let query = barrier.entered().await;
    let rpc = barrier.rpc(0).await;
    task.abort();
    assert!(task.await.expect_err("cancelled waiter").is_cancelled());
    let ingress = barrier
        .late_response(rpc, record(&secret, 10, native))
        .await
        .expect("actual late-response ingress decision");
    assert_eq!(ingress.rpc, rpc);
    assert!(ingress.event_id > 0);
    barrier.release_without_response().await;
    probe.wait_cleanup_finished().await;
    probe.wait_outbox_drained().await;
    assert_eq!(owner.inspect(key).winner_bytes, None);
    assert!(probe.dials().is_empty());
    assert_eq!(query.peer, key);
    owner.close().await.expect("joined close");
}

#[test]
fn pure_address_validator_accepts_four_and_rejects_five() {
    let four = (1..=4).map(address).collect::<Vec<_>>();
    assert_eq!(validate_snapshot(&four).expect("four addresses").len(), 4);
    let mut five = four;
    five.push(address(5));
    assert_eq!(
        validate_snapshot(&five),
        Err(SnapshotError::TooManyAddresses)
    );
}
