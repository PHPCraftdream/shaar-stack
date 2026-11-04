// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::fixture::{
    BootstrapError, CapacityError, ClockSample, OwnedUdpPeer, TestOwner, address, indexed_key,
    peer, record,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
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
async fn eight_active_and_sixteen_queued_distinct_operations_then_refuse_next() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("owned fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let handle = owner.handle();
    let admission = probe.hold_admission();
    let mut tickets = Vec::new();
    for i in 0..24 {
        let key = peer(&indexed_key(i + 1));
        tickets.push(
            handle
                .enqueue_resolve(key)
                .await
                .expect("reserved distinct key"),
        );
    }
    admission.wait_active(8).await;
    assert_eq!(owner.limits().active_operations, 8);
    assert_eq!(owner.limits().queued_operations, 16);
    let rejected = handle
        .enqueue_resolve(peer(&indexed_key(25)))
        .await
        .unwrap_err();
    assert_eq!(rejected, CapacityError::OperationsAndQueueFull);
    admission.release_all().await;
    for ticket in tickets {
        ticket.cancel().await;
    }
    probe.wait_cleanup_finished().await;
    assert_eq!(owner.limits().operation_charges, 0);
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn sixty_four_signed_query_winners_survive_expiry_conflict_and_lower_replay() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("owned fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let handle = owner.handle();
    let mut expected = Vec::new();
    for index in 0..64_u64 {
        let secret = indexed_key(index + 100);
        let key = peer(&secret);
        let seq = 999_999_900 + index as i64;
        let barrier = probe.query(key);
        let h = handle.clone();
        let task = tokio::spawn(async move { h.resolve(key).await });
        barrier.entered().await;
        barrier
            .release_correlated(vec![record(&secret, seq as u64, wire.destination())])
            .await;
        let winner = join(task).await.expect("actual winner query");
        assert_eq!(winner.sequence, seq);
        let bytes = record(&secret, seq as u64, wire.destination());
        assert_eq!(owner.inspect(key).winner_bytes, Some(bytes.clone()));
        assert_eq!(owner.inspect(key).watermark, Some(seq));
        expected.push((secret, key, seq, bytes));
    }
    probe.clock().advance(Duration::from_secs(31), 0).await;
    for (_, key, seq, bytes) in &expected {
        assert_eq!(owner.inspect(*key).watermark, Some(*seq));
        assert_eq!(owner.inspect(*key).winner_bytes, Some(bytes.clone()));
        assert!(
            owner
                .inspect(*key)
                .cache_expiry_monotonic_micros
                .expect("expired cache deadline")
                <= probe.clock().monotonic_micros()
        );
    }
    let rejected_peer = peer(&indexed_key(999));
    let rejected = handle.resolve(rejected_peer).await.unwrap_err();
    assert_eq!(
        rejected,
        super::fixture::RuntimeError::Capacity(CapacityError::WatermarksFull)
    );
    assert_eq!(owner.inspect(rejected_peer).watermark, None);
    assert_eq!(owner.limits().watermark_count, 64);

    for (secret, key, seq, bytes) in &expected {
        let key = *key;
        let conflict = probe.query(key);
        let h = handle.clone();
        let task = tokio::spawn(async move { h.resolve(key).await });
        conflict.entered().await;
        conflict
            .release_correlated(vec![record(secret, *seq as u64, address(4567))])
            .await;
        assert_eq!(
            join(task).await,
            Err(super::fixture::RuntimeError::Resolve(
                crate::native_discovery::runtime::ResolveError::EqualSequenceConflict
            ))
        );
        assert!(owner.inspect(key).conflicted);
        assert_eq!(owner.inspect(key).winner_bytes, Some(bytes.clone()));
        assert_eq!(owner.inspect(key).watermark, Some(*seq));
        let lower = probe.query(key);
        let h = handle.clone();
        let task = tokio::spawn(async move { h.resolve(key).await });
        lower.entered().await;
        lower
            .release_correlated(vec![record(secret, (*seq - 1) as u64, wire.destination())])
            .await;
        assert_eq!(
            join(task).await,
            Err(super::fixture::RuntimeError::Resolve(
                crate::native_discovery::runtime::ResolveError::Replay
            ))
        );
        assert_eq!(owner.inspect(key).watermark, Some(*seq));
        assert_eq!(owner.inspect(key).winner_bytes, Some(bytes.clone()));
        assert!(owner.inspect(key).conflicted);
    }
    let still_full = handle.resolve(rejected_peer).await.unwrap_err();
    assert_eq!(
        still_full,
        super::fixture::RuntimeError::Capacity(CapacityError::WatermarksFull)
    );
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn numeric_bootstrap_rejects_invalid_inputs_before_bind_or_hostname_resolution() {
    let wire = OwnedUdpPeer::bind_loopback().await.expect("owned fixture");
    let audit = super::fixture::BootstrapAudit::default();
    for endpoints in [
        vec![],
        vec![address(1000); 5],
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
        vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1000)],
    ] {
        assert!(matches!(
            TestOwner::bind_numeric(clock(), wire.socket(), endpoints, &audit).await,
            Err(BootstrapError::Invalid)
        ));
        assert_eq!(audit.bind_attempts(), 0);
        assert_eq!(audit.hostname_resolution_calls(), 0);
        assert_eq!(audit.default_bootstrap_uses(), 0);
    }
}

#[tokio::test]
async fn adaptive_client_guard_never_enables_responder_after_fifteen_minutes() {
    let wire = OwnedUdpPeer::bind_loopback()
        .await
        .expect("owned DHT fixture");
    let (mut owner, probe) = TestOwner::start(clock(), wire.socket())
        .await
        .expect("owner");
    let inbound = OwnedUdpPeer::bind_loopback()
        .await
        .expect("owned sender socket");
    let before = probe.send_inbound_query(inbound.socket()).await;
    let before_observation = probe.client_query_observation(before).await;
    assert!(before_observation.mode.hard_client_only);
    assert!(!before_observation.mode.adaptive_server_enabled);
    assert!(
        !before_observation
            .responder_attempts
            .iter()
            .any(|attempt| attempt.query_id == before.query_id)
    );
    probe.wait_outbox_drained().await;
    assert_eq!(
        inbound.try_recv().await.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    probe
        .clock()
        .advance(Duration::from_secs(15 * 60), 900_000_000)
        .await;
    let maintenance = probe.wait_maintenance_observed().await;
    assert_eq!(maintenance.observed_at_monotonic_micros, 900_000_000);
    let after_mode = probe.client_mode();
    assert!(after_mode.hard_client_only);
    assert!(!after_mode.adaptive_server_enabled);
    let after = probe.send_inbound_query(inbound.socket()).await;
    let after_observation = probe.client_query_observation(after).await;
    assert!(after_observation.mode.hard_client_only);
    assert!(!after_observation.mode.adaptive_server_enabled);
    assert!(
        !after_observation
            .responder_attempts
            .iter()
            .any(|attempt| attempt.query_id == after.query_id)
    );
    probe.wait_outbox_drained().await;
    assert_eq!(
        inbound.try_recv().await.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    owner.close().await.expect("joined close");
}

#[tokio::test]
async fn real_correlated_hostile_referral_is_blocked_at_send_boundary_before_io() {
    let fixture = OwnedUdpPeer::bind_loopback()
        .await
        .expect("allowed fixture");
    let hostile = OwnedUdpPeer::bind_loopback()
        .await
        .expect("separate hostile capture socket");
    assert_ne!(fixture.destination(), hostile.destination());
    let (mut owner, probe) = TestOwner::start(clock(), fixture.socket())
        .await
        .expect("owner");
    let allowed_destinations = probe.owned_destinations();
    assert!(allowed_destinations.contains(&fixture.destination()));
    assert!(!allowed_destinations.contains(&hostile.destination()));
    let key = peer(&indexed_key(500));
    let barrier = probe.query(key);
    let h = owner.handle();
    let task = tokio::spawn(async move { h.resolve(key).await });
    let rpc = barrier.rpc(0).await;
    let outbound = fixture.recv().await.expect("actual query datagram");
    assert_eq!(outbound.destination, fixture.destination());
    probe.inject_referral(rpc, hostile.destination()).await;
    probe.wait_outbox_drained().await;
    let attempts = probe.egress_receipts();
    assert!(attempts.iter().any(|r| {
        r.operation_id == rpc.operation_id
            && r.query_id == rpc.query_id
            && r.referral_transaction_id == rpc.transaction_id
            && r.destination == hostile.destination()
            && r.outcome == super::fixture::EgressOutcome::BlockedOutsideFixture
    }));
    assert!(!attempts.iter().any(|r| {
        r.destination == hostile.destination() && r.outcome == super::fixture::EgressOutcome::Sent
    }));
    assert!(
        attempts
            .iter()
            .filter(|r| r.outcome == super::fixture::EgressOutcome::Sent)
            .all(|r| allowed_destinations.contains(&r.destination))
    );
    assert_eq!(
        hostile.try_recv().await.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    barrier.release_empty().await;
    assert!(join(task).await.is_err());
    owner.close().await.expect("joined close");
}
