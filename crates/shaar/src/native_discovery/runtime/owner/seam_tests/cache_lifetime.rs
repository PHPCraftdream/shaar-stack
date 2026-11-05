// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::tests::fixture::CapturedPut;
use super::super::to_mutable;
use super::RuntimeError;
use super::{WALL, capture_get, record, record_at, resolve, setup};
use crate::native_discovery::policy::RecordError;
use crate::native_discovery::runtime::owner::resolver::ResolveError;
use crate::native_discovery::runtime::publisher::SignedSnapshot;
use iroh_base::{EndpointId, TransportAddr};
use n0_mainline::MutableItem;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

fn captured_item(captured: &CapturedPut) -> MutableItem {
    let mut envelope = Vec::with_capacity(104 + captured.value.len());
    envelope.extend_from_slice(&captured.key);
    envelope.extend_from_slice(&captured.signature);
    envelope.extend_from_slice(&captured.sequence.to_be_bytes());
    envelope.extend_from_slice(&captured.value);
    to_mutable(&SignedSnapshot {
        timestamp_us: captured.sequence,
        bytes: envelope,
    })
    .expect("captured local record")
}

#[tokio::test]
async fn replayed_records_never_renew_a_cached_entry() {
    let (mut peer, mut owner, clock) = setup(0x90).await;
    let winner = record_at(0x91, WALL, "127.0.0.1:9001".parse().expect("address"));
    let key = EndpointId::from_bytes(winner.key()).expect("record key");
    let target = MutableItem::target_from_key(winner.key(), None);
    let first = resolve(&mut owner, &mut peer, &winner)
        .await
        .expect("initial winner");
    assert_eq!(
        first.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(first);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(30_000_000),
        "receipt-anchored cap at monotonic zero",
    );

    // While the cache is valid a resolve is served without any GET, so a
    // replay cannot even reach the policy layer. Wall and monotonic advance
    // together: the publisher clock policy rejects monotonic-only progress.
    clock.set_wall(WALL + 29_999_999);
    clock.set_monotonic(29_999_999);
    let hit = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            held = peer.capture_get(target) => panic!("a valid cache must not query the peer: {held:?}"),
        }
    })
    .await
    .expect("cache lookup completes")
    .expect("cache hit");
    assert_eq!(hit.addresses().len(), 1);
    drop(hit);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(30_000_000),
        "the cache hit renews nothing",
    );

    // Expire the entry and replay only a lower-sequence record: the replay is
    // rejected and the expired deadline stays bit-identical (no commit).
    clock.set_wall(WALL + 30_000_000);
    clock.set_monotonic(30_000_000);
    let stale = record_at(
        0x91,
        WALL - 5_000_000,
        "127.0.0.1:9002".parse().expect("address"),
    );
    assert!(matches!(
        resolve(&mut owner, &mut peer, &stale).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::Replay
        )))
    ));
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(30_000_000),
        "a replayed record must commit nothing",
    );
    assert_eq!(
        owner.resolver.winner_sequence(key),
        Some(WALL),
        "the winner watermark survives the replay",
    );

    // The entry is still dead: the next resolve performs a fresh GET, and the
    // renewal at the new receipt is receipt-anchored, never replay-extended.
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source, transaction) = capture_get(&mut peer, target, &mut request).await;
    peer.reply_get(source, &transaction, &winner).await;
    let renewed = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded renewal")
        .expect("fresh receipt");
    assert_eq!(renewed.addresses().len(), 1);
    drop(renewed);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(60_000_000),
        "the renewal uses the new receipt plus the 30-second cap",
    );
    owner
        .close()
        .await
        .expect("actual joins after the replay cases");
}

#[tokio::test]
async fn equal_sequence_replay_kills_the_entry_and_recovery_needs_a_newer_winner() {
    let (mut peer, mut owner, clock) = setup(0x92).await;
    let winner = record_at(0x93, WALL, "127.0.0.1:9001".parse().expect("address"));
    let conflicting = record_at(0x93, WALL, "127.0.0.1:9002".parse().expect("address"));
    let key = EndpointId::from_bytes(winner.key()).expect("record key");
    let first = resolve(&mut owner, &mut peer, &winner)
        .await
        .expect("initial winner");
    drop(first);
    assert_eq!(owner.resolver.cache_deadline(key), Some(30_000_000));

    // Expire the entry; wall and monotonic advance together so the publisher
    // clock policy stays accepted. An equal-sequence record with a different
    // payload is a conflict: the deadline is cleared, never renewed.
    clock.set_wall(WALL + 30_000_000);
    clock.set_monotonic(30_000_000);
    assert!(matches!(
        resolve(&mut owner, &mut peer, &conflicting).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::EqualSequenceConflict
        )))
    ));
    assert_eq!(
        owner.resolver.cache_deadline(key),
        None,
        "the conflict clears the cache deadline instead of renewing it",
    );
    assert_eq!(
        owner.resolver.winner_sequence(key),
        Some(WALL),
        "the original winner watermark is retained",
    );

    // An equal-sequence replay of the already-seen winner bytes still cannot
    // recover the conflict: only a strictly newer sequence does.
    assert!(matches!(
        resolve(&mut owner, &mut peer, &winner).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::EqualSequenceConflict
        )))
    ));
    assert_eq!(owner.resolver.cache_deadline(key), None);

    // A strictly newer winner recovers and renews at the new receipt.
    let newer = record_at(
        0x93,
        WALL + 3_000_000,
        "127.0.0.1:9001".parse().expect("address"),
    );
    let recovered = resolve(&mut owner, &mut peer, &newer)
        .await
        .expect("a strictly newer sequence recovers");
    assert_eq!(
        recovered.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(recovered);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(60_000_000),
        "receipt-anchored renewal at monotonic 30_000_000",
    );
    assert_eq!(owner.resolver.winner_sequence(key), Some(WALL + 3_000_000));
    owner
        .close()
        .await
        .expect("actual joins after the conflict cases");
}

#[tokio::test]
async fn local_publication_alone_never_serves_or_renews_the_resolve_cache() {
    let (mut peer, mut owner, clock) = setup(0x94).await;
    // A network record first: this fixes the cache expiry boundary.
    let network = record(0x97, WALL);
    let network_key = EndpointId::from_bytes(network.key()).expect("network key");
    let first = resolve(&mut owner, &mut peer, &network)
        .await
        .expect("network winner");
    assert_eq!(first.addresses().len(), 1);
    drop(first);
    assert_eq!(
        owner.resolver.cache_deadline(network_key),
        Some(30_000_000),
        "the expiry boundary is receipt zero plus the 30-second cap",
    );

    // The local publication (real PUT, captured and acknowledged) must leave
    // that boundary bit-identical: a local PUT is not network work.
    let mut publication = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9005".parse().expect("published address"),
    )]));
    let (source, transaction, captured) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut publication => panic!("publication completed before the peer saw the PUT: {result:?}"),
    };
    peer.acknowledge(source, &transaction).await;
    publication.await.expect("local publication acknowledged");
    assert_eq!(
        owner.resolver.cache_deadline(network_key),
        Some(30_000_000),
        "a local publication must not move the cache expiry boundary",
    );

    // The locally published record is not served from any cache: no cache
    // entry exists for it, so resolving its key requires an actual GET.
    let local = captured_item(&captured);
    let local_key = EndpointId::from_bytes(local.key()).expect("local key");
    assert_eq!(
        owner.resolver.cache_deadline(local_key),
        None,
        "the local PUT must not populate the resolve cache",
    );
    let local_target = MutableItem::target_from_key(local.key(), None);
    let mut request =
        Box::pin(owner.resolve_until(local_key, Instant::now() + Duration::from_secs(10)));
    let (get_source, get_transaction) = capture_get(&mut peer, local_target, &mut request).await;
    peer.reply_get(get_source, &get_transaction, &local).await;
    let served = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded real resolution")
        .expect("the GET serves the locally published record");
    assert_eq!(
        served.addresses(),
        &["127.0.0.1:9005".parse::<SocketAddr>().expect("address")]
    );
    drop(served);
    assert_eq!(
        owner.resolver.cache_deadline(local_key),
        Some(30_000_000),
        "the entry exists only through the real GET receipt",
    );

    // A second local publication must not renew that entry either. Time moves
    // forward first (wall and monotonic together), so a renewal would shift the
    // boundary to 35_000_000 and be distinguishable from the retained 30_000_000.
    clock.set_wall(WALL + 5_000_000);
    clock.set_monotonic(5_000_000);
    let mut republication = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9006".parse().expect("replacement address"),
    )]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut republication => panic!("republication completed before the peer saw the PUT: {result:?}"),
    };
    peer.acknowledge(source, &transaction).await;
    republication.await.expect("republication acknowledged");
    assert_eq!(
        owner.resolver.cache_deadline(local_key),
        Some(30_000_000),
        "a local publication must not renew the cached entry",
    );
    owner
        .close()
        .await
        .expect("actual joins with the publication revoked");
}

#[tokio::test]
async fn sixty_four_lifetime_slots_survive_expiry_conflict_and_lower_replay() {
    let (mut peer, mut owner, clock) = setup(0x95).await;
    // Fill all sixty-four lifetime slots through real GETs.
    for seed in 0xa0..0xe0 {
        let item = record(seed, WALL);
        let delivered = resolve(&mut owner, &mut peer, &item)
            .await
            .expect("slot winner");
        assert_eq!(delivered.addresses().len(), 1);
        drop(delivered);
    }
    // The sixty-fifth key is rejected before any network work.
    let extra = record(0xe0, WALL);
    let extra_key = EndpointId::from_bytes(extra.key()).expect("extra key");
    let extra_target = MutableItem::target_from_key(extra.key(), None);
    let blocked = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(extra_key, Instant::now() + Duration::from_secs(10)) => result,
            held = peer.capture_get(extra_target) => panic!("the capacity bound must fail before a GET: {held:?}"),
        }
    })
    .await
    .expect("bounded capacity rejection");
    assert!(
        matches!(
            blocked,
            Err(RuntimeError::Resolve(ResolveError::Policy(
                RecordError::Capacity
            )))
        ),
        "the sixty-fifth key: {blocked:?}"
    );

    // Expiry advances wall and monotonic together: the publisher clock policy
    // accepts equal wall and monotonic progress and rejects monotonic-only
    // progress as a rollback.
    clock.set_wall(WALL + 30_000_001);
    clock.set_monotonic(30_000_001);

    // Deep-dive on the first slot: refresh, conflict, lower replay, recovery.
    let slot = record(0xa0, WALL);
    let slot_key = EndpointId::from_bytes(slot.key()).expect("slot key");
    let refreshed = resolve(&mut owner, &mut peer, &slot)
        .await
        .expect("the expired slot re-resolves");
    drop(refreshed);
    clock.set_wall(WALL + 60_000_002);
    clock.set_monotonic(60_000_002);
    let conflicting = record_at(0xa0, WALL, "127.0.0.1:9002".parse().expect("address"));
    assert!(matches!(
        resolve(&mut owner, &mut peer, &conflicting).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::EqualSequenceConflict
        )))
    ));
    assert_eq!(owner.resolver.cache_deadline(slot_key), None);
    assert_eq!(owner.resolver.winner_sequence(slot_key), Some(WALL));
    clock.set_wall(WALL + 61_000_002);
    let stale = record_at(
        0xa0,
        WALL - 5_000_000,
        "127.0.0.1:9003".parse().expect("address"),
    );
    assert!(matches!(
        resolve(&mut owner, &mut peer, &stale).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::Replay
        )))
    ));
    assert_eq!(owner.resolver.winner_sequence(slot_key), Some(WALL));
    assert_eq!(owner.resolver.cache_deadline(slot_key), None);
    let newer = record_at(
        0xa0,
        WALL + 3_000_000,
        "127.0.0.1:9001".parse().expect("address"),
    );
    let recovered = resolve(&mut owner, &mut peer, &newer)
        .await
        .expect("the strictly newer winner recovers the slot");
    drop(recovered);
    assert_eq!(
        owner.resolver.cache_deadline(slot_key),
        Some(90_000_002),
        "receipt 60_000_002 plus the 30-second cap",
    );

    // Every one of the sixty-four winners survives expiry: each remaining key
    // re-resolves through a fresh GET after its cache expired.
    for seed in 0xa1..0xe0 {
        let item = record(seed, WALL);
        let served = resolve(&mut owner, &mut peer, &item)
            .await
            .expect("surviving slot serves");
        assert_eq!(served.addresses().len(), 1);
        drop(served);
    }

    // No slot was evicted by the exercises: the sixty-fifth key is still
    // rejected without any GET.
    let blocked_again = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(extra_key, Instant::now() + Duration::from_secs(10)) => result,
            held = peer.capture_get(extra_target) => panic!("the capacity bound must not query: {held:?}"),
        }
    })
    .await
    .expect("bounded capacity rejection");
    assert!(matches!(
        blocked_again,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::Capacity
        )))
    ));

    // A surviving slot remains cached: the follow-up resolve is a cache hit.
    let survivor = record(0xa1, WALL);
    let survivor_key = EndpointId::from_bytes(survivor.key()).expect("survivor key");
    let survivor_target = MutableItem::target_from_key(survivor.key(), None);
    let hit = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(survivor_key, Instant::now() + Duration::from_secs(10)) => result,
            held = peer.capture_get(survivor_target) => panic!("the survivor cache hit must not query: {held:?}"),
        }
    })
    .await
    .expect("bounded cache hit")
    .expect("survivor cache hit");
    assert_eq!(hit.addresses().len(), 1);
    drop(hit);
    owner
        .close()
        .await
        .expect("actual joins after the slot exercises");
}
