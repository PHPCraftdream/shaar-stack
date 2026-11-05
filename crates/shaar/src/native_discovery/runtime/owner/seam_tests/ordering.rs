// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::endpoint_key;
use super::super::tests::fixture::LoopbackPeer;
use super::{RuntimeError, capture_get, record_at, setup_two};
use crate::identity::Identity;
use crate::native_discovery::policy::RecordError;
use crate::native_discovery::runtime::owner::resolver::ResolveError;
use n0_mainline::MutableItem;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn two_responders_select_the_strictly_newer_signed_record() {
    let mut peer_a = LoopbackPeer::bind().await;
    let mut peer_b = LoopbackPeer::bind().await;
    let (mut owner, clock) = setup_two(0x77, &peer_a, &peer_b).await;
    let identity = Identity::from_seed([0x78; 32]);
    let key = endpoint_key(&identity).expect("record key");
    let target = MutableItem::target_from_key(key.as_bytes(), None);
    let lower = record_at(
        0x78,
        super::WALL + 1_000_000,
        "127.0.0.1:9001".parse().expect("address"),
    );
    let higher = record_at(
        0x78,
        super::WALL + 2_000_000,
        "127.0.0.1:9002".parse().expect("address"),
    );

    // Permutation one: responder B holds the newer record.
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source_a, transaction_a) = capture_get(&mut peer_a, target, &mut request).await;
    let (source_b, transaction_b) = capture_get(&mut peer_b, target, &mut request).await;
    peer_a.reply_get(source_a, &transaction_a, &lower).await;
    peer_b.reply_get(source_b, &transaction_b, &higher).await;
    let resolved = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded two-responder resolution")
        .expect("the strictly newer record wins");
    assert_eq!(
        resolved.addresses(),
        &["127.0.0.1:9002".parse::<SocketAddr>().expect("address")]
    );
    drop(resolved);
    assert_eq!(
        owner.resolver.winner_sequence(key),
        Some(super::WALL + 2_000_000),
        "the strictly newer sequence wins regardless of response order",
    );

    // The winner is cached: a following resolve is served without any GET.
    let hit = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            held = peer_a.capture_get(target) => panic!("a cached winner must not query responder A: {held:?}"),
            held = peer_b.capture_get(target) => panic!("a cached winner must not query responder B: {held:?}"),
        }
    })
    .await
    .expect("cache lookup completes without network")
    .expect("cache hit");
    assert_eq!(
        hit.addresses(),
        &["127.0.0.1:9002".parse::<SocketAddr>().expect("address")]
    );
    drop(hit);

    // Expiry advances wall and monotonic together: the publisher clock policy
    // rejects monotonic-only progress as a rollback.
    clock.set_wall(super::WALL + 30_000_001);
    clock.set_monotonic(30_000_001);

    // Permutation two: responder A holds the newest record and responder B a
    // stale one; the winner policy must again pick the strictly newest.
    let newest = record_at(
        0x78,
        super::WALL + 4_000_000,
        "127.0.0.1:9001".parse().expect("address"),
    );
    let mid = record_at(
        0x78,
        super::WALL + 3_000_000,
        "127.0.0.1:9003".parse().expect("address"),
    );
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source_a, transaction_a) = capture_get(&mut peer_a, target, &mut request).await;
    let (source_b, transaction_b) = capture_get(&mut peer_b, target, &mut request).await;
    peer_a.reply_get(source_a, &transaction_a, &newest).await;
    peer_b.reply_get(source_b, &transaction_b, &mid).await;
    let resolved = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded second resolution")
        .expect("the strictly newer record wins again");
    assert_eq!(
        resolved.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(resolved);
    assert_eq!(
        owner.resolver.winner_sequence(key),
        Some(super::WALL + 4_000_000),
        "both newer-responder permutations select the strictly newest record",
    );
    owner
        .close()
        .await
        .expect("actual joins after both permutations");
}

#[tokio::test]
async fn equal_sequence_conflict_from_two_responders_recovers_only_on_a_newer_sequence() {
    let mut peer_a = LoopbackPeer::bind().await;
    let mut peer_b = LoopbackPeer::bind().await;
    let (mut owner, _clock) = setup_two(0x7b, &peer_a, &peer_b).await;
    let identity = Identity::from_seed([0x7c; 32]);
    let key = endpoint_key(&identity).expect("record key");
    let target = MutableItem::target_from_key(key.as_bytes(), None);
    let first = record_at(
        0x7c,
        super::WALL,
        "127.0.0.1:9001".parse().expect("address"),
    );
    let conflicting = record_at(
        0x7c,
        super::WALL,
        "127.0.0.1:9002".parse().expect("address"),
    );
    let newer = record_at(
        0x7c,
        super::WALL + 3_000_000,
        "127.0.0.1:9001".parse().expect("address"),
    );

    // Two responders answer the same query with equal sequences and different
    // payloads: the policy reports the conflict instead of picking a winner.
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source_a, transaction_a) = capture_get(&mut peer_a, target, &mut request).await;
    let (source_b, transaction_b) = capture_get(&mut peer_b, target, &mut request).await;
    peer_a.reply_get(source_a, &transaction_a, &first).await;
    peer_b
        .reply_get(source_b, &transaction_b, &conflicting)
        .await;
    let conflicted = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded two-responder resolution")
        .expect_err("an equal-sequence conflicting pair must be rejected");
    assert!(
        matches!(
            conflicted,
            RuntimeError::Resolve(ResolveError::Policy(RecordError::EqualSequenceConflict))
        ),
        "conflict result: {conflicted:?}"
    );
    // The conflict commit clears the cache deadline and retains the sequence
    // watermark; it never renews the entry.
    assert_eq!(
        owner.resolver.cache_deadline(key),
        None,
        "the conflict must clear the cache deadline",
    );
    assert_eq!(
        owner.resolver.winner_sequence(key),
        Some(super::WALL),
        "the conflicting sequence is retained as the winner watermark",
    );

    // Recovery: a fresh GET with a strictly newer record and a stale equal
    // record; only the strictly newer sequence is accepted.
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source_a, transaction_a) = capture_get(&mut peer_a, target, &mut request).await;
    let (source_b, transaction_b) = capture_get(&mut peer_b, target, &mut request).await;
    peer_a.reply_get(source_a, &transaction_a, &newer).await;
    peer_b.reply_get(source_b, &transaction_b, &first).await;
    let recovered = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded recovery")
        .expect("a strictly newer sequence recovers the conflict");
    assert_eq!(
        recovered.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(recovered);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(30_000_000),
        "receipt-anchored renewal at monotonic zero plus the 30-second cap",
    );
    owner.close().await.expect("actual joins after recovery");
}
