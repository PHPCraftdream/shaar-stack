// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::tests::fixture::LoopbackPeer;
use super::{RuntimeError, RuntimeOwner, endpoint_key, to_mutable};
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::TestClock;
use crate::native_discovery::runtime::publisher::PublisherState;
use iroh_base::{EndpointId, TransportAddr};
use n0_mainline::MutableItem;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

const WALL: i64 = 1_700_000_000_000_000;

async fn setup() -> (LoopbackPeer, RuntimeOwner, TestClock) {
    let peer = LoopbackPeer::bind().await;
    let SocketAddr::V4(bootstrap) = peer.address else {
        panic!("IPv4 bootstrap");
    };
    let clock = TestClock::new(WALL);
    let owner = RuntimeOwner::start_controlled(
        Identity::from_seed([0x71; 32]),
        "127.0.0.1:0".parse().expect("loopback"),
        &[bootstrap],
        clock.clone(),
    )
    .expect("actual runtime owner");
    (peer, owner, clock)
}

fn record_at(seed: u8, sequence: i64, address: SocketAddr) -> MutableItem {
    let identity = Identity::from_seed([seed; 32]);
    let mut publisher = PublisherState::new(endpoint_key(&identity).expect("key"));
    let sample = crate::native_discovery::runtime::clock::ClockSample {
        wall_us: sequence,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    };
    let (_, signed) = publisher
        .replace(&identity, &[TransportAddr::Ip(address)], sample)
        .expect("upstream signed record");
    to_mutable(&signed.expect("signed snapshot")).expect("typed item")
}

fn record(seed: u8, sequence: i64) -> MutableItem {
    record_at(seed, sequence, "127.0.0.1:9001".parse().expect("address"))
}

async fn resolve(
    owner: &mut RuntimeOwner,
    peer: &mut LoopbackPeer,
    item: &MutableItem,
) -> Result<crate::native_discovery::runtime::owner::resolver::ResolvedAddresses, RuntimeError> {
    let key = EndpointId::from_bytes(item.key()).expect("expected key");
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            _ = peer.serve_record(item) => unreachable!("server runs until request completes"),
        }
    })
    .await
    .expect("bounded real resolution")
}

async fn held_completion(
    owner: &RuntimeOwner,
    peer: &mut LoopbackPeer,
    item: &MutableItem,
) -> n0_mainline::OwnedQueryCompletion {
    let handle = owner.dht_handle().expect("actual actor handle");
    let target = MutableItem::target_from_key(item.key(), None);
    tokio::select! {
        result = handle.resolve_mutable(target) => result.expect("actual backend completion"),
        _ = peer.serve_record(item) => unreachable!("serve until completion"),
    }
}

#[tokio::test]
async fn deadline_passing_during_preparation_cannot_commit_cache_state() {
    use crate::native_discovery::runtime::clock::ClockSample;
    use crate::native_discovery::runtime::owner::resolver::ResolveError;

    let (mut peer, mut owner, _) = setup().await;
    let item = record(0x8a, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    let target = MutableItem::target_from_key(item.key(), None);
    let completion = held_completion(&owner, &mut peer, &item).await;
    let sample = ClockSample {
        wall_us: WALL,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    };
    assert!(
        owner
            .resolver
            .begin(key, sample)
            .expect("admit expected key")
            .is_none()
    );
    tokio::time::pause();
    let deadline = Instant::now() + Duration::from_millis(1);
    // Preparation runs first; the paused-clock advance fires inside the
    // test-only cooperative point, so only a post-preparation deadline check
    // can reject this commit.
    let (result, _) = tokio::join!(
        owner.resolver.complete(key, completion, sample, deadline),
        tokio::time::advance(Duration::from_secs(1)),
    );
    tokio::time::resume();
    assert!(
        matches!(result, Err(ResolveError::DeadlineExceeded)),
        "post-preparation deadline: {result:?}"
    );
    assert_eq!(owner.resolver.cache_deadline(key), None);

    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source, transaction) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = &mut request => panic!("expired commit populated usable cache: {result:?}"),
        }
    })
    .await
    .expect("fresh network query required");
    peer.reply_get(source, &transaction, &item).await;
    drop(request.await.expect("fresh response accepted"));
    owner
        .close()
        .await
        .expect("actual joins after rejected preparation");
}

#[tokio::test]
async fn cached_results_share_the_owner_wide_delivery_budget_before_allocation() {
    use crate::native_discovery::runtime::owner::resolver::ResolveError;

    let (mut peer, mut owner, _) = setup().await;
    let item = record(0x8b, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    let target = MutableItem::target_from_key(item.key(), None);
    let mut held = vec![
        resolve(&mut owner, &mut peer, &item)
            .await
            .expect("charged network result"),
    ];
    for _ in 0..7 {
        let hit = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
                _ = peer.capture_get(target) => panic!("cache hit must not issue a GET"),
            }
        })
        .await
        .expect("cache lookup completes without network")
        .expect("cache hit");
        held.push(hit);
    }
    let ninth = tokio::time::timeout(
        Duration::from_secs(2),
        owner.resolve_until(key, Instant::now() + Duration::from_secs(10)),
    )
    .await
    .expect("rejected before allocation, without waiting on the network");
    assert!(
        matches!(
            ninth,
            Err(RuntimeError::Resolve(ResolveError::DeliveryLimit))
        ),
        "eight held results must reject a ninth before allocation: {ninth:?}"
    );
    drop(held.pop());
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            _ = peer.capture_get(target) => panic!("released budget must serve the cached key without a GET"),
        }
    })
    .await
    .expect("budget recovery completes without network")
    .expect("cache hit after release");
    assert_eq!(
        recovered.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(recovered);
    drop(held);
    owner
        .close()
        .await
        .expect("actual joins with delivery budget released");
}

#[tokio::test]
async fn current_use_freshness_bounds_immediate_results_and_cache_lifetime() {
    use crate::native_discovery::policy::RecordError;
    use crate::native_discovery::runtime::owner::resolver::ResolveError;

    let (mut peer, mut owner, clock) = setup().await;
    let item = record(0x8d, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    let target = MutableItem::target_from_key(item.key(), None);

    // The receipt is sampled locally the moment the backend returns: holding
    // the response while the controlled clock advances moves the receipt to
    // the completion point, and the 30-second cap starts there, not at the
    // later use.
    clock.set_monotonic(1_000_000);
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source, transaction) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = &mut request => panic!("GET completed before held response: {result:?}"),
        }
    })
    .await
    .expect("actual GET captured");
    clock.set_monotonic(6_000_000);
    clock.set_wall(WALL + 5_000_000);
    peer.reply_get(source, &transaction, &item).await;
    let delivered = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("bounded real resolution")
        .expect("receipt-time commit");
    assert_eq!(delivered.addresses().len(), 1);
    drop(delivered);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(36_000_000),
        "the 30-second cap is anchored at the receipt, not shifted by the later use"
    );

    // The cap still expires at receipt + 30 seconds: at +34.999 s the cached
    // result is served, at +35 s a real GET is required again.
    clock.set_monotonic(35_999_999);
    clock.set_wall(WALL + 34_999_999);
    let hit = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            _ = peer.capture_get(target) => panic!("within the receipt cap no GET may be issued"),
        }
    })
    .await
    .expect("cache lookup completes")
    .expect("cache hit within the receipt cap");
    assert_eq!(hit.addresses().len(), 1);
    drop(hit);

    clock.set_monotonic(36_000_000);
    clock.set_wall(WALL + 35_000_000);
    let refreshed = resolve(&mut owner, &mut peer, &item)
        .await
        .expect("re-query after the cap");
    assert_eq!(refreshed.addresses().len(), 1);
    drop(refreshed);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(66_000_000),
        "the renewed deadline uses the new receipt",
    );

    // Exactly 300 seconds of signed age is still acceptable at use, with
    // zero positive cache lifetime.
    clock.set_monotonic(100_000_000);
    clock.set_wall(WALL + 300_000_000);
    let boundary = resolve(&mut owner, &mut peer, &item)
        .await
        .expect("age exactly 300 seconds is accepted");
    assert_eq!(boundary.addresses().len(), 1);
    drop(boundary);
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(100_000_000),
        "zero positive cache lifetime at the boundary",
    );

    // One microsecond past the boundary, current-use freshness rejects the
    // result: TooOld, no commit, watermark retained.
    clock.set_monotonic(100_000_001);
    clock.set_wall(WALL + 300_000_001);
    assert!(matches!(
        resolve(&mut owner, &mut peer, &item).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::TooOld
        )))
    ));
    assert_eq!(
        owner.resolver.cache_deadline(key),
        Some(100_000_000),
        "an age-expired result must not commit cache state"
    );
    assert_eq!(owner.resolver.winner_sequence(key), Some(WALL));
    owner
        .close()
        .await
        .expect("actual joins after boundary receipts");
}

#[tokio::test]
async fn commit_point_freshness_rejects_a_result_that_ages_out_during_handoff() {
    use crate::native_discovery::policy::RecordError;
    use crate::native_discovery::runtime::clock::ClockSample;
    use crate::native_discovery::runtime::owner::resolver::ResolveError;

    let (mut peer, mut owner, clock) = setup().await;
    let sample = ClockSample {
        wall_us: WALL,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    };

    // The receipt sample stays fresh; the controlled wall clock advances at the
    // test-only cooperative point after preparation, so only the commit-time
    // current-use check can see the age. Exactly 300 seconds is accepted and
    // leaves no positive cache lifetime.
    let accepted = record(0x8e, WALL);
    let accepted_key = EndpointId::from_bytes(accepted.key()).expect("key");
    let completion = held_completion(&owner, &mut peer, &accepted).await;
    assert!(
        owner
            .resolver
            .begin(accepted_key, sample)
            .expect("admit expected key")
            .is_none()
    );
    let (result, ()) = tokio::join!(
        owner.resolver.complete(
            accepted_key,
            completion,
            sample,
            Instant::now() + Duration::from_secs(10)
        ),
        async {
            clock.set_wall(WALL + 300_000_000);
        },
    );
    drop(result.expect("age exactly 300 s at the commit point"));
    assert_eq!(owner.resolver.cache_deadline(accepted_key), Some(0));

    // One microsecond older at the commit point is rejected without any commit.
    clock.set_wall(WALL);
    let stale = record(0x8f, WALL);
    let stale_key = EndpointId::from_bytes(stale.key()).expect("key");
    let completion = held_completion(&owner, &mut peer, &stale).await;
    assert!(
        owner
            .resolver
            .begin(stale_key, sample)
            .expect("admit expected key")
            .is_none()
    );
    let (result, ()) = tokio::join!(
        owner.resolver.complete(
            stale_key,
            completion,
            sample,
            Instant::now() + Duration::from_secs(10)
        ),
        async {
            clock.set_wall(WALL + 300_000_001);
        },
    );
    assert!(
        matches!(result, Err(ResolveError::Policy(RecordError::TooOld))),
        "age 300 s + 1 us at the commit point: {result:?}"
    );
    assert_eq!(owner.resolver.cache_deadline(stale_key), None);
    assert_eq!(owner.resolver.winner_sequence(stale_key), None);
    owner
        .close()
        .await
        .expect("actual joins after commit-point freshness cases");
}

/// cancel-safe: NO — a timed-out query is terminal for this owned test scenario.
async fn resolve_fresh(
    owner: &mut RuntimeOwner,
    peer: &mut LoopbackPeer,
    item: &MutableItem,
) -> Result<crate::native_discovery::runtime::owner::resolver::ResolvedAddresses, RuntimeError> {
    let key = EndpointId::from_bytes(item.key()).expect("expected key");
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::select! {
            result = owner.resolve_fresh_until(key, Instant::now() + Duration::from_secs(10)) => result,
            _ = peer.serve_record(item) => unreachable!("serve until fresh lookup completes"),
        }
    }).await.expect("bounded actual fresh query")
}

#[tokio::test]
async fn fresh_lookup_bypasses_live_address_cache_but_preserves_replay_watermark() {
    use super::resolver::ResolveError;
    use crate::native_discovery::policy::RecordError;
    let (mut peer, mut owner, clock) = setup().await;
    let old_address = "127.0.0.1:9001".parse::<SocketAddr>().expect("old socket");
    let new_address = "127.0.0.1:9002".parse::<SocketAddr>().expect("new socket");
    let old = record_at(0xb1, WALL, old_address);
    let new = record_at(0xb1, WALL + 1, new_address);
    let key = EndpointId::from_bytes(old.key()).expect("record key");
    let first = resolve(&mut owner, &mut peer, &old)
        .await
        .expect("first publication");
    assert_eq!(first.addresses(), &[old_address]);
    drop(first);
    let cached = owner
        .resolve_until(key, Instant::now() + Duration::from_secs(10))
        .await
        .expect("ordinary live cache hit");
    assert_eq!(cached.addresses(), &[old_address]);
    drop(cached);
    assert_eq!(owner.resolver.cache_deadline(key), Some(30_000_000));
    clock.set_wall(WALL + 1_000_000);
    clock.set_monotonic(1_000_000);
    let unchanged = resolve_fresh(&mut owner, &mut peer, &old)
        .await
        .expect("same winner remains usable through a real new network receipt");
    assert_eq!(unchanged.addresses(), &[old_address]);
    drop(unchanged);
    // A real GET renews at its new receipt; ordinary cache hits above do not.
    assert_eq!(owner.resolver.cache_deadline(key), Some(31_000_000));
    let fresh = resolve_fresh(&mut owner, &mut peer, &new)
        .await
        .expect("new signed socket before TTL expiry");
    assert_eq!(fresh.addresses(), &[new_address]);
    drop(fresh);
    assert_eq!(owner.resolver.winner_sequence(key), Some(WALL + 1));
    assert!(matches!(
        resolve_fresh(&mut owner, &mut peer, &old).await,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::Replay
        )))
    ));
    assert_eq!(owner.resolver.winner_sequence(key), Some(WALL + 1));
    owner
        .close()
        .await
        .expect("actual fresh-lookup owner joins");
}
