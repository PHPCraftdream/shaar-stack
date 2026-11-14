// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::super::tests::fixture::LoopbackPeer;
use super::super::{RuntimeOwner, endpoint_key};
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::TestClock;
use crate::native_discovery::runtime::owner::resolver::ReflexiveTally;
use n0_mainline::MutableItem;

const WALL: i64 = 1_700_000_000_000_000;

fn own_target(seed: u8) -> n0_mainline::Id {
    let key = endpoint_key(&Identity::from_seed([seed; 32])).expect("key");
    MutableItem::target_from_key(key.as_bytes(), None)
}

/// Spawns one answering task: loop `capture_get(own_target)`, count target
/// GETs, reply with the peer's vote (`None` = reply without `ip`).
async fn spawn_voter(
    peer: LoopbackPeer,
    target: n0_mainline::Id,
    vote: Option<Ipv4Addr>,
    gets: Arc<AtomicUsize>,
) -> SocketAddr {
    let address = peer.address;
    tokio::spawn(async move {
        let mut peer = peer;
        loop {
            let (source, transaction) = peer.capture_get(target).await;
            gets.fetch_add(1, Ordering::Relaxed);
            peer.reply_get_vote(source, &transaction, vote).await;
        }
    });
    address
}

async fn start_owner(
    seed: u8,
    bootstraps: &[SocketAddr],
) -> (RuntimeOwner, tokio::sync::watch::Receiver<Option<IpAddr>>) {
    let mut binds = Vec::with_capacity(bootstraps.len());
    for address in bootstraps {
        let SocketAddr::V4(bind) = *address else {
            panic!("IPv4 bootstrap");
        };
        binds.push(bind);
    }
    let owner = RuntimeOwner::start_controlled(
        Identity::from_seed([seed; 32]),
        "127.0.0.1:0".parse().expect("loopback"),
        &binds,
        TestClock::new(WALL),
    )
    .expect("actual runtime owner");
    let watch = owner.public_address_watch();
    // Let the spawned reflexive task consume its immediate first tick and arm
    // the window timer before any test pauses the clock; otherwise the first
    // advance would only create the interval and swallow window 1.
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    (owner, watch)
}

/// Drives exactly one 60 s refresh window under a paused clock.
async fn drive_window() {
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    tokio::time::resume();
}

/// Drives one window, waits (real clock, 5 s cap) until every peer has seen
/// `expected` target GETs, then lets the vote read and tally settle so the
/// next window cannot cancel an in-flight lookup through the paused clock.
async fn drive_window_settled(gets: &[Arc<AtomicUsize>], expected: usize) {
    drive_window().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while gets
        .iter()
        .any(|seen| seen.load(Ordering::Relaxed) < expected)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "window GET not observed in bounded time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// Bounded wait for the watch to change after a window (real clock, 5 s cap).
async fn expect_watch_change(watch: &mut tokio::sync::watch::Receiver<Option<IpAddr>>) {
    tokio::time::timeout(Duration::from_secs(5), watch.changed())
        .await
        .expect("bounded reflexive watch change")
        .expect("watch alive");
}

/// Bounded negative observation: the value must stay `None` while the
/// system settles (no fabricated exposure).
async fn assert_stays_none(owner: &RuntimeOwner) {
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(owner.public_address(), None);
    }
}

// Pure unit tests: sync, no sockets.
#[test]
fn tally_singleton_observation_keeps_none() {
    // Catches a majority filter that exposes a value from one ambiguous window.
    let mut tally = ReflexiveTally::new();
    let a: IpAddr = "203.0.113.5".parse().expect("ip");
    assert_eq!(tally.observe(Some(a)), None);
    assert_eq!(tally.observe(None), None);
}

#[test]
fn tally_two_agreeing_observations_expose() {
    // Catches a filter that never exposes without three agreeing windows.
    let mut tally = ReflexiveTally::new();
    let a: IpAddr = "203.0.113.5".parse().expect("ip");
    assert_eq!(tally.observe(Some(a)), None);
    assert_eq!(tally.observe(Some(a)), Some(a));
    assert_eq!(tally.observe(Some(a)), Some(a));
}

#[test]
fn tally_split_ring_keeps_incumbent() {
    // Catches exposure of a 1-vs-1-vs-empty split window.
    let mut tally = ReflexiveTally::new();
    let a: IpAddr = "203.0.113.5".parse().expect("ip");
    let b: IpAddr = "203.0.113.6".parse().expect("ip");
    assert_eq!(tally.observe(Some(a)), None);
    assert_eq!(tally.observe(Some(a)), Some(a));
    assert_eq!(tally.observe(Some(b)), Some(a));
    assert_eq!(tally.observe(None), Some(a));
    assert_eq!(tally.observe(Some(b)), Some(a));
}

#[test]
fn tally_three_way_tie_keeps_incumbent() {
    // Catches exposure when three distinct candidates tie 1-1-1.
    let mut tally = ReflexiveTally::new();
    let a: IpAddr = "203.0.113.5".parse().expect("ip");
    let b: IpAddr = "203.0.113.6".parse().expect("ip");
    let c: IpAddr = "203.0.113.7".parse().expect("ip");
    assert_eq!(tally.observe(Some(a)), None);
    assert_eq!(tally.observe(Some(a)), Some(a));
    assert_eq!(tally.observe(Some(b)), Some(a));
    assert_eq!(tally.observe(Some(c)), Some(a));
}

#[test]
fn tally_none_never_fabricates() {
    // Catches a filter that invents a value from absence of votes.
    let mut tally = ReflexiveTally::new();
    assert_eq!(tally.observe(None), None);
    assert_eq!(tally.observe(None), None);
    assert_eq!(tally.observe(None), None);
}

#[test]
fn tally_eviction_surfaces_change_after_two_agreeing_windows() {
    // Catches a stuck incumbent: [A,A,A] then B,B,B must flip at [A,B,B].
    let mut tally = ReflexiveTally::new();
    let a: IpAddr = "203.0.113.5".parse().expect("ip");
    let b: IpAddr = "203.0.113.6".parse().expect("ip");
    assert_eq!(tally.observe(Some(a)), Some(a));
    assert_eq!(tally.observe(Some(a)), Some(a));
    assert_eq!(tally.observe(Some(a)), Some(a));
    assert_eq!(tally.observe(Some(b)), Some(a)); // [A,A,B]
    assert_eq!(tally.observe(Some(b)), Some(b)); // [A,B,B]
    assert_eq!(tally.observe(Some(b)), Some(b)); // [B,B,B]
}

// Fixture: three peers vote A, A, B -> two windows expose A; exactly one
// bounded self-lookup per window per peer (the publisher is idle without a
// replace command, so every target GET counted belongs to the reflexive task).
#[tokio::test]
async fn fixture_majority_exposes_after_two_agreeing_windows() {
    let votes = [
        Some("203.0.113.5".parse::<Ipv4Addr>().expect("vote A")),
        Some("203.0.113.5".parse::<Ipv4Addr>().expect("vote A")),
        Some("203.0.113.6".parse::<Ipv4Addr>().expect("vote B")),
    ];
    let target = own_target(0x52);
    let mut peers = Vec::new();
    let mut counters = Vec::new();
    for vote in votes {
        let peer = LoopbackPeer::bind().await;
        let gets = Arc::new(AtomicUsize::new(0));
        let address = spawn_voter(peer, target, vote, Arc::clone(&gets)).await;
        peers.push(address);
        counters.push(gets);
    }
    let (mut owner, mut watch) = start_owner(0x52, &peers).await;
    assert_eq!(owner.public_address(), None);

    // Window 1: single observation, no majority yet.
    drive_window_settled(&counters, 1).await;
    assert_eq!(owner.public_address(), None);

    // Window 2: [A,A,empty] majority -> exposed.
    drive_window_settled(&counters, 2).await;
    expect_watch_change(&mut watch).await;
    assert_eq!(
        owner.public_address(),
        Some("203.0.113.5".parse::<IpAddr>().expect("ip A"))
    );

    // Exactly one bounded self-lookup per window: 2 target GETs per peer.
    for gets in &counters {
        assert_eq!(gets.load(Ordering::Relaxed), 2);
    }
    owner.close().await.expect("bounded close");
}

// Fixture: 2 peers vote A and B -> a single ambiguous window is never
// exposed (crate-internal per-query ties are unobservable here; see
// iterative_query.rs:129-141 for the nondeterministic tie source).
#[tokio::test]
async fn fixture_conflicting_tie_never_exposes() {
    let votes = [
        Some("203.0.113.5".parse::<Ipv4Addr>().expect("vote A")),
        Some("203.0.113.6".parse::<Ipv4Addr>().expect("vote B")),
    ];
    let target = own_target(0x54);
    let mut peers = Vec::new();
    let mut counters = Vec::new();
    for vote in votes {
        let peer = LoopbackPeer::bind().await;
        let gets = Arc::new(AtomicUsize::new(0));
        let address = spawn_voter(peer, target, vote, Arc::clone(&gets)).await;
        peers.push(address);
        counters.push(gets);
    }
    let (mut owner, _watch) = start_owner(0x54, &peers).await;
    assert_eq!(owner.public_address(), None);
    drive_window_settled(&counters, 1).await;
    assert_stays_none(&owner).await;
    owner.close().await.expect("bounded close");
}

// Fixture: one peer replies without `ip` -> absence of votes never exposes;
// no GET is sent before the first window boundary.
#[tokio::test]
async fn fixture_vote_absence_keeps_none_and_first_lookup_is_windowed() {
    let target = own_target(0x56);
    let peer = LoopbackPeer::bind().await;
    let gets = Arc::new(AtomicUsize::new(0));
    let address = spawn_voter(peer, target, None, Arc::clone(&gets)).await;
    let (mut owner, _watch) = start_owner(0x56, &[address]).await;

    // Bounded negative observation right after start: nothing before the
    // first window boundary.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(gets.load(Ordering::Relaxed), 0);
    }

    for window in 1..=2 {
        drive_window_settled(std::slice::from_ref(&gets), window).await;
        assert_stays_none(&owner).await;
    }
    assert_eq!(gets.load(Ordering::Relaxed), 2);
    owner.close().await.expect("bounded close");
}

// Fixture: a peer captures but never answers; shutdown cancels the in-flight
// lookup without retry and the close contract stays bounded.
#[tokio::test]
async fn fixture_shutdown_cancels_inflight_lookup() {
    let target = own_target(0x58);
    let peer = LoopbackPeer::bind().await;
    let address = peer.address;
    let gets = Arc::new(AtomicUsize::new(0));
    let captured = Arc::clone(&gets);
    // Silent peer: capture the first GET, then park forever without answering.
    tokio::spawn(async move {
        let mut peer = peer;
        let _ = peer.capture_get(target).await;
        captured.fetch_add(1, Ordering::Relaxed);
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let (mut owner, _watch) = start_owner(0x58, &[address]).await;

    drive_window().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while gets.load(Ordering::Relaxed) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "GET not captured in bounded time"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let closed = tokio::time::timeout(Duration::from_secs(10), owner.close())
        .await
        .expect("bounded close attempt");
    assert!(closed.is_ok(), "close returns Ok: {closed:?}");

    // Cancelled lookup is not retried: no further GET arrives.
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(gets.load(Ordering::Relaxed), 1);
    }
    assert!(!owner.has_pending_cleanup());
}
