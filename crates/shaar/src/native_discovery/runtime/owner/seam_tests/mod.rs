// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

mod cache_lifetime;
mod connect_cancel;
mod deadline_sharing;
mod dropped_resolve;
mod ordering;

use super::tests::fixture::LoopbackPeer;
use super::{RuntimeError, RuntimeOwner, endpoint_key, to_mutable};
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::TestClock;
use crate::native_discovery::runtime::owner::resolver::ResolvedAddresses;
use crate::native_discovery::runtime::publisher::PublisherState;
use iroh_base::{EndpointId, TransportAddr};
use n0_mainline::MutableItem;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;
use tokio::time::Instant;

const WALL: i64 = 1_700_000_000_000_000;

async fn setup(seed: u8) -> (LoopbackPeer, RuntimeOwner, TestClock) {
    let peer = LoopbackPeer::bind().await;
    let SocketAddr::V4(bootstrap) = peer.address else {
        panic!("IPv4 bootstrap");
    };
    let clock = TestClock::new(WALL);
    let owner = RuntimeOwner::start_controlled(
        Identity::from_seed([seed; 32]),
        "127.0.0.1:0".parse().expect("loopback"),
        &[bootstrap],
        clock.clone(),
    )
    .expect("actual runtime owner");
    (peer, owner, clock)
}

/// Two loopback peers as two bootstrap entries: the owned GET query visits
/// every bootstrap address whenever it knows fewer closest nodes, so both
/// peers deterministically receive one GET per query.
async fn setup_two(
    seed: u8,
    peer_a: &LoopbackPeer,
    peer_b: &LoopbackPeer,
) -> (RuntimeOwner, TestClock) {
    let SocketAddr::V4(bootstrap_a) = peer_a.address else {
        panic!("IPv4 bootstrap");
    };
    let SocketAddr::V4(bootstrap_b) = peer_b.address else {
        panic!("IPv4 bootstrap");
    };
    let clock = TestClock::new(WALL);
    let owner = RuntimeOwner::start_controlled(
        Identity::from_seed([seed; 32]),
        "127.0.0.1:0".parse().expect("loopback"),
        &[bootstrap_a, bootstrap_b],
        clock.clone(),
    )
    .expect("actual runtime owner");
    (owner, clock)
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
) -> Result<ResolvedAddresses, RuntimeError> {
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

/// Captures the GET of a pinned, not-yet-completed resolve request. The held
/// GET reply stays under the caller's control.
async fn capture_get<F>(
    peer: &mut LoopbackPeer,
    target: n0_mainline::Id,
    request: &mut Pin<Box<F>>,
) -> (SocketAddr, Vec<u8>)
where
    F: Future<Output = Result<ResolvedAddresses, RuntimeError>>,
{
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = request => panic!("resolution completed before the held response: {result:?}"),
        }
    })
    .await
    .expect("actual GET captured")
}
