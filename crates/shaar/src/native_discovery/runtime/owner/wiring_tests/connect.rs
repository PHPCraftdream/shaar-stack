// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::endpoint::NativeEndpointError;
use super::super::tests::fixture::LoopbackPeer;
use super::super::{endpoint_key, to_mutable};
use super::{bind, free_port, options, peer_v4};
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::ClockSample;
use crate::native_discovery::runtime::publisher::PublisherState;
use crate::network::{Allowlist, Endpoint, Limits};
use iroh_base::{PublicKey, TransportAddr};
use n0_mainline::MutableItem;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

fn now_us() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch");
    i64::try_from(elapsed.as_micros()).expect("microseconds fit")
}

/// A record signed by `identity` advertising `address`, fresh against the system clock.
fn signed_record(identity: &Identity, address: SocketAddr) -> MutableItem {
    let mut publisher = PublisherState::new(endpoint_key(identity).expect("key"));
    let sample = ClockSample {
        wall_us: now_us(),
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    };
    let (_, signed) = publisher
        .replace(identity, &[TransportAddr::Ip(address)], sample)
        .expect("upstream signed record");
    to_mutable(&signed.expect("signed snapshot")).expect("typed item")
}

async fn server(seed: u8, allowed: PublicKey) -> Endpoint {
    Endpoint::bind(
        &Identity::from_seed([seed; 32]),
        "127.0.0.1:0".parse().expect("loopback address"),
        Allowlist::new(&[allowed]).expect("allowlist"),
        Limits::new(4).expect("session limit"),
    )
    .await
    .expect("server endpoint binds")
}

#[tokio::test]
async fn resolved_address_connects_with_the_expected_key() {
    let mut peer = LoopbackPeer::bind().await;
    let mut client = bind(
        free_port().await,
        options(free_port().await, peer_v4(&peer)),
    )
    .await
    .expect("client binds");
    let identity_b = Identity::from_seed([0x62; 32]);
    let key_b = endpoint_key(&identity_b).expect("key");
    let mut server_b = server(0x62, client.id()).await;
    let item = signed_record(&identity_b, server_b.local_addr());
    let deadline = Instant::now() + Duration::from_secs(20);

    let (connected, accepted) = tokio::join!(
        async {
            tokio::select! {
                result = client.connect_until(key_b, deadline) => result,
                _ = peer.serve_record(&item) => unreachable!("the record server runs until the connect finishes"),
            }
        },
        server_b.accept(),
    );
    let connected = connected.expect("exact-key connect through the resolved address");
    let accepted = accepted.expect("allowlisted client accepted");
    assert_eq!(connected.peer_id(), key_b);
    assert_eq!(accepted.peer_id(), client.id());
    drop((connected, accepted));
    client.close().await.expect("client backends joined");
    server_b.close().await;
}

#[tokio::test]
async fn a_signed_address_hosting_another_identity_yields_no_session() {
    let mut peer = LoopbackPeer::bind().await;
    let mut client = bind(
        free_port().await,
        options(free_port().await, peer_v4(&peer)),
    )
    .await
    .expect("client binds");
    let key_b = endpoint_key(&Identity::from_seed([0x62; 32])).expect("key");
    // The record is signed by B but advertises the address of an endpoint owned by C.
    let mut impostor = server(0x63, client.id()).await;
    let item = signed_record(&Identity::from_seed([0x62; 32]), impostor.local_addr());
    let deadline = Instant::now() + Duration::from_secs(20);

    // The pinned future borrows the client; scope it so the borrow ends before close.
    let result = {
        let connect = async {
            tokio::select! {
                result = client.connect_until(key_b, deadline) => result,
                _ = peer.serve_record(&item) => unreachable!("the record server runs until the connect finishes"),
            }
        };
        tokio::pin!(connect);
        loop {
            tokio::select! {
                result = &mut connect => break result,
                _ = impostor.accept() => {}
            }
        }
    };
    assert!(
        matches!(result, Err(NativeEndpointError::Network(_))),
        "a different identity at the resolved address must not yield a session"
    );
    client.close().await.expect("client backends joined");
    impostor.close().await;
}

#[tokio::test]
async fn an_expired_deadline_fails_before_any_resolution_traffic() {
    let mut peer = LoopbackPeer::bind().await;
    let mut client = bind(
        free_port().await,
        options(free_port().await, peer_v4(&peer)),
    )
    .await
    .expect("client binds");
    let key_b = endpoint_key(&Identity::from_seed([0x62; 32])).expect("key");
    assert!(matches!(
        client.connect_until(key_b, Instant::now()).await,
        Err(NativeEndpointError::Deadline)
    ));
    let target = MutableItem::target_from_key(key_b.as_bytes(), None);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), peer.capture_get(target))
            .await
            .is_err(),
        "an expired deadline sends no GET"
    );
    client.close().await.expect("client backends joined");
}
