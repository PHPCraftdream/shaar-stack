// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::endpoint_key;
use super::super::tests::fixture::LoopbackPeer;
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::wiring_tests::connect::signed_record;
use crate::native_discovery::runtime::owner::wiring_tests::{bind, free_port, options, peer_v4};
use crate::network::{Allowlist, Endpoint, Limits};
use n0_mainline::MutableItem;
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn cancelled_connect_until_never_dials_late_and_the_cache_stays_uncommitted() {
    let mut peer = LoopbackPeer::bind().await;
    let mut client = bind(
        free_port().await,
        options(free_port().await, peer_v4(&peer)),
    )
    .await
    .expect("client binds");
    let identity_b = Identity::from_seed([0x62; 32]);
    let key_b = endpoint_key(&identity_b).expect("record key");
    let target = MutableItem::target_from_key(key_b.as_bytes(), None);
    let mut server_b = Endpoint::bind(
        &identity_b,
        "127.0.0.1:0".parse().expect("loopback address"),
        Allowlist::new(&[client.id()]).expect("allowlist"),
        Limits::new(4).expect("session limit"),
    )
    .await
    .expect("server endpoint binds");
    let item = signed_record(&identity_b, server_b.local_addr());

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut connect = Box::pin(client.connect_until(key_b, deadline));
    let (source, transaction) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = &mut connect => panic!("connect completed before the held response: {result:?}"),
        }
    })
    .await
    .expect("actual GET captured");

    // Cancel before the GET response: the dropped connect abandons its own
    // resolution, so no dial can ever start from it.
    drop(connect);
    peer.reply_get(source, &transaction, &item).await;

    // No late dial: the real second endpoint must not accept anything after
    // the late response was processed.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server_b.accept())
            .await
            .is_err(),
        "a cancelled connect must not dial the resolved address",
    );

    // No cache commit: a later connect of the same key performs a fresh GET.
    let mut retry = Box::pin(client.connect_until(key_b, Instant::now() + Duration::from_secs(20)));
    let (next_source, next_transaction) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            _ = &mut retry => panic!("the late response committed a cache hit"),
        }
    })
    .await
    .expect("a fresh GET is required after cancellation");
    assert_ne!(
        next_transaction, transaction,
        "the late response must not serve the retry",
    );
    peer.reply_get(next_source, &next_transaction, &item).await;

    // Positive control: the retry dial completes a real session at the second
    // endpoint.
    let (connected, accepted) = tokio::join!(&mut retry, server_b.accept());
    // End the pinned connect (and with it the exclusive client borrow) before
    // the client is used again.
    drop(retry);
    let session = connected.expect("retry connect reaches the real endpoint");
    let accepted = accepted.expect("allowlisted client accepted");
    let client_id = client.id();
    assert_eq!(session.peer_id(), key_b);
    assert_eq!(accepted.peer_id(), client_id);
    drop((session, accepted));
    client.close().await.expect("client backends joined");
    server_b.close().await;
}
