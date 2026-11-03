// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::time::Instant;

use super::*;

#[tokio::test(start_paused = true)]
async fn public_put_until_preserves_entry_deadline_across_retries() {
    let (peer, peer_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor.owned_disable_maintenance_for_test = true;
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let actor_addr = handle
        .info()
        .await
        .expect("actor info")
        .local_addr();
    let entry = Instant::now();
    let deadline = entry + Duration::from_millis(250);
    let item = crate::common::MutableItem::new(
        &SigningKey::from_bytes(&[0xD7; 32]),
        b"until-retry-deadline",
        1,
        None,
    );
    let target = *item.target();
    let mut admission = handle
        .put_mutable_until(item, deadline)
        .expect("admit deadline-bounded PUT");
    admission.wait().await.expect("admit owned PUT");
    let mut operation = admission.take_operation().expect("owned PUT operation");

    let (get, source) = receive_request(&peer).await;
    assert_eq!(source, actor_addr);
    let get_reply = Message {
        transaction_id: get.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0xA8; 20]),
                token: vec![0x44, 0x55].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(&get_reply.to_bytes().expect("encode GET reply"), source)
        .await
        .expect("send GET reply");
    let (first, first_source) = receive_request(&peer).await;
    assert_eq!(first_source, source);
    handle.test_put_control(target, 100).await.expect("expire first PUT");
    tokio::time::advance(Duration::from_millis(100)).await;
    let (second, second_source) = receive_request(&peer).await;
    assert_eq!(second_source, source);
    assert_ne!(second.transaction_id, first.transaction_id);
    handle.test_put_control(target, 100).await.expect("expire second PUT");
    tokio::time::advance(Duration::from_millis(99)).await;
    handle.info().await.expect("before-third-attempt timer barrier");
    let mut bytes = [0u8; 2048];
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "third PUT waits for its scheduled retry"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    let (third, third_source) = receive_request(&peer).await;
    assert_eq!(third_source, source);
    assert_ne!(third.transaction_id, second.transaction_id);

    tokio::time::advance(Duration::from_millis(50)).await;
    assert!(matches!(
        operation.wait().await,
        Err(OwnedPutError::Resource(
            crate::resource::ResourceError::DeadlineExceeded
        ))
    ));
    operation.cancel_and_wait().await.expect("observe actual cleanup");
    tokio::time::advance(Duration::from_millis(200)).await;
    handle.info().await.expect("actor receipt barrier");
    assert_eq!(
        peer.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "deadline expiry did not send a fourth PUT"
    );
    owner.close().await.expect("close owner");
    drop(UdpSocket::bind(actor_addr).expect("owner released actor socket"));
}
