// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::fixture::LoopbackPeer;
use crate::identity::Identity;
use iroh_base::TransportAddr;

#[tokio::test]
async fn initial_put_is_acknowledged_and_close_joins_before_socket_rebind() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let identity = Identity::from_seed([0x51; 32]);
    let mut owner = super::super::RuntimeOwner::start(
        identity.clone(),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT binds on loopback");
    let actor_handle = owner.dht_handle().expect("sender-only actor handle");
    let local_address = actor_handle
        .info()
        .await
        .expect("actor bound before publication")
        .local_addr();
    let address = TransportAddr::Ip(
        "127.0.0.1:9001"
            .parse()
            .expect("published loopback address"),
    );

    let replace = owner.replace(vec![address]);
    let mut replace = Box::pin(replace);
    let (source, transaction, captured) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replace => panic!("unexpected PUT result before peer captured it: {result:?}"),
    };
    peer.acknowledge(source, &transaction).await;
    assert!(
        replace.await.is_ok(),
        "replacement succeeds after actual PUT acknowledgement"
    );
    assert_eq!(captured.key, identity.public_key_bytes());
    assert_eq!(captured.signature.len(), 64);
    assert!(captured.sequence > 0);
    let envelope = signed_envelope(&captured);
    let signed = iroh_dns::pkarr::SignedPacket::from_bytes(&envelope)
        .expect("captured PUT envelope verifies the signature");
    let endpoint = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("PUT value decodes as endpoint info");
    let expected = iroh_base::EndpointId::from_bytes(&identity.public_key_bytes())
        .expect("expected endpoint identity");
    assert_eq!(endpoint.endpoint_id, expected);
    let expected_address: std::net::SocketAddr = "127.0.0.1:9001"
        .parse()
        .expect("expected published address");
    assert_eq!(
        endpoint
            .ip_addrs()
            .copied()
            .collect::<Vec<std::net::SocketAddr>>(),
        vec![expected_address]
    );

    owner
        .withdraw()
        .await
        .expect("withdraw completes after PUT cleanup");
    owner
        .close()
        .await
        .expect("publisher and actor joins observed");
    assert!(owner.dht.is_none());
    assert!(actor_handle.info().await.is_err());
    let rebound = tokio::net::UdpSocket::bind(local_address)
        .await
        .expect("joined actor released UDP socket");
    drop(rebound);
}

#[tokio::test]
async fn rejected_put_does_not_persist_and_owner_can_publish_replacement() {
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let identity = Identity::from_seed([0x52; 32]);
    let mut owner = super::super::RuntimeOwner::start(
        identity,
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
    )
    .expect("owned DHT binds on loopback");
    let actor_handle = owner.dht_handle().expect("sender-only actor handle");
    let local_address = actor_handle
        .info()
        .await
        .expect("actor bound before publication")
        .local_addr();

    let first = TransportAddr::Ip("127.0.0.1:9002".parse().expect("first published address"));
    let mut replace = Box::pin(owner.replace(vec![first]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replace => panic!("unexpected PUT result before peer captured it: {result:?}"),
    };
    peer.reject(source, &transaction).await;
    let result = replace.await;
    let Err(super::super::RuntimeError::Put(n0_mainline::OwnedPutError::Put(
        n0_mainline::errors::PutError::Query(n0_mainline::errors::PutQueryError::ErrorResponse(
            error,
        )),
    ))) = result
    else {
        panic!("wire KRPC rejection must preserve its typed PUT error: {result:?}");
    };
    assert_eq!(error.code, 201);
    assert_eq!(error.description, "PUT rejected");
    let cleanup = owner
        .barrier()
        .await
        .expect("publisher remains responsive after rejection");
    assert!(!cleanup.active, "rejected initial PUT was not persisted");

    let second = TransportAddr::Ip("127.0.0.1:9003".parse().expect("replacement address"));
    let replace = owner.replace(vec![second]);
    let receive_put = peer.serve_until_put();
    let (result, captured) = tokio::join!(replace, receive_put);
    assert!(result.is_ok(), "later replacement succeeds after rejection");
    let signed = iroh_dns::pkarr::SignedPacket::from_bytes(&signed_envelope(&captured))
        .expect("replacement PUT signature verifies");
    let endpoint = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("replacement PUT decodes");
    let expected_address: std::net::SocketAddr = "127.0.0.1:9003"
        .parse()
        .expect("expected replacement address");
    assert_eq!(
        endpoint
            .ip_addrs()
            .copied()
            .collect::<Vec<std::net::SocketAddr>>(),
        vec![expected_address]
    );

    owner
        .close()
        .await
        .expect("publisher and actor joins observed");
    assert!(owner.dht.is_none());
    assert!(actor_handle.info().await.is_err());
    let rebound = tokio::net::UdpSocket::bind(local_address)
        .await
        .expect("joined actor released UDP socket");
    drop(rebound);
}

fn signed_envelope(put: &super::fixture::CapturedPut) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(104 + put.value.len());
    envelope.extend_from_slice(&put.key);
    envelope.extend_from_slice(&put.signature);
    envelope.extend_from_slice(&put.sequence.to_be_bytes());
    envelope.extend_from_slice(&put.value);
    envelope
}
