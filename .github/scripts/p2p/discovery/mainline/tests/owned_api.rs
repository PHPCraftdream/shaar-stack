// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use n0_mainline::{
    Id, MutableItem, OwnedDht, OwnedDhtHandle, OwnedPutOperation, ResourceError,
};

fn loopback_bootstrap() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral loopback bootstrap socket");
    let addr = match socket.local_addr().expect("bootstrap socket address") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("loopback bootstrap socket is IPv4"),
    };
    (socket, addr)
}

fn mutable_item(sequence: i64) -> MutableItem {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x25; 32]);
    MutableItem::new(&signer, b"owned API test", sequence, None)
}

#[tokio::test]
async fn owned_api_handle_is_limited_and_reports_shutdown() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained: OwnedDhtHandle = owner.handle();
    let info = retained.info().await.expect("actor info before shutdown");
    let actor_addr = info.local_addr();
    assert_eq!(
        info.id(),
        owner.handle().info().await.expect("same actor info").id()
    );

    drop(bootstrap);
    owner.close().await.expect("join owned actor");
    assert!(matches!(
        retained.resolve_mutable(Id::random()).await,
        Err(ResourceError::QueryCancelled)
    ));
    assert!(matches!(
        retained.info().await,
        Err(ResourceError::QueryCancelled)
    ));
    assert!(matches!(
        retained.put_mutable(mutable_item(1)).await,
        Err(ResourceError::QueryCancelled)
    ));

    let rebound = UdpSocket::bind(actor_addr).expect("owned actor released its bound socket after join");
    drop(rebound);
}

#[tokio::test]
async fn owned_api_put_cancellation_finishes_operation() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained = owner.handle();
    let mut operation: OwnedPutOperation = retained
        .put_mutable(mutable_item(1))
        .await
        .expect("admit mutable put");
    operation.cancel_and_wait().await.expect("cancel and clean up operation");
    assert!(retained.info().await.expect("actor remains live").local_addr().port() > 0);
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_put_rejects_invalid_profiles() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained = owner.handle();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x26; 32]);

    let invalid_items = [
        MutableItem::new(&signer, &vec![0; 1001], 1, None),
        MutableItem::new(&signer, b"negative", -1, None),
        MutableItem::new(&signer, b"salted", 1, Some(b"salt")),
    ];
    for item in invalid_items {
        assert!(matches!(
            retained.put_mutable(item).await,
            Err(ResourceError::InvalidMutableItem)
        ));
    }

    let valid = MutableItem::new(&signer, b"valid", 1, None);
    let mut sig = *valid.signature();
    sig[0] ^= 1;
    let invalid_signature = MutableItem::new_signed_unchecked(
        *valid.key(),
        sig,
        valid.value(),
        valid.seq(),
        None,
    );
    assert!(matches!(
        retained.put_mutable(invalid_signature).await,
        Err(ResourceError::InvalidMutableItem)
    ));

    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}

#[tokio::test]
async fn owned_api_put_accepts_maximum_value_size() {
    let (bootstrap, bootstrap_addr) = loopback_bootstrap();
    let mut owner = OwnedDht::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &[bootstrap_addr])
        .expect("bind owned DHT");
    let retained = owner.handle();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x26; 32]);
    let mut operation = retained
        .put_mutable(MutableItem::new(&signer, &vec![0; 1000], 1, None))
        .await
        .expect("admit maximum-size mutable item");
    operation.cancel_and_wait().await.expect("cancel and clean up operation");
    drop(bootstrap);
    owner.close().await.expect("join owned actor");
}
