// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use n0_mainline::{Id, OwnedDht, OwnedDhtHandle, ResourceError};

#[tokio::test]
async fn owned_api_handle_is_limited_and_reports_shutdown() {
    let bootstrap = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral loopback bootstrap socket");
    let bootstrap_addr = match bootstrap.local_addr().expect("bootstrap socket address") {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!("loopback bootstrap socket is IPv4"),
    };
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

    let rebound =
        UdpSocket::bind(actor_addr).expect("owned actor released its bound socket after join");
    drop(rebound);
}
