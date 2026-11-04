// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::endpoint::{NativeDiscoveredEndpoint, NativeEndpointError};
use super::super::endpoint_key;
use super::super::options::{
    InvalidOption, NativeDiscoveryOptions, NativeOptionField, NativeOptionReason,
};
use super::super::tests::fixture::LoopbackPeer;
use super::{bind, free_port, identity, loopback_v4, options, peer_v4};
use crate::network::{Allowlist, Limits, NetworkError};
use iroh_base::TransportAddr;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

#[test]
fn invalid_options_name_the_offending_field_and_the_boundary_is_exact() {
    let valid = loopback_v4(6881);
    let rejected = |bootstrap: &[SocketAddrV4]| {
        NativeDiscoveryOptions::new(identity(), loopback_v4(0), bootstrap).err()
    };
    let invalid = |field, reason| Some(InvalidOption { field, reason });
    assert_eq!(
        rejected(&[]),
        invalid(NativeOptionField::Bootstrap, NativeOptionReason::Empty)
    );
    assert_eq!(
        rejected(&[valid; 5]),
        invalid(NativeOptionField::Bootstrap, NativeOptionReason::TooMany)
    );
    assert_eq!(
        rejected(&[loopback_v4(0)]),
        invalid(
            NativeOptionField::BootstrapPort,
            NativeOptionReason::ZeroPort
        )
    );
    assert_eq!(
        rejected(&[SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 6881)]),
        invalid(NativeOptionField::Bootstrap, NativeOptionReason::Unusable)
    );
    assert_eq!(
        rejected(&[SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 6881)]),
        invalid(NativeOptionField::Bootstrap, NativeOptionReason::Unusable)
    );
    // Four raw entries are accepted even when duplicated; the bind port may be zero.
    let accepted = NativeDiscoveryOptions::new(identity(), loopback_v4(0), &[valid; 4])
        .expect("four bootstrap entries");
    assert!(!format!("{accepted:?}").contains("127.0.0.1"));
}

#[tokio::test]
async fn invalid_native_address_binds_neither_backend() {
    let dht_port = free_port().await;
    let result = NativeDiscoveredEndpoint::bind_with_discovery(
        "224.0.0.1:0".parse().expect("multicast address"),
        Allowlist::default(),
        Limits::new(4).expect("session limit"),
        options(dht_port, loopback_v4(6881)),
    )
    .await;
    assert!(matches!(
        result,
        Err(NativeEndpointError::Network(NetworkError::InvalidAddress))
    ));
    UdpSocket::bind(loopback_v4(dht_port))
        .await
        .expect("the DHT port was never bound");
}

#[tokio::test]
async fn failed_dht_bind_closes_the_native_endpoint() {
    let native_port = free_port().await;
    // 192.0.2.0/24 is documentation space: no local interface owns it, so the bind fails.
    let unassigned = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 0);
    let options = NativeDiscoveryOptions::new(identity(), unassigned, &[loopback_v4(6881)])
        .expect("syntactically valid options");
    let result = bind(native_port, options).await;
    match result {
        Err(NativeEndpointError::Start(error)) => {
            // The failure is the OS refusing the bind, not a validation error.
            let _ = error.kind();
        }
        _ => panic!("the DHT bind must fail before the endpoint is returned"),
    }
    UdpSocket::bind(loopback_v4(native_port))
        .await
        .expect("the native endpoint was rolled back");
}

#[tokio::test]
async fn endpoint_publishes_only_the_callers_snapshot_and_closes_retryably() {
    let mut peer = LoopbackPeer::bind().await;
    let native_port = free_port().await;
    let dht_port = free_port().await;
    let mut endpoint = bind(native_port, options(dht_port, peer_v4(&peer)))
        .await
        .expect("composed endpoint binds");
    assert_eq!(
        endpoint.local_addr(),
        SocketAddr::from(loopback_v4(native_port))
    );
    assert_eq!(endpoint.id(), endpoint_key(&identity()).expect("key"));

    assert!(
        tokio::time::timeout(Duration::from_millis(300), peer.capture_put())
            .await
            .is_err(),
        "construction publishes nothing"
    );

    let snapshot = vec![TransportAddr::Ip(
        "127.0.0.1:9001".parse().expect("address"),
    )];
    let mut replace =
        Box::pin(endpoint.replace_until(snapshot, Instant::now() + Duration::from_secs(10)));
    let (source, transaction, captured) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replace => panic!("replacement finished before the peer saw a PUT: {result:?}"),
    };
    peer.acknowledge(source, &transaction).await;
    replace.await.expect("replacement acknowledged");
    assert_eq!(captured.key, identity().public_key_bytes());
    endpoint.withdraw().await.expect("withdraw completes");

    endpoint.close().await.expect("both backends joined");
    endpoint.close().await.expect("a repeated close is a no-op");
    assert!(matches!(
        endpoint
            .replace_until(Vec::new(), Instant::now() + Duration::from_secs(1))
            .await,
        Err(NativeEndpointError::Closed)
    ));
    UdpSocket::bind(loopback_v4(native_port))
        .await
        .expect("the native port was released");
    UdpSocket::bind(loopback_v4(dht_port))
        .await
        .expect("the DHT port was released");
}

#[tokio::test]
async fn a_cancelled_close_is_retried_to_completion() {
    let peer = LoopbackPeer::bind().await;
    let native_port = free_port().await;
    let dht_port = free_port().await;
    let mut endpoint = bind(native_port, options(dht_port, peer_v4(&peer)))
        .await
        .expect("composed endpoint binds");
    // The first close is cancelled almost immediately; its join handles stay owned.
    let _ = tokio::time::timeout(Duration::from_millis(1), endpoint.close()).await;
    endpoint
        .close()
        .await
        .expect("the retried close joins both backends");
    UdpSocket::bind(loopback_v4(native_port))
        .await
        .expect("the native port was released");
    UdpSocket::bind(loopback_v4(dht_port))
        .await
        .expect("the DHT port was released");
}

#[tokio::test]
async fn an_oversized_snapshot_is_rejected_by_the_runtime_owner() {
    use crate::native_discovery::runtime::owner::RuntimeError;
    use crate::native_discovery::runtime::publisher::PublishError;

    let peer = LoopbackPeer::bind().await;
    let mut endpoint = bind(
        free_port().await,
        options(free_port().await, peer_v4(&peer)),
    )
    .await
    .expect("composed endpoint binds");
    let snapshot: Vec<TransportAddr> = (9001..9006)
        .map(|port| TransportAddr::Ip(SocketAddr::from(loopback_v4(port))))
        .collect();
    assert!(matches!(
        endpoint
            .replace_until(snapshot, Instant::now() + Duration::from_secs(5))
            .await,
        Err(NativeEndpointError::Runtime(RuntimeError::Publish(
            PublishError::Snapshot(_)
        )))
    ));
    endpoint.close().await.expect("both backends joined");
}
