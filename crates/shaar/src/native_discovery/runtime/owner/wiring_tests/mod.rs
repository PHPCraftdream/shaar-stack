// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

mod composition;
pub(in crate::native_discovery::runtime::owner) mod connect;
mod lifecycle;
mod records;

use super::endpoint::{NativeDiscoveredEndpoint, NativeEndpointError};
use super::options::NativeDiscoveryOptions;
use super::tests::fixture::LoopbackPeer;
use crate::identity::Identity;
use crate::network::{Allowlist, Limits};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;

pub(in crate::native_discovery::runtime::owner) const RECORD_WALL_US: i64 = 1_800_000_000_000_000;

pub(in crate::native_discovery::runtime::owner) async fn bind_controlled(
    native_port: u16,
    options: NativeDiscoveryOptions,
) -> Result<NativeDiscoveredEndpoint, NativeEndpointError> {
    NativeDiscoveredEndpoint::bind_with_discovery_controlled(
        SocketAddr::from(loopback_v4(native_port)),
        Allowlist::default(),
        Limits::new(4).expect("session limit"),
        options,
        crate::native_discovery::runtime::clock::TestClock::new(RECORD_WALL_US),
    )
    .await
}

fn loopback_v4(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn identity() -> Identity {
    Identity::from_seed([0x61; 32])
}

pub(in crate::native_discovery::runtime::owner) fn peer_v4(peer: &LoopbackPeer) -> SocketAddrV4 {
    match peer.address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("loopback peer must bind IPv4"),
    }
}

/// A currently free loopback UDP port: bound, read and released again.
pub(in crate::native_discovery::runtime::owner) async fn free_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("probe socket binds");
    socket.local_addr().expect("probe address").port()
}

pub(in crate::native_discovery::runtime::owner) fn options(
    dht_port: u16,
    bootstrap: SocketAddrV4,
) -> NativeDiscoveryOptions {
    NativeDiscoveryOptions::new(identity(), loopback_v4(dht_port), &[bootstrap])
        .expect("valid discovery options")
}

pub(in crate::native_discovery::runtime::owner) async fn bind(
    native_port: u16,
    options: NativeDiscoveryOptions,
) -> Result<NativeDiscoveredEndpoint, NativeEndpointError> {
    NativeDiscoveredEndpoint::bind_with_discovery(
        SocketAddr::from(loopback_v4(native_port)),
        Allowlist::default(),
        Limits::new(4).expect("session limit"),
        options,
    )
    .await
}
