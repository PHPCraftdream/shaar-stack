// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::TransportAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
const MAX_ADDRESSES: usize = 4;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SnapshotError {
    TooManyAddresses,
    InvalidAddress,
    UnsupportedTransport,
    Oversize,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
pub(super) fn validate_snapshot(addrs: &[TransportAddr]) -> Result<Vec<SocketAddr>, SnapshotError> {
    validate_transport_addresses(addrs)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
pub(super) fn validate_transport_addresses(
    addrs: &[TransportAddr],
) -> Result<Vec<SocketAddr>, SnapshotError> {
    check_raw_count(addrs.len())?;
    let mut sockets = Vec::with_capacity(addrs.len());
    for address in addrs {
        match address {
            TransportAddr::Ip(socket) => sockets.push(*socket),
            TransportAddr::Relay(_) | TransportAddr::Custom(_) => {
                return Err(SnapshotError::UnsupportedTransport);
            }
            _ => return Err(SnapshotError::UnsupportedTransport),
        }
    }
    validate_addresses(&sockets)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
pub(super) fn validate_addresses(addrs: &[SocketAddr]) -> Result<Vec<SocketAddr>, SnapshotError> {
    validate_addresses_with_snapshot(addrs).map(|(_, canonical)| canonical)
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
pub(super) fn validate_addresses_with_snapshot(
    addrs: &[SocketAddr],
) -> Result<(Vec<SocketAddr>, Vec<SocketAddr>), SnapshotError> {
    check_raw_count(addrs.len())?;
    let mut raw = Vec::with_capacity(addrs.len());
    for address in addrs {
        if !valid_native(*address) || !portable_v6(*address) {
            return Err(SnapshotError::InvalidAddress);
        }
        raw.push(*address);
    }
    let mut canonical = Vec::with_capacity(raw.len());
    for address in raw.iter().copied().map(canonical_socket) {
        if !canonical.contains(&address) {
            canonical.push(address);
        }
    }
    Ok((raw, canonical))
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
fn check_raw_count(count: usize) -> Result<(), SnapshotError> {
    if count > MAX_ADDRESSES {
        Err(SnapshotError::TooManyAddresses)
    } else {
        Ok(())
    }
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
fn valid_native(address: SocketAddr) -> bool {
    let ip = address.ip().to_canonical();
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
        && match ip {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => v6.octets()[..6] != [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b],
        }
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
fn portable_v6(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v6) => {
            v6.scope_id() == 0 && v6.flowinfo() == 0 && !is_v6_link_local(v6.ip())
        }
    }
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
fn is_v6_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
fn canonical_socket(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), v6.port()),
            None => SocketAddr::V6(SocketAddrV6::new(
                *v6.ip(),
                v6.port(),
                v6.flowinfo(),
                v6.scope_id(),
            )),
        },
        SocketAddr::V4(_) => address,
    }
}
