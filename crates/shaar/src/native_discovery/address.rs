// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::TransportAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};

use crate::config::PublishAddress;

const MAX_ADDRESSES: usize = 4;

/// The address list to publish: the endpoint snapshot and, only with the
/// opt-in `plain` mode and a usable vote, ONE extra entry (the voted public IP
/// with the local QUIC port). The cap of four holds: when the snapshot is
/// already full its last (least specific) local entry yields its slot. `off`,
/// no vote, an unusable vote or no local IP address leave the snapshot
/// untouched. The vote is untrusted input: a wrong address is not
/// authenticated and costs a client at most one bounded dial slice, and an
/// address the record policy would reject is never added, so a hostile vote
/// cannot invalidate the whole record. Documentation ranges are publishable:
/// they are unrouted on the internet and the WAN of the namespace matrix.
pub(crate) fn compose_published(
    base: &[TransportAddr],
    vote: Option<IpAddr>,
    publish: PublishAddress,
) -> Vec<TransportAddr> {
    let mut addresses = base.to_vec();
    if publish != PublishAddress::Plain {
        return addresses;
    }
    let Some(ip) = vote else {
        return addresses;
    };
    let Some(port) = base.iter().find_map(|address| match address {
        TransportAddr::Ip(socket) => Some(socket.port()),
        _ => None,
    }) else {
        return addresses;
    };
    let candidate = SocketAddr::new(ip, port);
    if !usable_vote(candidate) {
        return addresses;
    }
    let reflexive = TransportAddr::Ip(candidate);
    if addresses.contains(&reflexive) {
        return addresses;
    }
    if addresses.len() >= MAX_ADDRESSES {
        addresses.pop();
    }
    addresses.push(reflexive);
    addresses
}

/// A vote is publishable only when it is a plausible public address that the
/// record policy accepts.
fn usable_vote(candidate: SocketAddr) -> bool {
    let ip = candidate.ip().to_canonical();
    let special = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(v4) => v4.is_link_local() || v4.is_broadcast(),
            IpAddr::V6(v6) => is_v6_link_local(&v6),
        };
    !special && valid_native(candidate) && portable_v6(candidate)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SnapshotError {
    TooManyAddresses,
    InvalidAddress,
    UnsupportedTransport,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "P09 actor boundary is not wired yet")
)]
pub(super) fn validate_snapshot(addrs: &[TransportAddr]) -> Result<Vec<SocketAddr>, SnapshotError> {
    validate_transport_addresses(addrs)
}

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

pub(super) fn validate_addresses(addrs: &[SocketAddr]) -> Result<Vec<SocketAddr>, SnapshotError> {
    validate_addresses_with_snapshot(addrs).map(|(_, canonical)| canonical)
}

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

fn check_raw_count(count: usize) -> Result<(), SnapshotError> {
    if count > MAX_ADDRESSES {
        Err(SnapshotError::TooManyAddresses)
    } else {
        Ok(())
    }
}
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
fn portable_v6(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v6) => {
            v6.scope_id() == 0 && v6.flowinfo() == 0 && !is_v6_link_local(v6.ip())
        }
    }
}
fn is_v6_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}
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

#[cfg(test)]
mod publish_tests {
    use super::*;

    fn ip(text: &str, port: u16) -> TransportAddr {
        TransportAddr::Ip(SocketAddr::new(text.parse().unwrap(), port))
    }

    fn vote(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    fn local() -> Vec<TransportAddr> {
        vec![ip("192.168.1.5", 7777), ip("10.0.0.2", 7777)]
    }

    #[test]
    fn off_and_missing_votes_leave_the_snapshot_untouched() {
        let base = local();
        assert_eq!(
            compose_published(&base, vote("8.8.8.8"), PublishAddress::Off),
            base
        );
        assert_eq!(compose_published(&base, None, PublishAddress::Plain), base);
        assert_eq!(
            compose_published(&[], vote("8.8.8.8"), PublishAddress::Plain),
            Vec::new()
        );
    }

    #[test]
    fn plain_with_a_vote_adds_exactly_one_entry_with_the_local_port() {
        let composed = compose_published(&local(), vote("8.8.8.8"), PublishAddress::Plain);
        let mut expected = local();
        expected.push(ip("8.8.8.8", 7777));
        assert_eq!(composed, expected);
        assert!(validate_transport_addresses(&composed).is_ok());
    }

    #[test]
    fn the_cap_of_four_holds_by_dropping_the_last_local_entry() {
        let full = vec![
            ip("192.168.1.5", 7777),
            ip("10.0.0.2", 7777),
            ip("10.0.0.3", 7777),
            ip("10.0.0.4", 7777),
        ];
        let composed = compose_published(&full, vote("8.8.8.8"), PublishAddress::Plain);
        assert_eq!(composed.len(), MAX_ADDRESSES);
        assert_eq!(composed[..3], full[..3]);
        assert_eq!(composed[3], ip("8.8.8.8", 7777));
        assert!(validate_transport_addresses(&composed).is_ok());
    }

    #[test]
    fn a_vote_already_in_the_snapshot_is_not_duplicated() {
        let base = vec![ip("8.8.8.8", 7777), ip("10.0.0.2", 7777)];
        assert_eq!(
            compose_published(&base, vote("8.8.8.8"), PublishAddress::Plain),
            base
        );
    }

    #[test]
    fn a_changed_vote_replaces_the_entry_in_the_next_composition() {
        let first = compose_published(&local(), vote("8.8.8.8"), PublishAddress::Plain);
        let second = compose_published(&local(), vote("1.1.1.1"), PublishAddress::Plain);
        assert_ne!(first, second);
        assert_eq!(second.last(), Some(&ip("1.1.1.1", 7777)));
        assert_eq!(second.len(), first.len());
    }

    /// The namespace matrix WAN is TEST-NET-3; its votes must reach the record.
    #[test]
    fn documentation_range_votes_are_published() {
        for documentation in ["203.0.113.1", "198.51.100.7", "192.0.2.5", "2001:db8::7"] {
            let composed = compose_published(&local(), vote(documentation), PublishAddress::Plain);
            assert_eq!(composed.len(), local().len() + 1, "{documentation}");
            assert!(
                validate_transport_addresses(&composed).is_ok(),
                "{documentation}"
            );
        }
    }

    #[test]
    fn hostile_votes_never_enter_the_record() {
        for hostile in [
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "::",
            "::1",
            "fe80::1",
            "fd15:70a:510b::1",
        ] {
            assert_eq!(
                compose_published(&local(), vote(hostile), PublishAddress::Plain),
                local(),
                "{hostile} must be refused"
            );
        }
    }
}
