// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, id};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use crate::native_discovery::{
    ClockSample, CompletedQuery, PolicyOwner, QuerySource, RecordError, RecordObservation,
    SnapshotError, validate_addresses, validate_snapshot, validate_transport_addresses,
};
use iroh_base::{CustomAddr, RelayUrl, TransportAddr};

#[test]
fn cached_address_seam_returns_only_fresh_approved_snapshot() {
    let key = id(PUB1);
    let address: SocketAddr = "192.168.1.4:443".parse().expect("literal");
    let mut owner = PolicyOwner::new();
    owner.admit_expected_key(key).expect("authorized");
    let receipt = ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 100,
    };
    let observation =
        RecordObservation::fixture(1_000_000_000, 1_000_000_000, vec![1; 104], vec![address]);
    owner
        .complete_query(
            key,
            CompletedQuery::new(QuerySource::Network, receipt, vec![observation]),
        )
        .expect("accepted fixture");
    assert_eq!(owner.addresses(key, receipt), Ok([address].as_slice()));
    assert_eq!(
        owner.addresses(
            key,
            ClockSample {
                monotonic_us: 30_000_100,
                ..receipt
            }
        ),
        Err(RecordError::CacheExpired)
    );
}

#[test]
fn mapped_ipv6_deduplicates_stably_and_lan_loopback_are_allowed() {
    let mapped_addr = socket("::ffff:192.168.1.3".parse().expect("mapped"), 7000);
    let v4 = socket(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 7000);
    let loopback = socket(IpAddr::V6(Ipv6Addr::LOCALHOST), 7001);
    let lan = socket(IpAddr::V6("2001:db8::3".parse().expect("literal")), 7002);
    assert_eq!(
        validate_addresses(&[mapped_addr, loopback, v4, lan]).unwrap(),
        [v4, loopback, lan]
    );
    let remaining = [
        socket(IpAddr::V6("fd00::1".parse().expect("ULA")), 7003),
        socket(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 7004),
    ];
    assert_eq!(validate_addresses(&remaining).unwrap(), remaining);
    assert_eq!(
        validate_addresses(&[mapped_addr, v4, loopback, lan]).unwrap(),
        [v4, loopback, lan]
    );
    assert!(validate_addresses(&[mapped_addr, v4, loopback, lan, remaining[0]]).is_err());
}

#[test]
fn address_policy_rejects_special_ranges_scope_flow_and_zero_port() {
    for address in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6("ff02::1".parse().expect("multicast")),
        IpAddr::V6("::ffff:224.0.0.1".parse().expect("mapped multicast")),
        IpAddr::V6("fd15:070a:510b::".parse().expect("excluded prefix start")),
        IpAddr::V6(
            "fd15:070a:510b:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("excluded prefix end"),
        ),
        IpAddr::V6("fe80::".parse().expect("link-local start")),
        IpAddr::V6(
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("link-local end"),
        ),
    ] {
        assert!(
            validate_addresses(&[socket(address, 9)]).is_err(),
            "{address}"
        );
    }
    for address in ["fd15:070a:510a::1", "fd15:070a:510c::1"] {
        assert!(
            validate_addresses(&[socket(address.parse().expect("adjacent prefix"), 9)]).is_ok()
        );
    }
    let scoped = SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::1".parse().expect("literal"),
        9,
        0,
        1,
    ));
    let flow = SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::1".parse().expect("literal"),
        9,
        1,
        0,
    ));
    assert!(validate_addresses(&[scoped]).is_err());
    assert!(validate_addresses(&[flow]).is_err());
    assert!(validate_addresses(&[socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)]).is_err());
    let custom = TransportAddr::Custom(CustomAddr::from_parts(0x5348, &[0; 16]));
    let relay = TransportAddr::Relay(
        "https://example.com"
            .parse::<RelayUrl>()
            .expect("relay URL"),
    );
    assert!(validate_transport_addresses(&[custom]).is_err());
    assert!(validate_transport_addresses(&[relay]).is_err());
}

#[test]
fn raw_address_limit_is_four_before_canonical_dedup_and_transport_conversion() {
    let four = vec![
        TransportAddr::Ip(socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1)),
        TransportAddr::Ip(socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2)),
        TransportAddr::Ip(socket(
            IpAddr::V6("2001:db8::3".parse().expect("literal")),
            3,
        )),
        TransportAddr::Ip(socket(
            IpAddr::V6("2001:db8::4".parse().expect("literal")),
            4,
        )),
    ];
    assert_eq!(validate_snapshot(&four).unwrap().len(), 4);
    assert_eq!(validate_transport_addresses(&four).unwrap().len(), 4);
    assert_eq!(
        validate_addresses(
            &four
                .iter()
                .map(|address| match address {
                    TransportAddr::Ip(socket) => *socket,
                    _ => unreachable!(),
                })
                .collect::<Vec<_>>()
        )
        .unwrap()
        .len(),
        4
    );
    let empty: [TransportAddr; 0] = [];
    assert!(validate_snapshot(&empty).unwrap().is_empty());
    assert!(validate_transport_addresses(&empty).unwrap().is_empty());
    let five = [
        four[0].clone(),
        four[1].clone(),
        four[2].clone(),
        four[3].clone(),
        TransportAddr::Ip(socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5)),
    ];
    assert!(matches!(
        validate_snapshot(&five),
        Err(SnapshotError::TooManyAddresses)
    ));
    assert!(matches!(
        validate_transport_addresses(&five),
        Err(SnapshotError::TooManyAddresses)
    ));
    let duplicate_five = [
        socket("::ffff:192.168.1.3".parse().expect("mapped"), 7000),
        socket(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 7000),
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2),
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 3),
    ];
    assert!(matches!(
        validate_addresses(&duplicate_five),
        Err(SnapshotError::TooManyAddresses)
    ));
    let transports: Vec<_> = duplicate_five
        .iter()
        .copied()
        .map(TransportAddr::Ip)
        .collect();
    assert!(matches!(
        validate_snapshot(&transports),
        Err(SnapshotError::TooManyAddresses)
    ));
    assert!(matches!(
        validate_transport_addresses(&transports),
        Err(SnapshotError::TooManyAddresses)
    ));
}

fn socket(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}
