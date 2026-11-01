// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, id, ip, socket};
use crate::native_discovery::{SnapshotError, validate_snapshot};
use iroh_base::{CustomAddr, RelayUrl, TransportAddr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};

#[test]
fn snapshot_four_is_atomic_and_signed_five_address_record_rejects_whole() {
    let four = vec![
        ip(socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1)),
        ip(socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2)),
        ip(socket(
            IpAddr::V6("2001:db8::3".parse().expect("literal")),
            3,
        )),
        ip(socket(
            IpAddr::V6("2001:db8::4".parse().expect("literal")),
            4,
        )),
    ];
    assert_eq!(validate_snapshot(&four).expect("four accepted").len(), 4);
    let four_sockets = [
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2),
        socket(IpAddr::V6("2001:db8::3".parse().expect("literal")), 3),
        socket(IpAddr::V6("2001:db8::4".parse().expect("literal")), 4),
    ];
    assert_eq!(
        crate::native_discovery::validate_addresses(&four_sockets)
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        crate::native_discovery::validate_transport_addresses(&four)
            .unwrap()
            .len(),
        4
    );
    let empty: [TransportAddr; 0] = [];
    assert!(validate_snapshot(&empty).unwrap().is_empty());
    assert!(
        crate::native_discovery::validate_addresses(&[])
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::native_discovery::validate_transport_addresses(&empty)
            .unwrap()
            .is_empty()
    );
    let mut five = four.clone();
    five.push(ip(socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5)));
    assert!(matches!(
        validate_snapshot(&five),
        Err(SnapshotError::TooManyAddresses)
    ));
    let five_sockets = [
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2),
        socket(IpAddr::V6("2001:db8::3".parse().expect("literal")), 3),
        socket(IpAddr::V6("2001:db8::4".parse().expect("literal")), 4),
        socket(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5),
    ];
    assert!(matches!(
        crate::native_discovery::validate_addresses(&five_sockets),
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
        crate::native_discovery::validate_addresses(&duplicate_five),
        Err(SnapshotError::TooManyAddresses)
    ));
    let duplicate_transport: Vec<_> = duplicate_five.iter().copied().map(ip).collect();
    assert!(matches!(
        validate_snapshot(&duplicate_transport),
        Err(SnapshotError::TooManyAddresses)
    ));
    assert!(matches!(
        crate::native_discovery::validate_transport_addresses(&duplicate_transport),
        Err(SnapshotError::TooManyAddresses)
    ));
    assert!(matches!(
        crate::native_discovery::validate_transport_addresses(&five),
        Err(SnapshotError::TooManyAddresses)
    ));

    let owner = crate::identity::Identity::from_seed(super::SEED1);
    let packet = iroh_dns::endpoint_info::EndpointInfo::from_parts(
        id(PUB1),
        iroh_dns::endpoint_info::EndpointData::new(five),
    )
    .to_pkarr_signed_packet(&owner.transport_key(), 30)
    .expect("upstream builds five-address packet");
    assert!(
        crate::native_discovery::decode_record(packet.as_bytes(), id(PUB1)).is_err(),
        "decoder must reject full record, not return first four"
    );
}

#[test]
fn address_policy_canonicalizes_mapped_and_keeps_lan_loopback() {
    let mapped = socket("::ffff:192.168.1.3".parse().expect("mapped"), 7000);
    let v4 = socket(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 7000);
    let loopback = socket(IpAddr::V6(Ipv6Addr::LOCALHOST), 7001);
    let v6_lan = socket(IpAddr::V6("2001:db8::3".parse().expect("literal")), 7002);
    let accepted = crate::native_discovery::validate_addresses(&[mapped, loopback, v4, v6_lan])
        .expect("bounded LAN, loopback and mapped canonicalization accepted");
    assert_eq!(accepted, [v4, loopback, v6_lan]);
    let remaining = [
        socket(IpAddr::V6("fd00::1".parse().expect("ULA")), 7003),
        socket(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 7004),
    ];
    assert_eq!(
        crate::native_discovery::validate_addresses(&remaining).unwrap(),
        remaining
    );
    let at_bound = [mapped, v4, loopback, v6_lan];
    assert_eq!(
        crate::native_discovery::validate_addresses(&at_bound).unwrap(),
        [v4, loopback, v6_lan]
    );
    let over_bound = [
        at_bound[0],
        at_bound[1],
        at_bound[2],
        at_bound[3],
        remaining[0],
    ];
    assert!(crate::native_discovery::validate_addresses(&over_bound).is_err());
}

#[test]
fn address_policy_rejects_specials_prefix_boundaries_scope_flow_and_zero_port() {
    for address in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6("ff02::1".parse().expect("literal")),
        IpAddr::V6("::ffff:224.0.0.1".parse().expect("mapped multicast")),
        IpAddr::V6("fd15:070a:510b::".parse().expect("prefix start")),
        IpAddr::V6(
            "fd15:070a:510b:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("prefix end"),
        ),
        IpAddr::V6("fe80::".parse().expect("link-local start")),
        IpAddr::V6(
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("link-local end"),
        ),
    ] {
        assert!(
            crate::native_discovery::validate_addresses(&[socket(address, 9)]).is_err(),
            "{address}"
        );
    }
    for address in ["fd15:070a:510a::1", "fd15:070a:510c::1"] {
        assert!(
            crate::native_discovery::validate_addresses(&[socket(
                address.parse().expect("adjacent /48"),
                9
            )])
            .is_ok(),
            "{address}"
        );
    }
    let scoped = std::net::SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::1".parse().expect("literal"),
        9,
        0,
        1,
    ));
    let flow = std::net::SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::1".parse().expect("literal"),
        9,
        1,
        0,
    ));
    assert!(crate::native_discovery::validate_addresses(&[scoped]).is_err());
    assert!(crate::native_discovery::validate_addresses(&[flow]).is_err());
    assert!(
        crate::native_discovery::validate_addresses(&[socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])
            .is_err()
    );

    let custom = TransportAddr::Custom(CustomAddr::from_parts(0x5348, &[0; 16]));
    let relay = TransportAddr::Relay(
        "https://example.com"
            .parse::<RelayUrl>()
            .expect("valid relay URL"),
    );
    assert!(crate::native_discovery::validate_transport_addresses(&[custom]).is_err());
    assert!(crate::native_discovery::validate_transport_addresses(&[relay]).is_err());
}

#[test]
fn signed_address_decoder_rejects_mixed_good_and_forbidden_addresses_whole() {
    let owner = crate::identity::Identity::from_seed(super::SEED1);
    let info = iroh_dns::endpoint_info::EndpointInfo::from_parts(
        id(PUB1),
        iroh_dns::endpoint_info::EndpointData::new(vec![
            ip(socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 9)),
            ip(socket(
                IpAddr::V6("fd15:070a:510b::1".parse().expect("literal")),
                10,
            )),
        ]),
    );
    let packet = info
        .to_pkarr_signed_packet(&owner.transport_key(), 30)
        .expect("upstream codec accepts addresses");
    assert!(
        crate::native_discovery::decode_record(packet.as_bytes(), id(PUB1)).is_err(),
        "valid prefix must not escape mixed rejected record"
    );
}
