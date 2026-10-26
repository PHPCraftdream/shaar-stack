use std::{borrow::Cow, io, net::SocketAddr};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

use super::{DiscoveryConfig, address::classify_complete};

pub(super) fn peer(marker: u8) -> PeerId {
    let mut hash = [marker; 34];
    hash[0] = 0x12;
    hash[1] = 32;
    PeerId::from_bytes(&hash).unwrap()
}

pub(super) fn servers() -> Vec<SocketAddr> {
    vec!["127.0.0.1:5300".parse().unwrap()]
}

fn complete(root: &str) -> Multiaddr {
    root.parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::P2p(peer(1)))
}

fn rejected(address: Multiaddr) {
    assert!(
        classify_complete(address.as_ref(), peer(1)).is_err(),
        "{address}"
    );
    assert!(DiscoveryConfig::new(vec![(peer(1), address)], servers()).is_err());
}

#[test]
fn discovery_address_supported_numeric_and_port_boundaries() {
    for root in [
        "/ip4/8.8.8.8/tcp/1",
        "/ip4/1.1.1.1/tcp/65535",
        "/ip6/2606:4700:4700::1111/tcp/4001",
    ] {
        let address = complete(root);
        let (host, port) = classify_complete(address.as_ref(), peer(1)).unwrap();
        assert!(matches!(host, Protocol::Ip4(_) | Protocol::Ip6(_)));
        assert_eq!(
            port,
            address.iter().find_map(|part| match part {
                Protocol::Tcp(port) => Some(port),
                _ => None,
            })
        );
        let config = DiscoveryConfig::new(vec![(peer(1), address.clone())], servers()).unwrap();
        assert_eq!(config.seeds[0].1, address);
    }
}

#[test]
fn discovery_address_supported_dns_borrows_complete_encoding() {
    for kind in ["dns", "dns4", "dns6", "dnsaddr"] {
        let tcp = if kind == "dnsaddr" { "" } else { "/tcp/4001" };
        let address = complete(&format!("/{kind}/seed.example.{tcp}"));
        let (host, port) = classify_complete(address.as_ref(), peer(1)).unwrap();
        let text = match host {
            Protocol::Dns(Cow::Borrowed(text))
            | Protocol::Dns4(Cow::Borrowed(text))
            | Protocol::Dns6(Cow::Borrowed(text))
            | Protocol::Dnsaddr(Cow::Borrowed(text)) => text,
            _ => panic!("DNS_CLASSIFICATION_MUST_BORROW"),
        };
        assert_eq!(text, "seed.example.");
        let start = address.as_ref().as_ptr_range();
        assert!(start.contains(&text.as_ptr()));
        assert_eq!(port, if kind == "dnsaddr" { None } else { Some(4001) });
        assert!(DiscoveryConfig::new(vec![(peer(1), address)], servers()).is_ok());
    }
}

#[test]
fn discovery_address_constructor_normalizes_and_preserves_optional_suffix() {
    for kind in ["dns", "dns4", "dns6", "dnsaddr"] {
        let tcp = if kind == "dnsaddr" { "" } else { "/tcp/4001" };
        for suffix in [false, true] {
            let mut address: Multiaddr = format!("/{kind}/SEED.Example.{tcp}").parse().unwrap();
            let mut expected: Multiaddr = format!("/{kind}/seed.example.{tcp}").parse().unwrap();
            if suffix {
                address.push(Protocol::P2p(peer(1)));
                expected.push(Protocol::P2p(peer(1)));
                assert!(classify_complete(address.as_ref(), peer(1)).is_err());
            }
            let config = DiscoveryConfig::new(vec![(peer(1), address)], servers()).unwrap();
            assert_eq!(config.seeds[0].1, expected);
        }
    }
}

#[test]
fn discovery_address_requires_exact_terminal_peer() {
    let root: Multiaddr = "/ip4/8.8.8.8/tcp/1".parse().unwrap();
    assert!(classify_complete(root.as_ref(), peer(1)).is_err());
    assert!(DiscoveryConfig::new(vec![(peer(1), root.clone())], servers()).is_ok());
    rejected(root.with(Protocol::P2p(peer(2))));
    rejected(complete("/ip4/8.8.8.8/tcp/1").with(Protocol::P2p(peer(1))));
    rejected(
        format!("/ip4/8.8.8.8/p2p/{}/tcp/1/p2p/{}", peer(1), peer(1))
            .parse()
            .unwrap(),
    );
}

#[test]
fn discovery_address_rejects_inherited_circuit_and_extra_components() {
    for root in [
        "/ip4/8.8.8.8/tcp/1/ws",
        "/ip4/8.8.8.8/tcp/1/tcp/2",
        "/ip4/8.8.8.8/ip4/1.1.1.1/tcp/1",
        "/ip4/8.8.8.8/udp/1",
        "/ip4/8.8.8.8/udp/1/quic-v1",
        "/dnsaddr/seed.example./tcp/1",
        "/dns4/seed.example./dns4/other.example./tcp/1",
        "/memory/1/ip4/8.8.8.8/tcp/1",
        "/p2p-circuit/ip4/8.8.8.8/tcp/1",
        "/ip6/2606:4700::1111/ip6zone/eth0/tcp/1",
    ] {
        rejected(complete(root));
    }
    rejected(complete("/ip4/8.8.8.8/tcp/1").with(Protocol::P2pCircuit));
    rejected(
        format!(
            "/ip4/8.8.8.8/tcp/1/p2p/{}/p2p-circuit/p2p/{}",
            peer(2),
            peer(1)
        )
        .parse()
        .unwrap(),
    );
}

#[test]
fn discovery_address_rejects_zero_or_missing_tcp_ports() {
    for root in [
        "/ip4/8.8.8.8/tcp/0",
        "/ip6/2606:4700::1111/tcp/0",
        "/dns/seed.example./tcp/0",
        "/dns4/seed.example./tcp/0",
        "/dns6/seed.example./tcp/0",
        "/ip4/8.8.8.8",
        "/dns4/seed.example.",
    ] {
        rejected(complete(root));
    }
}

#[test]
fn discovery_address_rejects_noncanonical_and_invalid_names() {
    for name in [
        "relative.example",
        ".",
        "bad..example.",
        "é.example.",
        "seed\\046example.",
    ] {
        for kind in ["dns", "dns4", "dns6", "dnsaddr"] {
            let tcp = if kind == "dnsaddr" { "" } else { "/tcp/1" };
            rejected(complete(&format!("/{kind}/{name}{tcp}")));
        }
    }
    let label = "a".repeat(64);
    rejected(complete(&format!("/dns/{label}.example./tcp/1")));
    // Multiaddr encodes strings without DNS validation, including an embedded NUL.
    let invalid = Multiaddr::empty()
        .with(Protocol::Dns("bad\0.example.".into()))
        .with(Protocol::Tcp(1))
        .with(Protocol::P2p(peer(1)));
    rejected(invalid);
}

#[test]
fn discovery_address_rejects_truncation_and_malformed_trailing_bytes() {
    for root in [
        "/ip4/8.8.8.8/tcp/1",
        "/ip6/2606:4700::1111/tcp/1",
        "/dnsaddr/seed.example.",
    ] {
        let address = complete(root);
        for length in 0..address.as_ref().len() {
            assert!(classify_complete(&address.as_ref()[..length], peer(1)).is_err());
        }
        for tail in [
            &[0x80][..],
            &[0xff, 0xff, 0xff, 0xff, 0xff][..],
            &[4, 8][..],
        ] {
            let mut bytes = address.as_ref().to_vec();
            bytes.extend_from_slice(tail);
            assert!(classify_complete(&bytes, peer(1)).is_err());
        }
    }
    for bytes in [
        &[0x80][..],
        &[4, 8][..],
        &[41, 0][..],
        &[54, 1, 0xff][..],
        &[54, 0xff, 0xff, 0xff, 0x7f][..],
    ] {
        assert!(classify_complete(bytes, peer(1)).is_err());
    }
}

fn boundary(kind: &str, length: usize) -> Multiaddr {
    for last in 1..=63 {
        let name = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(last)
        );
        let tcp = if kind == "dnsaddr" { "" } else { "/tcp/1" };
        let address = complete(&format!("/{kind}/{name}{tcp}"));
        if address.as_ref().len() == length {
            return address;
        }
    }
    panic!("COMPLETE_ADDRESS_BOUNDARY_FIXTURE_MISSING");
}

#[test]
fn discovery_address_complete_256_and_257_byte_boundaries() {
    for kind in ["dns", "dns4", "dns6", "dnsaddr"] {
        for length in [256, 257] {
            let address = boundary(kind, length);
            assert_eq!(address.as_ref().len(), length);
            assert_eq!(
                classify_complete(address.as_ref(), peer(1)).is_ok(),
                length == 256
            );
            assert_eq!(
                DiscoveryConfig::new(vec![(peer(1), address)], servers()).is_ok(),
                length == 256
            );
        }
    }
    assert!(classify_complete(&[0; 257], peer(1)).is_err());
}

#[test]
fn discovery_address_suffixless_constructor_charges_swarm_qualification() {
    for kind in ["dns", "dns4", "dns6", "dnsaddr"] {
        for length in [256, 257] {
            let mut address = boundary(kind, length);
            assert_eq!(address.pop(), Some(Protocol::P2p(peer(1))));
            assert!(address.as_ref().len() < 256);
            let result = DiscoveryConfig::new(vec![(peer(1), address.clone())], servers());
            assert_eq!(result.is_ok(), length == 256);
            if let Ok(config) = result {
                assert_eq!(config.seeds[0].1, address);
                assert_eq!(address.with_p2p(peer(1)).unwrap().as_ref().len(), 256);
            }
        }
    }
}

#[test]
fn discovery_address_numeric_seed_rejection_is_pure_and_field_specific() {
    // No runtime or listener exists; constructor itself must reject the endpoint.
    for root in [
        "/ip4/10.1.2.3/tcp/4001",
        "/ip4/192.0.0.9/tcp/1",
        "/ip6/fd00::1/tcp/1",
        "/ip6/::ffff:8.8.8.8/tcp/1",
    ] {
        let error =
            DiscoveryConfig::new(vec![(peer(1), root.parse().unwrap())], servers()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "discovery.seeds contains a forbidden IP scope"
        );
    }
}

#[test]
fn discovery_address_private_nameservers_do_not_inherit_seed_scope() {
    for server in [
        "127.0.0.1:5300",
        "10.0.0.2:54",
        "[::1]:5353",
        "[fd00::1]:65535",
    ] {
        let endpoint: SocketAddr = server.parse().unwrap();
        let config = DiscoveryConfig::new(
            vec![(peer(1), complete("/dns4/seed.example./tcp/1"))],
            vec![endpoint],
        )
        .unwrap();
        assert_eq!(config.nameservers(), &[endpoint]);
        let host = match endpoint {
            SocketAddr::V4(endpoint) => Protocol::Ip4(*endpoint.ip()),
            SocketAddr::V6(endpoint) => Protocol::Ip6(*endpoint.ip()),
        };
        rejected(
            Multiaddr::empty()
                .with(host)
                .with(Protocol::Tcp(endpoint.port()))
                .with(Protocol::P2p(peer(1))),
        );
    }
}
