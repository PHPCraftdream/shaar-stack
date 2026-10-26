use super::*;
use crate::Carrier;
use libp2p::identity::Keypair;

fn peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}
fn seed(peer: PeerId) -> (PeerId, Multiaddr) {
    (peer, "/dns4/seed.example./tcp/4001".parse().unwrap())
}
fn servers() -> Vec<SocketAddr> {
    vec!["127.0.0.1:5300".parse().unwrap()]
}

#[test]
fn owned_dns_config_counts_before_dedup_and_preserves_bounded_descriptors() {
    let descriptor = seed(peer());
    assert!(DiscoveryConfig::new(vec![], servers()).is_err());
    assert!(DiscoveryConfig::new(vec![descriptor.clone(); 5], servers()).is_err());
    assert!(DiscoveryConfig::new(vec![descriptor.clone()], vec![]).is_err());
    assert!(DiscoveryConfig::new(vec![descriptor.clone()], vec![servers()[0]; 5]).is_err());
    let config = DiscoveryConfig::new(vec![descriptor.clone(); 4], vec![servers()[0]; 4]).unwrap();
    assert_eq!(config.seeds.as_ref(), &[descriptor]);
    assert_eq!(config.nameservers.as_ref(), servers());
}

#[test]
fn owned_dns_config_rejects_unsupported_relative_and_inconsistent_addresses() {
    let expected = peer();
    for value in [
        "/dns4/relative.example/tcp/4001",
        "/dns/./tcp/1",
        "/dns4/bad..example./tcp/1",
        "/ip4/127.0.0.1/udp/4001",
        "/ip4/127.0.0.1/tcp/0",
        "/ip4/0.0.0.0/tcp/1",
        "/ip4/224.0.0.1/tcp/1",
        "/dns4/seed.example./tcp/1/p2p-circuit",
        "/dnsaddr/seed.example./tcp/4001",
        "/dns4/seed.example./tcp/4001/ws",
    ] {
        let address = value.parse().unwrap();
        assert!(
            DiscoveryConfig::new(vec![(expected, address)], servers()).is_err(),
            "{value}"
        );
    }
    let wrong = seed(expected).1.with(Protocol::P2p(peer()));
    assert!(DiscoveryConfig::new(vec![(expected, wrong)], servers()).is_err());
    let canonical: Multiaddr = format!("/dns4/SEED.example./tcp/4001/p2p/{expected}")
        .parse()
        .unwrap();
    let config = DiscoveryConfig::new(vec![(expected, canonical)], servers()).unwrap();
    assert_eq!(
        config.seeds[0].1.to_string(),
        format!("/dns4/seed.example./tcp/4001/p2p/{expected}")
    );
    for kind in ["dns", "dns4", "dns6", "dnsaddr"] {
        let value = if kind == "dnsaddr" {
            format!("/{kind}/seed.example./p2p/{expected}")
        } else {
            format!("/{kind}/seed.example./tcp/4001/p2p/{expected}")
        };
        assert!(DiscoveryConfig::new(vec![(expected, value.parse().unwrap())], servers()).is_ok());
    }
    for numeric in ["/ip4/10.0.0.1/tcp/4001", "/ip6/fd00::1/tcp/4001"] {
        assert!(
            DiscoveryConfig::new(vec![(expected, numeric.parse().unwrap())], servers()).is_ok()
        );
    }
    // Construct exact encoded boundaries through the real Multiaddr codec.
    let mut observed = [false; 2];
    for size in 1..=63 {
        let name = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(size)
        );
        let address: Multiaddr = format!("/dns4/{name}/tcp/1/p2p/{expected}")
            .parse()
            .unwrap();
        let length = address.as_ref().len();
        if length == 256 || length == 257 {
            observed[length - 256] = true;
            assert_eq!(
                DiscoveryConfig::new(vec![(expected, address)], servers()).is_ok(),
                length == 256
            );
        }
    }
    assert_eq!(
        observed,
        [true, true],
        "SEED_ENCODED_BOUNDARY_FIXTURE_MISSING"
    );
    // The byte budget includes the pinned peer suffix, not merely the hostname.
    let name = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(31)
    );
    let address: Multiaddr = format!("/dns4/{name}/tcp/1/p2p/{expected}")
        .parse()
        .unwrap();
    assert!(address.as_ref().len() > 256);
    assert!(DiscoveryConfig::new(vec![(expected, address)], servers()).is_err());
}

#[test]
fn owned_dns_config_numeric_nameservers_allow_private_loopback_and_custom_ports() {
    for value in [
        "127.0.0.1:5300",
        "10.0.0.2:54",
        "[::1]:5353",
        "[fd00::1]:65535",
    ] {
        assert!(DiscoveryConfig::new(vec![seed(peer())], vec![value.parse().unwrap()]).is_ok());
    }
    for value in [
        "0.0.0.0:53",
        "127.0.0.1:0",
        "224.0.0.1:53",
        "255.255.255.255:53",
        "[::]:53",
        "[ff02::1]:53",
        "[fe80::1]:53",
        "[::ffff:127.0.0.1]:53",
    ] {
        assert!(
            DiscoveryConfig::new(vec![seed(peer())], vec![value.parse().unwrap()]).is_err(),
            "{value}"
        );
    }
}

#[test]
fn owned_dns_identity_validation_precedes_runtime_and_listener_work() {
    // No runtime: a late validation would report the runtime error instead.
    for overlap in 0..3 {
        let key = Keypair::generate_ed25519();
        let local = key.public().to_peer_id();
        let seed_peer = if overlap == 0 { local } else { peer() };
        let allowed = match overlap {
            0 => vec![],
            1 => vec![seed_peer],
            _ => vec![local],
        };
        let config = DiscoveryConfig::new(vec![seed(seed_peer)], servers()).unwrap();
        let error =
            Carrier::bind_with_discovery(key, "127.0.0.1:0".parse().unwrap(), allowed, config)
                .err()
                .unwrap();
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "CONFIG_VALIDATION_AFTER_RUNTIME"
        );
    }
    let result = Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        DiscoveryConfig::new(vec![seed(peer())], servers()).unwrap(),
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        "carrier requires a Tokio runtime"
    );
}
