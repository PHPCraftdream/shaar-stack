use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libp2p::{Multiaddr, multiaddr::Protocol};

use super::{
    DiscoveryConfig,
    address::classify_complete,
    address_tests::{peer, servers},
    scope::discovery_ip_allowed,
};

fn check(ip: IpAddr, allowed: bool) {
    assert_eq!(discovery_ip_allowed(ip), allowed, "{ip}");
    let host = match ip {
        IpAddr::V4(ip) => Protocol::Ip4(ip),
        IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    let address = Multiaddr::empty()
        .with(host)
        .with(Protocol::Tcp(4001))
        .with(Protocol::P2p(peer(1)));
    assert_eq!(
        classify_complete(address.as_ref(), peer(1)).is_ok(),
        allowed,
        "{ip}"
    );
    assert_eq!(
        DiscoveryConfig::new(vec![(peer(1), address)], servers()).is_ok(),
        allowed,
        "{ip}"
    );
}

#[test]
fn discovery_address_ipv4_every_registry_row_and_multicast_boundaries() {
    // Independent inclusive endpoints transcribed from the reviewed IANA snapshot.
    for (first, last) in [
        ("0.0.0.0", "0.255.255.255"),
        ("0.0.0.0", "0.0.0.0"),
        ("10.0.0.0", "10.255.255.255"),
        ("100.64.0.0", "100.127.255.255"),
        ("127.0.0.0", "127.255.255.255"),
        ("169.254.0.0", "169.254.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.0.0.0", "192.0.0.255"),
        ("192.0.0.0", "192.0.0.7"),
        ("192.0.0.8", "192.0.0.8"),
        ("192.0.0.9", "192.0.0.9"),
        ("192.0.0.10", "192.0.0.10"),
        ("192.0.0.170", "192.0.0.170"),
        ("192.0.0.171", "192.0.0.171"),
        ("192.0.2.0", "192.0.2.255"),
        ("192.31.196.0", "192.31.196.255"),
        ("192.52.193.0", "192.52.193.255"),
        ("192.88.99.0", "192.88.99.255"),
        ("192.88.99.2", "192.88.99.2"),
        ("192.168.0.0", "192.168.255.255"),
        ("192.175.48.0", "192.175.48.255"),
        ("198.18.0.0", "198.19.255.255"),
        ("198.51.100.0", "198.51.100.255"),
        ("203.0.113.0", "203.0.113.255"),
        ("240.0.0.0", "255.255.255.255"),
        ("255.255.255.255", "255.255.255.255"),
        ("224.0.0.0", "239.255.255.255"),
    ] {
        let first = u32::from(first.parse::<Ipv4Addr>().unwrap());
        let last = u32::from(last.parse::<Ipv4Addr>().unwrap());
        for value in [first, first + (last - first) / 2, last] {
            check(Ipv4Addr::from(value).into(), false);
        }
    }
}

#[test]
fn discovery_address_ipv6_every_registry_row_boundaries() {
    for (first, last) in [
        ("::1", "::1"),
        ("::", "::"),
        ("::ffff:0:0", "::ffff:ffff:ffff"),
        ("64:ff9b::", "64:ff9b::ffff:ffff"),
        ("64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"),
        ("100::", "100::ffff:ffff:ffff:ffff"),
        ("100:0:0:1::", "100:0:0:1:ffff:ffff:ffff:ffff"),
        ("2001::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001::", "2001:0:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:1::1", "2001:1::1"),
        ("2001:1::2", "2001:1::2"),
        ("2001:1::3", "2001:1::3"),
        ("2001:2::", "2001:2:0:ffff:ffff:ffff:ffff:ffff"),
        ("2001:3::", "2001:3:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:4:112::", "2001:4:112:ffff:ffff:ffff:ffff:ffff"),
        ("2001:10::", "2001:1f:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:20::", "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:30::", "2001:3f:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2002::", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("2620:4f:8000::", "2620:4f:8000:ffff:ffff:ffff:ffff:ffff"),
        ("3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ] {
        let first = u128::from(first.parse::<Ipv6Addr>().unwrap());
        let last = u128::from(last.parse::<Ipv6Addr>().unwrap());
        for value in [first, first + (last - first) / 2, last] {
            check(Ipv6Addr::from(value).into(), false);
        }
    }
}

#[test]
fn discovery_address_global_controls_adjacent_to_exclusions() {
    for ip in [
        "1.0.0.0",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "191.255.255.255",
        "192.0.1.0",
        "192.0.1.255",
        "192.0.3.0",
        "192.31.195.255",
        "192.31.197.0",
        "192.52.192.255",
        "192.52.194.0",
        "192.88.98.255",
        "192.88.100.0",
        "192.167.255.255",
        "192.169.0.0",
        "192.175.47.255",
        "192.175.49.0",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.99.255",
        "198.51.101.0",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255",
        "8.8.8.8",
        "1.1.1.1",
        "2000::",
        "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:200::",
        "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db9::",
        "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2003::",
        "2620:4f:7fff:ffff:ffff:ffff:ffff:ffff",
        "2620:4f:8001::",
        "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "3fff:1000::",
        "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2606:4700:4700::1111",
    ] {
        check(ip.parse().unwrap(), true);
    }
}

#[test]
fn discovery_address_mapped_and_outside_global_unicast_are_denied() {
    for ip in [
        "::8.8.8.8",
        "::ffff:8.8.8.8",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:192.168.1.1",
        "::ffff:255.255.255.255",
        "64:ff9b::808:808",
        "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "4000::",
        "5fff::",
        "8000::",
        "fec0::",
        "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "ff00::",
        "ff02::1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ] {
        check(ip.parse().unwrap(), false);
    }
}
