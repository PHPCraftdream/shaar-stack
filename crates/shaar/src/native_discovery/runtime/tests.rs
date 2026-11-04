// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

#[path = "tests/bounds.rs"]
mod bounds;
#[path = "tests/fixture.rs"]
mod fixture;
#[path = "tests/lifetime.rs"]
mod lifetime;
#[path = "tests/publication.rs"]
mod publication;

use super::*;
use crate::native_discovery::runtime::clock::ClockSample;

fn test_clock_sample(wall_us: i64) -> ClockSample {
    ClockSample {
        wall_us,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    }
}

#[test]
fn mutable_conversion_preserves_signed_packet_sequence_and_key() {
    let identity = Identity::from_seed([0x51; 32]);
    let key = endpoint_key(&identity).expect("valid endpoint key");
    let mut publisher = PublisherState::new(key);
    let snapshot = [TransportAddr::Ip(
        "127.0.0.1:9001".parse().expect("valid test address"),
    )];
    let (_, packet) = publisher
        .replace(
            &identity,
            &snapshot,
            test_clock_sample(1_700_000_000_000_000),
        )
        .expect("signed snapshot");
    let signed = packet.expect("packet exists");

    let item = to_mutable(&signed).expect("verified signed packet converts");

    assert_eq!(
        item.key().as_slice(),
        identity.public_key_bytes().as_slice()
    );
    assert_eq!(item.seq(), signed.timestamp_us);
    assert!(item.salt().is_none());
}

#[test]
fn mutable_conversion_rejects_length_underflow_before_decode() {
    let packet = SignedSnapshot {
        timestamp_us: 1,
        bytes: vec![0; 103],
    };

    assert!(matches!(to_mutable(&packet), Err(RuntimeError::PutFailed)));
}

mod refresh_tests {
    use super::*;
    use crate::native_discovery::runtime::owner::{RuntimeOwner, TestClock};
    use std::time::Duration;

    #[tokio::test]
    async fn periodic_refresh_emits_new_signed_timestamp_to_loopback_peer() {
        let mut peer = fixture::LoopbackPeer::bind().await;
        let bootstrap = match peer.address {
            std::net::SocketAddr::V4(address) => address,
            std::net::SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
        };
        let identity = Identity::from_seed([0x73; 32]);
        let clock = TestClock::new(1_700_000_000_000_000);
        let mut owner = RuntimeOwner::start_controlled(
            identity,
            "127.0.0.1:0".parse().expect("loopback bind"),
            &[bootstrap],
            clock.clone(),
        )
        .expect("owned loopback DHT");
        let replace = owner.replace(vec![TransportAddr::Ip(
            "127.0.0.1:9011".parse().expect("published address"),
        )]);
        let initial_put = peer.serve_until_put();
        let (acknowledged, initial) = tokio::join!(replace, initial_put);
        assert!(acknowledged.is_ok());
        let initial_timestamp = initial.sequence;
        let initial_signature = initial.signature;
        let initial_value = initial.value;
        let initial_key = initial.key;

        tokio::time::pause();
        clock.set(initial_timestamp + 60_000_000);
        clock.set_monotonic(60_000_000);
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::resume();
        let refreshed = peer.serve_until_put().await;
        assert!(refreshed.sequence > initial_timestamp);
        assert_eq!(refreshed.value, initial_value);
        assert_eq!(refreshed.key, initial_key);
        assert_ne!(refreshed.signature, initial_signature);

        owner.close().await.expect("publisher and actor joined");
    }
}

#[test]
fn queued_snapshot_releases_excess_capacity_and_preserves_raw_ip_count() {
    let address = "127.0.0.1:9000".parse().expect("native address");
    for length in [0, 1, 4] {
        let mut input = Vec::with_capacity(64);
        input.resize_with(length, || TransportAddr::Ip(address));
        let bounded = bounded_replace(input).expect("bounded native snapshot");
        assert_eq!(bounded.len(), length);
        assert!(
            bounded.capacity() <= 4,
            "queued storage must not retain caller capacity"
        );
        assert!(
            bounded
                .iter()
                .all(|item| item == &TransportAddr::Ip(address))
        );
    }
}

#[test]
fn unsupported_transports_become_error_payloads_before_queueing() {
    for address in [
        TransportAddr::Custom(iroh_base::CustomAddr::from_parts(0x5348, &[0; 16])),
        TransportAddr::Relay("https://relay.invalid/".parse().expect("relay fixture")),
    ] {
        assert_eq!(
            bounded_replace(vec![address]),
            Err(SnapshotError::UnsupportedTransport)
        );
    }
}

#[test]
fn oversized_replace_payload_is_not_admitted_to_the_bounded_command() {
    let input = (0..5)
        .map(|port| {
            TransportAddr::Ip(
                format!("127.0.0.1:{}", 9000 + port)
                    .parse()
                    .expect("socket"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(bounded_replace(input), Err(SnapshotError::TooManyAddresses));
}
