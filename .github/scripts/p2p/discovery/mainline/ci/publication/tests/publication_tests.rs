// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::{EndpointId, SecretKey, TransportAddr};
use iroh_dns::{
    endpoint_info::{EndpointData, EndpointInfo},
    pkarr::{SignedPacket, SignedPacketBuildError},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn endpoint(key: &SecretKey, address: SocketAddr) -> EndpointInfo {
    EndpointInfo::from_parts(
        EndpointId::from_bytes(key.public().as_bytes()).expect("key id"),
        EndpointData::new(vec![TransportAddr::Ip(address)]),
    )
}

fn checked(packet: &SignedPacket, expected: &EndpointInfo, key: &SecretKey) {
    let verified =
        SignedPacket::from_bytes(packet.as_bytes()).expect("upstream signature verification");
    assert_eq!(verified.public_key(), key.public());
    assert_eq!(verified.as_bytes(), packet.as_bytes());
    let info = EndpointInfo::from_pkarr_signed_packet(&verified).expect("upstream TXT decode");
    assert_eq!(info.endpoint_id, expected.endpoint_id);
    assert_eq!(&info, expected);
}

#[test]
fn supplied_timestamp_zero_normal_and_ceiling_preserve_signed_wire_packet() {
    let key = SecretKey::from_bytes(&[7; 32]);
    let info = endpoint(&key, "127.0.0.1:9000".parse().expect("socket"));
    for timestamp in [0_i64, 1, 1_800_000_000_123_456, i64::MAX] {
        let packet = info
            .to_pkarr_signed_packet_at(&key, 30, timestamp as u64)
            .expect("timestamp is in contract");
        assert_eq!(packet.timestamp().as_micros(), timestamp as u64);
        assert_eq!(
            &packet.as_bytes()[96..104],
            &packet.timestamp().to_be_bytes()
        );
        checked(&packet, &info, &key);
    }
}

#[test]
fn timestamp_above_i64_ceiling_is_rejected() {
    let key = SecretKey::from_bytes(&[8; 32]);
    let info = endpoint(&key, "127.0.0.1:9000".parse().expect("socket"));
    for timestamp in [i64::MAX as u64 + 1, u64::MAX] {
        let error = info
            .to_pkarr_signed_packet_at(&key, 30, timestamp)
            .expect_err("outside signed range");
        assert!(
            error
                .to_string()
                .contains("Publication timestamp exceeds the signed i64 range")
        );
    }
}

#[test]
fn new_key_mismatch_is_rejected_and_legacy_behavior_is_unchanged() {
    let key = SecretKey::from_bytes(&[9; 32]);
    let other = SecretKey::from_bytes(&[10; 32]);
    let info = endpoint(&key, "127.0.0.1:9000".parse().expect("socket"));
    let error = info
        .to_pkarr_signed_packet_at(&other, 30, 1)
        .expect_err("wrong signing key");
    assert!(
        error
            .to_string()
            .contains("Publication signing key does not match endpoint id")
    );
    let legacy = info
        .to_pkarr_signed_packet(&other, 30)
        .expect("old API behavior");
    assert_eq!(legacy.public_key(), other.public());

    let txt_error = SignedPacket::from_txt_strings(&key, "_iroh", ["x".repeat(256)], 30)
        .expect_err("upstream TXT character-string limit");
    assert!(matches!(txt_error, SignedPacketBuildError::DnsError { .. }));
}

#[test]
fn upstream_dns_packet_limit_is_reported() {
    let key = SecretKey::from_bytes(&[11; 32]);
    let addresses = (1..=128)
        .map(|port| {
            TransportAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    10,
                    1,
                    (port / 250) as u8,
                    (port % 250) as u8 + 1,
                )),
                port,
            ))
        })
        .collect();
    let info = EndpointInfo::from_parts(
        EndpointId::from_bytes(key.public().as_bytes()).expect("key id"),
        EndpointData::new(addresses),
    );
    let values = info.to_txt_strings();
    let low_level = SignedPacket::from_txt_strings(&key, "_iroh", values, 30)
        .expect_err("upstream DNS packet exceeds size limit");
    assert!(matches!(low_level, SignedPacketBuildError::PacketTooLarge { len, .. } if len > 1000));
    let high_level = info
        .to_pkarr_signed_packet_at(&key, 30, 1)
        .expect_err("high-level encoder reports upstream size failure");
    assert!(high_level.to_string().contains("DNS packet too large:"));
}

#[test]
fn explicit_packet_matches_ordinary_complete_wire_at_captured_time() {
    let key = SecretKey::from_bytes(&[12; 32]);
    let info = endpoint(&key, "127.0.0.1:9000".parse().expect("socket"));
    let ordinary = info
        .to_pkarr_signed_packet(&key, 30)
        .expect("ordinary encoder");
    let ordinary_again = info
        .to_pkarr_signed_packet(&key, 30)
        .expect("ordinary timestamp continues");
    assert!(ordinary_again.timestamp().as_micros() > ordinary.timestamp().as_micros());
    let captured = ordinary.timestamp().as_micros();
    let explicit = info
        .to_pkarr_signed_packet_at(&key, 30, captured)
        .expect("explicit encoder");
    assert_eq!(explicit.as_bytes(), ordinary.as_bytes());
    checked(&explicit, &info, &key);
}

#[test]
fn verifier_rejects_mutated_key_signature_timestamp_dns_and_truncation() {
    let key = SecretKey::from_bytes(&[13; 32]);
    let info = endpoint(&key, "127.0.0.1:9000".parse().expect("socket"));
    let packet = info
        .to_pkarr_signed_packet_at(&key, 30, 42)
        .expect("packet");
    for index in [0, 32, 96, packet.as_bytes().len() - 1] {
        let mut bytes = packet.as_bytes().to_vec();
        bytes[index] ^= 1;
        assert!(SignedPacket::from_bytes(&bytes).is_err());
    }
    assert!(SignedPacket::from_bytes(&[0; 103]).is_err());
}
