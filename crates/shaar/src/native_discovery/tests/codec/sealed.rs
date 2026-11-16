// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! L3b: a record that seals its address list under an address key.

use super::{DecodeError, id, identity, ip, signed, socket};
use crate::identity::address_key::{AddressKey, MARK, seal_addresses};
use crate::native_discovery::codec::decode_record_with;
use iroh_dns::endpoint_info::{EndpointData, EndpointInfo, UserData};
use std::net::{Ipv4Addr, SocketAddr};

const SIGNED_AT_US: u64 = 1_700_000_000_000_000;

fn key(byte: u8) -> AddressKey {
    AddressKey::from_bytes([byte; 32])
}

fn addresses() -> [SocketAddr; 2] {
    [
        socket(Ipv4Addr::new(203, 0, 113, 7).into(), 4433),
        socket(Ipv4Addr::new(10, 0, 0, 2).into(), 4434),
    ]
}

fn server() -> [u8; 32] {
    identity().public_key_bytes()
}

/// A signed record whose only address data is `user_data`, plus any plain `extra` addresses.
fn record_with(user_data: String, extra: Vec<iroh_base::TransportAddr>, signed_at: u64) -> Vec<u8> {
    let owner = identity();
    let data =
        EndpointData::new(extra).with_user_data(UserData::try_from(user_data).expect("fits"));
    EndpointInfo::from_parts(id(server()), data)
        .to_pkarr_signed_packet_at(&owner.transport_key(), 30, signed_at)
        .expect("signed record")
        .as_bytes()
        .to_vec()
}

/// A record sealed at `sealed_at` and signed at `signed_at`.
fn sealed_record(secret: &AddressKey, sealed_at: u64, signed_at: u64) -> Vec<u8> {
    let sealed = seal_addresses(secret, &server(), sealed_at, &addresses()).expect("sealed");
    record_with(sealed, Vec::new(), signed_at)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn a_sealed_record_opens_with_the_key_and_yields_the_sealed_addresses() {
    let bytes = sealed_record(&key(1), SIGNED_AT_US, SIGNED_AT_US);
    let decoded =
        decode_record_with(&bytes, id(server()), Some(&key(1))).expect("opened with the key");
    assert_eq!(decoded.addresses(), addresses().as_slice());
    assert_eq!(
        decoded.signed_sequence,
        i64::try_from(SIGNED_AT_US).unwrap()
    );
}

#[test]
fn a_sealed_record_carries_no_plain_address_bytes() {
    let bytes = sealed_record(&key(1), SIGNED_AT_US, SIGNED_AT_US);
    assert!(
        contains(&bytes, MARK.as_bytes()),
        "the sealed mark is visible"
    );
    for address in addresses() {
        let text = address.ip().to_string();
        assert!(!contains(&bytes, text.as_bytes()), "{text} appears as text");
        if let std::net::IpAddr::V4(v4) = address.ip() {
            assert!(!contains(&bytes, &v4.octets()), "{text} appears as octets");
        }
    }
}

#[test]
fn a_sealed_record_without_a_key_names_the_reason_and_yields_nothing() {
    let bytes = sealed_record(&key(1), SIGNED_AT_US, SIGNED_AT_US);
    assert_eq!(
        decode_record_with(&bytes, id(server()), None),
        Err(DecodeError::Sealed)
    );
}

#[test]
fn a_sealed_record_is_rejected_under_a_wrong_key() {
    let bytes = sealed_record(&key(1), SIGNED_AT_US, SIGNED_AT_US);
    assert_eq!(
        decode_record_with(&bytes, id(server()), Some(&key(2))),
        Err(DecodeError::SealRejected)
    );
}

#[test]
fn a_sealed_value_replayed_under_another_signed_timestamp_is_rejected() {
    // The seal binds the signed timestamp: an old sealed value cannot be re-signed as fresh.
    let bytes = sealed_record(&key(1), SIGNED_AT_US, SIGNED_AT_US + 1);
    assert_eq!(
        decode_record_with(&bytes, id(server()), Some(&key(1))),
        Err(DecodeError::SealRejected)
    );
}

#[test]
fn a_sealed_value_with_a_corrupt_body_is_rejected_whatever_the_key() {
    let bytes = record_with(format!("{MARK}not-a-sealed-body"), Vec::new(), SIGNED_AT_US);
    assert_eq!(
        decode_record_with(&bytes, id(server()), Some(&key(1))),
        Err(DecodeError::SealRejected)
    );
    assert_eq!(
        decode_record_with(&bytes, id(server()), None),
        Err(DecodeError::Sealed)
    );
}

#[test]
fn sealed_addresses_pass_the_same_validation_as_plain_ones() {
    let invalid = [socket(Ipv4Addr::UNSPECIFIED.into(), 0)];
    let sealed = seal_addresses(&key(1), &server(), SIGNED_AT_US, &invalid).expect("sealed");
    let bytes = record_with(sealed, Vec::new(), SIGNED_AT_US);
    assert_eq!(
        decode_record_with(&bytes, id(server()), Some(&key(1))),
        Err(DecodeError::InvalidAddress)
    );
}

#[test]
fn plain_and_sealed_addresses_in_one_record_are_ambiguous_and_rejected() {
    let sealed = seal_addresses(&key(1), &server(), SIGNED_AT_US, &addresses()).expect("sealed");
    let bytes = record_with(sealed, vec![ip(addresses()[0])], SIGNED_AT_US);
    for held in [Some(key(1)), None] {
        assert_eq!(
            decode_record_with(&bytes, id(server()), held.as_ref()),
            Err(DecodeError::MalformedAddress)
        );
    }
}

#[test]
fn a_plain_record_still_decodes_when_a_key_is_configured() {
    let bytes = signed(vec![ip(addresses()[0])]);
    let decoded = decode_record_with(&bytes, id(server()), Some(&key(1))).expect("plain record");
    assert_eq!(decoded.addresses(), &addresses()[..1]);
}
