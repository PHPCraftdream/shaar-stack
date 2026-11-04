// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, PUB2, id, identity, ip, socket};
use crate::native_discovery::codec::{decode_mutable_record, parse_dns_profile};
use crate::native_discovery::{DecodeError, decode_record};
use iroh_dns::{
    endpoint_info::{EndpointData, EndpointInfo},
    pkarr::SignedPacket,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Frozen external pkarr output; provenance is in publication/tests/reference/README.md.
const INDEPENDENT_NATIVE_RECORD: [u8; 206] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    0x85, 0xdb, 0x20, 0xcc, 0x17, 0x28, 0x45, 0xba, 0x00, 0x1d, 0x1d, 0x65, 0xfa, 0x78, 0xba, 0x9c,
    0xb3, 0xe0, 0x45, 0x65, 0xe6, 0x8b, 0x43, 0x85, 0x6a, 0xd9, 0xe2, 0xb9, 0xc2, 0xd0, 0xce, 0x8a,
    0xb9, 0xc7, 0x8c, 0x7e, 0xf6, 0x6b, 0xb8, 0x61, 0x07, 0x8e, 0x25, 0xbe, 0xb9, 0x0d, 0x3f, 0x95,
    0x47, 0xdc, 0x99, 0x05, 0x63, 0xf8, 0xaa, 0xae, 0x75, 0x34, 0x8e, 0xd3, 0x8e, 0x85, 0x8e, 0x0e,
    0x00, 0x06, 0x0a, 0x24, 0x18, 0x1e, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x5f, 0x69, 0x72, 0x6f, 0x68, 0x34, 0x34, 0x37, 0x70, 0x6a, 0x6f,
    0x79, 0x63, 0x6e, 0x73, 0x72, 0x66, 0x6d, 0x78, 0x69, 0x6b, 0x6d, 0x39, 0x35, 0x6a, 0x68, 0x31,
    0x33, 0x79, 0x38, 0x38, 0x65, 0x38, 0x71, 0x6e, 0x68, 0x7a, 0x75, 0x35, 0x6b, 0x75, 0x6e, 0x67,
    0x6a, 0x70, 0x78, 0x79, 0x65, 0x70, 0x67, 0x74, 0x37, 0x61, 0x38, 0x6b, 0x72, 0x70, 0x79, 0x00,
    0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x14, 0x13, 0x61, 0x64, 0x64, 0x72, 0x3d,
    0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x39, 0x30, 0x30, 0x30,
];

#[test]
fn independent_native_record_decodes_and_enters_real_policy_owner() {
    let bytes = &INDEPENDENT_NATIVE_RECORD;
    let decoded = decode_record(bytes, id(PUB1)).expect("independent native signed record");
    let timestamp = 1_700_000_000_000_000;
    let address: SocketAddr = "127.0.0.1:9000".parse().expect("fixed reference address");
    assert_eq!(decoded.key, id(PUB1));
    assert_eq!(decoded.signed_sequence, timestamp);
    assert_eq!(decoded.signed_at_us, timestamp);
    assert_eq!(decoded.signed_bytes.as_slice(), bytes.as_slice());
    assert_eq!(decoded.addresses(), &[address]);
    assert!(decoded.metadata().is_empty());
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner
        .admit_expected_key(id(PUB1))
        .expect("authorized reference key");
    let at = crate::native_discovery::ClockSample {
        wall_us: timestamp + 10_000_000,
        monotonic_us: 50_000_000,
    };
    owner
        .complete_query(
            id(PUB1),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                at,
                vec![decoded.into()],
            ),
        )
        .expect("real policy owner accepts verified external record");
    assert_eq!(owner.winner_bytes(id(PUB1)), Some(bytes.as_slice()));
    assert_eq!(owner.winner_sequence(id(PUB1)), Some(timestamp));
    assert_eq!(owner.addresses(id(PUB1), at), Ok([address].as_slice()));
    assert_eq!(owner.cache_deadline(id(PUB1)), Some(80_000_000));
}

#[test]
fn independent_native_record_rejects_wrong_key_mutations_and_every_prefix() {
    let bytes = &INDEPENDENT_NATIVE_RECORD;
    assert!(matches!(
        decode_record(bytes, id(PUB2)),
        Err(DecodeError::WrongKey)
    ));
    for index in 0..bytes.len() {
        let mut changed = *bytes;
        changed[index] ^= 1;
        assert!(
            decode_record(&changed, id(PUB1)).is_err(),
            "accepted changed byte {index}"
        );
    }
    for length in 0..bytes.len() {
        assert!(
            decode_record(&bytes[..length], id(PUB1)).is_err(),
            "accepted prefix {length}"
        );
    }
    let mut suffix = bytes.to_vec();
    suffix.push(0);
    assert!(decode_record(&suffix, id(PUB1)).is_err());
}

#[test]
fn independent_native_record_obeys_actual_policy_freshness_boundaries() {
    use crate::native_discovery::{
        ClockSample, CompletedQuery, PolicyOwner, QuerySource, RecordError,
    };
    let timestamp = 1_700_000_000_000_000;
    for (offset, expected, deadline) in [
        (-30_000_000, Ok(()), Some(80_000_000)),
        (-30_000_001, Err(RecordError::TooFarFuture), None),
        (299_999_999, Ok(()), Some(50_000_001)),
        (300_000_000, Ok(()), Some(50_000_000)),
        (300_000_001, Err(RecordError::TooOld), None),
    ] {
        let decoded = decode_record(&INDEPENDENT_NATIVE_RECORD, id(PUB1)).expect("external vector");
        let mut owner = PolicyOwner::new();
        owner.admit_expected_key(id(PUB1)).expect("authorized key");
        let at = ClockSample {
            wall_us: timestamp + offset,
            monotonic_us: 50_000_000,
        };
        assert_eq!(
            owner.complete_query(
                id(PUB1),
                CompletedQuery::new(QuerySource::Network, at, vec![decoded.into()],)
            ),
            expected,
            "signed age offset {offset}"
        );
        assert_eq!(
            owner.cache_deadline(id(PUB1)),
            deadline,
            "signed age offset {offset}"
        );
    }
}

fn signed(addresses: Vec<iroh_base::TransportAddr>) -> Vec<u8> {
    let owner = identity();
    EndpointInfo::from_parts(id(owner.public_key_bytes()), EndpointData::new(addresses))
        .to_pkarr_signed_packet(&owner.transport_key(), 30)
        .expect("small signed record")
        .as_bytes()
        .to_vec()
}

#[test]
fn strict_profile_helper_rejects_untrusted_dns_encodings_without_claiming_signature_checks() {
    let key = id(PUB1);
    let valid = signed(vec![ip("127.0.0.1:9000".parse().expect("socket literal"))]);
    let dns = &valid[104..];
    let profile = parse_dns_profile(dns, key).expect("valid profile");
    assert_eq!(
        profile.raw_addresses,
        ["127.0.0.1:9000".parse::<SocketAddr>().expect("socket")]
    );
    assert_eq!(profile.canonical_addresses, profile.raw_addresses);
    assert!(profile.metadata.is_empty());
    assert!(parse_dns_profile(&dns[..dns.len() - 1], key).is_err());
    let mut trailing = dns.to_vec();
    trailing.push(0);
    assert!(simple_dns::Packet::parse(&trailing).is_ok());
    assert!(simple_dns::Packet::parse_exact(&trailing).is_err());
    assert!(parse_dns_profile(&trailing, key).is_err());

    // Helper receives unauthenticated DNS bytes; these checks do not test signature verification.
    let mut wrong_owner = dns.to_vec();
    let owner_label = b"_iroh";
    let label_start = wrong_owner
        .windows(owner_label.len())
        .position(|window| window == owner_label)
        .expect("owner label")
        + owner_label.len()
        + 1;
    wrong_owner[label_start] ^= 1;
    assert!(parse_dns_profile(&wrong_owner, key).is_err());

    let packet = iroh_dns::pkarr::SignedPacket::from_txt_strings(
        &identity().transport_key(),
        "_iroh",
        ["addr=   "],
        1,
    )
    .expect("upstream packet with whitespace address");
    assert!(parse_dns_profile(packet.encoded_packet(), key).is_err());
    let zero_ttl = iroh_dns::pkarr::SignedPacket::from_txt_strings(
        &identity().transport_key(),
        "_iroh",
        ["addr=127.0.0.1:9000"],
        0,
    )
    .expect("upstream packet with TTL zero");
    assert!(parse_dns_profile(zero_ttl.encoded_packet(), key).is_ok());

    let profile_name = format!("_iroh.{}", key.to_z32());
    let mut invalid_utf8 = simple_dns::rdata::TXT::new();
    invalid_utf8.add_char_string(
        simple_dns::CharacterString::new(b"addr=\xff").expect("valid DNS character-string"),
    );
    let mut invalid_utf8_packet = simple_dns::Packet::new_reply(0);
    invalid_utf8_packet
        .answers
        .push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new(&profile_name).expect("owner name"),
            simple_dns::CLASS::IN,
            1,
            simple_dns::rdata::RData::TXT(invalid_utf8),
        ));
    let invalid_utf8_dns = invalid_utf8_packet
        .build_bytes_vec_compressed()
        .expect("serialize invalid UTF-8 TXT");
    assert!(parse_dns_profile(&invalid_utf8_dns, key).is_err());

    let mut fragments = simple_dns::rdata::TXT::new();
    fragments
        .add_string("addr=127.0.0.")
        .expect("first fragment");
    fragments.add_string("1:9000").expect("second fragment");
    let mut fragment_packet = simple_dns::Packet::new_reply(0);
    fragment_packet
        .answers
        .push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new(&profile_name).expect("owner name"),
            simple_dns::CLASS::IN,
            1,
            simple_dns::rdata::RData::TXT(fragments),
        ));
    let fragment_dns = fragment_packet
        .build_bytes_vec_compressed()
        .expect("serialize fragmented TXT");
    let fragment_profile = parse_dns_profile(&fragment_dns, key).expect("fragment concatenates");
    assert_eq!(
        fragment_profile.raw_addresses,
        ["127.0.0.1:9000".parse::<SocketAddr>().expect("socket")]
    );

    let mut equals_fragment = simple_dns::rdata::TXT::new();
    equals_fragment
        .add_string("user-data=opaque=")
        .expect("first fragment");
    equals_fragment.add_string("tail").expect("second fragment");
    let valid_addr = simple_dns::ResourceRecord::new(
        simple_dns::Name::new(&profile_name).expect("owner name"),
        simple_dns::CLASS::IN,
        1,
        simple_dns::rdata::RData::TXT({
            let mut txt = simple_dns::rdata::TXT::new();
            txt.add_string("addr=127.0.0.1:9").expect("valid addr");
            txt
        }),
    );
    let mut equals_packet = simple_dns::Packet::new_reply(0);
    equals_packet.answers.push(valid_addr.clone());
    equals_packet.answers.push(simple_dns::ResourceRecord::new(
        simple_dns::Name::new(&profile_name).expect("owner name"),
        simple_dns::CLASS::IN,
        1,
        simple_dns::rdata::RData::TXT(equals_fragment),
    ));
    let equals_dns = equals_packet
        .build_bytes_vec_compressed()
        .expect("TXT packet");
    let profile = parse_dns_profile(&equals_dns, key).expect("concatenated TXT");
    assert_eq!(
        profile.metadata,
        [("user-data".to_owned(), "opaque=tail".to_owned())]
    );

    let mut utf8_fragments = simple_dns::rdata::TXT::new();
    utf8_fragments.add_char_string(
        simple_dns::CharacterString::new(b"user-data=split=\xc3").expect("UTF-8 prefix"),
    );
    utf8_fragments
        .add_char_string(simple_dns::CharacterString::new(b"\xa9").expect("UTF-8 suffix"));
    let mut utf8_packet = simple_dns::Packet::new_reply(0);
    utf8_packet.answers.push(valid_addr);
    utf8_packet.answers.push(simple_dns::ResourceRecord::new(
        simple_dns::Name::new(&profile_name).expect("owner name"),
        simple_dns::CLASS::IN,
        1,
        simple_dns::rdata::RData::TXT(utf8_fragments),
    ));
    let utf8_dns = utf8_packet.build_bytes_vec_compressed().expect("UTF-8 TXT");
    let profile = parse_dns_profile(&utf8_dns, key).expect("validate after concat");
    assert_eq!(
        profile.metadata,
        [("user-data".to_owned(), "split=é".to_owned())]
    );

    let mut equivalent = simple_dns::Packet::new_reply(0);
    for txt in ["addr=127.0.0.1:9", "addr=127.0.0.1:10"] {
        let mut data = simple_dns::rdata::TXT::new();
        data.add_string(txt).expect("single TXT value");
        equivalent.answers.push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new(&profile_name).expect("owner name"),
            simple_dns::CLASS::IN,
            1,
            simple_dns::rdata::RData::TXT(data),
        ));
    }
    let compressed = equivalent.build_bytes_vec_compressed().expect("compressed");
    let uncompressed = equivalent.build_bytes_vec().expect("uncompressed");
    assert_ne!(compressed, uncompressed);
    assert!(parse_dns_profile(&compressed, key).is_ok());
    assert!(parse_dns_profile(&uncompressed, key).is_ok());
    assert!(parse_dns_profile(&compressed[..compressed.len() - 1], key).is_err());
    assert!(parse_dns_profile(&uncompressed[..uncompressed.len() - 1], key).is_err());

    let mut non_txt_packet = simple_dns::Packet::new_reply(0);
    non_txt_packet.answers.push(simple_dns::ResourceRecord::new(
        simple_dns::Name::new(&profile_name).expect("owner name"),
        simple_dns::CLASS::IN,
        1,
        simple_dns::rdata::RData::Empty(simple_dns::TYPE::A),
    ));
    let non_txt_dns = non_txt_packet
        .build_bytes_vec_compressed()
        .expect("serialize non-TXT answer");
    assert!(parse_dns_profile(&non_txt_dns, key).is_err());

    let mut huge_counts = vec![0_u8; 12];
    huge_counts[2] = 0x80;
    huge_counts[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(parse_dns_profile(&huge_counts, key).is_err());
}

#[test]
fn checked_packet_accepts_zero_ttl() {
    let packet = iroh_dns::pkarr::SignedPacket::from_txt_strings(
        &identity().transport_key(),
        "_iroh",
        ["addr=127.0.0.1:9000"],
        0,
    )
    .expect("upstream packet with TTL zero");
    assert!(decode_record(packet.as_bytes(), id(PUB1)).is_ok());
}

#[test]
fn rfc8032_identity_and_checked_endpoint_codec_round_trip_v4_v6() {
    let owner = identity();
    assert_eq!(owner.public_key_bytes(), PUB1);
    let addresses = [
        socket(IpAddr::V4(Ipv4Addr::new(192, 168, 4, 7)), 4242),
        socket(IpAddr::V6("2001:db8::7".parse().expect("literal")), 4243),
    ];
    let bytes = signed(addresses.iter().copied().map(ip).collect());
    let checked =
        SignedPacket::from_bytes(&bytes).expect("independent checked upstream packet parse");
    let decoded = decode_record(&bytes, id(PUB1)).expect("expected-key checked decode");
    let timestamp =
        i64::try_from(checked.timestamp().as_micros()).expect("timestamp fits policy range");
    assert_eq!(decoded.key, id(PUB1));
    assert_eq!(decoded.key.as_bytes(), checked.public_key().as_bytes());
    assert_eq!(decoded.signed_at_us, timestamp);
    assert_eq!(decoded.signed_sequence, timestamp);
    assert_eq!(decoded.signed_bytes, bytes);
    assert_eq!(decoded.addresses(), &addresses);
    let observation: crate::native_discovery::policy::RecordObservation = decoded.into();
    assert_eq!(observation.sequence, timestamp);
    assert_eq!(observation.signed_at_us, timestamp);
    assert_eq!(observation.signed_bytes, bytes);
    assert_eq!(observation.addresses, addresses);
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner
        .admit_expected_key(id(PUB1))
        .expect("caller authorizes key");
    let receipt = crate::native_discovery::ClockSample {
        wall_us: timestamp,
        monotonic_us: 50_000_000,
    };
    owner
        .complete_query(
            id(PUB1),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                receipt,
                vec![observation],
            ),
        )
        .expect("decoded observation enters policy owner");
    assert_eq!(owner.winner_sequence(id(PUB1)), Some(timestamp));
    assert_eq!(owner.winner_bytes(id(PUB1)), Some(bytes.as_slice()));
    assert_eq!(owner.cache_deadline(id(PUB1)), Some(80_000_000));
    assert_eq!(owner.signed_timestamp(id(PUB1)), Some(timestamp));
    assert_eq!(owner.lookup_cache(id(PUB1), receipt), Ok(()));
    assert_eq!(owner.query_required(id(PUB1), receipt), Ok(false));
}

#[test]
fn checked_decoder_rejects_wrong_expected_key_every_byte_flip_and_truncation() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000);
    let bytes = signed(vec![ip(address)]);
    let decoded = decode_record(&bytes, id(PUB1)).expect("checked address");
    assert_eq!(decoded.addresses(), &[address]);
    assert!(matches!(
        decode_record(&bytes, id(PUB2)),
        Err(DecodeError::WrongKey)
    ));
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            decode_record(&changed, id(PUB1)).is_err(),
            "accepted bit flip at {index}"
        );
    }
    for end in [0, 1, 31, 32, 95, 103, 104, bytes.len() - 1] {
        assert!(
            decode_record(&bytes[..end], id(PUB1)).is_err(),
            "accepted prefix {end}"
        );
    }
    assert!(decode_record(&[], id(PUB1)).is_err());
    assert!(decode_record(&vec![0; SignedPacket::MAX_BYTES + 1], id(PUB1)).is_err());
    let mut overlong = bytes.clone();
    overlong.push(0);
    assert!(SignedPacket::from_bytes(&overlong).is_err());
    assert!(decode_record(&overlong, id(PUB1)).is_err());
}

#[test]
fn strict_decoder_rejects_malformed_mixed_txt_and_ignored_suffix_atomically() {
    let owner = identity();
    let key = owner.transport_key();
    for bad in ["addr=not-a-socket", "addr=127.0.0.1:9=ignored"] {
        let packet = SignedPacket::from_txt_strings(
            &key,
            "_iroh",
            ["addr=127.0.0.1:9".to_owned(), bad.to_owned()],
            30,
        )
        .expect("upstream signs arbitrary TXT strings");
        let checked = SignedPacket::from_bytes(packet.as_bytes()).expect("checked upstream packet");
        assert!(
            EndpointInfo::from_pkarr_signed_packet(&checked).is_ok(),
            "upstream is permissive"
        );
        assert!(matches!(
            decode_record(checked.as_bytes(), id(PUB1)),
            Err(DecodeError::MalformedAddress)
        ));
    }
}

#[test]
fn upstream_codec_exact_dns_and_signed_packet_limits() {
    let key = identity().transport_key();
    // Header 12 + compressed owner RR 71 + TXT 255+255+255+113 + three 13-byte RRs = 1000.
    let values = [
        "a".repeat(255),
        "b".repeat(255),
        "c".repeat(255),
        "d".repeat(113),
    ];
    let packet =
        SignedPacket::from_txt_strings(&key, "_iroh", values.iter(), 30).expect("1000 DNS bytes");
    assert_eq!(packet.encoded_packet().len(), 1000);
    assert_eq!(packet.as_bytes().len(), 1104);
    let checked = SignedPacket::from_bytes(packet.as_bytes()).expect("1104 signed bytes");
    assert_eq!(checked.as_bytes().len(), 1104);
    let mut one_over = packet.as_bytes().to_vec();
    one_over.push(0);
    assert!(SignedPacket::from_bytes(&one_over).is_err());
    assert!(decode_record(&one_over, id(PUB1)).is_err());
    let over = [
        "a".repeat(255),
        "b".repeat(255),
        "c".repeat(255),
        "d".repeat(114),
    ];
    assert!(SignedPacket::from_txt_strings(&key, "_iroh", over.iter(), 30).is_err());
}

#[test]
fn decoded_raw_and_canonical_addresses_reach_owner_and_raw_limit_precedes_dedup() {
    let mapped: SocketAddr = "[::ffff:192.168.1.3]:7000".parse().expect("mapped literal");
    let v4: SocketAddr = "192.168.1.3:7000".parse().expect("IPv4 literal");
    let second: SocketAddr = "192.168.1.4:7001".parse().expect("IPv4 literal");
    let third: SocketAddr = "192.168.1.5:7002".parse().expect("IPv4 literal");
    let bytes = signed(vec![ip(mapped), ip(v4), ip(second), ip(third)]);
    let decoded = decode_record(&bytes, id(PUB1)).expect("four raw addresses");
    assert_eq!(decoded.raw_addresses(), &[mapped, v4, second, third]);
    let expected = [v4, second, third];
    assert_eq!(decoded.addresses(), &expected);
    let observation: crate::native_discovery::policy::RecordObservation = decoded.into();
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(id(PUB1)).expect("authorized key");
    let now = crate::native_discovery::ClockSample {
        wall_us: observation.signed_at_us,
        monotonic_us: 10,
    };
    owner
        .complete_query(
            id(PUB1),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                now,
                vec![observation],
            ),
        )
        .expect("verified admission");
    assert_eq!(
        owner.addresses(id(PUB1), now).expect("cache winner"),
        &expected
    );
    let five = signed(vec![
        ip(mapped),
        ip(v4),
        ip(second),
        ip(third),
        ip("192.168.1.6:7003".parse().expect("IPv4 literal")),
    ]);
    assert!(decode_record(&five, id(PUB1)).is_err());
}

#[test]
fn verified_record_key_cannot_be_reassigned_to_a_different_policy_owner() {
    let bytes = signed(vec![ip(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        9000,
    ))]);
    let observation: crate::native_discovery::policy::RecordObservation =
        decode_record(&bytes, id(PUB1)).expect("checked key").into();
    let timestamp = observation.signed_at_us;
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner
        .admit_expected_key(id(PUB2))
        .expect("other expected key");
    let now = crate::native_discovery::ClockSample {
        wall_us: timestamp,
        monotonic_us: 1,
    };
    assert_eq!(
        owner.complete_query(
            id(PUB2),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                now,
                vec![observation]
            )
        ),
        Err(crate::native_discovery::RecordError::Unauthorized)
    );
    assert_eq!(owner.winner_sequence(id(PUB2)), None);
}

#[test]
fn verified_user_data_metadata_survives_the_private_policy_handoff() {
    let packet = SignedPacket::from_txt_strings(
        &identity().transport_key(),
        "_iroh",
        ["addr=127.0.0.1:9000", "user-data=private=meta"],
        30,
    )
    .expect("upstream signed TXT");
    let record = decode_record(packet.as_bytes(), id(PUB1)).expect("checked record");
    assert_eq!(
        record.metadata(),
        &[("user-data".to_owned(), "private=meta".to_owned())]
    );
    let observation: crate::native_discovery::policy::RecordObservation = record.into();
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(id(PUB1)).expect("authorized key");
    let now = crate::native_discovery::ClockSample {
        wall_us: observation.signed_at_us,
        monotonic_us: 1,
    };
    owner
        .complete_query(
            id(PUB1),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                now,
                vec![observation],
            ),
        )
        .expect("metadata admission");
    let data = owner
        .metadata(id(PUB1), now)
        .expect("cached metadata")
        .to_vec();
    assert_eq!(data, [("user-data".to_owned(), "private=meta".to_owned())]);
    let expired = crate::native_discovery::ClockSample {
        wall_us: now.wall_us,
        monotonic_us: 30_000_001,
    };
    assert_eq!(
        owner.metadata(id(PUB1), expired),
        Err(crate::native_discovery::RecordError::CacheExpired)
    );
}

#[test]
fn policy_bounds_raw_addresses_before_normalizing_and_stores_canonical_winner() {
    let address: SocketAddr = "192.168.1.3:7000".parse().expect("literal");
    let mapped: SocketAddr = "[::ffff:192.168.1.3]:7000".parse().expect("literal");
    let second: SocketAddr = "192.168.1.4:7001".parse().expect("literal");
    let third: SocketAddr = "192.168.1.5:7002".parse().expect("literal");
    let fourth: SocketAddr = "192.168.1.6:7003".parse().expect("literal");
    let mut owner = crate::native_discovery::PolicyOwner::new();
    owner.admit_expected_key(id(PUB1)).expect("authorized");
    let at = crate::native_discovery::ClockSample {
        wall_us: 1_000_000_000,
        monotonic_us: 10,
    };
    let four = crate::native_discovery::policy::RecordObservation::fixture(
        at.wall_us,
        at.wall_us,
        vec![1],
        vec![mapped, address, second, third],
    );
    owner
        .complete_query(
            id(PUB1),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                at,
                vec![four],
            ),
        )
        .expect("four raw addresses");
    assert_eq!(
        owner
            .addresses(id(PUB1), at)
            .expect("canonical owner snapshot"),
        &[address, second, third]
    );
    let five = crate::native_discovery::policy::RecordObservation::fixture(
        at.wall_us,
        at.wall_us,
        vec![2],
        vec![mapped, address, second, third, fourth],
    );
    assert_eq!(
        owner.complete_query(
            id(PUB1),
            crate::native_discovery::CompletedQuery::new(
                crate::native_discovery::QuerySource::Network,
                at,
                vec![five]
            )
        ),
        Err(crate::native_discovery::RecordError::InvalidObservation)
    );
    assert_eq!(
        owner
            .addresses(id(PUB1), at)
            .expect("previous snapshot retained"),
        &[address, second, third]
    );
}

fn independent_mutable_item(
    sequence: i64,
    salt: Option<&[u8]>,
    value: &[u8],
) -> n0_mainline::MutableItem {
    n0_mainline::MutableItem::new_signed_unchecked(
        PUB1,
        INDEPENDENT_NATIVE_RECORD[32..96]
            .try_into()
            .expect("external signature"),
        value,
        sequence,
        salt,
    )
}

#[test]
fn independent_native_record_survives_real_mutable_item_field_handoff() {
    let sequence = 1_700_000_000_000_000;
    let item = independent_mutable_item(sequence, None, &INDEPENDENT_NATIVE_RECORD[104..]);
    let decoded = decode_mutable_record(&item, id(PUB1)).expect("external native record fields");
    assert_eq!(
        decoded.signed_bytes.as_slice(),
        INDEPENDENT_NATIVE_RECORD.as_slice()
    );
    assert_eq!(decoded.signed_sequence, sequence);
    assert_eq!(decoded.addresses(), &[socket("127.0.0.1:9000")]);
    assert_eq!(
        decode_mutable_record(&item, id(PUB2)),
        Err(DecodeError::WrongKey)
    );
}

#[test]
fn mutable_item_field_handoff_rejects_salt_negative_sequence_and_oversize_before_decode() {
    let oversized = [0; 1001];
    let value = &INDEPENDENT_NATIVE_RECORD[104..];
    for (sequence, salt, value, expected) in [
        (
            1_700_000_000_000_000,
            Some(b"salt".as_slice()),
            value,
            DecodeError::InvalidPacket,
        ),
        (-1, None, value, DecodeError::InvalidSequence),
        (
            1_700_000_000_000_000,
            None,
            oversized.as_slice(),
            DecodeError::OverLimit,
        ),
    ] {
        let item = independent_mutable_item(sequence, salt, value);
        assert_eq!(decode_mutable_record(&item, id(PUB1)), Err(expected));
    }
}
