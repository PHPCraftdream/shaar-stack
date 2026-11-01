// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{PUB1, PUB2, id, identity, ip, socket};
use crate::native_discovery::codec::parse_dns_profile;
use crate::native_discovery::{DecodeError, decode_record};
use iroh_dns::{
    endpoint_info::{EndpointData, EndpointInfo},
    pkarr::SignedPacket,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
