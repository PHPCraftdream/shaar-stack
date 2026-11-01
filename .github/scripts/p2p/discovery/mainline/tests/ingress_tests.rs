// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::Message;

fn ping(transaction_id: &[u8; 2]) -> Vec<u8> {
    let mut bytes = b"d1:ad2:id20:".to_vec();
    bytes.extend_from_slice(&[7; 20]);
    bytes.extend_from_slice(b"e1:q4:ping1:t2:");
    bytes.extend_from_slice(transaction_id);
    bytes.extend_from_slice(b"1:y1:qe");
    bytes
}

fn add_unknown_value(mut bytes: Vec<u8>, value: &[u8]) -> Vec<u8> {
    let end = bytes.pop().expect("ping ends in dictionary terminator");
    assert_eq!(end, b'e');
    bytes.extend_from_slice(b"1:z");
    bytes.extend_from_slice(value);
    bytes.push(end);
    bytes
}

fn complete_ping(length: usize) -> Vec<u8> {
    let base = ping(b"aa");
    for payload_len in 0..length {
        let mut value = format!("{payload_len}:").into_bytes();
        value.resize(value.len() + payload_len, b'x');
        let candidate = add_unknown_value(base.clone(), &value);
        if candidate.len() == length {
            return candidate;
        }
    }
    panic!("a bencoded unknown string can fill the requested document length");
}

fn exact_ping() -> Vec<u8> {
    complete_ping(2048)
}

#[test]
fn actual_message_decoder_accepts_valid_ping_and_exact_datagram_limit() {
    let ordinary = ping(b"aa");
    let parsed = Message::from_bytes(&ordinary).expect("valid ping at decoder boundary");
    assert_eq!(parsed.transaction_id, u16::from_be_bytes(*b"aa") as u32);

    let exact = exact_ping();
    assert_eq!(exact.len(), 2048);
    let parsed = Message::from_bytes(&exact).expect("exactly 2048 bytes is accepted");
    assert_eq!(parsed.transaction_id, u16::from_be_bytes(*b"aa") as u32);
}

#[test]
fn actual_message_decoder_rejects_complete_oversize_documents() {
    for length in [2049, 4096] {
        let wire = complete_ping(length);
        assert_eq!(wire.len(), length);
        super::internal::DHTMessage::from_bytes(&wire)
            .expect("complete otherwise-valid document parses semantically");
        assert!(Message::from_bytes(&wire).is_err());
    }
}

#[test]
fn actual_message_decoder_rejects_oversize_and_trailing_datagrams() {
    let exact = exact_ping();
    for bytes in [
        {
            let mut bytes = exact.clone();
            bytes.push(b'x');
            bytes
        },
        {
            let mut bytes = exact.clone();
            let additional = 60_000 - bytes.len();
            bytes.extend(std::iter::repeat_n(b'x', additional));
            bytes
        },
        {
            let mut bytes = ping(b"aa");
            bytes.extend_from_slice(b"x");
            bytes
        },
        {
            let mut bytes = ping(b"aa");
            bytes.extend_from_slice(b"de");
            bytes
        },
        {
            let mut bytes = ping(b"aa");
            bytes.extend_from_slice(b"0:");
            bytes
        },
    ] {
        assert!(
            Message::from_bytes(&bytes).is_err(),
            "accepted {} bytes",
            bytes.len()
        );
    }
}

#[test]
fn actual_message_decoder_checks_bencode_integer_lengths_and_nesting() {
    for value in [
        &b"i-e"[..],
        &b"iXe"[..],
        &b"i9223372036854775808e"[..],
        &b"9999:x"[..],
        &b"184467440737095516160:"[..],
        &b"lllleeee"[..],
    ] {
        let bytes = add_unknown_value(ping(b"aa"), value);
        assert!(
            Message::from_bytes(&bytes).is_err(),
            "accepted malformed value {value:?}"
        );
    }

    // Arbitrary ID bytes containing bencode token characters are string payload,
    // not nested containers or integers.
    let mut payload = ping(b"aa");
    let id_start = b"d1:ad2:id20:".len();
    let bytes: [u8; 20] = [
        b'd', b'e', b'i', b'd', b'e', b'i', b'd', b'e', b'i', b'd', b'e', b'i', b'd', b'e', b'i',
        b'd', b'e', b'i', b'd', b'e',
    ];
    payload[id_start..id_start + 20].copy_from_slice(&bytes);
    assert!(Message::from_bytes(&payload).is_ok());

    for key in [b'd', b'e', b'l', b'i'] {
        let mut extended = ping(b"aa");
        assert_eq!(extended.pop(), Some(b'e'));
        extended.extend_from_slice(&[b'1', b':', key]);
        extended.extend_from_slice(b"1:x");
        extended.push(b'e');
        assert!(
            Message::from_bytes(&extended).is_ok(),
            "unknown key {key:?} should be treated as a string"
        );
    }
}

#[test]
fn actual_message_decoder_accepts_bounded_get_peers_nested_values() {
    let mut bytes = b"d1:rd2:id20:".to_vec();
    bytes.extend_from_slice(&[7; 20]);
    bytes.extend_from_slice(b"5:token1:t6:valuesl6:");
    bytes.extend_from_slice(&[127, 0, 0, 1, 0, 1]);
    bytes.extend_from_slice(b"ee1:t2:aa1:y1:re");
    let parsed = Message::from_bytes(&bytes).expect("valid bounded get_peers response");
    assert_eq!(parsed.transaction_id, u16::from_be_bytes(*b"aa") as u32);
}

#[test]
fn actual_message_decoder_accepts_error_response_tuple_lists_at_depth_two() {
    let wire = b"d1:eli201e5:errore1:t2:aa1:y1:ee";
    super::internal::DHTMessage::from_bytes(wire).expect("upstream accepts the error tuple");
    let parsed = Message::from_bytes(wire).expect("valid error response");
    assert_eq!(parsed.transaction_id, u16::from_be_bytes(*b"aa") as u32);
    assert!(
        matches!(parsed.message_type, crate::common::MessageType::Error(ref error)
        if error.code == 201 && error.description == "error")
    );
    assert!(Message::from_bytes(b"d1:eli201e4:errore1:t2:aa1:y1:ee").is_err());
}

#[test]
fn actual_message_decoder_rejects_deep_unknown_values_and_truncated_strings() {
    let deeply_nested = add_unknown_value(ping(b"aa"), b"llllleeeee");
    assert!(Message::from_bytes(&deeply_nested).is_err());

    // The declared string length exceeds the bounded input document.
    assert!(Message::from_bytes(b"d1:z99999:x e").is_err());
}

#[test]
fn bounded_bencode_api_preserves_legacy_grammar_and_enforces_limits() {
    use serde_bencode::{de, value::Value};

    let nested = b"llleee";
    assert!(de::from_bytes::<Value>(nested).is_ok());
    assert!(de::from_bytes_bounded::<Value>(nested, 6, 3).is_ok());
    assert!(de::from_bytes_bounded::<Value>(nested, 6, 2).is_err());

    assert_eq!(
        de::from_bytes_bounded::<i64>(b"i1e", 3, 0).expect("bounded integer"),
        1
    );
    assert!(de::from_bytes_bounded::<i64>(b"i1ex", 4, 0).is_err());
    // Keep legacy trailing-input behavior unchanged.
    assert_eq!(de::from_bytes::<i64>(b"i1ex").expect("legacy integer"), 1);

    // Preserve the upstream parser's accepted integer spelling.
    for wire in [b"i+1e".as_slice(), b"i01e"] {
        assert_eq!(
            de::from_bytes::<i64>(wire).expect("legacy integer spelling"),
            1
        );
        assert_eq!(
            de::from_bytes_bounded::<i64>(wire, wire.len(), 0).expect("bounded integer spelling"),
            1
        );
    }
    assert!(de::from_bytes_bounded::<Value>(b"99999:x", 7, 0).is_err());
}

#[test]
fn mutable_value_limit_precedes_signature_verification() {
    use crate::common::{MutableError, MutableItem};
    use ed25519_dalek::SigningKey;

    let signer = SigningKey::from_bytes(&[3; 32]);
    let item = MutableItem::new(&signer, &vec![5; 1000], 1, None);
    let accepted = MutableItem::from_dht_message(
        *item.target(),
        item.key(),
        item.value().to_vec().into_boxed_slice(),
        item.seq(),
        item.signature(),
        None,
    );
    assert!(
        accepted.is_ok(),
        "valid 1000-byte mutable item should verify"
    );

    let oversized = MutableItem::from_dht_message(
        *item.target(),
        &[0; 31],
        vec![5; 1001].into_boxed_slice(),
        item.seq(),
        &[0; 64],
        None,
    );
    assert!(matches!(oversized, Err(MutableError::ValueTooLarge)));

    let oversized_item = MutableItem::new(&signer, &vec![5; 1001], 1, None);
    let oversized_with_valid_signature = MutableItem::from_dht_message(
        *oversized_item.target(),
        oversized_item.key(),
        oversized_item.value().to_vec().into_boxed_slice(),
        oversized_item.seq(),
        oversized_item.signature(),
        None,
    );
    assert!(matches!(
        oversized_with_valid_signature,
        Err(MutableError::ValueTooLarge)
    ));

    let mut oversized_invalid_signature = *oversized_item.signature();
    oversized_invalid_signature[0] ^= 1;
    let oversized_with_invalid_signature = MutableItem::from_dht_message(
        *oversized_item.target(),
        oversized_item.key(),
        oversized_item.value().to_vec().into_boxed_slice(),
        oversized_item.seq(),
        &oversized_invalid_signature,
        None,
    );
    assert!(matches!(
        oversized_with_invalid_signature,
        Err(MutableError::ValueTooLarge)
    ));

    let mut invalid_signature = *item.signature();
    invalid_signature[0] ^= 1;
    assert!(matches!(
        MutableItem::from_dht_message(
            *item.target(),
            item.key(),
            item.value().to_vec().into_boxed_slice(),
            item.seq(),
            &invalid_signature,
            None,
        ),
        Err(MutableError::InvalidMutableSignature)
    ));
}

#[test]
fn actual_message_decoder_bounds_mutable_get_and_put_wire_values() {
    use crate::common::{
        GetMutableResponseArguments, Id, MessageType, MutableItem, PutMutableRequestArguments,
        PutRequest, RequestSpecific, RequestTypeSpecific, ResponseSpecific,
    };
    use ed25519_dalek::SigningKey;

    let signer = SigningKey::from_bytes(&[9; 32]);
    for (length, should_parse) in [(1000, true), (1001, false)] {
        let item = MutableItem::new(&signer, &vec![5; length], 1, None);
        let get = Message {
            transaction_id: 1,
            version: None,
            requester_ip: None,
            read_only: false,
            message_type: MessageType::Response(ResponseSpecific::GetMutable(
                GetMutableResponseArguments {
                    responder_id: Id::from_bytes(&[7; 20]).expect("20-byte ID"),
                    token: vec![1].into_boxed_slice(),
                    nodes: None,
                    v: vec![5; length].into_boxed_slice(),
                    k: *item.key(),
                    seq: item.seq(),
                    sig: *item.signature(),
                },
            )),
        };
        let get_wire = get.to_bytes().expect("encode mutable GET response");
        let parsed = Message::from_bytes(&get_wire);
        if should_parse {
            assert!(matches!(
                parsed.expect("1000-byte mutable GET response").message_type,
                MessageType::Response(ResponseSpecific::GetMutable(_))
            ));
        } else {
            assert!(matches!(
                parsed,
                Err(super::DecodeMessageError::ValueTooLarge)
            ));
        }

        let put = Message {
            transaction_id: 1,
            version: None,
            requester_ip: None,
            read_only: false,
            message_type: MessageType::Request(RequestSpecific {
                requester_id: Id::from_bytes(&[7; 20]).expect("20-byte ID"),
                request_type: RequestTypeSpecific::Put(PutRequest {
                    token: vec![1].into_boxed_slice(),
                    put_request_type: super::PutRequestSpecific::PutMutable(
                        PutMutableRequestArguments {
                            target: *item.target(),
                            v: vec![5; length].into_boxed_slice(),
                            k: *item.key(),
                            seq: item.seq(),
                            sig: *item.signature(),
                            salt: None,
                            cas: None,
                        },
                    ),
                }),
            }),
        };
        let put_wire = put.to_bytes().expect("encode mutable PUT request");
        let parsed = Message::from_bytes(&put_wire);
        if should_parse {
            assert!(matches!(
                parsed.expect("1000-byte mutable PUT request").message_type,
                MessageType::Request(RequestSpecific {
                    request_type: RequestTypeSpecific::Put(PutRequest {
                        put_request_type: super::PutRequestSpecific::PutMutable(_),
                        ..
                    }),
                    ..
                })
            ));
        } else {
            assert!(matches!(
                parsed,
                Err(super::DecodeMessageError::ValueTooLarge)
            ));
        }
    }
}
