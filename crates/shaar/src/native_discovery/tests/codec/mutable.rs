// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{DecodeError, INDEPENDENT_NATIVE_RECORD, PUB1, PUB2, id, socket};
use crate::native_discovery::codec::decode_mutable_record;
use std::net::Ipv4Addr;

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
    assert_eq!(
        decoded.addresses(),
        &[socket(Ipv4Addr::LOCALHOST.into(), 9000)]
    );
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
