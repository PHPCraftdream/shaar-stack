// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::{DecodeMessageError, bytes_to_signed_peer};

#[test]
fn signed_peer_rejects_invalid_record_lengths() {
    for input in [
        &[][..],
        &[0_u8; 103][..],
        &[0_u8; 105][..],
        &[0_u8; 208][..],
    ] {
        assert!(matches!(
            bytes_to_signed_peer(input),
            Err(DecodeMessageError::InvalidSignedPeersEncodingLength)
        ));
    }
}

#[test]
fn signed_peer_accepts_exactly_one_record() {
    let decoded = bytes_to_signed_peer([7_u8; 104]).expect("exact signed-peer record");
    assert_eq!(decoded.0, [7_u8; 32]);
    assert_eq!(decoded.1, u64::from_be_bytes([7_u8; 8]));
    assert_eq!(decoded.2, [7_u8; 64]);
}
