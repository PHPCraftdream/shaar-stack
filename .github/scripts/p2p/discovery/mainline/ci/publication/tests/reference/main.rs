// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use pkarr::{Keypair, SignedPacket};
use std::io::Write;

// Public RFC 8032 test 1 material, never a production identity.
const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const TIMESTAMP: u64 = 1_700_000_000_000_000;

fn signed() -> SignedPacket {
    let key = Keypair::from_secret_key(&SEED);
    SignedPacket::builder()
        .txt(
            "_iroh".try_into().expect("fixed owner name"),
            "addr=127.0.0.1:9000".try_into().expect("fixed TXT"),
            30,
        )
        .timestamp(TIMESTAMP.into())
        .sign(&key)
        .expect("bounded independent signed record")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments.next().ok_or("one output path is required")?;
    if arguments.next().is_some() {
        return Err("unexpected generator argument".into());
    }
    let packet = signed();
    let bytes = packet.as_bytes();
    assert!((105..=1104).contains(&bytes.len()));
    assert_eq!(&bytes[..32], &PUBLIC_KEY);
    assert_eq!(&bytes[96..104], &TIMESTAMP.to_be_bytes());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_reference_is_deterministic_and_verifies() {
        let first = signed();
        assert_eq!(first.as_bytes(), signed().as_bytes());
        assert!(SignedPacket::from_bytes(first.as_bytes()).is_ok());
        assert_eq!(&first.as_bytes()[..32], &PUBLIC_KEY);
        assert_eq!(&first.as_bytes()[96..104], &TIMESTAMP.to_be_bytes());
        assert!((105..=1104).contains(&first.as_bytes().len()));
    }

    #[test]
    fn key_signature_timestamp_and_dns_tampering_are_rejected() {
        let packet = signed();
        for index in [0, 32, 96, 104, packet.as_bytes().len() - 1] {
            let mut altered = packet.as_bytes().to_vec();
            altered[index] ^= 1;
            assert!(SignedPacket::from_bytes(&altered.into()).is_err());
        }
    }

    #[test]
    fn empty_and_truncated_envelopes_are_rejected() {
        let packet = signed();
        for length in [0, 31, 32, 95, 96, 103, 104, packet.as_bytes().len() - 1] {
            let truncated = packet.as_bytes()[..length].to_vec();
            assert!(SignedPacket::from_bytes(&truncated.into()).is_err());
        }
    }
}
