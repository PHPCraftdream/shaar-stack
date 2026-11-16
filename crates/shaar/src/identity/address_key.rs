// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! L3b: the published address list sealed under a key the client must know.
//!
//! The address key is a 32-byte secret kept in a file of the identity-key format (the same
//! open-handle permission checks apply). A Server that publishes `encrypted` seals the address
//! list under it; a Client that holds the same key opens it. Nobody else learns the addresses.
//!
//! Sealing: the AEAD key is HKDF-SHA256 of the secret with the Server key and a fresh random
//! salt, so every publication has a key of its own and a fixed nonce is safe. The associated
//! data binds the record to its Server key and signed timestamp. The sealed list travels in the
//! `user-data` attribute of the record (at most 245 characters), which holds exactly one key.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::error::IdentityError;
use super::store::load_blocking;

/// Bytes of an address key.
const KEY_BYTES: usize = 32;
/// Marks a sealed `user-data` value; the digit is the format version.
pub(crate) const MARK: &str = "shaar1.";
/// Longest `user-data` value the record format allows.
const MAX_USER_DATA: usize = 245;
/// Most addresses a record carries.
const MAX_ADDRESSES: usize = 4;
const SALT_BYTES: usize = 16;
const TAG_BYTES: usize = 16;
/// Salt, tag, the count byte and one IPv4 entry: the smallest valid blob.
const MIN_BLOB: usize = SALT_BYTES + TAG_BYTES + 1 + 7;
const PURPOSE: &[u8] = b"shaar address seal v1";
const AAD_LABEL: &[u8] = b"shaar-addr-seal-v1";
const AAD_BYTES: usize = AAD_LABEL.len() + 32 + 8;

/// Why a sealed value was not produced or not opened. Never carries key or address material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealError {
    /// Not a sealed value, or malformed encoding or length.
    Format,
    /// Wrong key, or the value or its context (Server key, timestamp) was altered.
    Authentication,
    /// No address, too many, or a malformed address list.
    Addresses,
    /// The sealed value would not fit the record.
    TooLarge,
}

/// The secret a Client must hold to read an encrypted record. `Debug` is redacted and the bytes
/// are erased on drop.
#[derive(Clone)]
pub(crate) struct AddressKey(Zeroizing<[u8; KEY_BYTES]>);

impl fmt::Debug for AddressKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AddressKey(..)")
    }
}

impl AddressKey {
    /// Loads a key file: exactly 32 bytes, owner-only, checked on the opened handle.
    /// Blocking: call it from `spawn_blocking`.
    pub(crate) fn load_blocking(path: &Path) -> Result<Self, IdentityError> {
        Ok(Self(load_blocking(path)?))
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Whether a `user-data` value is a sealed address list.
pub(crate) fn is_sealed(value: &str) -> bool {
    value.starts_with(MARK)
}

/// Seals `addresses` for the record of `server` signed at `timestamp_us`.
pub(crate) fn seal_addresses(
    key: &AddressKey,
    server: &[u8; 32],
    timestamp_us: u64,
    addresses: &[SocketAddr],
) -> Result<String, SealError> {
    let count = u8::try_from(addresses.len()).map_err(|_| SealError::Addresses)?;
    if count == 0 || usize::from(count) > MAX_ADDRESSES {
        return Err(SealError::Addresses);
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(1 + addresses.len() * 19));
    plain.push(count);
    for address in addresses {
        match address.ip() {
            IpAddr::V4(ip) => {
                plain.push(4);
                plain.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                plain.push(6);
                plain.extend_from_slice(&ip.octets());
            }
        }
        plain.extend_from_slice(&address.port().to_be_bytes());
    }
    let salt = random_salt();
    let sealed = cipher(key, server, &salt)?
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &plain,
                aad: &aad(server, timestamp_us),
            },
        )
        .map_err(|_| SealError::Format)?;
    let mut blob = Vec::with_capacity(SALT_BYTES + sealed.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&sealed);
    let value = format!("{MARK}{}", base64url_encode(&blob));
    if value.len() > MAX_USER_DATA {
        return Err(SealError::TooLarge);
    }
    Ok(value)
}

/// Opens a sealed value of the record of `server` signed at `timestamp_us`.
pub(crate) fn open_addresses(
    key: &AddressKey,
    server: &[u8; 32],
    timestamp_us: u64,
    value: &str,
) -> Result<Vec<SocketAddr>, SealError> {
    let encoded = value.strip_prefix(MARK).ok_or(SealError::Format)?;
    let blob = base64url_decode(encoded).ok_or(SealError::Format)?;
    if blob.len() < MIN_BLOB {
        return Err(SealError::Format);
    }
    let (salt, sealed) = blob.split_at(SALT_BYTES);
    let plain = Zeroizing::new(
        cipher(key, server, salt)?
            .decrypt(
                &Nonce::from([0u8; 12]),
                Payload {
                    msg: sealed,
                    aad: &aad(server, timestamp_us),
                },
            )
            .map_err(|_| SealError::Authentication)?,
    );
    parse_addresses(&plain)
}

/// The salt is not secret; it comes from the same OS-backed entropy as identity generation, so
/// no further dependency is needed.
fn random_salt() -> [u8; SALT_BYTES] {
    let bytes = Zeroizing::new(iroh_base::SecretKey::generate().to_bytes());
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&bytes[..SALT_BYTES]);
    salt
}

fn cipher(key: &AddressKey, server: &[u8; 32], salt: &[u8]) -> Result<ChaCha20Poly1305, SealError> {
    let mut hkdf_salt = [0u8; 32 + SALT_BYTES];
    hkdf_salt[..32].copy_from_slice(server);
    hkdf_salt[32..32 + salt.len()].copy_from_slice(salt);
    let hkdf = Hkdf::<Sha256>::new(Some(&hkdf_salt), &key.0[..]);
    let mut derived = Zeroizing::new([0u8; 32]);
    hkdf.expand(PURPOSE, &mut derived[..])
        .map_err(|_| SealError::Format)?;
    ChaCha20Poly1305::new_from_slice(&derived[..]).map_err(|_| SealError::Format)
}

fn aad(server: &[u8; 32], timestamp_us: u64) -> [u8; AAD_BYTES] {
    let mut bytes = [0u8; AAD_BYTES];
    bytes[..AAD_LABEL.len()].copy_from_slice(AAD_LABEL);
    bytes[AAD_LABEL.len()..AAD_LABEL.len() + 32].copy_from_slice(server);
    bytes[AAD_LABEL.len() + 32..].copy_from_slice(&timestamp_us.to_be_bytes());
    bytes
}

fn take(bytes: &[u8], length: usize) -> Option<(&[u8], &[u8])> {
    bytes.split_at_checked(length)
}

/// Strict parse: the entries must consume the plaintext exactly.
fn parse_addresses(plain: &[u8]) -> Result<Vec<SocketAddr>, SealError> {
    let (&count, mut rest) = plain.split_first().ok_or(SealError::Addresses)?;
    if count == 0 || usize::from(count) > MAX_ADDRESSES {
        return Err(SealError::Addresses);
    }
    let mut addresses = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (&family, tail) = rest.split_first().ok_or(SealError::Addresses)?;
        let (ip, tail) = match family {
            4 => {
                let (octets, tail) = take(tail, 4).ok_or(SealError::Addresses)?;
                let octets: [u8; 4] = octets.try_into().map_err(|_| SealError::Addresses)?;
                (IpAddr::V4(Ipv4Addr::from(octets)), tail)
            }
            6 => {
                let (octets, tail) = take(tail, 16).ok_or(SealError::Addresses)?;
                let octets: [u8; 16] = octets.try_into().map_err(|_| SealError::Addresses)?;
                (IpAddr::V6(Ipv6Addr::from(octets)), tail)
            }
            _ => return Err(SealError::Addresses),
        };
        let (port, tail) = take(tail, 2).ok_or(SealError::Addresses)?;
        let port = u16::from_be_bytes(port.try_into().map_err(|_| SealError::Addresses)?);
        addresses.push(SocketAddr::new(ip, port));
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(SealError::Addresses);
    }
    Ok(addresses)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 base64url without padding.
fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let sextets = [
            first >> 2,
            ((first & 0b11) << 4) | (second >> 4),
            ((second & 0b1111) << 2) | (third >> 6),
            third & 0b11_1111,
        ];
        for sextet in &sextets[..chunk.len() + 1] {
            out.push(char::from(ALPHABET[usize::from(*sextet)]));
        }
    }
    out
}

fn sextet(character: u8) -> Option<u8> {
    match character {
        b'A'..=b'Z' => Some(character - b'A'),
        b'a'..=b'z' => Some(character - b'a' + 26),
        b'0'..=b'9' => Some(character - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Strict decode: only the alphabet, a possible length, and zero trailing bits.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut values = [0u8; 4];
        for (slot, character) in values.iter_mut().zip(chunk) {
            *slot = sextet(*character)?;
        }
        out.push((values[0] << 2) | (values[1] >> 4));
        match chunk.len() {
            2 => {
                if values[1] & 0b1111 != 0 {
                    return None;
                }
            }
            3 => {
                out.push((values[1] << 4) | (values[2] >> 2));
                if values[2] & 0b11 != 0 {
                    return None;
                }
            }
            _ => {
                out.push((values[1] << 4) | (values[2] >> 2));
                out.push((values[2] << 6) | values[3]);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: [u8; 32] = [7; 32];
    const OTHER_SERVER: [u8; 32] = [8; 32];
    const STAMP: u64 = 1_700_000_000_000_000;

    fn key(fill: u8) -> AddressKey {
        AddressKey::from_bytes([fill; KEY_BYTES])
    }

    fn mixed() -> Vec<SocketAddr> {
        vec![
            "203.0.113.7:4433".parse().unwrap(),
            "[2001:db8::7]:4433".parse().unwrap(),
            "10.0.0.2:40000".parse().unwrap(),
            "[2001:db8::8]:1".parse().unwrap(),
        ]
    }

    #[test]
    fn a_holder_of_the_key_opens_the_exact_list_in_order() {
        let list = mixed();
        let value = seal_addresses(&key(1), &SERVER, STAMP, &list).unwrap();
        assert!(is_sealed(&value));
        assert!(value.len() <= MAX_USER_DATA, "{} characters", value.len());
        assert_eq!(
            open_addresses(&key(1), &SERVER, STAMP, &value).unwrap(),
            list
        );
        let one: Vec<SocketAddr> = vec!["198.51.100.9:9".parse().unwrap()];
        let value = seal_addresses(&key(1), &SERVER, STAMP, &one).unwrap();
        assert_eq!(
            open_addresses(&key(1), &SERVER, STAMP, &value).unwrap(),
            one
        );
    }

    #[test]
    fn four_ipv6_addresses_still_fit_the_user_data_limit() {
        let list: Vec<SocketAddr> = (1..=4)
            .map(|index| {
                format!("[2001:db8::{index:x}]:{}", 40000 + index)
                    .parse()
                    .unwrap()
            })
            .collect();
        let value = seal_addresses(&key(1), &SERVER, STAMP, &list).unwrap();
        assert!(value.len() <= MAX_USER_DATA, "{} characters", value.len());
        assert_eq!(
            open_addresses(&key(1), &SERVER, STAMP, &value).unwrap(),
            list
        );
    }

    #[test]
    fn every_publication_is_fresh_but_all_of_them_open() {
        let list = mixed();
        let first = seal_addresses(&key(1), &SERVER, STAMP, &list).unwrap();
        let second = seal_addresses(&key(1), &SERVER, STAMP, &list).unwrap();
        assert_ne!(first, second, "the salt is random per publication");
        for value in [first, second] {
            assert_eq!(
                open_addresses(&key(1), &SERVER, STAMP, &value).unwrap(),
                list
            );
        }
    }

    #[test]
    fn a_wrong_key_server_or_timestamp_does_not_open() {
        let value = seal_addresses(&key(1), &SERVER, STAMP, &mixed()).unwrap();
        for (label, result) in [
            ("key", open_addresses(&key(2), &SERVER, STAMP, &value)),
            (
                "server",
                open_addresses(&key(1), &OTHER_SERVER, STAMP, &value),
            ),
            (
                "timestamp",
                open_addresses(&key(1), &SERVER, STAMP + 1, &value),
            ),
        ] {
            assert_eq!(result, Err(SealError::Authentication), "{label}");
        }
    }

    #[test]
    fn a_flipped_character_is_rejected_at_every_position() {
        let value = seal_addresses(&key(1), &SERVER, STAMP, &mixed()).unwrap();
        for index in MARK.len()..value.len() {
            let mut bytes = value.clone().into_bytes();
            bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
            let altered = String::from_utf8(bytes).unwrap();
            assert!(
                open_addresses(&key(1), &SERVER, STAMP, &altered).is_err(),
                "position {index}"
            );
        }
    }

    #[test]
    fn malformed_values_are_format_errors() {
        let value = seal_addresses(&key(1), &SERVER, STAMP, &mixed()).unwrap();
        let encoded = &value[MARK.len()..];
        let cases = [
            ("no mark", encoded.to_owned()),
            ("other mark", format!("shaar2.{encoded}")),
            ("empty body", MARK.to_owned()),
            ("too short", format!("{MARK}AAAA")),
            ("padding", format!("{value}=")),
            (
                "outside alphabet",
                format!("{MARK}{}+", &encoded[..encoded.len() - 1]),
            ),
            ("impossible length", format!("{value}A")),
            ("truncated", value[..value.len() - 4].to_owned()),
        ];
        for (label, text) in cases {
            let result = open_addresses(&key(1), &SERVER, STAMP, &text);
            assert!(result.is_err(), "{label}: {result:?}");
        }
        assert_eq!(
            open_addresses(&key(1), &SERVER, STAMP, "plain"),
            Err(SealError::Format)
        );
    }

    #[test]
    fn the_address_count_is_bounded_on_both_sides() {
        let five: Vec<SocketAddr> = (1..=5)
            .map(|index| format!("198.51.100.{index}:9").parse().unwrap())
            .collect();
        assert_eq!(
            seal_addresses(&key(1), &SERVER, STAMP, &five),
            Err(SealError::Addresses)
        );
        assert_eq!(
            seal_addresses(&key(1), &SERVER, STAMP, &[]),
            Err(SealError::Addresses)
        );
        // Entries that do not consume the plaintext exactly are rejected after authentication.
        assert_eq!(parse_addresses(&[]), Err(SealError::Addresses));
        assert_eq!(parse_addresses(&[0]), Err(SealError::Addresses));
        assert_eq!(parse_addresses(&[5]), Err(SealError::Addresses));
        assert_eq!(
            parse_addresses(&[1, 4, 1, 2, 3, 4, 0, 9, 0]),
            Err(SealError::Addresses),
            "trailing byte"
        );
        assert_eq!(
            parse_addresses(&[1, 4, 1, 2, 3, 4, 0]),
            Err(SealError::Addresses),
            "short port"
        );
        assert_eq!(
            parse_addresses(&[1, 5, 1, 2, 3, 4, 0, 9]),
            Err(SealError::Addresses),
            "unknown family"
        );
        assert_eq!(
            parse_addresses(&[1, 4, 1, 2, 3, 4, 0, 9]).unwrap(),
            vec!["1.2.3.4:9".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn base64url_matches_the_rfc_vectors_and_round_trips() {
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
            (&[0xff, 0xff, 0xff], "____"),
        ] {
            assert_eq!(base64url_encode(plain), encoded);
            assert_eq!(base64url_decode(encoded).as_deref(), Some(plain));
        }
        for length in 0..=64u8 {
            let plain: Vec<u8> = (0..length).map(|byte| byte.wrapping_mul(37)).collect();
            assert_eq!(
                base64url_decode(&base64url_encode(&plain)).as_deref(),
                Some(&plain[..])
            );
        }
        // Non-canonical trailing bits and lengths that no encoder produces are refused.
        assert_eq!(base64url_decode("Zh"), None);
        assert_eq!(base64url_decode("Zm9"), None, "\"fo\" encodes to Zm8");
        assert_eq!(base64url_decode("Zm_"), None);
        assert_eq!(base64url_decode("A"), None);
        assert_eq!(base64url_decode("Zg=="), None);
    }

    #[test]
    fn the_key_never_shows_in_debug_output() {
        let text = format!("{:?}", key(0xAB));
        assert_eq!(text, "AddressKey(..)");
    }

    #[test]
    fn a_key_file_of_the_identity_format_loads_and_a_malformed_one_does_not() {
        let directory = std::env::temp_dir().join(format!(
            "shaar-address-key-{}-{}",
            std::process::id(),
            iroh_base::SecretKey::generate().public()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("address.key");
        super::super::store::create_new_blocking(&path, &[0x5A; 32]).unwrap();
        let loaded = AddressKey::load_blocking(&path).unwrap();
        let value = seal_addresses(&loaded, &SERVER, STAMP, &mixed()).unwrap();
        assert_eq!(
            open_addresses(&key(0x5A), &SERVER, STAMP, &value).unwrap(),
            mixed()
        );
        assert!(AddressKey::load_blocking(&directory.join("missing.key")).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
