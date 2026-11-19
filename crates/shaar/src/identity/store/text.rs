//! The portable text form of a key (leaf KEY-1): base58 of one version byte, the 32-byte seed and
//! a four-byte checksum, so that a key can be copied to another device by hand. A typo or a
//! cut-off copy is refused before anything is written. Every buffer that holds the seed is
//! zeroized on drop; the encoder and decoder run on fixed buffers.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::IdentityError;

const VERSION: u8 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"shaar-key-checksum/1";
const CHECKSUM_LEN: usize = 4;
/// The version byte and the seed, which the checksum covers.
const BODY_LEN: usize = 1 + 32;
const PAYLOAD_LEN: usize = BODY_LEN + CHECKSUM_LEN;
/// Base58 of 37 bytes takes at most 51 characters; a longer text cannot be a key.
const MAX_TEXT: usize = 64;

fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::new()
        .chain_update(CHECKSUM_DOMAIN)
        .chain_update(body)
        .finalize();
    let mut sum = [0_u8; CHECKSUM_LEN];
    sum.copy_from_slice(&digest[..CHECKSUM_LEN]);
    sum
}

/// The text form of `seed`.
pub(in crate::identity) fn encode(seed: &[u8; 32]) -> Result<Zeroizing<String>, IdentityError> {
    let mut payload = Zeroizing::new([0_u8; PAYLOAD_LEN]);
    payload[0] = VERSION;
    payload[1..BODY_LEN].copy_from_slice(seed);
    let sum = checksum(&payload[..BODY_LEN]);
    payload[BODY_LEN..].copy_from_slice(&sum);
    let mut buffer = Zeroizing::new([0_u8; MAX_TEXT]);
    let length = bs58::encode(&payload[..])
        .onto(&mut buffer[..])
        .map_err(|_| IdentityError::InvalidKeyText)?;
    let text = std::str::from_utf8(&buffer[..length]).map_err(|_| IdentityError::InvalidKeyText)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// The seed that `text` carries; surrounding white space is ignored.
pub(in crate::identity) fn decode(text: &str) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_TEXT {
        return Err(IdentityError::InvalidKeyText);
    }
    let mut payload = Zeroizing::new([0_u8; PAYLOAD_LEN]);
    let length = bs58::decode(text)
        .onto(&mut payload[..])
        .map_err(|_| IdentityError::InvalidKeyText)?;
    if length != PAYLOAD_LEN || payload[0] != VERSION {
        return Err(IdentityError::InvalidKeyText);
    }
    if checksum(&payload[..BODY_LEN])[..] != payload[BODY_LEN..] {
        return Err(IdentityError::KeyChecksum);
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&payload[1..BODY_LEN]);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        7, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 255,
    ];

    /// A text whose payload is `bytes`, with the checksum of its body when `sum` is true.
    fn text_of(mut bytes: Vec<u8>, sum: bool) -> String {
        if sum {
            let body = bytes.clone();
            bytes.extend_from_slice(&checksum(&body));
        }
        bs58::encode(bytes).into_string()
    }

    #[test]
    fn a_seed_survives_the_text_form() {
        let text = encode(&SEED).unwrap();
        assert!((40..=MAX_TEXT).contains(&text.len()), "{}", text.len());
        assert!(
            text.chars()
                .all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c)),
            "only base58 characters"
        );
        assert_eq!(*decode(&text).unwrap(), SEED);
    }

    #[test]
    fn two_different_seeds_have_different_texts_and_the_same_seed_the_same_text() {
        let other = [9_u8; 32];
        assert_ne!(*encode(&SEED).unwrap(), *encode(&other).unwrap());
        assert_eq!(*encode(&SEED).unwrap(), *encode(&SEED).unwrap());
        assert_eq!(*decode(&encode(&[0_u8; 32]).unwrap()).unwrap(), [0_u8; 32]);
    }

    #[test]
    fn white_space_around_the_text_is_ignored() {
        let text = encode(&SEED).unwrap();
        assert_eq!(*decode(&format!("  {}\r\n", *text)).unwrap(), SEED);
    }

    #[test]
    fn a_changed_checksum_is_named_a_checksum_error() {
        let mut body = vec![VERSION];
        body.extend_from_slice(&SEED);
        let mut bytes = body.clone();
        bytes.extend_from_slice(&checksum(&body));
        for index in BODY_LEN..PAYLOAD_LEN {
            let mut broken = bytes.clone();
            broken[index] ^= 0x40;
            let text = bs58::encode(broken).into_string();
            assert!(
                matches!(decode(&text), Err(IdentityError::KeyChecksum)),
                "{index}"
            );
        }
        let mut broken_seed = bytes.clone();
        broken_seed[5] ^= 1;
        let text = bs58::encode(broken_seed).into_string();
        assert!(matches!(decode(&text), Err(IdentityError::KeyChecksum)));
    }

    #[test]
    fn a_wrong_version_or_length_is_not_a_key_text() {
        let mut body = vec![VERSION + 1];
        body.extend_from_slice(&SEED);
        assert!(matches!(
            decode(&text_of(body, true)),
            Err(IdentityError::InvalidKeyText)
        ));
        let mut short = vec![VERSION];
        short.extend_from_slice(&SEED[..31]);
        assert!(matches!(
            decode(&text_of(short, true)),
            Err(IdentityError::InvalidKeyText)
        ));
        let mut long = vec![VERSION];
        long.extend_from_slice(&SEED);
        long.push(0);
        assert!(matches!(
            decode(&text_of(long, true)),
            Err(IdentityError::InvalidKeyText)
        ));
    }

    #[test]
    fn text_that_is_not_base58_or_is_too_long_or_cut_is_refused() {
        let text = encode(&SEED).unwrap();
        let cut = text[..text.len() - 3].to_owned();
        let long = "z".repeat(MAX_TEXT + 1);
        let accents = "é".repeat(20);
        for bad in [
            "",
            "   ",
            "1",
            "0OIl",
            "not a key",
            "+/==",
            cut.as_str(),
            long.as_str(),
            accents.as_str(),
        ] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(
            decode(&"z".repeat(MAX_TEXT)),
            Err(IdentityError::InvalidKeyText)
        ));
    }

    #[test]
    fn an_error_does_not_carry_the_text() {
        let text = encode(&SEED).unwrap();
        let mut flipped = text.to_string();
        flipped.replace_range(10..11, if &text[10..11] == "2" { "3" } else { "2" });
        let error = decode(&flipped).unwrap_err().to_string();
        assert!(!error.contains(&flipped[..8]), "{error}");
    }
}
