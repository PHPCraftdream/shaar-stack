//! The encrypted key file (leaf KEY-2): the seed sealed under a password.
//!
//! Layout, 94 bytes: the magic `SHAARKEY` (8), the version (1), the Argon2id cost (memory in KiB
//! 4, passes 4, lanes 1; big-endian), a random salt (16), a random nonce (12), and the
//! ChaCha20-Poly1305 sealed seed (32 + 16). The first 46 bytes are the associated data, so a byte
//! changed anywhere is refused. A plain key file is exactly 32 bytes, so the two forms are told
//! apart by their length and the magic, never by guessing. The cost is read from the file, within
//! fixed bounds, so that a hostile file cannot make the loader allocate without limit.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::identity::IdentityError;

pub(in crate::identity) const MAGIC: &[u8; 8] = b"SHAARKEY";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SALT_AT: usize = 8 + 1 + 4 + 4 + 1;
const NONCE_AT: usize = SALT_AT + SALT_LEN;
const HEADER_LEN: usize = NONCE_AT + NONCE_LEN;
const TAG_LEN: usize = 16;
/// The length of an encrypted key file.
pub(in crate::identity) const SEALED_LEN: usize = HEADER_LEN + 32 + TAG_LEN;
/// The most memory a file may ask for, in KiB.
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_PASSES: u32 = 10;
const MAX_LANES: u8 = 4;
/// Argon2 needs at least eight KiB per lane.
const MIN_KIB_PER_LANE: u32 = 8;

/// The cost of a file: memory in KiB, passes, lanes. The bounds are 8 KiB per lane to 256 MiB,
/// 1 to 10 passes and 1 to 4 lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u8,
}

/// The cost of a new file: 64 MiB, three passes, one lane (the interactive default; `key encrypt` can change it within the bounds).
pub const DEFAULT_COST: Cost = Cost {
    memory_kib: 64 * 1024,
    passes: 3,
    lanes: 1,
};

impl Cost {
    /// Whether a file or a caller may ask for this cost.
    #[must_use]
    pub fn within_bounds(self) -> bool {
        (1..=MAX_LANES).contains(&self.lanes)
            && (1..=MAX_PASSES).contains(&self.passes)
            && self.memory_kib <= MAX_MEMORY_KIB
            && self.memory_kib >= MIN_KIB_PER_LANE * u32::from(self.lanes)
    }
}

/// Whether `bytes` are the start of an encrypted key file.
pub(in crate::identity) fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

fn derive(password: &str, salt: &[u8], cost: Cost) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let params = Params::new(
        cost.memory_kib,
        cost.passes,
        u32::from(cost.lanes),
        Some(32),
    )
    .map_err(|_| IdentityError::InvalidFormat)?;
    // The memory is supplied here, bounded by the cost bounds, and wiped on drop.
    let mut blocks = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password.as_bytes(), salt, &mut key[..], &mut blocks[..])
        .map_err(|_| IdentityError::InvalidFormat)?;
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> Result<ChaCha20Poly1305, IdentityError> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|_| IdentityError::InvalidFormat)
}

/// Seals `seed` under `password`. The salt and the nonce come from the OS-backed entropy of the
/// identity generator, as the salt of the sealed address does, so no further dependency is needed.
pub(in crate::identity) fn seal(
    seed: &[u8; 32],
    password: &str,
    cost: Cost,
) -> Result<Vec<u8>, IdentityError> {
    if !cost.within_bounds() {
        return Err(IdentityError::InvalidFormat);
    }
    let random = Zeroizing::new(iroh_base::SecretKey::generate().to_bytes());
    let mut header = Vec::with_capacity(SEALED_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&cost.memory_kib.to_be_bytes());
    header.extend_from_slice(&cost.passes.to_be_bytes());
    header.push(cost.lanes);
    header.extend_from_slice(&random[..SALT_LEN]);
    header.extend_from_slice(&random[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let key = derive(password, &header[SALT_AT..NONCE_AT], cost)?;
    let nonce = Nonce::clone_from_slice(&header[NONCE_AT..]);
    let sealed = cipher(&key)?
        .encrypt(
            &nonce,
            Payload {
                msg: seed,
                aad: &header,
            },
        )
        .map_err(|_| IdentityError::InvalidFormat)?;
    header.extend_from_slice(&sealed);
    Ok(header)
}

/// The seed in the encrypted key file `bytes`. A file that is not of the exact length and
/// version, or asks for a cost outside the bounds, is `InvalidFormat` and costs no derivation; a
/// wrong password and a damaged file are the same `WrongPassword`, with no hint which.
pub(in crate::identity) fn open(
    bytes: &[u8],
    password: &str,
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    if bytes.len() != SEALED_LEN || !is_sealed(bytes) || bytes[8] != VERSION {
        return Err(IdentityError::InvalidFormat);
    }
    let cost = Cost {
        memory_kib: u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]),
        passes: u32::from_be_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]),
        lanes: bytes[17],
    };
    if !cost.within_bounds() {
        return Err(IdentityError::InvalidFormat);
    }
    let (header, sealed) = bytes.split_at(HEADER_LEN);
    let salt = &header[SALT_AT..NONCE_AT];
    let nonce = Nonce::clone_from_slice(&header[NONCE_AT..]);
    let key = derive(password, salt, cost)?;
    let plain = cipher(&key)?
        .decrypt(
            &nonce,
            Payload {
                msg: sealed,
                aad: header,
            },
        )
        .map_err(|_| IdentityError::WrongPassword)?;
    let plain = Zeroizing::new(plain);
    let mut seed = Zeroizing::new([0_u8; 32]);
    if plain.len() != 32 {
        return Err(IdentityError::InvalidFormat);
    }
    seed.copy_from_slice(&plain);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap enough for many derivations in a test.
    const FAST: Cost = Cost {
        memory_kib: 8,
        passes: 1,
        lanes: 1,
    };
    const SEED: [u8; 32] = [42; 32];

    #[test]
    fn a_sealed_seed_opens_with_the_password_and_has_the_fixed_layout() {
        let bytes = seal(&SEED, "correct horse", FAST).unwrap();
        assert_eq!(bytes.len(), SEALED_LEN);
        assert_eq!(SEALED_LEN, 94);
        assert!(is_sealed(&bytes) && bytes[8] == 1);
        assert_eq!(&bytes[9..13], 8_u32.to_be_bytes());
        assert_eq!(&bytes[13..17], 1_u32.to_be_bytes());
        assert_eq!(bytes[17], 1);
        assert!(
            !bytes.windows(32).any(|window| window == SEED),
            "the seed is not in the file"
        );
        assert_eq!(*open(&bytes, "correct horse").unwrap(), SEED);
    }

    #[test]
    fn a_wrong_password_and_an_empty_one_do_not_open_the_file() {
        let bytes = seal(&SEED, "correct horse", FAST).unwrap();
        for password in ["", "correct hors", "Correct horse", "correct horse "] {
            assert!(
                matches!(open(&bytes, password), Err(IdentityError::WrongPassword)),
                "{password:?}"
            );
        }
    }

    #[test]
    fn two_sealings_of_one_seed_differ_in_salt_and_nonce() {
        let first = seal(&SEED, "pw", FAST).unwrap();
        let second = seal(&SEED, "pw", FAST).unwrap();
        assert_ne!(first[18..46], second[18..46]);
        assert_ne!(first[46..], second[46..]);
        assert_eq!(*open(&first, "pw").unwrap(), *open(&second, "pw").unwrap());
    }

    #[test]
    fn a_byte_changed_anywhere_is_refused() {
        let bytes = seal(&SEED, "pw", FAST).unwrap();
        for index in 0..bytes.len() {
            let mut broken = bytes.clone();
            broken[index] ^= 0x01;
            assert!(open(&broken, "pw").is_err(), "byte {index}");
        }
    }

    #[test]
    fn a_wrong_length_or_a_foreign_file_is_not_a_sealed_key() {
        let bytes = seal(&SEED, "pw", FAST).unwrap();
        let mut longer = bytes.clone();
        longer.push(0);
        for broken in [&bytes[..93], &longer[..], &[0_u8; 32][..], &[][..]] {
            assert!(matches!(
                open(broken, "pw"),
                Err(IdentityError::InvalidFormat)
            ));
        }
        assert!(!is_sealed(&[0_u8; 32]) && !is_sealed(b"SHAAR"));
    }

    #[test]
    fn a_cost_outside_the_bounds_is_refused_before_any_derivation() {
        let bytes = seal(&SEED, "pw", FAST).unwrap();
        let with = |memory: u32, passes: u32, lanes: u8| {
            let mut changed = bytes.clone();
            changed[9..13].copy_from_slice(&memory.to_be_bytes());
            changed[13..17].copy_from_slice(&passes.to_be_bytes());
            changed[17] = lanes;
            changed
        };
        let started = std::time::Instant::now();
        for hostile in [
            with(u32::MAX, 1, 1),
            with(MAX_MEMORY_KIB + 1, 1, 1),
            with(8, MAX_PASSES + 1, 1),
            with(8, 0, 1),
            with(8, 1, 0),
            with(8, 1, MAX_LANES + 1),
            with(15, 1, 2),
            with(0, 1, 1),
        ] {
            assert!(matches!(
                open(&hostile, "pw"),
                Err(IdentityError::InvalidFormat)
            ));
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(matches!(
            seal(
                &SEED,
                "pw",
                Cost {
                    memory_kib: MAX_MEMORY_KIB + 1,
                    ..FAST
                }
            ),
            Err(IdentityError::InvalidFormat)
        ));
        assert!(
            Cost {
                memory_kib: MAX_MEMORY_KIB,
                passes: MAX_PASSES,
                lanes: MAX_LANES
            }
            .within_bounds()
        );
    }

    #[test]
    fn the_default_cost_is_inside_the_bounds_and_seals_and_opens() {
        assert!(DEFAULT_COST.within_bounds());
        let bytes = seal(&SEED, "pw", DEFAULT_COST).unwrap();
        assert_eq!(&bytes[9..13], (64_u32 * 1024).to_be_bytes());
        assert_eq!(*open(&bytes, "pw").unwrap(), SEED);
    }

    #[test]
    fn a_password_that_is_not_ascii_is_taken_byte_for_byte() {
        let bytes = seal(&SEED, "пароль-密码", FAST).unwrap();
        assert_eq!(*open(&bytes, "пароль-密码").unwrap(), SEED);
        assert!(open(&bytes, "пароль").is_err());
    }
}
