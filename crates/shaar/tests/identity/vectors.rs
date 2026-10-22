#![forbid(unsafe_code)]
//! P04 identity integration tests: cryptographic derivation vectors.
//!
//! RFC 8032 §7.1 (Ed25519) and libp2p PeerId framing. Constants are
//! independent copies of the upstream vectors; only `from_seed` comes
//! from the production path. The yggdrasil-go address golden vector
//! lives in the `ygg` unit tests (src/identity/ygg.rs), where the raw
//! upstream PUBLIC KEY — the correct input to `AddrForKey` — is used
//! directly; here we only assert identity-level determinism.

use crate::common::{self, TempDir};

use shaar::identity::Identity;

/// 1. RFC 8032 TEST1.
#[tokio::test]
async fn rfc8032_test1_public_key() {
    let id = Identity::from_seed(common::TEST1_SEED);
    assert_eq!(id.public_key_bytes(), common::TEST1_PUB);
}

/// 1. RFC 8032 TEST2.
#[tokio::test]
async fn rfc8032_test2_public_key() {
    let id = Identity::from_seed(common::TEST2_SEED);
    assert_eq!(id.public_key_bytes(), common::TEST2_PUB);
}

/// 1. RFC 8032 TEST3.
#[tokio::test]
async fn rfc8032_test3_public_key() {
    let id = Identity::from_seed(common::TEST3_SEED);
    assert_eq!(id.public_key_bytes(), common::TEST3_PUB);
}

/// 1b. Determinism: from_seed twice yields identical public keys, and
/// generate() yields distinct keys with overwhelming probability.
#[tokio::test]
async fn from_seed_deterministic_generate_distinct() {
    let a = Identity::from_seed(common::TEST1_SEED);
    let b = Identity::from_seed(common::TEST1_SEED);
    assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    let g1 = Identity::generate();
    let g2 = Identity::generate();
    assert_ne!(g1.public_key_bytes(), g2.public_key_bytes());
}

/// 2. PeerId reference: for RFC TEST1, the libp2p-identity dev-dep
/// derivation must equal `identity.peer_id_bytes()`, and the wire prefix
/// `00 24 08 01 12 20` is asserted directly.
#[tokio::test]
async fn peer_id_matches_libp2p_reference() {
    let id = Identity::from_seed(common::TEST1_SEED);
    let ours = id.peer_id_bytes();

    assert_eq!(&ours[..6], &[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
    assert_eq!(&ours[6..], &common::TEST1_PUB);

    let mut kp_seed = common::TEST1_SEED;
    let kp = libp2p_identity::Keypair::ed25519_from_bytes(&mut kp_seed).expect("libp2p keypair");
    let reference: Vec<u8> = kp.public().to_peer_id().to_bytes();
    assert_eq!(ours.as_slice(), reference.as_slice());
}

/// 3. Identity-level determinism/consistency only (no golden claim):
/// equal seeds give equal Yggdrasil addresses, different seeds give
/// different ones. The upstream golden vector is asserted in the `ygg`
/// unit tests against the raw public key.
#[tokio::test]
async fn ygg_address_deterministic_per_key() {
    let a = Identity::from_seed(common::TEST1_SEED);
    let b = Identity::from_seed(common::TEST2_SEED);
    assert_ne!(a.ygg_address(), b.ygg_address());
    let a2 = Identity::from_seed(common::TEST1_SEED);
    assert_eq!(a.ygg_address(), a2.ygg_address());
}

/// Key-file roundtrip through load_or_create on a fresh path (first-run
/// path of the normal lifecycle) — complements storage.rs coverage.
#[tokio::test]
async fn load_or_create_fresh_path_creates_once_and_second_call_loads() {
    let td = TempDir::new("lorc-fresh");
    let path = td.key_path();

    let id = Identity::load_or_create(&path).await.expect("create");
    let before = std::fs::read(&path).expect("read");
    assert_eq!(before.len(), 32);

    let id2 = Identity::load_or_create(&path).await.expect("load");
    assert_eq!(id2.public_key_bytes(), id.public_key_bytes());
    assert_eq!(std::fs::read(&path).expect("reread"), before);
}
