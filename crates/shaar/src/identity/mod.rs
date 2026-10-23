//! P04: node identity — one Ed25519 seed driving iroh, libp2p and
//! Yggdrasil identifiers, with hardened key-file storage.
//!
//! # Secret handling (threat model I3/I4)
//!
//! The seed lives in a private [`iroh_base::SecretKey`] (zeroize on
//! drop). Key-file writes use internal `zeroize::Zeroizing<[u8; 32]>`
//! staging; no seed accessor is exposed. Zeroize is best-effort in-memory
//! erasure on drop, not an OS/swap/compiler-proof guarantee. [`Identity`]
//! has redacted Debug output. Storage errors do not attach key contents;
//! underlying I/O error text is preserved and may contain paths.
//!
//! # Async discipline
//!
//! All blocking filesystem work runs in `tokio::task::spawn_blocking` with
//! owned inputs. Normal completion awaits the worker; dropping the async
//! waiter detaches it and does NOT stop running native I/O. Failure cleanup
//! remains inside the worker.

mod error;
mod store;
mod ygg;

pub use error::IdentityError;

use std::net::Ipv6Addr;
use std::path::PathBuf;

/// libp2p PeerId wire prefix for a 32-byte Ed25519 key:
/// identity multihash (0x00, len 0x24) over protobuf `08 01 12 20`.
const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// A node identity: one Ed25519 seed and its derived public identifiers.
///
/// `Clone` is allowed (`SecretKey` is `Clone + ZeroizeOnDrop`); there are
/// deliberately no serde derives. `Debug` is redacted.
#[derive(Clone)]
pub struct Identity {
    secret: iroh_base::SecretKey,
}

impl Identity {
    /// Generates a fresh identity from OS-backed entropy.
    /// This is the production path.
    pub fn generate() -> Self {
        Self {
            secret: iroh_base::SecretKey::generate(),
        }
    }

    /// Builds an identity from an explicit 32-byte seed.
    ///
    /// For test fixtures and explicit provisioning ONLY. Never derive
    /// seeds from passwords or other weak entropy.
    ///
    /// Erasure note: `SecretKey::from_bytes` copies the seed into the
    /// key (zeroize-on-drop); afterwards the caller-supplied buffer is
    /// zeroized as well. This is BEST-EFFORT only — not OS/swap- or
    /// compiler-proof, and any copies the caller made of the buffer
    /// before this call are out of reach.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let secret = iroh_base::SecretKey::from_bytes(&seed);
        use zeroize::Zeroize;
        seed.zeroize();
        Self { secret }
    }

    pub(crate) fn transport_key(&self) -> iroh_base::SecretKey {
        self.secret.clone()
    }

    /// The 32-byte Ed25519 public key (stable, config-compatible form).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.secret.public().as_bytes()
    }

    /// The libp2p `PeerId` bytes: `00 24 08 01 12 20 || public_key`.
    pub fn peer_id_bytes(&self) -> [u8; 38] {
        let mut out = [0u8; 38];
        out[..6].copy_from_slice(&PEER_ID_PREFIX);
        out[6..].copy_from_slice(&self.public_key_bytes());
        out
    }

    /// The Yggdrasil node address (`address.AddrForKey`, one-way bit
    /// truncation — NOT invertible to the key; see [`ygg`]).
    pub fn ygg_address(&self) -> Ipv6Addr {
        ygg::addr_for_key(&self.public_key_bytes())
    }

    /// Creates a NEW key file at `path`; never overwrites an existing one.
    ///
    /// Errors with [`IdentityError::AlreadyExists`] if the file exists.
    /// Under a concurrent race exactly one caller wins; losers get an
    /// error, never a second identity.
    /// cancel-safe: NO — a running worker may finish creation after the waiter
    /// is dropped. Existing files are never overwritten.
    pub async fn create_new(path: impl Into<PathBuf>) -> Result<Self, IdentityError> {
        let path = path.into();
        let secret = iroh_base::SecretKey::generate();
        let seed = zeroize::Zeroizing::new(secret.to_bytes());
        // Inputs are owned; normal completion joins the worker. Cancellation
        // drops this waiter but cannot abort the running blocking operation.
        tokio::task::spawn_blocking(move || store::create_new_blocking(&path, &seed))
            .await
            .map_err(|e| IdentityError::Io(std::io::Error::other(e)))??;
        Ok(Self { secret })
    }

    /// Loads an existing key file. A malformed, inaccessible, or
    /// insecure-permission file is ALWAYS an error and never triggers
    /// generation or overwrite.
    /// cancel-safe: NO — an already-running OS read continues after the waiter
    /// is dropped; loading performs no writes.
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self, IdentityError> {
        let path = path.into();
        // Seed staging is zeroize-on-drop; the upstream constructor copies it
        // into the key. Erasure remains best-effort, not compiler/OS proof.
        let seed = tokio::task::spawn_blocking(move || store::load_blocking(&path))
            .await
            .map_err(|e| IdentityError::Io(std::io::Error::other(e)))??;
        Ok(Self {
            secret: iroh_base::SecretKey::from_bytes(&seed),
        })
    }

    /// Loads if the file exists, otherwise creates it.
    ///
    /// Under a concurrent race it may fail safely: exactly one process
    /// wins; losers get [`IdentityError::AlreadyExists`], not a second
    /// identity.
    /// Only an open-time missing file permits creation, never a later read error.
    /// cancel-safe: NO — creation already started can finish after cancellation.
    pub async fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, IdentityError> {
        let path = path.into();
        let load_path = path.clone();
        let seed = tokio::task::spawn_blocking(move || store::load_if_present_blocking(&load_path))
            .await
            .map_err(|err| IdentityError::Io(std::io::Error::other(err)))??;
        match seed {
            Some(seed) => Ok(Self {
                secret: iroh_base::SecretKey::from_bytes(&seed),
            }),
            None => Self::create_new(path).await,
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: no key material, not even the public key, in Debug.
        f.write_str("Identity(..)")
    }
}
