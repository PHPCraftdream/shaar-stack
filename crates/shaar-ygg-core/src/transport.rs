//! Key-addressed datagram transport over one lifecycle-patched Yggdrasil core.
//!
//! The adapter adds no queue: bounds and backpressure are the core's own
//! (receive queue 512, protocol queue 64). Datagrams stay unreliable by contract.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::SigningKey;
use ironwood::Addr;
use yggdrasil::config::Config;
use yggdrasil::core::Core;

use crate::registry::KeyClaim;
use crate::validate::validate;

/// Settings for one transport. The seed and group password are secrets and are
/// never printed or echoed in errors.
#[derive(Clone)]
pub struct YggConfig {
    /// Ed25519 seed; the public key is the node's identity and address.
    pub seed: [u8; 32],
    /// Listen URIs such as `tcp://127.0.0.1:9001`.
    pub listen: Vec<String>,
    /// Peer URIs dialed at start.
    pub peers: Vec<String>,
    /// When non-empty, only these public keys may peer.
    pub allowed_public_keys: Vec<[u8; 32]>,
    /// Closed-network group password; `None` for an open network. `Some("")` is
    /// rejected: the core treats an empty password as open, so say `None` instead.
    pub group_password: Option<String>,
}

impl fmt::Debug for YggConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YggConfig")
            .field("seed", &"<redacted>")
            .field("listen", &self.listen.len())
            .field("peers", &self.peers.len())
            .field("allowed_public_keys", &self.allowed_public_keys.len())
            .field(
                "group_password",
                &self.group_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Best-effort in-memory erasure of the seed when the temporary configuration is
/// dropped, covering the copy held by [`YggTransport::start`] for the whole of
/// startup. Zeroize is best-effort, not an OS/swap/compiler-proof guarantee; copies
/// inside external cryptographic dependencies (for example ed25519-dalek signing-key
/// internals) are out of scope and no erasure is claimed for them.
impl Drop for YggConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

/// Transport failures. The adapter's own messages never contain secrets; the core's
/// tracing output is outside this guarantee and can mention peer URIs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum YggError {
    /// The transport was closed.
    Closed,
    /// A setting is invalid; only the field is named, never its value.
    InvalidConfig { field: &'static str },
    /// Another live transport in this process already uses this key.
    KeyInUse,
    /// The payload exceeds the transport MTU; nothing was sent.
    Oversize { len: usize, mtu: usize },
    /// The receive buffer cannot hold an MTU-sized payload.
    BufferTooSmall { len: usize, needed: usize },
    /// Starting failed at the named stage and the partly started core was closed.
    /// The upstream text is dropped on purpose: it can echo peer URIs with secrets.
    Start { stage: &'static str },
    /// Any other failure reported by the core.
    Io(String),
}

impl fmt::Display for YggError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "transport closed"),
            Self::Oversize { len, mtu } => write!(f, "payload of {len} bytes exceeds mtu {mtu}"),
            Self::BufferTooSmall { len, needed } => {
                write!(
                    f,
                    "receive buffer of {len} bytes is below the required {needed}"
                )
            }
            Self::InvalidConfig { field } => write!(f, "invalid configuration: {field}"),
            Self::KeyInUse => write!(f, "key already in use by a live transport"),
            Self::Start { stage } => write!(f, "start failed at {stage}"),
            Self::Io(reason) => write!(f, "core error: {reason}"),
        }
    }
}

impl std::error::Error for YggError {}

fn map_core_error(error: ironwood::Error) -> YggError {
    match error {
        ironwood::Error::Closed => YggError::Closed,
        other => YggError::Io(other.to_string()),
    }
}

fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A running transport. Call [`YggTransport::close`]: dropping it alone does not
/// stop the core's tasks.
pub struct YggTransport {
    core: Arc<Core>,
    claim: KeyClaim,
    closed: AtomicBool,
}

impl YggTransport {
    /// Start the core, listen on every listen URI and dial every peer URI.
    /// Await it to completion: dropping the future early can leave the core running.
    pub async fn start(config: YggConfig) -> Result<Self, YggError> {
        validate(&config)?;
        let signing_key = SigningKey::from_bytes(&config.seed);
        let claim =
            KeyClaim::acquire(signing_key.verifying_key().to_bytes()).ok_or(YggError::KeyInUse)?;
        let core_config = Config {
            allowed_public_keys: config.allowed_public_keys.iter().map(hex_key).collect(),
            group_password: config.group_password.clone().unwrap_or_default(),
            multicast_interfaces: Vec::new(),
            if_name: "none".to_string(),
            ..Config::default()
        };
        let core = Core::new(signing_key, core_config);
        core.init_links().await;
        let transport = Self {
            core,
            claim,
            closed: AtomicBool::new(false),
        };
        for uri in &config.listen {
            if transport.core.listen(uri).await.is_err() {
                let _ = transport.close().await;
                return Err(YggError::Start { stage: "listen" });
            }
        }
        for uri in &config.peers {
            if transport.core.add_peer(uri).await.is_err() {
                let _ = transport.close().await;
                return Err(YggError::Start { stage: "peer" });
            }
        }
        Ok(transport)
    }

    /// This node's public key, which is also its address.
    pub fn public_key(&self) -> [u8; 32] {
        *self.core.public_key()
    }

    /// Largest payload `send_to` accepts, in bytes.
    pub fn mtu(&self) -> usize {
        usize::try_from(self.core.mtu()).unwrap_or(usize::MAX)
    }

    /// Send one datagram to the node with the given public key.
    pub async fn send_to(&self, peer: &[u8; 32], payload: &[u8]) -> Result<(), YggError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(YggError::Closed);
        }
        let mtu = self.mtu();
        if payload.len() > mtu {
            return Err(YggError::Oversize {
                len: payload.len(),
                mtu,
            });
        }
        self.core
            .write_to(payload, &Addr(*peer))
            .await
            .map(|_| ())
            .map_err(map_core_error)
    }

    /// Receive one datagram into `buf` and return its length and the sender's key.
    /// `buf` must hold `mtu() + 1` bytes. Cancel-safe: a dropped future loses no datagram.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, [u8; 32]), YggError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(YggError::Closed);
        }
        let needed = self.mtu() + 1;
        if buf.len() < needed {
            return Err(YggError::BufferTooSmall {
                len: buf.len(),
                needed,
            });
        }
        let (range, sender) = self.core.read_from(buf).await.map_err(map_core_error)?;
        let len = range.len();
        buf.copy_within(range, 0);
        Ok((len, sender.0))
    }

    /// Stop every task of the core and release its sockets. Idempotent.
    /// The key is released for reuse once the core has stopped.
    /// After it starts, every `send_to` and `recv` reports `Closed`, whatever the arguments.
    pub async fn close(&self) -> Result<(), YggError> {
        self.closed.store(true, Ordering::SeqCst);
        let result = self.core.close().await.map_err(map_core_error);
        self.claim.release();
        result
    }
}

#[cfg(test)]
mod tests;
