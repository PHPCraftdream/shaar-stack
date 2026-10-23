//! Bounded native QUIC admission, without relays or external address lookup.
//!
//! A session authenticates the TLS peer, not a target TCP connection. Forwarding
//! is a separate layer. No raw endpoint/connection handle or early-data API is exposed.

mod endpoint;
mod error;
mod policy;
mod session;

pub use endpoint::Endpoint;
pub use error::NetworkError;
pub use policy::{Allowlist, Limits};
pub use session::Session;

/// Exact protocol identifier; no compatibility with historical draft protocols.
pub const ALPN: &[u8] = b"shaar/tcp/1";
