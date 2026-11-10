//! Bounded native QUIC admission and separately owned signaling carrier construction.
//!
//! A session authenticates the TLS peer, not a target TCP connection. Forwarding
//! is a separate layer. No raw endpoint/connection handle or early-data API is exposed.

mod admission;
mod error;
mod forwarding;
mod session;
pub(crate) mod signaling;

pub use admission::{Allowlist, Endpoint, Limits};
// Narrow crate-private re-export: the composed startup builds the custom-only
// payload endpoint from the admitted bridge (a production consumer exists).
pub(crate) use admission::ygg::YggEndpoint;
pub use error::NetworkError;
pub use forwarding::{ForwardError, ForwardStats, ServeReport};
pub use session::Session;
pub use signaling::{
    DiscoveredRelay, DiscoveryConfig, SignaledEndpoint, bind_signaling,
    bind_signaling_with_discovery,
};

/// Exact protocol identifier; no compatibility with historical draft protocols.
pub const ALPN: &[u8] = b"shaar/tcp/1";

const STREAM_LIMIT: u8 = 16;

// Re-exported only for the cfg(test)-only startup resources regression suite
// (chunk 2b).
#[cfg(test)]
pub(crate) use admission::negotiation_frames::RoleFrames;
#[cfg(test)]
pub(crate) use signaling::RelayFixture;
