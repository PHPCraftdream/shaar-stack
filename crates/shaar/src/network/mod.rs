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

/// QUIC-level concurrent bidi stream window advertised to the peer. quinn
/// queues `MAX_STREAMS` credit only once the unannounced share exceeds
/// `window / 8` (`queue_max_stream_id`), so the peer's announced budget can
/// trail freed streams by up to `window / 8`. Advertising the bare
/// `STREAM_LIMIT` therefore denied a peer its promised 16 concurrent streams
/// after drain history (P14 finding 12); this window keeps
/// `window - window / 8 >= STREAM_LIMIT`, so 16 concurrent opens always fit.
const STREAM_TRANSPORT_LIMIT: u8 = STREAM_LIMIT + 2;

// Re-exported only for the cfg(test)-only startup resources regression suite
// (chunk 2b).
#[cfg(test)]
pub(crate) use admission::negotiation_frames::RoleFrames;
#[cfg(test)]
pub(crate) use signaling::RelayFixture;
