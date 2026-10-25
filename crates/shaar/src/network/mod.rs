//! Bounded native QUIC admission and separately owned signaling carrier construction.
//!
//! A session authenticates the TLS peer, not a target TCP connection. Forwarding
//! is a separate layer. No raw endpoint/connection handle or early-data API is exposed.

mod admission;
mod error;
mod forwarding;
mod session;
mod signaling;

pub use admission::{Allowlist, Endpoint, Limits};
pub use error::NetworkError;
pub use forwarding::{ForwardError, ForwardStats, ServeReport};
pub use session::Session;
pub use signaling::bind_signaling;

/// Exact protocol identifier; no compatibility with historical draft protocols.
pub const ALPN: &[u8] = b"shaar/tcp/1";

const STREAM_LIMIT: u8 = 16;
