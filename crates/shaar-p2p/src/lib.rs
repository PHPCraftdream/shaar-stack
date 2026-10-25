#![forbid(unsafe_code)]
//! Bounded libp2p carrier building blocks; no application data routing policy here.
//!
//! Encrypted QUIC datagrams are opaque. Signaling-only enforcement belongs to the
//! trusted Noq packetization boundary, not inspection of this codec's payload.

mod bridge;
mod carrier;
mod executor;
mod packet;

pub use bridge::{SignalingPump, SignalingTransport};
pub use carrier::{Carrier, CarrierHandle, Link, Received, RelayAddr, RelayLease, Route};
pub use executor::{ExecutorHandle, OwnedExecutor};
pub use packet::{CONTROL_PROTOCOL, Datagram, DatagramCodec, MAX_DATAGRAM};
