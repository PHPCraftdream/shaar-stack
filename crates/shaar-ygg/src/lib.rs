#![forbid(unsafe_code)]
//! Yggdrasil transport adapter: key-addressed datagrams without TUN.
//!
//! This crate is the product-graph entry to the isolated adapter in
//! `shaar-ygg-core`, which wraps the pinned, lifecycle-patched Yggdrasil-ng core
//! (`docs/verification/rust-ygg.md`). It re-exports the transport vocabulary and adds
//! [`YggBridge`], the readiness bridge: a peer is ready only after an authenticated
//! probe round trip, and `close` joins the bridge task before the transport closes.
//! Path policy and payload authorization belong to later P10 leaves.
//! Interoperability with deployed Yggdrasil nodes is not claimed.

mod bridge;
mod frame;
mod pending;

pub use bridge::{ProbeError, YggBridge};
pub use pending::MAX_PENDING_PROBES;
pub use shaar_ygg_core::{YggConfig, YggError, YggTransport, address_for_key};

#[cfg(test)]
mod bridge_tests;
#[cfg(test)]
mod product_link_tests;
#[cfg(test)]
mod test_support;
