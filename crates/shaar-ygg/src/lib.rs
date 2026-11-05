#![forbid(unsafe_code)]
//! Yggdrasil transport adapter: key-addressed datagrams without TUN.
//!
//! This crate is the product-graph entry to the isolated adapter in
//! `shaar-ygg-core`, which wraps the pinned, lifecycle-patched Yggdrasil-ng core
//! (`docs/verification/rust-ygg.md`). It exports the transport vocabulary only;
//! readiness semantics, path policy and payload authorization belong to later
//! P10 leaves. Interoperability with deployed Yggdrasil nodes is not claimed.

pub use shaar_ygg_core::{YggConfig, YggError, YggTransport, address_for_key};

#[cfg(test)]
mod product_link_tests;
