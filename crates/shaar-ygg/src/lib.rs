#![forbid(unsafe_code)]
//! Yggdrasil transport adapter: key-addressed datagrams without TUN.
//!
//! Scaffold only. A native Rust backend replaces the former Go FFI plan.
//! Yggdrasil-ng is a candidate, not an integrated dependency; its lifecycle
//! source gate is documented in `docs/verification/rust-ygg.md`.
//! No transport, shutdown, interoperability, or resource proof is claimed.
