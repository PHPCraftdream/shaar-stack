#![forbid(unsafe_code)]
//! P04 identity integration tests — root of the `tests/identity/`
//! subtree. Covers RFC 8032 derivation vectors, libp2p PeerId framing,
//! the yggdrasil-go address golden vector, key-file storage semantics,
//! races, cancellation, redaction, and platform permission behavior.
//! Only `shaar::identity` public API is exercised.

mod common;
mod security;
mod storage;
mod vectors;
