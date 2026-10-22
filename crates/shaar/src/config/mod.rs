//! Startup configuration layer: ktav 0.8.* schemas, parsing, merging,
//! and validation for the Sha'ar Server and Client.
//!
//! Pure parsing and merging are synchronous; file loading is asynchronous
//! and bounded by [`MAX_CONFIG_BYTES`] (the read is limited via
//! `AsyncReadExt::take` before any read request is issued; the pure
//! `from_text` entry points enforce the same byte bound on their
//! argument). Fallback semantics: [`Fallback::Signal`] is
//! alternative-path negotiation only; [`Fallback::Standby`] (the
//! default) permits the Yggdrasil DATA fallback when direct is
//! unavailable; libp2p is never an application-data fallback. This
//! layer performs no writes, no networking, and never exposes secret
//! key material.

mod client;
mod error;
mod load;
mod raw;
mod server;

pub use client::{ClientConfig, ClientOverrides};
pub use error::{ConfigError, LoadKind, ValidationKind};
pub use load::{load_client, load_server};
pub use raw::Fallback;
pub use server::{ServerConfig, ServerOverrides};

/// Hard upper bound on configuration file size in bytes (1 MiB).
///
/// Loading reads at most one byte more than this bound before rejecting
/// the file, so an oversized file is never read into memory in full.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
