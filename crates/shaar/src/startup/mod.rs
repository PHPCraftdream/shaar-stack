//! Crate-private composed-startup preflight and retained Yggdrasil start.
//!
//! Pure validation performed before any network I/O or binding. The
//! composed startup requires the shared [`crate::config::NetworkSettings`]
//! object: no silent direct-only fallback is applied. The preflight
//! validates the raw application-peer count against the signaling bound
//! and checks identity-role conflicts against exact known public
//! identifiers. The retained same-identity Yggdrasil start (dial-out only,
//! zeroizing staging, joined cleanup) complements the preflight.

pub(crate) mod error;
pub(crate) mod preflight;
pub(crate) mod ygg_start;

pub(crate) use error::StartupError;
pub(crate) use preflight::{MAX_STARTUP_APP_PEERS, preflight_client, preflight_server};
pub(crate) use ygg_start::{RetainedYggStart, SameIdentityYgg, start_ygg_same_identity};

#[cfg(test)]
mod tests;
