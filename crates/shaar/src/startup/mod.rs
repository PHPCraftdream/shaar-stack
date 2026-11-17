//! Crate-private composed-startup preflight and retained Yggdrasil start.
//!
//! Pure validation performed before any network I/O or binding. The
//! composed startup requires the shared [`crate::config::NetworkSettings`]
//! object: no silent direct-only fallback is applied. The preflight
//! validates the raw application-peer count against the signaling bound
//! and checks identity-role conflicts against exact known public
//! identifiers. The retained same-identity Yggdrasil start (dial-out only,
//! zeroizing staging, joined cleanup) complements the preflight.

pub mod facade;
pub(crate) mod preflight;
pub(crate) mod resources;
mod role;
pub(crate) mod ygg_start;

pub use preflight::MAX_STARTUP_APP_PEERS;
#[cfg(test)]
pub(crate) use preflight::{preflight_client, preflight_server};
#[cfg(test)]
pub(crate) use resources::SharedResourcesStart;
#[cfg(test)]
pub(crate) use resources::YggPhase;
pub use role::{ClientRole, RoleOptions, ServerRole, StreamHandler};
#[cfg(test)]
pub(crate) use ygg_start::{RetainedYggStart, SameIdentityYgg, start_ygg_same_identity};

#[cfg(test)]
mod tests;

// Redacted composed-startup errors. Names roles, fields and stages only;
// never key material and never upstream I/O text (it can echo peer URIs).

use std::fmt;

use shaar_ygg::YggError;

/// Failures of composed startup preflight, the retained Yggdrasil start and
/// the composed role loops.
#[derive(Clone, PartialEq, Eq)]
pub enum StartupError {
    /// Composed startup was given a legacy config without the shared
    /// network object. No silent direct-only fallback is applied.
    NetworkRequired,
    /// Raw application-peer input length exceeds the composed bound.
    /// Duplicates are counted; never deduplicated or truncated to evade it.
    TooManyAppPeers { count: usize },
    /// Names only the conflicting role (`"relay"`, `"application"` or
    /// `"service"` — the configured service identity cannot be the local
    /// identity or pinned infrastructure), never key bytes.
    IdentityConflict { role: &'static str },
    /// Adapter startup failure, redacted on rendering.
    Ygg(YggError),
    /// Native endpoint/signaling bind failure. Names the stage only;
    /// upstream bind text is withheld (it can echo addresses).
    NativeBind,
    /// Mainline DHT runtime start failure. Names the stage only.
    MainlineStart,
    /// Yggdrasil payload endpoint or allowlist construction failure.
    /// Names the stage only.
    YggPayload,
    /// A retained shutdown stage reported an error. The stage is named;
    /// upstream text is withheld.
    Close { stage: &'static str },
    /// Local TCP listener bind failed. Upstream bind text is withheld (it
    /// can echo addresses).
    Listener,
    /// The path policy configuration was rejected by validation. Names no
    /// parameter values.
    InvalidPolicy,
    /// No usable path remained within the attempt budget.
    Exhausted,
    /// The pinned-relay destination reservation could not be established at
    /// startup. Names the stage only; never relay addresses or upstream text.
    RelayReserve,
    /// The address key file could not be read or is not a valid key. Names the stage only;
    /// never the path text or key material.
    AddressKey,
    /// No `network.mainline.bootstrap` entry is usable: every host name failed to
    /// resolve within the deadline and no numeric entry is configured. Names the
    /// field only; host names and resolver text are withheld.
    BootstrapUnresolved,
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkRequired => write!(
                f,
                "composed startup requires the shared network settings; direct-only fallback is not applied"
            ),
            Self::TooManyAppPeers { count } => write!(
                f,
                "raw application-peer entries: {count} exceeds the composed startup bound of {}",
                crate::startup::MAX_STARTUP_APP_PEERS
            ),
            Self::IdentityConflict { role } => write!(
                f,
                "identity role conflict: {role} identity collides with a distinct required role"
            ),
            Self::Ygg(e) => write!(f, "Yggdrasil start failed: {}", redact_ygg(e)),
            Self::NativeBind => write!(f, "native endpoint/signaling bind failed"),
            Self::MainlineStart => write!(f, "Mainline discovery runtime start failed"),
            Self::YggPayload => write!(f, "Yggdrasil payload endpoint construction failed"),
            Self::Close { stage } => write!(f, "shutdown failed at the {stage} stage"),
            Self::Listener => write!(f, "local listener bind failed"),
            Self::InvalidPolicy => write!(f, "path policy configuration rejected"),
            Self::Exhausted => write!(f, "no usable path remained within the attempt budget"),
            Self::RelayReserve => write!(f, "relay reservation failed at startup"),
            Self::AddressKey => write!(f, "address key file could not be loaded"),
            Self::BootstrapUnresolved => write!(
                f,
                "no bootstrap host of `network.mainline.bootstrap` could be resolved"
            ),
        }
    }
}

/// Redacted rendering: upstream I/O text is withheld, fields and stages only.
fn redact_ygg(e: &YggError) -> String {
    match e {
        YggError::Io(_) => "core I/O error (details withheld)".to_string(),
        YggError::InvalidConfig { field } => format!("invalid configuration: {field}"),
        YggError::Start { stage } => format!("start failed at {stage}"),
        YggError::KeyInUse => "key already in use by a live transport".to_string(),
        YggError::Closed => "transport closed".to_string(),
        _ => "Yggdrasil start failed".to_string(),
    }
}

impl fmt::Debug for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted, identical to Display: no key material, no upstream text.
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for StartupError {}
