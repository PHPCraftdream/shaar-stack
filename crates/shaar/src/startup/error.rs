//! Redacted composed-startup errors. Names roles, fields and stages only;
//! never key material and never upstream I/O text (it can echo peer URIs).

use std::fmt;

use shaar_ygg::YggError;

/// Failures of composed startup preflight and the retained Yggdrasil start.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum StartupError {
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
