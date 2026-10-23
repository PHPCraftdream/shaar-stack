use std::{error::Error, fmt};

/// Admission and transport failures; remote reason strings are never parsed as types.
#[derive(Debug)]
pub enum NetworkError {
    InvalidLimits,
    AllowlistTooLarge,
    InvalidAddress,
    Capacity,
    Closed,
    Deadline,
    AccessDenied,
    PeerMismatch,
    Protocol,
    Bind(Box<iroh::endpoint::BindError>),
    Connect(Box<iroh::endpoint::ConnectError>),
    Handshake(Box<iroh::endpoint::ConnectingError>),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLimits => "session limit must be between 1 and 32",
            Self::AllowlistTooLarge => "allowlist exceeds 256 entries",
            Self::InvalidAddress => "a usable native unicast address is required",
            Self::Capacity => "session admission limit reached",
            Self::Closed => "endpoint or session is closed",
            Self::Deadline => "handshake deadline exceeded",
            Self::AccessDenied => "peer is not allowed",
            Self::PeerMismatch => "authenticated peer does not match the pinned key",
            Self::Protocol => "unexpected application protocol",
            Self::Bind(_) => "native endpoint bind failed",
            Self::Connect(_) => "native peer connection failed",
            Self::Handshake(_) => "peer handshake failed",
        };
        f.write_str(message)
    }
}

impl Error for NetworkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind(source) => Some(source.as_ref()),
            Self::Connect(source) => Some(source.as_ref()),
            Self::Handshake(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}
