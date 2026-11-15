use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ForwardError {
    InvalidTarget,
    Capacity,
    AccessDenied,
    PathUnavailable,
    /// The peer's application-level close of the whole session — a clean end,
    /// never a path failure.
    PeerClosed,
    TargetUnavailable,
    Protocol,
    Deadline,
    StreamReset,
    TaskFailure,
    Io(io::Error),
}

impl ForwardError {
    pub(super) fn from_io(error: io::Error) -> Self {
        use iroh::endpoint::{ReadError, WriteError};
        let source = error.get_ref();
        if let Some(ReadError::ConnectionLost(reason)) =
            source.and_then(|source| source.downcast_ref())
        {
            return Self::connection(reason);
        }
        if let Some(WriteError::ConnectionLost(reason)) =
            source.and_then(|source| source.downcast_ref())
        {
            return Self::connection(reason);
        }
        if matches!(
            source.and_then(|source| source.downcast_ref::<ReadError>()),
            Some(ReadError::Reset(_))
        ) || matches!(
            source.and_then(|source| source.downcast_ref::<WriteError>()),
            Some(WriteError::Stopped(_))
        ) {
            return Self::StreamReset;
        }
        Self::Io(error)
    }

    /// Classifies a QUIC-level connection close. Only an access-denied close is
    /// an access failure; any other application close is a clean peer end; the
    /// rest (locally closed, transport errors, timeouts) are path failures.
    pub(super) fn from_connection_error(reason: iroh::endpoint::ConnectionError) -> Self {
        use iroh::endpoint::{ConnectionError, VarInt};
        match reason {
            ConnectionError::ApplicationClosed(reason)
                if reason.error_code
                    == VarInt::from_u32(crate::network::session::ACCESS_DENIED) =>
            {
                Self::AccessDenied
            }
            ConnectionError::ApplicationClosed(_) => Self::PeerClosed,
            _ => Self::PathUnavailable,
        }
    }

    fn connection(reason: &iroh::endpoint::ConnectionError) -> Self {
        Self::from_connection_error(reason.clone())
    }
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity => f.write_str("forwarding stream limit reached"),
            Self::InvalidTarget => f.write_str("target must be a nonzero loopback TCP address"),
            Self::AccessDenied => f.write_str("peer access denied"),
            Self::PathUnavailable => f.write_str("QUIC connection is unavailable"),
            Self::PeerClosed => f.write_str("peer closed the session"),
            Self::TargetUnavailable => f.write_str("target TCP connection failed"),
            Self::Protocol => f.write_str("invalid forwarding request or status"),
            Self::Deadline => f.write_str("forwarding setup deadline exceeded"),
            Self::StreamReset => f.write_str("forwarding stream was reset"),
            Self::TaskFailure => f.write_str("forwarding worker did not complete normally"),
            Self::Io(_) => f.write_str("forwarding I/O failed"),
        }
    }
}

impl Error for ForwardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
