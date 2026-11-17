use std::{error::Error, fmt, future::Future, io, net::SocketAddr};

use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use tokio::{
    net::TcpStream,
    task::{JoinError, JoinSet},
};

use super::{STREAM_LIMIT, Session};

pub mod observe;
mod protocol;
mod pump;
mod service;

pub use pump::ForwardStats;
pub use service::ServiceStream;

#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod tests;

/// What a serve worker task returns.
pub(super) type WorkerResult = Result<ForwardStats, ForwardError>;

/// Terminal worker counts; counters saturate at u64::MAX.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServeReport {
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    /// Sums over fully completed streams only (from_peer at the server = bytes
    /// received from the peer; to_peer = bytes sent to the peer); cancelled or
    /// failed streams contribute nothing.
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl ServeReport {
    fn record(
        &mut self,
        result: Result<Result<ForwardStats, ForwardError>, JoinError>,
    ) -> Result<(), ForwardError> {
        match result {
            Ok(Ok(stats)) => {
                self.completed = self.completed.saturating_add(1);
                self.bytes_in = self.bytes_in.saturating_add(stats.from_peer);
                self.bytes_out = self.bytes_out.saturating_add(stats.to_peer);
            }
            Ok(Err(_)) => self.failed = self.failed.saturating_add(1),
            Err(error) if error.is_cancelled() => self.cancelled = self.cancelled.saturating_add(1),
            Err(_) => return Err(ForwardError::TaskFailure),
        }
        Ok(())
    }
}

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

struct CloseOnExit<'a>(&'a Connection);

impl Drop for CloseOnExit<'_> {
    fn drop(&mut self) {
        self.0.close(VarInt::from_u32(0), b"");
    }
}

impl Session {
    /// Forwards an owned local TCP stream after the fixed-target status succeeds.
    /// At most 16 calls are admitted; no SDK task or waiting admission queue is created.
    /// cancel-safe: NO — cancellation drops TCP and resets this QUIC stream only.
    pub async fn forward(&self, tcp: TcpStream) -> Result<ForwardStats, ForwardError> {
        let _permit = self
            .streams
            .try_acquire()
            .map_err(|_| ForwardError::Capacity)?;
        let result = async {
            let stream = protocol::open(&self.connection).await?;
            pump::pump(stream, tcp).await
        }
        .await;
        result.map_err(|error| match self.connection.close_reason() {
            // Denied and clean-close classification flows through the shared
            // mapping; without a close reason the original error stays.
            Some(reason) => ForwardError::from_connection_error(reason),
            None => error,
        })
    }

    /// Serves only this validated fixed loopback target, never a peer-supplied address.
    /// Owns at most 16 workers and joins every worker before returning. Individual
    /// stream failures are counted without aborting other streams. `stop` closes
    /// the QUIC session, aborts outstanding workers and joins their terminal results.
    /// cancel-safe: NO — dropping the serve future closes the session and aborts its
    /// workers, but cannot await their termination. Use `stop` for joined shutdown.
    pub async fn serve(
        &mut self,
        target: SocketAddr,
        stop: impl Future<Output = ()>,
    ) -> Result<ServeReport, ForwardError> {
        if !target.ip().to_canonical().is_loopback() || target.port() == 0 {
            return Err(ForwardError::InvalidTarget);
        }
        self.serve_loop(stop, |tasks, pair| {
            tasks.spawn(async move {
                let mut stream = pump::Stream::new(pair);
                let tcp = protocol::target(&mut stream, target).await?;
                pump::pump(stream, tcp).await
            });
        })
        .await
    }

    /// Accept loop shared by the fixed-target and the in-process serving: at most
    /// `STREAM_LIMIT` workers, joined before returning, `stop` closes the session.
    /// cancel-safe: NO — see [`Session::serve`].
    pub(super) async fn serve_loop(
        &mut self,
        stop: impl Future<Output = ()>,
        mut spawn: impl FnMut(&mut JoinSet<WorkerResult>, (SendStream, RecvStream)),
    ) -> Result<ServeReport, ForwardError> {
        let close = CloseOnExit(&self.connection);
        let mut tasks = JoinSet::new();
        let mut report = ServeReport::default();
        tokio::pin!(stop);
        let mut outcome = loop {
            tokio::select! {
                biased;
                _ = &mut stop => break Ok(()),
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(result) = result
                        && let Err(error) = report.record(result) {
                        break Err(error);
                    }
                }
                pair = self.connection.accept_bi(), if tasks.len() < usize::from(STREAM_LIMIT) => {
                    match pair {
                        Ok(pair) => spawn(&mut tasks, pair),
                        Err(reason) => match ForwardError::from_connection_error(reason) {
                            // The peer's application close is a clean session
                            // end; only a non-application failure is a lost path.
                            ForwardError::PeerClosed => break Ok(()),
                            ForwardError::AccessDenied => break Err(ForwardError::AccessDenied),
                            _ => break Err(ForwardError::PathUnavailable),
                        },
                    }
                }
            }
        };
        drop(close);
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = report.record(result) {
                outcome = Err(error);
            }
        }
        outcome.map(|()| report)
    }
}
