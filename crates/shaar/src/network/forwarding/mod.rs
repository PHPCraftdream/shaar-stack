use std::{future::Future, net::SocketAddr};

use iroh::endpoint::{Connection, ConnectionError, VarInt};
use tokio::{
    net::TcpStream,
    task::{JoinError, JoinSet},
};

use super::{STREAM_LIMIT, Session, session::ACCESS_DENIED};

mod error;
mod protocol;
mod pump;

pub use error::ForwardError;
pub use pump::ForwardStats;

#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod tests;

/// Terminal worker counts; counters saturate at u64::MAX.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServeReport {
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
}

impl ServeReport {
    fn record(
        &mut self,
        result: Result<Result<ForwardStats, ForwardError>, JoinError>,
    ) -> Result<(), ForwardError> {
        match result {
            Ok(Ok(_)) => self.completed = self.completed.saturating_add(1),
            Ok(Err(_)) => self.failed = self.failed.saturating_add(1),
            Err(error) if error.is_cancelled() => self.cancelled = self.cancelled.saturating_add(1),
            Err(_) => return Err(ForwardError::TaskFailure),
        }
        Ok(())
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
            Some(ConnectionError::ApplicationClosed(reason))
                if reason.error_code == VarInt::from_u32(ACCESS_DENIED) =>
            {
                ForwardError::AccessDenied
            }
            Some(_) => ForwardError::PathUnavailable,
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
                        Ok(pair) => {
                            tasks.spawn(async move {
                                let mut stream = pump::Stream::new(pair);
                                let tcp = protocol::target(&mut stream, target).await?;
                                pump::pump(stream, tcp).await
                            });
                        }
                        Err(_) => break Err(ForwardError::PathUnavailable),
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
