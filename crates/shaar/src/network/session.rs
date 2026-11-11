use std::fmt;

use futures::Stream;
use iroh::endpoint::{Connection, ConnectionError, VarInt};
use iroh_base::PublicKey;
use tokio::sync::OwnedSemaphorePermit;

use super::NetworkError;

pub(crate) const ACCESS_DENIED: u32 = 1;

/// Fully handshaken peer. Not Clone; drop requests immediate close, not async drain.
/// The endpoint owns the separate drain/UDP shutdown boundary.
pub struct Session {
    pub(super) connection: Connection,
    pub(super) streams: tokio::sync::Semaphore,
    pub(super) _admission: OwnedSemaphorePermit,
}

impl Session {
    pub fn peer_id(&self) -> PublicKey {
        self.connection.remote_id()
    }

    /// Requests immediate connection close and releases the session admission slot.
    /// This does not mean protocol Drained; endpoint metadata remains separately capped.
    pub fn close(self) {
        drop(self);
    }

    /// Observes loss of every eligible Native payload path, not signaling health.
    /// cancel-safe: YES — a fresh subscription replays current state before waiting.
    pub(crate) async fn native_lost(&self) {
        let mut paths = self.connection.paths_stream();
        while let Some(snapshot) =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut paths).poll_next(cx)).await
        {
            if !snapshot.iter().any(|path| {
                matches!(
                    path.remote_addr(), iroh_base::TransportAddr::Ip(address)
                        if super::admission::native_ip(address.ip())
                )
            }) {
                return;
            }
        }
    }

    /// Observes connection closure, not protocol drain.
    /// cancel-safe: yes — dropping the observer does not close or consume the session.
    pub async fn closed(&self) -> NetworkError {
        match self.connection.closed().await {
            ConnectionError::ApplicationClosed(reason)
                if reason.error_code == VarInt::from_u32(ACCESS_DENIED) =>
            {
                NetworkError::AccessDenied
            }
            _ => NetworkError::Closed,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"");
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("peer", &self.peer_id())
            .finish_non_exhaustive()
    }
}
