use std::fmt;

use iroh_base::PublicKey;
use shaar_ygg::YggPump;
use tokio::time::{Instant, timeout_at};

use super::YggEndpoint;
use crate::network::{NetworkError, Session};
use crate::path::{DialError, Dialer};

/// Construction refused: the caller gets both owners back to close them in order.
pub(crate) struct Rejected {
    pub(crate) error: NetworkError,
    pub(crate) endpoint: YggEndpoint,
    pub(crate) pump: YggPump,
}

impl fmt::Debug for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Yggdrasil fallback route to one pinned, allowlisted peer for the path owner.
///
/// It owns the endpoint and its pump as a pair and spawns nothing itself; the
/// pump's retained writer starts on the first poll of `pump.run()`, which `dial`
/// and `lost` drive. The caller closes the borrowed `YggBridge` last, after
/// `close()` has returned `Ok`, because the carrier holds capabilities on it.
pub(crate) struct YggFallback {
    endpoint: YggEndpoint,
    pump: YggPump,
    peer: PublicKey,
    closed: bool,
}

impl YggFallback {
    /// Outbound authority needs the allowlist, so a peer outside it is refused here.
    pub(crate) fn new(
        endpoint: YggEndpoint,
        pump: YggPump,
        peer: PublicKey,
    ) -> Result<Self, Box<Rejected>> {
        if !endpoint.allowlist.contains(&peer) {
            return Err(Box::new(Rejected {
                error: NetworkError::AccessDenied,
                endpoint,
                pump,
            }));
        }
        Ok(Self {
            endpoint,
            pump,
            peer,
            closed: false,
        })
    }

    /// Clone of the endpoint admission semaphore, to prove charges are released.
    #[cfg(test)]
    pub(super) fn slots(&self) -> std::sync::Arc<tokio::sync::Semaphore> {
        self.endpoint.slots.clone()
    }

    /// Custom address of a peer, for path-frame oracles in tests.
    #[cfg(test)]
    pub(super) fn peer_address(
        &self,
        peer: &PublicKey,
    ) -> Result<iroh_base::CustomAddr, NetworkError> {
        self.endpoint.peer_address(peer)
    }

    /// Local endpoint identity, for tests that pair two fallbacks.
    #[cfg(test)]
    pub(super) fn endpoint_id(&self) -> PublicKey {
        self.endpoint.id()
    }
}

impl Dialer for YggFallback {
    type Link = Session;

    /// A pump that finishes means the carrier writer is gone, so no route can work.
    /// A session completed after `deadline` is dropped (closing it), never returned.
    async fn dial(&mut self, deadline: Instant) -> Result<Session, DialError> {
        if self.closed {
            return Err(DialError);
        }
        let peer = self.peer;
        let connected = timeout_at(deadline, async {
            tokio::select! {
                biased;
                _ = self.pump.run() => Err(DialError),
                result = self.endpoint.connect(peer) => result.map_err(|_| DialError),
            }
        })
        .await
        .map_err(|_| DialError)??;
        // timeout_at polls the inner future first, so it can win a tie with the deadline.
        if Instant::now() >= deadline {
            return Err(DialError);
        }
        Ok(connected)
    }

    /// Level-triggered: a closed session or a stopped writer both read as lost.
    /// cancel-safe: yes — `closed` and `run` retain no event.
    async fn lost(&mut self, link: &Session) {
        tokio::select! {
            _ = link.closed() => {}
            _ = self.pump.run() => {}
        }
    }

    /// Drains the endpoint, then joins the pump; both owners keep progress across
    /// cancellation, so a repeated call resumes. Success is remembered.
    /// cancel-safe: yes
    async fn close(&mut self) -> Result<(), DialError> {
        if self.closed {
            return Ok(());
        }
        self.endpoint
            .close(&mut self.pump)
            .await
            .map_err(|_| DialError)?;
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{config, identity, listener};
    use super::*;
    use crate::network::{Allowlist, Limits};
    use shaar_ygg::{YggBridge, YggTransport};
    use std::time::Duration;

    #[tokio::test]
    async fn rejected_peer_returns_both_owners_for_joined_cleanup() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let local = identity(0xCA);
            let allowed = identity(0xCB).transport_key().public();
            let denied = identity(0xCC).transport_key().public();
            let (transport, port) = listener(0xCA).await;
            let bridge = YggBridge::new(transport, []);
            let (endpoint, pump) = YggEndpoint::bind(
                &local,
                &bridge,
                Allowlist::new(&[allowed]).unwrap(),
                Limits::new(1).unwrap(),
            )
            .await
            .unwrap();
            let address = endpoint.peer_address(&allowed).unwrap();
            let rejected = match YggFallback::new(endpoint, pump, denied) {
                Err(rejected) => rejected,
                Ok(_) => panic!("forbidden fallback peer was accepted"),
            };
            let Rejected {
                error,
                mut endpoint,
                mut pump,
            } = *rejected;
            assert!(matches!(error, NetworkError::AccessDenied));
            assert_eq!(endpoint.slots.available_permits(), 1);
            assert_eq!(
                endpoint.carrier.authenticated_peer(&address).unwrap(),
                *allowed.as_bytes()
            );
            endpoint.close(&mut pump).await.unwrap();
            assert!(endpoint.carrier.authenticated_peer(&address).is_err());
            bridge.close().await.unwrap();
            let replacement = YggTransport::start(config(
                0xCA,
                vec![format!("tcp://127.0.0.1:{port}")],
                vec![],
            ))
            .await
            .unwrap();
            replacement.close().await.unwrap();
        })
        .await
        .expect("rejected fallback cleanup deadline");
    }
}
