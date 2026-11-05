//! Readiness bridge over one Yggdrasil transport.
//!
//! The datagram path is unreliable by contract and `send_to` succeeds before path
//! discovery finishes, so a peer counts as ready only after an authenticated round
//! trip: a probe carrying a fresh nonce is answered by the peer with the same nonce,
//! and the reply must come from the probed key (the session authenticates the key
//! that `recv` reports). One owner task reads every datagram, answers probes from the
//! keys it was told to serve and completes pending probes; all other datagrams are
//! counted and dropped. Payload paths are outside this bridge.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};

use crate::frame::{Frame, Kind, NonceSource};
use crate::pending::{Pending, Waiter};
use crate::{YggError, YggTransport};

/// A probe is repeated at this interval until it is answered or its deadline passes;
/// the first path discovery can swallow early probes.
const RESEND: Duration = Duration::from_millis(500);
/// The owner task spends at most this long on answering one probe.
const REPLY_BUDGET: Duration = Duration::from_millis(500);

/// Why a readiness probe did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeError {
    /// The bridge is closed or closing.
    Closed,
    /// Too many probes are already waiting for a reply.
    Busy,
    /// No authenticated reply arrived before the deadline.
    TimedOut,
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "bridge closed"),
            Self::Busy => write!(f, "too many probes in flight"),
            Self::TimedOut => write!(f, "no authenticated reply before the deadline"),
        }
    }
}

impl std::error::Error for ProbeError {}

struct Shared {
    transport: YggTransport,
    answer_to: HashSet<[u8; 32]>,
    pending: Mutex<Pending>,
    nonces: NonceSource,
    ignored: AtomicU64,
    stop: Notify,
}

impl Shared {
    /// The critical sections are a few map operations and never span an `.await`.
    fn pending(&self) -> MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ignore(&self) {
        self.ignored.fetch_add(1, Ordering::Relaxed);
    }

    async fn handle(&self, bytes: &[u8], from: [u8; 32]) {
        let Some(frame) = Frame::decode(bytes) else {
            self.ignore();
            return;
        };
        match frame.kind {
            Kind::Ping if self.answer_to.contains(&from) => {
                let pong = Frame {
                    kind: Kind::Pong,
                    nonce: frame.nonce,
                }
                .encode();
                let _ = timeout(REPLY_BUDGET, self.transport.send_to(&from, &pong)).await;
            }
            Kind::Ping => self.ignore(),
            Kind::Pong => {
                if !self.pending().complete(&frame.nonce, &from) {
                    self.ignore();
                }
            }
        }
    }

    /// Owner loop. A receive error other than a clean stop ends it for good: the table
    /// is closed, so later probes report `Closed` instead of waiting for a dead reader.
    async fn run(&self) {
        let mut buffer = vec![0u8; self.transport.mtu() + 1];
        loop {
            tokio::select! {
                () = self.stop.notified() => break,
                read = self.transport.recv(&mut buffer) => match read {
                    Ok((len, from)) => self.handle(&buffer[..len], from).await,
                    Err(_) => break,
                },
            }
        }
        self.pending().close();
    }
}

/// Removes a probe from the table however its future ends, including cancellation.
struct Registered<'a> {
    shared: &'a Shared,
    nonce: [u8; crate::frame::NONCE_LEN],
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.shared.pending().remove(&self.nonce);
    }
}

/// Probes peers and answers the probes of an allow-listed set of keys.
///
/// Call [`YggBridge::close`]: dropping the bridge alone does not stop its task.
pub struct YggBridge {
    shared: Arc<Shared>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
}

impl YggBridge {
    /// Take over `transport` and start the owner task; must run inside a Tokio runtime.
    /// Probes are answered only for the keys in `answer_to`; an empty set answers nobody.
    pub fn new(transport: YggTransport, answer_to: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let shared = Arc::new(Shared {
            transport,
            answer_to: answer_to.into_iter().collect(),
            pending: Mutex::new(Pending::default()),
            nonces: NonceSource::new(),
            ignored: AtomicU64::new(0),
            stop: Notify::new(),
        });
        let owner = Arc::clone(&shared);
        let task = tokio::spawn(async move { owner.run().await });
        Self {
            shared,
            task: AsyncMutex::new(Some(task)),
        }
    }

    /// This node's public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.shared.transport.public_key()
    }

    /// Datagrams that were not a valid probe or reply for this bridge: malformed
    /// frames, probes from keys it does not serve, and replies nobody awaits.
    pub fn ignored_frames(&self) -> u64 {
        self.shared.ignored.load(Ordering::Relaxed)
    }

    /// Prove that `peer` is reachable: send probes until the peer answers with the same
    /// nonce from its own key, and return the time until that reply (resends included).
    /// Cancel-safe.
    pub async fn probe(&self, peer: [u8; 32], deadline: Duration) -> Result<Duration, ProbeError> {
        let shared = &*self.shared;
        let started = Instant::now();
        let end = started + deadline;
        let nonce = shared.nonces.next();
        let (done, mut reply) = oneshot::channel();
        shared.pending().register(nonce, Waiter { peer, done })?;
        let _registered = Registered { shared, nonce };
        let ping = Frame {
            kind: Kind::Ping,
            nonce,
        }
        .encode();
        loop {
            match timeout_at(end, shared.transport.send_to(&peer, &ping)).await {
                Ok(Err(YggError::Closed)) => return Err(ProbeError::Closed),
                Err(_) => return Err(ProbeError::TimedOut),
                // Sent, or refused for now: either way wait for the reply and try again.
                Ok(_) => {}
            }
            match timeout_at((Instant::now() + RESEND).min(end), &mut reply).await {
                Ok(Ok(())) => return Ok(started.elapsed()),
                Ok(Err(_)) => return Err(ProbeError::Closed),
                Err(_) if Instant::now() >= end => return Err(ProbeError::TimedOut),
                Err(_) => {}
            }
        }
    }

    /// Stop the owner task, wait for it, release every waiting probe and close the
    /// transport. Idempotent; concurrent callers are serialized.
    pub async fn close(&self) -> Result<(), YggError> {
        let mut task = self.task.lock().await;
        self.shared.pending().close();
        self.shared.stop.notify_one();
        let Some(handle) = task.take() else {
            // An earlier call already joined the task and closed the transport.
            return Ok(());
        };
        let _ = handle.await;
        self.shared.transport.close().await
    }

    #[cfg(test)]
    pub(crate) fn pending_probes(&self) -> usize {
        self.shared.pending().len()
    }
}
