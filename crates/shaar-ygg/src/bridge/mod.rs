//! One owner demultiplexes readiness probes and explicitly registered carrier datagrams.
//!
//! Readiness requires an authenticated nonce round trip, not merely an accepted send.
//! Carrier registrations authorize session-key peers; APP modes and reliability belong
//! above this unreliable datagram layer. Call `close` to prove joined shutdown.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout, timeout_at};

use crate::frame::{Frame, Kind, NonceSource};
use crate::pending::{Pending, Waiter};
use crate::{YggError, YggTransport};

mod carrier;
mod carrier_pump;
mod carrier_state;
mod codec;
#[cfg(test)]
mod datagram_tests;
mod datagrams;

pub use carrier::YggCarrier;
pub use carrier_pump::YggPump;

pub use datagrams::{
    DATAGRAM_QUEUE_CAPACITY, DatagramError, DatagramSender, MAX_DATAGRAM_PEERS, PeerDatagrams,
};
use datagrams::{Register, Registry};

/// Repeat probes because initial path discovery can swallow accepted sends.
const RESEND: Duration = Duration::from_millis(500);
/// The reader spends at most this long answering one probe.
const REPLY_BUDGET: Duration = Duration::from_millis(500);
/// Bound adapter-owned send buffers before framing allocation; probes do not use this budget.
const MAX_DATAGRAM_SENDS: usize = 16;

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
    queued_datagrams: AtomicU64,
    dropped_datagrams: AtomicU64,
    carrier_submitted_datagrams: AtomicU64,
    datagrams: mpsc::Sender<Register>,
    datagram_sends: Semaphore,
    datagram_changed: Notify,
    closed: AtomicBool,
    stop: Notify,
}

impl Shared {
    /// A few probe-table operations; never locked across an await.
    fn pending(&self) -> MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ignore(&self) {
        self.ignored.fetch_add(1, Ordering::Relaxed);
    }

    fn record_carrier_submission(&self) {
        let _ = self.carrier_submitted_datagrams.try_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |count| Some(count.saturating_add(1)),
        );
    }

    /// Records the boundary call before constructing its real transport future.
    /// The count proves helper invocation, not future polling or transport acceptance.
    fn send_carrier<'a>(
        &'a self,
        peer: &'a [u8; 32],
        frame: &'a [u8],
    ) -> impl std::future::Future<Output = Result<(), YggError>> + 'a {
        self.record_carrier_submission();
        self.transport.send_to(peer, frame)
    }

    async fn handle(&self, bytes: &[u8], from: [u8; 32], registry: &Registry) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if let Some(inner) = codec::decode(bytes) {
            let counter = if registry.deliver(&from, inner) {
                &self.queued_datagrams
            } else {
                &self.dropped_datagrams
            };
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
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

    async fn run(&self, mut requests: mpsc::Receiver<Register>) -> Result<(), YggError> {
        let mut registry = Registry::default();
        let mut buffer = vec![0u8; self.transport.mtu() + 1];
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                () = self.stop.notified() => break,
                () = self.datagram_changed.notified() => registry.prune(),
                request = requests.recv() => match request {
                    Some(request) => registry.register(request, self.closed.load(Ordering::Acquire)),
                    None => break,
                },
                read = self.transport.recv(&mut buffer) => match read {
                    Ok((len, from)) => self.handle(&buffer[..len], from, &registry).await,
                    Err(_) => break,
                },
            }
        }
        self.closed.store(true, Ordering::Release);
        self.datagram_sends.close();
        self.pending().close();
        registry.close();
        drop(requests);
        self.transport.close().await
    }
}

struct Registered<'a> {
    shared: &'a Shared,
    nonce: [u8; crate::frame::NONCE_LEN],
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.shared.pending().remove(&self.nonce);
    }
}

struct CloseState {
    task: Option<JoinHandle<Result<(), YggError>>>,
    cleanup: bool,
    outcome: Option<Result<(), YggError>>,
}

/// Probes peers and demultiplexes carrier datagrams for locally registered keys.
/// Call `close`: dropping this value alone does not stop its task.
pub struct YggBridge {
    shared: Arc<Shared>,
    task: AsyncMutex<CloseState>,
}

impl YggBridge {
    /// Take over the transport inside a Tokio runtime. `answer_to` controls probe replies;
    /// carrier delivery additionally requires an explicit local peer registration.
    pub fn new(transport: YggTransport, answer_to: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let (datagrams, requests) = mpsc::channel(MAX_DATAGRAM_PEERS);
        let shared = Arc::new(Shared {
            transport,
            answer_to: answer_to.into_iter().collect(),
            pending: Mutex::new(Pending::default()),
            nonces: NonceSource::new(),
            ignored: AtomicU64::new(0),
            queued_datagrams: AtomicU64::new(0),
            dropped_datagrams: AtomicU64::new(0),
            carrier_submitted_datagrams: AtomicU64::new(0),
            datagrams,
            datagram_sends: Semaphore::new(MAX_DATAGRAM_SENDS),
            datagram_changed: Notify::new(),
            closed: AtomicBool::new(false),
            stop: Notify::new(),
        });
        let owner = Arc::clone(&shared);
        let task = tokio::spawn(async move { owner.run(requests).await });
        Self {
            shared,
            task: AsyncMutex::new(CloseState {
                task: Some(task),
                cleanup: false,
                outcome: None,
            }),
        }
    }

    /// This node's public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.shared.transport.public_key()
    }

    /// Malformed envelopes/probes, unserved probes and unsolicited probe replies.
    pub fn ignored_frames(&self) -> u64 {
        self.shared.ignored.load(Ordering::Relaxed)
    }

    /// Valid carrier datagrams admitted to a capability queue, not consumer acknowledgements.
    pub fn queued_datagrams(&self) -> u64 {
        self.shared.queued_datagrams.load(Ordering::Relaxed)
    }

    /// Valid envelopes refused for missing/revoked registration or a full receiver.
    pub fn dropped_datagrams(&self) -> u64 {
        self.shared.dropped_datagrams.load(Ordering::Relaxed)
    }

    /// Carrier send invocations; excludes Ping/Pong.
    /// Counts attempts even when the returned transport future fails, times out or is cancelled.
    pub fn carrier_submitted_datagrams(&self) -> u64 {
        self.shared
            .carrier_submitted_datagrams
            .load(Ordering::Relaxed)
    }

    /// Register the expected authenticated session key. Only local code can create this
    /// capability; callers must apply their peer policy before registration.
    /// cancel-safe: yes — dropping an unacknowledged capability revokes its registration.
    pub async fn open_datagrams(
        &self,
        peer: [u8; 32],
        budget: Duration,
    ) -> Result<PeerDatagrams, DatagramError> {
        datagrams::open(&self.shared, peer, budget).await
    }

    /// Prove reachability by an authenticated nonce round trip. Cancel-safe.
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

    /// Revoke registrations, stop the reader and join core/socket shutdown. Idempotent.
    /// cancel-safe: yes — the shutdown task remains owned across cancelled waiters.
    pub async fn close(&self) -> Result<(), YggError> {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.datagram_sends.close();
        self.shared.pending().close();
        self.shared.stop.notify_one();
        // Shutdown alone serializes access to its retained join; datagrams never take this lock.
        let mut state = self.task.lock().await;
        loop {
            if let Some(outcome) = &state.outcome {
                return outcome.clone();
            }
            let result = state.task.as_mut().expect("owned shutdown task").await;
            state.task = None;
            match result {
                Ok(outcome) => {
                    state.outcome = Some(outcome.clone());
                    return outcome;
                }
                Err(_) if !state.cleanup => {
                    // A failed reader is replaced once by a retained cleanup task, never detached.
                    state.cleanup = true;
                    let shared = Arc::clone(&self.shared);
                    state.task = Some(tokio::spawn(async move { shared.transport.close().await }));
                }
                Err(_) => {
                    let error = YggError::Io("bridge shutdown task failed".into());
                    state.outcome = Some(Err(error.clone()));
                    return Err(error);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_probes(&self) -> usize {
        self.shared.pending().len()
    }
}
