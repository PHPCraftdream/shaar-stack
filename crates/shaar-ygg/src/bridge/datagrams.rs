//! Locally registered peer capabilities; the bridge task alone owns the registry.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout_at};

use super::{Shared, codec};
use crate::YggError;

/// Maximum live peer capabilities and admitted registration requests per bridge.
pub const MAX_DATAGRAM_PEERS: usize = 16;
/// Maximum queued carrier datagrams per peer; a full queue drops incoming datagrams.
pub const DATAGRAM_QUEUE_CAPACITY: usize = 16;

/// Carrier capability failure, never an application-data authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramError {
    /// The bridge is closed or its reader stopped.
    Closed,
    /// This registration owner closed or was dropped.
    Revoked,
    /// The request queue, peer registry or carrier-send budget is full.
    Busy,
    /// A live capability already owns the peer's receiver.
    AlreadyRegistered,
    /// The budget expired or cannot represent a future deadline.
    TimedOut,
    /// The envelope plus payload cannot fit the carrier MTU.
    Oversize { len: usize, mtu: usize },
    /// The core refused the carrier send.
    Transport(YggError),
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "bridge closed"),
            Self::Revoked => write!(f, "datagram capability revoked"),
            Self::Busy => write!(f, "datagram admission capacity reached"),
            Self::AlreadyRegistered => write!(f, "peer already registered"),
            Self::TimedOut => write!(f, "datagram operation deadline exceeded"),
            Self::Oversize { len, mtu } => {
                write!(f, "datagram of {len} bytes exceeds carrier mtu {mtu}")
            }
            Self::Transport(_) => write!(f, "datagram transport failed"),
        }
    }
}

impl std::error::Error for DatagramError {}

/// A clonable sender tied to one locally owned registration and authenticated peer.
#[derive(Clone)]
pub struct DatagramSender {
    shared: Arc<Shared>,
    peer: [u8; 32],
    live: Arc<AtomicBool>,
}

impl DatagramSender {
    /// Maximum inner datagram length after accounting for the carrier envelope.
    pub fn mtu(&self) -> usize {
        codec::max_len(self.shared.transport.mtu())
    }

    pub(crate) fn status(&self) -> Result<(), DatagramError> {
        check(&self.shared, &self.live)
    }

    pub(crate) fn revoke(&self) {
        self.live.store(false, Ordering::Release);
        self.shared.datagram_changed.notify_one();
    }

    /// Send one unreliable carrier datagram. Registration revocation refuses new admissions;
    /// already admitted or transmitted datagrams cannot be recalled.
    /// cancel-safe: NO — the core may complete an admitted send after cancellation.
    pub async fn send(&self, bytes: &[u8], budget: Duration) -> Result<(), DatagramError> {
        check(&self.shared, &self.live)?;
        let mtu = self.mtu();
        if bytes.len() > mtu || self.shared.transport.mtu() < codec::HEADER {
            return Err(DatagramError::Oversize {
                len: bytes.len(),
                mtu,
            });
        }
        let deadline = end(budget)?;
        let _permit = self
            .shared
            .datagram_sends
            .try_acquire()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => DatagramError::Closed,
                tokio::sync::TryAcquireError::NoPermits => DatagramError::Busy,
            })?;
        let frame = codec::encode(bytes).ok_or(DatagramError::Oversize {
            len: bytes.len(),
            mtu,
        })?;
        let result = timeout_at(deadline, self.shared.send_carrier(&self.peer, &frame))
            .await
            .map_err(|_| DatagramError::TimedOut)?;
        if Instant::now() >= deadline {
            return Err(DatagramError::TimedOut);
        }
        result.map_err(|error| match error {
            YggError::Closed => DatagramError::Closed,
            other => DatagramError::Transport(other),
        })
    }
}

/// The registration owner and its single receiver. Drop revokes cloned senders and discards
/// this queue; a new registration for the same peer receives a different queue.
pub struct PeerDatagrams {
    sender: DatagramSender,
    receiver: mpsc::Receiver<Vec<u8>>,
}

impl PeerDatagrams {
    pub fn peer_key(&self) -> [u8; 32] {
        self.sender.peer
    }

    pub fn sender(&self) -> DatagramSender {
        self.sender.clone()
    }

    /// Receive exactly one inner carrier datagram, preserving empty and probe-shaped data.
    /// cancel-safe: yes — the receiver and queued datagrams remain owned by this capability.
    pub async fn recv(&mut self) -> Result<Vec<u8>, DatagramError> {
        check(&self.sender.shared, &self.sender.live)?;
        let bytes = self.receiver.recv().await.ok_or(DatagramError::Closed)?;
        check(&self.sender.shared, &self.sender.live)?;
        Ok(bytes)
    }

    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Vec<u8>, DatagramError>> {
        if let Err(error) = check(&self.sender.shared, &self.sender.live) {
            return std::task::Poll::Ready(Err(error));
        }
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Some(bytes)) => {
                match check(&self.sender.shared, &self.sender.live) {
                    Ok(()) => std::task::Poll::Ready(Ok(bytes)),
                    Err(error) => std::task::Poll::Ready(Err(error)),
                }
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(DatagramError::Closed)),
        }
    }

    /// Revoke this local registration. Previously returned or transmitted data is not recalled.
    pub fn close(&mut self) {
        self.sender.live.store(false, Ordering::Release);
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
        self.sender.shared.datagram_changed.notify_one();
    }
}

impl Drop for PeerDatagrams {
    fn drop(&mut self) {
        self.close();
    }
}

fn check(shared: &Shared, live: &AtomicBool) -> Result<(), DatagramError> {
    if shared.closed.load(Ordering::Acquire) {
        Err(DatagramError::Closed)
    } else if !live.load(Ordering::Acquire) {
        Err(DatagramError::Revoked)
    } else {
        Ok(())
    }
}

fn end(budget: Duration) -> Result<Instant, DatagramError> {
    let now = Instant::now();
    now.checked_add(budget)
        .filter(|deadline| *deadline > now)
        .ok_or(DatagramError::TimedOut)
}

pub(super) struct Register {
    peer: [u8; 32],
    live: Arc<AtomicBool>,
    sender: mpsc::Sender<Vec<u8>>,
    reply: oneshot::Sender<Result<(), DatagramError>>,
}

pub(super) async fn open(
    shared: &Arc<Shared>,
    peer: [u8; 32],
    budget: Duration,
) -> Result<PeerDatagrams, DatagramError> {
    if shared.closed.load(Ordering::Acquire) {
        return Err(DatagramError::Closed);
    }
    let deadline = end(budget)?;
    // Non-queued admission precedes allocation of the receiver and its revocation state.
    let permit = shared
        .datagrams
        .try_reserve()
        .map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => DatagramError::Busy,
            mpsc::error::TrySendError::Closed(_) => DatagramError::Closed,
        })?;
    let live = Arc::new(AtomicBool::new(true));
    let (sender, receiver) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
    let capability = PeerDatagrams {
        sender: DatagramSender {
            shared: Arc::clone(shared),
            peer,
            live: Arc::clone(&live),
        },
        receiver,
    };
    let (reply, answered) = oneshot::channel();
    permit.send(Register {
        peer,
        live,
        sender,
        reply,
    });
    timeout_at(deadline, answered)
        .await
        .map_err(|_| DatagramError::TimedOut)?
        .map_err(|_| DatagramError::Closed)??;
    if Instant::now() >= deadline {
        return Err(DatagramError::TimedOut);
    }
    check(shared, &capability.sender.live)?;
    Ok(capability)
}

struct Entry {
    live: Arc<AtomicBool>,
    sender: mpsc::Sender<Vec<u8>>,
}

#[derive(Default)]
pub(super) struct Registry {
    peers: HashMap<[u8; 32], Entry>,
}

impl Registry {
    pub(super) fn prune(&mut self) {
        self.peers
            .retain(|_, entry| entry.live.load(Ordering::Acquire));
    }

    pub(super) fn register(&mut self, request: Register, closed: bool) {
        self.prune();
        let error = if closed || !request.live.load(Ordering::Acquire) {
            Some(DatagramError::Closed)
        } else if self.peers.contains_key(&request.peer) {
            Some(DatagramError::AlreadyRegistered)
        } else if self.peers.len() >= MAX_DATAGRAM_PEERS {
            Some(DatagramError::Busy)
        } else {
            None
        };
        if let Some(error) = error {
            let _ = request.reply.send(Err(error));
            return;
        }
        let peer = request.peer;
        let live = Arc::clone(&request.live);
        self.peers.insert(
            peer,
            Entry {
                live: request.live,
                sender: request.sender,
            },
        );
        // Cancellation after admission cannot leave an ownerless registration charged.
        if request.reply.send(Ok(())).is_err() {
            live.store(false, Ordering::Release);
            self.peers.remove(&peer);
        }
    }

    pub(super) fn deliver(&self, peer: &[u8; 32], bytes: &[u8]) -> bool {
        let Some(entry) = self.peers.get(peer) else {
            return false;
        };
        if !entry.live.load(Ordering::Acquire) {
            return false;
        }
        let Ok(permit) = entry.sender.try_reserve() else {
            return false;
        };
        // The shared receive scratch buffer cannot be borrowed by an asynchronous consumer.
        permit.send(bytes.to_vec());
        true
    }

    pub(super) fn close(&mut self) {
        for entry in self.peers.values() {
            entry.live.store(false, Ordering::Release);
        }
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Reply = oneshot::Receiver<Result<(), DatagramError>>;

    fn request(peer: u8) -> (Register, Arc<AtomicBool>, mpsc::Receiver<Vec<u8>>, Reply) {
        let live = Arc::new(AtomicBool::new(true));
        let (sender, receiver) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
        let (reply, response) = oneshot::channel();
        (
            Register {
                peer: [peer; 32],
                live: Arc::clone(&live),
                sender,
                reply,
            },
            live,
            receiver,
            response,
        )
    }

    #[test]
    fn session_key_dispatch_and_duplicate_registration_do_not_cross_queues() {
        let mut registry = Registry::default();
        let (entry, _live, mut rx, mut ack) = request(1);
        registry.register(entry, false);
        assert_eq!(ack.try_recv(), Ok(Ok(())));
        let (duplicate, _token, _rx, mut rejected) = request(1);
        registry.register(duplicate, false);
        assert_eq!(
            rejected.try_recv(),
            Ok(Err(DatagramError::AlreadyRegistered))
        );
        assert!(!registry.deliver(&[2; 32], b"wrong session key"));
        assert!(registry.deliver(&[1; 32], b"expected"));
        assert_eq!(rx.try_recv(), Ok(b"expected".to_vec()));
    }

    #[test]
    fn closing_and_revoked_requests_never_allocate_a_registry_entry() {
        for closing in [false, true] {
            let mut registry = Registry::default();
            let (entry, live, _rx, mut ack) = request(1);
            if !closing {
                live.store(false, Ordering::Release);
            }
            registry.register(entry, closing);
            assert_eq!(ack.try_recv(), Ok(Err(DatagramError::Closed)));
            assert!(registry.peers.is_empty());
        }
        assert_eq!(end(Duration::ZERO), Err(DatagramError::TimedOut));
        assert_eq!(end(Duration::MAX), Err(DatagramError::TimedOut));
    }

    #[test]
    fn queue_admission_is_bounded_and_never_waits_for_a_consumer() {
        let mut registry = Registry::default();
        let (entry, _live, mut rx, _ack) = request(1);
        registry.register(entry, false);
        for index in 0..DATAGRAM_QUEUE_CAPACITY {
            assert!(registry.deliver(&[1; 32], &[u8::try_from(index).expect("small index")]));
        }
        assert!(!registry.deliver(&[1; 32], b"overflow"));
        for index in 0..DATAGRAM_QUEUE_CAPACITY {
            assert_eq!(
                rx.try_recv(),
                Ok(vec![u8::try_from(index).expect("small index")])
            );
        }
        assert!(registry.deliver(&[1; 32], b"space recovered"));
    }

    #[test]
    fn cancelled_admission_is_not_charged_and_re_registration_has_a_fresh_queue() {
        let mut registry = Registry::default();
        let (entry, cancelled, _rx, ack) = request(1);
        drop(ack);
        registry.register(entry, false);
        assert!(registry.peers.is_empty());
        assert!(!cancelled.load(Ordering::Acquire));
        let (entry, old, mut old_rx, _ack) = request(1);
        registry.register(entry, false);
        assert!(registry.deliver(&[1; 32], b"old queue"));
        old.store(false, Ordering::Release);
        registry.prune();
        let (entry, fresh, mut fresh_rx, _ack) = request(1);
        registry.register(entry, false);
        assert!(fresh.load(Ordering::Acquire));
        assert!(fresh_rx.try_recv().is_err());
        assert!(registry.deliver(&[1; 32], b"new queue"));
        assert_eq!(fresh_rx.try_recv(), Ok(b"new queue".to_vec()));
        assert_eq!(old_rx.try_recv(), Ok(b"old queue".to_vec()));
        registry.close();
        assert!(!fresh.load(Ordering::Acquire));
        assert_eq!(
            fresh_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
    }
}
