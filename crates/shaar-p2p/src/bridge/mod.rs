//! Caller-owned Iroh custom transport over authenticated signaling links.

mod driver;
mod state;
#[cfg(test)]
mod tests;

use std::{
    fmt, io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use libp2p::PeerId;
use n0_watcher::Watchable;
use tokio::sync::mpsc;

use crate::{CarrierHandle, Datagram, Link, MAX_DATAGRAM, Received};
pub use driver::SignalingPump;
use state::{QUEUE, Shared};

struct Inbound {
    received: Received,
    source: CustomAddr,
}

/// Prefix of a punch coordination message (leaf L4b). It rides an authenticated carrier link next
/// to the QUIC packets: signaling only, routed by the pump to the punch port and never to iroh.
pub const PUNCH_MAGIC: &[u8; 8] = b"shaar-pn";
const PUNCH_QUEUE: usize = 16;

/// One inbound punch message. The peer comes from the authenticated current link, never from the bytes.
pub struct PunchInbound {
    pub peer: PeerId,
    packet: Datagram,
}

impl PunchInbound {
    /// The message after the magic prefix.
    pub fn payload(&self) -> &[u8] {
        &self.packet.as_bytes()[PUNCH_MAGIC.len()..]
    }
}

/// The send half of the punch side channel: cloneable, so several workers can answer through the
/// one port whose receive half a single router owns.
#[derive(Clone)]
pub struct PunchSender {
    handle: CarrierHandle,
}

/// The single owner of the punch side channel of one signaling transport. Sending and receiving
/// need no pump task of their own: the pump classifies packets, the carrier handle sends.
pub struct PunchPort {
    sender: PunchSender,
    receiver: mpsc::Receiver<PunchInbound>,
}

impl PunchSender {
    /// Admits one message on the peer's current authenticated link; nothing is replayed on a
    /// successor link. Delivery is unreliable like any datagram.
    /// cancel-safe: NO — an admitted message may be delivered after waiter cancellation.
    pub async fn send(&self, peer: PeerId, payload: &[u8]) -> io::Result<()> {
        let length = PUNCH_MAGIC.len() + payload.len();
        if payload.is_empty() || length > MAX_DATAGRAM {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut bytes = [0_u8; MAX_DATAGRAM];
        bytes[..PUNCH_MAGIC.len()].copy_from_slice(PUNCH_MAGIC);
        bytes[PUNCH_MAGIC.len()..length].copy_from_slice(payload);
        let link = {
            let links = self.handle.links();
            let current = links.borrow();
            current
                .binary_search_by_key(&peer, |link| link.peer)
                .ok()
                .map(|index| current[index])
        }
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        self.handle
            .send_on(link, Datagram::new(&bytes[..length])?)
            .await
    }
}

impl PunchPort {
    /// The cloneable send half.
    pub fn sender(&self) -> PunchSender {
        self.sender.clone()
    }

    /// Same as [`PunchSender::send`].
    /// cancel-safe: NO — an admitted message may be delivered after waiter cancellation.
    pub async fn send(&self, peer: PeerId, payload: &[u8]) -> io::Result<()> {
        self.sender.send(peer, payload).await
    }

    /// The next inbound punch message; `None` once the transport is gone.
    /// cancel-safe: yes — a queued message stays queued.
    pub async fn recv(&mut self) -> Option<PunchInbound> {
        self.receiver.recv().await
    }
}

/// A single-bind factory. Retaining it owns queues and observations, not Swarm sockets.
pub struct SignalingTransport {
    shared: Arc<Shared>,
    handle: CarrierHandle,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
    receiver: Mutex<Option<mpsc::Receiver<Inbound>>>,
    punch: Mutex<Option<mpsc::Receiver<PunchInbound>>>,
}

impl fmt::Debug for SignalingTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignalingTransport(..)")
    }
}

impl SignalingTransport {
    /// Attaches the sole incoming receiver; neither this factory nor its pump spawns a root task.
    /// Drive the pump alongside Carrier::run, and stop/join both during endpoint shutdown.
    pub fn attach(
        handle: CarrierHandle,
        incoming: mpsc::Receiver<Received>,
    ) -> io::Result<(Arc<Self>, SignalingPump)> {
        let shared = Arc::new(Shared::new()?);
        {
            let links = handle.links();
            shared.refresh(&links.borrow())?;
        }
        let (deliver, receiver) = mpsc::channel(QUEUE);
        let (punch_tx, punch_rx) = mpsc::channel(PUNCH_QUEUE);
        let addresses = Arc::new(Watchable::new(vec![shared.local.clone()]));
        let factory = Arc::new(Self {
            shared: shared.clone(),
            handle: handle.clone(),
            addresses,
            receiver: Mutex::new(Some(receiver)),
            punch: Mutex::new(Some(punch_rx)),
        });
        let pump = SignalingPump {
            shared,
            handle,
            incoming,
            deliver,
            punch: punch_tx,
        };
        Ok((factory, pump))
    }

    /// Takes the punch side channel once (leaf L4b); a second call returns `None`.
    pub fn punch_port(&self) -> Option<PunchPort> {
        let receiver = self.punch.lock().ok()?.take()?;
        Some(PunchPort {
            sender: PunchSender {
                handle: self.handle.clone(),
            },
            receiver,
        })
    }

    /// Mints a local address for the current authenticated peer link, not a portable peer claim.
    /// No watcher guard or state lock is held across an await or I/O operation.
    pub fn peer_address(&self, peer: PeerId) -> io::Result<CustomAddr> {
        let links = self.handle.links();
        let current = links.borrow();
        self.shared.refresh(&current)?;
        self.shared.peer_address(peer)
    }

    /// Resolves only a current locally minted source, for final TLS-peer and epoch validation.
    /// The returned observation does not authorize later I/O or keep the link alive.
    pub fn authenticated_link(&self, address: &CustomAddr) -> io::Result<Link> {
        let links = self.handle.links();
        let current = links.borrow();
        self.shared.refresh(&current)?;
        self.shared.link(address)
    }
}

impl CustomTransport for SignalingTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        if *self.shared.closed.borrow() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| io::Error::other("signaling receiver state unavailable"))?
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrInUse))?;
        Ok(Box::new(Bound {
            shared: self.shared.clone(),
            handle: self.handle.clone(),
            addresses: self.addresses.clone(),
            receiver,
        }))
    }
}

struct Bound {
    shared: Arc<Shared>,
    handle: CarrierHandle,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
    receiver: mpsc::Receiver<Inbound>,
}
impl fmt::Debug for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignalingEndpoint(..)")
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        self.shared.close();
    }
}
impl CustomEndpoint for Bound {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addresses.watch()
    }
    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(Sender(self.shared.clone()))
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty()
            || bufs.len() != metas.len()
            || bufs.len() != infos.len()
            || bufs.len() > noq_udp::BATCH_SIZE
        {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let mut count = 0;
        for _ in 0..QUEUE {
            let input = match self.receiver.poll_recv(cx) {
                Poll::Pending if count == 0 => return Poll::Pending,
                Poll::Pending => return Poll::Ready(Ok(count)),
                Poll::Ready(None) if count == 0 => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(count)),
                Poll::Ready(Some(input)) => input,
            };
            let link = Link {
                peer: input.received.peer,
                connection: input.received.connection,
                route: input.received.route,
            };
            if !self.handle.is_current(&input.received) || !self.shared.matches(&input.source, link)
            {
                continue;
            }
            let bytes = input.received.packet.as_bytes();
            if bytes.len() > bufs[count].len() {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            bufs[count][..bytes.len()].copy_from_slice(bytes);
            metas[count] = noq_udp::RecvMeta::default();
            metas[count].len = bytes.len();
            metas[count].stride = bytes.len();
            infos[count] = RecvInfo::new(input.source, Some(self.shared.local.clone()));
            count += 1;
            if count == bufs.len() {
                return Poll::Ready(Ok(count));
            }
        }
        if count != 0 {
            Poll::Ready(Ok(count))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct Sender(Arc<Shared>);
impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignalingSender(..)")
    }
}
impl CustomSender for Sender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        self.0.accepts(addr)
    }
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        if src.is_some_and(|src| src != &self.0.local)
            || transmit
                .segment_size
                .is_some_and(|size| size != transmit.contents.len())
        {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        self.0.poll_send(cx, dst, transmit.contents)
    }
}
