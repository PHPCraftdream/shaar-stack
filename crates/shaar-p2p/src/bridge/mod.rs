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

use crate::{CarrierHandle, Link, Received};
pub use driver::SignalingPump;
use state::{QUEUE, Shared};

struct Inbound {
    received: Received,
    source: CustomAddr,
}

/// A single-bind factory. Retaining it owns queues and observations, not Swarm sockets.
pub struct SignalingTransport {
    shared: Arc<Shared>,
    handle: CarrierHandle,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
    receiver: Mutex<Option<mpsc::Receiver<Inbound>>>,
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
        let addresses = Arc::new(Watchable::new(vec![shared.local.clone()]));
        let factory = Arc::new(Self {
            shared: shared.clone(),
            handle: handle.clone(),
            addresses,
            receiver: Mutex::new(Some(receiver)),
        });
        let pump = SignalingPump {
            shared,
            handle,
            incoming,
            deliver,
        };
        Ok((factory, pump))
    }

    /// Mints a local address for the current authenticated peer link, not a portable peer claim.
    /// No watcher guard or state lock is held across an await or I/O operation.
    pub fn peer_address(&self, peer: PeerId) -> io::Result<CustomAddr> {
        let links = self.handle.links();
        let current = links.borrow();
        self.shared.refresh(&current)?;
        self.shared.peer_address(peer)
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
