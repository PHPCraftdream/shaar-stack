#![forbid(unsafe_code)]
//! One-connection CI custom transport. Tokio owns readiness; no detached I/O tasks.

use super::protocol::{self, FRAME_MAX, Kind, Nonce};
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use n0_watcher::Watchable;
use noq_udp::RecvMeta;
use std::{
    io,
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::ReadBuf, net::UdpSocket, time::MissedTickBehavior};

const TRANSPORT_ID: u64 = 0x30;

#[derive(Debug)]
struct Shared {
    socket: UdpSocket,
    relay: SocketAddr,
    nonce: Nonce,
    side: u8,
    local: CustomAddr,
    remote: CustomAddr,
    bound: AtomicBool,
    closed: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
}

impl Shared {
    fn local(&self) -> CustomAddr {
        self.local.clone()
    }
    fn remote(&self) -> CustomAddr {
        self.remote.clone()
    }
}

#[derive(Debug)]
pub struct Factory {
    shared: Arc<Shared>,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
}

impl Factory {
    /// cancel-safe: NO — cancellation closes this registration socket; registration is not retried on it.
    pub async fn register(
        bind: SocketAddr,
        relay: SocketAddr,
        nonce: Nonce,
        side: u8,
    ) -> io::Result<Arc<Self>> {
        if side > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixture side must be zero or one",
            ));
        }
        let socket = UdpSocket::bind(bind).await?;
        let mut output = [0; FRAME_MAX];
        let request = protocol::encode(&mut output, &nonce, Kind::Register, side, &[])?;
        let mut input = [0; FRAME_MAX + 1];
        let registration = async {
            let mut retry = tokio::time::interval(Duration::from_millis(100));
            retry.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = retry.tick() => {
                        if socket.send_to(request, relay).await? != request.len() {
                            return Err(io::Error::other("partial fixture registration"));
                        }
                    }
                    received = socket.recv_from(&mut input) => {
                        let (length, source) = received?;
                        if source != relay { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unexpected relay source")); }
                        let frame = protocol::decode(&input[..length], &nonce)?;
                        if frame.kind == Kind::Ready && frame.side == side { return Ok(()); }
                        // Reordered DATA also implies relay registration. Losing this first control
                        // datagram is ordinary UDP loss; the real QUIC handshake retransmits it.
                        if frame.kind == Kind::Data && frame.side == 1 - side { return Ok(()); }
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected registration response"));
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), registration)
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "relay registration deadline")
            })??;
        let shared = Arc::new(Shared {
            socket,
            relay,
            nonce,
            side,
            local: CustomAddr::from_parts(TRANSPORT_ID, &[side]),
            remote: CustomAddr::from_parts(TRANSPORT_ID, &[1 - side]),
            bound: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
        });
        let addresses = Arc::new(Watchable::new(vec![shared.local()]));
        Ok(Arc::new(Self { shared, addresses }))
    }

    pub fn bound_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }
    pub fn local_addr(&self) -> CustomAddr {
        self.shared.local()
    }
    pub fn remote_addr(&self) -> CustomAddr {
        self.shared.remote()
    }
    pub fn stats(&self) -> (u64, u64) {
        (
            self.shared.sent.load(Ordering::Relaxed),
            self.shared.received.load(Ordering::Relaxed),
        )
    }
}

impl CustomTransport for Factory {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        self.shared
            .bound
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::new(io::ErrorKind::AddrInUse, "fixture already bound"))?;
        Ok(Box::new(Bound {
            shared: self.shared.clone(),
            addresses: self.addresses.clone(),
            scratch: [0; FRAME_MAX + 1],
        }))
    }
}

#[derive(Debug)]
struct Bound {
    shared: Arc<Shared>,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
    scratch: [u8; FRAME_MAX + 1],
}

impl Drop for Bound {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
    }
}

impl CustomEndpoint for Bound {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addresses.watch()
    }
    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(Sender(self.shared.clone()))
    }
    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
        infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || bufs.len() != metas.len() || bufs.len() != infos.len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fixture receive slots",
            )));
        }
        for _ in 0..16 {
            let mut input = ReadBuf::new(&mut self.scratch);
            let source = match self.shared.socket.poll_recv_from(cx, &mut input) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(source)) => source,
            };
            if source != self.shared.relay {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unexpected relay source",
                )));
            }
            let frame = match protocol::decode(input.filled(), &self.shared.nonce) {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(error)),
            };
            // Registration retries may leave duplicate READY datagrams in the socket.
            if frame.kind == Kind::Ready && frame.side == self.shared.side {
                continue;
            }
            if frame.kind != Kind::Data
                || frame.side != 1 - self.shared.side
                || frame.payload.len() > bufs[0].len()
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid relay data",
                )));
            }
            bufs[0][..frame.payload.len()].copy_from_slice(frame.payload);
            metas[0] = RecvMeta::default();
            metas[0].len = frame.payload.len();
            metas[0].stride = frame.payload.len();
            infos[0] = RecvInfo::new(self.shared.remote(), Some(self.shared.local()));
            self.shared.received.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(1));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[derive(Debug)]
struct Sender(Arc<Shared>);
impl CustomSender for Sender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr == &self.0.remote
    }
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        if self.0.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if !self.is_valid_send_addr(dst)
            || src.is_some_and(|addr| addr != &self.0.local)
            || transmit
                .segment_size
                .is_some_and(|size| size != transmit.contents.len())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid fixture send address or layout",
            )));
        }
        let mut output = [0; FRAME_MAX];
        let bytes = match protocol::encode(
            &mut output,
            &self.0.nonce,
            Kind::Data,
            self.0.side,
            transmit.contents,
        ) {
            Ok(bytes) => bytes,
            Err(error) => return Poll::Ready(Err(error)),
        };
        match self.0.socket.poll_send_to(cx, bytes, self.0.relay) {
            Poll::Ready(Ok(length)) if length == bytes.len() => {
                self.0.sent.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::other("partial fixture datagram"))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}
