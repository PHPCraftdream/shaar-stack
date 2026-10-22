//! Bounded two-endpoint datagram fixture, not a production transport.
//!
//! Queue state and wake registration share a short mutex critical section;
//! no lock spans an await or a wake callback. Shared senders may be polled by
//! several tasks. Waiter storage is bounded; exceeding it fails explicitly.
//! Cancelled wakers are retained only until the next drain or link closure.

use std::{
    collections::VecDeque,
    io,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use iroh::endpoint::transports::{CustomEndpoint, CustomSender, RecvInfo, Transmit};
use iroh_base::CustomAddr;
use n0_watcher::Watchable;
use noq_udp::RecvMeta;

pub const TEST_TRANSPORT_ID: u64 = 0x20;
pub const MAX_PACKET: usize = 1500;
const QUEUE_CAP: usize = 64;
const MAX_WAITERS: usize = 64;
const CAPTURE_CAP: usize = 256;

#[derive(Debug, Default)]
pub struct DirectionStats {
    wire_bytes: AtomicU64,
    wire_packets: AtomicU64,
    delivered_bytes: AtomicU64,
    delivered_packets: AtomicU64,
    address_checks: AtomicU64,
    valid_addresses: AtomicU64,
    send_attempts: AtomicU64,
}

impl DirectionStats {
    pub fn wire_bytes(&self) -> u64 {
        self.wire_bytes.load(Ordering::Relaxed)
    }
    pub fn wire_packets(&self) -> u64 {
        self.wire_packets.load(Ordering::Relaxed)
    }
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes.load(Ordering::Relaxed)
    }
    pub fn delivered_packets(&self) -> u64 {
        self.delivered_packets.load(Ordering::Relaxed)
    }
    pub fn address_checks(&self) -> u64 {
        self.address_checks.load(Ordering::Relaxed)
    }
    pub fn valid_addresses(&self) -> u64 {
        self.valid_addresses.load(Ordering::Relaxed)
    }
    pub fn send_attempts(&self) -> u64 {
        self.send_attempts.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
struct Lane {
    packets: VecDeque<Vec<u8>>,
    receiver: Option<Waker>,
    writers: Vec<Waker>,
}

#[derive(Debug, Default)]
struct State {
    lanes: [Lane; 2],
    bound: [bool; 2],
    closed: bool,
    capture: Option<[Vec<Vec<u8>>; 2]>,
}

#[derive(Debug)]
pub struct MemNetwork {
    state: Mutex<State>,
    stats: [DirectionStats; 2],
    addresses: [CustomAddr; 2],
}

impl MemNetwork {
    /// Counters for the outgoing direction `side -> 1 - side`.
    pub fn stats(&self, side: usize) -> &DirectionStats {
        &self.stats[side % 2]
    }

    pub fn local_addr(&self, side: usize) -> CustomAddr {
        self.addresses[side % 2].clone()
    }

    /// Enable bounded ciphertext capture before either endpoint binds.
    pub fn enable_capture(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("memory link poisoned"))?;
        if state.closed || state.bound.iter().any(|bound| *bound) || state.capture.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "capture must be enabled once before bind",
            ));
        }
        state.capture = Some(Default::default());
        Ok(())
    }

    /// Take at most 256 successfully enqueued datagrams per direction.
    pub fn take_capture(&self) -> io::Result<Option<[Vec<Vec<u8>>; 2]>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("memory link poisoned"))?;
        Ok(state.capture.take())
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.closed = true;
        let mut wake = Vec::new();
        for lane in &mut state.lanes {
            lane.packets.clear();
            wake.extend(lane.receiver.take());
            wake.append(&mut lane.writers);
        }
        drop(state);
        for waker in wake {
            waker.wake();
        }
    }
}

#[derive(Debug)]
pub struct MemTransport {
    side: usize,
    network: Arc<MemNetwork>,
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
}

impl MemTransport {
    pub fn pair() -> (Arc<Self>, Arc<Self>, Arc<MemNetwork>) {
        let network = Arc::new(MemNetwork {
            state: Mutex::new(State::default()),
            stats: Default::default(),
            addresses: [
                CustomAddr::from_parts(TEST_TRANSPORT_ID, &[0]),
                CustomAddr::from_parts(TEST_TRANSPORT_ID, &[1]),
            ],
        });
        let transport = |side| {
            Arc::new(Self {
                side,
                network: network.clone(),
                addresses: Arc::new(Watchable::new(vec![network.local_addr(side)])),
            })
        };
        (transport(0), transport(1), network)
    }
}

impl iroh::endpoint::transports::CustomTransport for MemTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let mut state = self
            .network
            .state
            .lock()
            .map_err(|_| io::Error::other("memory link poisoned"))?;
        if state.closed || state.bound[self.side] {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "memory side unavailable",
            ));
        }
        state.bound[self.side] = true;
        Ok(Box::new(Endpoint {
            side: self.side,
            network: self.network.clone(),
            addresses: self.addresses.clone(),
        }))
    }
}

#[derive(Debug)]
struct Endpoint {
    side: usize,
    network: Arc<MemNetwork>,
    // Keep the publisher alive after the transport factory is dropped.
    addresses: Arc<Watchable<Vec<CustomAddr>>>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // Closing an owned endpoint ends this fixture's entire duplex link.
        self.network.close();
    }
}

impl CustomEndpoint for Endpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addresses.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(Sender {
            side: self.side,
            network: self.network.clone(),
        })
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
                "invalid receive slots",
            )));
        }
        let mut state = match self.network.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io::Error::other("memory link poisoned"))),
        };
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let lane = &mut state.lanes[self.side];
        if lane.packets.is_empty() {
            lane.receiver = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut count = 0;
        let mut bytes = 0;
        while count < bufs.len() {
            let Some(packet) = lane.packets.front() else {
                break;
            };
            if packet.len() > bufs[count].len() {
                if count == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "receive slot too small",
                    )));
                }
                break;
            }
            // The front packet was checked while this same lock is held.
            let packet = lane.packets.pop_front().expect("front packet exists");
            bufs[count][..packet.len()].copy_from_slice(&packet);
            metas[count] = RecvMeta::default();
            metas[count].len = packet.len();
            metas[count].stride = packet.len();
            infos[count] = RecvInfo::new(
                self.network.local_addr(1 - self.side),
                Some(self.network.local_addr(self.side)),
            );
            bytes += packet.len() as u64;
            count += 1;
        }
        let wake = std::mem::take(&mut lane.writers);
        let stats = self.network.stats(1 - self.side);
        stats.delivered_bytes.fetch_add(bytes, Ordering::Relaxed);
        stats
            .delivered_packets
            .fetch_add(count as u64, Ordering::Relaxed);
        drop(state);
        for waker in wake {
            waker.wake();
        }
        Poll::Ready(Ok(count))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

#[derive(Debug)]
struct Sender {
    side: usize,
    network: Arc<MemNetwork>,
}

impl Sender {
    fn send_packet(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        packet: &[u8],
    ) -> Poll<io::Result<()>> {
        if dst != &self.network.local_addr(1 - self.side)
            || packet.is_empty()
            || packet.len() > MAX_PACKET
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid datagram",
            )));
        }
        let mut state = match self.network.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(io::Error::other("memory link poisoned"))),
        };
        if state.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if state
            .capture
            .as_ref()
            .is_some_and(|capture| capture[self.side].len() == CAPTURE_CAP)
        {
            return Poll::Ready(Err(io::Error::other("ciphertext capture limit")));
        }
        let lane = &mut state.lanes[1 - self.side];
        if lane.packets.len() == QUEUE_CAP {
            if !lane.writers.iter().any(|waker| waker.will_wake(cx.waker())) {
                if lane.writers.len() == MAX_WAITERS {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "capacity waiter limit",
                    )));
                }
                lane.writers.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        lane.packets.push_back(packet.to_vec());
        let wake = lane.receiver.take();
        if let Some(capture) = &mut state.capture {
            capture[self.side].push(packet.to_vec());
        }
        let stats = self.network.stats(self.side);
        stats
            .wire_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        stats.wire_packets.fetch_add(1, Ordering::Relaxed);
        drop(state);
        if let Some(waker) = wake {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl CustomSender for Sender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        let stats = self.network.stats(self.side);
        stats.address_checks.fetch_add(1, Ordering::Relaxed);
        let valid = addr == &self.network.local_addr(1 - self.side);
        if valid {
            stats.valid_addresses.fetch_add(1, Ordering::Relaxed);
        }
        valid
    }

    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        self.network
            .stats(self.side)
            .send_attempts
            .fetch_add(1, Ordering::Relaxed);
        if src.is_some_and(|addr| addr != &self.network.local_addr(self.side))
            || transmit
                .segment_size
                .is_some_and(|size| size != transmit.contents.len())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported datagram layout",
            )));
        }
        self.send_packet(cx, dst, transmit.contents)
    }
}

#[cfg(test)]
#[path = "mem_tests.rs"]
mod tests;
