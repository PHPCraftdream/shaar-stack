//! An explicitly driven, bounded TCP/Noise/Yamux carrier, not a QUIC payload policy.

mod admission;
mod driver;

use std::{io, net::SocketAddr};

use libp2p::{PeerId, swarm::ConnectionId};
use tokio::sync::{mpsc, oneshot, watch};

use crate::Datagram;
pub use driver::Carrier;

const PEER_LIMIT: usize = 16;
const PENDING_LIMIT: usize = 8;
const QUEUE_LIMIT: usize = 32;
const REQUEST_LIMIT: usize = 32;

/// Source identity and connection come from authenticated Swarm events, never packet bytes.
#[derive(Debug)]
pub struct Received {
    pub peer: PeerId,
    pub connection: ConnectionId,
    pub packet: Datagram,
}

/// Submission capability only; retaining it does not retain the carrier's sockets.
#[derive(Clone)]
pub struct CarrierHandle {
    commands: mpsc::Sender<Command>,
    listening: watch::Receiver<Option<SocketAddr>>,
    peer: PeerId,
}

type Reply<T> = oneshot::Sender<io::Result<T>>;

// At most 32 queued inline packets; boxing would add a needless per-packet allocation.
#[allow(clippy::large_enum_variant)]
enum Command {
    Connect(PeerId, SocketAddr, Reply<ConnectionId>),
    Send(PeerId, Datagram, Reply<()>),
    Disconnect(PeerId, Reply<()>),
}

impl CarrierHandle {
    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    /// cancel-safe: yes — observes readiness without altering the driver.
    pub async fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut listening = self.listening.clone();
        loop {
            if self.commands.is_closed() {
                return Err(closed());
            }
            if let Some(address) = *listening.borrow_and_update() {
                return Ok(address);
            }
            listening.changed().await.map_err(|_| closed())?;
        }
    }

    /// Connects to an explicitly allowed peer, or reuses its authenticated connection.
    /// No automatic retries or address cache: a failed attempt is terminal.
    /// cancel-safe: NO — an admitted dial may finish after this waiter is dropped.
    pub async fn connect(&self, peer: PeerId, address: SocketAddr) -> io::Result<ConnectionId> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Connect(peer, address, reply))?;
        result.await.map_err(|_| closed())?
    }

    /// Acknowledgement means admission to the remote bounded queue, not application processing.
    /// Queue saturation fails immediately; it never creates an unbounded channel waiter.
    /// cancel-safe: NO — an admitted packet may be delivered after waiter cancellation.
    /// Do not retry an ambiguous result as though delivery were impossible.
    pub async fn send(&self, peer: PeerId, packet: Datagram) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Send(peer, packet, reply))?;
        result.await.map_err(|_| closed())?
    }

    /// Resolves after the connection-closed event, not merely after requesting close.
    /// cancel-safe: NO — cancellation does not undo an admitted disconnect.
    pub async fn disconnect(&self, peer: PeerId) -> io::Result<()> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Disconnect(peer, reply))?;
        result.await.map_err(|_| closed())?
    }

    fn submit(&self, command: Command) -> io::Result<()> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => capacity(),
                mpsc::error::TrySendError::Closed(_) => closed(),
            })
    }
}

fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "carrier admission limit reached")
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "carrier closed")
}

fn socket_address(address: &libp2p::Multiaddr) -> Option<SocketAddr> {
    use libp2p::multiaddr::Protocol;
    let mut parts = address.iter();
    let ip = match parts.next()? {
        Protocol::Ip4(ip) => ip.into(),
        Protocol::Ip6(ip) => ip.into(),
        _ => return None,
    };
    let Protocol::Tcp(port) = parts.next()? else {
        return None;
    };
    if parts.next().is_some() {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

fn multiaddr(address: SocketAddr) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let mut result = libp2p::Multiaddr::empty();
    match address.ip() {
        std::net::IpAddr::V4(ip) => result.push(Protocol::Ip4(ip)),
        std::net::IpAddr::V6(ip) => result.push(Protocol::Ip6(ip)),
    }
    result.push(Protocol::Tcp(address.port()));
    result
}
