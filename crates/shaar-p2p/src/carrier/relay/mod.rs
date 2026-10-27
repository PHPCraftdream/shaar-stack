mod controller;
pub(crate) mod gate;
pub(super) mod native;
#[cfg(test)]
mod tests;

use std::{
    collections::{HashMap, HashSet, hash_map::RandomState},
    hash::BuildHasher,
    io,
    net::SocketAddr,
    time::Duration,
};

use libp2p::{
    Multiaddr, PeerId, Transport,
    core::{
        muxing::StreamMuxerBox,
        transport::{Boxed, ListenerId},
        upgrade,
    },
    identity::Keypair,
    multiaddr::Protocol,
    noise, relay as protocol,
    swarm::{ConnectionId, dial_opts::DialOpts},
    yamux,
};
use tokio::{
    sync::{oneshot, watch},
    time::Instant,
};

use super::super::{PEER_LIMIT, PENDING_LIMIT, RELAY_LIMIT, Reply, capacity, multiaddr};
use super::{Closing, Core, DEADLINE, Pending};

const RESERVATIONS: usize = 2;
const ADDRESSES: usize = 4;
const ADDRESS_BYTES: usize = 256;
const CIRCUIT_BYTES: u64 = 1024 * 1024;
const CIRCUIT_AGE: Duration = Duration::from_secs(120);
const HISTORY_AGE: Duration = Duration::from_secs(60);

/// A locally configured, pinned relay endpoint; never an unchecked peer address list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayAddr {
    peer: PeerId,
    address: SocketAddr,
}

impl RelayAddr {
    pub fn new(peer: PeerId, address: SocketAddr) -> io::Result<Self> {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid relay address",
            ));
        }
        Ok(Self { peer, address })
    }
    pub fn peer_id(self) -> PeerId {
        self.peer
    }
    pub fn socket_addr(self) -> SocketAddr {
        self.address
    }
    fn prefix(self) -> Multiaddr {
        multiaddr(self.address)
            .with(Protocol::P2p(self.peer))
            .with(Protocol::P2pCircuit)
    }
}

/// Snapshot, not ownership of the reservation or authority to extend its lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayLease {
    relay: RelayAddr,
    expires_at: Instant,
    generation: u64,
    control: ConnectionId,
}
impl RelayLease {
    pub fn relay(self) -> RelayAddr {
        self.relay
    }
    pub fn expires_at(self) -> Instant {
        self.expires_at
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
    pub fn connection_id(self) -> ConnectionId {
        self.control
    }
}

/// Direct means direct libp2p TCP, not a native QUIC application-data path.
/// Inbound circuits have no fabricated relay-hop attribution; the peer/connection remain authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Direct,
    Relayed {
        relay: Option<PeerId>,
        generation: u64,
    },
}

pub(super) fn transport(
    native: Boxed<(PeerId, StreamMuxerBox)>,
    key: &Keypair,
    factory: Option<protocol::client::OperationFactory>,
    roles: Option<crate::discovery::roles::View>,
) -> io::Result<(Boxed<(PeerId, StreamMuxerBox)>, protocol::client::Behaviour)> {
    // Discovery branch: owner-gated operations from trusted staged intent.
    // Legacy branch keeps `new` unchanged, byte-for-byte.
    let (relayed, behaviour) = match factory {
        Some(factory) => {
            protocol::client::new_with_operation_factory(key.public().to_peer_id(), factory)
        }
        None => protocol::client::new(key.public().to_peer_id()),
    };
    let relayed = relayed
        .map(|stream, _| {
            super::circuit_io::Budgeted::new(stream, CIRCUIT_BYTES, Instant::now() + CIRCUIT_AGE)
        })
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).map_err(io::Error::other)?)
        .multiplex(yamux::Config::default())
        .timeout(DEADLINE)
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
    let relayed = if let Some(roles) = roles {
        crate::dns::transport::Guard::child(relayed, roles)
            .map_err(io::Error::other)
            .boxed()
    } else {
        relayed.boxed()
    };
    Ok((
        relayed
            .or_transport(native)
            .map(|either, _| either.into_inner())
            .boxed(),
        behaviour,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Active,
    Stopping,
    Failed,
}
struct Record {
    address: RelayAddr,
    listener: Option<ListenerId>,
    control: Option<ConnectionId>,
    expiry: Option<Instant>,
    // Same number space as capability/route generations (gate counter).
    generation: u64,
    phase: Phase,
    deadline: Instant,
    forget_at: Instant,
    attempts: u8,
    failed: bool,
    addresses: HashSet<Multiaddr>,
    ready: Option<Reply<RelayLease>>,
    released: Option<Reply<()>>,
}
struct Target {
    address: RelayAddr,
    used: Instant,
}

pub(super) struct State {
    records: HashMap<PeerId, Record>,
    targets: HashMap<PeerId, Target>,
    pub(super) routes: HashMap<ConnectionId, Route>,
    snapshots: watch::Sender<Vec<RelayLease>>,
    pub(super) gate: gate::Gate,
    jitter: RandomState,
    dirty: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        self.snapshots.send_replace(Vec::new());
    }
}

impl State {
    pub(super) fn new(gate: gate::Gate) -> (Self, watch::Receiver<Vec<RelayLease>>) {
        let (snapshots, receiver) = watch::channel(Vec::new());
        (
            Self {
                records: HashMap::with_capacity(RESERVATIONS),
                targets: HashMap::with_capacity(RELAY_LIMIT),
                routes: HashMap::with_capacity(PEER_LIMIT),
                snapshots,
                gate,
                jitter: RandomState::new(),
                dirty: false,
            },
            receiver,
        )
    }
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        let now = Instant::now();
        self.records
            .values()
            .map(|record| match record.phase {
                Phase::Pending | Phase::Stopping => record.deadline,
                Phase::Failed => record.forget_at,
                Phase::Active => record.expiry.unwrap_or(record.deadline),
            })
            .chain(
                self.targets
                    .values()
                    .map(|target| target.used + HISTORY_AGE)
                    .filter(|deadline| *deadline > now),
            )
            .min()
    }
    fn publish(&mut self, now: Instant) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let mut values: Vec<_> = self
            .records
            .values()
            .filter_map(|record| {
                if record.phase != Phase::Active || record.addresses.is_empty() {
                    return None;
                }
                let (Some(expires_at), Some(control)) = (record.expiry, record.control) else {
                    return None;
                };
                (expires_at > now).then_some(RelayLease {
                    relay: record.address,
                    expires_at,
                    generation: record.generation,
                    control,
                })
            })
            .collect();
        values.sort_unstable_by_key(|lease| lease.relay.peer);
        let changed = *self.snapshots.borrow() != values;
        if changed {
            self.snapshots.send_replace(values);
        }
    }
}
