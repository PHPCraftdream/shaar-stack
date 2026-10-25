use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    io,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, behaviour::FromSwarm, dummy,
    },
};

use super::{PEER_LIMIT, PENDING_LIMIT, RELAY_LIMIT, capacity};

/// Single Swarm owner; bounds apply before Noise negotiation and handler creation.
pub(super) struct Admission {
    allowed: Box<[PeerId]>,
    pending: HashMap<ConnectionId, Option<PeerId>>,
    connected: HashMap<PeerId, ConnectionId>,
    relays: HashSet<PeerId>,
}

impl Admission {
    pub(super) fn new(mut peers: Vec<PeerId>) -> io::Result<Self> {
        if peers.len() > PEER_LIMIT {
            return Err(capacity());
        }
        peers.sort_unstable();
        peers.dedup();
        Ok(Self {
            allowed: peers.into_boxed_slice(),
            pending: HashMap::with_capacity(PENDING_LIMIT),
            connected: HashMap::with_capacity(PEER_LIMIT + RELAY_LIMIT),
            relays: HashSet::with_capacity(RELAY_LIMIT),
        })
    }

    pub(super) fn allows(&self, peer: &PeerId) -> bool {
        self.allowed.binary_search(peer).is_ok()
    }

    pub(super) fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        self.connected.get(peer).copied()
    }

    pub(super) fn authorize_relay(&mut self, peer: PeerId) -> io::Result<()> {
        if self.allows(&peer) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay and application identities must be distinct",
            ));
        }
        if !self.relays.contains(&peer) && self.relays.len() >= RELAY_LIMIT {
            return Err(capacity());
        }
        self.relays.insert(peer);
        Ok(())
    }

    pub(super) fn pending_peer(&self, peer: PeerId) -> bool {
        self.pending.values().any(|pending| *pending == Some(peer))
    }

    pub(super) fn forget_relay(&mut self, peer: PeerId) {
        if !self.connected.contains_key(&peer) && !self.pending_peer(peer) {
            self.relays.remove(&peer);
        }
    }

    fn permits(&self, peer: &PeerId) -> bool {
        self.allows(peer) || self.relays.contains(peer)
    }

    fn pending(&mut self, id: ConnectionId, peer: Option<PeerId>) -> Result<(), ConnectionDenied> {
        if self.pending.len() >= PENDING_LIMIT {
            return Err(ConnectionDenied::new(capacity()));
        }
        self.pending.insert(id, peer);
        Ok(())
    }

    fn established(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
    ) -> Result<dummy::ConnectionHandler, ConnectionDenied> {
        self.pending.remove(&id);
        if !self.permits(&peer) {
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "carrier peer not allowed",
            )));
        }
        if self.connected.len() >= PEER_LIMIT + RELAY_LIMIT || self.connected.contains_key(&peer) {
            return Err(ConnectionDenied::new(capacity()));
        }
        Ok(dummy::ConnectionHandler)
    }
}

impl NetworkBehaviour for Admission {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.pending(id, None)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if !peer.is_some_and(|peer| self.permits(&peer)) {
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "carrier peer not allowed",
            )));
        }
        self.pending(id, peer)?;
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if !self.allows(&peer) {
            self.pending.remove(&id);
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsolicited infrastructure connection",
            )));
        }
        self.established(id, peer)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.established(id, peer)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.pending.remove(&event.connection_id);
                self.connected.insert(event.peer_id, event.connection_id);
            }
            FromSwarm::ConnectionClosed(event) => {
                if self.connected.get(&event.peer_id) == Some(&event.connection_id) {
                    self.connected.remove(&event.peer_id);
                }
            }
            FromSwarm::DialFailure(event) => {
                self.pending.remove(&event.connection_id);
            }
            FromSwarm::ListenFailure(event) => {
                self.pending.remove(&event.connection_id);
            }
            _ => {} // Other lifecycle notifications do not allocate admission state.
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // No queued events; only Swarm callbacks modify this behaviour.
        Poll::Pending
    }
}
