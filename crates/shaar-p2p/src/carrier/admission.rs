use crate::discovery::roles::{self, AttemptKey, Root};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    io,
    task::{Context, Poll},
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

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
    owner: Option<roles::Owner>,
    native_permit: Option<Arc<dyn Fn(PeerId, &Multiaddr) -> bool + Send + Sync>>,
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
            owner: None,
            native_permit: None,
            pending: HashMap::with_capacity(PENDING_LIMIT),
            connected: HashMap::with_capacity(PEER_LIMIT + RELAY_LIMIT),
            relays: HashSet::with_capacity(RELAY_LIMIT),
        })
    }

    pub(super) fn with_authority(
        peers: Vec<PeerId>,
        owner: roles::Owner,
        native_permit: Option<Arc<dyn Fn(PeerId, &Multiaddr) -> bool + Send + Sync>>,
    ) -> io::Result<Self> {
        let mut admission = Self::new(peers)?;
        admission.owner = Some(owner);
        admission.native_permit = native_permit;
        Ok(admission)
    }

    pub(super) fn roles_view(&self) -> Option<roles::View> {
        self.owner.as_ref().map(roles::Owner::view)
    }

    pub(super) fn admit_identity(&mut self, peer: PeerId, role: roles::Role) -> io::Result<()> {
        if let Some(owner) = &mut self.owner {
            owner.admit_identity(peer, role)
        } else {
            Ok(())
        }
    }

    pub(super) fn stage_native(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        id: ConnectionId,
    ) -> io::Result<Option<AttemptKey>> {
        if self.owner.is_none() {
            return Ok(None);
        }
        let root = Root::new(address.as_ref(), peer)?;
        let Some(owner) = &mut self.owner else {
            return Ok(None);
        };
        let now = Instant::now();
        let key = owner.admit(peer, id, now + Duration::from_secs(10), now)?;
        if let Err(error) = owner.pin_root(key, root, now) {
            owner.terminal(key, None, now);
            return Err(error);
        }
        Ok(Some(key))
    }

    pub(super) fn terminal(
        &mut self,
        key: AttemptKey,
        authenticated: Option<PeerId>,
    ) -> Option<std::net::SocketAddr> {
        self.owner
            .as_mut()?
            .terminal(key, authenticated, Instant::now())
    }

    pub(super) fn close_authority(&mut self) {
        if let Some(owner) = &mut self.owner {
            owner.close();
        }
    }

    pub(super) fn allows(&self, peer: &PeerId) -> bool {
        if let Some(owner) = &self.owner {
            owner.view().role(*peer) == Some(roles::Role::Application)
        } else {
            self.allowed.binary_search(peer).is_ok()
        }
    }

    pub(super) fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        self.connected.get(peer).copied()
    }

    pub(super) fn application_connections(
        &self,
    ) -> impl Iterator<Item = (PeerId, ConnectionId)> + '_ {
        self.connected
            .iter()
            .filter_map(|(peer, connection)| self.allows(peer).then_some((*peer, *connection)))
    }

    pub(super) fn authorize_relay(&mut self, peer: PeerId) -> io::Result<()> {
        if let Some(owner) = &self.owner {
            return if matches!(owner.view().role(peer), Some(roles::Role::ExplicitRelay(_))) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "relay identity not admitted",
                ))
            };
        }
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
        if let Some(owner) = &self.owner {
            owner.view().current(peer, Instant::now()).is_some()
        } else {
            self.pending.values().any(|pending| *pending == Some(peer))
        }
    }

    pub(super) fn forget_relay(&mut self, peer: PeerId) {
        if !self.connected.contains_key(&peer) && !self.pending_peer(peer) {
            if let Some(owner) = &mut self.owner {
                let _ = owner.forget_identity(peer);
            } else {
                self.relays.remove(&peer);
            }
        }
    }

    fn permits(&self, peer: &PeerId) -> bool {
        if let Some(owner) = &self.owner {
            matches!(
                owner.view().role(*peer),
                Some(roles::Role::Application | roles::Role::ExplicitRelay(_))
            )
        } else {
            self.allows(peer) || self.relays.contains(peer)
        }
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
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if let Some(owner) = &mut self.owner {
            owner
                .admit_inbound_at(id, local, remote)
                .map_err(ConnectionDenied::new)
        } else {
            self.pending(id, None)
        }
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(view) = self.owner.as_ref().map(|owner| owner.view()) {
            if peer.is_none_or(|peer| !self.permits(&peer)) {
                return Err(ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "carrier peer not allowed",
                )));
            }
            let peer = peer.expect("checked above");
            if addresses.len() != 1 {
                return Err(ConnectionDenied::new(io::Error::from(
                    io::ErrorKind::PermissionDenied,
                )));
            }
            // Swarm qualifies after this hook; pin the identical address before admission.
            let qualified = addresses[0].clone().with_p2p(peer).map_err(|_| {
                ConnectionDenied::new(io::Error::from(io::ErrorKind::PermissionDenied))
            })?;
            let now = Instant::now();
            if let Some(key) = view.current(peer, now) {
                if key.connection != id || addresses.len() != 1 {
                    return Err(ConnectionDenied::new(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "destination authority unavailable",
                    )));
                }
                if view.matches_root(key, qualified.as_ref(), now) {
                    return Ok(Vec::new());
                }
                if view.is_child(key)
                    && self
                        .native_permit
                        .as_ref()
                        .is_some_and(|permit| permit(peer, &qualified))
                {
                    return Ok(Vec::new());
                }
                return Err(ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destination authority unavailable",
                )));
            }
            let role = view.role(peer);
            let application_child = role == Some(roles::Role::Application)
                && addresses.len() == 1
                && self
                    .native_permit
                    .as_ref()
                    .is_some_and(|permit| permit(peer, &qualified));
            if application_child {
                self.owner
                    .as_mut()
                    .expect("owner view came from owner")
                    .admit_child(peer, id, now + Duration::from_secs(10), now)
                    .map_err(ConnectionDenied::new)?;
                return Ok(Vec::new());
            }
            let exact_explicit = role
                .is_some_and(|role| matches!(role, roles::Role::ExplicitRelay(_)))
                && addresses.len() == 1
                && self
                    .native_permit
                    .as_ref()
                    .is_some_and(|permit| permit(peer, &qualified));
            if !exact_explicit {
                return Err(ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destination authority unavailable",
                )));
            }
            self.stage_native(peer, &qualified, id)
                .map_err(ConnectionDenied::new)?;
            return Ok(Vec::new());
        }
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
            if let Some(owner) = &mut self.owner {
                owner.finish_inbound(id);
            }
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsolicited infrastructure connection",
            )));
        }
        let result = self.established(id, peer);
        if let Some(owner) = &mut self.owner {
            owner.finish_inbound(id);
        }
        result
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(owner) = &mut self.owner {
            let now = Instant::now();
            let view = owner.view();
            let key = view.attempt_for_connection(id).ok_or_else(|| {
                ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destination authority unavailable",
                ))
            })?;
            let valid = if key.peer == peer {
                if view.is_child(key) {
                    owner.terminal_child(key, peer, now)
                } else {
                    owner.terminal(key, Some(peer), now).is_some()
                }
            } else {
                owner.terminal(key, None, now);
                false
            };
            if !valid {
                return Err(ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destination authority unavailable",
                )));
            }
        }
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
                if let Some(owner) = &mut self.owner {
                    let key = owner.view().attempt_for_connection(event.connection_id);
                    if let Some(key) = key {
                        owner.terminal(key, None, Instant::now());
                    }
                }
                self.pending.remove(&event.connection_id);
            }
            FromSwarm::ListenFailure(event) => {
                self.pending.remove(&event.connection_id);
                if let Some(owner) = &mut self.owner {
                    owner.finish_inbound(event.connection_id);
                }
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
