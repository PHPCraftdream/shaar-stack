use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
        behaviour::{FromSwarm, toggle::Toggle},
    },
};
use std::task::{Context, Poll};

use crate::discovery::roles::{self, AttemptKey, View};

#[derive(Clone, Copy)]
struct Connection {
    key: AttemptKey,
    established: bool,
}

/// Enables discovery handlers only on an owner's exact authenticated infrastructure attempt.
pub(in super::super) struct Guard<B: NetworkBehaviour> {
    inner: Toggle<B>,
    view: Option<View>,
    connections: [Option<Connection>; roles::INFRASTRUCTURE_CONNECTIONS],
    rejected_address: fn() -> B::ToSwarm,
}

impl<B: NetworkBehaviour> Guard<B> {
    pub(super) fn new(
        inner: Option<B>,
        view: Option<View>,
        rejected_address: fn() -> B::ToSwarm,
    ) -> Self {
        Self {
            inner: inner.into(),
            view,
            connections: [None; roles::INFRASTRUCTURE_CONNECTIONS],
            rejected_address,
        }
    }

    pub(super) fn as_mut(&mut self) -> Option<&mut B> {
        self.inner.as_mut()
    }

    fn pending(&self, id: ConnectionId, peer: PeerId) -> Option<AttemptKey> {
        let view = self.view.as_ref()?;
        let key = view.attempt_for_connection(id)?;
        (key.peer == peer && view.infrastructure_pending(key, tokio::time::Instant::now()))
            .then_some(key)
    }

    fn claim(&mut self, key: AttemptKey) -> Result<(), ConnectionDenied> {
        if let Some(entry) = self
            .connections
            .iter()
            .flatten()
            .find(|entry| entry.key.connection == key.connection)
        {
            return if entry.key == key && !entry.established {
                Ok(())
            } else {
                Err(ConnectionDenied::new(std::io::Error::other(
                    "duplicate discovery handler",
                )))
            };
        }
        if self
            .connections
            .iter()
            .flatten()
            .any(|entry| entry.key.peer == key.peer)
        {
            return Err(ConnectionDenied::new(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "discovery peer control is still owned",
            )));
        }
        let slot = self
            .connections
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| {
                ConnectionDenied::new(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "discovery handler capacity exhausted",
                ))
            })?;
        *slot = Some(Connection {
            key,
            established: false,
        });
        Ok(())
    }

    fn known(&self, id: ConnectionId, peer: PeerId) -> bool {
        self.connections
            .iter()
            .flatten()
            .any(|entry| entry.established && entry.key.connection == id && entry.key.peer == peer)
    }

    fn remove(&mut self, id: ConnectionId) {
        for slot in &mut self.connections {
            if slot.is_some_and(|entry| entry.key.connection == id) {
                *slot = None;
            }
        }
    }
}

impl<B: NetworkBehaviour> NetworkBehaviour for Guard<B> {
    type ConnectionHandler = <Toggle<B> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = B::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Toggle::<B>::from(None).handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(key) = peer
            .and_then(|peer| self.pending(id, peer))
            .filter(|_| self.inner.is_enabled())
        else {
            return Ok(Vec::new());
        };
        // Admission consumes the pending attempt when it authenticates the connection.
        self.claim(key)?;
        self.inner
            .handle_pending_outbound_connection(id, peer, addresses, role)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let entry = self
            .connections
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                slot.filter(|entry| {
                    !entry.established && entry.key.connection == id && entry.key.peer == peer
                })
                .map(|entry| (index, entry.key))
            });
        let Some((slot, key)) = entry.filter(|(_, key)| {
            self.view
                .as_ref()
                .is_some_and(|view| view.infrastructure_live(*key).is_some())
        }) else {
            return Toggle::<B>::from(None)
                .handle_established_outbound_connection(id, peer, address, role, port_use);
        };
        let handler = self
            .inner
            .handle_established_outbound_connection(id, peer, address, role, port_use)?;
        self.connections[slot] = Some(Connection {
            key,
            established: true,
        });
        Ok(handler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        let forward = match &event {
            FromSwarm::ConnectionEstablished(event) => {
                self.known(event.connection_id, event.peer_id)
            }
            FromSwarm::ConnectionClosed(event) => {
                let known = self.known(event.connection_id, event.peer_id);
                self.remove(event.connection_id);
                known
            }
            FromSwarm::DialFailure(event) => {
                self.remove(event.connection_id);
                // Rejected owner dials still need to terminate the child's original query.
                true
            }
            FromSwarm::AddressChange(_) | FromSwarm::NewExternalAddrOfPeer(_) => false,
            _ => true,
        };
        if forward {
            self.inner.on_swarm_event(event);
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        let live = self
            .connections
            .iter()
            .flatten()
            .find(|entry| entry.established && entry.key.connection == id && entry.key.peer == peer)
            .is_some_and(|entry| {
                self.view
                    .as_ref()
                    .is_some_and(|view| view.infrastructure_live(entry.key).is_some())
            });
        if live {
            self.inner.on_connection_handler_event(peer, id, event);
        }
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        match self.inner.poll(context) {
            Poll::Ready(
                ToSwarm::NewExternalAddrCandidate(_) | ToSwarm::NewExternalAddrOfPeer { .. },
            ) => Poll::Ready(ToSwarm::GenerateEvent((self.rejected_address)())),
            other => other,
        }
    }
}
