use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, behaviour::FromSwarm, dial_opts::DialOpts,
    },
};
use std::task::{Context, Poll};

type Constrain<B> = fn(
    &B,
    ConnectionId,
    Option<PeerId>,
    &[Multiaddr],
    &mut Vec<Multiaddr>,
) -> Result<(), ConnectionDenied>;

/// Checks child addresses and hands dependency dials to the carrier owner.
pub(super) struct Boundary<B: NetworkBehaviour> {
    pub(super) inner: B,
    pub(super) constrain: Constrain<B>,
    pub(super) dial_event: fn(DialOpts) -> B::ToSwarm,
}

impl<B: NetworkBehaviour> NetworkBehaviour for Boundary<B> {
    type ConnectionHandler = B::ConnectionHandler;
    type ToSwarm = B::ToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_inbound_connection(id, peer, local, remote)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let mut additional = self
            .inner
            .handle_pending_outbound_connection(id, peer, addresses, role)?;
        (self.constrain)(&self.inner, id, peer, addresses, &mut additional)?;
        Ok(additional)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_outbound_connection(id, peer, address, role, port_use)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, event);
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        match self.inner.poll(context) {
            Poll::Ready(ToSwarm::Dial { opts }) => {
                Poll::Ready(ToSwarm::GenerateEvent((self.dial_event)(opts)))
            }
            other => other,
        }
    }
}

#[cfg(test)]
#[path = "boundary/tests.rs"]
mod tests;
