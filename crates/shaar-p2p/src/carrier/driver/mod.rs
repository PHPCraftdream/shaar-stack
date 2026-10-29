use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, num::NonZeroUsize, time::Duration,
};

use futures::StreamExt;
use libp2p::{
    PeerId, StreamProtocol, Swarm, Transport,
    core::{muxing::StreamMuxerBox, transport::ListenerId, upgrade},
    identity::Keypair,
    multiaddr::Protocol,
    noise, request_response as rpc,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
    tcp, yamux,
};
use tokio::sync::{mpsc, watch};

use super::{
    CarrierHandle, Command, Link, PEER_LIMIT, PENDING_LIMIT, QUEUE_LIMIT, RELAY_LIMIT,
    REQUEST_LIMIT, Received, Reply, admission::Admission, capacity, multiaddr, socket_address,
};
use crate::discovery::roles::AttemptKey;
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use crate::dns::NumericOnly;
use crate::{
    CONTROL_PROTOCOL, Datagram, DatagramCodec, DiscoveryConfig, OwnedExecutor, discovery,
    dns::{OwnedResolver, transport::Guard},
};

const DEADLINE: Duration = Duration::from_secs(10);

/// Registry capacity exhaustion keeps the carrier's existing capacity error;
/// policy denials keep the registry's own error.
fn admission_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        capacity()
    } else {
        error
    }
}

#[path = "../circuit_io.rs"]
mod circuit_io;
#[path = "../relay/mod.rs"]
mod relay;
pub use relay::{RelayAddr, RelayLease, Route};

#[path = "runtime/boundary.rs"]
mod boundary;
#[path = "runtime/events.rs"]
mod events;
#[path = "runtime/infrastructure.rs"]
mod infrastructure;
#[path = "runtime/setup.rs"]
mod setup;

// Preserve the derived behaviour's bounded inline packet storage; boxing would
// allocate for every signaling packet. The dial handoff adds no larger payload.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum BehaviourEvent {
    Relays(libp2p::relay::client::Event),
    Packets(rpc::Event<Datagram, ()>),
    Dial(DialOpts),
}

impl From<std::convert::Infallible> for BehaviourEvent {
    fn from(event: std::convert::Infallible) -> Self {
        match event {}
    }
}

impl From<libp2p::relay::client::Event> for BehaviourEvent {
    fn from(event: libp2p::relay::client::Event) -> Self {
        Self::Relays(event)
    }
}

impl From<rpc::Event<Datagram, ()>> for BehaviourEvent {
    fn from(event: rpc::Event<Datagram, ()>) -> Self {
        Self::Packets(event)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
struct Behaviour {
    admission: Admission,
    relays: libp2p::relay::client::Behaviour,
    packets: rpc::Behaviour<DatagramCodec>,
}

/// The caller drives this owner; no root task is detached or hidden behind handles.
pub struct Carrier {
    core: Core,
    executor: OwnedExecutor,
}

struct Core {
    // Declared first so the authority closes before Swarm and executor teardown.
    discovery: Option<discovery::State>,
    swarm: Swarm<boundary::Boundary<Behaviour>>,
    infrastructure: infrastructure::State,
    commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<Received>,
    listening: watch::Sender<Option<SocketAddr>>,
    links: watch::Sender<Vec<Link>>,
    pending: HashMap<ConnectionId, Pending>,
    native_listener: ListenerId,
    relay: relay::State,
    requests: HashMap<rpc::OutboundRequestId, Request>,
    closing: HashMap<PeerId, Closing>,
}

struct Pending {
    peer: PeerId,
    reply: Reply<ConnectionId>,
    route: Option<RelayAddr>,
    attempt: Option<AttemptKey>,
    // Gate ticket for relay dials: authenticated control-bound operations.
    operation: Option<relay::gate::Ticket>,
}

struct Request {
    peer: PeerId,
    deadline: tokio::time::Instant,
    reply: Option<Reply<()>>,
}

struct Closing {
    deadline: tokio::time::Instant,
    reply: Option<Reply<()>>,
}

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../fault_tests.rs"]
mod fault_tests;

#[cfg(test)]
#[path = "../../dns/tests/transport.rs"]
mod dns_tests;

#[cfg(test)]
mod roles_gate_tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod relay_retention_tests;

#[cfg(test)]
mod relay_roles_tests;

/// Carrier role-integration wiring proofs.
#[cfg(test)]
mod roles_tests;

impl Drop for Core {
    fn drop(&mut self) {
        self.commands.close();
        // Cancel and drop every live relay operation owner outside all guards;
        // the Swarm field below drops the last capability clones.
        self.relay.gate.revoke_all();
        self.withdraw_all_infrastructure();
        self.swarm.behaviour_mut().inner.admission.close_authority();
        if let Some(discovery) = &self.discovery {
            discovery.lifetime.close();
        }
        // Close/wake precedes field destruction; only Carrier::run joins the executor.
        self.links.send_replace(Vec::new());
    }
}

impl Core {
    fn allows_application(&self, peer: &PeerId) -> bool {
        self.swarm.behaviour().inner.admission.allows(peer)
            && !self
                .discovery
                .as_ref()
                .is_some_and(|state| state.is_seed(peer))
    }

    fn publish_links(&self) {
        let mut links: Vec<_> = self
            .swarm
            .behaviour()
            .inner
            .admission
            .application_connections()
            .filter_map(|(peer, connection)| {
                if self.closing.contains_key(&peer) || !self.allows_application(&peer) {
                    return None;
                }
                self.relay
                    .routes
                    .get(&connection)
                    .copied()
                    .map(|route| Link {
                        peer,
                        connection,
                        route,
                    })
            })
            .collect();
        links.sort_unstable_by_key(|link| link.peer);
        let changed = *self.links.borrow() != links;
        if changed {
            self.links.send_replace(links);
        }
    }

    async fn drive(
        &mut self,
        executor: &mut OwnedExecutor,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        tokio::pin!(stop);
        loop {
            self.infrastructure_tick(tokio::time::Instant::now())?;
            self.relay_tick(tokio::time::Instant::now())?;
            // All ledgers have fixed limits; no separately allocated timer queue.
            let deadline = self
                .closing
                .values()
                .map(|closing| closing.deadline)
                .chain(
                    self.requests
                        .values()
                        .filter(|request| request.reply.is_some())
                        .map(|request| request.deadline),
                )
                .chain(self.relay.next_deadline())
                .chain(self.relay.gate.next_deadline())
                .chain(self.infrastructure.next_deadline())
                .min();
            let closing_deadline = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = closing_deadline => {
                    let now = tokio::time::Instant::now();
                    self.expire(now)?;
                    self.relay_tick(now)?;
                },
                _ = &mut stop => return Ok(()),
                _ = self.incoming.closed() => return Ok(()),
                command = self.commands.recv() => match command {
                    Some(command) => self.command(command),
                    None => return Ok(()),
                },
                event = self.swarm.select_next_some() => self.event(event)?,
                result = executor.next_result() => result?,
            }
        }
    }

    fn expire(&mut self, now: tokio::time::Instant) -> io::Result<()> {
        if self.closing.values().any(|closing| closing.deadline <= now) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "carrier disconnect deadline",
            ));
        }
        let mut changed = false;
        for request in self.requests.values() {
            if request.deadline <= now
                && request.reply.is_some()
                && let std::collections::hash_map::Entry::Vacant(entry) =
                    self.closing.entry(request.peer)
            {
                let _ = self.swarm.disconnect_peer_id(request.peer);
                entry.insert(Closing {
                    deadline: now + DEADLINE,
                    reply: None,
                });
                changed = true;
            }
        }
        if changed {
            self.publish_links();
        }
        for request in self.requests.values_mut() {
            if request.deadline <= now
                && let Some(reply) = request.reply.take()
            {
                let _ = reply.send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "carrier request deadline",
                )));
            }
            // Keep the ID charged until the dependency emits its terminal event.
        }
        Ok(())
    }

    fn send_packet(
        &mut self,
        peer: PeerId,
        expected: Option<Link>,
        packet: Datagram,
        reply: Reply<()>,
    ) {
        if reply.is_closed() {
            return;
        }
        if self.requests.len() >= REQUEST_LIMIT {
            let _ = reply.send(Err(capacity()));
        } else if !self.allows_application(&peer)
            || self.closing.contains_key(&peer)
            || !self.swarm.behaviour().inner.packets.is_connected(&peer)
            || expected.is_some_and(|link| {
                self.swarm.behaviour().inner.admission.connection(&peer) != Some(link.connection)
                    || self.relay.routes.get(&link.connection) != Some(&link.route)
            })
        {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "carrier peer not connected",
            )));
        } else {
            // The sole owner validates the exact link before allocating a request ID.
            // With one admitted connection per peer, request-response pins NotifyHandler to that ID.
            let id = self
                .swarm
                .behaviour_mut()
                .inner
                .packets
                .send_request(&peer, packet);
            self.requests.insert(
                id,
                Request {
                    peer,
                    deadline: tokio::time::Instant::now() + DEADLINE,
                    reply: Some(reply),
                },
            );
        }
    }

    /// Pins the exact selected root and stages the registry attempt for an explicit dial.
    /// The registry role predicates enforce endpoint exactness at pinning time.
    fn admit_attempt(
        &mut self,
        peer: PeerId,
        root: &libp2p::Multiaddr,
        connection: ConnectionId,
    ) -> io::Result<Option<AttemptKey>> {
        self.swarm
            .behaviour_mut()
            .inner
            .admission
            .stage_native(peer, root, connection)
    }

    fn terminal(
        &mut self,
        attempt: AttemptKey,
        authenticated: Option<PeerId>,
    ) -> Option<std::net::SocketAddr> {
        self.swarm
            .behaviour_mut()
            .inner
            .admission
            .terminal(attempt, authenticated.filter(|peer| *peer == attempt.peer))
    }

    fn command(&mut self, command: Command) {
        match command {
            Command::Connect(peer, address, reply) => {
                if reply.is_closed() {
                    return;
                }
                if !self.allows_application(&peer) {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "carrier peer not allowed",
                    )));
                } else if address.port() == 0
                    || address.ip().is_unspecified()
                    || address.ip().is_multicast()
                {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid carrier peer address",
                    )));
                } else if self.closing.contains_key(&peer) {
                    let _ = reply.send(Err(capacity()));
                } else if let Some(id) = self.swarm.behaviour().inner.admission.connection(&peer) {
                    let result = if self.relay.routes.get(&id) == Some(&Route::Direct) {
                        Ok(id)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "peer has a different carrier route",
                        ))
                    };
                    let _ = reply.send(result);
                } else if self.pending.len() >= PENDING_LIMIT
                    || self.pending.values().any(|pending| pending.peer == peer)
                {
                    let _ = reply.send(Err(capacity()));
                } else {
                    // Signaling uses explicit TCP dials, not listener-port hole punching.
                    // In the discovery branch the dial carries the exact selected root;
                    // hints and discovery paths never call admit or pin_root.
                    let mut address = multiaddr(address);
                    if self
                        .swarm
                        .behaviour()
                        .inner
                        .admission
                        .roles_view()
                        .is_some()
                    {
                        address = address.with(Protocol::P2p(peer));
                    }
                    match self.dial_native(peer, &address) {
                        Ok((id, attempt)) => {
                            self.pending.insert(
                                id,
                                Pending {
                                    peer,
                                    reply,
                                    route: None,
                                    attempt,
                                    operation: None,
                                },
                            );
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
            }
            Command::Send(peer, packet, reply) => self.send_packet(peer, None, packet, reply),
            Command::SendOn(link, packet, reply) => {
                self.send_packet(link.peer, Some(link), packet, reply)
            }
            Command::Disconnect(peer, reply) => {
                if self.closing.contains_key(&peer)
                    || self.pending.values().any(|pending| pending.peer == peer)
                {
                    let _ = reply.send(Err(capacity()));
                } else if self.swarm.disconnect_peer_id(peer).is_ok() {
                    self.closing.insert(
                        peer,
                        Closing {
                            deadline: tokio::time::Instant::now() + DEADLINE,
                            reply: Some(reply),
                        },
                    );
                    self.publish_links();
                } else {
                    let _ = reply.send(Ok(()));
                }
            }
            Command::Reserve(relay, reply) => self.reserve_relay(relay, reply),
            Command::ReleaseRelay(peer, reply) => self.release_relay(peer, reply),
            Command::ConnectVia(peer, relay, reply) => self.connect_via(peer, relay, reply),
        }
    }

    fn packet(&mut self, event: rpc::Event<Datagram, ()>) {
        match event {
            rpc::Event::Message {
                peer,
                connection_id,
                message:
                    rpc::Message::Request {
                        request, channel, ..
                    },
            } => {
                let Some(route) = self.relay.routes.get(&connection_id).copied() else {
                    return;
                };
                if !self.allows_application(&peer)
                    || self.swarm.behaviour().inner.admission.connection(&peer)
                        != Some(connection_id)
                    || self.closing.contains_key(&peer)
                {
                    return;
                }
                // Authenticated current circuit only; failed admission omits the acknowledgement.
                if self
                    .incoming
                    .try_send(Received {
                        peer,
                        connection: connection_id,
                        route,
                        packet: request,
                    })
                    .is_ok()
                {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .inner
                        .packets
                        .send_response(channel, ());
                }
            }
            rpc::Event::Message {
                message: rpc::Message::Response { request_id, .. },
                ..
            } => {
                if let Some(Request {
                    reply: Some(reply), ..
                }) = self.requests.remove(&request_id)
                {
                    let _ = reply.send(Ok(()));
                }
            }
            rpc::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(Request {
                    reply: Some(reply), ..
                }) = self.requests.remove(&request_id)
                {
                    let _ = reply.send(Err(io::Error::other(error)));
                }
            }
            rpc::Event::InboundFailure { .. } | rpc::Event::ResponseSent { .. } => {}
        }
    }
}
