use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, num::NonZeroUsize, time::Duration,
};

use futures::StreamExt;
use libp2p::{
    PeerId, StreamProtocol, Swarm, Transport,
    core::{muxing::StreamMuxerBox, transport::ListenerId, upgrade},
    identity::Keypair,
    noise, request_response as rpc,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
    tcp, yamux,
};
use tokio::sync::{mpsc, watch};

use super::{
    CarrierHandle, Command, Link, PENDING_LIMIT, QUEUE_LIMIT, REQUEST_LIMIT, Received, Reply,
    admission::Admission, capacity, multiaddr, socket_address,
};
use crate::{CONTROL_PROTOCOL, Datagram, DatagramCodec, OwnedExecutor};

const DEADLINE: Duration = Duration::from_secs(10);

#[path = "circuit_io.rs"]
mod circuit_io;
#[path = "relay/mod.rs"]
mod relay;
pub use relay::{RelayAddr, RelayLease, Route};

#[derive(NetworkBehaviour)]
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
    swarm: Swarm<Behaviour>,
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

impl Carrier {
    /// Creates one native listener and an immutable allowlist of at most 16 entries.
    /// Requires a Tokio runtime; readiness is published while `run` is polled.
    /// Input count is checked before deduplication. Noise consumes the key;
    /// no raw secret getter is exposed.
    pub fn bind(
        key: Keypair,
        bind: SocketAddr,
        allowed: Vec<PeerId>,
    ) -> io::Result<(Self, CarrierHandle, mpsc::Receiver<Received>)> {
        let admission = Admission::new(allowed)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("carrier requires a Tokio runtime"))?;
        let peer = key.public().to_peer_id();
        let executor = OwnedExecutor::new();
        let transport = relay::native::FreshPorts(tcp::tokio::Transport::new(
            tcp::Config::default().nodelay(true),
        ))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&key).map_err(io::Error::other)?)
        .multiplex(yamux::Config::default())
        .timeout(DEADLINE)
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();
        let (transport, relays) = relay::transport(transport, &key)?;
        let behaviour = Behaviour {
            admission,
            relays,
            packets: rpc::Behaviour::with_codec(
                DatagramCodec,
                [(
                    StreamProtocol::new(CONTROL_PROTOCOL),
                    rpc::ProtocolSupport::Full,
                )],
                rpc::Config::default()
                    .with_request_timeout(DEADLINE)
                    .with_max_concurrent_streams(2),
            ),
        };
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer,
            libp2p::swarm::Config::with_executor(executor.handle())
                .with_notify_handler_buffer_size(NonZeroUsize::new(8).expect("nonzero constant"))
                .with_per_connection_event_buffer_size(8)
                .with_max_negotiating_inbound_streams(2)
                .with_idle_connection_timeout(Duration::from_secs(30)),
        );
        let native_listener = swarm.listen_on(multiaddr(bind)).map_err(io::Error::other)?;
        let (sender, commands) = mpsc::channel(QUEUE_LIMIT);
        let (incoming, receiver) = mpsc::channel(QUEUE_LIMIT);
        let (listening, ready) = watch::channel(None);
        let (relay, leases) = relay::State::new();
        let (links, observed_links) = watch::channel(Vec::new());
        let handle = CarrierHandle {
            commands: sender,
            listening: ready,
            leases,
            links: observed_links,
            peer,
        };
        Ok((
            Self {
                core: Core {
                    swarm,
                    commands,
                    incoming,
                    listening,
                    links,
                    native_listener,
                    relay,
                    pending: HashMap::with_capacity(PENDING_LIMIT),
                    requests: HashMap::with_capacity(REQUEST_LIMIT),
                    closing: HashMap::with_capacity(super::PEER_LIMIT + super::RELAY_LIMIT),
                },
                executor,
            },
            handle,
            receiver,
        ))
    }

    /// Stops on caller cancellation signal, last submission-handle drop or incoming-consumer drop.
    /// Drops Swarm before aborting and joining every managed connection/listener task.
    /// cancel-safe: NO — dropping this future aborts tasks but cannot join destruction.
    pub async fn run(self, stop: impl Future<Output = ()>) -> io::Result<()> {
        let Self {
            mut core,
            mut executor,
        } = self;
        let result = core.drive(&mut executor, stop).await;
        core.commands.close();
        drop(core);
        let joined = executor.shutdown().await;
        result.and(joined)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "fault_tests.rs"]
mod fault_tests;

impl Drop for Core {
    fn drop(&mut self) {
        // Synchronous observation revocation only; I/O destruction is joined by Carrier::run.
        self.links.send_replace(Vec::new());
    }
}

impl Core {
    fn publish_links(&self) {
        let mut links: Vec<_> = self
            .swarm
            .behaviour()
            .admission
            .application_connections()
            .filter_map(|(peer, connection)| {
                if self.closing.contains_key(&peer) {
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

    fn command(&mut self, command: Command) {
        match command {
            Command::Connect(peer, address, reply) => {
                if reply.is_closed() {
                    return;
                }
                if !self.swarm.behaviour().admission.allows(&peer) {
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
                } else if let Some(id) = self.swarm.behaviour().admission.connection(&peer) {
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
                    let options = DialOpts::peer_id(peer)
                        .addresses(vec![multiaddr(address)])
                        .allocate_new_port()
                        .build();
                    let id = options.connection_id();
                    match self.swarm.dial(options) {
                        Ok(()) => {
                            self.pending.insert(
                                id,
                                Pending {
                                    peer,
                                    reply,
                                    route: None,
                                },
                            );
                        }
                        Err(error) => {
                            let _ = reply.send(Err(io::Error::other(error)));
                        }
                    }
                }
            }
            Command::Send(peer, packet, reply) => {
                if reply.is_closed() {
                    return;
                }
                if self.requests.len() >= REQUEST_LIMIT {
                    let _ = reply.send(Err(capacity()));
                } else if !self.swarm.behaviour().admission.allows(&peer)
                    || self.closing.contains_key(&peer)
                    || !self.swarm.behaviour().packets.is_connected(&peer)
                {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "carrier peer not connected",
                    )));
                } else {
                    // The global gate precedes ID allocation and dependency pending-map insertion.
                    let id = self
                        .swarm
                        .behaviour_mut()
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

    fn event(&mut self, event: SwarmEvent<BehaviourEvent>) -> io::Result<()> {
        match event {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } if listener_id == self.native_listener => {
                let address = socket_address(&address)
                    .ok_or_else(|| io::Error::other("unexpected carrier listen address"))?;
                self.listening.send_replace(Some(address));
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => self.relay_listen_address(listener_id, address),
            SwarmEvent::ListenerError { listener_id, error }
                if listener_id == self.native_listener =>
            {
                return Err(error);
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                self.relay_listener_failed(listener_id, error)
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } if listener_id == self.native_listener => {
                return Err(reason
                    .err()
                    .unwrap_or_else(|| io::Error::other("carrier listener closed")));
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => self.relay_listener_closed(listener_id, reason.err()),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let pending = self.pending.remove(&connection_id);
                let intended = pending.as_ref().and_then(|pending| pending.route);
                let result =
                    self.relay_connected(peer_id, connection_id, endpoint.is_relayed(), intended);
                if result.is_err() {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                }
                self.publish_links();
                if let Some(pending) = pending {
                    let _ = pending.reply.send(result.map(|()| connection_id));
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } => {
                if let Some(pending) = self.pending.remove(&connection_id) {
                    let _ = pending.reply.send(Err(io::Error::other(error)));
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                self.relay_control_closed(peer_id, connection_id);
                self.publish_links();
                if num_established == 0
                    && let Some(Closing {
                        reply: Some(reply), ..
                    }) = self.closing.remove(&peer_id)
                {
                    let _ = reply.send(Ok(()));
                }
                // Request-response emits terminal failures; request charges stay until then.
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relays(event)) => self.relay_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Packets(event)) => self.packet(event),
            SwarmEvent::Behaviour(BehaviourEvent::Admission(event)) => match event {},
            _ => {} // Other notifications add no carrier state.
        }
        Ok(())
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
                if !self.swarm.behaviour().admission.allows(&peer)
                    || self.swarm.behaviour().admission.connection(&peer) != Some(connection_id)
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
