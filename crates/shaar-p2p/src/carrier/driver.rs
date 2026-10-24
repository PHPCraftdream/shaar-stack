use std::{
    collections::HashMap, future::Future, io, net::SocketAddr, num::NonZeroUsize, time::Duration,
};

use futures::StreamExt;
use libp2p::{
    PeerId, StreamProtocol, Swarm, Transport,
    core::{muxing::StreamMuxerBox, upgrade},
    identity::Keypair,
    noise, request_response as rpc,
    swarm::{ConnectionId, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
    tcp, yamux,
};
use tokio::sync::{mpsc, watch};

use super::{
    CarrierHandle, Command, PENDING_LIMIT, QUEUE_LIMIT, REQUEST_LIMIT, Received, Reply,
    admission::Admission, capacity, multiaddr, socket_address,
};
use crate::{CONTROL_PROTOCOL, Datagram, DatagramCodec, OwnedExecutor};

const DEADLINE: Duration = Duration::from_secs(10);

#[derive(NetworkBehaviour)]
struct Behaviour {
    admission: Admission,
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
    pending: HashMap<ConnectionId, (PeerId, Reply<ConnectionId>)>,
    requests: HashMap<rpc::OutboundRequestId, Request>,
    closing: HashMap<PeerId, Closing>,
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
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(noise::Config::new(&key).map_err(io::Error::other)?)
            .multiplex(yamux::Config::default())
            .timeout(DEADLINE)
            .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
            .boxed();
        let behaviour = Behaviour {
            admission,
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
        swarm.listen_on(multiaddr(bind)).map_err(io::Error::other)?;
        let (sender, commands) = mpsc::channel(QUEUE_LIMIT);
        let (incoming, receiver) = mpsc::channel(QUEUE_LIMIT);
        let (listening, ready) = watch::channel(None);
        let handle = CarrierHandle {
            commands: sender,
            listening: ready,
            peer,
        };
        Ok((
            Self {
                core: Core {
                    swarm,
                    commands,
                    incoming,
                    listening,
                    pending: HashMap::with_capacity(PENDING_LIMIT),
                    requests: HashMap::with_capacity(REQUEST_LIMIT),
                    closing: HashMap::with_capacity(super::PEER_LIMIT),
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

impl Core {
    async fn drive(
        &mut self,
        executor: &mut OwnedExecutor,
        stop: impl Future<Output = ()>,
    ) -> io::Result<()> {
        tokio::pin!(stop);
        loop {
            // At most 48 entries: a bounded scan avoids a separately allocated timer queue.
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
                .min();
            let closing_deadline = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = closing_deadline => self.expire(tokio::time::Instant::now())?,
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
        for request in self.requests.values_mut() {
            if request.deadline > now {
                continue;
            }
            let Some(reply) = request.reply.take() else {
                continue;
            };
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "carrier request deadline",
            )));
            // Keep the ID charged until the dependency emits its terminal event.
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.closing.entry(request.peer)
            {
                let _ = self.swarm.disconnect_peer_id(request.peer);
                entry.insert(Closing {
                    deadline: now + DEADLINE,
                    reply: None,
                });
            }
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
                    let _ = reply.send(Ok(id));
                } else if self.pending.len() >= PENDING_LIMIT
                    || self.pending.values().any(|(id, _)| *id == peer)
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
                            self.pending.insert(id, (peer, reply));
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
                } else if self.closing.contains_key(&peer)
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
                    || self.pending.values().any(|(id, _)| *id == peer)
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
                } else {
                    let _ = reply.send(Ok(()));
                }
            }
        }
    }

    fn event(&mut self, event: SwarmEvent<BehaviourEvent>) -> io::Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                let address = socket_address(&address)
                    .ok_or_else(|| io::Error::other("unexpected carrier listen address"))?;
                self.listening.send_replace(Some(address));
            }
            SwarmEvent::ListenerError { error, .. } => return Err(error),
            SwarmEvent::ListenerClosed { reason, .. } => {
                return Err(reason
                    .err()
                    .unwrap_or_else(|| io::Error::other("carrier listener closed")));
            }
            SwarmEvent::ConnectionEstablished { connection_id, .. } => {
                if let Some((_, reply)) = self.pending.remove(&connection_id) {
                    let _ = reply.send(Ok(connection_id));
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } => {
                if let Some((_, reply)) = self.pending.remove(&connection_id) {
                    let _ = reply.send(Err(io::Error::other(error)));
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                if let Some(Closing {
                    reply: Some(reply), ..
                }) = self.closing.remove(&peer_id)
                {
                    let _ = reply.send(Ok(()));
                }
                // Request-response emits the terminal failure for each outstanding ID.
            }
            SwarmEvent::Behaviour(BehaviourEvent::Packets(event)) => self.packet(event),
            SwarmEvent::Behaviour(BehaviourEvent::Admission(event)) => match event {},
            _ => {} // Other transport/address notifications own no carrier ledger entries.
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
                // Event metadata is authenticated; failed admission omits the acknowledgement.
                if self
                    .incoming
                    .try_send(Received {
                        peer,
                        connection: connection_id,
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
