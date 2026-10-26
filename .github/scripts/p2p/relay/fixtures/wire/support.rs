#![forbid(unsafe_code)]

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    identity, noise,
    swarm::{ConnectionId, Executor, SwarmEvent},
    tcp, yamux,
};
use libp2p_relay::{
    self as relay,
    client::{OperationCapability, OperationDescriptor, OperationKind, OperationOwner},
};
use std::{
    collections::VecDeque,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::task::JoinSet;

#[derive(Clone)]
pub struct Tasks(Arc<Mutex<JoinSet<()>>>);
impl Tasks {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(JoinSet::new())))
    }
    pub async fn shutdown(self) {
        let mut tasks = std::mem::take(&mut *self.0.lock().unwrap());
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled(), "fixture executor panicked: {error}");
            }
        }
    }
}
impl Executor for Tasks {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut tasks = self.0.lock().unwrap();
        assert!(tasks.len() < 64, "fixture executor capacity exceeded");
        tasks.spawn(future);
    }
}

fn native(key: &identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(10))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

#[derive(Clone, Copy)]
pub struct Progress {
    pub accepted: usize,
    pub server_accepted: usize,
}

pub struct Harness {
    pub client: Swarm<relay::client::Behaviour>,
    pub server: Swarm<relay::Behaviour>,
    pub relay_peer: PeerId,
    pub address: Multiaddr,
    pub control: Option<ConnectionId>,
    pub accepted: usize,
    pub server_accepted: usize,
    pub closed: usize,
    pub staged: Arc<Mutex<VecDeque<OperationCapability>>>,
    pub owners: Vec<(Arc<AtomicBool>, OperationOwner)>,
    pub tasks: Tasks,
    released: Arc<AtomicUsize>,
    issued: usize,
}

impl Harness {
    pub async fn new() -> Self {
        let tasks = Tasks::new();
        let server_key = identity::Keypair::generate_ed25519();
        let relay_peer = server_key.public().to_peer_id();
        let mut config = relay::Config::default();
        config.reservation_duration = Duration::from_secs(4);
        config.reservation_rate_limiters.clear();
        config.circuit_src_rate_limiters.clear();
        let mut server = Swarm::new(
            native(&server_key),
            relay::Behaviour::new(relay_peer, config),
            relay_peer,
            libp2p::swarm::Config::with_executor(tasks.clone())
                .with_idle_connection_timeout(Duration::from_secs(120)),
        );
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address;
            }
        };
        server.add_external_address(address.clone());
        let client_key = identity::Keypair::generate_ed25519();
        let client_peer = client_key.public().to_peer_id();
        let staged = Arc::new(Mutex::new(VecDeque::<OperationCapability>::new()));
        let factory_queue = staged.clone();
        let (relayed, behaviour) = relay::client::new_with_operation_factory(
            client_peer,
            Arc::new(move |_, _, _| {
                let capability = factory_queue.lock().unwrap().pop_front();
                capability.ok_or_else(|| std::io::ErrorKind::PermissionDenied.into())
            }),
        );
        let relayed = relayed
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(noise::Config::new(&client_key).unwrap())
            .multiplex(yamux::Config::default())
            .timeout(Duration::from_secs(10))
            .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
            .boxed();
        let transport = relayed
            .or_transport(native(&client_key))
            .map(|either, _| either.into_inner())
            .boxed();
        let client = Swarm::new(
            transport,
            behaviour,
            client_peer,
            libp2p::swarm::Config::with_executor(tasks.clone())
                .with_idle_connection_timeout(Duration::from_secs(120)),
        );
        Self {
            client,
            server,
            relay_peer,
            address,
            control: None,
            accepted: 0,
            server_accepted: 0,
            closed: 0,
            staged,
            owners: Vec::with_capacity(2),
            tasks,
            released: Arc::new(AtomicUsize::new(0)),
            issued: 0,
        }
    }

    pub fn stage(&mut self, kind: OperationKind, generation: u64) {
        assert!(self.owners.len() < 2);
        let eligible = Arc::new(AtomicBool::new(true));
        let authority = eligible.clone();
        let descriptor = OperationDescriptor::new(
            self.relay_peer,
            self.address.clone(),
            kind,
            NonZeroU64::new(generation).unwrap(),
        );
        let released = self.released.clone();
        let (owner, capability) = OperationCapability::owned(
            descriptor,
            move |_, _| authority.load(Ordering::Acquire),
            move || {
                released.fetch_add(1, Ordering::AcqRel);
            },
        );
        self.issued += 1;
        let mut staged = self.staged.lock().unwrap();
        assert!(staged.len() < 2);
        staged.push_back(capability);
        drop(staged);
        self.owners.push((eligible, owner));
    }

    pub fn arm_latest(&mut self) {
        let (eligible, owner) = self.owners.pop().expect("staged operation owner");
        relay::wire_probe::arm(move || {
            eligible.store(false, Ordering::Release);
            owner.cancel();
            drop(owner);
        });
    }

    pub fn circuit_address(&self) -> Multiaddr {
        self.address
            .clone()
            .with(libp2p::multiaddr::Protocol::P2p(self.relay_peer))
            .with(libp2p::multiaddr::Protocol::P2pCircuit)
    }

    fn client_event(&mut self, event: SwarmEvent<relay::client::Event>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } if peer_id == self.relay_peer => {
                assert!(
                    self.control.replace(connection_id).is_none(),
                    "unexpected replacement control"
                );
            }
            SwarmEvent::Behaviour(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                connection_id,
                renewal,
                ..
            }) => {
                assert_eq!(relay_peer_id, self.relay_peer);
                assert_eq!(
                    Some(connection_id),
                    self.control,
                    "renewal changed authenticated control"
                );
                assert_eq!(renewal, self.accepted != 0);
                self.accepted += 1;
            }
            SwarmEvent::ConnectionClosed { .. } => self.closed += 1,
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                error,
                ..
            } if peer == self.relay_peer => {
                panic!("owned relay setup failed: {error}");
            }
            _ => {}
        }
    }

    fn server_event(&mut self, event: SwarmEvent<relay::Event>) {
        if let SwarmEvent::Behaviour(relay::Event::ReservationReqAccepted { renewed, .. }) = event {
            assert_eq!(renewed, self.server_accepted != 0);
            self.server_accepted += 1;
        }
    }

    /// cancel-safe: yes — Swarm stream polling and observation do not consume partial frames.
    pub async fn until(&mut self, done: impl Fn(Progress, relay::wire_probe::Snapshot) -> bool) {
        loop {
            let progress = Progress {
                accepted: self.accepted,
                server_accepted: self.server_accepted,
            };
            if done(progress, relay::wire_probe::snapshot()) {
                return;
            }
            tokio::select! {
                event = self.client.select_next_some() => self.client_event(event),
                event = self.server.select_next_some() => self.server_event(event),
                _ = futures::future::poll_fn(|cx| relay::wire_probe::poll_observation(cx, |snapshot| done(progress, snapshot))) => {},
            }
        }
    }

    /// cancel-safe: yes — the timeout stops observation, not resource ownership.
    pub async fn observe_next_renewal_window(&mut self) {
        let end = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(end);
        loop {
            tokio::select! {
                _ = &mut end => return,
                event = self.client.select_next_some() => self.client_event(event),
                event = self.server.select_next_some() => self.server_event(event),
            }
        }
    }

    pub async fn close(self) {
        let Self {
            client,
            server,
            owners,
            tasks,
            released,
            issued,
            ..
        } = self;
        drop(owners);
        drop(client);
        drop(server);
        tasks.shutdown().await;
        assert_eq!(
            released.load(Ordering::Acquire),
            issued,
            "joined cleanup retained operation charges"
        );
    }
}
