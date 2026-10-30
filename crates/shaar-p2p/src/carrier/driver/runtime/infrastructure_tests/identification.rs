use super::*;
use libp2p::{identify, kad};

#[path = "discovery.rs"]
mod discovery;

#[derive(Debug)]
struct MetadataEvent(Option<identify::Event>);

impl From<identify::Event> for MetadataEvent {
    fn from(event: identify::Event) -> Self {
        Self(Some(event))
    }
}

impl From<kad::Event> for MetadataEvent {
    fn from(_: kad::Event) -> Self {
        Self(None)
    }
}

impl From<libp2p::relay::Event> for MetadataEvent {
    fn from(_: libp2p::relay::Event) -> Self {
        Self(None)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MetadataEvent")]
struct Metadata {
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    relay: libp2p::relay::Behaviour,
}

struct MetadataServer {
    swarm: Swarm<Metadata>,
    executor: OwnedExecutor,
    peer: PeerId,
    public: libp2p::identity::PublicKey,
    address: SocketAddr,
}

impl MetadataServer {
    /// cancel-safe: NO — dropping startup aborts owned work without joining it.
    async fn new() -> Self {
        let key = Keypair::generate_ed25519();
        let public = key.public();
        let peer = public.to_peer_id();
        let executor = OwnedExecutor::new();
        let mut config = kad::Config::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
        config.set_periodic_bootstrap_interval(None);
        config.set_automatic_bootstrap_throttle(None);
        let mut kad = kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), config);
        kad.set_mode(Some(kad::Mode::Server));
        let behaviour = Metadata {
            identify: identify::Behaviour::new(
                identify::Config::new("owned-fixture".into(), public.clone())
                    .with_cache_size(0)
                    .with_push_listen_addr_updates(false),
            ),
            kad,
            relay: libp2p::relay::Behaviour::new(
                peer,
                libp2p::relay::Config {
                    max_reservations: 0,
                    max_reservations_per_peer: 0,
                    max_circuits: 0,
                    max_circuits_per_peer: 0,
                    ..libp2p::relay::Config::default()
                },
            ),
        };
        let mut swarm = Swarm::new(
            native(&key),
            behaviour,
            peer,
            libp2p::swarm::Config::with_executor(executor.handle())
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                swarm.add_external_address(address.clone());
                break socket_address(&address).unwrap();
            }
        };
        Self {
            swarm,
            executor,
            peer,
            public,
            address,
        }
    }

    /// cancel-safe: NO — dropping the join cannot prove resource destruction.
    async fn shutdown(self) {
        let Self {
            swarm,
            executor,
            address,
            ..
        } = self;
        drop(swarm);
        executor.shutdown().await.unwrap();
        drop(tokio::net::TcpListener::bind(address).await.unwrap());
    }
}

fn info(public: &libp2p::identity::PublicKey, protocols: Vec<StreamProtocol>) -> identify::Info {
    identify::Info {
        public_key: public.clone(),
        protocol_version: "owned-fixture".into(),
        agent_version: "owned-fixture".into(),
        listen_addrs: vec!["/ip4/8.8.4.4/tcp/4001".parse().unwrap()],
        protocols,
        observed_addr: "/ip4/8.8.4.4/tcp/4002".parse().unwrap(),
        signed_peer_record: None,
    }
}

fn receive(source: &mut Carrier, peer: PeerId, connection: ConnectionId, info: identify::Info) {
    source
        .core
        .event(SwarmEvent::Behaviour(BehaviourEvent::Protocols(
            protocols::Event::Identify(identify::Event::Received {
                connection_id: connection,
                peer_id: peer,
                info,
            }),
        )))
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_identify_binds_capabilities_to_exact_live_control() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = MetadataServer::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, address.clone())]);
        let (connection, key) = stage(&mut source, server.peer, &address, server.address);
        let mut client_public = None;
        let mut source_received = false;
        let exchanged = timeout(Duration::from_secs(25), async {
        loop {
            tokio::select! {
                event = source.core.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::Protocols(protocols::Event::Identify(identify::Event::Received { info, .. }))) = &event {
                        source_received = true;
                        assert_eq!(protocols::capabilities(&info.protocols), protocols::DHT | protocols::HOP,
                            "owned fixture protocol advertisement: {:?}", info.protocols);
                    }
                    source.core.event(event).unwrap();
                },
                event = server.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(MetadataEvent(Some(event))) = event {
                        match event {
                            identify::Event::Received { peer_id, info, .. } => {
                                assert_eq!(peer_id, handle.peer_id());
                                assert_eq!(info.public_key.to_peer_id(), handle.peer_id());
                                assert!(info.listen_addrs.is_empty());
                                client_public = Some(info.public_key);
                            }
                            identify::Event::Error { error, .. } => panic!("owned infrastructure Identify failed: {error}"),
                            _ => {}
                        }
                    }
                }
            }
            if source.core.infrastructure.entries.get(&connection).is_some_and(|entry| {
                entry.phase == Phase::Live && entry.protocols == (protocols::DHT | protocols::HOP)
            }) && client_public.is_some() {
                break;
            }
        }
        }).await;
        assert!(exchanged.is_ok(), "owned Identify exchange boundary: native_live={}, phase_live={}, capabilities={:?}, source_received={}, server_received={}",
            source.core.swarm.behaviour().inner.admission.roles_view().unwrap().infrastructure_live(key).is_some(),
            source.core.infrastructure.entries.get(&connection).is_some_and(|entry| entry.phase == Phase::Live),
            source.core.infrastructure.entries.get(&connection).map(|entry| entry.protocols),
            source_received, client_public.is_some());
        assert!(handle.links().borrow().is_empty());
        let unchanged = [StreamProtocol::new("/ipfs/kad/1.0.0"), StreamProtocol::new("/libp2p/circuit/relay/0.2.0/hop")];
        assert!(source.core.record_infrastructure_protocols(server.peer, connection, Some(&unchanged)).is_none());
        let selected = protocols::cached_addresses(&mut source.core.swarm.behaviour_mut().inner.protocols, server.peer);
        assert!(!selected.is_empty());
        assert!(selected.iter().all(|selected| selected == &address));
        receive(&mut source, handle.peer_id(), connection, info(client_public.as_ref().unwrap(), vec![]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, protocols::DHT | protocols::HOP);
        receive(&mut source, server.peer, ConnectionId::new_unchecked(usize::MAX - 1), info(&server.public, vec![]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, protocols::DHT | protocols::HOP);
        receive(&mut source, server.peer, connection, info(&server.public, vec![StreamProtocol::new("/libp2p/circuit/relay/0.2.0/stop")]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, 0);
        assert!(protocols::cached_addresses(&mut source.core.swarm.behaviour_mut().inner.protocols, server.peer).is_empty());
        receive(&mut source, server.peer, connection, info(&server.public, vec![StreamProtocol::new("/ipfs/kad/1.0.0")]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, protocols::DHT);
        let selected = protocols::cached_addresses(&mut source.core.swarm.behaviour_mut().inner.protocols, server.peer);
        assert!(selected.iter().all(|selected| selected == &address));
        source.core.event(SwarmEvent::Behaviour(BehaviourEvent::Protocols(protocols::Event::Identify(
            identify::Event::Error {
                connection_id: connection, peer_id: server.peer,
                error: libp2p::swarm::StreamUpgradeError::NegotiationFailed,
            },
        )))).unwrap();
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, 0);
        assert!(protocols::cached_addresses(&mut source.core.swarm.behaviour_mut().inner.protocols, server.peer).is_empty());
        receive(&mut source, server.peer, connection, info(&server.public, vec![StreamProtocol::new("/ipfs/kad/1.0.0")]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, protocols::DHT);
        receive(&mut source, server.peer, connection, info(&client_public.unwrap(), vec![StreamProtocol::new("/ipfs/kad/1.0.0")]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, 0);
        receive(&mut source, server.peer, connection, info(&server.public, vec![StreamProtocol::new("/libp2p/circuit/relay/0.2.0/hop")]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, protocols::HOP);
        source.core.close_infrastructure(key, Instant::now());
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, 0);
        receive(&mut source, server.peer, connection, info(&server.public, vec![StreamProtocol::new("/libp2p/circuit/relay/0.2.0/hop")]));
        assert_eq!(source.core.infrastructure.entries[&connection].protocols, 0);
        source.run(async {}).await.unwrap();
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_app_connection_rejects_identify_at_protocol_negotiation() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = MetadataServer::new().await;
        let seed = Keypair::generate_ed25519().public().to_peer_id();
        let (mut source, handle, _incoming) = Carrier::bind_with_discovery(
            Keypair::generate_ed25519(), "127.0.0.1:0".parse().unwrap(), vec![server.peer],
            DiscoveryConfig::new(vec![(seed, root(seed, server.address.port()))], vec![dns.address]).unwrap(),
        ).unwrap();
        let address = multiaddr(server.address).with(Protocol::P2p(server.peer));
        source.core.dial_native(server.peer, &address).unwrap();
        let mut rejected = false;
        loop {
            tokio::select! {
                event = source.core.swarm.select_next_some() => source.core.event(event).unwrap(),
                event = server.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(MetadataEvent(Some(event))) = event {
                        match event {
                            identify::Event::Error { peer_id, error, .. } => {
                                assert_eq!(peer_id, handle.peer_id());
                                assert!(matches!(error, libp2p::swarm::StreamUpgradeError::NegotiationFailed));
                                rejected = true;
                            }
                            identify::Event::Received { .. } => panic!("APP connection negotiated discovery Identify"),
                            _ => {}
                        }
                    }
                }
            }
            if rejected && handle.links().borrow().iter().any(|link| link.peer == server.peer) {
                break;
            }
        }
        assert!(source.core.infrastructure.entries.is_empty());
        assert!(handle.links().borrow().iter().any(|link| link.peer == server.peer));
        source.run(async {}).await.unwrap();
        server.shutdown().await;
        assert_eq!(dns.shutdown().await, 0);
    }).await.unwrap();
}
