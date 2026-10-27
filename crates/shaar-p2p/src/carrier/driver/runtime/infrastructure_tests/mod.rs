use super::*;
use crate::dns::tests::support::{Server as DnsServer, a, response};
use futures::{FutureExt, Stream, future::poll_fn};
use hickory_resolver::proto::op::ResponseCode;
use libp2p::{core::transport::Boxed, swarm::dummy};
use std::task::Poll;
use tokio::{sync::oneshot, task::JoinSet, time::timeout};

struct Dns {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinSet<(DnsServer, usize)>,
}

impl Dns {
    async fn new() -> Self {
        let server = DnsServer::new().await;
        let address = server.address;
        let (stop, mut stopped) = oneshot::channel();
        let mut task = JoinSet::new();
        task.spawn(async move {
            let mut requests = 0;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    (query, source) = server.question() => {
                        requests += 1;
                        let answer = response(&query, Some(a()), ResponseCode::NoError);
                        server.udp.send_to(&answer.to_vec().unwrap(), source).await.unwrap();
                    }
                }
            }
            (server, requests)
        });
        Self {
            address,
            stop,
            task,
        }
    }

    async fn shutdown(mut self) -> usize {
        self.stop.send(()).unwrap();
        let (server, requests) = self.task.join_next().await.unwrap().unwrap();
        assert!(self.task.is_empty());
        server.quiet();
        drop(server);
        requests
    }
}

struct Server {
    swarm: Swarm<dummy::Behaviour>,
    executor: OwnedExecutor,
    peer: PeerId,
    address: SocketAddr,
}

fn native(key: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(DEADLINE)
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

impl Server {
    async fn new() -> Self {
        let key = Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let executor = OwnedExecutor::new();
        let mut swarm = Swarm::new(
            native(&key),
            dummy::Behaviour,
            peer,
            libp2p::swarm::Config::with_executor(executor.handle())
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break socket_address(&address).unwrap();
            }
        };
        Self {
            swarm,
            executor,
            peer,
            address,
        }
    }

    async fn shutdown(self) {
        let Self {
            swarm,
            executor,
            address,
            ..
        } = self;
        drop(swarm);
        executor.shutdown().await.unwrap();
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        drop(listener);
    }
}

fn root(peer: PeerId, port: u16) -> libp2p::Multiaddr {
    format!("/dns4/owned.example./tcp/{port}/p2p/{peer}")
        .parse()
        .unwrap()
}

fn carrier(
    dns: &Dns,
    seeds: Vec<(PeerId, libp2p::Multiaddr)>,
) -> (Carrier, CarrierHandle, mpsc::Receiver<Received>) {
    Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        DiscoveryConfig::new(seeds, vec![dns.address]).unwrap(),
    )
    .unwrap()
}

fn stage(
    source: &mut Carrier,
    peer: PeerId,
    address: &libp2p::Multiaddr,
    endpoint: SocketAddr,
) -> (ConnectionId, AttemptKey) {
    let (options, attempt) = source.core.prepare_native(peer, address).unwrap();
    let key = attempt.unwrap();
    source
        .core
        .swarm
        .behaviour_mut()
        .admission
        .allow_infrastructure_fixture(key, address, endpoint)
        .unwrap();
    let (connection, actual) = source.core.submit_native(options, Some(key)).unwrap();
    assert_eq!(actual, Some(key));
    (connection, key)
}

/// cancel-safe: yes — each selected Swarm event is dispatched synchronously.
async fn pump(source: &mut Carrier, server: &mut Server) {
    tokio::select! {
        event = source.core.swarm.select_next_some() => source.core.event(event).unwrap(),
        _ = server.swarm.select_next_some() => {}
    }
}

async fn live(source: &mut Carrier, server: &mut Server, connection: ConnectionId) {
    timeout(DEADLINE, async {
        loop {
            let entry = source
                .core
                .infrastructure
                .entries
                .get(&connection)
                .expect("owned infrastructure operation remains pending");
            if entry.phase == Phase::Live {
                break;
            }
            pump(source, server).await;
        }
    })
    .await
    .unwrap();
}

async fn gone(source: &mut Carrier, server: &mut Server, connection: ConnectionId) {
    timeout(DEADLINE, async {
        while source.core.infrastructure.entries.contains_key(&connection) {
            pump(source, server).await;
        }
    })
    .await
    .unwrap();
}

async fn shutdown(mut source: Carrier, handle: &CarrierHandle) {
    timeout(DEADLINE, async {
        while handle.listening.borrow().is_none() {
            let event = source.core.swarm.select_next_some().await;
            source.core.event(event).unwrap();
        }
    })
    .await
    .unwrap();
    let listening = (*handle.listening.borrow()).unwrap();
    source.run(async {}).await.unwrap();
    assert!(handle.links().borrow().is_empty());
    let listener = tokio::net::TcpListener::bind(listening).await.unwrap();
    drop(listener);
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_authenticates_without_app_authority_or_deadline_renewal() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = Server::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, mut incoming) =
            carrier(&dns, vec![(server.peer, address.clone())]);
        let (connection, key) = stage(&mut source, server.peer, &address, server.address);
        live(&mut source, &mut server, connection).await;
        assert_eq!(
            source
                .core
                .swarm
                .behaviour()
                .admission
                .connection(&server.peer),
            Some(connection)
        );
        assert_eq!(
            source
                .core
                .swarm
                .behaviour()
                .admission
                .roles_view()
                .unwrap()
                .infrastructure_live(key),
            Some(server.address)
        );
        assert!(source.core.relay.routes.is_empty());
        assert!(handle.links().borrow().is_empty());
        assert!(handle.relay_leases().borrow().is_empty());
        assert!(matches!(
            incoming.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let (reply, result) = oneshot::channel();
        source
            .core
            .command(Command::Connect(server.peer, server.address, reply));
        assert_eq!(
            result.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let (reply, result) = oneshot::channel();
        source.core.command(Command::Send(
            server.peer,
            Datagram::new(b"denied").unwrap(),
            reply,
        ));
        assert_eq!(
            result.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        tokio::time::pause();
        tokio::time::advance(DEADLINE + Duration::from_millis(1)).await;
        source.core.infrastructure_tick(Instant::now()).unwrap();
        assert!(
            source
                .core
                .infrastructure
                .entries
                .get(&connection)
                .is_some_and(|entry| entry.phase == Phase::Live)
        );
        assert!(source.core.infrastructure.next_deadline().is_none());
        tokio::time::resume();
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_rejects_unstaged_and_unselected_roots_before_dns() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let server = Server::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, address.clone())]);
        let options = DialOpts::peer_id(server.peer)
            .addresses(vec![address.clone()])
            .build();
        assert!(source.core.swarm.dial(options).is_err());
        let other: libp2p::Multiaddr = format!(
            "/dns4/other.example./tcp/{}/p2p/{}",
            server.address.port(),
            server.peer
        )
        .parse()
        .unwrap();
        assert_eq!(
            source
                .core
                .prepare_native(server.peer, &other)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let foreign = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(
            source
                .core
                .prepare_native(foreign, &root(foreign, server.address.port()))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(source.core.infrastructure.entries.is_empty());
        timeout(DEADLINE, async {
            while handle.listening.borrow().is_none() {
                let event = source.core.swarm.select_next_some().await;
                source.core.event(event).unwrap();
            }
        })
        .await
        .unwrap();
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert_eq!(dns.shutdown().await, 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_wrong_noise_identity_retires_only_after_last_guard() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = Server::new().await;
        let expected = Keypair::generate_ed25519().public().to_peer_id();
        let address = root(expected, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(expected, address.clone())]);
        let (options, attempt) = source.core.prepare_native(expected, &address).unwrap();
        let key = attempt.unwrap();
        source
            .core
            .swarm
            .behaviour_mut()
            .admission
            .allow_infrastructure_fixture(key, &address, server.address)
            .unwrap();
        let view = source
            .core
            .swarm
            .behaviour()
            .admission
            .roles_view()
            .unwrap();
        let held = view.root_lease(address.as_ref()).unwrap();
        let (connection, _) = source.core.submit_native(options, Some(key)).unwrap();
        gone(&mut source, &mut server, connection).await;
        assert!(view.infrastructure_live(key).is_none());
        assert!(handle.links().borrow().is_empty());
        let mut joined = Box::pin(view.join_infrastructure_release());
        assert!(futures::poll!(&mut joined).is_pending());
        drop(held);
        timeout(DEADLINE, &mut joined).await.unwrap();
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_rejects_authenticated_unsolicited_inbound() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = Server::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, mut incoming) = carrier(&dns, vec![(server.peer, address)]);
        let listening = timeout(DEADLINE, async {
            loop {
                if let Some(address) = *handle.listening.borrow() {
                    break address;
                }
                let event = source.core.swarm.select_next_some().await;
                source.core.event(event).unwrap();
            }
        })
        .await
        .unwrap();
        server
            .swarm
            .dial(
                DialOpts::peer_id(handle.peer_id())
                    .addresses(vec![multiaddr(listening)])
                    .allocate_new_port()
                    .build(),
            )
            .unwrap();
        timeout(DEADLINE, async {
            loop {
                tokio::select! {
                    event = source.core.swarm.select_next_some() => {
                        let rejected = matches!(&event, SwarmEvent::IncomingConnectionError { .. });
                        source.core.event(event).unwrap();
                        if rejected { break; }
                    }
                    _ = server.swarm.select_next_some() => {}
                }
            }
        })
        .await
        .unwrap();
        assert!(
            source
                .core
                .swarm
                .behaviour()
                .admission
                .connection(&server.peer)
                .is_none()
        );
        assert!(source.core.infrastructure.entries.is_empty());
        assert!(handle.links().borrow().is_empty());
        assert!(matches!(
            incoming.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert_eq!(dns.shutdown().await, 0);
    })
    .await
    .unwrap();
}

/// cancel-safe: yes — dispatches one selected event from bounded owned Swarms.
async fn pump_many(source: &mut Carrier, servers: &mut [Server]) {
    tokio::select! {
        event = source.core.swarm.select_next_some() => source.core.event(event).unwrap(),
        _ = poll_fn(|cx| {
            for server in servers.iter_mut() {
                if let Poll::Ready(Some(event)) = std::pin::Pin::new(&mut server.swarm).poll_next(cx) {
                    return Poll::Ready(event);
                }
            }
            Poll::Pending
        }) => {}
    }
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_four_controls_keep_retained_slot_charged() {
    timeout(Duration::from_secs(40), async {
        let dns = Dns::new().await;
        let mut servers = Vec::new();
        for _ in 0..4 {
            servers.push(Server::new().await);
        }
        let seeds: Vec<_> = servers
            .iter()
            .map(|server| (server.peer, root(server.peer, server.address.port())))
            .collect();
        let (mut source, handle, _incoming) = carrier(&dns, seeds.clone());
        let mut operations = Vec::new();
        for (index, (peer, address)) in seeds.iter().enumerate() {
            operations.push(stage(&mut source, *peer, address, servers[index].address));
        }
        let view = source
            .core
            .swarm
            .behaviour()
            .admission
            .roles_view()
            .unwrap();
        let held = view.root_lease(seeds[0].1.as_ref()).unwrap();
        timeout(DEADLINE, async {
            while source
                .core
                .infrastructure
                .entries
                .values()
                .any(|entry| entry.phase != Phase::Live)
            {
                pump_many(&mut source, &mut servers).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(source.core.infrastructure.entries.len(), 4);
        assert!(handle.links().borrow().is_empty());
        assert_eq!(
            source
                .core
                .prepare_native(seeds[0].0, &seeds[0].1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        source
            .core
            .close_infrastructure(operations[0].1, Instant::now());
        timeout(DEADLINE, async {
            while source
                .core
                .infrastructure
                .entries
                .contains_key(&operations[0].0)
            {
                pump_many(&mut source, &mut servers).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(source.core.infrastructure.entries.len(), 3);
        assert_eq!(
            source
                .core
                .prepare_native(seeds[0].0, &seeds[0].1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(held);
        let (next, next_key) = stage(&mut source, seeds[0].0, &seeds[0].1, servers[0].address);
        assert_ne!(next_key, operations[0].1);
        timeout(DEADLINE, async {
            while source.core.infrastructure.entries.get(&next).unwrap().phase != Phase::Live {
                pump_many(&mut source, &mut servers).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(source.core.infrastructure.entries.len(), 4);
        for (index, (_, key)) in operations.iter().enumerate().skip(1) {
            assert_eq!(view.infrastructure_live(*key), Some(servers[index].address));
        }
        shutdown(source, &handle).await;
        for server in servers {
            server.shutdown().await;
        }
        assert!(dns.shutdown().await >= 4);
    })
    .await
    .unwrap();
}

mod lifecycle;
