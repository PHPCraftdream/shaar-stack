use super::*;
use futures::StreamExt;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    noise,
    swarm::{Executor, SwarmEvent},
    tcp, yamux,
};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    sync::oneshot,
    task::JoinSet,
    time::{Duration, timeout},
};

fn relay_native(key: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(10))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

#[derive(Clone)]
struct RelayExecutor(Arc<std::sync::Mutex<JoinSet<()>>>);
impl Executor for RelayExecutor {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut tasks = self.0.lock().unwrap();
        assert!(tasks.len() < 64);
        tasks.spawn(future);
    }
}
impl RelayExecutor {
    async fn shutdown(self) {
        let mut tasks = std::mem::take(&mut *self.0.lock().unwrap());
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled());
            }
        }
    }
}

struct RelayServer {
    peer: PeerId,
    address: RelayAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

async fn start_relay() -> RelayServer {
    let key = Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let executor = RelayExecutor(Arc::new(std::sync::Mutex::new(JoinSet::new())));
    let mut config = libp2p::relay::Config::default();
    config.reservation_rate_limiters.clear();
    config.circuit_src_rate_limiters.clear();
    config.reservation_duration = Duration::from_secs(4);
    let mut server = Swarm::new(
        relay_native(&key),
        libp2p::relay::Behaviour::new(peer, config),
        peer,
        libp2p::swarm::Config::with_executor(executor.clone()),
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
    let relay_addr = RelayAddr::new(peer, socket_address(&address).unwrap()).unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = stopped => {},
            _ = async { loop { server.select_next_some().await; } } => {},
        }
        drop(server);
        executor.shutdown().await;
    });
    RelayServer {
        peer,
        address: relay_addr,
        stop,
        task,
    }
}

fn discovery(dns: &crate::dns::tests::support::Server) -> DiscoveryConfig {
    let seed = Keypair::generate_ed25519().public().to_peer_id();
    DiscoveryConfig::new(
        vec![(
            seed,
            format!("/dns4/seed.example./tcp/443/p2p/{seed}")
                .parse()
                .unwrap(),
        )],
        vec![dns.address],
    )
    .unwrap()
}

async fn stop_relay(server: RelayServer) {
    let _ = server.stop.send(());
    timeout(Duration::from_secs(10), server.task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_production_relay_roles_end_to_end() {
    timeout(Duration::from_secs(30), async {
        let dns = crate::dns::tests::support::Server::new().await;
        let server = start_relay().await;
        let relay = server.address;
        let source_key = Keypair::generate_ed25519();
        let destination_key = Keypair::generate_ed25519();
        let source_peer = source_key.public().to_peer_id();
        let destination_peer = destination_key.public().to_peer_id();
        let source_discovery = discovery(&dns);
        let destination_discovery = discovery(&dns);
        let (source, source_handle, mut source_in) = Carrier::bind_with_discovery(
            source_key,
            "127.0.0.1:0".parse().unwrap(),
            vec![destination_peer],
            source_discovery,
        )
        .unwrap();
        let (destination, destination_handle, mut destination_in) = Carrier::bind_with_discovery(
            destination_key,
            "127.0.0.1:0".parse().unwrap(),
            vec![source_peer],
            destination_discovery,
        )
        .unwrap();
        let mut tasks = JoinSet::new();
        let (source_stop, source_stopped) = oneshot::channel();
        let (destination_stop, destination_stopped) = oneshot::channel();
        tasks.spawn(source.run(async {
            let _ = source_stopped.await;
        }));
        tasks.spawn(destination.run(async {
            let _ = destination_stopped.await;
        }));
        let mut snapshots = destination_handle.relay_leases();
        let initial = timeout(Duration::from_secs(10), destination_handle.reserve(relay))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshots.borrow().as_slice(), &[initial]);
        assert_eq!(
            timeout(Duration::from_secs(10), destination_handle.reserve(relay))
                .await
                .unwrap()
                .unwrap(),
            initial
        );
        loop {
            let renewed = snapshots.borrow_and_update().first().copied();
            if let Some(renewed) = renewed {
                assert_eq!(renewed.generation(), initial.generation());
                assert_eq!(renewed.connection_id(), initial.connection_id());
                if renewed.expires_at() > initial.expires_at() {
                    break;
                }
            }
            snapshots.changed().await.unwrap();
        }
        let connection = timeout(
            Duration::from_secs(10),
            source_handle.connect_via(destination_peer, relay),
        )
        .await
        .unwrap()
        .unwrap();
        let link = source_handle.links().borrow()[0];
        assert_eq!(link.connection, connection);
        let Route::Relayed {
            relay: Some(attributed_relay),
            generation,
        } = link.route
        else {
            panic!("expected outbound relayed route");
        };
        assert_eq!(attributed_relay, relay.peer_id());
        assert!(generation > 0);
        source_handle
            .send_on(link, Datagram::new(b"ping").unwrap())
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(10), destination_in.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.peer, source_peer);
        assert!(matches!(received.route, Route::Relayed { relay: Some(attributed_relay), generation } if attributed_relay == relay.peer_id() && generation > 0));
        assert_eq!(received.packet.as_bytes(), b"ping");
        destination_handle
            .send(source_peer, Datagram::new(b"pong").unwrap())
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(10), source_in.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.peer, destination_peer);
        assert_eq!(received.packet.as_bytes(), b"pong");
        assert_eq!(received.route, link.route);
        assert_eq!(
            received.route,
            Route::Relayed {
                relay: Some(relay.peer_id()),
                generation
            }
        );
        let _ = source_stop.send(());
        let _ = destination_stop.send(());
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        stop_relay(server).await;
        dns.quiet();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_production_hostile_relay_identity_and_endpoint() {
    timeout(Duration::from_secs(20), async {
        let dns = crate::dns::tests::support::Server::new().await;
        let server = start_relay().await;
        let key = Keypair::generate_ed25519();
        let (carrier, handle, _incoming) = Carrier::bind_with_discovery(
            key,
            "127.0.0.1:0".parse().unwrap(),
            vec![],
            discovery(&dns),
        )
        .unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(carrier.run(async {
            let _ = stopped.await;
        }));
        let wrong = RelayAddr::new(
            Keypair::generate_ed25519().public().to_peer_id(),
            server.address.socket_addr(),
        )
        .unwrap();
        assert!(
            timeout(Duration::from_secs(10), handle.reserve(wrong))
                .await
                .unwrap()
                .is_err()
        );
        let lease = timeout(Duration::from_secs(10), handle.reserve(server.address))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.relay(), server.address);
        let mut alternate = server.address.socket_addr();
        alternate.set_port(if alternate.port() == 1 { 2 } else { 1 });
        let pinned_elsewhere = RelayAddr::new(server.peer, alternate).unwrap();
        let error = timeout(Duration::from_secs(10), handle.reserve(pinned_elsewhere))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        let _ = stop.send(());
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        stop_relay(server).await;
        dns.quiet();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_production_pending_noise_shutdown_joins_socket() {
    timeout(Duration::from_secs(20), async {
        let dns = crate::dns::tests::support::Server::new().await;
        let server = start_relay().await;
        let key = Keypair::generate_ed25519();
        let app_key = Keypair::generate_ed25519();
        let app = app_key.public().to_peer_id();
        let (carrier, handle, _incoming) = Carrier::bind_with_discovery(
            key,
            "127.0.0.1:0".parse().unwrap(),
            vec![app],
            discovery(&dns),
        )
        .unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(carrier.run(async {
            let _ = stopped.await;
        }));
        let leases = handle.relay_leases();
        let lease = timeout(Duration::from_secs(10), handle.reserve(server.address))
            .await
            .unwrap()
            .unwrap();
        let before = leases.borrow().clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let waiter = tokio::spawn({
            let handle = handle.clone();
            async move { handle.connect(app, endpoint).await }
        });
        let (mut socket, _) = timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(leases.borrow().as_slice(), before.as_slice());
        assert_eq!(leases.borrow()[0].generation(), lease.generation());
        assert_eq!(
            timeout(Duration::from_secs(10), handle.reserve(server.address))
                .await
                .unwrap()
                .unwrap()
                .generation(),
            lease.generation()
        );
        let _ = stop.send(());
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(5), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        stop_relay(server).await;
        dns.quiet();
    })
    .await
    .unwrap();
}
