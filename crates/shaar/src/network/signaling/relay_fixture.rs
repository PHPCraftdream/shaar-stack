use std::{io, net::SocketAddr, time::Duration};

use futures::StreamExt;
use libp2p::{
    Swarm, Transport,
    core::{muxing::StreamMuxerBox, upgrade},
    identity::Keypair,
    multiaddr::Protocol,
    noise, relay,
    swarm::SwarmEvent,
    tcp, yamux,
};
use shaar_p2p::{OwnedExecutor, RelayAddr};
use tokio::{sync::oneshot, task::JoinSet};

pub(super) struct RelayFixture {
    pub(super) address: RelayAddr,
    stop: Option<oneshot::Sender<()>>,
    tasks: JoinSet<io::Result<()>>,
}
impl RelayFixture {
    /// cancel-safe: NO — fixture Drop aborts, while successful close joins its retained root.
    pub(super) async fn start() -> Self {
        let key = Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let (ready, address) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(run(key, ready, stopped));
        let address = RelayAddr::new(peer, address.await.unwrap()).unwrap();
        Self {
            address,
            stop: Some(stop),
            tasks,
        }
    }
    /// cancel-safe: NO — only successful return proves the relay root and I/O were joined.
    pub(super) async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.tasks.join_next().await.unwrap().unwrap().unwrap();
        assert!(self.tasks.is_empty());
        let _rebound = tokio::net::TcpListener::bind(self.address.socket_addr())
            .await
            .unwrap();
    }
}

async fn run(
    key: Keypair,
    ready: oneshot::Sender<SocketAddr>,
    mut stop: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut executor = OwnedExecutor::new();
    let peer = key.public().to_peer_id();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&key).map_err(io::Error::other)?)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(10))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed();
    let config = relay::Config {
        max_reservations: 2,
        max_reservations_per_peer: 1,
        reservation_duration: Duration::from_secs(60),
        max_circuits: 4,
        max_circuits_per_peer: 2,
        max_circuit_duration: Duration::from_secs(30),
        max_circuit_bytes: 128 * 1024,
        ..Default::default()
    };
    let mut swarm = Swarm::new(
        transport,
        relay::Behaviour::new(peer, config),
        peer,
        libp2p::swarm::Config::with_executor(executor.handle()),
    );
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .map_err(io::Error::other)?;
    let mut ready = Some(ready);
    let result = loop {
        tokio::select! {
            _ = &mut stop => break Ok(()),
            result = executor.next_result() => if let Err(error) = result { break Err(error); },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    swarm.add_external_address(address.clone());
                    let mut parts = address.iter();
                    let Some(Protocol::Ip4(ip)) = parts.next() else { panic!("fixture requires IPv4"); };
                    let Some(Protocol::Tcp(port)) = parts.next() else { panic!("fixture requires TCP"); };
                    if let Some(ready) = ready.take() { let _ = ready.send(SocketAddr::new(ip.into(), port)); }
                }
                SwarmEvent::ListenerError { error, .. } => break Err(error),
                _ => {}
            }
        }
    };
    drop(swarm);
    let joined = executor.shutdown().await;
    result.and(joined)
}
