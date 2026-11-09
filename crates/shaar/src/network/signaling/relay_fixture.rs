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

// Widened to `pub(crate)` ONLY for the cfg(test)-only startup resources
// regression suite (this module itself is #[cfg(test)]-only). Every byte
// traversing the relay is counted for the zero-payload oracle.
pub(crate) struct RelayFixture {
    pub(crate) address: RelayAddr,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop: Option<oneshot::Sender<()>>,
    tasks: JoinSet<io::Result<()>>,
}
impl RelayFixture {
    /// cancel-safe: NO — fixture Drop aborts, while successful close joins its retained root.
    pub(crate) async fn start() -> Self {
        let key = Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let (ready, address) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut tasks = JoinSet::new();
        tasks.spawn(run(key, ready, stopped, std::sync::Arc::clone(&counter)));
        let address = RelayAddr::new(peer, address.await.unwrap()).unwrap();
        Self {
            address,
            counter,
            stop: Some(stop),
            tasks,
        }
    }
    /// Total bytes counted through every relay-node connection so far.
    pub(crate) fn relayed_bytes(&self) -> u64 {
        self.counter.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// cancel-safe: NO — only successful return proves the relay root and I/O were joined.
    pub(crate) async fn close(mut self) {
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
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> io::Result<()> {
    let mut executor = OwnedExecutor::new();
    let peer = key.public().to_peer_id();
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .map(move |io, _| CountingIo::new(io, counter))
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

/// Counts every byte that enters or leaves the relay node on any
/// connection (inbound reads and outbound writes): the byte-level
/// oracle for "zero application payload traversed the relay".
struct CountingIo<S> {
    io: S,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
impl<S> CountingIo<S> {
    fn new(io: S, counter: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
        Self { io, counter }
    }
}
impl<S: futures::io::AsyncRead + Unpin> futures::io::AsyncRead for CountingIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let counted = std::sync::Arc::clone(&self.counter);
        std::pin::Pin::new(&mut self.io)
            .poll_read(cx, buf)
            .map(|ready| {
                ready.map(|read| {
                    counted.fetch_add(read as u64, std::sync::atomic::Ordering::SeqCst);
                    read
                })
            })
    }
}
impl<S: futures::io::AsyncWrite + Unpin> futures::io::AsyncWrite for CountingIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let counted = std::sync::Arc::clone(&self.counter);
        std::pin::Pin::new(&mut self.io)
            .poll_write(cx, buf)
            .map(|ready| {
                ready.map(|written| {
                    counted.fetch_add(written as u64, std::sync::atomic::Ordering::SeqCst);
                    written
                })
            })
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_close(cx)
    }
}
