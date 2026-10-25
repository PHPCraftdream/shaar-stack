use std::{io, net::SocketAddr, time::Duration};

use futures::StreamExt;
use libp2p::{
    PeerId, Swarm, Transport,
    core::{muxing::StreamMuxerBox, upgrade},
    identity::Keypair,
    multiaddr::Protocol,
    noise, relay,
    swarm::SwarmEvent,
    tcp, yamux,
};
use shaar_p2p::{Carrier, CarrierHandle, OwnedExecutor, Received, RelayAddr};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};

#[derive(Clone, Copy, Default, Debug)]
pub struct Counts {
    pub reserved: u64,
    pub renewed: u64,
    pub denied: u64,
    pub circuits: u64,
    pub closed: u64,
}

async fn server(
    key: Keypair,
    config: relay::Config,
    ready: oneshot::Sender<SocketAddr>,
    stop: oneshot::Receiver<()>,
    counts: watch::Sender<Counts>,
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
    let mut data = Counts::default();
    tokio::pin!(stop);
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
                SwarmEvent::Behaviour(event) => {
                    match event {
                        relay::Event::ReservationReqAccepted { renewed: true, .. } => data.renewed = data.renewed.saturating_add(1),
                        relay::Event::ReservationReqAccepted { renewed: false, .. } => data.reserved = data.reserved.saturating_add(1),
                        relay::Event::ReservationReqDenied { .. } => data.denied = data.denied.saturating_add(1),
                        relay::Event::CircuitReqAccepted { .. } => data.circuits = data.circuits.saturating_add(1),
                        relay::Event::CircuitClosed { .. } | relay::Event::ReservationClosed { .. } => data.closed = data.closed.saturating_add(1),
                        _ => {} // Other fixture diagnostics do not establish acceptance.
                    }
                    counts.send_replace(data);
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

pub struct Group {
    pub a: CarrierHandle,
    pub b: CarrierHandle,
    pub a_in: mpsc::Receiver<Received>,
    pub b_in: mpsc::Receiver<Received>,
    pub relay: RelayAddr,
    pub counts: watch::Receiver<Counts>,
    stops: Vec<oneshot::Sender<()>>,
    tasks: JoinSet<io::Result<()>>,
}

impl Group {
    pub async fn start(config: relay::Config) -> Self {
        let server_key = Keypair::generate_ed25519();
        let server_id = server_key.public().to_peer_id();
        let ka = Keypair::generate_ed25519();
        let kb = Keypair::generate_ed25519();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (a, ah, ar) = Carrier::bind(ka, "127.0.0.1:0".parse().unwrap(), vec![pb]).unwrap();
        let (b, bh, br) = Carrier::bind(kb, "127.0.0.1:0".parse().unwrap(), vec![pa]).unwrap();
        let mut tasks = JoinSet::new();
        let mut stops = Vec::with_capacity(3);
        for owner in [a, b] {
            let (stop, stopped) = oneshot::channel();
            stops.push(stop);
            // Exactly two owned signal drivers and one owned relay fixture.
            tasks.spawn(owner.run(async {
                let _ = stopped.await;
            }));
        }
        let (ready, address) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        stops.push(stop);
        let (counts, observed) = watch::channel(Counts::default());
        tasks.spawn(server(server_key, config, ready, stopped, counts));
        let relay = RelayAddr::new(server_id, address.await.unwrap()).unwrap();
        ah.local_addr().await.unwrap();
        bh.local_addr().await.unwrap();
        Self {
            a: ah,
            b: bh,
            a_in: ar,
            b_in: br,
            relay,
            counts: observed,
            stops,
            tasks,
        }
    }

    pub fn stop_relay(&mut self) {
        // The finished relay task's result remains owned by the same JoinSet.
        let _ = self.stops.remove(2).send(());
    }

    pub async fn close(mut self) {
        for stop in self.stops.drain(..) {
            // Best effort: completed drivers are still checked through their retained results.
            let _ = stop.send(());
        }
        let mut joined = 0;
        while let Some(result) = self.tasks.join_next().await {
            result.unwrap().unwrap();
            joined += 1;
        }
        assert_eq!(joined, 3);
        assert!(self.a.local_addr().await.is_err());
        assert!(self.b.local_addr().await.is_err());
    }

    pub async fn wait_counts(&self, predicate: impl Fn(Counts) -> bool) {
        let mut counts = self.counts.clone();
        loop {
            let value = *counts.borrow_and_update();
            if predicate(value) {
                return;
            }
            counts.changed().await.unwrap();
        }
    }
}

pub fn config() -> relay::Config {
    relay::Config {
        max_reservations: 2,
        max_reservations_per_peer: 1,
        reservation_duration: Duration::from_secs(60),
        max_circuits: 4,
        max_circuits_per_peer: 2,
        max_circuit_duration: Duration::from_secs(60),
        max_circuit_bytes: 128 * 1024,
        ..relay::Config::default()
    }
}

pub fn unknown_peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}
