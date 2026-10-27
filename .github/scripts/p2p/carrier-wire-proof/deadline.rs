#![forbid(unsafe_code)]

use super::*;
use libp2p::{
    core::transport::TransportEvent,
    relay::client::{
        Behaviour as ClientBehaviour, Connection, OperationCapability, Transport as RelayTransport,
    },
};
use std::pin::Pin;
use tokio::time::{Instant, advance, pause, resume};

type Server = Swarm<libp2p::relay::Behaviour>;
type Capture = (PeerId, OperationCapability);

/// A real authenticated relay-control peer that accepts STOP but never answers APP Noise.
struct NoiseSink {
    swarm: Swarm<ClientBehaviour>,
    transport: RelayTransport,
    stream: Option<Connection>,
    announced: bool,
    accepted: bool,
    noise_seen: bool,
}

fn poll_noise(
    stream: &mut Option<Connection>,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<usize>> {
    let Some(connection) = stream.as_mut() else {
        return Poll::Pending;
    };
    let mut byte = [0; 1];
    futures::AsyncRead::poll_read(Pin::new(connection), cx, &mut byte)
}

async fn pump(
    server: &mut Server,
    source: &mut Carrier,
    first: &mut Carrier,
    sink: &mut NoiseSink,
) -> Option<Capture> {
    let NoiseSink {
        swarm,
        transport,
        stream,
        announced,
        accepted,
        noise_seen,
    } = sink;
    let read_enabled = stream.is_some() && !*noise_seen;
    tokio::select! {
        _ = server.select_next_some() => None,
        event = source.core.swarm.select_next_some() => {
            let captured = match &event {
                SwarmEvent::Behaviour(BehaviourEvent::Relays(
                    libp2p::relay::client::Event::OutboundCircuitEstablished {
                        relay_peer_id, operation, ..
                    }
                )) => Some((*relay_peer_id, operation.clone())),
                _ => None,
            };
            source.core.event(event).unwrap();
            captured
        }
        event = first.core.swarm.select_next_some() => {
            first.core.event(event).unwrap();
            None
        }
        event = swarm.select_next_some() => {
            if let SwarmEvent::Behaviour(libp2p::relay::client::Event::ReservationReqAccepted { .. }) = event {
                *accepted = true;
            }
            None
        }
        event = futures::future::poll_fn(|cx| Pin::new(&mut *transport).poll(cx)) => {
            match event {
                TransportEvent::NewAddress { .. } => *announced = true,
                TransportEvent::Incoming { upgrade, .. } => {
                    assert!(stream.is_none(), "one controlled negative circuit");
                    // The raw relay upgrade is Ready; stream I/O performs real STOP acceptance.
                    *stream = Some(upgrade.await.unwrap());
                }
                TransportEvent::ListenerError { error, .. } => panic!("sink listener error: {error}"),
                TransportEvent::ListenerClosed { reason, .. } => panic!("sink listener closed: {reason:?}"),
                _ => {}
            }
            None
        }
        read = futures::future::poll_fn(|cx| poll_noise(stream, cx)), if read_enabled => {
            assert_eq!(read.unwrap(), 1, "real source Noise byte after STOP acceptance");
            *noise_seen = true;
            None
        }
    }
}

async fn reserve(
    server: &mut Server,
    source: &mut Carrier,
    first: &mut Carrier,
    sink: &mut NoiseSink,
    relay: RelayAddr,
) {
    let (sender, mut receiver) = oneshot::channel();
    first.core.command(Command::Reserve(relay, sender));
    let mut first_ready = false;
    timeout(DEADLINE, async {
        while !first_ready || !sink.announced || !sink.accepted {
            assert!(pump(server, source, first, sink).await.is_none());
            if !first_ready {
                match receiver.try_recv() {
                    Ok(result) => {
                        assert_eq!(result.unwrap().relay(), relay);
                        first_ready = true;
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(oneshot::error::TryRecvError::Closed) => panic!("reservation reply closed"),
                }
            }
        }
    })
    .await
    .unwrap();
}

fn staged_generation(source: &Carrier, peer: PeerId) -> u64 {
    source
        .core
        .pending
        .values()
        .find(|pending| pending.peer == peer)
        .and_then(|pending| pending.operation)
        .expect("production Connect command staged an operation")
        .generation
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_protocol_fixture_established_deadline() {
    timeout(Duration::from_secs(40), async {
        probe::reset();
        let dns = crate::dns::tests::support::Server::new().await;
        let server_key = Keypair::generate_ed25519();
        let relay_peer = server_key.public().to_peer_id();
        let server_executor = OwnedExecutor::new();
        let mut config = libp2p::relay::Config::default();
        config.reservation_rate_limiters.clear();
        config.circuit_src_rate_limiters.clear();
        config.reservation_duration = Duration::from_secs(60);
        let mut server = Swarm::new(
            native(&server_key),
            libp2p::relay::Behaviour::new(relay_peer, config),
            relay_peer,
            libp2p::swarm::Config::with_executor(server_executor.handle()),
        );
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let listen = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address;
            }
        };
        server.add_external_address(listen.clone());
        let relay = RelayAddr::new(relay_peer, socket_address(&listen).unwrap()).unwrap();
        let source_key = Keypair::generate_ed25519();
        let first_key = Keypair::generate_ed25519();
        let sink_key = Keypair::generate_ed25519();
        let source_peer = source_key.public().to_peer_id();
        let first_peer = first_key.public().to_peer_id();
        let sink_peer = sink_key.public().to_peer_id();
        let (mut source, source_handle, _source_incoming) = Carrier::bind_with_discovery(
            source_key,
            "127.0.0.1:0".parse().unwrap(),
            vec![first_peer, sink_peer],
            discovery(&dns),
        )
        .unwrap();
        let (mut first, first_handle, _first_incoming) = Carrier::bind_with_discovery(
            first_key,
            "127.0.0.1:0".parse().unwrap(),
            vec![source_peer],
            discovery(&dns),
        )
        .unwrap();
        let sink_executor = OwnedExecutor::new();
        let (mut transport, behaviour) = libp2p::relay::client::new(sink_peer);
        transport
            .listen_on(
                ListenerId::next(),
                listen
                    .with(Protocol::P2p(relay_peer))
                    .with(Protocol::P2pCircuit),
            )
            .unwrap();
        let mut sink = NoiseSink {
            swarm: Swarm::new(
                native(&sink_key),
                behaviour,
                sink_peer,
                libp2p::swarm::Config::with_executor(sink_executor.handle()),
            ),
            transport,
            stream: None,
            announced: false,
            accepted: false,
            noise_seen: false,
        };
        reserve(&mut server, &mut source, &mut first, &mut sink, relay).await;

        let (sender, mut receiver) = oneshot::channel();
        source
            .core
            .command(Command::ConnectVia(first_peer, relay, sender));
        let established_generation = staged_generation(&source, first_peer);
        let mut established_capture = None;
        let mut established_reply = None;
        timeout(DEADLINE, async {
            while established_capture.is_none() || established_reply.is_none() {
                if let Some(capture) = pump(&mut server, &mut source, &mut first, &mut sink).await {
                    assert!(
                        established_capture.is_none(),
                        "only one source Connect operation"
                    );
                    assert_eq!(capture.0, relay_peer);
                    assert_eq!(
                        capture.1.generation().unwrap().get(),
                        established_generation
                    );
                    established_capture = Some(capture.1);
                }
                if established_reply.is_none() {
                    match receiver.try_recv() {
                        Ok(result) => established_reply = Some(result.unwrap()),
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(oneshot::error::TryRecvError::Closed) => {
                            panic!("established Connect reply closed")
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        let established = established_capture.take().unwrap();
        let connection = established_reply.unwrap();
        let link = source_handle
            .links()
            .borrow()
            .iter()
            .find(|link| link.peer == first_peer)
            .copied()
            .expect("authenticated APP link published");
        assert_eq!(link.connection, connection);
        assert!(
            matches!(link.route, Route::Relayed { relay: Some(peer), generation }
            if peer == relay_peer && generation == established_generation)
        );
        assert!(probe::bound_live(&established));
        let control = source
            .core
            .swarm
            .behaviour()
            .admission
            .connection(&relay_peer)
            .unwrap();
        println!("CARRIER_ESTABLISHED_CAPTURED");

        let (sender, mut pending_reply) = oneshot::channel();
        source
            .core
            .command(Command::ConnectVia(sink_peer, relay, sender));
        let pending_generation = staged_generation(&source, sink_peer);
        assert_ne!(pending_generation, established_generation);
        let mut pending_capture = None;
        timeout(DEADLINE, async {
            while pending_capture.is_none() || !sink.noise_seen {
                if let Some(capture) = pump(&mut server, &mut source, &mut first, &mut sink).await {
                    assert!(pending_capture.is_none());
                    assert_eq!(capture.0, relay_peer);
                    assert_eq!(capture.1.generation().unwrap().get(), pending_generation);
                    pending_capture = Some(capture.1);
                }
            }
        })
        .await
        .unwrap();
        let pending = pending_capture.take().unwrap();
        assert_eq!(
            source
                .core
                .swarm
                .behaviour()
                .admission
                .connection(&relay_peer),
            Some(control)
        );
        assert!(
            source
                .core
                .pending
                .values()
                .any(|item| item.peer == sink_peer)
        );
        assert!(
            !source_handle
                .links()
                .borrow()
                .iter()
                .any(|link| link.peer == sink_peer)
        );
        assert!(matches!(
            pending_reply.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(probe::bound_live(&established));
        assert!(probe::bound_live(&pending));
        println!("CARRIER_UNESTABLISHED_CAPTURED");

        let before = Instant::now();
        pause();
        advance(DEADLINE + Duration::from_millis(1)).await;
        assert!(Instant::now() > before + DEADLINE);
        println!("CARRIER_ORIGINAL_DEADLINE_CROSSED");
        assert!(
            probe::bound_live(&established),
            "CARRIER_ESTABLISHED_DEADLINE_REGRESSION"
        );
        assert!(!probe::bound_live(&pending));
        println!("CARRIER_ESTABLISHED_DEADLINE_LIVE");
        drop(established);
        drop(pending);
        resume();

        let listeners = [
            (*source_handle.listening.borrow()).unwrap(),
            (*first_handle.listening.borrow()).unwrap(),
        ];
        drop(sink);
        sink_executor.shutdown().await.unwrap();
        source.run(async {}).await.unwrap();
        first.run(async {}).await.unwrap();
        drop(server);
        server_executor.shutdown().await.unwrap();
        probe::reset();
        for address in listeners {
            let listener = tokio::net::TcpListener::bind(address).await.unwrap();
            drop(listener);
        }
        dns.quiet();
        println!("CARRIER_DEADLINE_JOINED_CLEANUP");
    })
    .await
    .unwrap();
}
