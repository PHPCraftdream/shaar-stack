#![forbid(unsafe_code)]

use super::*;
use libp2p::relay::client::OperationCapability;
use tokio::time::{Instant, advance, pause, resume};

type Server = Swarm<libp2p::relay::Behaviour>;
type Capture = (PeerId, OperationCapability);

async fn pump(
    server: &mut Server,
    source: &mut Carrier,
    first: &mut Carrier,
    second: &mut Carrier,
    poll_second: bool,
) -> Option<Capture> {
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
        event = second.core.swarm.select_next_some(), if poll_second => {
            second.core.event(event).unwrap();
            None
        }
    }
}

async fn reserve(
    server: &mut Server,
    source: &mut Carrier,
    first: &mut Carrier,
    second: &mut Carrier,
    relay: RelayAddr,
    reserve_first: bool,
) {
    let (sender, mut receiver) = oneshot::channel();
    if reserve_first {
        first.core.command(Command::Reserve(relay, sender));
    } else {
        second.core.command(Command::Reserve(relay, sender));
    }
    timeout(DEADLINE, async {
        loop {
            assert!(pump(server, source, first, second, true).await.is_none());
            match receiver.try_recv() {
                Ok(result) => {
                    assert_eq!(result.unwrap().relay(), relay);
                    break;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => panic!("reservation reply closed"),
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
        let second_key = Keypair::generate_ed25519();
        let source_peer = source_key.public().to_peer_id();
        let first_peer = first_key.public().to_peer_id();
        let second_peer = second_key.public().to_peer_id();
        let (mut source, source_handle, _source_incoming) = Carrier::bind_with_discovery(
            source_key,
            "127.0.0.1:0".parse().unwrap(),
            vec![first_peer, second_peer],
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
        let (mut second, second_handle, _second_incoming) = Carrier::bind_with_discovery(
            second_key,
            "127.0.0.1:0".parse().unwrap(),
            vec![source_peer],
            discovery(&dns),
        )
        .unwrap();
        reserve(
            &mut server,
            &mut source,
            &mut first,
            &mut second,
            relay,
            true,
        )
        .await;
        reserve(
            &mut server,
            &mut source,
            &mut first,
            &mut second,
            relay,
            false,
        )
        .await;

        let (sender, mut receiver) = oneshot::channel();
        source
            .core
            .command(Command::ConnectVia(first_peer, relay, sender));
        let established_generation = staged_generation(&source, first_peer);
        let mut established_capture = None;
        let mut established_reply = None;
        timeout(DEADLINE, async {
            while established_capture.is_none() || established_reply.is_none() {
                if let Some(capture) =
                    pump(&mut server, &mut source, &mut first, &mut second, true).await
                {
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
            .command(Command::ConnectVia(second_peer, relay, sender));
        let pending_generation = staged_generation(&source, second_peer);
        assert_ne!(pending_generation, established_generation);
        // Its control handler remains driven by the owned executor, but no second APP
        // listener upgrade is polled: HOP completes while end-to-end Noise is withheld.
        let pending = timeout(DEADLINE, async {
            loop {
                if let Some(capture) =
                    pump(&mut server, &mut source, &mut first, &mut second, false).await
                {
                    assert_eq!(capture.0, relay_peer);
                    assert_eq!(capture.1.generation().unwrap().get(), pending_generation);
                    break capture.1;
                }
            }
        })
        .await
        .unwrap();
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
                .any(|item| item.peer == second_peer)
        );
        assert!(
            !source_handle
                .links()
                .borrow()
                .iter()
                .any(|link| link.peer == second_peer)
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
        // Both are genuine, control-bound capabilities. Only the first operation
        // reached the production Swarm/Noise establishment path before expiry.
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
            (*second_handle.listening.borrow()).unwrap(),
        ];
        source.run(async {}).await.unwrap();
        first.run(async {}).await.unwrap();
        second.run(async {}).await.unwrap();
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
