#![forbid(unsafe_code)]

use super::*;
use futures::task::{ArcWake, waker};
use libp2p::{multiaddr::Protocol, relay::wire_probe as probe};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::SystemTime,
};
use tokio::{sync::oneshot, time::timeout};

#[path = "../../../../crates/shaar-p2p/tests/relay_expiry/codec.rs"]
mod codec;

struct ReleaseWake(AtomicUsize);

impl ArcWake for ReleaseWake {
    fn wake_by_ref(counter: &Arc<Self>) {
        counter.0.fetch_add(1, Ordering::SeqCst);
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

fn native(key: &Keypair) -> libp2p::core::transport::Boxed<(PeerId, StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(DEADLINE)
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

fn respond(
    server: &mut Swarm<rpc::Behaviour<codec::HopCodec>>,
    event: SwarmEvent<rpc::Event<codec::Hop, codec::Hop>>,
    client: PeerId,
    listen: &libp2p::Multiaddr,
    relay: PeerId,
    requests: &mut usize,
) {
    if let SwarmEvent::Behaviour(rpc::Event::Message {
        peer,
        message: rpc::Message::Request {
            request, channel, ..
        },
        ..
    }) = event
    {
        assert_eq!(peer, client);
        assert_eq!(request.kind, Some(0));
        assert!(request.reservation.is_none());
        *requests += 1;
        assert_eq!(*requests, 1, "one owned RESERVE request");
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        server
            .behaviour_mut()
            .send_response(
                channel,
                codec::Hop {
                    kind: Some(2),
                    status: Some(100),
                    reservation: Some(codec::Reservation {
                        expire: Some(now + 60),
                        addresses: vec![listen.clone().with(Protocol::P2p(relay)).to_vec()],
                    }),
                    limit: Some(codec::Limit {
                        duration: Some(1),
                        data: Some(4096),
                    }),
                },
            )
            .unwrap();
    }
}

async fn run_case(revoked: bool) {
    probe::reset();
    let dns = crate::dns::tests::support::Server::new().await;
    let key = Keypair::generate_ed25519();
    let relay_peer = key.public().to_peer_id();
    let server_executor = OwnedExecutor::new();
    let mut server = Swarm::new(
        native(&key),
        rpc::Behaviour::with_codec(
            codec::HopCodec,
            [(libp2p::relay::HOP_PROTOCOL_NAME, rpc::ProtocolSupport::Full)],
            rpc::Config::default()
                .with_request_timeout(DEADLINE)
                .with_max_concurrent_streams(1),
        ),
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
    let relay = RelayAddr::new(relay_peer, socket_address(&listen).unwrap()).unwrap();
    let (mut carrier, handle, _incoming) = Carrier::bind_with_discovery(
        Keypair::generate_ed25519(),
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        discovery(&dns),
    )
    .unwrap();
    let client = *carrier.core.swarm.local_peer_id();
    probe::arm(relay_peer).unwrap();
    assert!(
        probe::arm(relay_peer).is_err(),
        "a second arm must apply backpressure"
    );
    let (reply, mut result) = oneshot::channel();
    carrier.core.command(Command::Reserve(relay, reply));
    let mut entered = None;
    let mut requests = 0;
    timeout(DEADLINE, async {
        while entered.is_none() || handle.listening.borrow().is_none() {
            tokio::select! {
                entry = futures::future::poll_fn(probe::poll_entered), if entered.is_none() => {
                    entered = Some(entry);
                }
                event = carrier.core.swarm.select_next_some() => carrier.core.event(event).unwrap(),
                event = server.select_next_some() => {
                    respond(&mut server, event, client, &listen, relay_peer, &mut requests);
                    assert_eq!(requests, 0, "protocol must remain before its first inner poll");
                }
            }
        }
    })
    .await
    .unwrap();
    let entry = entered.unwrap();
    let (generation, control) = entry.entered.expect("actual protocol barrier entry");
    assert!(generation > 0);
    assert!(entry.held);
    assert_eq!(entry.fresh_inner_polls, 0);
    assert_eq!(
        carrier
            .core
            .swarm
            .behaviour()
            .admission
            .connection(&relay_peer),
        Some(control)
    );
    let capability = probe::take_retained().expect("actual operation retained at barrier");
    assert_eq!(capability.generation().unwrap().get(), generation);
    assert!(probe::bound_live(&capability));
    let gate = carrier.core.relay.gate.clone();
    let released = gate
        .released_flag(relay_peer, relay::gate::Slot::Reserve, generation)
        .unwrap();
    assert!(!released.load(Ordering::Acquire));
    let listening = (*handle.listening.borrow()).expect("native listener observed");

    if !revoked {
        probe::release_protocol();
        let lease = timeout(DEADLINE, async {
            loop {
                tokio::select! {
                    event = carrier.core.swarm.select_next_some() => carrier.core.event(event).unwrap(),
                    event = server.select_next_some() => {
                        respond(&mut server, event, client, &listen, relay_peer, &mut requests);
                    }
                }
                match result.try_recv() {
                    Ok(reply) => break reply.unwrap(),
                    Err(oneshot::error::TryRecvError::Empty) => {}
                    Err(oneshot::error::TryRecvError::Closed) => panic!("positive reserve reply closed"),
                }
            }
        }).await.unwrap();
        assert_eq!(requests, 1);
        assert_eq!(lease.relay(), relay);
        assert_eq!(lease.generation(), generation);
        assert_eq!(lease.connection_id(), control);
        assert_eq!(handle.relay_leases().borrow().as_slice(), &[lease]);
        assert!(probe::snapshot().fresh_inner_polls > 0);
        drop(capability);
        carrier.run(async {}).await.unwrap();
        probe::reset();
        println!("CARRIER_PROTOCOL_POSITIVE_ACCEPTED");
    } else {
        println!("CARRIER_PROTOCOL_ENTERED_BOUND");
        gate.revoke_generation(relay_peer, relay::gate::Slot::Reserve, generation);
        assert!(!probe::bound_live(&capability));
        gate.prune_released();
        assert_eq!(gate.record_count(), 1);
        assert!(!released.load(Ordering::Acquire));
        assert!(matches!(
            result.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        probe::release_protocol();
        // Hold terminal notifications until the gate itself has resolved the parked poll.
        // Otherwise Core's disconnect could mask a missing protocol guard.
        let mut terminal_events = Vec::with_capacity(2);
        let resolution = timeout(DEADLINE, async {
            loop {
                tokio::select! {
                    observed = futures::future::poll_fn(probe::poll_resolution) => break observed,
                    event = carrier.core.swarm.select_next_some() => {
                        let related = matches!(&event,
                            SwarmEvent::ListenerError { listener_id, .. }
                            | SwarmEvent::ListenerClosed { listener_id, .. }
                            if *listener_id != carrier.core.native_listener);
                        if related {
                            assert!(terminal_events.len() < 2, "bounded terminal notifications");
                            terminal_events.push(event);
                        } else {
                            carrier.core.event(event).unwrap();
                        }
                    }
                    event = server.select_next_some() => {
                        assert_eq!(probe::snapshot().fresh_inner_polls, 0, "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION");
                        respond(&mut server, event, client, &listen, relay_peer, &mut requests);
                    }
                }
                assert_eq!(probe::snapshot().fresh_inner_polls, 0, "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION");
            }
        }).await.unwrap();
        assert_eq!(
            resolution.fresh_inner_polls, 0,
            "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION"
        );
        assert!(resolution.denied_protocol_polls > 0);
        let mut terminal = false;
        for event in terminal_events {
            terminal |= matches!(&event, SwarmEvent::ListenerClosed { .. });
            carrier.core.event(event).unwrap();
        }
        let mut reply = match result.try_recv() {
            Ok(value) => Some(value),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => panic!("revoked reserve lost its reply"),
        };
        timeout(DEADLINE, async {
            while !terminal || reply.is_none() {
                tokio::select! {
                    progress = futures::future::poll_fn(|cx| probe::poll_progress(cx, 0)) => {
                        assert_eq!(progress.fresh_inner_polls, 0, "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION");
                    }
                    event = carrier.core.swarm.select_next_some() => {
                        if let SwarmEvent::ListenerClosed { listener_id, .. } = &event {
                            terminal |= *listener_id != carrier.core.native_listener;
                        }
                        carrier.core.event(event).unwrap();
                    }
                    event = server.select_next_some() => {
                        assert_eq!(probe::snapshot().fresh_inner_polls, 0, "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION");
                        respond(&mut server, event, client, &listen, relay_peer, &mut requests);
                    }
                }
                assert_eq!(probe::snapshot().fresh_inner_polls, 0, "CARRIER_PROTOCOL_POLL_AFTER_REVOCATION");
                if reply.is_none() {
                    match result.try_recv() {
                        Ok(value) => reply = Some(value),
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        Err(oneshot::error::TryRecvError::Closed) => panic!("revoked reserve lost its reply"),
                    }
                }
            }
        }).await.unwrap();
        assert!(reply.unwrap().is_err());
        assert_eq!(requests, 0);
        assert!(handle.relay_leases().borrow().is_empty());
        assert!(handle.links().borrow().is_empty());
        assert!(!released.load(Ordering::Acquire));
        gate.prune_released();
        assert_eq!(gate.record_count(), 1);
        println!("CARRIER_PROTOCOL_REVOKED_NO_INNER_POLL");
        gate.revoke_all();
        let Carrier { core, executor } = carrier;
        drop(core);
        executor.shutdown().await.unwrap();
        gate.finish_shutdown();
        probe::reset();
        assert!(!released.load(Ordering::Acquire));
        let mut join = Box::pin(gate.join_release());
        let wake = Arc::new(ReleaseWake(AtomicUsize::new(0)));
        let task_waker = waker(wake.clone());
        let mut cx = Context::from_waker(&task_waker);
        assert!(join.as_mut().poll(&mut cx).is_pending());
        let before = wake.0.load(Ordering::SeqCst);
        drop(capability);
        assert!(released.load(Ordering::Acquire));
        assert!(wake.0.load(Ordering::SeqCst) > before);
        assert!(matches!(join.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        drop(join);
        gate.prune_released();
        assert_eq!(gate.record_count(), 0);
        println!("CARRIER_PROTOCOL_RETAINED_UNTIL_LAST_DROP");
    }
    drop(server);
    server_executor.shutdown().await.unwrap();
    let listener = tokio::net::TcpListener::bind(listening).await.unwrap();
    drop(listener);
    dns.quiet();
    if revoked {
        println!("CARRIER_PROTOCOL_JOINED_CLEANUP");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_protocol_fixture_revocation() {
    timeout(Duration::from_secs(40), async {
        run_case(false).await;
        run_case(true).await;
    })
    .await
    .unwrap();
}
