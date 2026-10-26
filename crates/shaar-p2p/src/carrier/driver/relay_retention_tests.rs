use super::*;
use futures::{
    StreamExt,
    task::{ArcWake, waker},
};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    noise,
    swarm::SwarmEvent,
    tcp, yamux,
};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    sync::oneshot,
    task::JoinSet,
    time::{Duration, Instant, timeout},
};

fn native(key: &Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(key).unwrap())
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(10))
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed()
}

#[derive(Clone)]
struct Executor(Arc<std::sync::Mutex<JoinSet<()>>>);
impl Executor {
    async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        let mut tasks = std::mem::take(&mut *self.0.lock().unwrap());
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled());
            }
        }
        Ok(())
    }
}
impl libp2p::swarm::Executor for Executor {
    fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let mut tasks = self.0.lock().unwrap();
        assert!(tasks.len() < 64);
        tasks.spawn(future);
    }
}

struct WakeCounter(AtomicUsize);
impl ArcWake for WakeCounter {
    fn wake_by_ref(counter: &Arc<Self>) {
        counter.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_buffered_reservation_revocation_and_join_vetoes() {
    buffered_reservation_revocation(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_buffered_reservation_revocation_and_join_successor_generation() {
    buffered_reservation_revocation(true).await;
}

async fn buffered_reservation_revocation(successor_case: bool) {
    timeout(Duration::from_secs(20), async {
        let dns = crate::dns::tests::support::Server::new().await;
        let server_key = Keypair::generate_ed25519();
        let relay_peer = server_key.public().to_peer_id();
        let server_executor = Executor(Arc::new(std::sync::Mutex::new(JoinSet::new())));
        let mut server = Swarm::new(
            native(&server_key),
            libp2p::relay::Behaviour::new(relay_peer, {
                let mut config = libp2p::relay::Config::default();
                config.reservation_rate_limiters.clear();
                config
            }),
            relay_peer,
            libp2p::swarm::Config::with_executor(server_executor.clone()),
        );
        server.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let relay_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address;
            }
        };
        server.add_external_address(relay_addr.clone());
        let relay = RelayAddr::new(relay_peer, socket_address(&relay_addr).unwrap()).unwrap();
        let seed = Keypair::generate_ed25519().public().to_peer_id();
        let discovery = DiscoveryConfig::new(
            vec![(seed, format!("/dns4/seed.example./tcp/443/p2p/{seed}").parse().unwrap())],
            vec![dns.address],
        )
        .unwrap();
        let (mut carrier, handle, _incoming) = Carrier::bind_with_discovery(
            Keypair::generate_ed25519(),
            "127.0.0.1:0".parse().unwrap(),
            vec![],
            discovery,
        )
        .unwrap();
        let (reply, mut result) = oneshot::channel();
        carrier.core.command(Command::Reserve(relay, reply));
        let mut original_event = None;
        let mut actual_event_capability = None;
        let mut event_fields = None;
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = carrier.core.swarm.select_next_some() => match event {
                        SwarmEvent::Behaviour(BehaviourEvent::Relays(event @ libp2p::relay::client::Event::ReservationReqAccepted { .. })) => {
                            if let libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, connection_id, operation, .. } = &event {
                                event_fields = Some((*relay_peer_id, *connection_id, operation.generation().unwrap().get()));
                                actual_event_capability = Some(operation.clone());
                            }
                            original_event = Some(event);
                            break;
                        }
                        other => carrier.core.event(other).unwrap(),
                    },
                    _ = server.select_next_some() => {}
                }
            }
        }).await.unwrap();

        let (event_peer, old_connection, generation) = event_fields.unwrap();
        assert_eq!(event_peer, relay_peer);
        let gate = carrier.core.relay.gate.clone();
        assert!(gate.reservation_permit(event_peer, generation, old_connection));
        let released = gate.released_flag(event_peer, relay::gate::Slot::Reserve, generation).unwrap();
        gate.revoke_generation(event_peer, relay::gate::Slot::Reserve, generation);
        assert!(!gate.reservation_permit(event_peer, generation, old_connection));

        assert!(!released.load(Ordering::Acquire));
        let mut successor_lease = None;
        let mut successor_operation = None;
        if successor_case {
            let (release, mut released_reply) = oneshot::channel();
            carrier.core.command(Command::ReleaseRelay(event_peer, release));
            assert_eq!(result.try_recv().unwrap().unwrap_err().kind(), io::ErrorKind::Interrupted);
            let mut release_done = false;
            timeout(Duration::from_secs(10), async {
                while !release_done {
                    tokio::select! {
                        event = carrier.core.swarm.select_next_some() => carrier.core.event(event).unwrap(),
                        _ = server.select_next_some() => {},
                    }
                    carrier.core.relay_tick(Instant::now()).unwrap();
                    release_done = matches!(released_reply.try_recv(), Ok(Ok(())));
                }
            }).await.unwrap();
            assert!(gate.record_count() >= 1);
            assert!(!released.load(Ordering::Acquire));
            let (successor_reply, mut successor_result) = oneshot::channel();
            carrier.core.command(Command::Reserve(relay, successor_reply));
            let mut accepted = None;
            timeout(Duration::from_secs(10), async {
                while accepted.is_none() {
                    tokio::select! {
                        event = carrier.core.swarm.select_next_some() => match event {
                            SwarmEvent::Behaviour(BehaviourEvent::Relays(event @ libp2p::relay::client::Event::ReservationReqAccepted { .. })) => {
                                if let libp2p::relay::client::Event::ReservationReqAccepted { operation, .. } = &event {
                                    successor_operation = Some(operation.clone());
                                }
                                accepted = Some(event);
                            }
                            other => carrier.core.event(other).unwrap(),
                        },
                        _ = server.select_next_some() => {}
                    }
                    carrier.core.relay_tick(Instant::now()).unwrap();
                }
            }).await.unwrap();
            carrier.core.event(SwarmEvent::Behaviour(BehaviourEvent::Relays(accepted.unwrap()))).unwrap();
            let lease = match successor_result.try_recv() {
                Ok(Ok(lease)) => lease,
                Ok(Err(error)) => panic!("successor reserve failed: {error}"),
                Err(oneshot::error::TryRecvError::Empty) => timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            event = carrier.core.swarm.select_next_some() => carrier.core.event(event).unwrap(),
                            _ = server.select_next_some() => {},
                        }
                        carrier.core.relay_tick(Instant::now()).unwrap();
                        match successor_result.try_recv() {
                            Ok(Ok(lease)) => break lease,
                            Ok(Err(error)) => panic!("successor reserve failed: {error}"),
                            Err(oneshot::error::TryRecvError::Empty) => {}
                            Err(oneshot::error::TryRecvError::Closed) => panic!("successor reserve reply closed"),
                        }
                    }
                }).await.unwrap(),
                Err(oneshot::error::TryRecvError::Closed) => panic!("successor reserve reply closed"),
            };
            assert_ne!(lease.generation(), generation);
            assert_ne!(lease.connection_id(), old_connection);
            assert!(gate.reservation_permit(event_peer, lease.generation(), lease.connection_id()));
            assert_eq!(handle.relay_leases().borrow().as_slice(), &[lease]);
            successor_lease = Some(lease);
            carrier.core.event(SwarmEvent::Behaviour(BehaviourEvent::Relays(original_event.take().unwrap()))).unwrap();
            assert_eq!(handle.relay_leases().borrow().as_slice(), &[lease]);
            drop(successor_operation.take());
        }

        if successor_case {
            assert_eq!(handle.relay_leases().borrow().as_slice(), &[successor_lease.unwrap()]);
        } else {
            carrier.core.event(SwarmEvent::Behaviour(BehaviourEvent::Relays(original_event.take().unwrap()))).unwrap();
            assert!(handle.relay_leases().borrow().is_empty());
            assert!(matches!(result.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
        }

        let count_before_shutdown = gate.record_count();
        gate.revoke_all();
        let Carrier { core, executor: carrier_executor } = carrier;
        drop(core);
        carrier_executor.shutdown().await.unwrap();
        gate.finish_shutdown();
        drop(server);
        server_executor.shutdown().await.unwrap();

        let mut join = Box::pin(gate.join_release());
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let task_waker = waker(counter.clone());
        let mut cx = std::task::Context::from_waker(&task_waker);
        assert!(join.as_mut().poll(&mut cx).is_pending());
        assert!(!released.load(Ordering::Acquire));
        assert_eq!(gate.record_count(), count_before_shutdown);
        let wakes = counter.0.load(Ordering::SeqCst);
        drop(actual_event_capability);
        assert!(counter.0.load(Ordering::SeqCst) > wakes);
        assert!(released.load(Ordering::Acquire));
        assert!(matches!(join.as_mut().poll(&mut cx), std::task::Poll::Ready(Ok(()))));
        gate.prune_released();
        assert_eq!(gate.record_count(), 0);
        dns.quiet();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_destination_old_reservation_acceptance_cannot_replace_successor_record() {
    timeout(Duration::from_secs(20), async {
        let dns = crate::dns::tests::support::Server::new().await;
        let server_key = Keypair::generate_ed25519();
        let relay_peer = server_key.public().to_peer_id();
        let server_executor = Executor(Arc::new(std::sync::Mutex::new(JoinSet::new())));
        let mut server = Swarm::new(
            native(&server_key),
            libp2p::relay::Behaviour::new(relay_peer, {
                let mut config = libp2p::relay::Config::default();
                config.reservation_rate_limiters.clear();
                config
            }),
            relay_peer,
            libp2p::swarm::Config::with_executor(server_executor.clone()),
        );
        server.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let relay_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address;
            }
        };
        let relay = RelayAddr::new(relay_peer, socket_address(&relay_addr).unwrap()).unwrap();
        let seed = Keypair::generate_ed25519().public().to_peer_id();
        let discovery = DiscoveryConfig::new(
            vec![(seed, format!("/dns4/seed.example./tcp/443/p2p/{seed}").parse().unwrap())],
            vec![dns.address],
        )
        .unwrap();
        let (mut carrier, _handle, _incoming) = Carrier::bind_with_discovery(
            Keypair::generate_ed25519(),
            "127.0.0.1:0".parse().unwrap(),
            vec![],
            discovery,
        )
        .unwrap();
        let (reply, mut result) = oneshot::channel();
        carrier.core.command(Command::Reserve(relay, reply));
        let mut original_event = None;
        let mut fields = None;
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = carrier.core.swarm.select_next_some() => match event {
                        SwarmEvent::Behaviour(BehaviourEvent::Relays(event @ libp2p::relay::client::Event::ReservationReqAccepted { .. })) => {
                            if let libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, connection_id, operation, .. } = &event {
                                fields = Some((*relay_peer_id, *connection_id, operation.clone()));
                            }
                            original_event = Some(event);
                            break;
                        }
                        other => carrier.core.event(other).unwrap(),
                    },
                    _ = server.select_next_some() => {}
                }
            }
        }).await.unwrap();
        let (peer, control, old_capability) = fields.unwrap();
        assert_eq!(peer, relay_peer);
        carrier.core.regression_old_acceptance(peer, control, old_capability, original_event.take().unwrap());

        let gate = carrier.core.relay.gate.clone();
        gate.revoke_all();
        let Carrier { core, executor } = carrier;
        drop(core);
        executor.shutdown().await.unwrap();
        gate.finish_shutdown();
        drop(server);
        server_executor.shutdown().await.unwrap();
        dns.quiet();
        assert!(matches!(result.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
    }).await.unwrap();
}
