use super::*;

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_rootless_dependency_dial_uses_staged_native_root() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = Server::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, address.clone())]);
        let options = DialOpts::peer_id(server.peer).allocate_new_port().build();
        let connection = options.connection_id();
        let deadline = Instant::now() + DEADLINE;
        let admission = &mut source.core.swarm.behaviour_mut().inner.admission;
        let (key, permit) = admission
            .stage_infrastructure(server.peer, &address, connection, deadline)
            .unwrap();
        admission
            .allow_infrastructure_fixture(key, &address, server.address)
            .unwrap();
        source.core.infrastructure.entries.insert(
            connection,
            Entry {
                key,
                permit,
                deadline,
                phase: Phase::Pending,
            },
        );
        source
            .core
            .event(SwarmEvent::Behaviour(BehaviourEvent::Dial(options)))
            .unwrap();
        live(&mut source, &mut server, connection).await;
        assert!(handle.links().borrow().is_empty());
        source.core.close_infrastructure(key, Instant::now());
        gone(&mut source, &mut server, connection).await;
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_reopen_waits_for_retained_guard_and_ignores_old_key() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = Server::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, address.clone())]);
        let (old, old_key) = stage(&mut source, server.peer, &address, server.address);
        let view = source
            .core
            .swarm
            .behaviour()
            .inner
            .admission
            .roles_view()
            .unwrap();
        let held = capture_incoming(&mut source, &mut server, old_key).await;
        live(&mut source, &mut server, old).await;
        source.core.close_infrastructure(old_key, Instant::now());
        gone(&mut source, &mut server, old).await;
        assert!(view.infrastructure_live(old_key).is_none());
        assert_eq!(
            source
                .core
                .prepare_native(server.peer, &address)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut released = Box::pin(view.join_infrastructure_release());
        assert!(futures::poll!(&mut released).is_pending());
        drop(held);
        timeout(DEADLINE, &mut released).await.unwrap();
        let (next, next_key) = stage(&mut source, server.peer, &address, server.address);
        assert_ne!(old, next);
        assert_ne!(old_key, next_key);
        live(&mut source, &mut server, next).await;
        source.core.close_infrastructure(old_key, Instant::now());
        assert!(
            source
                .core
                .infrastructure
                .entries
                .get(&next)
                .is_some_and(|entry| entry.phase == Phase::Live)
        );
        assert_eq!(view.infrastructure_live(next_key), Some(server.address));
        assert!(handle.links().borrow().is_empty());
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_pending_timeout_and_cancel_reconcile_actual_dial() {
    timeout(Duration::from_secs(45), async {
        for expired in [false, true] {
            let dns = Dns::new().await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap();
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            let address = root(peer, endpoint.port());
            let (mut source, handle, _incoming) = carrier(&dns, vec![(peer, address.clone())]);
            let (connection, key) = stage(&mut source, peer, &address, endpoint);
            let view = source.core.swarm.behaviour().inner.admission.roles_view().unwrap();
            let stream = timeout(DEADLINE, async {
                loop {
                    tokio::select! {
                        accepted = listener.accept() => break accepted.unwrap().0,
                        event = source.core.swarm.select_next_some() => source.core.event(event).unwrap(),
                    }
                }
            }).await.unwrap();
            assert!(source.core.infrastructure.entries.get(&connection).is_some_and(|entry| entry.phase == Phase::Pending));
            let held = view.lease(key, crate::discovery::roles::LeaseKind::Pending, Instant::now()).unwrap();
            if expired {
                tokio::time::pause();
                tokio::time::advance(DEADLINE + Duration::from_millis(1)).await;
                source.core.infrastructure_tick(Instant::now()).unwrap();
            } else {
                source.core.close_infrastructure(key, Instant::now());
            }
            assert!(source.core.infrastructure.entries.get(&connection).is_some_and(|entry| entry.phase == Phase::Closing));
            assert!(!view.infrastructure_pending(key, Instant::now()));
            timeout(DEADLINE, async {
                while source.core.infrastructure.entries.contains_key(&connection) {
                    let event = source.core.swarm.select_next_some().await;
                    source.core.event(event).unwrap();
                }
            }).await.unwrap();
            if expired { tokio::time::resume(); }
            assert!(view.infrastructure_live(key).is_none());
            assert!(handle.links().borrow().is_empty());
            let mut released = Box::pin(view.join_infrastructure_release());
            assert!(futures::poll!(&mut released).is_pending());
            drop(held);
            timeout(DEADLINE, &mut released).await.unwrap();
            drop(stream);
            drop(listener);
            shutdown(source, &handle).await;
            let rebound = tokio::net::TcpListener::bind(endpoint).await.unwrap();
            drop(rebound);
            assert!(dns.shutdown().await > 0);
        }
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_infrastructure_network_shutdown_joins_io_then_waits_for_last_guard() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = Server::new().await;
        let address = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, address.clone())]);
        let (connection, key) = stage(&mut source, server.peer, &address, server.address);
        let view = source.core.swarm.behaviour().inner.admission.roles_view().unwrap();
        let held = capture_incoming(&mut source, &mut server, key).await;
        live(&mut source, &mut server, connection).await;
        let listening = (*handle.listening.borrow()).unwrap();
        let (entered, mut barrier) = oneshot::channel();
        source.core.infrastructure.shutdown_entered = Some(entered);
        let mut running = Box::pin(source.run(async {}));
        tokio::select! {
            result = &mut running => panic!("shutdown completed before retained guard release: {result:?}"),
            joined = &mut barrier => joined.unwrap(),
        }
        // The barrier follows executor joining and actual terminal reconciliation.
        assert!(running.as_mut().now_or_never().is_none());
        assert!(view.infrastructure_live(key).is_none());
        assert!(handle.links().borrow().is_empty());
        assert_eq!(handle.connect(server.peer, server.address).await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        let listener = tokio::net::TcpListener::bind(listening).await.unwrap();
        drop(listener);
        drop(held);
        timeout(DEADLINE, running).await.unwrap().unwrap();
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    }).await.unwrap();
}
