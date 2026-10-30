use super::*;

#[tokio::test(flavor = "current_thread")]
async fn carrier_discovery_queries_owned_seed_and_authenticates_referred_hop_without_app_authority()
{
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut seed = MetadataServer::new().await;
        let mut relay = MetadataServer::new().await;
        seed.swarm.remove_external_address(&multiaddr(seed.address));
        let seed_root = root(seed.peer, seed.address.port());
        let relay_root = root(relay.peer, relay.address.port());
        seed.swarm.behaviour_mut().kad.add_address(&relay.peer, relay_root);
        let (mut source, handle, mut incoming) = carrier(&dns, vec![(seed.peer, seed_root)]);
        source.core.discovery_witnesses = [Some((seed.peer, seed.address)), Some((relay.peer, relay.address)), None, None];
        let (reply, mut result) = oneshot::channel();
        source.core.command(Command::Discover(reply));
        let deadline = source.core.discovery_deadline().unwrap();
        let (overlap, rejected) = oneshot::channel();
        source.core.command(Command::Discover(overlap));
        assert_eq!(rejected.await.unwrap().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let mut referred_connection = None;
        let candidates = loop {
            source.core.discovery_tick(Instant::now());
            tokio::select! {
                result = &mut result => break result.unwrap().unwrap(),
                event = source.core.swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } = &event
                        && *peer_id == relay.peer
                    {
                        referred_connection = Some(*connection_id);
                    }
                    source.core.event(event).unwrap();
                },
                _ = seed.swarm.select_next_some() => {},
                _ = relay.swarm.select_next_some() => {},
                _ = tokio::time::sleep_until(deadline) => panic!("owned referral discovery deadline"),
            }
        };
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].peer_id(), relay.peer);
        let connection = referred_connection.expect("candidate was not authenticated over a real connection");
        let entry = source.core.infrastructure.entries.get(&connection).unwrap();
        assert_eq!(candidates[0].key, entry.key);
        assert_eq!(entry.deadline, deadline, "REFERRED_DIAL_RESET_OPERATION_DEADLINE");
        assert!(entry.identified);
        assert_eq!(entry.protocols, protocols::DHT | protocols::HOP);
        assert!(handle.links().borrow().is_empty());
        assert!(handle.relay_leases().borrow().is_empty());
        assert!(source.core.relay.routes.is_empty());
        assert!(matches!(incoming.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
        let (reply, denied) = oneshot::channel();
        source.core.command(Command::Connect(relay.peer, relay.address, reply));
        assert_eq!(denied.await.unwrap().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        shutdown(source, &handle).await;
        seed.shutdown().await;
        relay.shutdown().await;
        assert!(dns.shutdown().await > 0);
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_discovery_waiter_cancellation_wakes_owner_and_closes_live_control() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut seed = MetadataServer::new().await;
        let seed_root = root(seed.peer, seed.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(seed.peer, seed_root)]);
        source.core.discovery_witnesses[0] = Some((seed.peer, seed.address));
        let (reply, result) = oneshot::channel();
        source.core.command(Command::Discover(reply));
        let deadline = source.core.discovery_deadline().unwrap();
        let mut remote_established = false;
        let connection = loop {
            tokio::select! {
                event = source.core.swarm.select_next_some() => {
                    let established = match &event {
                        SwarmEvent::ConnectionEstablished { connection_id, .. } => Some(*connection_id),
                        _ => None,
                    };
                    source.core.event(event).unwrap();
                    if let Some(connection) = established { break connection; }
                },
                event = seed.swarm.select_next_some() => {
                    remote_established |= matches!(event, SwarmEvent::ConnectionEstablished { .. });
                },
                _ = tokio::time::sleep_until(deadline) => panic!("seed connection deadline"),
            }
        };
        // The close oracle requires the remote Swarm to have published its live connection.
        while !remote_established {
            tokio::select! {
                event = seed.swarm.select_next_some() => {
                    remote_established = matches!(event, SwarmEvent::ConnectionEstablished { .. });
                },
                _ = tokio::time::sleep_until(deadline) => panic!("remote seed connection deadline"),
            }
        }
        let key = source.core.infrastructure.entries.get(&connection).unwrap().key;
        let view = source.core.swarm.behaviour().inner.admission.roles_view().unwrap();
        drop(result);
        {
            let driving = source.core.drive(&mut source.executor, std::future::pending());
            tokio::pin!(driving);
            loop {
                tokio::select! {
                    result = &mut driving => panic!("carrier stopped during discovery cancellation: {result:?}"),
                    event = seed.swarm.select_next_some() => {
                        if matches!(event, SwarmEvent::ConnectionClosed { .. }) { break; }
                    },
                    _ = tokio::time::sleep_until(deadline) => panic!("waiter cancellation close boundary: live_authority={:?}", view.infrastructure_live(key)),
                }
            }
        }
        assert!(source.core.discovery_operation.is_none());
        assert!(source.core.infrastructure.entries.get(&connection).is_none_or(|entry| entry.phase == Phase::Closing));
        assert!(handle.links().borrow().is_empty());
        shutdown(source, &handle).await;
        seed.shutdown().await;
        assert!(dns.shutdown().await > 0);
    }).await.unwrap();
}
