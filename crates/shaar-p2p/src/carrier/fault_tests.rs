use super::*;
use tokio::{sync::oneshot, task::JoinSet};

fn key() -> Keypair {
    Keypair::generate_ed25519()
}

fn bind() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn connect_keeps_invalid_address_priority_and_closing_guard() {
    let peer = key().public().to_peer_id();
    let (mut owner, _handle, _incoming) = Carrier::bind(key(), bind(), vec![peer]).unwrap();
    owner.core.closing.insert(
        peer,
        Closing {
            deadline: tokio::time::Instant::now() + DEADLINE,
            reply: None,
        },
    );
    let (reply, result) = oneshot::channel();
    owner
        .core
        .command(Command::Connect(peer, "0.0.0.0:0".parse().unwrap(), reply));
    assert_eq!(
        result.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let (reply, result) = oneshot::channel();
    owner.core.command(Command::Connect(
        peer,
        "127.0.0.1:1".parse().unwrap(),
        reply,
    ));
    assert_eq!(
        result.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_driver_paths_join_and_release_listeners_with_external_handles() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (address, mode) in [
            ("127.0.0.1:20031", 0),
            ("127.0.0.1:20032", 1),
            ("127.0.0.1:20033", 2),
        ] {
            let peer = key().public().to_peer_id();
            let (mut owner, handle, incoming) =
                Carrier::bind(key(), address.parse().unwrap(), vec![peer]).unwrap();
            // Seed an observation to make destruction revocation sensitive on every terminal path.
            owner.core.links.send_replace(vec![Link {
                peer,
                connection: ConnectionId::new_unchecked(99),
                route: Route::Direct,
            }]);
            let observed = handle.links();
            match mode {
                0 => {
                    owner.core.closing.insert(
                        peer,
                        Closing {
                            deadline: tokio::time::Instant::now(),
                            reply: None,
                        },
                    );
                    let error = owner.run(std::future::pending()).await.unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    assert!(handle.commands.is_closed());
                    drop(incoming);
                }
                1 => {
                    drop(incoming);
                    owner.run(std::future::pending()).await.unwrap();
                    assert!(handle.commands.is_closed());
                }
                _ => {
                    drop(handle);
                    owner.run(std::future::pending()).await.unwrap();
                    drop(incoming);
                }
            }
            assert!(observed.borrow().is_empty());
            let _rebound = tokio::net::TcpListener::bind(address).await.unwrap();
        }
    })
    .await
    .expect("terminal driver resource deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn a_send_queued_before_reopen_cannot_allocate_an_id_on_the_successor() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (mut a, ah, _ar) = Carrier::bind(ka, bind(), vec![pb]).unwrap();
        let (b, bh, mut br) = Carrier::bind(kb, bind(), vec![pa]).unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(b.run(async {
            let _ = stopped.await;
        }));
        let address = bh.local_addr().await.unwrap();
        let (reply, connected) = oneshot::channel();
        a.core.command(Command::Connect(pb, address, reply));
        while !a.core.pending.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        connected.await.unwrap().unwrap();
        let old = a.core.links.borrow()[0];
        let (reply, stale) = oneshot::channel();
        ah.submit(Command::SendOn(
            old,
            Datagram::new(b"old queued packet").unwrap(),
            reply,
        ))
        .unwrap();
        let (reply, closed) = oneshot::channel();
        a.core.command(Command::Disconnect(pb, reply));
        while !a.core.closing.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        closed.await.unwrap().unwrap();
        // Observe remote close before redial; this is not a sleep/retry readiness oracle.
        bh.disconnect(pa).await.unwrap();
        let (reply, connected) = oneshot::channel();
        a.core.command(Command::Connect(pb, address, reply));
        while !a.core.pending.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        connected.await.unwrap().unwrap();
        let current = a.core.links.borrow()[0];
        assert_ne!(old.connection, current.connection);
        let queued = a.core.commands.recv().await.unwrap();
        a.core.command(queued);
        assert_eq!(
            stale.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(a.core.requests.is_empty());
        let current = a.core.links.borrow()[0];
        let (reply, unlinked) = oneshot::channel();
        assert!(
            a.core
                .requests
                .admit(request_owner::Pending {
                    peer: pb,
                    expected: current,
                    packet: Datagram::new(b"unlinked").unwrap(),
                    deadline: tokio::time::Instant::now() + DEADLINE,
                    reply: Some(reply),
                })
                .is_ok()
        );
        a.core.relay.routes.remove(&current.connection);
        a.core.request_owner_tick();
        assert!(a.core.requests.is_empty());
        assert_eq!(
            unlinked.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        a.core
            .relay
            .routes
            .insert(current.connection, current.route);
        let current = a.core.links.borrow()[0];
        a.core.relay.routes.insert(
            current.connection,
            Route::Relayed {
                relay: None,
                generation: 7,
            },
        );
        let (reply, stale_route) = oneshot::channel();
        assert!(
            a.core
                .requests
                .admit(request_owner::Pending {
                    peer: pb,
                    expected: current,
                    packet: Datagram::new(b"captured old route").unwrap(),
                    deadline: tokio::time::Instant::now() + DEADLINE,
                    reply: Some(reply),
                })
                .is_ok()
        );
        a.core.request_owner_tick();
        assert_eq!(a.core.requests.len(), 0);
        assert_eq!(
            stale_route.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        a.core
            .relay
            .routes
            .insert(current.connection, current.route);
        let (reply, delivered) = oneshot::channel();
        a.core.command(Command::SendOn(
            current,
            Datagram::new(b"successor packet").unwrap(),
            reply,
        ));
        while !a.core.requests.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        delivered.await.unwrap().unwrap();
        assert_eq!(
            br.recv().await.unwrap().packet.as_bytes(),
            b"successor packet"
        );
        a.run(async {}).await.unwrap();
        stop.send(()).unwrap();
        tasks.join_next().await.unwrap().unwrap().unwrap();
    })
    .await
    .expect("queued generation-bound send deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn core_send_without_link_is_bound_to_capture_route_generation() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (mut a, _ah, _ar) = Carrier::bind(ka, bind(), vec![pb]).unwrap();
        let (b, bh, _br) = Carrier::bind(kb, bind(), vec![pa]).unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(b.run(async {
            let _ = stopped.await;
        }));
        let (reply, connected) = oneshot::channel();
        a.core
            .command(Command::Connect(pb, bh.local_addr().await.unwrap(), reply));
        while !a.core.pending.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        connected.await.unwrap().unwrap();
        let captured = a.core.links.borrow()[0];

        let (reply, first) = oneshot::channel();
        a.core
            .command(Command::Send(pb, Datagram::new(b"active").unwrap(), reply));
        assert_eq!(a.core.requests.submitted_len(), 1);
        let (reply, queued) = oneshot::channel();
        a.core.command(Command::Send(
            pb,
            Datagram::new(b"queued on captured link").unwrap(),
            reply,
        ));
        assert_eq!(a.core.requests.queued_len(), 1);
        assert_eq!(a.core.requests.queued().next().unwrap().expected, captured);

        a.core.relay.routes.insert(
            captured.connection,
            Route::Relayed {
                relay: None,
                generation: 7,
            },
        );
        a.core.request_owner_tick();
        assert_eq!(
            a.core.requests.submitted_len(),
            1,
            "old submitted request remains charged"
        );
        assert_eq!(
            a.core.requests.queued_len(),
            0,
            "queued request with stale route is rejected"
        );
        assert_eq!(
            queued.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );

        a.core
            .relay
            .routes
            .insert(captured.connection, captured.route);
        while !a.core.requests.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        first.await.unwrap().unwrap();
        a.run(async {}).await.unwrap();
        stop.send(()).unwrap();
        tasks.join_next().await.unwrap().unwrap().unwrap();
    })
    .await
    .expect("core admission captured-link generation deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn ledger_caps_before_submission_and_expired_ids_remain_charged_until_terminal() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (mut a, _ah, _ar) = Carrier::bind(ka, bind(), vec![pb]).unwrap();
        let (b, bh, _br) = Carrier::bind(kb, bind(), vec![pa]).unwrap();
        let (stop, stopped) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(b.run(async {
            let _ = stopped.await;
        }));
        let address = bh.local_addr().await.unwrap();
        let (reply, connected) = oneshot::channel();
        a.core.command(Command::Connect(pb, address, reply));
        while !a.core.pending.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        connected.await.unwrap().unwrap();
        assert_eq!(a.core.links.borrow().len(), 1);
        let mut results = Vec::with_capacity(REQUEST_LIMIT);
        for _ in 0..REQUEST_LIMIT {
            let (reply, result) = oneshot::channel();
            a.core
                .command(Command::Send(pb, Datagram::new(b"bounded").unwrap(), reply));
            results.push(result);
        }
        assert_eq!(a.core.requests.len(), REQUEST_LIMIT);
        assert_eq!(a.core.requests.submitted_len(), 1);
        assert_eq!(a.core.requests.queued_len(), REQUEST_LIMIT - 1);
        let (reply, excess) = oneshot::channel();
        a.core
            .command(Command::Send(pb, Datagram::new(b"excess").unwrap(), reply));
        assert_eq!(
            excess.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(a.core.requests.len(), REQUEST_LIMIT);
        assert_eq!(a.core.requests.submitted_len(), 1);
        assert_eq!(a.core.requests.queued_len(), REQUEST_LIMIT - 1);

        // Caller cancellation purges unsent work promptly; submitted requests remain charged.
        drop(results.pop().unwrap());
        a.core.requests.cancel_queued();
        assert_eq!(a.core.requests.len(), REQUEST_LIMIT - 1);
        assert_eq!(a.core.requests.submitted_len(), 1);
        // The remaining queued calls expire without disconnect; only the active submitted call enforces it.
        let expired = tokio::time::Instant::now() + DEADLINE;
        a.core.requests.expire_queued(expired);
        assert_eq!(a.core.requests.len(), 1);
        a.core.expire(expired).unwrap();
        assert!(a.core.links.borrow().is_empty());
        for result in results {
            assert_eq!(
                result.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert_eq!(a.core.requests.len(), 1);
        assert_eq!(a.core.requests.submitted_len(), 1);
        assert_eq!(a.core.closing.len(), 1);
        let (reply, still_full) = oneshot::channel();
        a.core.command(Command::Send(
            pb,
            Datagram::new(b"no early reuse").unwrap(),
            reply,
        ));
        assert_eq!(
            still_full.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        while !a.core.requests.is_empty() {
            let event = a.core.swarm.select_next_some().await;
            a.core.event(event).unwrap();
        }
        a.run(async {}).await.unwrap();
        stop.send(()).unwrap();
        tasks.join_next().await.unwrap().unwrap().unwrap();
    })
    .await
    .expect("request ledger deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn two_authenticated_owners_promote_bounded_concurrent_bursts_both_directions() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let address_a = bind();
        let address_b = bind();
        let (a, ah, mut ar) = Carrier::bind(ka, address_a, vec![pb]).unwrap();
        let (b, bh, mut br) = Carrier::bind(kb, address_b, vec![pa]).unwrap();
        let (stop_a, stopped_a) = oneshot::channel();
        let (stop_b, stopped_b) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(a.run(async {
            let _ = stopped_a.await;
        }));
        tasks.spawn(b.run(async {
            let _ = stopped_b.await;
        }));
        let a_addr = ah.local_addr().await.unwrap();
        let b_addr = bh.local_addr().await.unwrap();
        let connection_a = ah.connect(pb, b_addr).await.unwrap();
        let mut links_a = ah.links();
        let mut links_b = bh.links();
        for (links, peer, connection) in [
            (&mut links_a, pb, Some(connection_a)),
            (&mut links_b, pa, None),
        ] {
            loop {
                let link = {
                    let snapshot = links.borrow_and_update();
                    if let Some(link) = snapshot.iter().find(|link| link.peer == peer) {
                        assert_eq!(snapshot.len(), 1);
                        Some(*link)
                    } else {
                        None
                    }
                };
                if let Some(link) = link {
                    assert_eq!(link.route, Route::Direct);
                    if let Some(connection) = connection {
                        assert_eq!(link.connection, connection);
                    }
                    break;
                }
                links.changed().await.expect("carrier link watch closed");
            }
        }

        const BURST: usize = 8;
        let outbound_a = (0..BURST)
            .map(|index| format!("a-to-b-{index}"))
            .collect::<Vec<_>>();
        let outbound_b = (0..BURST)
            .map(|index| format!("b-to-a-{index}"))
            .collect::<Vec<_>>();
        let sends_a = futures::future::join_all(
            outbound_a
                .iter()
                .map(|packet| ah.send(pb, Datagram::new(packet.as_bytes()).unwrap())),
        );
        let sends_b = futures::future::join_all(
            outbound_b
                .iter()
                .map(|packet| bh.send(pa, Datagram::new(packet.as_bytes()).unwrap())),
        );
        let (results_a, results_b) = tokio::join!(sends_a, sends_b);
        for (side, results) in [("A->B", &results_a), ("B->A", &results_b)] {
            for (index, result) in results.iter().enumerate() {
                assert!(
                    result.is_ok(),
                    "{side} send at index {index} failed: {result:?}; A->B={results_a:?}; B->A={results_b:?}"
                );
            }
        }

        let mut received_a = Vec::with_capacity(BURST);
        let mut received_b = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            received_a.push(ar.recv().await.unwrap().packet.as_bytes().to_vec());
            received_b.push(br.recv().await.unwrap().packet.as_bytes().to_vec());
        }
        let mut expected_a = outbound_b
            .iter()
            .map(|packet| packet.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let mut expected_b = outbound_a
            .iter()
            .map(|packet| packet.as_bytes().to_vec())
            .collect::<Vec<_>>();
        received_a.sort();
        received_b.sort();
        expected_a.sort();
        expected_b.sort();
        assert_eq!(received_a, expected_a);
        assert_eq!(received_b, expected_b);

        stop_a.send(()).unwrap();
        stop_b.send(()).unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        assert!(ah.local_addr().await.is_err());
        assert!(bh.local_addr().await.is_err());
        let _rebound_a = tokio::net::TcpListener::bind(a_addr).await.unwrap();
        let _rebound_b = tokio::net::TcpListener::bind(b_addr).await.unwrap();
    })
    .await
    .expect("concurrent two-owner request promotion deadline");
}

/// Deliberately holds response channels on a real authenticated link, never acknowledging.
async fn withhold_ack(
    owner: Carrier,
    stop: impl Future<Output = ()>,
    seen: oneshot::Sender<()>,
    release: Option<oneshot::Receiver<()>>,
) -> io::Result<()> {
    let Carrier {
        mut core,
        mut executor,
    } = owner;
    let mut seen = Some(seen);
    let mut held = Vec::with_capacity(2);
    tokio::pin!(stop);
    let mut release = release;
    let mut holding = true;
    let result = loop {
        tokio::select! {
            _ = &mut stop => break Ok(()),
            _ = async { match &mut release { Some(release) => { let _ = release.await; }, None => std::future::pending::<()>().await } }, if holding && release.is_some() => {
                for channel in held.drain(..) {
                    let _ = core.swarm.behaviour_mut().inner.packets.send_response(channel, ());
                }
                holding = false;
            }
            command = core.commands.recv() => match command {
                Some(command) => core.command(command),
                None => break Ok(()),
            },
            result = executor.next_result() => if let Err(error) = result { break Err(error); },
            event = core.swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Packets(rpc::Event::Message {
                        message: rpc::Message::Request { channel, .. }, ..
                    })) if holding => {
                        assert!(held.len() < 2);
                        held.push(channel);
                        if let Some(seen) = seen.take() { seen.send(()).unwrap(); }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Packets(event)) => {
                        core.packet(event);
                        core.request_owner_tick();
                    }
                    event => if let Err(error) = core.event(event) { break Err(error); },
                }
            }
        }
    };
    drop(held);
    drop(core);
    let joined = executor.shutdown().await;
    result.and(joined)
}

#[tokio::test(flavor = "current_thread")]
async fn held_inbound_response_and_outbound_share_request_limit() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (a, ah, mut ar) = Carrier::bind(ka, bind(), vec![pb]).unwrap();
        let (b, bh, _br) = Carrier::bind(kb, bind(), vec![pa]).unwrap();
        let (stop_a, stopped_a) = oneshot::channel();
        let (stop_b, stopped_b) = oneshot::channel();
        let (seen, observed) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(a.run(async {
            let _ = stopped_a.await;
        }));
        tasks.spawn(withhold_ack(
            b,
            async {
                let _ = stopped_b.await;
            },
            seen,
            Some(release_rx),
        ));
        ah.connect(pb, bh.local_addr().await.unwrap())
            .await
            .unwrap();
        let futures = (0..8).map(|_| ah.send(pb, Datagram::new(b"bounded interleave").unwrap()));
        let (results, ()) = tokio::join!(futures::future::join_all(futures), async {
            observed.await.unwrap();
            let inbound = bh
                .send(pa, Datagram::new(b"opposite direction").unwrap())
                .await;
            inbound.unwrap();
            assert_eq!(
                ar.recv().await.unwrap().packet.as_bytes(),
                b"opposite direction"
            );
            release.send(()).unwrap();
        });
        assert!(results.iter().all(Result::is_ok));
        stop_a.send(()).unwrap();
        stop_b.send(()).unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .expect("held inbound and queued outbound deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn a_live_peer_withholding_ack_cannot_hold_the_request_forever() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let ka = key();
        let kb = key();
        let pa = ka.public().to_peer_id();
        let pb = kb.public().to_peer_id();
        let (a, ah, _ar) = Carrier::bind(ka, bind(), vec![pb]).unwrap();
        let (b, bh, _br) = Carrier::bind(kb, bind(), vec![pa]).unwrap();
        let (stop_a, stopped_a) = oneshot::channel();
        let (stop_b, stopped_b) = oneshot::channel();
        let (seen, observed) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(a.run(async {
            let _ = stopped_a.await;
        }));
        tasks.spawn(withhold_ack(
            b,
            async {
                let _ = stopped_b.await;
            },
            seen,
            None,
        ));
        ah.connect(pb, bh.local_addr().await.unwrap())
            .await
            .unwrap();
        let (result, received) = tokio::join!(
            ah.send(pb, Datagram::new(b"never acknowledged").unwrap()),
            observed
        );
        received.unwrap();
        assert!(result.is_err());
        stop_a.send(()).unwrap();
        stop_b.send(()).unwrap();
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .expect("withheld acknowledgement deadline");
}
