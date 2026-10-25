use super::*;
use tokio::{sync::oneshot, task::JoinSet};

fn key() -> Keypair {
    Keypair::generate_ed25519()
}

fn bind() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
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
        let (reply, excess) = oneshot::channel();
        a.core
            .command(Command::Send(pb, Datagram::new(b"excess").unwrap(), reply));
        assert_eq!(
            excess.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(a.core.requests.len(), REQUEST_LIMIT);

        // Cancelling a caller must not return a slot still retained by request-response.
        drop(results.pop().unwrap());
        // Exercise the production deadline action on real admitted IDs, before polling replies.
        let expired = tokio::time::Instant::now() + DEADLINE;
        a.core.expire(expired).unwrap();
        assert!(a.core.links.borrow().is_empty());
        for result in results {
            assert_eq!(
                result.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert_eq!(a.core.requests.len(), REQUEST_LIMIT);
        assert_eq!(a.core.closing.len(), 1);
        let (reply, still_full) = oneshot::channel();
        a.core.command(Command::Send(
            pb,
            Datagram::new(b"no early reuse").unwrap(),
            reply,
        ));
        assert_eq!(
            still_full.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
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

/// Deliberately holds response channels on a real authenticated link, never acknowledging.
async fn withhold_ack(
    owner: Carrier,
    stop: impl Future<Output = ()>,
    seen: oneshot::Sender<()>,
) -> io::Result<()> {
    let Carrier {
        mut core,
        mut executor,
    } = owner;
    let mut seen = Some(seen);
    let mut held = Vec::with_capacity(2);
    tokio::pin!(stop);
    let result = loop {
        tokio::select! {
            _ = &mut stop => break Ok(()),
            result = executor.next_result() => if let Err(error) = result { break Err(error); },
            event = core.swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Packets(rpc::Event::Message {
                        message: rpc::Message::Request { channel, .. }, ..
                    })) => {
                        assert!(held.len() < 2);
                        held.push(channel);
                        if let Some(seen) = seen.take() { seen.send(()).unwrap(); }
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
