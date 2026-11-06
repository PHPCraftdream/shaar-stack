//! Carrier capabilities on real loopback cores, independent of APP modes.

use std::future::{Future, poll_fn};
use std::net::TcpListener;
use std::task::Poll;
use std::time::Duration;

use tokio::time::{Instant, sleep, timeout};

use super::{DatagramError, DatagramSender, PeerDatagrams, YggBridge, codec};
use crate::frame::{Frame, Kind};
use crate::test_support::{BUDGET, close_within, config, poll_until, start_dialer, start_listener};
use crate::{DATAGRAM_QUEUE_CAPACITY, YggError, YggTransport};

async fn close(bridge: &YggBridge) {
    timeout(BUDGET, bridge.close())
        .await
        .expect("bridge close deadline")
        .expect("bridge joined");
}

async fn exact(
    sender: &DatagramSender,
    receiver: &mut PeerDatagrams,
    payload: &[u8],
    stale: &[Vec<u8>],
) {
    timeout(BUDGET, async {
        loop {
            sender
                .send(payload, Duration::from_secs(1))
                .await
                .expect("carrier send");
            match timeout(Duration::from_millis(100), receiver.recv()).await {
                Ok(Ok(bytes)) if bytes == payload => return,
                Ok(Ok(bytes)) => assert!(stale.contains(&bytes), "unexpected datagram: {bytes:?}"),
                Ok(Err(error)) => panic!("capability receive failed: {error}"),
                Err(_) => {}
            }
        }
    })
    .await
    .expect("exact datagram eventually delivered");
}

async fn send_until(sender: &DatagramSender, bytes: &[u8], observed: impl Fn() -> bool) {
    let deadline = Instant::now() + BUDGET;
    while !observed() {
        assert!(Instant::now() < deadline, "carrier effect not observed");
        sender
            .send(bytes, Duration::from_secs(1))
            .await
            .expect("send");
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn binary_empty_and_probe_shaped_carriers_share_the_reader_with_probes() {
    timeout(Duration::from_secs(60), async {
        let (server, port) = start_listener(0xC1).await;
        let client = start_dialer(0xC2, port).await;
        let (server_key, client_key) = (server.public_key(), client.public_key());
        let server = YggBridge::new(server, [client_key]);
        let client = YggBridge::new(client, [server_key]);
        let mut to_server = server
            .open_datagrams(client_key, BUDGET)
            .await
            .expect("server capability");
        let mut to_client = client
            .open_datagrams(server_key, BUDGET)
            .await
            .expect("client capability");
        assert_eq!(to_server.peer_key(), client_key);
        client
            .probe(server_key, BUDGET)
            .await
            .expect("client route ready");
        server
            .probe(client_key, BUDGET)
            .await
            .expect("server route ready");
        let c = to_client.sender();
        let s = to_server.sender();
        let ping = Frame {
            kind: Kind::Ping,
            nonce: [0x77; 16],
        }
        .encode()
        .to_vec();
        let pong = Frame {
            kind: Kind::Pong,
            nonce: [0x88; 16],
        }
        .encode()
        .to_vec();
        let vectors = vec![
            Vec::new(),
            (0..=255).collect(),
            ping,
            pong,
            vec![0xA5; c.mtu()],
        ];
        let mut stale = Vec::new();
        for bytes in vectors {
            exact(&c, &mut to_server, &bytes, &stale).await;
            exact(&s, &mut to_client, &bytes, &stale).await;
            stale.push(bytes);
            client
                .probe(server_key, BUDGET)
                .await
                .expect("probe still independent");
        }
        assert_eq!(server.pending_probes(), 0);
        assert_eq!(client.pending_probes(), 0);
        let oversize = vec![0; c.mtu() + 1];
        assert_eq!(
            c.send(&oversize, BUDGET).await,
            Err(DatagramError::Oversize {
                len: oversize.len(),
                mtu: c.mtu()
            })
        );
        assert_eq!(
            c.send(b"deadline", Duration::ZERO).await,
            Err(DatagramError::TimedOut)
        );
        close(&client).await;
        close(&server).await;
        assert_eq!(
            c.send(&oversize, Duration::ZERO).await,
            Err(DatagramError::Closed)
        );
        assert_eq!(to_server.recv().await, Err(DatagramError::Closed));
        TcpListener::bind(("127.0.0.1", port)).expect("port released with retained capabilities");
        let replacement = YggTransport::start(config(0xC1, vec![], vec![]))
            .await
            .expect("key claim released");
        close(&server).await;
        assert!(matches!(
            YggTransport::start(config(0xC1, vec![], vec![])).await,
            Err(YggError::KeyInUse)
        ));
        close_within(&replacement, "replacement").await;
    })
    .await
    .expect("bounded carrier round trips");
}

#[tokio::test]
async fn unregistered_peered_keys_are_rejected_and_revocation_is_peer_local() {
    timeout(Duration::from_secs(60), async {
        let (server, port) = start_listener(0xC3).await;
        let good = start_dialer(0xC4, port).await;
        let other = start_dialer(0xC5, port).await;
        let (server_key, good_key, other_key) =
            (server.public_key(), good.public_key(), other.public_key());
        let server = YggBridge::new(server, [good_key, other_key]);
        let good = YggBridge::new(good, []);
        let other = YggBridge::new(other, []);
        let mut good_rx = server
            .open_datagrams(good_key, BUDGET)
            .await
            .expect("good registration");
        let good_cap = good
            .open_datagrams(server_key, BUDGET)
            .await
            .expect("good sender");
        let other_cap = other
            .open_datagrams(server_key, BUDGET)
            .await
            .expect("other sender");
        good.probe(server_key, BUDGET)
            .await
            .expect("good peer reachable");
        other
            .probe(server_key, BUDGET)
            .await
            .expect("unregistered peer is genuinely peered");
        let other_sender = other_cap.sender();
        let before = server.dropped_datagrams();
        send_until(&other_sender, b"stranger", || {
            server.dropped_datagrams() > before
        })
        .await;
        assert!(
            timeout(Duration::from_millis(100), good_rx.recv())
                .await
                .is_err()
        );
        exact(&good_cap.sender(), &mut good_rx, b"good", &[]).await;
        let mut other_rx = server
            .open_datagrams(other_key, BUDGET)
            .await
            .expect("other registration");
        let revoked_sender = good_rx.sender();
        good_rx.close();
        assert_eq!(
            revoked_sender.send(b"revoked", BUDGET).await,
            Err(DatagramError::Revoked)
        );
        assert_eq!(good_rx.recv().await, Err(DatagramError::Revoked));
        exact(
            &other_sender,
            &mut other_rx,
            b"unrelated peer remains usable",
            &[b"stranger".to_vec()],
        )
        .await;
        let before = server.dropped_datagrams();
        send_until(&good_cap.sender(), b"after revoke", || {
            server.dropped_datagrams() > before
        })
        .await;
        let mut fresh = server
            .open_datagrams(good_key, BUDGET)
            .await
            .expect("fresh registration");
        assert_eq!(
            revoked_sender.send(b"old generation", BUDGET).await,
            Err(DatagramError::Revoked)
        );
        assert_eq!(good_rx.recv().await, Err(DatagramError::Revoked));
        exact(
            &good_cap.sender(),
            &mut fresh,
            b"fresh",
            &[b"good".to_vec(), b"after revoke".to_vec()],
        )
        .await;
        close(&other).await;
        close(&good).await;
        close(&server).await;
    })
    .await
    .expect("bounded per-peer authorization");
}

#[tokio::test]
async fn malformed_envelopes_never_deliver_and_a_full_sink_cannot_block_probes() {
    timeout(Duration::from_secs(60), async {
        let (server, port) = start_listener(0xC6).await;
        let client = start_dialer(0xC7, port).await;
        let (server_key, client_key) = (server.public_key(), client.public_key());
        let server = YggBridge::new(server, [client_key]);
        let client = YggBridge::new(client, []);
        let mut receiver = server
            .open_datagrams(client_key, BUDGET)
            .await
            .expect("receiver");
        let cap = client
            .open_datagrams(server_key, BUDGET)
            .await
            .expect("sender");
        client.probe(server_key, BUDGET).await.expect("ready route");
        let mut invalid = codec::encode(b"invalid kind").expect("small envelope");
        invalid[9] = 99;
        let before = server.ignored_frames();
        let deadline = Instant::now() + BUDGET;
        while server.ignored_frames() == before {
            assert!(Instant::now() < deadline, "malformed envelope not observed");
            client
                .shared
                .transport
                .send_to(&server_key, &invalid)
                .await
                .expect("raw malformed send");
            sleep(Duration::from_millis(50)).await;
        }
        assert!(
            timeout(Duration::from_millis(100), receiver.recv())
                .await
                .is_err()
        );
        let sender = cap.sender();
        let permits = client
            .shared
            .datagram_sends
            .acquire_many(u32::try_from(super::MAX_DATAGRAM_SENDS).expect("small send budget"))
            .await
            .expect("send budget available");
        assert_eq!(
            sender.send(b"send backpressure", BUDGET).await,
            Err(DatagramError::Busy)
        );
        client
            .probe(server_key, BUDGET)
            .await
            .expect("send budget does not block probes");
        drop(permits);
        for goal in 1..=DATAGRAM_QUEUE_CAPACITY {
            send_until(&sender, b"queued", || {
                server.queued_datagrams() >= u64::try_from(goal).expect("small goal")
            })
            .await;
        }
        // No receiver reads occur here; retransmits beyond capacity must be drops.
        assert_eq!(
            server.queued_datagrams(),
            u64::try_from(DATAGRAM_QUEUE_CAPACITY).expect("small capacity")
        );
        let before = server.dropped_datagrams();
        send_until(&sender, b"overflow", || server.dropped_datagrams() > before).await;
        client
            .probe(server_key, BUDGET)
            .await
            .expect("full data queue does not block probe replies");
        receiver.close();
        let mut fresh = server
            .open_datagrams(client_key, BUDGET)
            .await
            .expect("slot recycled");
        exact(
            &sender,
            &mut fresh,
            b"after drain",
            &[b"queued".to_vec(), b"overflow".to_vec()],
        )
        .await;
        close(&client).await;
        close(&server).await;
    })
    .await
    .expect("bounded backpressure and malformed frame checks");
}

#[tokio::test]
async fn cancelled_registration_and_capacity_have_no_stale_charges() {
    let (transport, _) = start_listener(0xC8).await;
    let bridge = YggBridge::new(transport, []);
    let peer = [0x71; 32];
    let mut registering = Box::pin(bridge.open_datagrams(peer, BUDGET));
    poll_fn(|cx| {
        assert!(registering.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(registering);
    let capability = bridge
        .open_datagrams(peer, BUDGET)
        .await
        .expect("cancelled request released");
    assert!(matches!(
        bridge.open_datagrams(peer, BUDGET).await,
        Err(DatagramError::AlreadyRegistered)
    ));
    assert!(matches!(
        bridge.open_datagrams([0x72; 32], Duration::ZERO).await,
        Err(DatagramError::TimedOut)
    ));
    drop(capability);
    let mut caps = Vec::new();
    for index in 0..super::MAX_DATAGRAM_PEERS {
        let key = [u8::try_from(index).expect("small peer index"); 32];
        caps.push(
            bridge
                .open_datagrams(key, BUDGET)
                .await
                .expect("within capacity"),
        );
    }
    assert!(matches!(
        bridge.open_datagrams([0xF1; 32], BUDGET).await,
        Err(DatagramError::Busy)
    ));
    drop(caps.pop());
    let last = bridge
        .open_datagrams([0xF1; 32], BUDGET)
        .await
        .expect("revoked slot recycled");
    close(&bridge).await;
    assert!(matches!(
        bridge.open_datagrams(peer, BUDGET).await,
        Err(DatagramError::Closed)
    ));
    drop(last);
}

#[tokio::test]
async fn the_registration_command_queue_has_non_queued_admission() {
    let (transport, _) = start_listener(0xCB).await;
    let bridge = YggBridge::new(transport, []);
    let mut waiting = Vec::new();
    for index in 0..super::MAX_DATAGRAM_PEERS {
        let peer = [u8::try_from(index).expect("small peer index"); 32];
        let mut request = Box::pin(bridge.open_datagrams(peer, BUDGET));
        poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        waiting.push(request);
    }
    assert!(matches!(
        bridge.open_datagrams([0xF2; 32], BUDGET).await,
        Err(DatagramError::Busy)
    ));
    drop(waiting);
    poll_until("cancelled registration requests drained", || {
        bridge.shared.datagrams.capacity() == super::MAX_DATAGRAM_PEERS
    })
    .await;
    let _fresh = bridge
        .open_datagrams([0; 32], BUDGET)
        .await
        .expect("no stale charge");
    close(&bridge).await;
}

#[tokio::test]
async fn cancelled_close_retains_the_join_and_releases_resources_with_live_handles() {
    let (transport, port) = start_listener(0xC9).await;
    let bridge = YggBridge::new(transport, []);
    let mut cap = bridge
        .open_datagrams([0x73; 32], BUDGET)
        .await
        .expect("live capability");
    let sender = cap.sender();
    let mut closing = Box::pin(bridge.close());
    poll_fn(|cx| {
        assert!(
            closing.as_mut().poll(cx).is_pending(),
            "the reader cannot run inside this poll"
        );
        Poll::Ready(())
    })
    .await;
    drop(closing);
    close(&bridge).await;
    close(&bridge).await;
    assert_eq!(
        sender.send(b"late", BUDGET).await,
        Err(DatagramError::Closed)
    );
    assert_eq!(cap.recv().await, Err(DatagramError::Closed));
    TcpListener::bind(("127.0.0.1", port)).expect("cancelled close eventually releases port");
    let replacement = YggTransport::start(config(0xC9, vec![], vec![]))
        .await
        .expect("claim released");
    close_within(&replacement, "replacement").await;
}

#[tokio::test]
async fn failed_shutdown_is_reported_and_never_restarted() {
    for (seed, abort_cleanup) in [(0xCC, false), (0xCD, true)] {
        let (transport, port) = start_listener(seed).await;
        let bridge = YggBridge::new(transport, []);
        let _cap = bridge
            .open_datagrams([0x75; 32], BUDGET)
            .await
            .expect("reader started");
        let reader = bridge.task.lock().await.task.take().expect("reader handle");
        reader.abort();
        assert!(reader.await.is_err(), "the reader abort is joined");
        let failed = if abort_cleanup {
            let task = tokio::spawn(std::future::pending::<Result<(), YggError>>());
            task.abort();
            task
        } else {
            tokio::spawn(async {
                Err::<(), YggError>(YggError::Io("injected shutdown failure".into()))
            })
        };
        {
            let mut state = bridge.task.lock().await;
            state.cleanup = true;
            state.task = Some(failed);
        }
        let first = timeout(BUDGET, bridge.close())
            .await
            .expect("failed shutdown returns");
        assert!(matches!(&first, Err(YggError::Io(_))));
        assert_eq!(
            bridge.close().await,
            first,
            "terminal failure is not hidden or retried"
        );
        assert!(bridge.task.lock().await.task.is_none());
        // Fault injection replaced the real cleanup; the test explicitly releases that core.
        close_within(&bridge.shared.transport, "fault-injection core cleanup").await;
        TcpListener::bind(("127.0.0.1", port)).expect("test cleanup released port");
    }
}

#[tokio::test]
async fn an_aborted_reader_is_replaced_by_one_owned_cleanup_task() {
    let (transport, port) = start_listener(0xCA).await;
    let bridge = YggBridge::new(transport, []);
    let _cap = bridge
        .open_datagrams([0x74; 32], BUDGET)
        .await
        .expect("reader started");
    {
        let state = bridge.task.lock().await;
        state.task.as_ref().expect("reader handle").abort();
    }
    close(&bridge).await;
    assert!(
        bridge.task.lock().await.cleanup,
        "aborted reader required fallback cleanup"
    );
    TcpListener::bind(("127.0.0.1", port)).expect("fallback cleanup released port");
    poll_until("bridge tasks joined", || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            == 0
    })
    .await;
}
