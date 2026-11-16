//! The readiness bridge on real loopback transports: a probe is ready only after an
//! authenticated round trip, foreign replies and garbage never make a peer ready, and
//! `close` joins the owner task and releases every resource.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{Instant, sleep, timeout};

use crate::frame::{FRAME_LEN, Frame, Kind};
use crate::test_support::{BUDGET, close_within, poll_until, start_dialer, start_listener};
use crate::{
    DATAGRAM_QUEUE_CAPACITY, DatagramSender, MAX_PENDING_PROBES, PeerDatagrams, ProbeError,
    YggBridge, YggTransport,
};

/// A key nobody runs: probes to it can only time out.
const DEAD_KEY: [u8; 32] = [0x55; 32];
const SHORT: Duration = Duration::from_millis(1500);
/// Long enough that every slot stays taken while the test observes it.
const HOLD: Duration = Duration::from_secs(4);

async fn close_bridge_within(bridge: &YggBridge) {
    let closed = timeout(BUDGET, bridge.close()).await;
    assert!(
        closed.is_ok(),
        "bridge close() did not finish within {BUDGET:?}"
    );
    assert!(
        closed.expect("checked above").is_ok(),
        "bridge close() failed"
    );
}

/// Keep sending until the effect of the frame is observed: early datagrams can be
/// lost while the path is still being discovered.
async fn send_until(
    sender: &YggTransport,
    to: &[u8; 32],
    frame: &[u8],
    observed: impl Fn() -> bool,
) {
    let deadline = Instant::now() + BUDGET;
    while !observed() {
        assert!(Instant::now() < deadline, "the frame was never observed");
        let _ = timeout(Duration::from_secs(1), sender.send_to(to, frame)).await;
        sleep(Duration::from_millis(100)).await;
    }
}

/// Read datagrams on a raw transport until a probe request arrives.
async fn next_ping(receiver: &YggTransport) -> Frame {
    let mut buffer = vec![0u8; receiver.mtu() + 1];
    let found = timeout(BUDGET, async {
        loop {
            let (len, _from) = receiver.recv(&mut buffer).await.expect("recv succeeds");
            if let Some(frame) = Frame::decode(&buffer[..len])
                && frame.kind == Kind::Ping
            {
                return frame;
            }
        }
    })
    .await;
    found.expect("a probe request reaches the probed peer")
}

#[tokio::test]
async fn a_served_peer_answers_and_the_probe_reports_a_round_trip() {
    let (listener, port) = start_listener(0xA1).await;
    let dialer = start_dialer(0xA2, port).await;
    let (listener_key, dialer_key) = (listener.public_key(), dialer.public_key());
    let server = YggBridge::new(listener, [dialer_key]);
    let client = YggBridge::new(dialer, []);

    let rtt = client
        .probe(listener_key, BUDGET)
        .await
        .expect("the served peer answers");
    assert!(rtt < BUDGET, "round trip took {rtt:?}");
    assert_eq!(
        client.pending_probes(),
        0,
        "a finished probe leaves no entry"
    );

    close_bridge_within(&client).await;
    close_bridge_within(&server).await;
}

#[tokio::test]
async fn a_key_outside_the_served_set_is_never_ready() {
    let (listener, port) = start_listener(0xA3).await;
    let served = start_dialer(0xA4, port).await;
    let stranger = start_dialer(0xA5, port).await;
    let listener_key = listener.public_key();
    let server = YggBridge::new(listener, [served.public_key()]);
    let served = YggBridge::new(served, []);
    let stranger = YggBridge::new(stranger, []);

    // The served key proves that the path and the responder work at all.
    served
        .probe(listener_key, BUDGET)
        .await
        .expect("the served key is answered");
    let outcome = stranger.probe(listener_key, Duration::from_secs(5)).await;
    assert_eq!(outcome, Err(ProbeError::TimedOut));
    assert!(
        server.ignored_frames() >= 1,
        "the server must have received and ignored the stranger's probes"
    );

    for bridge in [&stranger, &served, &server] {
        close_bridge_within(bridge).await;
    }
}

#[tokio::test]
async fn a_reply_from_another_key_does_not_complete_the_probe() {
    let (listener, port) = start_listener(0xA6).await;
    let probed = start_dialer(0xA7, port).await;
    let impostor = start_dialer(0xA8, port).await;
    let (listener_key, probed_key) = (listener.public_key(), probed.public_key());
    let prober = Arc::new(YggBridge::new(listener, []));
    let probe = tokio::spawn({
        let prober = Arc::clone(&prober);
        async move { prober.probe(probed_key, BUDGET).await }
    });

    // The impostor knows the right nonce, but the session authenticates its own key.
    let ping = next_ping(&probed).await;
    let forged = Frame {
        kind: Kind::Pong,
        nonce: ping.nonce,
    }
    .encode();
    send_until(&impostor, &listener_key, &forged, || {
        prober.ignored_frames() >= 1
    })
    .await;
    assert!(
        !probe.is_finished(),
        "a reply from another key must not make the peer ready"
    );

    let genuine = Frame {
        kind: Kind::Pong,
        nonce: ping.nonce,
    }
    .encode();
    send_until(&probed, &listener_key, &genuine, || probe.is_finished()).await;
    probe
        .await
        .expect("the probe task joins")
        .expect("the genuine reply completes the probe");

    close_within(&impostor, "impostor").await;
    close_within(&probed, "probed").await;
    close_bridge_within(&prober).await;
}

#[tokio::test]
async fn garbage_is_ignored_and_the_bridge_keeps_serving() {
    let (listener, port) = start_listener(0xAD).await;
    let sender = start_dialer(0xAE, port).await;
    let client = start_dialer(0xAF, port).await;
    let (listener_key, client_key) = (listener.public_key(), client.public_key());
    let server = YggBridge::new(listener, [client_key]);
    let client = YggBridge::new(client, []);

    let valid = Frame {
        kind: Kind::Ping,
        nonce: [9; 16],
    }
    .encode();
    let mut wrong_magic = valid;
    wrong_magic[0] = b'x';
    let mut wrong_version = valid;
    wrong_version[8] = 2;
    let garbage: [&[u8]; 5] = [
        b"hello",
        &wrong_magic,
        &wrong_version,
        &valid[..FRAME_LEN - 1],
        // well-formed, but the sender is not served
        &valid,
    ];
    for (index, frame) in garbage.into_iter().enumerate() {
        let before = server.ignored_frames();
        let accounted = || server.ignored_frames() > before;
        send_until(&sender, &listener_key, frame, accounted).await;
        assert!(accounted(), "garbage frame {index} was not counted");
    }

    client
        .probe(listener_key, BUDGET)
        .await
        .expect("the bridge still answers a served key after garbage");

    close_within(&sender, "sender").await;
    close_bridge_within(&client).await;
    close_bridge_within(&server).await;
}

#[tokio::test]
async fn a_probe_to_a_key_nobody_runs_times_out_and_cleans_up() {
    let (transport, _port) = start_listener(0xA9).await;
    let bridge = YggBridge::new(transport, []);
    let outcome = bridge.probe(DEAD_KEY, SHORT).await;
    assert_eq!(outcome, Err(ProbeError::TimedOut));
    assert_eq!(bridge.pending_probes(), 0);
    close_bridge_within(&bridge).await;
}

#[tokio::test]
async fn the_number_of_waiting_probes_is_bounded() {
    let (transport, _port) = start_listener(0xAA).await;
    let bridge = Arc::new(YggBridge::new(transport, []));
    let waiting: Vec<_> = (0..MAX_PENDING_PROBES)
        .map(|_| {
            let bridge = Arc::clone(&bridge);
            tokio::spawn(async move { bridge.probe(DEAD_KEY, HOLD).await })
        })
        .collect();
    poll_until("every probe slot is taken", || {
        bridge.pending_probes() == MAX_PENDING_PROBES
    })
    .await;
    assert_eq!(bridge.probe(DEAD_KEY, BUDGET).await, Err(ProbeError::Busy));
    for task in waiting {
        assert_eq!(
            task.await.expect("the probe task joins"),
            Err(ProbeError::TimedOut)
        );
    }
    assert_eq!(bridge.pending_probes(), 0);
    close_bridge_within(&bridge).await;
}

#[tokio::test]
async fn a_cancelled_probe_leaves_no_pending_entry() {
    let (transport, _port) = start_listener(0xAB).await;
    let bridge = YggBridge::new(transport, []);
    let cancelled = timeout(Duration::from_millis(100), bridge.probe(DEAD_KEY, BUDGET)).await;
    assert!(cancelled.is_err(), "the probe was still waiting");
    assert_eq!(bridge.pending_probes(), 0);
    close_bridge_within(&bridge).await;
}

#[tokio::test]
async fn close_joins_the_task_releases_waiters_and_is_idempotent() {
    let (transport, port) = start_listener(0xAC).await;
    let bridge = Arc::new(YggBridge::new(transport, []));
    let waiting = tokio::spawn({
        let bridge = Arc::clone(&bridge);
        async move { bridge.probe(DEAD_KEY, BUDGET).await }
    });
    poll_until("the probe is registered", || bridge.pending_probes() == 1).await;

    close_bridge_within(&bridge).await;
    assert_eq!(
        waiting.await.expect("the probe task joins"),
        Err(ProbeError::Closed)
    );
    assert_eq!(
        bridge.probe(DEAD_KEY, BUDGET).await,
        Err(ProbeError::Closed)
    );
    close_bridge_within(&bridge).await;

    drop(bridge);
    poll_until("a task of the bridge is still alive", || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            == 0
    })
    .await;
    TcpListener::bind(("127.0.0.1", port)).expect("the listening port is free again");
}

/// Send `bytes` every 50 ms until `observed` holds: early datagrams can be lost while
/// the path is still being discovered.
async fn send_datagram_until(sender: &DatagramSender, bytes: &[u8], observed: impl Fn() -> bool) {
    let deadline = Instant::now() + BUDGET;
    while !observed() {
        assert!(Instant::now() < deadline, "the datagram was never observed");
        sender
            .send(bytes, Duration::from_secs(1))
            .await
            .expect("carrier send");
        sleep(Duration::from_millis(50)).await;
    }
}

/// Everything already queued for one capability, until it stays quiet for 300 ms.
async fn drain(capability: &mut PeerDatagrams) -> Vec<Vec<u8>> {
    let mut seen = Vec::new();
    while let Ok(received) = timeout(Duration::from_millis(300), capability.recv()).await {
        seen.push(received.expect("the capability is live"));
    }
    seen
}

#[tokio::test]
async fn payload_and_control_datagrams_reach_only_their_own_capability_and_counter() {
    let (server, port) = start_listener(0xB1).await;
    let client = start_dialer(0xB2, port).await;
    let (server_key, client_key) = (server.public_key(), client.public_key());
    let server = YggBridge::new(server, [client_key]);
    let client = YggBridge::new(client, [server_key]);
    let mut server_payload = server
        .open_datagrams(client_key, BUDGET)
        .await
        .expect("server payload capability");
    let mut server_control = server
        .open_control_datagrams(client_key, BUDGET)
        .await
        .expect("server control capability");
    let client_payload = client
        .open_datagrams(server_key, BUDGET)
        .await
        .expect("client payload capability");
    let client_control = client
        .open_control_datagrams(server_key, BUDGET)
        .await
        .expect("client control capability");
    client
        .probe(server_key, BUDGET)
        .await
        .expect("the route is ready");
    let (payload_sender, control_sender) = (client_payload.sender(), client_control.sender());

    // More payload datagrams than one queue holds: none may reach, or spend a slot of,
    // the control queue.
    let goal = u64::try_from(DATAGRAM_QUEUE_CAPACITY + 4).expect("small goal");
    send_datagram_until(&payload_sender, b"data", || {
        server.queued_datagrams() >= goal || server.dropped_datagrams() > 0
    })
    .await;
    assert_eq!(server.control_datagrams(), 0, "payload is never control");
    // The control side sees nothing until a control datagram is sent: a payload copy in
    // the control queue would show up here.
    assert!(drain(&mut server_control).await.is_empty());

    send_datagram_until(&control_sender, b"offer", || {
        server.control_datagrams() >= 1
    })
    .await;
    let control = drain(&mut server_control).await;
    assert!(
        !control.is_empty() && control.iter().all(|datagram| datagram == b"offer"),
        "the control queue holds only control datagrams: {control:?}"
    );
    let payload = drain(&mut server_payload).await;
    assert!(
        !payload.is_empty() && payload.iter().all(|datagram| datagram == b"data"),
        "the payload queue holds only payload datagrams: {payload:?}"
    );
    assert!(
        payload.len() <= DATAGRAM_QUEUE_CAPACITY,
        "a queue never exceeds its capacity"
    );

    for bridge in [&client, &server] {
        close_bridge_within(bridge).await;
    }
}
