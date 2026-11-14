#![forbid(unsafe_code)]

use super::*;
use std::{error::Error, net::IpAddr};
use tokio::net::UdpSocket;

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}

fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&identity(seed).public_key_bytes()).expect("public fixture key")
}

/// cancel-safe: NO — terminal test deadline, not a startup retry mechanism.
async fn bind(seed: u8, allowed: &[PublicKey], sessions: usize) -> Endpoint {
    Endpoint::bind(
        &identity(seed),
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(allowed).unwrap(),
        Limits::new(sessions).unwrap(),
    )
    .await
    .expect("bind SDK endpoint")
}

/// The pending set must keep the endpoint Send and Sync: callers share it across tasks.
#[test]
fn endpoint_stays_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Endpoint>();
}

#[test]
fn policy_bounds_and_native_address_denial() {
    for limit in [0, 33, usize::MAX] {
        assert!(matches!(
            Limits::new(limit),
            Err(NetworkError::InvalidLimits)
        ));
    }
    for limit in [1, 32] {
        assert_eq!(Limits::new(limit).unwrap().sessions, limit);
    }
    assert_eq!(Limits::default().sessions, 32);
    let a = key(67);
    let b = key(68);
    let list = Allowlist::new(&[b, a, b]).unwrap();
    assert!(list.contains(&a));
    assert!(list.contains(&b));
    assert!(!list.contains(&key(69)));
    assert!(!Allowlist::default().contains(&a));
    assert!(Allowlist::new(&[a; 256]).unwrap().contains(&a));
    assert!(matches!(
        Allowlist::new(&[a; 257]),
        Err(NetworkError::AllowlistTooLarge)
    ));
    for ip in ["fd15:70a:510b::1", "fd15:70a:510b:ffff:ffff:ffff:ffff:ffff"] {
        assert!(!policy::native_ip(ip.parse::<IpAddr>().unwrap()));
    }
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "fd15:70a:510c::1"] {
        assert!(policy::native_ip(ip.parse::<IpAddr>().unwrap()));
    }
    for address in [
        "127.0.0.1:0",
        "0.0.0.0:1",
        "[::]:1",
        "224.0.0.1:1",
        "[ff02::1]:1",
        "255.255.255.255:1",
        "[fd15:70a:510b::1]:1",
    ] {
        assert!(!policy::dial_address(address.parse().unwrap()));
    }
    assert!(policy::dial_address("127.0.0.1:1".parse().unwrap()));
    assert!(NetworkError::Capacity.source().is_none());
    assert_eq!(
        NetworkError::AccessDenied.to_string(),
        "peer is not allowed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_sessions_hold_slots_and_close_releases_udp_with_handles_alive() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(68)], 1).await;
        let client = bind(68, &[], 1).await;
        assert_eq!(server.id(), key(67));
        let server_address = server.local_addr();
        let client_address = client.local_addr();
        let (accepted, connected) =
            tokio::join!(server.accept(), client.connect(key(67), server_address));
        let accepted = accepted.unwrap();
        let connected = connected.unwrap();
        assert_eq!(accepted.peer_id(), key(68));
        assert_eq!(connected.peer_id(), key(67));
        assert_eq!(accepted.connection.alpn(), ALPN);
        assert_eq!(connected.connection.alpn(), ALPN);
        assert_eq!(server.slots.available_permits(), 0);
        assert_eq!(client.slots.available_permits(), 0);
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            client
                .connect(key(69), observer.local_addr().unwrap())
                .await,
            Err(NetworkError::Capacity)
        ));
        let mut packet = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), observer.recv_from(&mut packet))
                .await
                .is_err()
        );
        tokio::join!(server.close(), client.close());
        let _server_rebound = UdpSocket::bind(server_address)
            .await
            .expect("server UDP released");
        let _client_rebound = UdpSocket::bind(client_address)
            .await
            .expect("client UDP released");
        assert!(matches!(accepted.closed().await, NetworkError::Closed));
        assert!(matches!(connected.closed().await, NetworkError::Closed));
        drop((accepted, connected));
    })
    .await
    .expect("SDK sessions/shutdown deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_peer_never_receives_an_inbound_session_and_releases_slot() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(69)], 1).await;
        let client = bind(68, &[], 1).await;
        let address = server.local_addr();
        let (accepted, connected) = tokio::join!(server.accept(), client.connect(key(67), address));
        assert!(matches!(accepted, Err(NetworkError::AccessDenied)));
        assert_eq!(server.slots.available_permits(), 1);
        if let Ok(session) = connected {
            assert!(matches!(session.closed().await, NetworkError::AccessDenied));
            session.close();
        }
        assert_eq!(client.slots.available_permits(), 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("SDK access-denial deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_pinned_key_cannot_authenticate_the_real_server() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(68)], 1).await;
        let client = bind(68, &[], 1).await;
        let address = server.local_addr();
        let (accepted, connected) = tokio::join!(server.accept(), client.connect(key(69), address));
        assert!(connected.is_err());
        assert!(accepted.is_err());
        assert_eq!(client.slots.available_permits(), 1);
        assert_eq!(server.slots.available_permits(), 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("SDK pinned-key rejection deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_outbound_handshake_returns_slot_after_observed_initial() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let client = bind(68, &[], 1).await;
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = [0u8; 2048];
        let mut attempt = Box::pin(client.connect(key(67), observer.local_addr().unwrap()));
        tokio::select! {
            result = &mut attempt => panic!("completed before any peer response: {result:?}"),
            packet = observer.recv_from(&mut packet) => assert!(packet.unwrap().0 >= 1200),
        }
        assert_eq!(client.slots.available_permits(), 0);
        drop(attempt);
        assert_eq!(client.slots.available_permits(), 1);
        client.close().await;
    })
    .await
    .expect("SDK cancelled handshake deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn inbound_handshake_deadline_returns_slot_without_a_completed_peer() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(68)], 1).await;
        let client = bind(68, &[], 1).await;
        let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = [0u8; 2048];
        let mut attempt = Box::pin(client.connect(key(67), proxy.local_addr().unwrap()));
        let size = tokio::select! {
            result = &mut attempt => panic!("completed before any peer response: {result:?}"),
            packet = proxy.recv_from(&mut packet) => packet.unwrap().0,
        };
        proxy
            .send_to(&packet[..size], server.local_addr())
            .await
            .unwrap();
        assert!(matches!(server.accept().await, Err(NetworkError::Deadline)));
        assert_eq!(server.slots.available_permits(), 1);
        drop(attempt);
        assert_eq!(client.slots.available_permits(), 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("SDK stalled inbound handshake deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_inbound_is_refused_and_dropped_sessions_allow_a_new_peer() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(68), key(69)], 1).await;
        let first = bind(68, &[], 1).await;
        let next = bind(69, &[], 1).await;
        let address = server.local_addr();
        let (accepted, connected) = tokio::join!(server.accept(), first.connect(key(67), address));
        let accepted = accepted.unwrap();
        let connected = connected.unwrap();
        let (rejected, refused) = tokio::join!(server.accept(), next.connect(key(67), address));
        assert!(matches!(rejected, Err(NetworkError::Capacity)));
        assert!(refused.is_err());
        assert_eq!(next.slots.available_permits(), 1);
        accepted.close();
        connected.close();
        assert_eq!(server.slots.available_permits(), 1);
        assert_eq!(first.slots.available_permits(), 1);
        let (accepted, connected) = tokio::join!(server.accept(), next.connect(key(67), address));
        let accepted = accepted.unwrap();
        let connected = connected.unwrap();
        assert_eq!(accepted.peer_id(), key(69));
        drop((accepted, connected));
        tokio::join!(server.close(), first.close(), next.close());
    })
    .await
    .expect("SDK inbound saturation/reuse deadline");
}

/// Covers the documented cancel-safe contract of `accept`: a dropped accept
/// future parks the attempt and a later call completes the same handshake.
#[tokio::test(flavor = "multi_thread")]
async fn dropped_accept_retains_the_in_flight_handshake() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(68)], 1).await;
        let client = bind(68, &[], 1).await;
        let address = server.local_addr();
        let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = [0u8; 2048];
        let mut attempt = Box::pin(client.connect(key(67), proxy.local_addr().unwrap()));
        let (size, peer) = tokio::select! {
            result = &mut attempt => panic!("completed before any peer response: {result:?}"),
            packet = proxy.recv_from(&mut packet) => packet.unwrap(),
        };
        // One-way relay: the Initial reaches the server, its response dies here.
        proxy.send_to(&packet[..size], address).await.unwrap();
        let slots = server.slots.clone();
        let mut accept = Box::pin(server.accept());
        tokio::select! {
            result = &mut accept => panic!("completed without a reachable client: {result:?}"),
            _ = async {
                loop {
                    let (_, source) = proxy.recv_from(&mut packet).await.unwrap();
                    if source == address { break; }
                }
            } => {}
        }
        // A parked handshake holds no session slot; slots are charged only
        // after authentication.
        assert_eq!(slots.available_permits(), 1);
        // Dropping the accept future parks the handshake in the endpoint: it is
        // neither abandoned nor replayed, just retained for the next accept.
        drop(accept);
        assert_eq!(server.slots.available_permits(), 1);
        // The relay turns transparent again and the SAME handshake completes.
        let relay = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            loop {
                let Ok((size, source)) = proxy.recv_from(&mut packet).await else {
                    break;
                };
                let target = if source == address { peer } else { address };
                if proxy.send_to(&packet[..size], target).await.is_err() {
                    break;
                }
            }
        });
        let (accepted, connected) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(server.accept(), &mut attempt)
        })
        .await
        .expect("retained handshake completes after the accept future was dropped");
        let accepted = accepted.unwrap();
        let connected = connected.unwrap();
        assert_eq!(accepted.peer_id(), key(68));
        // The slot is charged only now, at authentication.
        assert_eq!(server.slots.available_permits(), 0);
        relay.abort();
        drop((accepted, connected, attempt));
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("SDK inbound accept-cancellation deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_initial_does_not_stall_a_second_peer() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = bind(67, &[key(68)], 2).await;
        let legit = bind(68, &[], 1).await;
        let address = server.local_addr();
        // A silent peer: its Initial reaches the server, every response dies at
        // the proxy, so the handshake stays parked without a session slot.
        let silent = bind(69, &[], 1).await;
        let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = [0u8; 2048];
        let mut attempt = Box::pin(silent.connect(key(67), proxy.local_addr().unwrap()));
        let size = tokio::select! {
            result = &mut attempt => panic!("completed before any peer response: {result:?}"),
            packet = proxy.recv_from(&mut packet) => packet.unwrap().0,
        };
        proxy.send_to(&packet[..size], address).await.unwrap();
        assert_eq!(server.slots.available_permits(), 2);
        // The legitimate peer is admitted while the silent handshake is parked,
        // far below the 10 s handshake deadline; the serial accept first awaited
        // the silent handshake's Deadline and failed this bound.
        let (accepted, connected) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server.accept(), legit.connect(key(67), address))
        })
        .await
        .expect("second peer admitted below the handshake deadline");
        let accepted = accepted.unwrap();
        let connected = connected.unwrap();
        assert_eq!(accepted.peer_id(), key(68));
        assert_eq!(accepted.connection.alpn(), ALPN);
        // One slot for the admitted peer; the parked silent attempt holds none.
        assert_eq!(server.slots.available_permits(), 1);
        drop((accepted, connected, attempt));
        tokio::join!(server.close(), legit.close(), silent.close());
    })
    .await
    .expect("silent-Initial concurrency deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_handshake_cap_bounds_silent_initials() {
    tokio::time::timeout(Duration::from_secs(60), async {
        const EXCESS: usize = 2;
        let mut server = bind(67, &[key(68)], 8).await;
        let address = server.local_addr();
        let cap = server.pending_cap;
        // One silent peer per one-way relay: Initial in, every response dies.
        let count = cap + EXCESS;
        let mut silent_peers = Vec::new();
        for seed in 70..(70 + count as u8) {
            let client = bind(seed, &[], 1).await;
            let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = [0u8; 2048];
            {
                // The Initial is out once it is relayed; the dropped attempt sends
                // nothing the server could see, because the proxy relays no more.
                let mut attempt =
                    Box::pin(client.connect(key(67), proxy.local_addr().unwrap()));
                let size = tokio::select! {
                    result = &mut attempt => panic!("completed before any peer response: {result:?}"),
                    packet = proxy.recv_from(&mut packet) => packet.unwrap().0,
                };
                proxy.send_to(&packet[..size], address).await.unwrap();
            }
            silent_peers.push((client, proxy));
        }
        // The accept loop parks up to the cap and refuses the excess instead of
        // queueing memory.
        let _ = tokio::time::timeout(Duration::from_secs(2), server.accept()).await;
        assert_eq!(server.pending.len(), cap);
        // Silent peers hold no session slots.
        assert_eq!(server.slots.available_permits(), 8);
        // At the cap a new attempt is refused promptly while accept is polled, not parked.
        let direct = bind(68, &[], 1).await;
        let refused = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                result = direct.connect(key(67), address) => result,
                accepted = server.accept() => panic!("unexpected admission: {accepted:?}"),
            }
        })
        .await
        .expect("over-cap attempt refused promptly");
        assert!(refused.is_err());
        assert_eq!(server.pending.len(), cap);
        drop(silent_peers);
        drop(refused);
        tokio::join!(server.close(), direct.close());
    })
    .await
    .expect("pending cap deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unoffered_alpn_cannot_produce_an_sdk_session() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut server = bind(67, &[key(68)], 1).await;
        let raw = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(identity(68).transport_key())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .bind()
            .await
            .unwrap();
        let remote = EndpointAddr::from_parts(key(67), [TransportAddr::Ip(server.local_addr())]);
        let (accepted, connected) =
            tokio::join!(server.accept(), raw.connect(remote, b"not-shaar"));
        assert!(accepted.is_err());
        assert!(connected.is_err());
        assert_eq!(server.slots.available_permits(), 1);
        tokio::join!(server.close(), raw.close());
    })
    .await
    .expect("SDK ALPN rejection deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_addresses_fail_before_admission_or_socket_binding() {
    let invalid = "[fd15:70a:510b::1]:0".parse().unwrap();
    assert!(matches!(
        Endpoint::bind(
            &identity(67),
            invalid,
            Allowlist::default(),
            Limits::default()
        )
        .await,
        Err(NetworkError::InvalidAddress)
    ));
    let client = bind(68, &[], 1).await;
    assert!(matches!(
        client.connect(key(67), "0.0.0.0:1".parse().unwrap()).await,
        Err(NetworkError::InvalidAddress)
    ));
    assert_eq!(client.slots.available_permits(), 1);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_metadata_exhaustion_is_capacity_not_a_generic_connect_failure() {
    tokio::time::timeout(Duration::from_secs(15), async {
        // Force the actual lower-layer boundary while one SDK slot is available.
        let inner = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(identity(68).transport_key())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .connection_limit(0)
            .bind()
            .await
            .unwrap();
        let address = inner.bound_sockets()[0];
        let client = Endpoint {
            inner,
            address,
            allowlist: Allowlist::default(),
            slots: Arc::new(Semaphore::new(1)),
            custom: None,
            pending_cap: 1,
            pending: Pending::new(),
        };
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            client
                .connect(key(67), observer.local_addr().unwrap())
                .await,
            Err(NetworkError::Capacity)
        ));
        assert_eq!(client.slots.available_permits(), 1);
        let mut bytes = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), observer.recv_from(&mut bytes))
                .await
                .is_err()
        );
        client.close().await;
    })
    .await
    .expect("SDK metadata capacity mapping deadline");
}
