#![forbid(unsafe_code)]
//! P06 public API acceptance; no raw backend handles or mocked target oracle.

use iroh_base::PublicKey;
use shaar::{
    identity::{Identity, IdentityError},
    network::{Allowlist, Endpoint, ForwardError, ForwardStats, Limits, NetworkError, Session},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinSet,
};

// The documented key-creation example, compiled verbatim (docs/guide/).
#[allow(dead_code)]
#[path = "../../../docs/guide/examples/keygen.rs"]
mod keygen;

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}
fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&identity(seed).public_key_bytes()).unwrap()
}

/// cancel-safe: NO — terminal fixture setup, not a retry loop.
async fn endpoint(seed: u8, allowed: &[PublicKey]) -> Endpoint {
    Endpoint::bind(
        &identity(seed),
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(allowed).unwrap(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap()
}

/// cancel-safe: NO — terminal fixture setup owns both native endpoints.
async fn pair() -> (Endpoint, Endpoint, Session, Session) {
    let mut server = endpoint(81, &[key(82)]).await;
    let client = endpoint(82, &[]).await;
    let address = server.local_addr();
    let (accepted, connected) = tokio::join!(server.accept(), client.connect(key(81), address));
    (server, client, accepted.unwrap(), connected.unwrap())
}

/// cancel-safe: NO — an accepted test TCP pair is never replayed.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (local, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (local.unwrap(), accepted.unwrap().0)
}

/// cancel-safe: NO — consumes the TCP stream pair and checks its terminal result.
async fn exchange(session: &Session, payload: &[u8]) -> ForwardStats {
    let (mut app, bridge) = tcp_pair().await;
    let application = async {
        app.write_all(payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        app.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, payload);
    };
    let (result, ()) = tokio::join!(session.forward(bridge), application);
    result.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn authorized_public_sessions_forward_exactly_two_fixed_target_connections() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = pair().await;
        let server_address = server.local_addr();
        let client_address = client.local_addr();
        assert_eq!(accepted.peer_id(), key(82));
        assert_eq!(connected.peer_id(), key(81));
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let service = async {
                let mut count = 0;
                for _ in 0..2 {
                    let (mut tcp, _) = target.accept().await.unwrap();
                    count += 1;
                    let mut bytes = Vec::new();
                    tcp.read_to_end(&mut bytes).await.unwrap();
                    tcp.write_all(&bytes).await.unwrap();
                    tcp.shutdown().await.unwrap();
                }
                count
            };
            let requests = async {
                assert_eq!(
                    exchange(&connected, b"public SDK traffic").await,
                    ForwardStats {
                        to_peer: 18,
                        from_peer: 18
                    }
                );
                assert_eq!(
                    exchange(&connected, b"second stream").await,
                    ForwardStats {
                        to_peer: 13,
                        from_peer: 13
                    }
                );
            };
            let (count, ()) = tokio::join!(service, requests);
            assert_eq!(count, 2);
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        assert_eq!(report.completed + report.failed + report.cancelled, 2);
        tokio::join!(server.close(), client.close());
        let _server_rebound = UdpSocket::bind(server_address).await.unwrap();
        let _client_rebound = UdpSocket::bind(client_address).await.unwrap();
        drop(target);
        let _target_rebound = TcpListener::bind(address).await.unwrap();
        drop((accepted, connected));
    })
    .await
    .expect("public fixed-target acceptance deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_or_impersonated_peers_open_zero_target_tcp_connections() {
    tokio::time::timeout(Duration::from_secs(45), async {
        for impersonated in [false, true] {
            let mut server = endpoint(81, &[key(83)]).await;
            let client = endpoint(82, &[]).await;
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr();
            let expected = if impersonated { key(84) } else { key(81) };
            let (accepted, connected) =
                tokio::join!(server.accept(), client.connect(expected, address));
            if impersonated {
                assert!(matches!(accepted, Err(NetworkError::Handshake(_))));
                assert!(matches!(
                    connected,
                    Err(NetworkError::Connect(_) | NetworkError::PeerMismatch)
                ));
            } else {
                assert!(matches!(accepted, Err(NetworkError::AccessDenied)));
                match connected {
                    Ok(session) => {
                        let (_app, bridge) = tcp_pair().await;
                        assert!(matches!(
                            session.forward(bridge).await,
                            Err(ForwardError::AccessDenied)
                        ));
                    }
                    Err(error) => assert!(matches!(error, NetworkError::AccessDenied)),
                }
            }
            // Authentication attempt is terminal, not just a timeout readiness guess.
            let count =
                match tokio::time::timeout(Duration::from_millis(100), target.accept()).await {
                    Err(_) => 0,
                    Ok(Ok(_)) => 1,
                    Ok(Err(error)) => panic!("target listener failed: {error}"),
                };
            assert_eq!(count, 0);
            tokio::join!(server.close(), client.close());
        }
    })
    .await
    .expect("public authorization/target counter deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn all_sixteen_stream_slots_are_bounded_and_joined_before_resource_release() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (server, client, mut accepted, connected) = pair().await;
        let connected = Arc::new(connected);
        let server_address = server.local_addr();
        let client_address = client.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let mut applications = Vec::with_capacity(16);
            let mut clients = JoinSet::new();
            for _ in 0..16 {
                let (app, bridge) = tcp_pair().await;
                applications.push(app);
                let session = connected.clone();
                clients.spawn(async move { session.forward(bridge).await });
            }
            let mut targets = Vec::with_capacity(16);
            for _ in 0..16 {
                targets.push(target.accept().await.unwrap().0);
            }
            assert_eq!(targets.len(), 16);
            let (_extra_app, bridge) = tcp_pair().await;
            assert!(matches!(
                connected.forward(bridge).await,
                Err(ForwardError::Capacity)
            ));
            assert!(
                tokio::time::timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err()
            );
            stop.send(()).unwrap();
            let mut joined = 0;
            while let Some(result) = clients.join_next().await {
                assert!(result.unwrap().is_err());
                joined += 1;
            }
            assert_eq!(joined, 16);
            for mut tcp in targets {
                let mut byte = [0];
                assert_eq!(tcp.read(&mut byte).await.unwrap(), 0);
            }
            drop(applications);
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        assert_eq!(report.completed, 0);
        assert_eq!(report.failed + report.cancelled, 16);
        tokio::join!(server.close(), client.close());
        let _server_rebound = UdpSocket::bind(server_address).await.unwrap();
        let _client_rebound = UdpSocket::bind(client_address).await.unwrap();
        assert_eq!(Arc::strong_count(&connected), 1);
        drop(target);
        let _target_rebound = TcpListener::bind(address).await.unwrap();
        drop(accepted);
    })
    .await
    .expect("public sixteen-stream resource deadline");
}

fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("shaar-guide-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn guide_keygen_creates_shows_and_never_overwrites_a_key() {
    let dir = scratch_dir("keygen-create");
    let path = dir.join("example.key");
    let path_text = path.to_str().unwrap();

    let created = keygen::create_key(path_text).await.unwrap();
    assert_eq!(created.len(), 64);
    assert!(
        created
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        32,
        "32 raw seed bytes"
    );

    let loaded = Identity::load(&path).await.unwrap();
    let expected: String = loaded
        .public_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(created, expected);
    assert_eq!(keygen::show_key(path_text).await.unwrap(), created);

    let before = std::fs::read(&path).unwrap();
    let error = keygen::create_key(path_text).await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<IdentityError>(),
        Some(IdentityError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before, "key left untouched");

    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[tokio::test]
async fn guide_keygen_show_rejects_missing_and_malformed_files() {
    let dir = scratch_dir("keygen-show");
    let missing = dir.join("missing.key");
    assert!(keygen::show_key(missing.to_str().unwrap()).await.is_err());
    assert!(!missing.exists(), "show never creates a key");

    let short = dir.join("short.key");
    std::fs::write(&short, [7_u8; 31]).unwrap();
    let error = keygen::show_key(short.to_str().unwrap()).await.unwrap_err();
    assert!(error.downcast_ref::<IdentityError>().is_some());

    std::fs::remove_file(&short).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
