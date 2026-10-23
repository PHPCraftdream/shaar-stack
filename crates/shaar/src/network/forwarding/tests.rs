#![forbid(unsafe_code)]

use iroh_base::PublicKey;
use std::{future::pending, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Barrier, oneshot},
    task::JoinSet,
};

use super::*;
use crate::{
    identity::Identity,
    network::{Allowlist, Endpoint, Limits},
};

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}
fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&identity(seed).public_key_bytes()).unwrap()
}

/// cancel-safe: NO — terminal test setup, never retried after cancellation.
pub(super) async fn sessions() -> (Endpoint, Endpoint, Session, Session) {
    let mut server = Endpoint::bind(
        &identity(71),
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(&[key(72)]).unwrap(),
        Limits::new(2).unwrap(),
    )
    .await
    .unwrap();
    let client = Endpoint::bind(
        &identity(72),
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::default(),
        Limits::new(2).unwrap(),
    )
    .await
    .unwrap();
    let address = server.local_addr();
    let (accepted, connected) = tokio::join!(server.accept(), client.connect(key(71), address));
    (server, client, accepted.unwrap(), connected.unwrap())
}

/// cancel-safe: NO — owned test socket setup is not replayed.
pub(super) async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (local, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (local.unwrap(), accepted.unwrap().0)
}

/// cancel-safe: NO — one owned application/TCP stream is consumed.
async fn exchange(session: &Session, payload: &[u8]) -> ForwardStats {
    let (mut app, bridge) = tcp_pair().await;
    let application = async {
        app.write_all(payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut received = Vec::new();
        app.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);
    };
    let (result, ()) = tokio::join!(session.forward(bridge), application);
    result.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_request_eof_preserves_response_direction_and_exact_bytes() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let service = async {
                let (mut tcp, _) = target.accept().await.unwrap();
                let mut bytes = Vec::new();
                tcp.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"request after which only response remains");
                tcp.write_all(b"response after EOF").await.unwrap();
                tcp.shutdown().await.unwrap();
            };
            let (mut app, bridge) = tcp_pair().await;
            let app = async {
                app.write_all(b"request after which only response remains")
                    .await
                    .unwrap();
                app.shutdown().await.unwrap();
                let mut response = Vec::new();
                app.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"response after EOF");
            };
            let (forwarded, (), ()) = tokio::join!(connected.forward(bridge), app, service);
            assert_eq!(
                forwarded.unwrap(),
                ForwardStats {
                    to_peer: 41,
                    from_peer: 18
                }
            );
            assert!(connected.connection.close_reason().is_none());
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        assert_eq!(report.completed + report.failed + report.cancelled, 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("TCP request half-close deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn target_write_eof_keeps_the_application_write_direction_open() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let service = async {
                let (mut tcp, _) = target.accept().await.unwrap();
                tcp.write_all(b"greeting").await.unwrap();
                tcp.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                tcp.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"after target EOF");
            };
            let (mut app, bridge) = tcp_pair().await;
            let app = async {
                let mut bytes = Vec::new();
                app.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"greeting");
                app.write_all(b"after target EOF").await.unwrap();
                app.shutdown().await.unwrap();
            };
            let (result, (), ()) = tokio::join!(connected.forward(bridge), app, service);
            assert_eq!(
                result.unwrap(),
                ForwardStats {
                    to_peer: 16,
                    from_peer: 8
                }
            );
            assert!(connected.connection.close_reason().is_none());
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        assert_eq!(report.completed + report.failed + report.cancelled, 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("TCP target half-close deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_streams_are_admitted_concurrently_and_not_serially() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let service = async {
                let barrier = Arc::new(Barrier::new(4));
                let mut tasks = JoinSet::new();
                for _ in 0..4 {
                    let (mut tcp, _) = target.accept().await.unwrap();
                    let barrier = barrier.clone();
                    tasks.spawn(async move {
                        barrier.wait().await;
                        let mut bytes = Vec::new();
                        tcp.read_to_end(&mut bytes).await.unwrap();
                        tcp.write_all(&bytes).await.unwrap();
                        tcp.shutdown().await.unwrap();
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            };
            let clients = async {
                let results = tokio::join!(
                    exchange(&connected, b"one"),
                    exchange(&connected, b"two"),
                    exchange(&connected, b"three"),
                    exchange(&connected, b"four")
                );
                assert_eq!(results.0.to_peer, 3);
                assert_eq!(results.1.to_peer, 3);
                assert_eq!(results.2.to_peer, 5);
                assert_eq!(results.3.to_peer, 4);
            };
            tokio::join!(clients, service);
            assert!(connected.connection.close_reason().is_none());
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        assert_eq!(report.completed + report.failed + report.cancelled, 4);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("parallel forwarding deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_targets_and_full_stream_admission_fail_without_remote_work() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (server, client, mut accepted, connected) = sessions().await;
        for address in ["127.0.0.1:0", "0.0.0.0:1", "192.0.2.1:80", "[::]:1"] {
            assert!(matches!(
                accepted.serve(address.parse().unwrap(), pending()).await,
                Err(ForwardError::InvalidTarget)
            ));
        }
        let held = connected
            .streams
            .try_acquire_many(u32::from(STREAM_LIMIT))
            .unwrap();
        let (mut app, bridge) = tcp_pair().await;
        assert!(matches!(
            connected.forward(bridge).await,
            Err(ForwardError::Capacity)
        ));
        let mut byte = [0];
        assert_eq!(app.read(&mut byte).await.unwrap(), 0);
        drop(held);
        assert_eq!(
            connected.streams.available_permits(),
            usize::from(STREAM_LIMIT)
        );
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("forwarding validation deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn target_failure_is_a_typed_status_and_drops_local_tcp() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = reserved.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let (mut app, bridge) = tcp_pair().await;
            assert!(matches!(
                connected.forward(bridge).await,
                Err(ForwardError::TargetUnavailable)
            ));
            let mut byte = [0];
            assert_eq!(app.read(&mut byte).await.unwrap(), 0);
            assert_eq!(
                connected.streams.available_permits(),
                usize::from(STREAM_LIMIT)
            );
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        assert_eq!(report.failed + report.cancelled, 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("target failure deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_request_never_opens_target_tcp() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let (mut send, mut recv) = connected.connection.open_bi().await.unwrap();
            send.write_all(&[0]).await.unwrap();
            send.finish().unwrap();
            let mut status = [0];
            recv.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [2]);
            assert!(recv.read_to_end(16).await.unwrap().is_empty());
            assert!(
                tokio::time::timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err()
            );
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        assert_eq!(report.unwrap().failed, 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("malformed forwarding request deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_one_stream_does_not_abort_the_next_stream() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let application = async {
            let service = async {
                let (mut broken, _) = target.accept().await.unwrap();
                let mut bytes = Vec::new();
                let _ = broken.read_to_end(&mut bytes).await;
                assert!(bytes.is_empty());
                let (mut good, _) = target.accept().await.unwrap();
                let mut bytes = Vec::new();
                good.read_to_end(&mut bytes).await.unwrap();
                good.write_all(&bytes).await.unwrap();
                good.shutdown().await.unwrap();
            };
            let requests = async {
                let mut broken = protocol::open(&connected.connection).await.unwrap();
                broken.send.reset(VarInt::from_u32(9)).unwrap();
                broken.recv.stop(VarInt::from_u32(9)).unwrap();
                drop(broken);
                assert_eq!(exchange(&connected, b"still alive").await.to_peer, 11);
                assert!(connected.connection.close_reason().is_none());
            };
            tokio::join!(requests, service);
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            application
        );
        let report = report.unwrap();
        // Client completion does not order the server's final FIN ACK before stop.
        assert_eq!(report.completed + report.failed + report.cancelled, 2);
        assert!(report.failed + report.cancelled >= 1);
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("isolated stream reset deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_forward_resets_its_stream_and_returns_its_permit() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let (ready, observed) = oneshot::channel();
        let application = async {
            let service = async {
                let (mut broken, _) = target.accept().await.unwrap();
                ready.send(()).unwrap();
                let mut bytes = Vec::new();
                let _ = broken.read_to_end(&mut bytes).await;
                assert!(bytes.is_empty());
                let (mut good, _) = target.accept().await.unwrap();
                let mut bytes = Vec::new();
                good.read_to_end(&mut bytes).await.unwrap();
                good.write_all(&bytes).await.unwrap();
                good.shutdown().await.unwrap();
            };
            let requests = async {
                let (_app, bridge) = tcp_pair().await;
                let mut forward = Box::pin(connected.forward(bridge));
                tokio::select! {
                    result = &mut forward => panic!("forward completed before cancellation: {result:?}"),
                    result = observed => result.unwrap(),
                }
                assert_eq!(connected.streams.available_permits(), usize::from(STREAM_LIMIT) - 1);
                drop(forward);
                assert_eq!(connected.streams.available_permits(), usize::from(STREAM_LIMIT));
                exchange(&connected, b"after cancellation").await;
                assert!(connected.connection.close_reason().is_none());
            };
            tokio::join!(requests, service);
            stop.send(()).unwrap();
        };
        let (report, ()) = tokio::join!(accepted.serve(address, async { stopped.await.unwrap(); }), application);
        let report = report.unwrap();
        // Stop may also terminate the successfully delivered worker before its ACK.
        assert_eq!(report.completed + report.failed + report.cancelled, 2);
        assert!(report.failed + report.cancelled >= 1);
        tokio::join!(server.close(), client.close());
    }).await.expect("forward cancellation deadline");
}
