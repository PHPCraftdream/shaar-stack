#![forbid(unsafe_code)]

use iroh::endpoint::{ConnectionError, ReadError, VarInt, WriteError};
use std::{error::Error, io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

use super::{
    ForwardError, STREAM_LIMIT,
    tests::{sessions, tcp_pair},
};

#[test]
fn errors_preserve_types_without_parsing_remote_text() {
    assert!(matches!(
        ForwardError::from_io(ReadError::Reset(VarInt::from_u32(3)).into()),
        ForwardError::StreamReset
    ));
    assert!(matches!(
        ForwardError::from_io(WriteError::Stopped(VarInt::from_u32(3)).into()),
        ForwardError::StreamReset
    ));
    assert!(matches!(
        ForwardError::from_io(ReadError::ConnectionLost(ConnectionError::LocallyClosed).into()),
        ForwardError::PathUnavailable
    ));
    let ordinary = ForwardError::from_io(io::Error::other("target TCP connection failed"));
    assert!(matches!(ordinary, ForwardError::Io(_)));
    assert!(ordinary.source().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_status_rejects_before_any_tcp_payload_is_read() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (server, client, accepted, connected) = sessions().await;
        let (mut app, bridge) = tcp_pair().await;
        app.write_all(b"not before status").await.unwrap();
        let peer = async {
            let (mut send, mut recv) = accepted.connection.accept_bi().await.unwrap();
            let mut request = [0];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [1]);
            let mut unexpected = [0];
            assert!(tokio::time::timeout(Duration::from_millis(100), recv.read(&mut unexpected)).await.is_err());
            send.write_all(&[255]).await.unwrap();
            send.finish().unwrap();
            assert!(matches!(recv.read_to_end(32).await, Err(iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code))) if code == VarInt::from_u32(3)));
        };
        let (result, ()) = tokio::join!(connected.forward(bridge), peer);
        assert!(matches!(result, Err(ForwardError::Protocol)));
        assert_eq!(connected.streams.available_permits(), usize::from(STREAM_LIMIT));
        tokio::join!(server.close(), client.close());
    }).await.expect("forwarding status ordering deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_deadline_resets_stream_and_returns_client_slot() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (server, client, accepted, connected) = sessions().await;
        let (_app, bridge) = tcp_pair().await;
        let peer = async {
            let (_send, mut recv) = accepted.connection.accept_bi().await.unwrap();
            let mut request = [0];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [1]);
            assert!(matches!(recv.read_to_end(32).await, Err(iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code))) if code == VarInt::from_u32(3)));
        };
        let (result, ()) = tokio::join!(connected.forward(bridge), peer);
        assert!(matches!(result, Err(ForwardError::Deadline)));
        assert_eq!(connected.streams.available_permits(), usize::from(STREAM_LIMIT));
        tokio::join!(server.close(), client.close());
    }).await.expect("forwarding setup deadline/reset proof");
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_closes_active_tcp_workers_and_joins_their_results() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (server, client, mut accepted, connected) = sessions().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let (_app, bridge) = tcp_pair().await;
        let service = async {
            let (mut tcp, _) = target.accept().await.unwrap();
            stop.send(()).unwrap();
            let mut bytes = Vec::new();
            let _ = tcp.read_to_end(&mut bytes).await;
            assert!(bytes.is_empty());
        };
        let (report, result, ()) = tokio::join!(
            accepted.serve(address, async {
                stopped.await.unwrap();
            }),
            connected.forward(bridge),
            service
        );
        let report = report.unwrap();
        assert_eq!(report.completed, 0);
        assert_eq!(report.failed + report.cancelled, 1);
        assert!(matches!(result, Err(ForwardError::PathUnavailable)));
        assert_eq!(
            connected.streams.available_permits(),
            usize::from(STREAM_LIMIT)
        );
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("joined forwarding shutdown deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_copy_loop_propagates_quic_backpressure_and_resumes_exactly_once() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, accepted, connected) = sessions().await;
        // Deterministic local capacity; production supplies borrowed TCP halves.
        let (mut app, local) = tokio::io::duplex(32);
        let (read, write) = tokio::io::split(local);
        let payload = vec![0x5a; 2 * 1024 * 1024];
        let (ready, observed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let peer = async {
            let (mut send, mut recv) = accepted.connection.accept_bi().await.unwrap();
            let mut byte = [0];
            recv.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [1]);
            send.write_all(&[0]).await.unwrap();
            recv.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [0x5a]);
            ready.send(()).unwrap();
            released.await.unwrap();
            let rest = recv.read_to_end(payload.len()).await.unwrap();
            assert_eq!(rest.as_slice(), &payload[1..]);
            send.finish().unwrap();
            assert_eq!(send.stopped().await.unwrap(), None);
        };
        let application = async {
            let mut pending = Box::pin(app.write_all(&payload));
            tokio::select! {
                result = &mut pending => panic!("write exceeded bounded queues before peer read: {result:?}"),
                result = observed => result.unwrap(),
            }
            assert!(tokio::time::timeout(Duration::from_millis(100), &mut pending).await.is_err());
            release.send(()).unwrap();
            pending.await.unwrap();
            app.shutdown().await.unwrap();
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            assert!(response.is_empty());
        };
        let forwarding = async {
            let stream = super::protocol::open(&connected.connection).await.unwrap();
            super::pump::copy_halves(stream, read, write).await.unwrap()
        };
        let (stats, (), ()) = tokio::join!(forwarding, application, peer);
        assert_eq!(stats, super::ForwardStats { to_peer: 2 * 1024 * 1024, from_peer: 0 });
        tokio::join!(server.close(), client.close());
    }).await.expect("bounded pump backpressure/release deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn reverse_copy_backpressure_preserves_all_peer_bytes_after_release() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, accepted, connected) = sessions().await;
        let (mut app, local) = tokio::io::duplex(32);
        let (read, write) = tokio::io::split(local);
        let payload = vec![0x6b; 2 * 1024 * 1024];
        let (ready, observed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let peer = async {
            let (mut send, mut recv) = accepted.connection.accept_bi().await.unwrap();
            let mut request = [0];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [1]);
            send.write_all(&[0]).await.unwrap();
            assert!(recv.read_to_end(32).await.unwrap().is_empty());
            let mut pending = Box::pin(send.write_all(&payload));
            tokio::select! {
                result = &mut pending => panic!("peer write exceeded bounded queues: {result:?}"),
                result = observed => result.unwrap(),
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut pending)
                    .await
                    .is_err()
            );
            release.send(()).unwrap();
            pending.await.unwrap();
            send.finish().unwrap();
            assert_eq!(send.stopped().await.unwrap(), None);
        };
        let application = async {
            app.shutdown().await.unwrap();
            let mut first = [0];
            app.read_exact(&mut first).await.unwrap();
            assert_eq!(first, [0x6b]);
            ready.send(()).unwrap();
            released.await.unwrap();
            let mut rest = Vec::new();
            app.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest.as_slice(), &payload[1..]);
        };
        let forwarding = async {
            let stream = super::protocol::open(&connected.connection).await.unwrap();
            super::pump::copy_halves(stream, read, write).await.unwrap()
        };
        let (stats, (), ()) = tokio::join!(forwarding, application, peer);
        assert_eq!(
            stats,
            super::ForwardStats {
                to_peer: 0,
                from_peer: 2 * 1024 * 1024
            }
        );
        tokio::join!(server.close(), client.close());
    })
    .await
    .expect("reverse pump backpressure deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_a_blocked_copy_resets_partial_data_instead_of_finishing_it() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (server, client, accepted, connected) = sessions().await;
        let (mut app, local) = tokio::io::duplex(32);
        let (read, write) = tokio::io::split(local);
        let payload = vec![0x7c; 2 * 1024 * 1024];
        let (ready, observed) = oneshot::channel();
        let (cancel, cancelled) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let peer = async {
            let (mut send, mut recv) = accepted.connection.accept_bi().await.unwrap();
            let mut byte = [0];
            recv.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [1]);
            send.write_all(&[0]).await.unwrap();
            recv.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [0x7c]);
            ready.send(()).unwrap();
            released.await.unwrap();
            assert!(matches!(recv.read_to_end(payload.len()).await, Err(iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code))) if code == VarInt::from_u32(3)));
        };
        let application = async {
            let mut pending = Box::pin(app.write_all(&payload));
            tokio::select! {
                result = &mut pending => panic!("copy was not backpressured before cancellation: {result:?}"),
                result = observed => result.unwrap(),
            }
            assert!(tokio::time::timeout(Duration::from_millis(100), &mut pending).await.is_err());
            cancel.send(()).unwrap();
            release.send(()).unwrap();
            assert!(pending.await.is_err());
        };
        let forwarding = async {
            let stream = super::protocol::open(&connected.connection).await.unwrap();
            let copy = super::pump::copy_halves(stream, read, write);
            tokio::pin!(copy);
            tokio::select! {
                result = &mut copy => panic!("copy ended before requested cancellation: {result:?}"),
                result = cancelled => result.unwrap(),
            }
        };
        tokio::join!(forwarding, application, peer);
        tokio::join!(server.close(), client.close());
    }).await.expect("blocked-copy cancellation/reset deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn truncated_request_or_status_is_protocol_failure_not_generic_io() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for truncated_request in [false, true] {
            let (server, client, accepted, connected) = sessions().await;
            if truncated_request {
                let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = target.local_addr().unwrap();
                let peer = async {
                    let (mut send, mut recv) = connected.connection.open_bi().await.unwrap();
                    send.finish().unwrap();
                    assert!(matches!(recv.read_to_end(32).await, Err(iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code))) if code == VarInt::from_u32(3)));
                };
                let handler = async {
                    let pair = accepted.connection.accept_bi().await.unwrap();
                    let mut stream = super::pump::Stream::new(pair);
                    assert!(matches!(super::protocol::target(&mut stream, address).await, Err(ForwardError::Protocol)));
                    assert!(tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err());
                };
                tokio::join!(handler, peer);
            } else {
                let (_app, bridge) = tcp_pair().await;
                let peer = async {
                    let (mut send, mut recv) = accepted.connection.accept_bi().await.unwrap();
                    let mut request = [0];
                    recv.read_exact(&mut request).await.unwrap();
                    assert_eq!(request, [1]);
                    send.finish().unwrap();
                    assert!(matches!(recv.read_to_end(32).await, Err(iroh::endpoint::ReadToEndError::Read(ReadError::Reset(code))) if code == VarInt::from_u32(3)));
                };
                let (result, ()) = tokio::join!(connected.forward(bridge), peer);
                assert!(matches!(result, Err(ForwardError::Protocol)));
                assert_eq!(connected.streams.available_permits(), usize::from(STREAM_LIMIT));
            }
            tokio::join!(server.close(), client.close());
        }
    }).await.expect("truncated protocol fields deadline");
}
