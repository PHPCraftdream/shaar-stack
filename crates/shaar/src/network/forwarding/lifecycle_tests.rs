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
