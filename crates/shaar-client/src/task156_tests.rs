use super::*;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

fn key(identity: &Identity) -> String {
    let mut value = String::new();
    for byte in identity.public_key_bytes() {
        write!(&mut value, "{byte:02x}").unwrap();
    }
    value
}

async fn endpoint(identity: &Identity, allow: Allowlist) -> Endpoint {
    Endpoint::bind(
        identity,
        "127.0.0.1:0".parse().unwrap(),
        allow,
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn coordinator_forwards_concurrent_streams_over_one_session() {
    timeout(Duration::from_secs(30), async {
        let client_id = Identity::from_seed([61; 32]);
        let server_id = Identity::from_seed([62; 32]);
        let client = endpoint(&client_id, Allowlist::default()).await;
        let mut server = endpoint(&server_id, Allowlist::new(&[client.id()]).unwrap()).await;
        let server_address = server.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (stop_server_tx, stop_server_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut session = server.accept().await.unwrap();
            let _ = session
                .serve(target_address, async {
                    let _ = stop_server_rx.await;
                })
                .await;
            server.close().await;
        });
        let target_task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            for _ in 0..4 {
                let (mut stream, _) = target.accept().await.unwrap();
                handlers.spawn(async move {
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(result) = handlers.join_next().await {
                result.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let coordinator = tokio::spawn(coordinate_until(
            listener,
            client,
            key(&server_id),
            server_address,
            async move {
                let _ = stop_rx.await;
                Ok(())
            },
        ));
        let mut apps = Vec::new();
        let mut expected = Vec::new();
        for index in 0..4u8 {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let bytes = vec![index + 1; 96];
            stream.write_all(&bytes).await.unwrap();
            stream.shutdown().await.unwrap();
            apps.push(stream);
            expected.push(bytes);
        }
        let mut clients = JoinSet::new();
        for (mut app, expected) in apps.into_iter().zip(expected) {
            clients.spawn(async move {
                let mut got = Vec::new();
                app.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, expected);
            });
        }
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        target_task.await.unwrap();
        stop_tx.send(()).unwrap();
        coordinator.await.unwrap().unwrap();
        let _ = stop_server_tx.send(());
        server_task.await.unwrap();
    })
    .await
    .expect("forwarding deadline");
}

#[tokio::test]
async fn coordinator_shutdown_joins_active_forwarding() {
    timeout(Duration::from_secs(30), async {
        let client_id = Identity::from_seed([71; 32]);
        let server_id = Identity::from_seed([72; 32]);
        let client = endpoint(&client_id, Allowlist::default()).await;
        let mut server = endpoint(&server_id, Allowlist::new(&[client.id()]).unwrap()).await;
        let server_address = server.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (target_tx, target_rx) = tokio::sync::oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target.accept().await.unwrap();
            target_tx.send(()).unwrap();
            let _ = stream.readable().await;
            drop(stream);
        });
        let (server_stop_tx, server_stop_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut session = server.accept().await.unwrap();
            let _ = session
                .serve(target_address, async {
                    let _ = server_stop_rx.await;
                })
                .await;
            server.close().await;
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let coordinator = tokio::spawn(coordinate_until(
            listener,
            client,
            key(&server_id),
            server_address,
            async move {
                let _ = stop_rx.await;
                Ok(())
            },
        ));
        let application = TcpStream::connect(address).await.unwrap();
        target_rx.await.unwrap();
        stop_tx.send(()).unwrap();
        drop(application);
        coordinator.await.unwrap().unwrap();
        target_task.await.unwrap();
        let _ = server_stop_tx.send(());
        server_task.await.unwrap();
    })
    .await
    .expect("active forwarding shutdown deadline");
}

#[tokio::test]
async fn coordinator_does_not_forward_with_wrong_pinned_key() {
    timeout(Duration::from_secs(35), async {
        let client_id = Identity::from_seed([81; 32]);
        let server_id = Identity::from_seed([82; 32]);
        let wrong_id = Identity::from_seed([83; 32]);
        let client = endpoint(&client_id, Allowlist::default()).await;
        let mut server = endpoint(&server_id, Allowlist::new(&[client.id()]).unwrap()).await;
        let server_address = server.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (stop_server_tx, mut stop_server_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            tokio::select! {
                result = server.accept() => {
                    if let Ok(mut session) = result {
                        let _ = session.serve(target_address, async {
                            let _ = stop_server_rx.await;
                        }).await;
                    }
                }
                _ = &mut stop_server_rx => {}
            }
            server.close().await;
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let coordinator = tokio::spawn(coordinate_until(
            listener,
            client,
            key(&wrong_id),
            server_address,
            async move {
                let _ = stop_rx.await;
                Ok(())
            },
        ));
        let mut application = TcpStream::connect(address).await.unwrap();
        application
            .write_all(b"no response expected")
            .await
            .unwrap();
        let mut response = [0; 1];
        let read = timeout(Duration::from_secs(31), application.read(&mut response))
            .await
            .expect("coordinator retry deadline");
        assert!(
            matches!(read, Ok(0))
                || matches!(read, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionReset),
            "wrong-pinned-key stream should close without response: {read:?}"
        );
        stop_tx.send(()).unwrap();
        coordinator.await.unwrap().unwrap();
        let _ = stop_server_tx.send(());
        server_task.await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    })
    .await
    .expect("wrong-key coordinator deadline");
}

#[tokio::test]
async fn invalid_session_limits_are_rejected() {
    assert!(Limits::new(0).is_err());
    assert!(Limits::new(33).is_err());
}
