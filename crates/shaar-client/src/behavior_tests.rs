use super::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

#[tokio::test]
async fn shutdown_releases_listener_port() {
    timeout(Duration::from_secs(5), async {
        let identity = Identity::from_seed([131; 32]);
        let endpoint = Endpoint::bind(
            &identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let coordinator = tokio::spawn(coordinate_until(
            listener,
            endpoint,
            String::new(),
            "127.0.0.1:9".parse().unwrap(),
            async move {
                let _ = shutdown_rx.await;
                Ok(())
            },
        ));
        shutdown_tx.send(()).unwrap();
        timeout(Duration::from_secs(2), coordinator)
            .await
            .expect("coordinator did not stop")
            .unwrap()
            .unwrap();
        let rebound = TcpListener::bind(address)
            .await
            .expect("coordinator did not release listener port");
        drop(rebound);
    })
    .await
    .expect("shutdown/port-reuse test timed out");
}

#[tokio::test]
async fn worker_failures_are_reported_and_cancelled_workers_are_joined() {
    assert!(worker_failure(Ok(Err(ForwardError::TaskFailure)), false).is_some());
    assert!(worker_failure(Ok(Err(ForwardError::PathUnavailable)), false).is_none());
    assert!(
        worker_failure(
            Ok(Ok(ForwardStats {
                to_peer: 0,
                from_peer: 0,
            })),
            false
        )
        .is_none()
    );

    let mut workers = JoinSet::new();
    workers.spawn(async { std::future::pending::<Result<ForwardStats, ForwardError>>().await });
    assert!(abort_workers(&mut workers).await.is_none());
    assert!(workers.is_empty());

    workers.spawn(async { panic!("worker failure") });
    let result = workers.join_next().await.unwrap();
    assert!(worker_failure(result, false).is_some());
}

#[tokio::test]
async fn coordinator_reports_worker_failure_after_joining_other_workers() {
    timeout(Duration::from_secs(15), async {
        let identity = Identity::from_seed([132; 32]);
        let endpoint = Endpoint::bind(
            &identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let endpoint_address = endpoint.local_addr();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let (held_tx, held_rx) = oneshot::channel::<()>();
        let mut workers = JoinSet::new();
        workers.spawn(async move {
            let _held = held_tx;
            std::future::pending::<Result<ForwardStats, ForwardError>>().await
        });
        workers.spawn(async { Err(ForwardError::TaskFailure) });
        let result = coordinate_with_workers(
            listener,
            endpoint,
            String::new(),
            "127.0.0.1:9".parse().unwrap(),
            std::future::pending(),
            workers,
        )
        .await;
        let error = result.expect_err("worker failure must be returned");
        assert!(matches!(
            error.downcast_ref::<ForwardError>(),
            Some(ForwardError::TaskFailure)
        ));
        assert!(held_rx.await.is_err());
        TcpListener::bind(listener_address).await.unwrap();
        tokio::net::UdpSocket::bind(endpoint_address).await.unwrap();
    })
    .await
    .expect("worker failure cleanup deadline");
}

#[tokio::test]
async fn binary_run_reports_an_occupied_local_listener() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let directory = std::env::temp_dir().join(format!(
        "shaar-client-busy-{}-{}",
        std::process::id(),
        address.port()
    ));
    std::fs::create_dir(&directory).unwrap();
    let key_path = directory.join("identity.key");
    let config_path = directory.join("client.ktav");
    let identity = Identity::create_new(&key_path).await.unwrap();
    let server_key: String = identity
        .public_key_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let key_path = key_path.to_str().unwrap().replace('\\', "/");
    let text = format!(
        "server: {server_key}\nserver_address: 127.0.0.1:9\nlisten: {address}\nkey_file: {key_path}\n"
    );
    std::fs::write(&config_path, text).unwrap();
    let parsed = read_config(
        &config_path,
        &ClientOverrides::default(),
        &ClientEndpointOverrides::default(),
    )
    .await
    .unwrap();
    assert_eq!(parsed.key_file(), std::path::Path::new(&key_path));
    Identity::load(parsed.key_file()).await.unwrap();
    let result = timeout(Duration::from_secs(10), run_from_config(config_path)).await;
    std::fs::remove_dir_all(directory).unwrap();
    let error = result
        .expect("busy listener must fail promptly")
        .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap_or_else(|| panic!("expected listener I/O failure, got: {error}"))
            .kind(),
        std::io::ErrorKind::AddrInUse
    );
    assert_eq!(occupied.local_addr().unwrap(), address);
    drop(occupied);
    TcpListener::bind(address).await.unwrap();
}

#[test]
fn invalid_configuration_text_is_rejected() {
    let result = ClientConfig::from_text_with_endpoint_overrides(
        "not a valid configuration",
        &ClientOverrides::default(),
        &ClientEndpointOverrides::default(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn coordinator_forwards_and_reconnects_after_session_loss() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let client_identity = Identity::from_seed([91; 32]);
        let server_identity = Identity::from_seed([92; 32]);
        let client = Endpoint::bind(
            &client_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::default(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let mut server = Endpoint::bind(
            &server_identity,
            "127.0.0.1:0".parse().unwrap(),
            Allowlist::new(&[client.id()]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let server_address = server.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (close_first, close_first_rx) = oneshot::channel::<()>();
        let (first_done, first_done_rx) = oneshot::channel::<()>();
        let (first_finished, first_finished_rx) = oneshot::channel::<()>();
        let target_task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let mut first_done = Some(first_done);
            for index in 0..2 {
                let (mut stream, _) = target.accept().await.unwrap();
                let done = if index == 0 { first_done.take() } else { None };
                tasks.spawn(async move {
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                    if let Some(done) = done {
                        let _ = done.send(());
                    }
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let server_task = tokio::spawn(async move {
            let mut first = server.accept().await.unwrap();
            first
                .serve(target_address, async {
                    let _ = close_first_rx.await;
                })
                .await
                .unwrap();
            drop(first);
            let _ = first_finished.send(());
            let mut second = server.accept().await.unwrap();
            let result = second.serve(target_address, std::future::pending()).await;
            assert!(
                result.is_ok(),
                "the coordinator's clean session close is not a path error"
            );
            drop(second);
            server
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel::<()>();
        let coordinator = tokio::spawn(coordinate_until(
            listener,
            client,
            server_key(&server_identity),
            server_address,
            async move {
                let _ = shutdown_rx.await;
                Ok(())
            },
        ));
        let mut first_app = tcp_connect(local).await;
        first_app.write_all(b"first stream").await.unwrap();
        first_app.shutdown().await.unwrap();
        let mut first_response = Vec::new();
        first_app.read_to_end(&mut first_response).await.unwrap();
        assert_eq!(first_response, b"first stream");
        let _ = first_done_rx.await;
        let _ = close_first.send(());
        let _ = first_finished_rx.await;
        let mut next_app = tcp_connect(local).await;
        next_app
            .write_all(b"new stream after session loss")
            .await
            .unwrap();
        next_app.shutdown().await.unwrap();
        let mut next_response = Vec::new();
        next_app.read_to_end(&mut next_response).await.unwrap();
        assert_eq!(next_response, b"new stream after session loss");
        drop(first_app);
        drop(next_app);
        let _ = shutdown.send(());
        coordinator.await.unwrap().unwrap();
        target_task.await.unwrap();
        server_task.await.unwrap().close().await;
    })
    .await
    .expect("coordinator integration deadline");
}

fn server_key(identity: &Identity) -> String {
    let mut result = String::new();
    for byte in identity.public_key_bytes() {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}
async fn tcp_connect(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.unwrap()
}

#[tokio::test]
async fn admission_gate_prefers_closed_session_when_both_branches_are_ready() {
    let client_identity = Identity::from_seed([111; 32]);
    let server_identity = Identity::from_seed([112; 32]);
    let client = Endpoint::bind(
        &client_identity,
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::default(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap();
    let mut server = Endpoint::bind(
        &server_identity,
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(&[client.id()]).unwrap(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap();
    let (client_session, server_session) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            client.connect(server.id(), server.local_addr()),
            server.accept(),
        )
        .unwrap()
    })
    .await
    .expect("concurrent SDK handshake deadline");

    // Observe the SDK event first, then poll the exact production admission gate.
    // At that point both gate branches are ready; biased selection must reject.
    server_session.close();
    assert!(matches!(
        client_session.closed().await,
        NetworkError::Closed
    ));
    assert!(!admission_live(&client_session).await);

    client_session.close();
    client.close().await;
    server.close().await;
}

#[tokio::test]
async fn admission_gate_prefers_observed_session_closure_when_ready_together() {
    let client_identity = Identity::from_seed([101; 32]);
    let server_identity = Identity::from_seed([102; 32]);
    let client = Endpoint::bind(
        &client_identity,
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::default(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap();
    let mut server = Endpoint::bind(
        &server_identity,
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(&[client.id()]).unwrap(),
        Limits::new(1).unwrap(),
    )
    .await
    .unwrap();
    let (connected, accepted) = tokio::try_join!(
        client.connect(server.id(), server.local_addr()),
        server.accept(),
    )
    .unwrap();

    accepted.close();
    // This await synchronizes on the SDK closure event; the subsequent gate
    // polls closed() and its ready admission branch together, without timing.
    assert!(matches!(connected.closed().await, NetworkError::Closed));
    assert!(!admission_live(&connected).await);

    connected.close();
    client.close().await;
    server.close().await;
}
