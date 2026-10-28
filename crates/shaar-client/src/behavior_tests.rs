use super::*;
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

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
    assert!(worker_failure(Ok(Ok(())), false).is_none());

    let mut workers = JoinSet::new();
    workers.spawn(async { std::future::pending::<Result<(), ForwardError>>().await });
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
            std::future::pending::<Result<(), ForwardError>>().await
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

#[test]
fn invalid_configuration_text_is_rejected() {
    let result = ClientConfig::from_text_with_endpoint_overrides(
        "not a valid configuration",
        &ClientOverrides::default(),
        &ClientEndpointOverrides::default(),
    );
    assert!(result.is_err());
}
