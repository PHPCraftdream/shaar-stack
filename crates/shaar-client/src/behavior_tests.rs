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

#[test]
fn invalid_configuration_text_is_rejected() {
    let result = ClientConfig::from_text_with_endpoint_overrides(
        "not a valid configuration",
        &ClientOverrides::default(),
        &ClientEndpointOverrides::default(),
    );
    assert!(result.is_err());
}
