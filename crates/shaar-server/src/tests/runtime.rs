use std::time::Duration;

use iroh_base::PublicKey;
use shaar::{
    config::{Fallback, ServerConfig, ServerOverrides},
    identity::Identity,
    network::{Allowlist, Endpoint, Limits, NetworkError},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::oneshot,
};

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}
fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&identity(seed).public_key_bytes()).unwrap()
}

async fn endpoint(seed: u8, allowed: &[PublicKey], capacity: usize) -> Endpoint {
    Endpoint::bind(
        &identity(seed),
        "127.0.0.1:0".parse().unwrap(),
        Allowlist::new(allowed).unwrap(),
        Limits::new(capacity).unwrap(),
    )
    .await
    .unwrap()
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), server.unwrap().0)
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_loop_shutdown_joins_inflight_stream_and_releases_udp_bind() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut server = endpoint(170, &[key(171)], 1).await;
        let client = endpoint(171, &[], 1).await;
        let server_addr = server.local_addr();
        let client_addr = client.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let (reached_tx, reached_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (_stream, _) = target.accept().await.unwrap();
            reached_tx.send(()).unwrap();
            release_rx.await.unwrap();
        });
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let mut shutdown = Box::pin(async move { stop_rx.await.map_err(std::io::Error::other) });
        let loop_task = tokio::spawn(async move {
            let result =
                super::super::server_loop(&mut server, target_addr, 1, &mut shutdown).await;
            server.close().await;
            result
        });
        let session = client.connect(key(170), server_addr).await.unwrap();
        let (_app, bridge) = tcp_pair().await;
        let forward_task = tokio::spawn(async move { session.forward(bridge).await });
        reached_rx.await.unwrap();
        stop_tx.send(()).unwrap();
        assert!(loop_task.await.unwrap().is_ok());
        assert!(forward_task.await.unwrap().is_err());
        release_tx.send(()).unwrap();
        target_task.await.unwrap();
        UdpSocket::bind(server_addr).await.unwrap();
        client.close().await;
        UdpSocket::bind(client_addr).await.unwrap();
    })
    .await
    .expect("runtime shutdown deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_loop_denial_has_no_target_connection_and_capacity_recovers() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let mut server = endpoint(180, &[key(181), key(183)], 1).await;
        let server_addr = server.local_addr();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let mut shutdown = Box::pin(async move { stop_rx.await.map_err(std::io::Error::other) });
        let loop_task = tokio::spawn(async move {
            let result =
                super::super::server_loop(&mut server, target_addr, 1, &mut shutdown).await;
            server.close().await;
            result
        });

        let denied = endpoint(182, &[], 1).await;
        let denied_session = denied.connect(key(180), server_addr).await;
        match denied_session {
            Ok(session) => {
                let (_app, bridge) = tcp_pair().await;
                assert!(matches!(
                    session.forward(bridge).await,
                    Err(shaar::network::ForwardError::AccessDenied)
                ));
            }
            Err(error) => assert!(matches!(error, NetworkError::AccessDenied)),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
        denied.close().await;

        let first_client = endpoint(181, &[], 2).await;
        let second_client = endpoint(183, &[], 2).await;
        let first_session = first_client.connect(key(180), server_addr).await.unwrap();
        let (mut first_app, first_bridge) = tcp_pair().await;
        first_app.write_all(b"held").await.unwrap();
        first_app.flush().await.unwrap();
        let first_task = tokio::spawn(async move { first_session.forward(first_bridge).await });
        let (mut first_target, _) = target.accept().await.unwrap();
        let mut held = [0; 4];
        first_target.read_exact(&mut held).await.unwrap();
        assert_eq!(&held, b"held");

        let second_client_for_connect = second_client;
        let (second_started_tx, second_started_rx) = oneshot::channel();
        let second_task = tokio::spawn(async move {
            second_started_tx.send(()).unwrap();
            let session = second_client_for_connect
                .connect(key(180), server_addr)
                .await
                .unwrap();
            let (mut app, bridge) = tcp_pair().await;
            app.write_all(b"recovered").await.unwrap();
            app.shutdown().await.unwrap();
            let result = session.forward(bridge).await;
            (app, result)
        });
        second_started_rx.await.unwrap();
        let held_accept = target.accept();
        tokio::pin!(held_accept);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut held_accept)
                .await
                .is_err()
        );

        first_task.abort();
        let _ = first_task.await;
        let (mut second_target, _) =
            tokio::time::timeout(Duration::from_secs(10), &mut held_accept)
                .await
                .expect("second target after capacity recovery")
                .unwrap();
        let mut request = Vec::new();
        second_target.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"recovered");
        second_target.write_all(b"response").await.unwrap();
        second_target.shutdown().await.unwrap();
        let (mut second_app, second_result) =
            tokio::time::timeout(Duration::from_secs(10), second_task)
                .await
                .expect("second session recovery")
                .unwrap();
        let mut response = Vec::new();
        second_app.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        assert!(second_result.is_ok());
        drop(first_target);
        stop_tx.send(()).unwrap();
        assert!(loop_task.await.unwrap().is_ok());
    })
    .await
    .expect("runtime admission deadline");
}

#[test]
fn server_config_validation_and_fallback_startup_policy_are_explicit() {
    assert!(
        ServerConfig::from_text("target: 0.0.0.0:9000\n", &ServerOverrides::default()).is_err()
    );
    let standby = ServerConfig::from_text(
        "target: 127.0.0.1:9000\nfallback: standby\n",
        &ServerOverrides::default(),
    )
    .unwrap();
    assert_eq!(standby.fallback(), Fallback::Standby);
    let signal = ServerConfig::from_text(
        "target: 127.0.0.1:9000\nfallback: signal\n",
        &ServerOverrides::default(),
    )
    .unwrap();
    assert_eq!(signal.fallback(), Fallback::Signal);
    assert!(
        ServerConfig::from_text(
            "target: 127.0.0.1:9000\nfallback: unknown\n",
            &ServerOverrides::default()
        )
        .is_err()
    );
    let defaulted =
        ServerConfig::from_text("target: 127.0.0.1:9000\n", &ServerOverrides::default()).unwrap();
    assert_eq!(defaulted.fallback(), Fallback::Standby);
    assert!(super::super::validate_fallback(Fallback::Standby).is_err());
    assert!(super::super::validate_fallback(Fallback::Signal).is_ok());
}
