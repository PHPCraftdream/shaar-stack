//! Bound addresses the composed roles expose for operator output.

#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::{net::TcpListener, sync::oneshot};

use crate::{
    native_discovery::runtime::owner::LoopbackPeer,
    network::{Allowlist, Limits, RelayFixture},
    startup::{ClientRole, ServerRole},
};

use super::{
    super::fixtures::{
        bootstrap_v4, client_role_config, echo_target, identity, pub_key_hex, server_role_config,
        start_listener, tuned_policy,
    },
    helpers::assert_key_released_once,
};

const CLIENT: u8 = 0xb2;
const CLIENT_TRANSIT: u8 = 0xb3;
const SERVER: u8 = 0xb4;
const SERVER_TRANSIT: u8 = 0xb5;

#[tokio::test]
async fn listening_resolves_none_when_the_client_role_is_dropped_before_binding() {
    let peer = LoopbackPeer::bind().await;
    let config = client_role_config(
        &pub_key_hex(&identity(CLIENT)),
        bootstrap_v4(&peer),
        "12D3KooWRhxsqdyvN1Cy4HDzPjKtdscPa9XUyqoqJwHSsGY8LQTQ",
        "192.0.2.20:4001".parse().unwrap(),
        "tcp://192.0.2.30:1514",
        "signal",
        None,
    );
    let role = ClientRole::new(
        config,
        &identity(CLIENT_TRANSIT),
        Limits::new(1).unwrap(),
        tuned_policy(),
    )
    .unwrap();
    let listening = role.listening();
    drop(role);
    let resolved = tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("a dropped role must not leave the waiter pending");
    assert_eq!(resolved, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_listening_reports_the_bound_listener_and_server_reports_its_native_address() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut client_peer = LoopbackPeer::bind().await;
        let mut server_peer = LoopbackPeer::bind().await;
        let relay = RelayFixture::start().await;
        let relay_id = relay.address.peer_id().to_string();
        let relay_address = relay.address.socket_addr();
        let (client_transit, client_transit_port) = start_listener(CLIENT_TRANSIT).await;
        let (server_transit, server_transit_port) = start_listener(SERVER_TRANSIT).await;
        let (echo, target) = echo_target().await;

        let server_identity = identity(SERVER);
        let server_config = server_role_config(
            target,
            bootstrap_v4(&server_peer),
            &relay_id,
            relay_address,
            &format!("tcp://127.0.0.1:{server_transit_port}"),
            "signal",
        );
        let mut server = ServerRole::new(
            server_config,
            &server_identity,
            Allowlist::default(),
            Limits::new(2).unwrap(),
            tuned_policy(),
        )
        .unwrap();
        assert_eq!(server.native_addr(), None, "no address before start");
        let (source, transaction) = {
            let mut start = std::pin::pin!(server.start());
            let mut capture = std::pin::pin!(server_peer.capture_put_record());
            let mut started = false;
            let mut captured = None;
            while !started || captured.is_none() {
                tokio::select! {
                    result = &mut start, if !started => {
                        result.expect("server starts");
                        started = true;
                    }
                    record = &mut capture, if captured.is_none() => {
                        captured = Some(record);
                    }
                }
            }
            let (source, transaction, _, _) = captured.unwrap();
            (source, transaction)
        };
        server_peer.acknowledge(source, &transaction).await;
        let native = server.native_addr().expect("native address after start");
        assert_ne!(native.port(), 0);
        assert!(native.ip().is_ipv4() && native.ip().is_unspecified());
        server.shutdown().await.expect("server joined close");
        assert_eq!(server.native_addr(), None, "no address after close");

        let client_identity = identity(CLIENT);
        let client_config = client_role_config(
            &pub_key_hex(&server_identity),
            bootstrap_v4(&client_peer),
            &relay_id,
            relay_address,
            &format!("tcp://127.0.0.1:{client_transit_port}"),
            "signal",
            None,
        );
        let mut client = ClientRole::new(
            client_config,
            &client_identity,
            Limits::new(1).unwrap(),
            tuned_policy(),
        )
        .unwrap();
        let listening = client.listening();
        let (started, (source, transaction, _, _)) =
            tokio::join!(client.start(), client_peer.capture_put_record());
        started.expect("client starts");
        client_peer.acknowledge(source, &transaction).await;
        let (stop, stopped) = oneshot::channel::<()>();
        let mut shutdown = std::pin::pin!(async {
            let _ = stopped.await;
        });
        let mut run = std::pin::pin!(client.run(&mut shutdown));
        let address = tokio::select! {
            address = listening => address.expect("listener address published"),
            result = &mut run => panic!("client role ended before binding: {result:?}"),
        };
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        assert!(
            TcpListener::bind(address).await.is_err(),
            "the reported address is the live listener"
        );
        stop.send(()).unwrap();
        run.await.expect("client run ends on shutdown");
        client.shutdown().await.expect("client joined close");

        client_transit.close().await.unwrap();
        server_transit.close().await.unwrap();
        echo.close().await;
        relay.close().await;
        assert_key_released_once(CLIENT, "address client").await;
        assert_key_released_once(SERVER, "address server").await;
    })
    .await
    .expect("role address regressions complete within the bound");
}
