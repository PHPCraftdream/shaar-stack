//! The router mapping of a started role (leaf PORT-1, step 3c): the role asks its gateway to
//! forward the port its endpoint is bound to, and its joined close deletes the mapping.

#![forbid(unsafe_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use tokio::sync::oneshot;

use crate::{
    native_discovery::runtime::owner::LoopbackPeer,
    network::{
        Allowlist, Limits, RelayFixture,
        ports::mapping::{
            Gateway, RouterMapping, Timing,
            tests::{Fake, fake, is_pcp, pcp_answer},
        },
    },
    startup::{ClientRole, RoleOptions, ServerRole},
};

use super::{
    super::fixtures::{
        bootstrap_v4, client_role_config, echo_target, identity, pub_key_hex, server_role_config,
        start_listener, tuned_policy,
    },
    helpers::assert_key_released_once,
};

const CLIENT: u8 = 0xc2;
const CLIENT_TRANSIT: u8 = 0xc3;
const SERVER: u8 = 0xc4;
const SERVER_TRANSIT: u8 = 0xc5;
// The unmapped server runs in parallel with the mapped one, so it has seeds of its own.
const PLAIN_SERVER: u8 = 0xc6;
const PLAIN_SERVER_TRANSIT: u8 = 0xc7;

/// Short pace: the lifetime is two seconds on the wire, a renewal comes after one.
const PACE: Timing = Timing {
    lifetime: Duration::from_secs(2),
    request_budget: Duration::from_millis(300),
    min_renew: Duration::from_millis(50),
    retry: Duration::from_millis(100),
    silent_retry: Duration::from_millis(100),
};

/// A PCP gateway on the loopback that grants every request for the port it was asked for.
async fn granting_gateway() -> Fake {
    fake(|_, request| {
        let port = u16::from_be_bytes([request[42], request[43]]);
        vec![pcp_answer(request, 0, port)]
    })
    .await
}

fn options_for(gateway: &Fake) -> RoleOptions {
    let gateway = Gateway {
        address: gateway.address,
        upnp: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        local: IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    RoleOptions {
        router_mapping: RouterMapping::Gateway(gateway, PACE),
        ..tuned_policy()
    }
}

/// The internal port of a request that maps (a lifetime above zero), when `request` is one.
fn mapped_port(request: &[u8]) -> Option<u16> {
    (is_pcp(request) && request.len() == 60 && request[4..8] != [0; 4])
        .then(|| u16::from_be_bytes([request[40], request[41]]))
}

/// The internal port of the first mapping request the gateway saw, within five seconds.
async fn first_mapped_port(gateway: &Fake) -> u16 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(port) = gateway
                .requests()
                .iter()
                .find_map(|request| mapped_port(request))
            {
                return port;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the role asked its gateway for a mapping")
}

/// Whether the last request is the deletion of the mapping of `port`: lifetime zero.
fn ends_with_deletion_of(gateway: &Fake, port: u16) -> bool {
    gateway.requests().last().is_some_and(|last| {
        is_pcp(last) && last[4..8] == [0; 4] && last[40..42] == port.to_be_bytes()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_started_server_maps_its_bound_port_and_its_close_deletes_the_mapping() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut server_peer = LoopbackPeer::bind().await;
        let relay = RelayFixture::start().await;
        let relay_id = relay.address.peer_id().to_string();
        let relay_address = relay.address.socket_addr();
        let (server_transit, server_transit_port) = start_listener(SERVER_TRANSIT).await;
        let (echo, target) = echo_target().await;
        let gateway = granting_gateway().await;
        let mut server = ServerRole::new(
            server_role_config(
                target,
                bootstrap_v4(&server_peer),
                &relay_id,
                relay_address,
                &format!("tcp://127.0.0.1:{server_transit_port}"),
                "signal",
            ),
            &identity(SERVER),
            Allowlist::default(),
            Limits::new(2).unwrap(),
            options_for(&gateway),
        )
        .unwrap();
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
        let bound = server
            .native_addr()
            .expect("native address after start")
            .port();
        assert_eq!(first_mapped_port(&gateway).await, bound);
        server.shutdown().await.expect("server joined close");
        assert!(
            ends_with_deletion_of(&gateway, bound),
            "the joined close deletes the mapping: {:?}",
            gateway.requests().last()
        );

        server_transit.close().await.unwrap();
        echo.close().await;
        relay.close().await;
        assert_key_released_once(SERVER, "mapping server").await;
    })
    .await
    .expect("the server mapping case completes within the bound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_with_the_default_options_asks_no_gateway_for_anything() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut server_peer = LoopbackPeer::bind().await;
        let relay = RelayFixture::start().await;
        let relay_id = relay.address.peer_id().to_string();
        let relay_address = relay.address.socket_addr();
        let (server_transit, server_transit_port) = start_listener(PLAIN_SERVER_TRANSIT).await;
        let (echo, target) = echo_target().await;
        let gateway = granting_gateway().await;
        let mut server = ServerRole::new(
            server_role_config(
                target,
                bootstrap_v4(&server_peer),
                &relay_id,
                relay_address,
                &format!("tcp://127.0.0.1:{server_transit_port}"),
                "signal",
            ),
            &identity(PLAIN_SERVER),
            Allowlist::default(),
            Limits::new(2).unwrap(),
            tuned_policy(),
        )
        .unwrap();
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
        server.shutdown().await.expect("server joined close");
        assert!(
            gateway.requests().is_empty(),
            "no mapping without the option"
        );

        server_transit.close().await.unwrap();
        echo.close().await;
        relay.close().await;
        assert_key_released_once(PLAIN_SERVER, "unmapped server").await;
    })
    .await
    .expect("the unmapped server case completes within the bound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_started_client_maps_its_bound_port_and_its_close_deletes_the_mapping() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mut client_peer = LoopbackPeer::bind().await;
        let relay = RelayFixture::start().await;
        let relay_id = relay.address.peer_id().to_string();
        let relay_address = relay.address.socket_addr();
        let (client_transit, client_transit_port) = start_listener(CLIENT_TRANSIT).await;
        let gateway = granting_gateway().await;
        let mut client = ClientRole::new(
            client_role_config(
                &pub_key_hex(&identity(SERVER)),
                bootstrap_v4(&client_peer),
                &relay_id,
                relay_address,
                &format!("tcp://127.0.0.1:{client_transit_port}"),
                "signal",
                None,
            ),
            &identity(CLIENT),
            Limits::new(1).unwrap(),
            options_for(&gateway),
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
        let bound = {
            let mut run = std::pin::pin!(client.run(&mut shutdown));
            let bound = tokio::select! {
                address = listening => {
                    address.expect("listener address published");
                    first_mapped_port(&gateway).await
                }
                result = &mut run => panic!("client role ended before binding: {result:?}"),
            };
            stop.send(()).unwrap();
            run.as_mut().await.expect("client run ends on shutdown");
            bound
        };
        client.shutdown().await.expect("client joined close");
        assert!(
            ends_with_deletion_of(&gateway, bound),
            "the joined close deletes the mapping: {:?}",
            gateway.requests().last()
        );

        client_transit.close().await.unwrap();
        relay.close().await;
        assert_key_released_once(CLIENT, "mapping client").await;
    })
    .await
    .expect("the client mapping case completes within the bound");
}
