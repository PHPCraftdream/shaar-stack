//! Occupied local listener failure through the retained composed client.

#![forbid(unsafe_code)]

use std::{future::pending, time::Duration};

use tokio::net::TcpListener;

use crate::{
    config::{ClientConfig, ClientOverrides},
    native_discovery::runtime::owner::LoopbackPeer,
    network::{Limits, RelayFixture},
    startup::{ClientRole, StartupError},
};

use super::{
    super::fixtures::{
        bootstrap_v4, identity, pub_key_hex, reserve_tcp_port, reserve_udp_port, start_listener,
        tuned_policy,
    },
    helpers::{assert_client_binds_released, assert_key_released_once},
};

// Distinct from the other role/resource fixtures; reused only after joined close.
const CLIENT: u8 = 0x37;
const TRANSIT: u8 = 0x38;
const SERVICE: u8 = 0x39;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn occupied_composed_listener_retains_error_and_joins_owners_in_both_modes() {
    tokio::time::timeout(Duration::from_secs(90), async {
        for fallback in ["signal", "standby"] {
            let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = occupied.local_addr().unwrap();
            let mut peer = LoopbackPeer::bind().await;
            let relay = RelayFixture::start().await;
            let relay_id = relay.address.peer_id().to_string();
            let relay_address = relay.address.socket_addr();
            let (transit, transit_port) = start_listener(TRANSIT).await;
            let client_identity = identity(CLIENT);
            let service_key = pub_key_hex(&identity(SERVICE));
            let bootstrap = bootstrap_v4(&peer);
            let mainline_port = reserve_udp_port();
            let signaling_port = reserve_tcp_port();
            let text = format!(
                "server: {service_key}\nlisten: {address}\nfallback: {fallback}\n\
                 network: {{\n    mainline: {{\n        bind: 127.0.0.1:{mainline_port}\n\
                 bootstrap: [\n            {bootstrap}\n        ]\n    }}\n\
                 signaling: {{\n        bind: 127.0.0.1:{signaling_port}\n\
                 relay: {relay_id}\n        relay_address: {relay_address}\n    }}\n\
                 ygg: {{\n        peers: [\n            tcp://127.0.0.1:{transit_port}\n\
                 ]\n    }}\n}}\n"
            );
            let config = ClientConfig::from_text(&text, &ClientOverrides::default()).unwrap();
            assert!(config.server_address().is_none());
            let mut role = ClientRole::new(
                config.clone(),
                &client_identity,
                Limits::new(1).unwrap(),
                tuned_policy(),
            )
            .unwrap();

            let (started, (source, transaction, _, _)) =
                tokio::join!(role.start(), peer.capture_put_record());
            started.expect("real composition starts before local listener binding");
            peer.acknowledge(source, &transaction).await;
            let mut shutdown = std::pin::pin!(pending::<()>());
            let outcome = role.run(&mut shutdown).await;
            assert_eq!(outcome, Err(StartupError::Listener));
            let joined = role.shutdown().await;
            assert_eq!(joined, outcome, "joined close preserves the listener error");
            assert_eq!(role.shutdown().await, joined, "close result is retained");
            assert_client_binds_released(&config, fallback);
            assert_key_released_once(CLIENT, fallback).await;
            assert_eq!(occupied.local_addr().unwrap(), address);
            drop(occupied);
            TcpListener::bind(address).await.unwrap();

            transit.close().await.unwrap();
            relay.close().await;
            assert_key_released_once(TRANSIT, "listener fixture transit").await;
        }
    })
    .await
    .expect("composed busy-listener error and joined cleanup complete within the bound");
}
