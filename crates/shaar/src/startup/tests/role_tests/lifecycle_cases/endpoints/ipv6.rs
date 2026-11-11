//! Key-only location and fixed-target forwarding with an IPv6-only native client.

#![forbid(unsafe_code)]

use std::{net::Ipv6Addr, time::Duration};

use iroh_base::PublicKey;
use tokio::sync::oneshot;

use crate::{
    native_discovery::runtime::owner::LoopbackPeer,
    network::{Allowlist, Limits, RelayFixture},
    path::PathKind,
    startup::role::{ClientRole, RoleEvent, serve_server_with_events},
};

use super::{
    super::fixtures::{
        ROLE_BUDGET, admit_and_capture, bootstrap_v4, client_role_config, dead_relay_address,
        echo_target, forward_and_echo, identity, pin_role, probe_claim_free, pub_key_hex,
        role_logs, server_role_config, shutdown_roles, start_listener, tuned_policy,
    },
    helpers::{assert_client_binds_released, assert_role_binds_released},
};

const SERVICE: u8 = 0x3D;
const CLIENT: u8 = 0x3E;
const TRANSIT: u8 = 0x3F;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_only_ipv6_forwards_to_the_fixed_target_in_signal_and_standby() {
    tokio::time::timeout(Duration::from_secs(120), async {
        for fallback in ["signal", "standby"] {
            let mut service_peer = LoopbackPeer::bind().await;
            let mut client_peer = LoopbackPeer::bind().await;
            let relay = RelayFixture::start().await;
            let relay_id = relay.address.peer_id().to_string();
            let relay_address = relay.address.socket_addr();
            let (transit, transit_port) = start_listener(TRANSIT).await;
            let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
            let (echo, target_address) = echo_target().await;
            let service_identity = identity(SERVICE);
            let client_identity = identity(CLIENT);
            let client_key = PublicKey::from_bytes(&client_identity.public_key_bytes()).unwrap();
            let service_key = pub_key_hex(&service_identity);
            let server_config = server_role_config(
                target_address, bootstrap_v4(&service_peer), &relay_id,
                relay_address, &transit_uri, fallback,
            );
            let client_config = client_role_config(
                &service_key, bootstrap_v4(&client_peer), &relay_id,
                dead_relay_address(), &transit_uri, fallback, None,
            );
            assert!(client_config.server_address().is_none());
            let (server_log, client_log) = role_logs();
            let (server_stop, server_stopped) = oneshot::channel();
            let server_close_config = server_config.clone();
            let mut server = pin_role(serve_owned_server(
                server_config, service_identity, client_key, server_stopped, server_log.clone(),
            ));
            let item = admit_and_capture(
                &mut service_peer, &mut server, &server_log, ROLE_BUDGET,
            ).await;

            let mut role = ClientRole::with_events_ipv6_only_for_tests(
                client_config.clone(), &client_identity, Limits::new(2).unwrap(),
                tuned_policy(), client_log.clone(),
            ).unwrap();
            let (started, (source, transaction, _, _)) = tokio::time::timeout(ROLE_BUDGET, async {
                tokio::select! {
                    captured = async { tokio::join!(role.start(), client_peer.capture_put_record()) } => captured,
                    result = &mut server => panic!("server stopped while IPv6 client starts: {result:?}"),
                }
            }).await.expect("real client composition and its own signed PUT are observed");
            started.unwrap();
            client_peer.acknowledge(source, &transaction).await;
            let sockets = role.native_sockets_for_tests().expect("live client native owner");
            assert_eq!(sockets.len(), 1);
            assert_eq!(sockets[0].ip(), std::net::IpAddr::V6(Ipv6Addr::LOCALHOST));
            let (client_stop, client_stopped) = oneshot::channel();
            let mut client = pin_role(async move {
                let mut shutdown = std::pin::pin!(async { let _ = client_stopped.await; });
                let outcome = role.run(&mut shutdown).await;
                let close = role.shutdown().await;
                outcome.and(close)
            });

            // Return only the server's actual signed publication, never a rewritten record.
            let target = n0_mainline::MutableItem::target_from_key(item.key(), None);
            let (get_source, get_transaction) = tokio::time::timeout(ROLE_BUDGET, async {
                tokio::select! {
                    query = client_peer.capture_get(target) => query,
                    result = &mut client => panic!("client stopped before cold service-key GET: {result:?}"),
                    result = &mut server => panic!("server stopped before cold GET: {result:?}"),
                }
            }).await.expect("the IPv6-only client emits its actual service-key GET");
            client_peer.reply_get(get_source, &get_transaction, &item).await;
            let mut record_server = std::pin::pin!(client_peer.serve_record(&item));
            let native = |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
            tokio::time::timeout(ROLE_BUDGET, async {
                tokio::select! {
                    event = client_log.wait(native) => assert_eq!(event, RoleEvent::RouteActive(PathKind::Native)),
                    result = &mut client => panic!("client stopped before IPv6 Native route: {result:?}"),
                    result = &mut server => panic!("server stopped before IPv6 route: {result:?}"),
                    _ = &mut record_server => panic!("signed record responder stopped"),
                }
            }).await.expect("real signed-key resolution reaches the IPv6 native server");
            let listener = match client_log.find(&|event| matches!(event, RoleEvent::ListenerReady(_))) {
                Some(RoleEvent::ListenerReady(address)) => address,
                other => panic!("actual local listener was not observed: {other:?}"),
            };
            tokio::select! {
                () = forward_and_echo(listener, b"key-only-ipv6-target-byte", &mut server, &mut client, fallback) => {},
                _ = &mut record_server => panic!("record responder stopped during IPv6 forwarding"),
            }
            assert_eq!(echo.count(), 1);
            assert!(client_log.find(&|event| matches!(event, RoleEvent::ForwardStarted(PathKind::Native))).is_some());
            let _ = server_stop.send(());
            let _ = client_stop.send(());
            tokio::select! {
                () = shutdown_roles(&mut server, &mut client) => {},
                _ = &mut record_server => panic!("record responder stopped during joined shutdown"),
            }
            assert_client_binds_released(&client_config, fallback);
            assert_role_binds_released(&server_close_config, fallback);
            std::net::UdpSocket::bind(sockets[0]).unwrap();
            echo.close().await;
            transit.close().await.unwrap();
            relay.close().await;
            probe_claim_free(SERVICE, "IPv6 service identity released").await;
            probe_claim_free(CLIENT, "IPv6 client identity released").await;
            probe_claim_free(TRANSIT, "IPv6 transit identity released").await;
        }
    }).await.expect("both key-only IPv6 mode cases finish within the bound");
}

/// cancel-safe: NO — a dropped whole-role fixture cannot prove joined cleanup.
async fn serve_owned_server(
    config: crate::config::ServerConfig,
    identity: crate::identity::Identity,
    client: PublicKey,
    stopped: oneshot::Receiver<()>,
    events: crate::startup::role::RoleEventLog,
) -> Result<(), crate::startup::StartupError> {
    serve_server_with_events(
        &config,
        &identity,
        Allowlist::new(&[client]).unwrap(),
        Limits::new(2).unwrap(),
        tuned_policy(),
        async {
            let _ = stopped.await;
        },
        events,
    )
    .await
}
