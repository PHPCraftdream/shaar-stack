//! Cross-path admission capacity and recovery with retained role drives.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use iroh_base::PublicKey;
use tokio::sync::oneshot;

use crate::config::{ClientConfig, ServerConfig};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::{Allowlist, Limits, RelayFixture};
use crate::path::PathKind;
use crate::startup::StartupError;
use crate::startup::role::{RoleEvent, serve_client_with_events, serve_server_with_events};

use super::super::fixtures::{
    RoleFuture, admit_and_capture, arm_client_on_peer, bootstrap_v4, client_role_config,
    dead_relay_address, echo_target, identity, pin_role, pub_key_hex, role_logs,
    server_role_config, silent_udp, start_listener, tuned_policy,
};
use super::helpers::assert_key_released_once;

const ADMIT_SERVER: u8 = 0x64;
const ADMIT_CLIENT_A: u8 = 0x61;
const ADMIT_CLIENT_B: u8 = 0x62;
const ADMIT_CLIENT_C: u8 = 0x63;
const ADMIT_TRANSIT: u8 = 0x65;
const ADMISSION_BUDGET: Duration = Duration::from_secs(150);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_path_capacity_refuses_while_one_shared_slot_is_held() {
    tokio::time::timeout(ADMISSION_BUDGET, async {
        let mut service_peer = LoopbackPeer::bind().await;
        let mut shared_peer = LoopbackPeer::bind().await;
        let mut client_c_peer = LoopbackPeer::bind().await;
        let fixture = RelayFixture::start().await;
        let relay_id = fixture.address.peer_id().to_string();
        let relay_address = fixture.address.socket_addr();
        let (transit, transit_port) = start_listener(ADMIT_TRANSIT).await;
        let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
        let (echo, echo_address) = echo_target().await;
        let silent = silent_udp();

        let server_identity: &'static Identity = Box::leak(Box::new(identity(ADMIT_SERVER)));
        let identity_a: &'static Identity = Box::leak(Box::new(identity(ADMIT_CLIENT_A)));
        let identity_b: &'static Identity = Box::leak(Box::new(identity(ADMIT_CLIENT_B)));
        let identity_c: &'static Identity = Box::leak(Box::new(identity(ADMIT_CLIENT_C)));
        let server_key_hex = pub_key_hex(server_identity);
        let key = |identity: &'static Identity| {
            PublicKey::from_bytes(&identity.public_key_bytes()).expect("fixture client key")
        };
        let server_config: &'static ServerConfig = Box::leak(Box::new(server_role_config(
            echo_address,
            bootstrap_v4(&service_peer),
            &relay_id,
            relay_address,
            &transit_uri,
            "standby",
        )));
        let config_for = |bootstrap: SocketAddrV4, relay: SocketAddr, fallback: &str| {
            Box::leak(Box::new(client_role_config(
                &server_key_hex,
                bootstrap,
                &relay_id,
                relay,
                &transit_uri,
                fallback,
                None,
            ))) as &'static ClientConfig
        };

        let (server_log, _) = role_logs();
        let (server_stop, server_stop_rx) = oneshot::channel();
        let mut server: RoleFuture = pin_role(serve_server_with_events(
            server_config,
            server_identity,
            Allowlist::new(&[key(identity_a), key(identity_b), key(identity_c)])
                .expect("fixture allowlist"),
            Limits::new(1).expect("single-slot fixture limits"),
            tuned_policy(),
            async move {
                let _ = server_stop_rx.await;
            },
            server_log.clone(),
        ));
        let item = admit_and_capture(
            &mut service_peer,
            &mut server,
            &server_log,
            ADMISSION_BUDGET,
        )
        .await;

        // A is silent-bootstrap + dead relay: its only viable path is Ygg.
        let config_a: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &server_key_hex,
            match silent.address {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => panic!("silent bootstrap must bind IPv4"),
            },
            &relay_id,
            dead_relay_address(),
            &transit_uri,
            "standby",
            None,
        )));
        let (stop_a, mut client_a, log_a, listener_a) =
            arm_silent_client_with_server(config_a, identity_a, &mut server, "client A").await;
        let session_ygg = wait_event_with_roles(
            &mut server,
            &mut client_a,
            &server_log,
            &log_a,
            |event| matches!(event, RoleEvent::SessionAdmitted(PathKind::Yggdrasil)),
            "A Ygg session",
        )
        .await;
        assert_eq!(session_ygg, RoleEvent::SessionAdmitted(PathKind::Yggdrasil));
        let held_a = open_held_echo(
            listener_a,
            b"shaar-5c-cap-a",
            &mut server,
            &mut client_a,
            "client A",
        )
        .await;
        assert_eq!(echo.count(), 1, "only A reached the fixed target");

        // B's PUT is captured and ACKed against its own peer before the record
        // server is armed. Its real record GET is driven while both roles run.
        let mut arm_b = Box::pin(arm_client_on_peer(
            config_for(bootstrap_v4(&shared_peer), relay_address, "standby"),
            identity_b,
            &mut shared_peer,
            tuned_policy(),
            ADMISSION_BUDGET,
        ));
        let (_stop_b, mut client_b, _log_b, _) = tokio::time::timeout(ADMISSION_BUDGET, async {
            tokio::select! {
                result = &mut server => panic!(
                    "server ended while B arms: {result:?}"),
                result = &mut client_a => panic!(
                    "A ended while B arms: {result:?}"),
                armed = &mut arm_b => armed,
            }
        })
        .await
        .expect("B arms against its bootstrap peer while server remains live");
        drop(arm_b);
        let mut record_b = std::pin::pin!(shared_peer.serve_record(&item));
        let result_b = tokio::time::timeout(ADMISSION_BUDGET, async {
            tokio::select! {
                result = &mut server => panic!("server ended while B is refused: {result:?}"),
                result = &mut client_a => panic!("A ended while B is refused: {result:?}"),
                _ = &mut record_b => panic!("B record responder terminated"),
                result = &mut client_b => result,
            }
        })
        .await
        .expect("B's path attempts finish within the attempt budget");
        assert!(
            matches!(result_b, Err(StartupError::Exhausted)),
            "B truthfully exhausts against the shared occupied slot: {result_b:?}"
        );
        assert!(
            server_log
                .find(&|event| matches!(event, RoleEvent::AdmissionCapacity(PathKind::Native)))
                .is_some(),
            "B is capacity-refused on Native while A owns the Ygg session: {:?}",
            server_log.snapshot()
        );
        assert!(
            server_log
                .find(&|event| matches!(event, RoleEvent::AdmissionCapacity(PathKind::Yggdrasil)))
                .is_some(),
            "B fallback is capacity-refused on Yggdrasil too: {:?}",
            server_log.snapshot()
        );
        assert_eq!(echo.count(), 1, "B caused no fixed-target connection");
        drop(record_b);

        // The borrowed stream remains owned until A's real role shutdown has
        // joined; the server accept/pump/session drain stays polled meanwhile.
        let _ = stop_a.send(());
        tokio::time::timeout(ADMISSION_BUDGET, async {
            tokio::select! {
                result = &mut server => panic!(
                    "server ended while A's role closes its session: {result:?}"),
                result = &mut client_a => result,
            }
        })
        .await
        .expect("A role/session close joins with the forwarding stream retained")
        .expect("A role shutdown joins cleanly before stream drop");
        drop(held_a);

        // C uses Signal + a dead relay and no direct hint: only a signed
        // Mainline record can establish its native service-key route. Its own
        // peer separates its acknowledged PUT from the server record GET.
        let client_c_config: &'static ClientConfig = Box::leak(Box::new(client_role_config(
            &server_key_hex,
            bootstrap_v4(&client_c_peer),
            &relay_id,
            dead_relay_address(),
            &transit_uri,
            "signal",
            None,
        )));
        assert!(
            client_c_config.server_address().is_none(),
            "C has no direct hint"
        );
        assert_eq!(
            client_c_config.fallback(),
            crate::config::Fallback::Signal,
            "C's policy excludes Ygg payload fallback"
        );
        let mut arm_c = Box::pin(arm_client_on_peer(
            client_c_config,
            identity_c,
            &mut client_c_peer,
            tuned_policy(),
            ADMISSION_BUDGET,
        ));
        let (stop_c, mut client_c, log_c, listener_c) =
            tokio::time::timeout(ADMISSION_BUDGET, async {
                tokio::select! {
                    result = &mut server => panic!(
                        "server ended while C arms: {result:?}"),
                    armed = &mut arm_c => armed,
                }
            })
            .await
            .expect("C arms with the server continuously serving");
        drop(arm_c);
        let mut record_c = std::pin::pin!(client_c_peer.serve_record(&item));
        let route_native =
            |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Native));
        let admission_native =
            |event: &RoleEvent| matches!(event, RoleEvent::SessionAdmitted(PathKind::Native));
        let mut route_seen = log_c.find(&route_native).is_some();
        let mut admission_seen = server_log.find(&admission_native).is_some();
        tokio::time::timeout(ADMISSION_BUDGET, async {
            while !route_seen || !admission_seen {
                tokio::select! {
                    result = &mut server => panic!("server ended during C recovery: {result:?}"),
                    result = &mut client_c => panic!("C ended during native recovery: {result:?}"),
                    () = &mut record_c => panic!("C signed-record responder terminated"),
                    event = server_log.wait(&admission_native), if !admission_seen => {
                        assert_eq!(event, RoleEvent::SessionAdmitted(PathKind::Native));
                        admission_seen = true;
                    }
                    event = log_c.wait(&route_native), if !route_seen => {
                        assert_eq!(event, RoleEvent::RouteActive(PathKind::Native));
                        route_seen = true;
                    }
                }
            }
        })
        .await
        .expect("signed Mainline discovery yields Native route and server admission");
        assert!(
            log_c
                .find(&|event| matches!(event, RoleEvent::YggPayloadAcquired(false)))
                .is_some(),
            "Signal C transfers no Ygg payload pair"
        );
        let mut stream = tokio::select! {
            result = &mut server => panic!("server ended during C echo: {result:?}"),
            result = &mut client_c => panic!("C ended during echo: {result:?}"),
            _ = &mut record_c => panic!("C record responder ended during echo"),
            opened = tokio::net::TcpStream::connect(listener_c) => {
                opened.expect("C opens forwarding stream")
            }
        };
        let pattern = b"shaar-5c-cap-c";
        let io = async {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            stream
                .write_all(pattern)
                .await
                .expect("C sends echo payload");
            let mut echoed = vec![0; pattern.len()];
            stream
                .read_exact(&mut echoed)
                .await
                .expect("C receives echo payload");
            assert_eq!(
                echoed, pattern,
                "C's exact bytes reach and return from target"
            );
        };
        tokio::time::timeout(ADMISSION_BUDGET, async {
            tokio::select! {
                result = &mut server => panic!("server ended during C echo: {result:?}"),
                result = &mut client_c => panic!("C ended during echo: {result:?}"),
                _ = &mut record_c => panic!("C signed-record responder ended during echo"),
                () = io => {},
            }
        })
        .await
        .expect("C native echo succeeds while roles and record responder are polled");
        drop(stream);
        assert_eq!(echo.count(), 2, "C is the second fixed-target connection");

        let _ = server_stop.send(());
        let _ = stop_c.send(());
        let mut server_result = None;
        let mut client_result = None;
        tokio::time::timeout(ADMISSION_BUDGET, async {
            while server_result.is_none() || client_result.is_none() {
                tokio::select! {
                    result = &mut server, if server_result.is_none() => {
                        server_result = Some(result);
                    }
                    result = &mut client_c, if client_result.is_none() => {
                        client_result = Some(result);
                    }
                    _ = &mut record_c => panic!(
                        "C record responder ended before final joined close"),
                }
            }
        })
        .await
        .expect("both active role wrappers join while the record responder stays live");
        assert_eq!(
            server_result,
            Some(Ok(())),
            "server joined close is truthful Ok"
        );
        assert_eq!(client_result, Some(Ok(())), "C joined close is truthful Ok");
        drop(record_c);

        echo.close().await;
        let closed = tokio::time::timeout(ADMISSION_BUDGET, transit.close()).await;
        assert!(
            closed.is_ok() && closed.expect("checked").is_ok(),
            "transit closes"
        );
        fixture.close().await;
        assert_key_released_once(ADMIT_SERVER, "server identity").await;
        assert_key_released_once(ADMIT_CLIENT_A, "A identity").await;
        assert_key_released_once(ADMIT_CLIENT_B, "B identity").await;
        assert_key_released_once(ADMIT_CLIENT_C, "C identity").await;
        assert_key_released_once(ADMIT_TRANSIT, "transit identity").await;
    })
    .await
    .expect("the shared-admission case completes within its budget");
}

async fn arm_silent_client_with_server<S>(
    config: &'static ClientConfig,
    identity: &'static crate::identity::Identity,
    server: &mut S,
    who: &'static str,
) -> (
    oneshot::Sender<()>,
    RoleFuture,
    crate::startup::role::RoleEventLog,
    SocketAddr,
)
where
    S: std::future::Future<Output = Result<(), StartupError>> + Unpin,
{
    let (stop, stop_rx) = oneshot::channel();
    let log = crate::startup::role::RoleEventLog::new();
    let mut role = pin_role(serve_client_with_events(
        config,
        identity,
        Limits::new(4).expect("fixture limits"),
        tuned_policy(),
        async move {
            let _ = stop_rx.await;
        },
        log.clone(),
    ));
    let ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
    let address = tokio::time::timeout(ADMISSION_BUDGET, async {
        tokio::select! {
            result = &mut *server => panic!("server ended while {who} arms: {result:?}"),
            result = &mut role => panic!("{who} ended while arming: {result:?}"),
            event = log.wait(&ready) => match event {
                RoleEvent::ListenerReady(address) => address,
                other => panic!("{who}: unexpected arm event {other:?}"),
            },
        }
    })
    .await
    .expect("silent-bootstrap client listener becomes ready");
    let route_ygg =
        |event: &RoleEvent| matches!(event, RoleEvent::RouteActive(PathKind::Yggdrasil));
    tokio::time::timeout(ADMISSION_BUDGET, async {
        tokio::select! {
            result = &mut *server => panic!("server ended while {who} finds Ygg: {result:?}"),
            result = &mut role => panic!("{who} ended while finding Ygg: {result:?}"),
            event = log.wait(&route_ygg) => {
                assert_eq!(event, RoleEvent::RouteActive(PathKind::Yggdrasil));
            }
        }
    })
    .await
    .expect("silent-bootstrap client reaches its standby Ygg route");
    (stop, role, log, address)
}

async fn wait_event_with_roles<S, C>(
    server: &mut S,
    client: &mut C,
    server_log: &crate::startup::role::RoleEventLog,
    client_log: &crate::startup::role::RoleEventLog,
    pred: impl Fn(&RoleEvent) -> bool + Copy,
    who: &'static str,
) -> RoleEvent
where
    S: std::future::Future<Output = Result<(), StartupError>> + Unpin,
    C: std::future::Future<Output = Result<(), StartupError>> + Unpin,
{
    if let Some(event) = server_log.find(&pred).or_else(|| client_log.find(&pred)) {
        return event;
    }
    tokio::select! {
        result = &mut *server => panic!("{who}: server ended: {result:?}"),
        result = &mut *client => panic!("{who}: client ended: {result:?}"),
        event = server_log.wait(&pred) => event,
        event = client_log.wait(&pred) => event,
    }
}

async fn open_held_echo<S, C>(
    listener: SocketAddr,
    bytes: &[u8],
    server: &mut S,
    client: &mut C,
    who: &'static str,
) -> tokio::net::TcpStream
where
    S: std::future::Future<Output = Result<(), StartupError>> + Unpin,
    C: std::future::Future<Output = Result<(), StartupError>> + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = tokio::select! {
        result = &mut *server => panic!("{who}: server ended opening stream: {result:?}"),
        result = &mut *client => panic!("{who}: client ended opening stream: {result:?}"),
        opened = tokio::net::TcpStream::connect(listener) => {
            opened.expect("held stream connects through client listener")
        }
    };
    let io = async {
        stream
            .write_all(bytes)
            .await
            .expect("held stream writes bytes");
        let mut echoed = vec![0; bytes.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("held echo read");
        assert_eq!(echoed, bytes, "A real target echoes held bytes");
    };
    tokio::select! {
        result = &mut *server => panic!("{who}: server ended during echo: {result:?}"),
        result = &mut *client => panic!("{who}: client ended during echo: {result:?}"),
        () = io => {}
    }
    stream
}
