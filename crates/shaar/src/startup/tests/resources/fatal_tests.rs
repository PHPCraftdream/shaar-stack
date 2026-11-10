//! Configured-port fatal rollback through the retained startup API. An occupied
//! Mainline UDP port produces `MainlineStart` before Ygg acquisition; a payload
//! fault after bridge acquisition exercises the same post-transfer fatal path.
//! In both cases `wait` reports the fatal, while `shutdown` joins cleanup.

use std::net::SocketAddrV4;
use std::net::TcpListener;

use crate::startup::SharedResourcesStart;
use crate::startup::StartupError;

use super::{
    BUDGET, identity, parse_server_config, probe_claim_free, reserve_tcp_port, reserve_udp_port,
    server_config_text, start_composition, start_listener, start_with_payload_fault,
};

const SEED: u8 = 0xD1;
/// Post-transfer fatal test: composition identity 0xE4, transit 0xE5,
/// distinct app-peer fixture key 0xE6 (all globally unique in the crate).
const PAYLOAD_SEED: u8 = 0xE4;
const PAYLOAD_TRANSIT_SEED: u8 = 0xE5;
const PAYLOAD_PEER_SEED: u8 = 0xE6;

async fn join_fatal_shutdown(start: &mut SharedResourcesStart, expected: StartupError) {
    let terminal = tokio::time::timeout(BUDGET, async {
        loop {
            match start.shutdown().await {
                Err(error) if error == expected => break error,
                Err(StartupError::Close { stage: "mainline" }) => {
                    tokio::time::sleep(super::STEP).await;
                }
                other => panic!("unexpected fatal shutdown result: {other:?}"),
            }
        }
    })
    .await
    .expect("fatal shutdown joins within the budget");
    assert_eq!(
        terminal, expected,
        "joined shutdown preserves the startup fatal"
    );
    assert_eq!(
        start.shutdown().await,
        Err(expected.clone()),
        "terminal shutdown repeats the startup fatal"
    );
    let closed_wait = tokio::time::timeout(BUDGET, start.wait())
        .await
        .expect("wait after shutdown completes within the budget")
        .expect_err("wait after shutdown is closed");
    assert_eq!(closed_wait, StartupError::Ygg(shaar_ygg::YggError::Closed));
}

#[tokio::test]
async fn occupied_configured_mainline_port_is_fatal_redacted_and_rolls_back_signaling() {
    // Occupy the configured Mainline port with a LIVE socket: this makes
    // RuntimeOwner::start fail deterministically after the signaling
    // endpoint already bound its reserved TCP port — the fatal stage runs
    // BEFORE any Yggdrasil resource exists, so no transit listener is
    // needed and no identity claim is ever taken.
    let occupant = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("occupy a loopback UDP port");
    let mainline_port = occupant.local_addr().expect("local address").port();

    // Reserved signaling port: after the rolled-back fatal this TCP port
    // MUST be bindable again, proving the rollback released the endpoint.
    let signaling_port = reserve_tcp_port();

    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, mainline_port),
        &[SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 9)],
        format!("127.0.0.1:{signaling_port}")
            .parse()
            .expect("signaling bind"),
        &["tcp://127.0.0.1:9".to_string()],
        None,
    );
    let config = parse_server_config(&text);
    let identity = identity(SEED);
    let mut start: SharedResourcesStart = start_composition(&identity, &config, &[]);

    // wait reports the fatal after its initial rollback attempt; shutdown
    // below joins any cleanup still retained by the owner.
    let fatal = tokio::time::timeout(BUDGET, start.wait())
        .await
        .expect("fatal wait finishes within the budget")
        .expect_err("an occupied configured mainline port must be fatal");
    assert_eq!(fatal, StartupError::MainlineStart);
    join_fatal_shutdown(&mut start, fatal.clone()).await;

    // Redaction: neither Display nor Debug may echo the occupied port
    // (StartupError Debug is documented identical to Display).
    let rendered = format!("{} {fatal:?}", fatal);
    assert!(
        !rendered.contains(&mainline_port.to_string()),
        "port leaked through error rendering: {rendered}"
    );

    // Rollback proof: the already-bound signaling TCP port rebinds.
    let rebound = TcpListener::bind(("127.0.0.1", signaling_port))
        .expect("rolled-back signaling port must rebind");
    drop(rebound);

    drop(occupant);
}

/// A fatal AFTER the Yggdrasil transport was synchronously transferred into
/// the bridge must roll back the BRIDGE-OWNED transport through the SAME
/// ordered close (close.rs phase (vi) closes the bridge, the retained-start
/// shutdown joins, native/mainline owners close). This test FAILS if
/// `finish_fatal` skipped the bridge close: the identity key claim would
/// stay held by the unclosed bridge and `probe_claim_free` would time out.
#[tokio::test]
async fn payload_stage_fault_after_ygg_acquisition_rolls_back_the_bridge_owned_transport() {
    let (transit, transit_port) = start_listener(PAYLOAD_TRANSIT_SEED).await;
    let transit_uri = format!("tcp://127.0.0.1:{transit_port}");
    let mainline_port = reserve_udp_port();
    let signaling_port = reserve_tcp_port();
    let text = server_config_text(
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, mainline_port),
        &[SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 9)],
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, signaling_port).into(),
        std::slice::from_ref(&transit_uri),
        Some("standby"),
    );
    let config = parse_server_config(&text);
    let identity = identity(PAYLOAD_SEED);
    // ONE distinct app peer keeps the payload stage on the REAL path.
    let app_peer = [super::identity(PAYLOAD_PEER_SEED).public_key_bytes()];
    let app_peers: Vec<iroh_base::PublicKey> = app_peer
        .iter()
        .map(|key| iroh_base::PublicKey::from_bytes(key).expect("fixture key"))
        .collect();
    let mut start = start_with_payload_fault(&identity, &config, &app_peers);

    // wait reports the fatal after its initial rollback attempt; shutdown
    // below joins cleanup of the bridge-owned transport.
    let fatal = tokio::time::timeout(BUDGET, start.wait())
        .await
        .expect("fatal wait finishes within the budget")
        .expect_err("an armed payload-stage fault must be fatal");
    assert_eq!(fatal, StartupError::YggPayload);
    join_fatal_shutdown(&mut start, fatal).await;

    // Fatal observation and cleanup completion are separate: shutdown above
    // joined the retained owner before any claim or port release is asserted.
    probe_claim_free(PAYLOAD_SEED, "bridge-owned transport claim released").await;
    // Rollback proof: cleanup joined before the signaling TCP port rebind.
    let rebound = TcpListener::bind(("127.0.0.1", signaling_port))
        .expect("rolled-back signaling port must rebind");
    drop(rebound);
    // Rollback proof: cleanup joined before the Mainline UDP port rebind.
    let mainline_rebound = tokio::net::UdpSocket::bind(("127.0.0.1", mainline_port))
        .await
        .expect("rolled-back mainline port must rebind");
    drop(mainline_rebound);

    let closed = tokio::time::timeout(BUDGET, transit.close()).await;
    assert!(
        closed.is_ok() && closed.expect("transit close").is_ok(),
        "transit close"
    );
    probe_claim_free(PAYLOAD_TRANSIT_SEED, "transit claim released").await;
}
