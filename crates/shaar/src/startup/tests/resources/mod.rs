//! Composed shared-resource regressions (P10 leaf 5b, chunk R3).
//!
//! Every test drives the PRODUCTION retained constructor
//! [`crate::startup::SharedResourcesStart::start`] against real fixtures
//! only (loopback Mainline peers, real Yggdrasil transit cores, the real
//! signaling relay fixture) — no fake publisher, no fake endpoint.

mod close_tests;
mod fatal_tests;
mod lifecycle_tests;
mod relay_tests;
mod status_tests;
mod ygg_tests;

use std::net::{SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use libp2p_identity::PeerId;
use shaar_ygg::{YggConfig, YggError, YggTransport};

use crate::config::{ServerConfig, ServerOverrides};
use crate::identity::Identity;
use crate::native_discovery::runtime::publisher::PublicationStatus;
use crate::network::Limits;
use crate::startup::SharedResourcesStart;
use crate::startup::preflight::preflight_server;

pub(super) const BUDGET: Duration = Duration::from_secs(10);
pub(super) const PROBE: Duration = Duration::from_secs(5);
pub(super) const STEP: Duration = Duration::from_millis(20);

/// Awaits the retained owner's publisher watch until `Published` within the
/// budget. One condition-based wait on real publication changes; no
/// readiness-query polling.
pub(super) async fn published_on_watch(
    resources: &crate::startup::resources::SharedResources,
) -> PublicationStatus {
    let mut publication = resources
        .publication_watch_for_tests()
        .expect("publisher watch seam installed for admitted compositions");
    tokio::time::timeout(BUDGET, async {
        loop {
            let current = publication.borrow().current(tokio::time::Instant::now());
            if let PublicationStatus::Published { .. } = current {
                return current;
            }
            publication
                .changed()
                .await
                .expect("publisher watch stays live until Published");
        }
    })
    .await
    .expect("actual PUT acknowledgement reaches Published readiness")
}

/// RFC 8032 § 7.1 test-vector 1 Ed25519 public key (fixture only; never the
/// local identity, so the relay role conflict check passes).
const RFC8032_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

pub(super) fn identity(seed_byte: u8) -> Identity {
    Identity::from_seed([seed_byte; 32])
}

/// Real base58btc PeerId text for the pinned relay fixture key; never
/// hand-written.
pub(super) fn relay_peer_id_text() -> String {
    let mut mh = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    mh.extend_from_slice(&hex_32(RFC8032_PUB_HEX));
    PeerId::from_bytes(&mh)
        .expect("valid identity multihash")
        .to_string()
}

fn hex_32(text: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        out[index] =
            u8::from_str_radix(std::str::from_utf8(chunk).expect("hex"), 16).expect("hex digit");
    }
    out
}

// Reserved ports come from a range below the OS ephemeral ranges (Linux 32768+,
// Windows 49152+), so outbound sockets of parallel tests cannot own them, and
// each number is handed out once per process.
const RESERVED_LOW: u32 = 12_000;
const RESERVED_SPAN: u32 = 18_000;
static NEXT_RESERVED: AtomicU32 = AtomicU32::new(0);

fn next_reserved_port() -> u16 {
    let step = NEXT_RESERVED.fetch_add(1, Ordering::Relaxed);
    let start = std::process::id() % RESERVED_SPAN;
    u16::try_from(RESERVED_LOW + (start + step) % RESERVED_SPAN).expect("reserved range fits u16")
}

/// Pick a currently free loopback TCP port that no parallel test can also hold.
pub(super) fn reserve_tcp_port() -> u16 {
    (0..RESERVED_SPAN)
        .map(|_| next_reserved_port())
        .find(|port| TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .expect("a free loopback TCP port in the reserved range")
}

/// Pick a free UDP port from the reserved range (see above); the port is
/// still observable for configuring a mainline bind.
pub(super) fn reserve_udp_port() -> u16 {
    (0..RESERVED_SPAN)
        .map(|_| next_reserved_port())
        .find(|port| UdpSocket::bind(("127.0.0.1", *port)).is_ok())
        .expect("a free loopback UDP port in the reserved range")
}

#[test]
fn reserved_ports_are_unique_free_and_below_the_ephemeral_ranges() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..64 {
        let (tcp, udp) = (reserve_tcp_port(), reserve_udp_port());
        for port in [tcp, udp] {
            assert!(
                (12_000..30_000).contains(&port),
                "port {port} left the reserved range"
            );
            assert!(seen.insert(port), "port {port} was handed out twice");
        }
        assert!(TcpListener::bind(("127.0.0.1", tcp)).is_ok());
        assert!(UdpSocket::bind(("127.0.0.1", udp)).is_ok());
    }
}

/// Server config text with explicit binds; `bootstrap` 1..=4 entries.
/// `fallback` is the raw top-level `fallback: signal|standby` selection;
/// `None` omits the field (the schema default is `standby`).
pub(super) fn server_config_text(
    mainline_bind: SocketAddrV4,
    bootstrap: &[SocketAddrV4],
    signaling_bind: SocketAddr,
    ygg_peers: &[String],
    fallback: Option<&str>,
) -> String {
    let bootstrap_list = bootstrap
        .iter()
        .map(|address| format!("            {address}\n"))
        .collect::<String>();
    let ygg_list = ygg_peers
        .iter()
        .map(|uri| format!("            {uri}\n"))
        .collect::<String>();
    let fallback_line = fallback
        .map(|mode| format!("fallback: {mode}\n"))
        .unwrap_or_default();
    format!(
        "target: 127.0.0.1:9000\n{fallback_line}network: {{\n    mainline: {{\n        \
         bind: {mainline_bind}\n        bootstrap: [\n{bootstrap_list}        ]\n    }}\n    \
         signaling: {{\n        bind: {signaling_bind}\n        relay: {relay}\n        \
         relay_address: 192.0.2.20:7000\n    }}\n    ygg: {{\n        peers: [\n{ygg_list}        \
         ]\n    }}\n}}\n",
        fallback_line = fallback_line,
        mainline_bind = mainline_bind,
        bootstrap_list = bootstrap_list,
        signaling_bind = signaling_bind,
        relay = relay_peer_id_text(),
        ygg_list = ygg_list,
    )
}

/// Parse a fixture server config.
pub(super) fn parse_server_config(text: &str) -> ServerConfig {
    ServerConfig::from_text(text, &ServerOverrides::default()).expect("fixture config parses")
}

/// Spawn the PRODUCTION retained composition start over the fixture plan
/// (default limits). Synchronous: exactly one owner task is spawned.
pub(super) fn start_composition(
    identity: &Identity,
    config: &ServerConfig,
    app_peers: &[iroh_base::PublicKey],
) -> SharedResourcesStart {
    SharedResourcesStart::start(
        identity,
        &plan_for(config, identity, app_peers),
        Limits::default(),
    )
}

/// Test-only retained start with the payload-stage fault seam armed BEFORE
/// the owner task is spawned (race-free constructor variant).
pub(super) fn start_with_payload_fault(
    identity: &Identity,
    config: &ServerConfig,
    app_peers: &[iroh_base::PublicKey],
) -> SharedResourcesStart {
    SharedResourcesStart::start_with_payload_fault_for_tests(
        identity,
        &plan_for(config, identity, app_peers),
        Limits::default(),
    )
}

/// Parse and preflight a server config; the plan borrows `config`.
pub(super) fn plan_for<'a>(
    config: &'a ServerConfig,
    identity: &Identity,
    app_peers: &'a [iroh_base::PublicKey],
) -> crate::startup::preflight::ComposedStartupPlan<'a> {
    preflight_server(config, identity, app_peers).expect("fixture plan passes preflight")
}

/// Admits the retained composition: `wait()` resolving `Ok` IS the
/// deterministic barrier (the owner task published `Status::Admitted`), and
/// a fatal stage produces the original error instead.
pub(super) async fn wait_admitted(
    start: &mut SharedResourcesStart,
) -> crate::startup::resources::SharedResources {
    tokio::time::timeout(BUDGET, start.wait())
        .await
        .expect("composition admits within the budget")
        .expect("composition succeeds")
}

/// Real loopback Yggdrasil transit core (distinct identity + listener), the
/// `ygg_start_tests` listener pattern: dial-out-only service cores peer
/// against it; nothing dials any public peer.
pub(super) async fn start_listener(seed_byte: u8) -> (YggTransport, u16) {
    for _ in 0..50 {
        let port = reserve_tcp_port();
        let uri = format!("tcp://127.0.0.1:{port}");
        let config = YggConfig {
            seed: [seed_byte; 32],
            listen: vec![uri],
            peers: Vec::new(),
            allowed_public_keys: Vec::new(),
            group_password: None,
        };
        match YggTransport::start(config).await {
            Ok(transport) => return (transport, port),
            Err(YggError::Start { .. }) => tokio::time::sleep(STEP).await,
            Err(other) => panic!("listener start failed: {other}"),
        }
    }
    panic!("no reserved loopback port could be bound");
}

/// Bounded key-claim release probe (the ygg_start_tests pattern): the
/// dropped handle's socket teardown has no earlier observable, so the claim
/// is observed with a bounded retry.
pub(super) async fn probe_claim_free(seed_byte: u8, who: &str) {
    let config = YggConfig {
        seed: [seed_byte; 32],
        listen: Vec::new(),
        peers: Vec::new(),
        allowed_public_keys: Vec::new(),
        group_password: None,
    };
    let deadline = tokio::time::Instant::now() + BUDGET;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{who}: key claim not released within {BUDGET:?}"
        );
        match YggTransport::start(config.clone()).await {
            Ok(probe) => {
                let closed = tokio::time::timeout(BUDGET, probe.close())
                    .await
                    .expect("probe close");
                assert!(closed.is_ok(), "{who}: probe close failed");
                return;
            }
            Err(YggError::KeyInUse) => tokio::time::sleep(STEP).await,
            Err(other) => panic!("{who}: probe start failed: {other}"),
        }
    }
}
