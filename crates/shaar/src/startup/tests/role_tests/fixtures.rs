//! Shared controlled-5c role fixture helpers (no tests in this module).
//!
//! Everything here reuses the proven 5b fixture machinery
//! (`crate::startup::tests::resources`): same seed discipline, same
//! budget/timeout style, same owned-loopback-fixture patterns. Role futures
//! are PINNED and driven inside the test body (the client role future is not
//! `Send`, so nothing here `tokio::spawn`s a role); role observations come
//! from the lossless `RoleEventLog` — no synthetic seed events, an absent
//! event is absent and every recorded event stays observable in order.
//!
//! Every I/O-adjacent helper here (the arming barrier, the forwarded echo,
//! the held stream) CONTINUOUSLY drives BOTH relevant pinned role futures
//! while its I/O progresses — parking a role deadlocks the data plane.
//! Arming against a bootstrap peer requires the client's initial PUT captured
//! AND acknowledged plus the listener ready before any record server is
//! armed; the arming policy is an explicit `RoleOptions` parameter.
//!
//! Unique seed-byte discipline (process-wide same-key exclusion — every
//! `#[tokio::test]` in this directory runs in one binary):
//! - location case 1: identity 0x51, client identity 0x52, transit 0x53
//! - location case 2: identity 0x54, client identity 0x55, transit 0x56
//! - denial case 5:   identity 0x57, allowed client 0x58, denied client
//!   0x59, transit 0x5A
//! (The 5b suites own 0xB* and 0xE* ranges; no overlap.)

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;

/// Re-exported resource helpers so case files can import them through
/// `super::fixtures` alongside the fixture API.
pub(super) use super::super::resources::{
    identity, probe_claim_free, reserve_tcp_port, reserve_udp_port, start_listener,
};
use crate::config::{ClientConfig, ClientOverrides, ServerConfig, ServerOverrides};
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::network::Limits;
use crate::path::PolicyConfig;
use crate::startup::StartupError;
use crate::startup::role::{ClientRole, RoleEvent, RoleEventLog, RoleOptions};

/// Generous wall-clock bound around one whole role composition (real transit
/// start, real Mainline PUT/GET, real relay reservation and negotiation,
/// tuned retry policy and joined shutdowns). One condition-synchronized test
/// body fits far inside it; the timeout exists only to fail loudly instead
/// of hanging CI.
pub(super) const ROLE_BUDGET: Duration = Duration::from_secs(30);

/// Tight but legal policy per `PolicyConfig::validate`
/// (crates/shaar/src/path/model.rs): every field nonzero and
/// `backoff_base <= backoff_cap`. `attempt_timeout` stays above the 5s
/// per-resolve Mainline budget (`dialers::RESOLVE_BUDGET`) plus one relay
/// negotiation, so a single cold attempt can complete even when the resolve
/// must first time out against the silent bootstrap; `max_attempts: 2`
/// bounds worst-case retry latency far inside [`ROLE_BUDGET`].
pub(super) fn tuned_policy() -> RoleOptions {
    RoleOptions {
        policy: PolicyConfig {
            loss_grace: 200,
            attempt_timeout: 15_000,
            backoff_base: 20,
            backoff_cap: 200,
            max_attempts: 2,
            stable_hold: 200,
        },
    }
}

/// An owned echo server on a loopback ephemeral port: every accepted
/// connection is echoed byte-for-byte and counted. Regression caught by the
/// count: any case that claims a payload path while the fixed server target
/// was never reached (or was reached twice) fails loudly.
pub(super) struct EchoTarget {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
    tasks: JoinSet<()>,
}

impl EchoTarget {
    /// Bounded joined close: stops the accept loop, aborts lingering echo
    /// connections and joins every task. A hang here is a leaked task.
    pub(super) async fn close(mut self) {
        let _ = self.stop.send(true);
        tokio::time::timeout(ROLE_BUDGET, async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .expect("echo target tasks join within the budget");
        assert!(self.tasks.is_empty(), "echo target fully joined");
    }

    pub(super) fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

pub(super) async fn echo_target() -> (EchoTarget, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo target binds a loopback listener");
    let address = listener.local_addr().expect("echo target local address");
    let count = Arc::new(AtomicUsize::new(0));
    let (stop, mut stop_rx) = watch::channel(false);
    let mut tasks: JoinSet<()> = JoinSet::new();
    let counter = Arc::clone(&count);
    tasks.spawn(async move {
        // Per-connection echoes live in a nested JoinSet so one slow client
        // never blocks further accepts.
        let mut connections: JoinSet<std::io::Result<()>> = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow_and_update() {
                        break;
                    }
                }
                accepted = listener.accept() => match accepted {
                    Ok((mut stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        connections.spawn(async move {
                            let (mut read, mut write) = stream.split();
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                            let _ = write.shutdown().await;
                            Ok(())
                        });
                    }
                    Err(_) => break,
                },
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    let target = EchoTarget {
        address,
        count,
        stop,
        tasks,
    };
    (target, address)
}

/// A bound UDP socket that never replies. It keeps a blackhole bootstrap
/// address alive: Mainline GETs against it time out inside the resolve
/// budget instead of failing fast on ICMP, which is exactly the cold-lookup
/// condition the relay-negotiation case needs. Drop closes the socket.
pub(super) struct SilentUdp {
    pub(super) address: SocketAddr,
    _socket: std::net::UdpSocket,
}

pub(super) fn silent_udp() -> SilentUdp {
    let socket =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("silent bootstrap binds a loopback port");
    let address = socket.local_addr().expect("silent bootstrap address");
    SilentUdp {
        address,
        _socket: socket,
    }
}

/// 64 lowercase hex characters of the identity public key (the ktav
/// `server:` field shape).
pub(super) fn pub_key_hex(identity: &Identity) -> String {
    identity
        .public_key_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// IPv4 bootstrap address of a loopback Mainline peer (the peer must bind
/// IPv4; the ktav `bootstrap` entries are `SocketAddrV4`).
pub(super) fn bootstrap_v4(peer: &LoopbackPeer) -> SocketAddrV4 {
    match peer.address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("loopback Mainline peer must bind IPv4"),
    }
}

/// Server role config text (ktav) for the controlled fixtures, modeled on
/// the 5b `server_config_text` builder: real bootstrap, real pinned relay,
/// real transit peer, loopback fixed target. Parsed via the production
/// `ServerConfig::from_text`.
pub(super) fn server_role_config(
    target: SocketAddr,
    bootstrap: SocketAddrV4,
    relay_id: &str,
    relay_address: SocketAddr,
    transit_uri: &str,
    fallback: &str,
) -> ServerConfig {
    let mainline_bind = SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_udp_port());
    let signaling_bind: SocketAddr = format!("127.0.0.1:{}", reserve_tcp_port())
        .parse()
        .expect("reserved signaling bind");
    let text = format!(
        "target: {target}\nfallback: {fallback}\nnetwork: {{\n    mainline: {{\n        \
         bind: {mainline_bind}\n        bootstrap: [\n            {bootstrap}\n        ]\n    \
         }}\n    signaling: {{\n        bind: {signaling_bind}\n        relay: {relay_id}\n        \
         relay_address: {relay_address}\n    }}\n    ygg: {{\n        peers: [\n            \
         {transit_uri}\n        ]\n    }}\n}}\n",
    );
    ServerConfig::from_text(&text, &ServerOverrides::default())
        .expect("fixture server role config parses")
}

/// Client role config text (ktav). `listen` is a loopback ephemeral port;
/// the legacy `server_address` locator is emitted ONLY when the caller
/// passes `direct_hint` — the key-only cases must not carry it. Parsed via
/// the production `ClientConfig::from_text`.
pub(super) fn client_role_config(
    server_key_hex: &str,
    bootstrap: SocketAddrV4,
    relay_id: &str,
    relay_address: SocketAddr,
    transit_uri: &str,
    fallback: &str,
    direct_hint: Option<SocketAddr>,
) -> ClientConfig {
    let mainline_bind = SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_udp_port());
    let signaling_bind: SocketAddr = format!("127.0.0.1:{}", reserve_tcp_port())
        .parse()
        .expect("reserved signaling bind");
    let hint_line = direct_hint
        .map(|address| format!("server_address: {address}\n"))
        .unwrap_or_default();
    let text = format!(
        "server: {server_key_hex}\nlisten: 127.0.0.1:0\n{hint_line}fallback: {fallback}\n\
         network: {{\n    mainline: {{\n        bind: {mainline_bind}\n        bootstrap: [\n    \
         {bootstrap}\n        ]\n    }}\n    signaling: {{\n        bind: {signaling_bind}\n    \
         relay: {relay_id}\n        relay_address: {relay_address}\n    }}\n    ygg: {{\n        \
         peers: [\n            {transit_uri}\n        ]\n    }}\n}}\n",
    );
    ClientConfig::from_text(&text, &ClientOverrides::default())
        .expect("fixture client role config parses")
}

/// Two fresh lossless role logs (server, client). No synthetic seeds: an
/// absent event is absent, and every recorded event stays observable.
pub(super) fn role_logs() -> (RoleEventLog, RoleEventLog) {
    (RoleEventLog::new(), RoleEventLog::new())
}

/// A pinned role future driven inside the test body. The client role future
/// is not Send (the standby owner parks non-Send dialer tasks), so roles are
/// never tokio::spawn-ed in fixtures.
pub(super) type RoleFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StartupError>> + 'static>>;

/// Pins one role future for in-body driving. See [`RoleFuture`].
pub(super) fn pin_role(
    fut: impl std::future::Future<Output = Result<(), StartupError>> + 'static,
) -> RoleFuture {
    Box::pin(fut)
}

/// Drives both pinned role futures while waiting for one log predicate on
/// either log. A role that ENDS while still awaited is a loud failure that
/// names the role and its truthful result — this is what makes the budget
/// bounds fail fast instead of hanging. The unconditional scans up front make
/// an event recorded before the call observed without waiting for a version
/// change; the log's `wait` is cancel-safe, so re-selecting it every loop
/// loses nothing.
pub(super) async fn wait_role_event<'a, S, C>(
    server: &'a mut S,
    client: &'a mut C,
    server_log: &RoleEventLog,
    client_log: &RoleEventLog,
    pred: impl Fn(&RoleEvent) -> bool + Copy,
    who: &'static str,
) -> RoleEvent
where
    S: Future<Output = Result<(), StartupError>> + Unpin,
    C: Future<Output = Result<(), StartupError>> + Unpin,
{
    if let Some(event) = server_log.find(&pred) {
        return event;
    }
    if let Some(event) = client_log.find(&pred) {
        return event;
    }
    tokio::select! {
        result = &mut *server => panic!("{who}: server role ended while waiting: {result:?}"),
        result = &mut *client => panic!("{who}: client role ended while waiting: {result:?}"),
        event = server_log.wait(&pred) => return event,
        event = client_log.wait(&pred) => return event,
    }
}

/// Drives both pinned futures until the CLIENT completes; used when a client
/// is expected to end (e.g. truthful budget exhaustion). The server must
/// stay alive; a server that ends is a loud failure.
pub(super) async fn drive_client_to_end<S, C>(
    server: &mut S,
    client: &mut C,
    who: &'static str,
) -> Result<(), StartupError>
where
    S: Future<Output = Result<(), StartupError>> + Unpin,
    C: Future<Output = Result<(), StartupError>> + Unpin,
{
    tokio::select! {
        result = &mut *server => panic!(
            "{who}: server role ended while waiting for the client: {result:?}"
        ),
        // A pinned future cannot fail to join; its Result is returned
        // truthfully for the caller to inspect.
        result = &mut *client => result,
    }
}

/// Bounded graceful shutdown of one pinned role after its stop sender fired:
/// drives the role to completion and asserts a truthful `Ok(())` — a role
/// that "succeeded" while leaking its owners fails here.
/// cancel-safe: NO — completed borrowed roles must not be polled again on retry.
pub(super) async fn shutdown_roles(server: &mut RoleFuture, client: &mut RoleFuture) {
    tokio::time::timeout(ROLE_BUDGET, async {
        let mut server_done = false;
        let mut client_done = false;
        while !server_done || !client_done {
            tokio::select! {
                result = &mut *server, if !server_done => {
                    result.expect("server joined shutdown succeeds");
                    server_done = true;
                }
                result = &mut *client, if !client_done => {
                    result.expect("client joined shutdown succeeds");
                    client_done = true;
                }
            }
        }
    })
    .await
    .expect("both role shutdowns complete within the budget");
}

/// Forwards one byte pattern through the client's local listener and
/// asserts the echo came back byte-for-byte, CONTINUOUSLY driving both
/// pinned role futures while the I/O progresses — the data plane only
/// moves while the roles are polled. A role that ends mid-transfer is a
/// loud truthful failure.
pub(super) async fn forward_and_echo<S, C>(
    listener_address: SocketAddr,
    pattern: &[u8],
    server: &mut S,
    client: &mut C,
    who: &'static str,
) where
    S: Future<Output = Result<(), StartupError>> + Unpin,
    C: Future<Output = Result<(), StartupError>> + Unpin,
{
    let io = async {
        let mut stream = TcpStream::connect(listener_address)
            .await
            .unwrap_or_else(|_| panic!("{who} opens its forwarding probe"));
        stream
            .write_all(pattern)
            .await
            .unwrap_or_else(|_| panic!("{who} pattern written"));
        let mut echoed = vec![0_u8; pattern.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .unwrap_or_else(|_| panic!("{who} echoed pattern read back"));
        assert_eq!(
            &echoed[..],
            pattern,
            "forwarded byte pattern echoes byte-for-byte"
        );
    };
    tokio::select! {
        result = &mut *server => {
            panic!("{who}: server role ended during the forwarded echo: {result:?}")
        }
        result = &mut *client => {
            panic!("{who}: client role ended during the forwarded echo: {result:?}")
        }
        _ = io => {}
    }
}

/// Arms one client role against `bootstrap_peer` WITHOUT any record server:
/// retain startup and capture its initial PUT before running the client; only
/// after acknowledging that PUT does the live role loop start. The arming
/// barrier also requires `ListenerReady` observed, while the pinned run future
/// is driven. `options` is the explicit arming policy. Returns the stop sender,
/// the pinned future, the client's log and the listener address. Callers arm
/// the Mainline record server only AFTER all clients they intend to arm have
/// been armed (a PUT landing in the record server's GET loop would panic).
pub(super) async fn arm_client_on_peer(
    config: &'static ClientConfig,
    identity: &'static Identity,
    bootstrap_peer: &mut LoopbackPeer,
    options: RoleOptions,
    budget: Duration,
) -> (oneshot::Sender<()>, RoleFuture, RoleEventLog, SocketAddr) {
    let log = RoleEventLog::new();
    let mut role = ClientRole::with_events(
        config.clone(),
        identity,
        Limits::new(4).expect("fixture limits"),
        options,
        log.clone(),
    )
    .expect("client role builds for retained startup");
    let (stop, stop_rx) = oneshot::channel();

    let (client, listener) = tokio::time::timeout(budget, async {
        // Do not poll `run` while the bootstrap PUT is outstanding: it may
        // issue a real service GET, which this peer intentionally does not
        // answer.
        let captured = {
            let mut start = Box::pin(role.start());
            let mut capture = Box::pin(bootstrap_peer.capture_put_record());
            let mut started = false;
            let mut captured = None;
            while !started || captured.is_none() {
                tokio::select! {
                    result = &mut start, if !started => {
                        result.expect("client startup succeeds before its run loop");
                        started = true;
                    }
                    record = &mut capture, if captured.is_none() => {
                        captured = Some(record);
                    }
                }
            }
            captured.expect("initial PUT captured")
        };
        let (source, transaction, _signed, _item) = captured;
        bootstrap_peer.acknowledge(source, &transaction).await;

        let mut client = pin_role(async move {
            let mut role = role;
            let mut shutdown = std::pin::pin!(async move {
                let _ = stop_rx.await;
            });
            let outcome = role.run(&mut shutdown).await;
            let close = role.shutdown().await;
            outcome.and(close)
        });
        let listener_ready = |event: &RoleEvent| matches!(event, RoleEvent::ListenerReady(_));
        let listener = tokio::select! {
            result = &mut client => panic!(
                "client role ended while awaiting ListenerReady: {result:?}"
            ),
            event = log.wait(&listener_ready) => match event {
                RoleEvent::ListenerReady(address) => address,
                other => panic!("unexpected role event while arming the client: {other:?}"),
            },
        };
        (client, listener)
    })
    .await
    .expect("client arming (startup, initial PUT acknowledgement, and listener ready) within the budget");

    (stop, client, log, listener)
}

/// The 5b admit-and-capture pattern, pinned-driving edition: server admission
/// and its real initial PUT are concurrently retained (the SERVER role future
/// is driven in a select arm while the capture races it), then the PUT is
/// acknowledged. Returns the signed record item the clients' cold GETs must
/// be served with.
pub(super) async fn admit_and_capture<S>(
    peer: &mut LoopbackPeer,
    server: &mut S,
    server_log: &RoleEventLog,
    budget: Duration,
) -> n0_mainline::MutableItem
where
    S: Future<Output = Result<(), StartupError>> + Unpin,
{
    let admitted = |event: &RoleEvent| matches!(event, RoleEvent::Admitted);
    let mut capture = Box::pin(peer.capture_put_record());
    let mut admitted_seen = false;
    let mut held = None;
    tokio::time::timeout(budget, async {
        while !admitted_seen || held.is_none() {
            tokio::select! {
                _ = server_log.wait(&admitted), if !admitted_seen => admitted_seen = true,
                captured = &mut capture, if held.is_none() => held = Some(captured),
                result = &mut *server => panic!(
                    "server role ended while awaiting admission and its initial PUT: {result:?}"
                ),
            }
        }
    })
    .await
    .expect("server role admission and actual initial PUT are both observed");
    // The capture future borrows `peer` mutably for as long as it lives;
    // the output is already owned by `held`, so drop it before the ack.
    drop(capture);
    let (source, transaction, _signed, item) = held.expect("captured PUT retained");
    peer.acknowledge(source, &transaction).await;
    item
}

/// Opens a HELD forwarding stream through the client listener and asserts
/// the byte pattern echoes, driving both pinned role futures throughout
/// (see [`forward_and_echo`]); the stream stays open in the caller (the
/// server-side admission slot stays taken while it lives).
pub(super) async fn hold_echoing_stream<S, C>(
    listener: SocketAddr,
    pattern: &[u8],
    server: &mut S,
    client: &mut C,
    who: &'static str,
) -> TcpStream
where
    S: Future<Output = Result<(), StartupError>> + Unpin,
    C: Future<Output = Result<(), StartupError>> + Unpin,
{
    let io = async {
        let stream = TcpStream::connect(listener)
            .await
            .unwrap_or_else(|_| panic!("{who} opens its held forwarding stream"));
        stream
    };
    let mut stream = tokio::select! {
        result = &mut *server => {
            panic!("{who}: server role ended while opening the held stream: {result:?}")
        }
        result = &mut *client => {
            panic!("{who}: client role ended while opening the held stream: {result:?}")
        }
        opened = io => opened,
    };
    echo_on_held_stream(&mut stream, pattern, server, client, who).await;
    stream
}

/// Echoes one more pattern over an ALREADY HELD forwarding stream while
/// driving both pinned role futures (see [`forward_and_echo`]): the held
/// stream's forward worker and the server-side session only move while
/// their owning role futures are polled.
pub(super) async fn echo_on_held_stream<S, C>(
    stream: &mut TcpStream,
    pattern: &[u8],
    server: &mut S,
    client: &mut C,
    who: &'static str,
) where
    S: Future<Output = Result<(), StartupError>> + Unpin,
    C: Future<Output = Result<(), StartupError>> + Unpin,
{
    let io = async {
        stream
            .write_all(pattern)
            .await
            .unwrap_or_else(|_| panic!("{who} held-stream pattern written"));
        let mut echoed = vec![0_u8; pattern.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .unwrap_or_else(|_| panic!("{who} held-stream pattern echoed"));
        assert_eq!(
            &echoed[..],
            pattern,
            "{who} held stream echoes byte-for-byte"
        );
    };
    tokio::select! {
        result = &mut *server => {
            panic!("{who}: server role ended during the held-stream echo: {result:?}")
        }
        result = &mut *client => {
            panic!("{who}: client role ended during the held-stream echo: {result:?}")
        }
        _ = io => {}
    }
}

/// A deliberately dead relay destination: a port claimed from the fixture
/// reservation pool (reserved-then-dropped by [`reserve_tcp_port`]) formatted
/// as a loopback address. Nothing listens there by dial time, so the dial
/// fails truthfully.
pub(super) fn dead_relay_address() -> SocketAddr {
    format!("127.0.0.1:{}", reserve_tcp_port())
        .parse()
        .expect("dead relay address parses")
}
