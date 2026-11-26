// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! The read side of the relay protocol (leaf PKARR-4) against a plain-HTTP loopback relay and the
//! loopback DHT peer of the runtime tests.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh_base::{EndpointId, TransportAddr};
use n0_mainline::MutableItem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::client::classify_read;
use super::*;
use crate::identity::Identity;
use crate::identity::address_key::AddressKey;
use crate::native_discovery::runtime::clock::{ClockSample, TestClock};
use crate::native_discovery::runtime::owner::{
    LoopbackPeer, RuntimeError, RuntimeOwner, endpoint_key, to_mutable,
};
use crate::native_discovery::runtime::publisher::{PublisherState, SignedSnapshot};

const WALL: i64 = 1_700_000_000_000_000;
const WINDOW: Duration = Duration::from_secs(120);
const TIMING: MirrorTiming = MirrorTiming {
    interval: WINDOW,
    gap: Duration::ZERO,
    request_bound: Duration::from_secs(5),
};
const SHORT: MirrorTiming = MirrorTiming {
    request_bound: Duration::from_millis(400),
    ..TIMING
};

#[derive(Clone)]
enum Serve {
    /// `200` with this body.
    Body(Vec<u8>),
    /// `200` with the body of the n-th request (the last one repeats).
    Bodies(Vec<Vec<u8>>),
    /// `200` with this body after the delay.
    After(Duration, Vec<u8>),
    /// An empty answer with this status.
    Status(u16),
    /// `200` that streams this many bytes and names no length (a hostile relay).
    Endless(usize),
    /// Reads the request, never answers, and counts the connection when the client closes it.
    Hang,
}

/// A plain-HTTP loopback stand-in of a pkarr relay that answers `GET`.
struct FakeGet {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    closed: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeGet {
    async fn start(serve: Serve) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let addr = listener.local_addr().expect("bound address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicUsize::new(0));
        let (seen_in, closed_in) = (Arc::clone(&seen), Arc::clone(&closed));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (serve, seen, closed) = (serve.clone(), seen_in.clone(), closed_in.clone());
                tokio::spawn(answer(stream, serve, seen, closed));
            }
        });
        Self {
            addr,
            seen,
            closed,
            task,
        }
    }

    fn url(&self) -> RelayUrl {
        RelayUrl::parse(&format!("http://{}/", self.addr)).expect("loopback relay address")
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.seen.lock().expect("seen lock").clone()
    }

    fn count(&self) -> usize {
        self.requests().len()
    }
}

impl Drop for FakeGet {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn answer(
    mut stream: TcpStream,
    serve: Serve,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    closed: Arc<AtomicUsize>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    }
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let mut first = head.lines().next().unwrap_or_default().split_whitespace();
    let method = first.next().unwrap_or_default().to_owned();
    let path = first.next().unwrap_or_default().to_owned();
    let ordinal = {
        let mut seen = seen.lock().expect("seen lock");
        seen.push((method, path));
        seen.len() - 1
    };
    let bytes = match serve {
        Serve::Body(body) => response(200, &body),
        Serve::Bodies(bodies) => response(200, &bodies[ordinal.min(bodies.len() - 1)]),
        Serve::After(delay, body) => {
            tokio::time::sleep(delay).await;
            response(200, &body)
        }
        Serve::Status(code) => response(code, &[]),
        Serve::Endless(count) => {
            let mut bytes = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
            bytes.resize(bytes.len() + count, 0xaa);
            bytes
        }
        Serve::Hang => {
            while !matches!(stream.read(&mut chunk).await, Ok(0) | Err(_)) {}
            closed.fetch_add(1, Ordering::SeqCst);
            return;
        }
    };
    let _ = stream.write_all(&bytes).await;
    let _ = stream.shutdown().await;
}

async fn wait_until(mut reached: impl FnMut() -> bool) {
    for _ in 0..300 {
        if reached() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached within 3 s");
}

fn sample(wall_us: i64) -> ClockSample {
    ClockSample {
        wall_us,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    }
}

/// A real signed snapshot of the test identity `seed`, signed at `wall_us`.
fn snapshot(seed: u8, wall_us: i64, seal: Option<AddressKey>) -> (EndpointId, SignedSnapshot) {
    let identity = Identity::from_seed([seed; 32]);
    let key = endpoint_key(&identity).expect("identity key");
    let address = TransportAddr::Ip("127.0.0.1:9001".parse().expect("test address"));
    let (_, packet) = PublisherState::new(key)
        .with_seal(seal)
        .replace(&identity, &[address], sample(wall_us))
        .expect("valid snapshot");
    (key, packet.expect("a packet"))
}

/// What a relay's `GET` returns: the signed packet without its key.
fn body_with(seed: u8, wall_us: i64, seal: Option<AddressKey>) -> (EndpointId, Vec<u8>) {
    let (key, packet) = snapshot(seed, wall_us, seal);
    (key, packet.bytes[KEY_BYTES..].to_vec())
}

fn body(seed: u8, wall_us: i64) -> (EndpointId, Vec<u8>) {
    body_with(seed, wall_us, None)
}

/// A loopback DHT peer that answers every `GET` of `target` with nothing.
async fn reply_empty(peer: &mut LoopbackPeer, target: n0_mainline::Id) {
    loop {
        let (source, transaction) = peer.capture_get(target).await;
        peer.reply_empty_get(source, &transaction).await;
    }
}

fn spec(relays: &[RelayUrl], timing: MirrorTiming) -> MirrorSpec<'_> {
    MirrorSpec { relays, timing }
}

async fn drain(read: &mut RelayRead) -> Vec<Answer> {
    let mut answers = Vec::new();
    while let Some(answer) = read.next().await {
        answers.push(answer);
    }
    answers
}

#[test]
fn answers_are_classified_without_remote_text() {
    assert_eq!(classify_read(404), Fetched::NotFound);
    assert_eq!(classify_read(429), Fetched::RateLimited);
    assert_eq!(classify_read(500), Fetched::ServerError);
    assert_eq!(classify_read(503), Fetched::ServerError);
    assert_eq!(classify_read(302), Fetched::Status(302));
    assert_eq!(classify_read(204), Fetched::Status(204));
    let tokens = [
        (Fetched::Found(vec![1]), "found"),
        (Fetched::NotFound, "not-found"),
        (Fetched::TooLarge, "too-large"),
        (Fetched::RateLimited, "rate-limited"),
        (Fetched::ServerError, "server-error"),
        (Fetched::Status(302), "status-302"),
        (Fetched::Timeout, "timeout"),
        (Fetched::Network, "network"),
    ];
    for (fetched, token) in tokens {
        assert_eq!(fetched.token(), token);
    }
    assert_eq!(
        read_line(1, "found", Duration::from_millis(412)),
        "shaar: pkarr read relay=1 result=found ms=412"
    );
}

#[tokio::test]
async fn a_200_body_comes_back_from_a_get_of_the_key_path() {
    let (key, packet) = body(0x61, WALL);
    let relay = FakeGet::start(Serve::Body(packet.clone())).await;
    let mut reader = RelayReader::start(spec(&[relay.url()], TIMING)).expect("reader");
    let answers = drain(&mut reader.begin(key, Instant::now())).await;
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].index, 0);
    assert_eq!(answers[0].fetched, Fetched::Found(packet));
    assert_eq!(
        relay.requests(),
        vec![("GET".to_owned(), format!("/{}", key.to_z32()))]
    );
}

#[tokio::test]
async fn statuses_and_failures_are_misses_with_their_class() {
    let key = body(0x61, WALL).0;
    let refused = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = RelayUrl::parse(&format!("http://{}/", listener.local_addr().expect("addr")))
            .expect("url");
        drop(listener);
        url
    };
    let cases = [
        (Serve::Status(404), Fetched::NotFound),
        (Serve::Status(429), Fetched::RateLimited),
        (Serve::Status(500), Fetched::ServerError),
        (Serve::Status(302), Fetched::Status(302)),
        (Serve::Hang, Fetched::Timeout),
    ];
    for (serve, expected) in cases {
        let relay = FakeGet::start(serve).await;
        let mut reader = RelayReader::start(spec(&[relay.url()], SHORT)).expect("reader");
        let answers = drain(&mut reader.begin(key, Instant::now())).await;
        assert_eq!(answers[0].fetched, expected);
    }
    let mut reader = RelayReader::start(spec(&[refused], TIMING)).expect("reader");
    let answers = drain(&mut reader.begin(key, Instant::now())).await;
    assert_eq!(answers[0].fetched, Fetched::Network);
}

#[tokio::test]
async fn a_body_past_the_bound_is_too_large_by_its_length_or_while_it_is_read() {
    let key = body(0x61, WALL).0;
    let cases = [
        (Serve::Body(vec![7; MAX_BODY_BYTES + 1]), Fetched::TooLarge),
        (Serve::Endless(100_000), Fetched::TooLarge),
        (
            Serve::Body(vec![7; MAX_BODY_BYTES]),
            Fetched::Found(vec![7; MAX_BODY_BYTES]),
        ),
    ];
    for (serve, expected) in cases {
        let relay = FakeGet::start(serve).await;
        let mut reader = RelayReader::start(spec(&[relay.url()], TIMING)).expect("reader");
        let answers = drain(&mut reader.begin(key, Instant::now())).await;
        assert_eq!(answers[0].fetched, expected);
    }
}

#[tokio::test]
async fn no_relay_means_no_reader_and_the_list_is_bounded() {
    assert!(RelayReader::start(MirrorSpec::NONE).is_none());
    let relay = FakeGet::start(Serve::Status(404)).await;
    let many = vec![relay.url(); MAX_RELAYS + 2];
    let reader = RelayReader::start(spec(&many, TIMING)).expect("reader");
    assert_eq!(reader.relays.len(), MAX_RELAYS);
    assert_eq!(reader.budgets.len(), MAX_RELAYS);
}

#[tokio::test]
async fn a_relay_is_asked_three_times_per_window_and_a_429_silences_it() {
    let key = body(0x61, WALL).0;
    let relay = FakeGet::start(Serve::Status(404)).await;
    let mut reader = RelayReader::start(spec(&[relay.url()], TIMING)).expect("reader");
    let start = Instant::now();
    for _ in 0..3 {
        assert_eq!(drain(&mut reader.begin(key, start)).await.len(), 1);
    }
    assert!(reader.begin(key, start).is_empty(), "the fourth is refused");
    assert!(reader.begin(key, start + WINDOW / 2).is_empty());
    assert_eq!(relay.count(), 3);
    assert_eq!(drain(&mut reader.begin(key, start + WINDOW)).await.len(), 1);
    assert_eq!(relay.count(), 4, "a new window admits again");

    let limited = FakeGet::start(Serve::Status(429)).await;
    let mut reader = RelayReader::start(spec(&[limited.url()], TIMING)).expect("reader");
    assert_eq!(drain(&mut reader.begin(key, start)).await.len(), 1);
    reader.silence(0, start);
    assert!(reader.begin(key, start + WINDOW / 2).is_empty());
    assert_eq!(limited.count(), 1);
    assert_eq!(drain(&mut reader.begin(key, start + WINDOW)).await.len(), 1);
}

#[tokio::test]
async fn dropping_the_read_cancels_the_requests_and_a_live_relay_answers_first() {
    let (key, packet) = body(0x61, WALL);
    let hung = FakeGet::start(Serve::Hang).await;
    let live = FakeGet::start(Serve::Body(packet.clone())).await;
    let mut reader = RelayReader::start(spec(&[hung.url(), live.url()], TIMING)).expect("reader");
    let mut read = reader.begin(key, Instant::now());
    let first = read.next().await.expect("an answer");
    assert_eq!((first.index, first.fetched), (1, Fetched::Found(packet)));
    wait_until(|| hung.count() == 1).await;
    drop(read);
    wait_until(|| hung.closed.load(Ordering::SeqCst) == 1).await;
}

struct Rig {
    peer: LoopbackPeer,
    owner: RuntimeOwner,
}

async fn start_rig(relays: &[RelayUrl], timing: MirrorTiming, seal: Option<AddressKey>) -> Rig {
    let peer = LoopbackPeer::bind().await;
    let SocketAddr::V4(bootstrap) = peer.address else {
        panic!("IPv4 bootstrap");
    };
    let owner = RuntimeOwner::start_controlled_relays(
        Identity::from_seed([0x51; 32]),
        "127.0.0.1:0".parse().expect("loopback"),
        &[bootstrap],
        TestClock::new(WALL),
        seal,
        spec(relays, timing),
    )
    .expect("owner on loopback");
    Rig { peer, owner }
}

fn deadline(millis: u64) -> Instant {
    Instant::now() + Duration::from_millis(millis)
}

fn addresses_of(
    result: &Result<crate::native_discovery::runtime::owner::ResolvedAddresses, RuntimeError>,
) -> Vec<SocketAddr> {
    result.as_ref().expect("a record").addresses().to_vec()
}

#[tokio::test]
async fn a_relay_record_is_delivered_while_the_dht_is_silent() {
    let (key, packet) = body(0x61, WALL);
    let relay = FakeGet::start(Serve::Body(packet)).await;
    let mut rig = start_rig(&[relay.url()], TIMING, None).await;
    let started = std::time::Instant::now();
    let result = rig.owner.resolve_until(key, deadline(10_000)).await;
    assert_eq!(
        addresses_of(&result),
        vec!["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(relay.count(), 1);
    rig.owner.close().await.expect("the owner closes");
}

#[tokio::test]
async fn a_sealed_relay_record_opens_with_the_address_key_and_is_a_miss_without_it() {
    let secret = AddressKey::from_bytes([3; 32]);
    let (key, packet) = body_with(0x61, WALL, Some(secret.clone()));
    let relay = FakeGet::start(Serve::Body(packet)).await;
    let mut keyed = start_rig(&[relay.url()], TIMING, Some(secret)).await;
    let result = keyed.owner.resolve_until(key, deadline(10_000)).await;
    assert_eq!(addresses_of(&result).len(), 1);
    let mut keyless = start_rig(&[relay.url()], TIMING, None).await;
    let result = keyless.owner.resolve_until(key, deadline(1_500)).await;
    assert!(matches!(result, Err(RuntimeError::DeadlineExceeded)));
    assert_eq!(relay.count(), 2);
}

#[tokio::test]
async fn a_body_that_does_not_verify_is_a_miss_and_never_an_error_of_its_own() {
    let (key, good) = body(0x61, WALL);
    let mut flipped = good.clone();
    flipped[3] ^= 0xff;
    let other_signer = body(0x72, WALL).1;
    let bodies = [other_signer, flipped, good[..50].to_vec(), vec![0x5a; 200]];
    assert_eq!(bodies.len(), MAX_RELAYS);
    let mut relays = Vec::new();
    for bad in bodies {
        relays.push(FakeGet::start(Serve::Body(bad)).await);
    }
    let urls: Vec<RelayUrl> = relays.iter().map(FakeGet::url).collect();
    let mut rig = start_rig(&urls, TIMING, None).await;
    let result = rig.owner.resolve_until(key, deadline(1_500)).await;
    assert!(matches!(result, Err(RuntimeError::DeadlineExceeded)));
    assert!(relays.iter().all(|relay| relay.count() == 1));
}

#[tokio::test]
async fn a_stale_record_and_one_older_than_the_winner_are_misses() {
    let (key, stale) = body(0x61, WALL - 600_000_000);
    let old = FakeGet::start(Serve::Body(stale)).await;
    let mut rig_old = start_rig(&[old.url()], TIMING, None).await;
    let result = rig_old.owner.resolve_until(key, deadline(1_500)).await;
    assert!(matches!(result, Err(RuntimeError::DeadlineExceeded)));

    let newer = body(0x61, WALL).1;
    let older = body(0x61, WALL - 5_000_000).1;
    let relay = FakeGet::start(Serve::Bodies(vec![newer, older])).await;
    let mut rig = start_rig(&[relay.url()], TIMING, None).await;
    assert!(rig.owner.resolve_until(key, deadline(10_000)).await.is_ok());
    let replay = rig.owner.resolve_fresh_until(key, deadline(1_500)).await;
    assert!(matches!(replay, Err(RuntimeError::DeadlineExceeded)));
    assert_eq!(relay.count(), 2);
}

#[tokio::test]
async fn the_dht_wins_when_it_answers_first_and_the_slow_relay_is_cancelled() {
    let (key, packet) = snapshot(0x62, WALL, None);
    let item: MutableItem = to_mutable(&packet).expect("typed item");
    let hung = FakeGet::start(Serve::Hang).await;
    let mut rig = start_rig(&[hung.url()], TIMING, None).await;
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::select! {
            result = rig.owner.resolve_until(key, deadline(10_000)) => result,
            _ = rig.peer.serve_record(&item) => unreachable!("serves until dropped"),
        }
    })
    .await
    .expect("bounded lookup");
    assert_eq!(addresses_of(&result).len(), 1);
    wait_until(|| hung.closed.load(Ordering::SeqCst) == 1).await;
}

#[tokio::test]
async fn a_dht_miss_waits_for_the_relay_but_never_past_the_deadline() {
    let (key, packet) = body(0x61, WALL);
    let target = MutableItem::target_from_key(key.as_bytes(), None);

    let slow = FakeGet::start(Serve::After(Duration::from_millis(300), packet)).await;
    let mut rig = start_rig(&[slow.url()], TIMING, None).await;
    let result = tokio::select! {
        result = rig.owner.resolve_until(key, deadline(10_000)) => result,
        _ = reply_empty(&mut rig.peer, target) => unreachable!("the driver never ends"),
    };
    assert_eq!(
        addresses_of(&result).len(),
        1,
        "the relay answered after the DHT's miss"
    );

    let missing = FakeGet::start(Serve::Status(404)).await;
    let mut rig = start_rig(&[missing.url()], TIMING, None).await;
    let result = tokio::select! {
        result = rig.owner.resolve_until(key, deadline(10_000)) => result,
        _ = reply_empty(&mut rig.peer, target) => unreachable!("the driver never ends"),
    };
    assert!(
        matches!(result, Err(RuntimeError::Resolve(_))),
        "the DHT's own miss: {result:?}"
    );

    let hung = FakeGet::start(Serve::Hang).await;
    let mut rig = start_rig(&[hung.url()], TIMING, None).await;
    let started = std::time::Instant::now();
    let result = tokio::select! {
        result = rig.owner.resolve_until(key, deadline(1_200)) => result,
        _ = reply_empty(&mut rig.peer, target) => unreachable!("the driver never ends"),
    };
    assert!(matches!(result, Err(RuntimeError::Resolve(_))));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the 5 s request bound is not awaited"
    );
}

#[tokio::test]
async fn the_budget_holds_across_lookups_of_one_owner() {
    let key = body(0x61, WALL).0;
    let relay = FakeGet::start(Serve::Status(404)).await;
    let mut rig = start_rig(&[relay.url()], TIMING, None).await;
    for _ in 0..4 {
        let result = rig.owner.resolve_until(key, deadline(500)).await;
        assert!(result.is_err());
    }
    assert_eq!(relay.count(), 3, "the fourth lookup sends no request");
}

#[tokio::test]
async fn a_dropped_lookup_ends_its_request_and_the_owner_closes() {
    let key = body(0x61, WALL).0;
    let hung = FakeGet::start(Serve::Hang).await;
    let mut rig = start_rig(&[hung.url()], TIMING, None).await;
    let lookup = rig.owner.resolve_until(key, deadline(10_000));
    let _ = tokio::time::timeout(Duration::from_millis(300), lookup).await;
    wait_until(|| hung.closed.load(Ordering::SeqCst) == 1).await;
    assert_eq!(hung.count(), 1);
    rig.owner.close().await.expect("the owner closes");
}
