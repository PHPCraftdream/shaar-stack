// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh_base::{EndpointId, TransportAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::client::{Class, RelayClient, RelayUrlError, classify, http_client};
use super::*;
use crate::identity::Identity;
use crate::native_discovery::codec::decode_record;
use crate::native_discovery::runtime::clock::ClockSample;
use crate::native_discovery::runtime::owner::{LoopbackPeer, RuntimeOwner, endpoint_key};
use crate::native_discovery::runtime::publisher::{PublicationStatus, PublisherState};

/// No gap: every replacement goes at once.
const GENEROUS: MirrorTiming = MirrorTiming {
    interval: Duration::from_secs(3),
    gap: Duration::ZERO,
    request_bound: Duration::from_secs(5),
};

/// The same with a gap of 600 ms between two requests to one relay.
const GAPPED: MirrorTiming = MirrorTiming {
    gap: Duration::from_millis(600),
    ..GENEROUS
};

#[derive(Clone, Copy)]
enum Reply {
    /// An empty answer with this status.
    Status(u16),
    /// `204` with the stored-nodes header set to this text.
    Header(&'static str),
    /// `204` after this delay.
    Delay(Duration),
    /// Reads the request, never answers, and counts the connection when the client closes it.
    Hang,
}

struct Seen {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// A plain-HTTP loopback stand-in of a pkarr relay.
struct FakeRelay {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    closed: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl FakeRelay {
    async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let addr = listener.local_addr().expect("bound address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicUsize::new(0));
        let (seen_in, closed_in) = (Arc::clone(&seen), Arc::clone(&closed));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(
                    stream,
                    reply,
                    Arc::clone(&seen_in),
                    Arc::clone(&closed_in),
                ));
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

    fn count(&self) -> usize {
        self.seen.lock().expect("seen lock").len()
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        let seen = self.seen.lock().expect("seen lock");
        seen.iter().map(|request| request.body.clone()).collect()
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    mut stream: TcpStream,
    reply: Reply,
    seen: Arc<Mutex<Vec<Seen>>>,
    closed: Arc<AtomicUsize>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 2048];
    let head_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut first = head.lines().next().unwrap_or_default().split_whitespace();
    let method = first.next().unwrap_or_default().to_owned();
    let path = first.next().unwrap_or_default().to_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buffer.len() < head_end + length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(count) => buffer.extend_from_slice(&chunk[..count]),
        }
    }
    seen.lock().expect("seen lock").push(Seen {
        method,
        path,
        body: buffer[head_end..head_end + length].to_vec(),
    });
    let response = match reply {
        Reply::Status(code) => {
            format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        }
        Reply::Header(value) => format!(
            "HTTP/1.1 204 No Content\r\nPkarr-Dht-Stored-Nodes: {value}\r\nConnection: close\r\n\r\n"
        ),
        Reply::Delay(delay) => {
            tokio::time::sleep(delay).await;
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_owned()
        }
        Reply::Hang => {
            loop {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            closed.fetch_add(1, Ordering::SeqCst);
            return;
        }
    };
    let _ = stream.write_all(response.as_bytes()).await;
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

/// A real signed packet (with its key) of the test identity `seed`.
fn signed_packet(seed: u8) -> (EndpointId, Vec<u8>) {
    let identity = Identity::from_seed([seed; 32]);
    let key = endpoint_key(&identity).expect("identity key");
    let address = TransportAddr::Ip("127.0.0.1:9001".parse().expect("test address"));
    let (_, packet) = PublisherState::new(key)
        .replace(&identity, &[address], sample(1_700_000_000_000_000))
        .expect("valid snapshot");
    (key, packet.expect("a packet").bytes)
}

fn key_only(seed: u8) -> EndpointId {
    endpoint_key(&Identity::from_seed([seed; 32])).expect("identity key")
}

fn spec(relays: &[RelayUrl], timing: MirrorTiming) -> MirrorSpec<'_> {
    MirrorSpec { relays, timing }
}

#[test]
fn answers_are_classified_without_remote_text() {
    assert_eq!(classify(204, Some(8)), Class::Stored(Some(8)));
    assert_eq!(classify(204, None), Class::Stored(None));
    assert_eq!(classify(400, None), Class::BadRequest);
    assert_eq!(classify(409, None), Class::Stale);
    assert_eq!(classify(413, None), Class::TooLarge);
    assert_eq!(classify(429, None), Class::RateLimited);
    assert_eq!(classify(500, None), Class::ServerError);
    assert_eq!(classify(503, None), Class::ServerError);
    assert_eq!(classify(404, None), Class::Status(404));
    assert_eq!(classify(302, None), Class::Status(302));
    assert_eq!(Class::Stale.token(), "stale");
    assert_eq!(Class::Status(404).token(), "status-404");
    assert_eq!(Class::Stored(Some(3)).stored_nodes(), Some(3));
    assert_eq!(Class::Timeout.stored_nodes(), None);
}

#[test]
fn trace_line_names_the_class_and_the_count_and_nothing_else() {
    let stored = trace_line(1, Class::Stored(Some(8)), Duration::from_millis(412));
    assert_eq!(
        stored,
        "shaar-server: pkarr relay=1 result=stored stored=8 elapsed_ms=412"
    );
    let unknown = trace_line(0, Class::Stored(None), Duration::from_millis(5));
    assert_eq!(
        unknown,
        "shaar-server: pkarr relay=0 result=stored stored=? elapsed_ms=5"
    );
    let failed = trace_line(2, Class::Timeout, Duration::from_secs(10));
    assert_eq!(
        failed,
        "shaar-server: pkarr relay=2 result=timeout stored=? elapsed_ms=10000"
    );
}

#[test]
fn relay_addresses_are_validated() {
    for good in [
        "https://pkarr.pubky.app",
        "https://relay.pkarr.org/",
        "https://pkarr.pubky.org:8443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8080/",
    ] {
        assert!(RelayUrl::parse(good).is_ok(), "{good}");
    }
    for (bad, error) in [
        ("not a url", RelayUrlError::Syntax),
        ("", RelayUrlError::Syntax),
        ("http://example.com", RelayUrlError::Scheme),
        ("http://10.0.0.1:80", RelayUrlError::Scheme),
        ("http://[::1]:80", RelayUrlError::Scheme),
        ("ftp://example.com", RelayUrlError::Scheme),
        ("https://1.2.3.4", RelayUrlError::Host),
        ("https://[::1]/", RelayUrlError::Host),
        ("https://user:pass@example.com/", RelayUrlError::Credentials),
        ("https://user@example.com/", RelayUrlError::Credentials),
        ("https://example.com/path", RelayUrlError::Extra),
        ("https://example.com/?q=1", RelayUrlError::Extra),
        ("https://example.com/#f", RelayUrlError::Extra),
    ] {
        assert_eq!(RelayUrl::parse(bad), Err(error), "{bad}");
    }
}

#[tokio::test]
async fn the_body_is_the_signed_packet_without_its_key_and_it_verifies() {
    let relay = FakeRelay::start(Reply::Header("8")).await;
    let (key, packet) = signed_packet(0x61);
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key, spec(&relays, GENEROUS)).expect("one relay");
    mirror.offer(&packet, true);
    wait_until(|| relay.count() == 1).await;
    {
        let seen = relay.seen.lock().expect("seen lock");
        assert_eq!(seen[0].method, "PUT");
        assert_eq!(seen[0].path, format!("/{}", key.to_z32()));
        assert_eq!(seen[0].body, packet[KEY_BYTES..]);
        assert!(seen[0].body.len() <= 1072);
    }
    let mut full = key.as_bytes().to_vec();
    full.extend_from_slice(&relay.bodies()[0]);
    decode_record(&full, key).expect("the relay's body verifies once the key is re-attached");
}

#[tokio::test]
async fn every_class_of_answer_reaches_the_client() {
    let key = key_only(0x62);
    let cases = [
        (Reply::Header("8"), Class::Stored(Some(8))),
        (Reply::Status(204), Class::Stored(None)),
        (Reply::Header("many"), Class::Stored(None)),
        (Reply::Status(400), Class::BadRequest),
        (Reply::Status(409), Class::Stale),
        (Reply::Status(413), Class::TooLarge),
        (Reply::Status(429), Class::RateLimited),
        (Reply::Status(500), Class::ServerError),
        (Reply::Status(302), Class::Status(302)),
        (Reply::Status(404), Class::Status(404)),
    ];
    for (reply, expected) in cases {
        let relay = FakeRelay::start(reply).await;
        let http = http_client(GENEROUS.request_bound).expect("client");
        let client = RelayClient::new(http, &relay.url(), key);
        assert_eq!(client.put(&[7; 40]).await, expected);
        assert_eq!(relay.count(), 1, "a redirect or an error is not retried");
    }
}

#[tokio::test]
async fn a_relay_that_never_answers_ends_by_the_bound() {
    let relay = FakeRelay::start(Reply::Hang).await;
    let http = http_client(Duration::from_millis(300)).expect("client");
    let client = RelayClient::new(http, &relay.url(), key_only(0x63));
    let started = std::time::Instant::now();
    assert_eq!(client.put(&[7; 40]).await, Class::Timeout);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_refused_connection_is_a_network_failure() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind");
    let url = RelayUrl::parse(&format!("http://{}/", listener.local_addr().expect("addr")))
        .expect("address");
    drop(listener);
    let http = http_client(GENEROUS.request_bound).expect("client");
    let client = RelayClient::new(http, &url, key_only(0x64));
    assert_eq!(client.put(&[7; 40]).await, Class::Network);
}

#[tokio::test]
async fn a_dead_relay_does_not_delay_the_others_and_the_hand_over_never_blocks() {
    let hung = FakeRelay::start(Reply::Hang).await;
    let live = FakeRelay::start(Reply::Header("4")).await;
    let relays = [hung.url(), live.url()];
    let mirror = RelayMirror::start(key_only(0x65), spec(&relays, GENEROUS)).expect("relays");
    let started = std::time::Instant::now();
    for index in 0..1000_u16 {
        let mut packet = vec![0_u8; 40];
        packet[0] = u8::try_from(index % 251).expect("small");
        mirror.offer(&packet, true);
    }
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "a thousand hand-overs while a relay hangs"
    );
    wait_until(|| live.count() >= 1).await;
    assert_eq!(hung.count(), 1, "one request in flight per relay");
}

#[tokio::test]
async fn only_the_latest_packet_waits_behind_a_request_in_flight() {
    let relay = FakeRelay::start(Reply::Delay(Duration::from_millis(300))).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x66), spec(&relays, GENEROUS)).expect("relay");
    mirror.offer(&[1; 40], true);
    wait_until(|| relay.count() == 1).await;
    mirror.offer(&[2; 40], true);
    mirror.offer(&[3; 40], true);
    wait_until(|| relay.count() == 2).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        relay.bodies(),
        vec![vec![1; 8], vec![3; 8]],
        "the packet in between was replaced, not queued"
    );
}

#[tokio::test]
async fn a_refresh_waits_for_the_interval_and_a_replacement_does_not() {
    let relay = FakeRelay::start(Reply::Header("8")).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x67), spec(&relays, GENEROUS)).expect("relay");
    mirror.offer(&[1; 40], true);
    wait_until(|| relay.count() == 1).await;
    mirror.offer(&[2; 40], false);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay.count(), 1, "a refresh inside the interval is skipped");
    mirror.offer(&[3; 40], true);
    wait_until(|| relay.count() == 2).await;
    assert_eq!(relay.bodies()[1], vec![3; 8]);
}

/// Regression of the PKARR-3 run: a failing DHT publication is retried as a new replacement each
/// time, and every one of them went to every relay at once (15 requests in 58 s for 3 relays).
#[tokio::test]
async fn a_burst_of_replacements_costs_one_request_per_gap_and_the_latest_wins() {
    let relay = FakeRelay::start(Reply::Header("8")).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x6d), spec(&relays, GAPPED)).expect("relay");
    mirror.offer(&[1; 40], true);
    wait_until(|| relay.count() == 1).await;
    let first = std::time::Instant::now();
    for packet in [[2_u8; 40], [3; 40], [4; 40]] {
        mirror.offer(&packet, true);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay.count(), 1, "the burst waits out the gap");
    wait_until(|| relay.count() == 2).await;
    assert!(
        first.elapsed() >= Duration::from_millis(450),
        "the second request came {:?} after the first, inside the gap",
        first.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        relay.bodies(),
        vec![vec![1; 8], vec![4; 8]],
        "one request for the whole burst, carrying the latest packet"
    );
}

/// A refresh that arrives while a replacement waits for the gap is the newer packet of the same
/// content: it is the one sent, and nothing is lost or sent twice.
#[tokio::test]
async fn a_refresh_during_the_wait_is_sent_in_place_of_the_replacement() {
    let relay = FakeRelay::start(Reply::Header("8")).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x6e), spec(&relays, GAPPED)).expect("relay");
    mirror.offer(&[1; 40], true);
    wait_until(|| relay.count() == 1).await;
    mirror.offer(&[2; 40], true);
    tokio::time::sleep(Duration::from_millis(100)).await;
    mirror.offer(&[3; 40], false);
    wait_until(|| relay.count() == 2).await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(relay.bodies(), vec![vec![1; 8], vec![3; 8]]);
}

/// The budget of the live run (item 24 of the v1 focus): 106 s, three relays, at most 9 requests.
#[test]
fn the_product_gap_keeps_a_live_run_within_three_requests_per_relay() {
    let run = 106;
    let per_relay = run / MirrorTiming::PRODUCT.gap.as_secs() + 1;
    assert!(per_relay * 3 <= 9, "{per_relay} requests per relay");
    assert!(MirrorTiming::PRODUCT.gap <= MirrorTiming::PRODUCT.interval);
}

#[tokio::test]
async fn a_rate_limited_relay_is_left_alone_until_the_interval_ends() {
    let relay = FakeRelay::start(Reply::Status(429)).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x68), spec(&relays, GENEROUS)).expect("relay");
    mirror.offer(&[1; 40], true);
    wait_until(|| relay.count() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    mirror.offer(&[2; 40], true);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay.count(), 1, "not even a replacement while paused");
}

#[tokio::test]
async fn closing_the_mirror_drops_the_request_in_flight() {
    let relay = FakeRelay::start(Reply::Hang).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x69), spec(&relays, GENEROUS)).expect("relay");
    mirror.offer(&[1; 40], true);
    wait_until(|| relay.count() == 1).await;
    drop(mirror);
    wait_until(|| relay.closed.load(Ordering::SeqCst) == 1).await;
}

#[tokio::test]
async fn no_relay_means_no_task_and_the_list_is_bounded() {
    assert!(RelayMirror::start(key_only(0x6a), MirrorSpec::NONE).is_none());
    let relay = FakeRelay::start(Reply::Status(204)).await;
    let many = vec![relay.url(); MAX_RELAYS + 2];
    let mirror = RelayMirror::start(key_only(0x6a), spec(&many, GENEROUS)).expect("relays");
    assert_eq!(mirror.tasks.len(), MAX_RELAYS);
}

#[tokio::test]
async fn sizes_outside_a_signed_packet_are_ignored() {
    let relay = FakeRelay::start(Reply::Status(204)).await;
    let relays = [relay.url()];
    let mirror = RelayMirror::start(key_only(0x6b), spec(&relays, GENEROUS)).expect("relay");
    mirror.offer(&[1; KEY_BYTES], true);
    mirror.offer(&[1; MAX_PACKET_BYTES + 1], true);
    mirror.offer(&[], true);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relay.count(), 0);
    mirror.offer(&[1; MAX_PACKET_BYTES], true);
    wait_until(|| relay.count() == 1).await;
}

/// The publication goes to the DHT exactly as without a mirror while every relay hangs, and the
/// owner closes without waiting for the request in flight.
#[tokio::test]
async fn a_hanging_relay_changes_nothing_in_the_dht_publication() {
    let hung = FakeRelay::start(Reply::Hang).await;
    let mut peer = LoopbackPeer::bind().await;
    let bootstrap = match peer.address {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => panic!("peer must bind IPv4 loopback"),
    };
    let relays = [hung.url()];
    let mut owner = RuntimeOwner::start_mirrored(
        Identity::from_seed([0x6c; 32]),
        "127.0.0.1:0".parse().expect("loopback bind"),
        &[bootstrap],
        None,
        &relays,
    )
    .expect("owned DHT binds on loopback");
    let address = TransportAddr::Ip("127.0.0.1:9001".parse().expect("test address"));
    let mut replacement = Box::pin(owner.replace(vec![address]));
    let (source, transaction, _captured) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut replacement => panic!("the PUT ended before it was held: {result:?}"),
    };
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Pending { .. }
    ));
    wait_until(|| hung.count() == 1).await;
    peer.acknowledge(source, &transaction).await;
    replacement.await.expect("the DHT acknowledged the PUT");
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Published { .. }
    ));
    let started = std::time::Instant::now();
    owner.close().await.expect("the owner closes");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the request in flight does not hold the close"
    );
    wait_until(|| hung.closed.load(Ordering::SeqCst) == 1).await;
}
