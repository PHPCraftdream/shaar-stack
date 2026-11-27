// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

//! Contract of the adaptive departure pacing of the owned requests (leaf PACE-1).

use std::collections::VecDeque;
use std::fmt::Debug;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use tokio::time::Instant;

use super::super::KrpcSocket;
use super::pacer::{Pacer, WINDOW};
use crate::common::{
    ErrorSpecific, Id, Message, MessageType, RequestSpecific, RequestTypeSpecific,
};
use crate::resource::OperationId;

const SPACING_25: Duration = Duration::from_millis(40);

/// Feeds one window with `answered` answers; the result of the last observation.
fn window(pacer: &mut Pacer, answered: u32) -> bool {
    let mut changed = false;
    for index in 0..WINDOW {
        changed = pacer.observe(index < answered);
    }
    changed
}

fn engaged() -> Pacer {
    let mut pacer = Pacer::default();
    assert!(window(&mut pacer, 0));
    assert_eq!(pacer.rate(), Some(25));
    pacer
}

#[test]
fn a_device_that_gets_its_answers_is_never_paced() {
    let mut pacer = Pacer::default();
    let now = Instant::now();
    for _ in 0..50 {
        assert!(!window(&mut pacer, 7));
        assert_eq!(pacer.rate(), None);
        assert_eq!(pacer.wait_until(now), None);
        pacer.departed(now);
    }
    assert_eq!(pacer.wait_until(now), None);
}

#[test]
fn the_engage_boundary_is_an_answered_share_of_twenty_percent() {
    let mut pacer = Pacer::default();
    assert!(!window(&mut pacer, 4));
    assert_eq!(pacer.rate(), None);
    assert!(window(&mut pacer, 3));
    assert_eq!(pacer.rate(), Some(25));
}

#[test]
fn a_window_is_judged_only_when_it_is_full() {
    let mut pacer = Pacer::default();
    for _ in 0..WINDOW - 1 {
        assert!(!pacer.observe(false));
    }
    assert_eq!(pacer.rate(), None);
    assert!(pacer.observe(false));
    assert_eq!(pacer.rate(), Some(25));
}

#[test]
fn a_paced_schedule_allows_a_burst_and_then_spaces_departures() {
    let mut pacer = engaged();
    let start = Instant::now();
    for _ in 0..4 {
        assert_eq!(pacer.wait_until(start), None);
        pacer.departed(start);
    }
    assert_eq!(pacer.wait_until(start), Some(start + SPACING_25));
    assert_eq!(pacer.wait_until(start + SPACING_25), None);
}

#[test]
fn no_more_than_the_rate_plus_the_burst_leaves_in_any_second() {
    let mut pacer = engaged();
    let start = Instant::now();
    let mut now = start;
    let mut sent = Vec::new();
    loop {
        if let Some(release) = pacer.wait_until(now) {
            now = release;
        }
        if now >= start + Duration::from_secs(3) {
            break;
        }
        pacer.departed(now);
        sent.push(now);
    }
    for (index, first) in sent.iter().enumerate() {
        let in_second = sent[index..]
            .iter()
            .take_while(|at| **at < *first + Duration::from_secs(1))
            .count();
        assert!(in_second <= 25 + 4, "{in_second} departures in one second");
    }
    let in_first_second = sent
        .iter()
        .take_while(|at| **at < start + Duration::from_secs(1))
        .count();
    assert!(
        in_first_second >= 25,
        "{in_first_second} departures in one second"
    );
}

#[test]
fn each_collapse_halves_the_rate_down_to_the_floor() {
    let mut pacer = engaged();
    assert!(window(&mut pacer, 0));
    assert_eq!(pacer.rate(), Some(12));
    assert!(window(&mut pacer, 0));
    assert_eq!(pacer.rate(), Some(10));
    assert!(!window(&mut pacer, 0));
    assert_eq!(pacer.rate(), Some(10));
}

#[test]
fn good_windows_climb_back_to_unpaced() {
    let mut pacer = engaged();
    assert!(window(&mut pacer, 0));
    assert!(window(&mut pacer, 0));
    assert_eq!(pacer.rate(), Some(10));
    assert!(!window(&mut pacer, 9));
    assert_eq!(pacer.rate(), Some(10));
    for expected in [15, 20, 25, 30, 35, 40, 45] {
        assert!(window(&mut pacer, 10));
        assert_eq!(pacer.rate(), Some(expected));
    }
    assert!(window(&mut pacer, 16));
    assert_eq!(pacer.rate(), None);
    let now = Instant::now();
    for _ in 0..40 {
        pacer.departed(now);
        assert_eq!(pacer.wait_until(now), None);
    }
}

#[test]
fn a_middling_window_keeps_the_rate() {
    let mut pacer = engaged();
    for answered in [4, 8, 9] {
        assert!(!window(&mut pacer, answered));
        assert_eq!(pacer.rate(), Some(25));
    }
}

/// A responder that drops every datagram that arrives while three or more arrivals are within
/// the last 100 ms, the dropped ones included (a per-source flow limiter).
struct Quota {
    arrivals: VecDeque<Instant>,
}

impl Quota {
    fn admit(&mut self, at: Instant) -> bool {
        while self
            .arrivals
            .front()
            .is_some_and(|first| at.duration_since(*first) >= Duration::from_millis(100))
        {
            self.arrivals.pop_front();
        }
        let answered = self.arrivals.len() < 3;
        self.arrivals.push_back(at);
        answered
    }
}

/// Answers of a walk of `rounds` rounds of 16 requests each, one round every 500 ms.
fn walk(adaptive: bool, rounds: u32) -> u32 {
    let mut pacer = Pacer::default();
    let mut quota = Quota {
        arrivals: VecDeque::new(),
    };
    let mut now = Instant::now();
    let mut total = 0;
    for _ in 0..rounds {
        let mut outcomes = Vec::new();
        for _ in 0..16 {
            if let Some(release) = pacer.wait_until(now) {
                now = release;
            }
            pacer.departed(now);
            outcomes.push(quota.admit(now));
        }
        now += Duration::from_millis(500);
        for answered in outcomes {
            total += u32::from(answered);
            if adaptive {
                pacer.observe(answered);
            }
        }
    }
    total
}

#[test]
fn against_a_flow_limiter_the_adaptive_schedule_gets_at_least_twice_the_answers() {
    let unpaced = walk(false, 40);
    let adaptive = walk(true, 40);
    assert_eq!(unpaced, 3 * 40);
    assert!(
        adaptive >= 2 * unpaced,
        "{adaptive} answers against {unpaced}"
    );
}

fn capture() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback capture");
    let address = match socket.local_addr().expect("capture address") {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!("IPv4 socket"),
    };
    socket.set_nonblocking(true).expect("nonblocking capture");
    (socket, address)
}

fn drain(peer: &UdpSocket) -> Vec<Message> {
    let mut messages = Vec::new();
    let mut bytes = [0_u8; 2048];
    while let Ok((length, _)) = peer.recv_from(&mut bytes) {
        messages.push(Message::from_bytes(&bytes[..length]).expect("datagram decodes"));
    }
    messages
}

fn ping() -> RequestSpecific {
    RequestSpecific {
        requester_id: Id::from([1_u8; 20]),
        request_type: RequestTypeSpecific::Ping,
    }
}

/// A socket with its first send behind it. On a paused clock the first `writable()` of a fresh
/// socket parks the runtime, which then jumps the clock to the next timer; a reply registers no
/// timer, so the jump cannot land inside the scenario that follows.
async fn paced_socket(seconds: u64) -> (KrpcSocket, OperationId) {
    let mut socket = KrpcSocket::client().expect("KRPC socket");
    socket.enable_owned_resources();
    let (warm_peer, warm_to) = capture();
    let warm = ErrorSpecific {
        code: 201,
        description: "warm-up".to_owned(),
    };
    socket.error_owned(warm_to, 1, warm).expect("warm-up reply");
    socket.flush_owned().await;
    assert_eq!(drain(&warm_peer).len(), 1);
    let operation = socket.allocate_operation().expect("operation");
    socket
        .register_owned_deadline(operation, Instant::now() + Duration::from_secs(seconds))
        .expect("deadline");
    socket.collapse_owned_pacing_for_test();
    assert_eq!(socket.owned_pacing_rate_for_test(), Some(25));
    (socket, operation)
}

fn queue(
    socket: &mut KrpcSocket,
    operation: OperationId,
    to: SocketAddrV4,
    count: usize,
) -> Vec<u32> {
    (0..count)
        .map(|_| {
            socket
                .request_owned(to, ping(), operation)
                .expect("request")
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn a_paced_queue_releases_a_burst_and_then_waits_for_its_turn() {
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    let tids = queue(&mut socket, operation, destination, 6);
    socket.flush_owned().await;
    let first: Vec<u32> = drain(&peer)
        .iter()
        .map(|message| message.transaction_id)
        .collect();
    assert_eq!(first.as_slice(), &tids[..4]);
    let held_until = socket
        .owned_next_departure()
        .expect("the fifth request is held");
    let wait = held_until - Instant::now();
    assert!(wait > Duration::ZERO && wait <= SPACING_25, "{wait:?}");
    socket.flush_owned().await;
    assert!(drain(&peer).is_empty());
    tokio::time::advance(SPACING_25).await;
    socket.flush_owned().await;
    let second: Vec<u32> = drain(&peer)
        .iter()
        .map(|message| message.transaction_id)
        .collect();
    assert_eq!(second.as_slice(), &tids[4..5]);
    tokio::time::advance(SPACING_25).await;
    socket.flush_owned().await;
    let third: Vec<u32> = drain(&peer)
        .iter()
        .map(|message| message.transaction_id)
        .collect();
    assert_eq!(third.as_slice(), &tids[5..]);
    assert_eq!(socket.owned_next_departure(), None);
    assert_eq!(socket.owned_failure(), None);
}

#[tokio::test(start_paused = true)]
async fn a_queued_request_does_not_expire_and_its_timeout_runs_from_the_departure() {
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    let tids = queue(&mut socket, operation, destination, 6);
    socket.flush_owned().await;
    assert_eq!(drain(&peer).len(), 4);
    socket.expire_owned_requests(Duration::ZERO);
    for tid in &tids[..4] {
        assert!(!socket.owned_inflight(*tid), "a sent request expires");
    }
    for tid in &tids[4..] {
        assert!(
            socket.owned_inflight(*tid),
            "a queued request stays in flight"
        );
    }
    // The timestamps of the requests are wall-clock: let real time pass while two requests wait.
    std::thread::sleep(Duration::from_millis(200));
    tokio::time::advance(Duration::from_secs(1)).await;
    socket.flush_owned().await;
    assert_eq!(drain(&peer).len(), 2);
    socket.expire_owned_requests(Duration::from_millis(150));
    for tid in &tids[4..] {
        assert!(
            socket.owned_inflight(*tid),
            "the timeout runs from the departure"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_reply_leaves_at_once_behind_a_held_request() {
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    let tids = queue(&mut socket, operation, destination, 6);
    socket.flush_owned().await;
    assert_eq!(drain(&peer).len(), 4);
    let reply = ErrorSpecific {
        code: 201,
        description: "fixture".to_owned(),
    };
    socket
        .error_owned(destination, 4_000, reply)
        .expect("reply");
    socket.flush_owned().await;
    let sent = drain(&peer);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].transaction_id, 4_000);
    assert!(matches!(sent[0].message_type, MessageType::Error(_)));
    assert!(socket.owned_inflight(tids[4]) && socket.owned_inflight(tids[5]));
    assert!(socket.owned_next_departure().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_held_request_past_its_operation_deadline_is_dropped_when_it_falls_due() {
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    socket
        .register_owned_deadline(operation, Instant::now() + Duration::from_millis(100))
        .expect("tightened deadline");
    let tids = queue(&mut socket, operation, destination, 6);
    socket.flush_owned().await;
    assert_eq!(drain(&peer).len(), 4);
    tokio::time::advance(Duration::from_millis(200)).await;
    socket.flush_owned().await;
    assert!(drain(&peer).is_empty());
    assert!(!socket.owned_inflight(tids[4]) && !socket.owned_inflight(tids[5]));
    assert_eq!(socket.owned_next_departure(), None);
    assert_eq!(socket.owned_failure(), None);
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_operation_drops_the_held_requests() {
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    queue(&mut socket, operation, destination, 6);
    socket.flush_owned().await;
    assert_eq!(drain(&peer).len(), 4);
    socket.cancel_owned_operation(operation);
    assert_eq!(socket.owned_next_departure(), None);
    tokio::time::advance(Duration::from_secs(1)).await;
    socket.flush_owned().await;
    assert!(drain(&peer).is_empty());
    assert_eq!(socket.owned_test_state(), Some((0, 0, 0, 0)));
}

#[tokio::test(start_paused = true)]
async fn answers_that_arrive_speed_a_paced_schedule_up() {
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(120).await;
    for _ in 0..WINDOW {
        tokio::time::advance(SPACING_25).await;
        let tid = socket
            .request_owned(destination, ping(), operation)
            .expect("request");
        socket.flush_owned().await;
        assert_eq!(drain(&peer).len(), 1);
        assert!(socket.accept_owned_response(tid, destination));
    }
    assert_eq!(socket.owned_pacing_rate_for_test(), Some(30));
}

// The outcome lines (`sent=<n> kind=<k>`, leaf PACE-3a) are read from the log the socket keeps
// next to the trace, not captured from `tracing`: a thread-local subscriber loses its events when
// a parallel case without one is the first to hit the callsite (the interest cache is global).

/// Failure-only diagnostics of a case: the notes it took are printed as one tagged line when the
/// case panics and never otherwise (a green run prints nothing, which the CI output check also
/// enforces). Each note carries the real and the paused clock, so a stall shows as a gap.
struct Notes {
    real: std::time::Instant,
    paused: Instant,
    lines: Vec<String>,
}

impl Notes {
    fn new() -> Self {
        Self {
            real: std::time::Instant::now(),
            paused: Instant::now(),
            lines: Vec::new(),
        }
    }

    fn note(&mut self, label: &str, value: &dyn Debug) {
        self.lines.push(format!(
            "{{\"real_ms\":{},\"virtual_ms\":{},\"label\":{label:?},\"value\":{:?}}}",
            self.real.elapsed().as_millis(),
            self.paused.elapsed().as_millis(),
            format!("{value:?}")
        ));
    }

    fn render(&self, test: &str) -> String {
        format!(
            "[failure diagnostics] {{\"test\":{test:?},\"notes\":[{}]}}",
            self.lines.join(",")
        )
    }
}

impl Drop for Notes {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let thread = std::thread::current();
            eprintln!("{}", self.render(thread.name().unwrap_or("?")));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn the_failure_report_lists_the_notes_in_order_and_names_the_case() {
    let mut notes = Notes::new();
    notes.note("first", &Some(3_usize));
    notes.note("second", &"two words");
    let report = notes.render("case");
    assert!(report.starts_with("[failure diagnostics] {\"test\":\"case\",\"notes\":[{"));
    assert!(report.contains("\"label\":\"first\",\"value\":\"Some(3)\""));
    assert!(report.find("\"first\"").unwrap() < report.find("\"second\"").unwrap());
    assert!(report.contains("\"real_ms\":") && report.contains("\"virtual_ms\":"));
    assert!(report.ends_with("}]}"));
}

#[tokio::test(start_paused = true)]
async fn the_departure_index_follows_the_order_of_departure_not_of_resolution() {
    let mut notes = Notes::new();
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    let tids = queue(&mut socket, operation, destination, 3);
    socket.flush_owned().await;
    let departed = drain(&peer).len();
    notes.note("departed", &departed);
    notes.note("state after the flush", &socket.owned_test_state());
    assert_eq!(departed, 3);
    assert!(socket.take_outcomes_for_test().is_empty(), "nothing resolved yet");
    assert!(socket.accept_owned_response(tids[2], destination));
    let answered = socket.take_outcomes_for_test();
    notes.note("after the answer of the third", &answered);
    assert_eq!(answered, ["sent=2 kind=0"]);
    socket.expire_owned_requests(Duration::ZERO);
    let expired = socket.take_outcomes_for_test();
    notes.note("after the expiry", &expired);
    notes.note("state after the expiry", &socket.owned_test_state());
    assert_eq!(expired, ["sent=0 kind=1", "sent=1 kind=1"]);
    let next = queue(&mut socket, operation, destination, 1);
    socket.flush_owned().await;
    assert_eq!(drain(&peer).len(), 1);
    assert!(socket.accept_owned_response(next[0], destination));
    assert_eq!(socket.take_outcomes_for_test(), ["sent=3 kind=0"], "the count goes on");
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_operation_prints_the_dropped_kind_for_departed_requests_only() {
    let mut notes = Notes::new();
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    queue(&mut socket, operation, destination, 6);
    socket.flush_owned().await;
    let departed = drain(&peer).len();
    notes.note("departed", &departed);
    notes.note("state after the flush", &socket.owned_test_state());
    assert_eq!(departed, 4);
    socket.cancel_owned_operation(operation);
    let dropped = socket.take_outcomes_for_test();
    notes.note("after the cancellation", &dropped);
    assert_eq!(
        dropped,
        ["sent=0 kind=2", "sent=1 kind=2", "sent=2 kind=2", "sent=3 kind=2"],
        "the two queued requests never left and print nothing"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    socket.flush_owned().await;
    assert!(socket.take_outcomes_for_test().is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_answer_after_the_expiry_prints_nothing() {
    let mut notes = Notes::new();
    let (peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    let tids = queue(&mut socket, operation, destination, 1);
    notes.note("state after the queueing", &socket.owned_test_state());
    socket.flush_owned().await;
    let departed = drain(&peer).len();
    notes.note("departed", &departed);
    notes.note("state after the flush", &socket.owned_test_state());
    notes.note("rate", &socket.owned_pacing_rate_for_test());
    assert_eq!(departed, 1);
    socket.expire_owned_requests(Duration::ZERO);
    let expired = socket.take_outcomes_for_test();
    notes.note("after the expiry", &expired);
    notes.note("state after the expiry", &socket.owned_test_state());
    assert_eq!(expired, ["sent=0 kind=1"]);
    assert!(!socket.accept_owned_response(tids[0], destination));
    assert!(socket.take_outcomes_for_test().is_empty(), "one line per request");
}

#[tokio::test(start_paused = true)]
async fn a_request_that_failed_to_leave_prints_nothing() {
    let mut notes = Notes::new();
    let (_peer, destination) = capture();
    let (mut socket, operation) = paced_socket(30).await;
    queue(&mut socket, operation, destination, 1);
    socket.fail_next_send_for_test();
    socket.flush_owned().await;
    let lines = socket.take_outcomes_for_test();
    notes.note("lines after the failed send", &lines);
    notes.note("state after the failed send", &socket.owned_test_state());
    assert!(lines.is_empty());
    assert_eq!(socket.owned_test_state().map(|state| state.2), Some(0));
}
