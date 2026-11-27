//! Contract of the birthday trial (leaf BDAY-1a): the engine against a model NAT, the caps, the
//! token, cancellation, the probe policy and the control messages.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::model::{EASY, HARD_IP, HardPort, Net};
use super::run::{EasyPlan, HardPlan, Hit, Schedule, Trial, run_easy, run_hard};
use super::wire::{self, MESSAGE_LEN};
use super::{
    Counters, DATAGRAM_LEN, FIRST_PORT, Kind, MAX_PROBES, MAX_SENT_BYTES, MAX_SOCKETS, Mark,
    Report, Rng, Role, SprayMessage, TRIAL_WINDOW, UDP_IPV4_HEADER, datagram, random_ports,
    read_datagram,
};

const INSTANT: Schedule = Schedule {
    per_tick: usize::MAX,
    tick: Duration::ZERO,
};

struct Outcome {
    hard: Option<Hit<HardPort>>,
    easy: Option<SocketAddrV4>,
    hard_report: Report,
    easy_report: Report,
}

fn trial_of(
    token: super::Token,
    counters: &Arc<Counters>,
    cancel: &watch::Receiver<bool>,
) -> Trial {
    Trial {
        token,
        counters: Arc::clone(counters),
        deadline: Instant::now() + TRIAL_WINDOW,
        cancel: cancel.clone(),
    }
}

/// One whole trial of both sides over the model network.
async fn trial(net: &Net, seed: u64, sockets: usize, probes: usize, open_limit: usize) -> Outcome {
    let mut easy_port = net.easy_port();
    let mut opener = net.opener(open_limit);
    let mut rng = Rng::seeded(seed.wrapping_mul(31).wrapping_add(7));
    let token = rng.token();
    let (_keep, cancel) = watch::channel(false);
    let hard_counters = Arc::new(Counters::new());
    let easy_counters = Arc::new(Counters::new());
    let hard_plan = HardPlan {
        sockets,
        schedule: INSTANT,
    };
    let easy_plan = EasyPlan {
        probes,
        schedule: INSTANT,
    };
    let (hard, easy) = tokio::join!(
        run_hard(
            &mut opener,
            EASY,
            hard_plan,
            trial_of(token, &hard_counters, &cancel)
        ),
        run_easy(
            &mut easy_port,
            HARD_IP,
            easy_plan,
            &mut rng,
            trial_of(token, &easy_counters, &cancel)
        ),
    );
    Outcome {
        hard,
        easy,
        hard_report: hard_counters.report(),
        easy_report: easy_counters.report(),
    }
}

/// At 3000 sockets and 65 probes the model gives 3.0 expected hits and a chance of 95 % of at least
/// one; 200 seeded trials must hit in at least 90 % of them, and a hit is the same path on both
/// sides: the endpoint the easy side heard is the external endpoint of the socket that was heard.
#[tokio::test(start_paused = true)]
async fn the_engine_finds_a_hit_in_nine_trials_of_ten_at_the_planned_numbers() {
    let mut hits = 0_u32;
    for seed in 0..200_u64 {
        let net = Net::new(seed);
        let outcome = trial(&net, seed, 3000, 65, usize::MAX).await;
        match (outcome.hard, outcome.easy) {
            (Some(hard), Some(easy)) => {
                hits += 1;
                assert_eq!(hard.peer, EASY);
                let external = net.external_port(hard.port.id()).expect("the socket wrote");
                assert_eq!(easy, SocketAddrV4::new(HARD_IP, external));
            }
            (None, None) => {}
            (hard, easy) => panic!(
                "the two sides disagree: hard {} easy {}",
                hard.is_some(),
                easy.is_some()
            ),
        }
    }
    assert!(hits >= 180, "{hits} hits in 200 trials");
}

/// Without a probe of the easy side no filter entry exists and nothing is heard, however many
/// sockets the hard side opens; its datagrams still count.
#[tokio::test(start_paused = true)]
async fn no_hit_without_a_probe_of_the_easy_side() {
    let net = Net::new(1);
    let outcome = trial(&net, 1, 300, 0, usize::MAX).await;
    assert!(outcome.hard.is_none() && outcome.easy.is_none());
    assert_eq!(outcome.hard_report.sockets, 300);
    assert_eq!(outcome.hard_report.probes, 300);
    assert_eq!(outcome.easy_report.sent_datagrams, 0);
    assert_eq!(outcome.easy_report.recv_datagrams, 0);
}

/// A hit costs what the model says: the counters of both devices agree with the datagrams that
/// were written, in IP bytes, and stay far under the cap.
#[tokio::test(start_paused = true)]
async fn the_counters_book_every_datagram_in_ip_bytes() {
    let net = Net::new(2);
    let outcome = trial(&net, 2, 3000, 200, usize::MAX).await;
    assert!(outcome.hard.is_some() && outcome.easy.is_some());
    let each = (DATAGRAM_LEN + UDP_IPV4_HEADER) as u64;
    for report in [outcome.hard_report, outcome.easy_report] {
        assert_eq!(report.sent_bytes, report.sent_datagrams * each);
        assert_eq!(report.recv_bytes, report.recv_datagrams * each);
        assert!(report.sent_bytes < MAX_SENT_BYTES / 4);
    }
    assert_eq!(outcome.easy_report.probes, 200);
    assert_eq!(outcome.hard_report.sockets, 3000);
}

#[test]
fn the_plans_are_clamped_to_the_caps() {
    assert_eq!(HardPlan::new(1_000_000).sockets, MAX_SOCKETS);
    assert_eq!(EasyPlan::new(1_000_000).probes, MAX_PROBES);
    assert_eq!(HardPlan::new(10).sockets, 10);
    assert_eq!(EasyPlan::new(10).probes, 10);
    assert_eq!(random_ports(&mut Rng::seeded(3), 10_000).len(), MAX_PROBES);
}

#[test]
fn the_byte_cap_stops_the_booking_before_it_is_passed() {
    let counters = Counters::with_cap(2 * (DATAGRAM_LEN + UDP_IPV4_HEADER) as u64);
    assert!(counters.reserve_send(DATAGRAM_LEN, true));
    assert!(counters.reserve_send(DATAGRAM_LEN, false));
    assert!(!counters.reserve_send(DATAGRAM_LEN, true));
    let report = counters.report();
    assert_eq!((report.sent_datagrams, report.probes), (2, 1));
    assert!(report.sent_bytes <= 2 * (DATAGRAM_LEN + UDP_IPV4_HEADER) as u64);
}

/// With a cap too small for the plan the easy side stops sending at the cap and no more.
#[tokio::test(start_paused = true)]
async fn a_side_never_sends_more_than_its_byte_cap() {
    let net = Net::new(4);
    let mut port = net.easy_port();
    let (_keep, cancel) = watch::channel(false);
    let counters = Arc::new(Counters::with_cap(
        10 * (DATAGRAM_LEN + UDP_IPV4_HEADER) as u64,
    ));
    let plan = EasyPlan {
        probes: 100,
        schedule: INSTANT,
    };
    let mut rng = Rng::seeded(4);
    let token = rng.token();
    let found = run_easy(
        &mut port,
        HARD_IP,
        plan,
        &mut rng,
        trial_of(token, &counters, &cancel),
    )
    .await;
    assert!(found.is_none());
    assert_eq!(counters.report().sent_datagrams, 10);
}

/// A cancellation before the start stops both sides before they send or open anything.
#[tokio::test(start_paused = true)]
async fn a_cancelled_trial_sends_and_opens_nothing() {
    let net = Net::new(5);
    let mut port = net.easy_port();
    let mut opener = net.opener(usize::MAX);
    let (keep, cancel) = watch::channel(false);
    keep.send(true).unwrap();
    let hard_counters = Arc::new(Counters::new());
    let easy_counters = Arc::new(Counters::new());
    let mut rng = Rng::seeded(5);
    let token = rng.token();
    let hard = run_hard(
        &mut opener,
        EASY,
        HardPlan::new(100),
        trial_of(token, &hard_counters, &cancel),
    )
    .await;
    let easy = run_easy(
        &mut port,
        HARD_IP,
        EasyPlan::new(100),
        &mut rng,
        trial_of(token, &easy_counters, &cancel),
    )
    .await;
    assert!(hard.is_none() && easy.is_none());
    assert_eq!(hard_counters.report().sockets, 0);
    assert_eq!(hard_counters.report().sent_datagrams, 0);
    assert_eq!(easy_counters.report().sent_datagrams, 0);
}

/// A cancellation in the middle of a paced trial ends it at once, before its deadline.
#[tokio::test(start_paused = true)]
async fn a_cancellation_in_the_middle_ends_the_trial() {
    let net = Net::new(6);
    let mut opener = net.opener(usize::MAX);
    let (keep, cancel) = watch::channel(false);
    let counters = Arc::new(Counters::new());
    let token = Rng::seeded(6).token();
    let started = Instant::now();
    let run = run_hard(
        &mut opener,
        EASY,
        HardPlan::new(1000),
        trial_of(token, &counters, &cancel),
    );
    let stop = async {
        tokio::time::sleep(Duration::from_millis(250)).await;
        keep.send(true).unwrap();
    };
    let (hit, ()) = tokio::join!(run, stop);
    assert!(hit.is_none());
    assert!(started.elapsed() < Duration::from_secs(1));
    let opened = counters.report().sockets;
    assert!((1..1000).contains(&opened), "{opened} sockets");
}

/// When the system refuses another socket the opening stops with what is open.
#[tokio::test(start_paused = true)]
async fn a_refused_socket_ends_the_opening_without_a_failure() {
    let net = Net::new(7);
    let outcome = trial(&net, 7, 3000, 0, 50).await;
    assert!(outcome.hard.is_none());
    assert_eq!(outcome.hard_report.sockets, 50);
}

/// Addresses the probe policy denies are never written to and no socket is opened for them.
#[tokio::test(start_paused = true)]
async fn the_probe_policy_applies_to_both_sides() {
    let net = Net::new(8);
    let mut opener = net.opener(usize::MAX);
    let mut port = net.easy_port();
    let (_keep, cancel) = watch::channel(false);
    let counters = Arc::new(Counters::new());
    let mut rng = Rng::seeded(8);
    let token = rng.token();
    let denied = SocketAddrV4::new(Ipv4Addr::new(169, 254, 1, 1), 9000);
    let hit = run_hard(
        &mut opener,
        denied,
        HardPlan::new(100),
        trial_of(token, &counters, &cancel),
    )
    .await;
    assert!(hit.is_none());
    for ip in [Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::UNSPECIFIED] {
        let found = run_easy(
            &mut port,
            ip,
            EasyPlan::new(100),
            &mut rng,
            trial_of(token, &counters, &cancel),
        )
        .await;
        assert!(found.is_none());
    }
    assert_eq!(counters.report().sockets, 0);
    assert_eq!(counters.report().sent_datagrams, 0);
}

/// Only a datagram of the right length, magic and token is read, and the mark must be known.
#[test]
fn a_datagram_without_the_token_is_not_a_hit() {
    let token = Rng::seeded(9).token();
    let other = Rng::seeded(10).token();
    let probe = datagram(&token, Mark::Probe);
    assert_eq!(read_datagram(&probe, &token), Some(Mark::Probe));
    assert_eq!(
        read_datagram(&datagram(&token, Mark::Ack), &token),
        Some(Mark::Ack)
    );
    assert_eq!(read_datagram(&probe, &other), None);
    assert_eq!(read_datagram(&probe[..DATAGRAM_LEN - 1], &token), None);
    let mut long = probe.to_vec();
    long.push(0);
    assert_eq!(read_datagram(&long, &token), None);
    let mut wrong_magic = probe;
    wrong_magic[0] ^= 1;
    assert_eq!(read_datagram(&wrong_magic, &token), None);
    let mut wrong_mark = probe;
    wrong_mark[DATAGRAM_LEN - 1] = 9;
    assert_eq!(read_datagram(&wrong_mark, &token), None);
    assert_eq!(read_datagram(&[], &token), None);
}

#[test]
fn the_drawn_ports_are_distinct_and_in_the_range() {
    let mut rng = Rng::seeded(11);
    for _ in 0..50 {
        let ports = random_ports(&mut rng, 200);
        assert_eq!(ports.len(), 200);
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 200);
        assert!(ports.iter().all(|port| *port >= FIRST_PORT));
    }
}

#[test]
fn the_operator_line_has_counts_only() {
    let report = Report {
        sockets: 3000,
        probes: 3000,
        sent_datagrams: 3001,
        sent_bytes: 147_049,
        recv_datagrams: 2,
        recv_bytes: 98,
    };
    assert_eq!(
        report.line(Role::Hard, true, Duration::from_millis(5321)),
        "shaar: spray role=hard sockets=3000 probes=3000 sent_bytes=147049 recv_bytes=98 hit=yes elapsed_ms=5321"
    );
    assert!(
        report
            .line(Role::Easy, false, Duration::ZERO)
            .contains("role=easy")
    );
}

fn message(kind: Kind, role: Role) -> SprayMessage {
    let address = match role {
        Role::Hard => SocketAddrV4::new(HARD_IP, 0),
        Role::Easy => EASY,
    };
    SprayMessage {
        kind,
        epoch: 7,
        token: Rng::seeded(12).token(),
        role,
        address,
        planned: 65,
    }
}

#[test]
fn every_control_message_round_trips() {
    for kind in [Kind::Offer, Kind::Answer] {
        for role in [Role::Hard, Role::Easy] {
            let original = message(kind, role);
            let bytes = wire::encode(&original).expect("encodes");
            assert_eq!(bytes.len(), MESSAGE_LEN);
            assert_eq!(wire::decode(&bytes), Some(original));
        }
    }
    let hit = SprayMessage {
        kind: Kind::Hit,
        address: SocketAddrV4::new(HARD_IP, 50_001),
        ..message(Kind::Offer, Role::Easy)
    };
    assert_eq!(wire::decode(&wire::encode(&hit).unwrap()), Some(hit));
}

#[test]
fn the_codec_refuses_what_the_product_never_sends() {
    let easy = message(Kind::Offer, Role::Easy);
    let mut hard = message(Kind::Offer, Role::Hard);
    // A hard side names no port; an easy side must name one.
    hard.address = SocketAddrV4::new(HARD_IP, 4000);
    assert!(wire::encode(&hard).is_none());
    let mut portless = easy.clone();
    portless.address = SocketAddrV4::new(*EASY.ip(), 0);
    assert!(wire::encode(&portless).is_none());
    // Addresses the probe policy denies.
    for ip in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(169, 254, 3, 3),
        Ipv4Addr::new(224, 1, 1, 1),
        Ipv4Addr::BROADCAST,
    ] {
        let mut denied = easy.clone();
        denied.address = SocketAddrV4::new(ip, 4000);
        assert!(wire::encode(&denied).is_none(), "{ip}");
    }
    // Planned counts over the caps.
    let mut over = easy.clone();
    over.planned = (MAX_PROBES + 1) as u16;
    assert!(wire::encode(&over).is_none());
    let mut over_hard = message(Kind::Answer, Role::Hard);
    over_hard.planned = (MAX_SOCKETS + 1) as u16;
    assert!(wire::encode(&over_hard).is_none());
    over_hard.planned = MAX_SOCKETS as u16;
    assert!(wire::encode(&over_hard).is_some());
}

/// Every prefix and every extension of a valid message, a flipped byte anywhere, and thousands of
/// random strings decode to `None` or to a message that encodes back to the same bytes; nothing
/// panics.
#[test]
fn hostile_input_never_panics_and_never_decodes_to_something_else() {
    let valid = wire::encode(&message(Kind::Offer, Role::Easy)).unwrap();
    for length in 0..valid.len() {
        assert_eq!(wire::decode(&valid[..length]), None);
    }
    let mut longer = valid.clone();
    longer.push(0);
    assert_eq!(wire::decode(&longer), None);
    for at in 0..valid.len() {
        for flip in [1_u8, 0x80, 0xff] {
            let mut bytes = valid.clone();
            bytes[at] ^= flip;
            if let Some(decoded) = wire::decode(&bytes) {
                assert_eq!(wire::encode(&decoded).as_deref(), Some(bytes.as_slice()));
            }
        }
    }
    let mut rng = Rng::seeded(13);
    for _ in 0..5000 {
        let length = rng.below(2 * MESSAGE_LEN as u64) as usize;
        let bytes: Vec<u8> = (0..length).map(|_| rng.next_u64() as u8).collect();
        if let Some(decoded) = wire::decode(&bytes) {
            assert_eq!(wire::encode(&decoded).as_deref(), Some(bytes.as_slice()));
        }
    }
}
