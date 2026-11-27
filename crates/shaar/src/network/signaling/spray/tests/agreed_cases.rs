//! Contract of the runners of an agreement (leaf BDAY-1b, slice 4a-1): each side runs its part
//! of what was agreed, prints one counts-only line, and the punch link carries the control bytes.

use std::collections::VecDeque;
use std::net::SocketAddrV4;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::watch;

use super::super::negotiate::{Agreement, OverPunch, Wire};
use super::super::{
    DEFAULT_PROBES, DEFAULT_SOCKETS, MAX_SENT_BYTES, Rng, Role, TRIAL_WINDOW, run_easy_agreed,
    run_hard_agreed,
};
use super::model::{EASY, HARD_IP, Net};
use crate::network::signaling::punch::{PunchLink, PunchMessage, SendError};

fn hard_agreement(token: [u8; 16]) -> Agreement {
    Agreement {
        epoch: 7,
        token,
        role: Role::Hard,
        peer: EASY,
        planned: DEFAULT_SOCKETS,
    }
}

fn easy_agreement(token: [u8; 16]) -> Agreement {
    Agreement {
        epoch: 7,
        token,
        role: Role::Easy,
        peer: SocketAddrV4::new(HARD_IP, 0),
        planned: DEFAULT_PROBES,
    }
}

/// At the default plan the model gives 9.3 expected hits, a chance of 99.99 % of at least one;
/// 20 seeded trials of the two agreed runners must hit in at least 18, both sides or neither.
#[tokio::test(start_paused = true)]
async fn the_agreed_runners_find_a_hit_in_nine_trials_of_ten_at_the_default_plan() {
    let mut hits = 0_u32;
    for seed in 0..20_u64 {
        let net = Net::new(seed);
        let mut easy_port = net.easy_port();
        let mut opener = net.opener(usize::MAX);
        let mut rng = Rng::seeded(seed.wrapping_mul(17).wrapping_add(3));
        let token = rng.token();
        let (_keep, cancel) = watch::channel(false);
        let (hard_side, easy_side) = (hard_agreement(token), easy_agreement(token));
        let (hard, easy) = tokio::join!(
            run_hard_agreed(&mut opener, &hard_side, cancel.clone()),
            run_easy_agreed(&mut easy_port, &easy_side, &mut rng, cancel.clone()),
        );
        match (&hard.found, &easy.found) {
            (Some(_), Some(_)) => hits += 1,
            (None, None) => {}
            (h, e) => panic!(
                "the sides disagree: hard {} easy {}",
                h.is_some(),
                e.is_some()
            ),
        }
        // A hit ends both sides early; without one each side spends its whole plan.
        assert!(hard.report.sockets <= u64::from(DEFAULT_SOCKETS));
        assert!(easy.report.probes <= u64::from(DEFAULT_PROBES));
        if hard.found.is_none() {
            assert_eq!(hard.report.sockets, u64::from(DEFAULT_SOCKETS));
            assert_eq!(hard.report.probes, u64::from(DEFAULT_SOCKETS));
            assert_eq!(easy.report.probes, u64::from(DEFAULT_PROBES));
        }
        assert!(hard.report.sent_bytes <= MAX_SENT_BYTES);
        assert!(easy.report.sent_bytes <= MAX_SENT_BYTES);
        assert!(hard.elapsed <= TRIAL_WINDOW && easy.elapsed <= TRIAL_WINDOW);
    }
    assert!(hits >= 18, "{hits} hits in 20 trials");
}

#[tokio::test(start_paused = true)]
async fn the_operator_line_of_a_finished_side_has_counts_and_no_address() {
    let net = Net::new(4);
    let mut easy_port = net.easy_port();
    let mut opener = net.opener(usize::MAX);
    let mut rng = Rng::seeded(11);
    let token = rng.token();
    let (_keep, cancel) = watch::channel(false);
    let (hard_side, easy_side) = (hard_agreement(token), easy_agreement(token));
    let (hard, easy) = tokio::join!(
        run_hard_agreed(&mut opener, &hard_side, cancel.clone()),
        run_easy_agreed(&mut easy_port, &easy_side, &mut rng, cancel.clone()),
    );
    let hard_line = hard.line(Role::Hard);
    let easy_line = easy.line(Role::Easy);
    assert!(
        hard_line.starts_with("shaar: spray role=hard sockets="),
        "{hard_line}"
    );
    assert!(
        easy_line.starts_with("shaar: spray role=easy sockets=0 probes="),
        "{easy_line}"
    );
    assert!(
        hard_line.contains(&format!(" sockets={} ", hard.report.sockets)),
        "{hard_line}"
    );
    assert!(
        easy_line.contains(&format!(" probes={} ", easy.report.probes)),
        "{easy_line}"
    );
    for line in [&hard_line, &easy_line] {
        assert!(line.contains(" sent_bytes="), "{line}");
        assert!(
            line.contains(" recv_bytes=") && line.contains(" hit="),
            "{line}"
        );
        assert!(line.contains(" elapsed_ms="), "{line}");
        assert!(
            !line.contains("198.51.100") && !line.contains("203.0.113"),
            "{line}"
        );
        assert_eq!(line.lines().count(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_run_sends_nothing_and_an_agreement_of_the_other_role_runs_nothing() {
    let net = Net::new(5);
    let mut easy_port = net.easy_port();
    let mut opener = net.opener(usize::MAX);
    let mut rng = Rng::seeded(13);
    let token = rng.token();
    let (cancel_now, cancel) = watch::channel(true);
    let hard = run_hard_agreed(&mut opener, &hard_agreement(token), cancel.clone()).await;
    let easy = run_easy_agreed(&mut easy_port, &easy_agreement(token), &mut rng, cancel).await;
    drop(cancel_now);
    assert!(hard.found.is_none() && easy.found.is_none());
    assert_eq!(hard.report.sent_datagrams + easy.report.sent_datagrams, 0);
    assert_eq!(hard.report.sockets, 0);

    let (_keep, cancel) = watch::channel(false);
    let wrong_hard = run_hard_agreed(&mut opener, &easy_agreement(token), cancel.clone()).await;
    let wrong_easy =
        run_easy_agreed(&mut easy_port, &hard_agreement(token), &mut rng, cancel).await;
    assert!(wrong_hard.found.is_none() && wrong_easy.found.is_none());
    assert_eq!(wrong_hard.report.sockets, 0);
    assert_eq!(wrong_easy.report.sent_datagrams, 0);
    assert_eq!(wrong_hard.elapsed, Duration::ZERO);
}

/// A punch link that records what it was asked to send; `carries` says whether it overrides
/// `send_raw`.
struct Link {
    sent: Mutex<Vec<Vec<u8>>>,
    inbox: VecDeque<Vec<u8>>,
    carries: bool,
    refuse: bool,
}

impl Link {
    fn new(carries: bool, refuse: bool) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            inbox: VecDeque::new(),
            carries,
            refuse,
        }
    }
}

impl PunchLink for Link {
    async fn send(&self, _: &PunchMessage, _: Duration) -> Result<(), SendError> {
        Err(SendError::Closed)
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        self.inbox.pop_front()
    }

    async fn send_raw(&self, bytes: &[u8], _: Duration) -> Result<(), SendError> {
        if !self.carries {
            return Err(SendError::Closed);
        }
        if self.refuse {
            return Err(SendError::Refused);
        }
        self.sent.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn the_adapter_carries_bytes_both_ways_and_reports_a_refused_send() {
    let mut link = Link::new(true, false);
    link.inbox.push_back(b"from the peer".to_vec());
    let mut wire = OverPunch(&mut link);
    assert!(wire.send(b"to the peer").await);
    assert_eq!(wire.recv().await, Some(b"from the peer".to_vec()));
    assert_eq!(wire.recv().await, None, "a closed link ends the reading");
    assert_eq!(*link.sent.lock().unwrap(), vec![b"to the peer".to_vec()]);

    let mut refusing = Link::new(true, true);
    assert!(!OverPunch(&mut refusing).send(b"x").await);
    assert!(refusing.sent.lock().unwrap().is_empty());
}

/// A link that does not override `send_raw` keeps the default: nothing is carried.
#[tokio::test(start_paused = true)]
async fn a_link_that_does_not_carry_raw_bytes_carries_nothing() {
    let mut link = Link::new(false, false);
    assert!(!OverPunch(&mut link).send(b"x").await);
    assert!(link.sent.lock().unwrap().is_empty());
}
