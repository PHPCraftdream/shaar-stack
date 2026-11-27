//! Contract of the Server's side of the birthday trial (leaf BDAY-1b, slice 4a-2): which datagrams
//! it takes, when it answers, what it starts, and that it never starts a second trial at once.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};

use super::spray::{Ground, Spray};
use crate::network::signaling::punch::{PunchLink, PunchMessage, SendError};
use crate::network::signaling::spray::{
    self, Agreement, DEFAULT_PROBES, Kind, MIN_INTERVAL, Role, SprayMessage,
};

const PEER: [u8; 32] = [7; 32];
const TOKEN: [u8; 16] = [5; 16];
/// The external endpoint of the model spray socket.
const ENDPOINT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40_000);
/// The public address of the model hard peer (port zero: a hard side cannot tell its port).
const HARD_PEER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 0);

/// A link that records what the responder sends.
struct Link {
    sent: Mutex<Vec<Vec<u8>>>,
}

impl Link {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }
}

impl PunchLink for Link {
    async fn send(&self, _: &PunchMessage, _: Duration) -> Result<(), SendError> {
        Err(SendError::Closed)
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        None
    }

    async fn send_raw(&self, bytes: &[u8], _: Duration) -> Result<(), SendError> {
        self.sent.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

/// The world as the cases set it: a role, an endpoint that can be learned or not, and trials that
/// run until the case releases them.
struct Fake {
    role: Option<Role>,
    endpoint: Option<SocketAddrV4>,
    opened: Arc<AtomicUsize>,
    started: mpsc::UnboundedSender<Agreement>,
    release: Arc<Notify>,
}

impl Ground for Fake {
    type Port = ();

    fn role(&self) -> Option<Role> {
        self.role
    }

    async fn open(&mut self) -> Option<((), SocketAddrV4)> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        self.endpoint.map(|endpoint| ((), endpoint))
    }

    fn run(
        &self,
        agreement: Agreement,
        _: (),
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let started = self.started.clone();
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            let _ = started.send(agreement);
            release.notified().await;
        })
    }
}

struct Rig {
    spray: Spray<Fake>,
    link: Link,
    opened: Arc<AtomicUsize>,
    started: mpsc::UnboundedReceiver<Agreement>,
    release: Arc<Notify>,
}

fn rig(role: Option<Role>, endpoint: Option<SocketAddrV4>) -> Rig {
    let opened = Arc::new(AtomicUsize::new(0));
    let (tx, started) = mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let ground = Fake {
        role,
        endpoint,
        opened: Arc::clone(&opened),
        started: tx,
        release: Arc::clone(&release),
    };
    Rig {
        spray: Spray::new(ground),
        link: Link::new(),
        opened,
        started,
        release,
    }
}

fn message(kind: Kind, epoch: u32, role: Role, address: SocketAddrV4) -> Vec<u8> {
    spray::encode(&SprayMessage {
        kind,
        epoch,
        token: TOKEN,
        role,
        address,
        planned: 100,
    })
    .expect("a message the codec accepts")
}

fn hard_offer(epoch: u32) -> Vec<u8> {
    message(Kind::Offer, epoch, Role::Hard, HARD_PEER)
}

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn an_easy_device_answers_a_hard_peer_with_the_endpoint_it_learned_and_starts_one_trial() {
    let mut rig = rig(Some(Role::Easy), Some(ENDPOINT));
    assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
    let sent = rig.link.sent();
    assert_eq!(sent.len(), 1);
    let answer = spray::decode(&sent[0]).expect("an Answer");
    assert_eq!(
        (answer.kind, answer.epoch, answer.token),
        (Kind::Answer, 7, TOKEN)
    );
    assert_eq!((answer.role, answer.address), (Role::Easy, ENDPOINT));
    assert_eq!(usize::from(answer.planned), usize::from(DEFAULT_PROBES));
    settle().await;
    let agreement = rig.started.try_recv().expect("one trial started");
    assert_eq!((agreement.role, agreement.peer), (Role::Easy, HARD_PEER));
    assert_eq!((agreement.epoch, agreement.token), (7, TOKEN));
    assert!(rig.started.try_recv().is_err());
    assert_eq!(rig.spray.running(), 1);
    assert_eq!(rig.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_repeated_copy_gets_the_same_answer_and_starts_nothing() {
    let mut rig = rig(Some(Role::Easy), Some(ENDPOINT));
    assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
    assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
    let sent = rig.link.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1], "the same Answer again");
    settle().await;
    assert!(rig.started.try_recv().is_ok());
    assert!(rig.started.try_recv().is_err(), "one trial per epoch");
    assert_eq!(
        rig.opened.load(Ordering::SeqCst),
        1,
        "no second socket for a copy"
    );
}

#[tokio::test(start_paused = true)]
async fn a_new_epoch_is_refused_while_a_trial_runs_and_inside_the_cooldown_after_it() {
    let mut rig = rig(Some(Role::Easy), Some(ENDPOINT));
    assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
    settle().await;
    assert_eq!(rig.spray.running(), 1);
    // While the trial runs: silent.
    assert!(rig.spray.handle(&hard_offer(8), PEER, &mut rig.link).await);
    assert_eq!(rig.link.sent().len(), 1);
    // After it ended, inside the cooldown: silent.
    rig.release.notify_one();
    settle().await;
    assert_eq!(rig.spray.running(), 0);
    assert!(rig.spray.handle(&hard_offer(8), PEER, &mut rig.link).await);
    assert_eq!(rig.link.sent().len(), 1);
    // After the cooldown: answered, and a second trial starts.
    tokio::time::advance(MIN_INTERVAL).await;
    assert!(rig.spray.handle(&hard_offer(9), PEER, &mut rig.link).await);
    assert_eq!(rig.link.sent().len(), 2);
    settle().await;
    assert_eq!(rig.started.try_recv().map(|a| a.epoch), Ok(7));
    assert_eq!(rig.started.try_recv().map(|a| a.epoch), Ok(9));
}

#[tokio::test(start_paused = true)]
async fn a_device_that_is_not_easy_stays_silent_and_learns_nothing() {
    for role in [None, Some(Role::Hard)] {
        let mut rig = rig(role, Some(ENDPOINT));
        assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
        assert!(rig.link.sent().is_empty());
        assert_eq!(rig.opened.load(Ordering::SeqCst), 0);
        assert_eq!(rig.spray.running(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn an_offer_of_another_easy_side_is_not_answered_and_costs_no_socket() {
    let mut rig = rig(Some(Role::Easy), Some(ENDPOINT));
    let easy_offer = message(Kind::Offer, 7, Role::Easy, ENDPOINT);
    assert!(rig.spray.handle(&easy_offer, PEER, &mut rig.link).await);
    assert!(rig.link.sent().is_empty());
    assert_eq!(rig.opened.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_that_cannot_be_learned_books_nothing_and_the_next_copy_tries_again() {
    let mut rig = rig(Some(Role::Easy), None);
    assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
    assert!(rig.link.sent().is_empty());
    assert_eq!(rig.spray.running(), 0);
    // The same epoch again: tried again, still nothing booked against the peer.
    assert!(rig.spray.handle(&hard_offer(7), PEER, &mut rig.link).await);
    assert_eq!(rig.opened.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn what_is_no_message_of_the_trial_is_left_to_the_punch_code() {
    let mut rig = rig(Some(Role::Easy), Some(ENDPOINT));
    let punch_offer = crate::network::signaling::punch::encode(&PunchMessage {
        kind: crate::network::signaling::punch::Kind::Offer,
        epoch: 1,
        candidates: vec!["10.0.0.1:4433".parse().unwrap()],
    })
    .unwrap();
    for raw in [punch_offer, b"garbage".to_vec(), Vec::new()] {
        assert!(!rig.spray.handle(&raw, PEER, &mut rig.link).await);
    }
    assert!(rig.link.sent().is_empty());
    // A message of the trial that is no Offer is taken and left unanswered.
    let hit = message(Kind::Hit, 7, Role::Hard, ENDPOINT);
    assert!(rig.spray.handle(&hit, PEER, &mut rig.link).await);
    let answer = message(Kind::Answer, 7, Role::Hard, HARD_PEER);
    assert!(rig.spray.handle(&answer, PEER, &mut rig.link).await);
    assert!(rig.link.sent().is_empty());
    assert_eq!(rig.opened.load(Ordering::SeqCst), 0);
}
