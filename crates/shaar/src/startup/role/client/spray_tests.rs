//! Contract of the Client's side of the birthday trial (leaf BDAY-1b, slice 4a-3): when it offers,
//! what it starts, and that a silent or unfit peer costs the dial its window once in ten minutes.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use super::spray::{Ground, SprayDial};
use crate::network::signaling::punch::{PunchLink, PunchMessage, SendError};
use crate::network::signaling::spray::{
    self, Agreement, DEFAULT_SOCKETS, Kind, MIN_INTERVAL, Role, SprayMessage,
};

const PEER: [u8; 32] = [7; 32];
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
/// The external endpoint of the easy peer's spray socket.
const EASY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40_000);
/// The public address of a model hard peer.
const HARD: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 0);
/// The window of the exchange, as the cases measure it.
const WINDOW: Duration = Duration::from_secs(3);

/// How the model peer reacts to an Offer.
#[derive(Clone, Copy, PartialEq)]
enum Peer {
    /// Answers as an easy side.
    Easy,
    /// Answers as a hard side (a pair that needs no trial).
    Hard,
    /// Says nothing.
    Silent,
}

/// A punch link to a model peer: an Offer sent through it is answered as `peer` says.
struct Link {
    peer: Peer,
    sent: Mutex<Vec<SprayMessage>>,
    inbox: Mutex<VecDeque<Vec<u8>>>,
    wake: Notify,
    closed: bool,
}

impl Link {
    fn new(peer: Peer) -> Self {
        Self {
            peer,
            sent: Mutex::new(Vec::new()),
            inbox: Mutex::new(VecDeque::new()),
            wake: Notify::new(),
            closed: false,
        }
    }

    fn offers(&self) -> Vec<SprayMessage> {
        self.sent.lock().unwrap().clone()
    }
}

impl PunchLink for Link {
    async fn send(&self, _: &PunchMessage, _: Duration) -> Result<(), SendError> {
        Err(SendError::Closed)
    }

    async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(bytes) = self.inbox.lock().unwrap().pop_front() {
                return Some(bytes);
            }
            if self.closed {
                return None;
            }
            self.wake.notified().await;
        }
    }

    async fn send_raw(&self, bytes: &[u8], _: Duration) -> Result<(), SendError> {
        let Some(offer) = spray::decode(bytes) else {
            return Ok(());
        };
        self.sent.lock().unwrap().push(offer.clone());
        let (role, address) = match self.peer {
            Peer::Easy => (Role::Easy, EASY),
            Peer::Hard => (Role::Hard, HARD),
            Peer::Silent => return Ok(()),
        };
        let answer = spray::encode(&SprayMessage {
            kind: Kind::Answer,
            epoch: offer.epoch,
            token: offer.token,
            role,
            address,
            planned: 100,
        })
        .expect("an Answer the codec accepts");
        self.inbox.lock().unwrap().push_back(answer);
        self.wake.notify_one();
        Ok(())
    }
}

struct Fake {
    role: Option<Role>,
    ip: Option<Ipv4Addr>,
    started: mpsc::UnboundedSender<Agreement>,
}

impl Ground for Fake {
    fn role(&self) -> Option<Role> {
        self.role
    }

    fn public_ip(&self) -> Option<Ipv4Addr> {
        self.ip
    }

    fn run(&self, agreement: Agreement) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let started = self.started.clone();
        Box::pin(async move {
            let _ = started.send(agreement);
        })
    }
}

fn dial(
    role: Option<Role>,
    ip: Option<Ipv4Addr>,
) -> (SprayDial<Fake>, mpsc::UnboundedReceiver<Agreement>) {
    let (started, receiver) = mpsc::unbounded_channel();
    (SprayDial::new(Fake { role, ip, started }), receiver)
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_hard_client_offers_with_its_public_address_and_starts_its_side_on_an_answer() {
    let (mut dial, mut started) = dial(Some(Role::Hard), Some(PUBLIC_IP));
    let mut link = Link::new(Peer::Easy);
    assert!(dial.attempt(&mut link, PEER, 7, later()).await);
    let offers = link.offers();
    assert_eq!(offers.len(), 1, "the Answer came before the first resend");
    let offer = &offers[0];
    assert_eq!(
        (offer.kind, offer.epoch, offer.role),
        (Kind::Offer, 7, Role::Hard)
    );
    assert_eq!(offer.address, SocketAddrV4::new(PUBLIC_IP, 0));
    assert_eq!(usize::from(offer.planned), usize::from(DEFAULT_SOCKETS));
    settle().await;
    let agreement = started.try_recv().expect("one trial started");
    assert_eq!((agreement.role, agreement.peer), (Role::Hard, EASY));
    assert_eq!((agreement.epoch, agreement.token), (7, offer.token));
    assert!(started.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn nothing_is_offered_unless_the_role_is_hard_and_a_public_address_is_known() {
    for (role, ip) in [
        (None, Some(PUBLIC_IP)),
        (Some(Role::Easy), Some(PUBLIC_IP)),
        (Some(Role::Hard), None),
    ] {
        let (mut dial, mut started) = dial(role, ip);
        let mut link = Link::new(Peer::Easy);
        assert!(!dial.attempt(&mut link, PEER, 1, later()).await);
        assert!(link.offers().is_empty());
        settle().await;
        assert!(started.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn a_silent_peer_costs_the_window_once_and_the_next_dial_inside_ten_minutes_offers_nothing() {
    let (mut dial, mut started) = dial(Some(Role::Hard), Some(PUBLIC_IP));
    let mut link = Link::new(Peer::Silent);
    let began = Instant::now();
    assert!(!dial.attempt(&mut link, PEER, 1, later()).await);
    assert_eq!(Instant::now() - began, WINDOW);
    let first = link.offers().len();
    assert!(first >= 2, "the Offer is repeated inside the window");
    // The next dial, another epoch, inside the cooldown: no Offer and no wait.
    let again = Instant::now();
    assert!(!dial.attempt(&mut link, PEER, 2, later()).await);
    assert_eq!(Instant::now(), again);
    assert_eq!(link.offers().len(), first);
    // After the cooldown the Offer goes out again.
    tokio::time::advance(MIN_INTERVAL).await;
    assert!(!dial.attempt(&mut link, PEER, 3, later()).await);
    assert!(link.offers().len() > first);
    settle().await;
    assert!(started.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn the_deadline_of_the_dial_cuts_the_window_short() {
    let (mut dial, _started) = dial(Some(Role::Hard), Some(PUBLIC_IP));
    let mut link = Link::new(Peer::Silent);
    let began = Instant::now();
    let deadline = began + Duration::from_millis(700);
    assert!(!dial.attempt(&mut link, PEER, 1, deadline).await);
    assert!(Instant::now() - began <= Duration::from_millis(700));
}

#[tokio::test(start_paused = true)]
async fn an_answer_of_a_hard_peer_starts_no_trial() {
    let (mut dial, mut started) = dial(Some(Role::Hard), Some(PUBLIC_IP));
    let mut link = Link::new(Peer::Hard);
    assert!(!dial.attempt(&mut link, PEER, 1, later()).await);
    settle().await;
    assert!(started.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_closed_link_ends_the_attempt_at_once() {
    let (mut dial, mut started) = dial(Some(Role::Hard), Some(PUBLIC_IP));
    let mut link = Link::new(Peer::Silent);
    link.closed = true;
    let began = Instant::now();
    assert!(!dial.attempt(&mut link, PEER, 1, later()).await);
    assert!(Instant::now() - began < Duration::from_millis(500));
    settle().await;
    assert!(started.try_recv().is_err());
}
