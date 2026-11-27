//! Contract of the exchange that agrees a trial (leaf BDAY-1b-3): the roles, the token and the epoch,
//! the cooldown, the resend, the answers that must be ignored and the single hit report.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::super::negotiate::{
    Admit, Agreement, COOLDOWN_PEERS, Cooldown, DEFAULT_PROBES, DEFAULT_SOCKETS, EXCHANGE_WINDOW,
    Hits, OFFER_RESEND, Side, Wire, answer, initiate, prepare, respond,
};
use super::super::wire::{self, Kind, SprayMessage};
use super::super::{MAX_PROBES, MAX_SOCKETS, MIN_INTERVAL, Role, Token};

const TOKEN: Token = [7; 16];
const PEER: [u8; 32] = [3; 32];
const HARD: Side = Side {
    role: Role::Hard,
    address: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 0),
    planned: 3000,
};
const EASY: Side = Side {
    role: Role::Easy,
    address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40_000),
    planned: 200,
};

/// One end of an in-memory link.
struct Pipe {
    out: mpsc::UnboundedSender<Vec<u8>>,
    inbox: mpsc::UnboundedReceiver<Vec<u8>>,
}

fn pair() -> (Pipe, Pipe) {
    let (to_b, from_a) = mpsc::unbounded_channel();
    let (to_a, from_b) = mpsc::unbounded_channel();
    (
        Pipe {
            out: to_b,
            inbox: from_b,
        },
        Pipe {
            out: to_a,
            inbox: from_a,
        },
    )
}

impl Pipe {
    /// What is waiting in the inbox, without waiting.
    fn waiting(&mut self) -> Vec<Vec<u8>> {
        let mut copies = Vec::new();
        while let Ok(bytes) = self.inbox.try_recv() {
            copies.push(bytes);
        }
        copies
    }
}

impl Wire for Pipe {
    async fn send(&mut self, bytes: &[u8]) -> bool {
        self.out.send(bytes.to_vec()).is_ok()
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.recv().await
    }
}

/// The responder: takes the first message, answers it and returns what started.
async fn serve(wire: &mut Pipe, side: Side, cooldown: &mut Cooldown) -> Option<Agreement> {
    let raw = wire.recv().await?;
    let response = respond(&raw, side, PEER, cooldown, Instant::now())?;
    wire.send(&response.answer).await;
    response.start
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn message(kind: Kind, epoch: u32, token: Token, side: Side) -> Vec<u8> {
    wire::encode(&SprayMessage {
        kind,
        epoch,
        token,
        role: side.role,
        address: side.address,
        planned: side.planned,
    })
    .expect("a message the codec accepts")
}

#[tokio::test(start_paused = true)]
async fn a_hard_initiator_and_an_easy_responder_agree_on_one_trial() {
    let (mut initiator, mut responder) = pair();
    let mut cooldown = Cooldown::new();
    let (initiated, started) = tokio::join!(
        initiate(&mut initiator, HARD, 7, TOKEN, later()),
        serve(&mut responder, EASY, &mut cooldown),
    );
    let (initiated, started) = (initiated.expect("agreed"), started.expect("started"));
    assert_eq!((initiated.epoch, initiated.token), (7, TOKEN));
    assert_eq!((started.epoch, started.token), (7, TOKEN));
    assert_eq!((initiated.role, started.role), (Role::Hard, Role::Easy));
    // The hard side learns the endpoint to write to, the easy side the address to spray.
    assert_eq!(initiated.peer, EASY.address);
    assert_eq!(started.peer, HARD.address);
    assert_eq!((initiated.planned, started.planned), (3000, 200));
}

#[tokio::test(start_paused = true)]
async fn an_easy_initiator_and_a_hard_responder_agree_as_well() {
    let (mut initiator, mut responder) = pair();
    let mut cooldown = Cooldown::new();
    let (initiated, started) = tokio::join!(
        initiate(&mut initiator, EASY, 9, TOKEN, later()),
        serve(&mut responder, HARD, &mut cooldown),
    );
    let (initiated, started) = (initiated.expect("agreed"), started.expect("started"));
    assert_eq!((initiated.role, started.role), (Role::Easy, Role::Hard));
    assert_eq!(initiated.peer, HARD.address);
    assert_eq!(started.peer, EASY.address);
}

#[tokio::test(start_paused = true)]
async fn two_sides_of_a_kind_agree_on_nothing_and_the_initiator_gives_up_at_the_window() {
    for side in [HARD, EASY] {
        let (mut initiator, mut responder) = pair();
        let mut cooldown = Cooldown::new();
        let started_at = Instant::now();
        let (initiated, started) = tokio::join!(
            initiate(&mut initiator, side, 1, TOKEN, later()),
            serve(&mut responder, side, &mut cooldown),
        );
        assert_eq!((initiated, started), (None, None));
        assert_eq!(Instant::now() - started_at, EXCHANGE_WINDOW);
        assert_eq!(cooldown.len(), 0, "a refused pair books nothing");
    }
}

#[tokio::test(start_paused = true)]
async fn the_offer_is_repeated_every_half_second_for_the_window() {
    let (mut initiator, mut responder) = pair();
    let got = initiate(&mut initiator, HARD, 5, TOKEN, later()).await;
    assert_eq!(got, None);
    let copies = responder.waiting();
    // At 0, 0.5, ... 2.5 s: six copies in the three-second window, all the same.
    assert_eq!(
        copies.len(),
        (EXCHANGE_WINDOW.as_millis() / OFFER_RESEND.as_millis()) as usize
    );
    assert!(copies.iter().all(|copy| *copy == copies[0]));
    let offer = wire::decode(&copies[0]).expect("an Offer");
    assert_eq!(
        (offer.kind, offer.epoch, offer.token),
        (Kind::Offer, 5, TOKEN)
    );
}

#[tokio::test(start_paused = true)]
async fn a_closed_link_ends_the_exchange_at_once() {
    let (mut initiator, responder) = pair();
    drop(responder);
    let started_at = Instant::now();
    assert_eq!(
        initiate(&mut initiator, HARD, 1, TOKEN, later()).await,
        None
    );
    assert!(Instant::now() - started_at < OFFER_RESEND);
}

#[tokio::test(start_paused = true)]
async fn the_deadline_cuts_the_window_short() {
    let (mut initiator, _responder) = pair();
    let started_at = Instant::now();
    let deadline = started_at + Duration::from_millis(700);
    assert_eq!(
        initiate(&mut initiator, HARD, 1, TOKEN, deadline).await,
        None
    );
    assert!(Instant::now() - started_at <= Duration::from_millis(700));
}

#[tokio::test(start_paused = true)]
async fn answers_for_another_epoch_or_token_or_role_and_other_kinds_are_ignored() {
    let (mut initiator, mut responder) = pair();
    let stranger = Side {
        address: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 77), 40_001),
        ..EASY
    };
    for wrong in [
        message(Kind::Answer, 8, TOKEN, stranger),
        message(Kind::Answer, 7, [9; 16], stranger),
        message(Kind::Answer, 7, TOKEN, HARD),
        message(Kind::Offer, 7, TOKEN, stranger),
        message(Kind::Hit, 7, TOKEN, stranger),
        b"garbage".to_vec(),
    ] {
        responder.send(&wrong).await;
    }
    responder.send(&message(Kind::Answer, 7, TOKEN, EASY)).await;
    let agreed = initiate(&mut initiator, HARD, 7, TOKEN, later())
        .await
        .expect("the right Answer is found among the wrong ones");
    assert_eq!(
        agreed.peer, EASY.address,
        "none of the wrong ones was taken"
    );
}

#[tokio::test(start_paused = true)]
async fn a_plan_over_the_caps_is_never_offered() {
    let (mut initiator, mut responder) = pair();
    let greedy = Side {
        planned: u16::try_from(MAX_SOCKETS + 1).expect("fits"),
        ..HARD
    };
    assert_eq!(
        initiate(&mut initiator, greedy, 1, TOKEN, later()).await,
        None
    );
    assert!(responder.waiting().is_empty(), "nothing was sent");
}

#[test]
fn the_default_plans_are_within_the_caps() {
    assert!(usize::from(DEFAULT_SOCKETS) <= MAX_SOCKETS);
    assert!(usize::from(DEFAULT_PROBES) <= MAX_PROBES);
}

#[test]
fn a_repeated_copy_is_answered_and_starts_nothing_and_a_new_epoch_waits_for_the_cooldown() {
    let t0 = Instant::now();
    let mut cooldown = Cooldown::new();
    let offer = message(Kind::Offer, 7, TOKEN, HARD);
    let first = respond(&offer, EASY, PEER, &mut cooldown, t0).expect("answered");
    assert!(first.start.is_some());
    let copy = respond(
        &offer,
        EASY,
        PEER,
        &mut cooldown,
        t0 + Duration::from_millis(500),
    )
    .expect("answered again");
    assert_eq!(copy.answer, first.answer);
    assert_eq!(copy.start, None, "one trial per epoch");
    let next = message(Kind::Offer, 8, [8; 16], HARD);
    let just_before = t0 + MIN_INTERVAL - Duration::from_millis(1);
    assert_eq!(respond(&next, EASY, PEER, &mut cooldown, just_before), None);
    let after = respond(&next, EASY, PEER, &mut cooldown, t0 + MIN_INTERVAL).expect("allowed");
    assert!(after.start.is_some());
    // Another peer is not held back by this one.
    let other = respond(&offer, EASY, [4; 32], &mut cooldown, t0).expect("answered");
    assert!(other.start.is_some());
}

#[test]
fn the_responder_answers_only_an_offer_of_the_other_role() {
    let t0 = Instant::now();
    let mut cooldown = Cooldown::new();
    let cases = [
        message(Kind::Offer, 1, TOKEN, EASY),
        message(Kind::Answer, 1, TOKEN, HARD),
        message(Kind::Hit, 1, TOKEN, EASY),
        b"garbage".to_vec(),
        Vec::new(),
    ];
    for raw in cases {
        assert_eq!(respond(&raw, EASY, PEER, &mut cooldown, t0), None);
    }
    assert_eq!(cooldown.len(), 0, "a refusal books nothing");
}

#[test]
fn the_cooldown_remembers_a_bounded_number_of_peers_and_drops_the_oldest() {
    let t0 = Instant::now();
    let mut cooldown = Cooldown::new();
    let peer = |index: u32| {
        let mut key = [0_u8; 32];
        key[..4].copy_from_slice(&index.to_le_bytes());
        key
    };
    for index in 0..200_u32 {
        let at = t0 + Duration::from_millis(u64::from(index));
        assert_eq!(cooldown.admit(peer(index), 1, at), Admit::Fresh);
        assert!(cooldown.len() <= COOLDOWN_PEERS);
    }
    let now = t0 + Duration::from_millis(200);
    assert_eq!(
        cooldown.admit(peer(199), 1, now),
        Admit::Repeat,
        "a recent peer is kept"
    );
    assert_eq!(
        cooldown.admit(peer(0), 2, now),
        Admit::Fresh,
        "the oldest was dropped"
    );
}

#[test]
fn a_hit_report_is_taken_once_and_only_for_its_epoch_and_token() {
    let agreement = Agreement {
        epoch: 7,
        token: TOKEN,
        role: Role::Hard,
        peer: EASY.address,
        planned: 3000,
    };
    let heard = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40_000);
    let hit = |kind, epoch, token| {
        message(
            kind,
            epoch,
            token,
            Side {
                address: heard,
                ..EASY
            },
        )
    };
    let mut hits = Hits::new(&agreement);
    assert_eq!(hits.take(&hit(Kind::Hit, 8, TOKEN)), None, "another epoch");
    assert_eq!(
        hits.take(&hit(Kind::Hit, 7, [9; 16])),
        None,
        "another token"
    );
    assert_eq!(hits.take(&hit(Kind::Offer, 7, TOKEN)), None, "another kind");
    assert_eq!(hits.take(b"garbage"), None);
    assert_eq!(hits.take(&hit(Kind::Hit, 7, TOKEN)), Some(heard));
    assert_eq!(hits.take(&hit(Kind::Hit, 7, TOKEN)), None, "once");
}

#[test]
fn the_peer_is_booked_by_the_answer_and_not_by_the_preparation() {
    let t0 = Instant::now();
    let mut cooldown = Cooldown::new();
    let offer = message(Kind::Offer, 7, TOKEN, HARD);
    let admitted = prepare(&offer, Role::Easy, PEER, &cooldown, t0).expect("admitted");
    assert!(admitted.fresh);
    assert_eq!(cooldown.len(), 0, "preparing books nothing");
    // Prepared again, the Offer is still fresh: the endpoint could not be learned the first time.
    assert!(
        prepare(&offer, Role::Easy, PEER, &cooldown, t0)
            .expect("admitted")
            .fresh
    );
    let response = answer(&admitted, EASY, PEER, &mut cooldown, t0).expect("answered");
    assert!(response.start.is_some());
    assert_eq!(cooldown.len(), 1);
    assert!(
        !prepare(&offer, Role::Easy, PEER, &cooldown, t0)
            .expect("admitted")
            .fresh
    );
    let next = message(Kind::Offer, 8, TOKEN, HARD);
    assert!(prepare(&next, Role::Easy, PEER, &cooldown, t0).is_none());
    // The same role as the Offer's is no match, whatever the cooldown says.
    assert!(prepare(&offer, Role::Hard, PEER, &cooldown, t0).is_none());
}
