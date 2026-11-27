//! The exchange that agrees one trial between the two sides (leaf BDAY-1b-3). The initiator (the
//! Client, which dials) sends an Offer with its role, its endpoint and the count it plans; the
//! responder checks that the roles are one hard and one easy side, that this peer has not had a
//! trial lately, and answers with its own side. Both then hold an [`Agreement`]: the token the
//! initiator drew, the epoch, and the endpoint of the peer, which is all [`super::run`] needs.
//! Nothing here touches a socket of the trial; the links are anything that carries bytes between
//! two authenticated peers.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddrV4;
use std::time::Duration;

use tokio::time::{Instant, timeout_at};

use super::wire::{self, Kind, SprayMessage};
use super::{MIN_INTERVAL, Role, Token};
use crate::network::signaling::punch::{EXCHANGE_BUDGET, PunchLink};

/// Sockets a hard side plans by default: 3000 sockets and 200 probes give 9.3 expected hits, a
/// chance of 99.99 % in the model, for about 150 KB from the hard side and 10 KB from the easy
/// side (item 48).
pub(crate) const DEFAULT_SOCKETS: u16 = 3000;
/// Probes an easy side plans by default.
pub(crate) const DEFAULT_PROBES: u16 = 200;
/// Interval between copies of the same Offer: a first datagram to a cold path can be lost.
pub(crate) const OFFER_RESEND: Duration = Duration::from_millis(500);
/// Longest the initiator waits for an Answer.
pub(crate) const EXCHANGE_WINDOW: Duration = Duration::from_secs(3);
/// Most peers the cooldown remembers; the oldest is dropped first.
pub(crate) const COOLDOWN_PEERS: usize = 64;

/// What one side tells the other about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Side {
    pub role: Role,
    /// An easy side names the external endpoint of its spray socket, a hard side only its public
    /// address with port zero (the codec checks this).
    pub address: SocketAddrV4,
    /// Sockets (hard) or probes (easy).
    pub planned: u16,
}

/// What a side holds once the exchange succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Agreement {
    pub epoch: u32,
    pub token: Token,
    /// This side's own role.
    pub role: Role,
    /// The peer's address: the easy side's endpoint when this side is hard, the hard side's
    /// public address (port zero) when this side is easy.
    pub peer: SocketAddrV4,
    /// What this side runs.
    pub planned: u16,
}

/// A link that carries the control messages between two authenticated peers.
pub(crate) trait Wire: Send {
    /// Sends one message; `false` when the link refused it.
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = bool> + Send;
    /// The next message; `None` when the link is closed. Must be cancel-safe.
    fn recv(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// One hard and one easy side make a trial; two of a kind need none (or are out of scope).
fn compatible(mine: Role, theirs: Role) -> bool {
    mine != theirs
}

/// The initiator: sends the Offer, repeats it every [`OFFER_RESEND`] and waits for the Answer that
/// carries its epoch and token, for [`EXCHANGE_WINDOW`] or until `deadline`. `None` when no Answer
/// came, the link closed, or the Offer is one the codec refuses.
pub(crate) async fn initiate<W: Wire>(
    wire: &mut W,
    side: Side,
    epoch: u32,
    token: Token,
    deadline: Instant,
) -> Option<Agreement> {
    let offer = wire::encode(&SprayMessage {
        kind: Kind::Offer,
        epoch,
        token,
        role: side.role,
        address: side.address,
        planned: side.planned,
    })?;
    let end = deadline.min(Instant::now() + EXCHANGE_WINDOW);
    let mut resend = Instant::now();
    loop {
        if Instant::now() >= resend {
            // A refused or slow copy is lost like any other; the next one follows.
            let _ = timeout_at(end, wire.send(&offer)).await;
            resend = Instant::now() + OFFER_RESEND;
        }
        match timeout_at(resend.min(end), wire.recv()).await {
            Err(_) if Instant::now() >= end => return None,
            Err(_) => {}
            Ok(None) => return None,
            Ok(Some(raw)) => {
                if let Some(answer) = wire::decode(&raw)
                    && answer.kind == Kind::Answer
                    && answer.epoch == epoch
                    && answer.token == token
                    && compatible(side.role, answer.role)
                {
                    return Some(Agreement {
                        epoch,
                        token,
                        role: side.role,
                        peer: answer.address,
                        planned: side.planned,
                    });
                }
            }
        }
    }
}

/// What the cooldown says of an Offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    /// The first Offer of this epoch from this peer: a trial starts.
    Fresh,
    /// Another copy of an Offer already answered: it is answered again and starts nothing.
    Repeat,
    /// A new epoch inside [`MIN_INTERVAL`] of the last trial with this peer: no answer.
    Refused,
}

/// One trial per peer per [`MIN_INTERVAL`] (the cap of item 48), over a bounded memory.
#[derive(Debug, Default)]
pub(crate) struct Cooldown {
    last: HashMap<[u8; 32], (Instant, u32)>,
}

impl Cooldown {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// What booking an Offer of `epoch` from `peer` at `now` would say, without booking it.
    pub(crate) fn check(&self, peer: [u8; 32], epoch: u32, now: Instant) -> Admit {
        match self.last.get(&peer) {
            Some((at, last_epoch)) if now.saturating_duration_since(*at) < MIN_INTERVAL => {
                if *last_epoch == epoch {
                    Admit::Repeat
                } else {
                    Admit::Refused
                }
            }
            _ => Admit::Fresh,
        }
    }

    /// Books an Offer of `epoch` from `peer` at `now`.
    pub(crate) fn admit(&mut self, peer: [u8; 32], epoch: u32, now: Instant) -> Admit {
        let verdict = self.check(peer, epoch, now);
        if verdict != Admit::Fresh {
            return verdict;
        }
        if self.last.len() >= COOLDOWN_PEERS && !self.last.contains_key(&peer) {
            self.last
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < MIN_INTERVAL);
        }
        if self.last.len() >= COOLDOWN_PEERS && !self.last.contains_key(&peer) {
            let oldest = self
                .last
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.last.remove(&oldest);
            }
        }
        self.last.insert(peer, (now, epoch));
        Admit::Fresh
    }

    pub(crate) fn len(&self) -> usize {
        self.last.len()
    }
}

/// What the responder does with an Offer: the Answer to send, and the agreement when a trial
/// starts now (not for a repeated copy).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub answer: Vec<u8>,
    pub start: Option<Agreement>,
}

/// An Offer that this side may answer: of the other role, and not refused by the cooldown. `fresh`
/// tells the first copy of an epoch from a repeated one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    pub offer: SprayMessage,
    pub fresh: bool,
}

/// The first half of the responder, which books nothing: `None` for anything but an Offer of the
/// other role from a peer the cooldown admits. The responder learns its own endpoint between the
/// two halves, so a failure to learn it leaves the peer unbooked.
pub(crate) fn prepare(
    raw: &[u8],
    mine: Role,
    peer: [u8; 32],
    cooldown: &Cooldown,
    now: Instant,
) -> Option<Admitted> {
    let offer = wire::decode(raw)?;
    if offer.kind != Kind::Offer || !compatible(mine, offer.role) {
        return None;
    }
    match cooldown.check(peer, offer.epoch, now) {
        Admit::Refused => None,
        Admit::Repeat => Some(Admitted {
            offer,
            fresh: false,
        }),
        Admit::Fresh => Some(Admitted { offer, fresh: true }),
    }
}

/// The second half: the Answer for an admitted Offer, with this side's own `side`, and the
/// agreement when it is the first copy of its epoch (the peer is booked then). `None` when the
/// codec refuses the Answer.
pub(crate) fn answer(
    admitted: &Admitted,
    side: Side,
    peer: [u8; 32],
    cooldown: &mut Cooldown,
    now: Instant,
) -> Option<Response> {
    let offer = &admitted.offer;
    let bytes = wire::encode(&SprayMessage {
        kind: Kind::Answer,
        epoch: offer.epoch,
        token: offer.token,
        role: side.role,
        address: side.address,
        planned: side.planned,
    })?;
    let start = if admitted.fresh {
        cooldown.admit(peer, offer.epoch, now);
        Some(Agreement {
            epoch: offer.epoch,
            token: offer.token,
            role: side.role,
            peer: offer.address,
            planned: side.planned,
        })
    } else {
        None
    };
    Some(Response {
        answer: bytes,
        start,
    })
}

/// Both halves at once, for a side that knows its endpoint already.
pub(crate) fn respond(
    raw: &[u8],
    side: Side,
    peer: [u8; 32],
    cooldown: &mut Cooldown,
    now: Instant,
) -> Option<Response> {
    let admitted = prepare(raw, side.role, peer, cooldown, now)?;
    answer(&admitted, side, peer, cooldown, now)
}

/// Takes the hit report of one agreement, once: the first `Hit` message with the agreement's
/// epoch and token gives the endpoint the peer says it heard from; every later one, and anything
/// else, gives nothing.
#[derive(Debug)]
pub(crate) struct Hits {
    epoch: u32,
    token: Token,
    taken: bool,
}

impl Hits {
    pub(crate) fn new(agreement: &Agreement) -> Self {
        Self {
            epoch: agreement.epoch,
            token: agreement.token,
            taken: false,
        }
    }

    pub(crate) fn take(&mut self, raw: &[u8]) -> Option<SocketAddrV4> {
        let message = wire::decode(raw)?;
        if self.taken
            || message.kind != Kind::Hit
            || message.epoch != self.epoch
            || message.token != self.token
        {
            return None;
        }
        self.taken = true;
        Some(message.address)
    }
}

/// A punch link as a [`Wire`]: the control messages of the trial ride the link that carries the
/// punch offers, bounded by the budget of one punch exchange.
pub(crate) struct OverPunch<'a, L>(pub(crate) &'a mut L);

impl<L: PunchLink + Send> Wire for OverPunch<'_, L> {
    async fn send(&mut self, bytes: &[u8]) -> bool {
        self.0.send_raw(bytes, EXCHANGE_BUDGET).await.is_ok()
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.0.recv_raw().await
    }
}
