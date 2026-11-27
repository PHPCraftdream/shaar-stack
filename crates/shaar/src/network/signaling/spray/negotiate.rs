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

    /// Books an Offer of `epoch` from `peer` at `now`.
    pub(crate) fn admit(&mut self, peer: [u8; 32], epoch: u32, now: Instant) -> Admit {
        if let Some((at, last_epoch)) = self.last.get(&peer)
            && now.saturating_duration_since(*at) < MIN_INTERVAL
        {
            return if *last_epoch == epoch {
                Admit::Repeat
            } else {
                Admit::Refused
            };
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

/// The responder: `None` (no answer, nothing started) for anything but an Offer from a peer whose
/// role fits, whose epoch the cooldown admits, and whose answer the codec accepts.
pub(crate) fn respond(
    raw: &[u8],
    side: Side,
    peer: [u8; 32],
    cooldown: &mut Cooldown,
    now: Instant,
) -> Option<Response> {
    let offer = wire::decode(raw)?;
    if offer.kind != Kind::Offer || !compatible(side.role, offer.role) {
        return None;
    }
    let answer = wire::encode(&SprayMessage {
        kind: Kind::Answer,
        epoch: offer.epoch,
        token: offer.token,
        role: side.role,
        address: side.address,
        planned: side.planned,
    })?;
    let start = match cooldown.admit(peer, offer.epoch, now) {
        Admit::Refused => return None,
        Admit::Repeat => None,
        Admit::Fresh => Some(Agreement {
            epoch: offer.epoch,
            token: offer.token,
            role: side.role,
            peer: offer.address,
            planned: side.planned,
        }),
    };
    Some(Response { answer, start })
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
