#![forbid(unsafe_code)]
//! Disposable-fixture capture after authenticated carrier and current mapping validation.

use std::{fmt, io, sync::Mutex};

use iroh_base::CustomAddr;
use libp2p::{PeerId, swarm::ConnectionId};
use tokio::sync::Notify;

use crate::{Link, MAX_DATAGRAM, Received, Route};

const SCOPES: usize = 4;
const PER_SIDE: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub local: PeerId,
    pub peer: PeerId,
    pub connection: ConnectionId,
    pub route: Route,
    pub transport_type: u64,
    pub instance: u64,
    pub epoch: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Scope {
    /// Call only with a link obtained from the factory's authenticated_link API.
    pub fn observed(local: PeerId, link: Link, source: &CustomAddr) -> io::Result<Self> {
        let data = source.data();
        if data.len() != 16 {
            return Err(invalid("custom binding layout changed"));
        }
        let scope = Self {
            local,
            peer: link.peer,
            connection: link.connection,
            route: link.route,
            transport_type: source.id(),
            instance: u64::from_be_bytes(
                data[..8]
                    .try_into()
                    .map_err(|_| invalid("instance layout"))?,
            ),
            epoch: u64::from_be_bytes(data[8..].try_into().map_err(|_| invalid("epoch layout"))?),
        };
        if !scope.valid() {
            return Err(invalid(
                "capture requires a current relayed nonlocal binding",
            ));
        }
        Ok(scope)
    }

    fn valid(self) -> bool {
        self.local != self.peer
            && self.transport_type != 0
            && self.instance != 0
            && self.epoch != 0
            && matches!(self.route, Route::Relayed { generation, .. } if generation != 0)
    }

    fn follows(self, previous: Self) -> bool {
        let (
            Route::Relayed { relay, generation },
            Route::Relayed {
                relay: old_relay,
                generation: old_generation,
            },
        ) = (self.route, previous.route)
        else {
            return false;
        };
        self.valid()
            && self.local == previous.local
            && self.peer == previous.peer
            && self.transport_type == previous.transport_type
            && self.instance == previous.instance
            && self.epoch > previous.epoch
            && self.connection != previous.connection
            && relay == old_relay
            && generation > old_generation
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Scoped {
    pub identity: Scope,
    pub active: bool,
    pub side: usize,
}

pub struct Packet {
    pub scope: usize,
    length: u16,
    bytes: [u8; MAX_DATAGRAM],
}

impl Packet {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("scope", &self.scope)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Transcript {
    pub scopes: [Option<Scoped>; SCOPES],
    pub packets: Vec<Packet>,
}

struct Capture {
    scopes: [Option<Scoped>; SCOPES],
    sides: [usize; 2],
    counts: [usize; SCOPES],
    packets: Vec<Packet>,
    failed: Option<&'static str>,
}

impl Capture {
    fn new(pair: [Scope; 2]) -> io::Result<Self> {
        if !pair.iter().all(|scope| scope.valid())
            || pair[0].local != pair[1].peer
            || pair[1].local != pair[0].peer
            || pair[0].instance == pair[1].instance
            || pair[0].transport_type != pair[1].transport_type
        {
            return Err(invalid(
                "capture peer/instance pair is not distinct and reciprocal",
            ));
        }
        Ok(Self {
            scopes: [
                Some(Scoped {
                    identity: pair[0],
                    active: true,
                    side: 0,
                }),
                Some(Scoped {
                    identity: pair[1],
                    active: true,
                    side: 1,
                }),
                None,
                None,
            ],
            sides: [0; 2],
            counts: [0; SCOPES],
            packets: Vec::with_capacity(2 * PER_SIDE),
            failed: None,
        })
    }

    fn successor(&mut self, previous: Scope, next: Scope) -> io::Result<()> {
        if !next.follows(previous) {
            return Err(invalid(
                "successor changed peer/instance or reused a control generation",
            ));
        }
        let old = self
            .scopes
            .iter()
            .position(|scope| scope.is_some_and(|scope| scope.active && scope.identity == previous))
            .ok_or_else(|| invalid("previous capture scope is not active"))?;
        if self
            .scopes
            .iter()
            .flatten()
            .any(|scope| scope.identity == next)
        {
            return Err(invalid("capture scope already recorded"));
        }
        let free = self
            .scopes
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        let side = self.scopes[old].expect("selected populated scope").side;
        self.scopes[old]
            .as_mut()
            .expect("selected populated scope")
            .active = false;
        self.scopes[free] = Some(Scoped {
            identity: next,
            active: true,
            side,
        });
        Ok(())
    }

    fn push(&mut self, local: PeerId, received: &Received, source: &CustomAddr) {
        if self.failed.is_some() {
            return;
        }
        let link = Link {
            peer: received.peer,
            connection: received.connection,
            route: received.route,
        };
        let Ok(identity) = Scope::observed(local, link, source) else {
            self.failed = Some("malformed actual carrier scope");
            return;
        };
        let Some(index) = self.scopes.iter().position(|scope| {
            scope.is_some_and(|scope| scope.active && scope.identity == identity)
        }) else {
            self.failed = Some("unknown or retired actual carrier scope");
            return;
        };
        let side = self.scopes[index].expect("selected populated scope").side;
        if self.sides[side] == PER_SIDE {
            self.failed = Some("carrier capture overflow");
            return;
        }
        let bytes = received.packet.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
            self.failed = Some("carrier packet shape changed");
            return;
        }
        let Ok(length) = u16::try_from(bytes.len()) else {
            self.failed = Some("carrier packet length encoding");
            return;
        };
        let mut packet = Packet {
            scope: index,
            length,
            bytes: [0; MAX_DATAGRAM],
        };
        packet.bytes[..bytes.len()].copy_from_slice(bytes);
        self.packets.push(packet);
        self.sides[side] += 1;
        self.counts[index] += 1;
    }

    fn finish(self) -> io::Result<Transcript> {
        if let Some(message) = self.failed {
            return Err(invalid(message));
        }
        if self
            .scopes
            .iter()
            .enumerate()
            .any(|(index, scope)| scope.is_some() && self.counts[index] == 0)
        {
            return Err(invalid("capture has an unobserved registered scope"));
        }
        Ok(Transcript {
            scopes: self.scopes,
            packets: self.packets,
        })
    }
}

static CAPTURE: Mutex<Option<Capture>> = Mutex::new(None);
static CHANGED: Notify = Notify::const_new();

pub fn arm(pair: [Scope; 2]) -> io::Result<()> {
    let capture = Capture::new(pair)?;
    let mut slot = CAPTURE
        .lock()
        .map_err(|_| invalid("capture lock poisoned"))?;
    if slot.is_some() {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    *slot = Some(capture);
    drop(slot);
    CHANGED.notify_waiters();
    Ok(())
}

pub fn admit_successor(previous: Scope, next: Scope) -> io::Result<()> {
    let result = {
        let mut slot = CAPTURE
            .lock()
            .map_err(|_| invalid("capture lock poisoned"))?;
        slot.as_mut()
            .ok_or_else(|| invalid("capture is not armed"))?
            .successor(previous, next)
    };
    CHANGED.notify_waiters();
    result
}

/// Called only by the instrumented receive loop, after all production scope checks.
pub fn received(local: PeerId, packet: &Received, source: &CustomAddr) {
    {
        if let Ok(mut slot) = CAPTURE.lock()
            && let Some(capture) = slot.as_mut()
        {
            capture.push(local, packet, source);
        }
    }
    CHANGED.notify_waiters();
}

pub fn count(identity: Scope) -> io::Result<usize> {
    let slot = CAPTURE
        .lock()
        .map_err(|_| invalid("capture lock poisoned"))?;
    let capture = slot
        .as_ref()
        .ok_or_else(|| invalid("capture is not armed"))?;
    if let Some(message) = capture.failed {
        return Err(invalid(message));
    }
    let index = capture
        .scopes
        .iter()
        .position(|scope| scope.is_some_and(|scope| scope.active && scope.identity == identity))
        .ok_or_else(|| invalid("requested capture scope is not active"))?;
    Ok(capture.counts[index])
}

/// cancel-safe: yes — observes exact-scope receive progress without changing admission.
pub async fn wait_after(identity: Scope, previous: usize) -> io::Result<usize> {
    loop {
        let changed = CHANGED.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let observed = count(identity)?;
        if observed > previous {
            return Ok(observed);
        }
        changed.await;
    }
}

/// Call after endpoints/carrier/pump have stopped and joined, never as an early cutoff.
pub fn finish() -> io::Result<Transcript> {
    let capture = {
        CAPTURE
            .lock()
            .map_err(|_| invalid("capture lock poisoned"))?
            .take()
    }
    .ok_or_else(|| invalid("capture is not armed"))?;
    CHANGED.notify_waiters();
    capture.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Datagram;

    fn peer(value: u8) -> PeerId {
        let mut bytes = [value; 34];
        bytes[0] = 0x12;
        bytes[1] = 32;
        PeerId::from_bytes(&bytes).unwrap()
    }

    fn address(instance: u64, epoch: u64) -> CustomAddr {
        let mut data = [0; 16];
        data[..8].copy_from_slice(&instance.to_be_bytes());
        data[8..].copy_from_slice(&epoch.to_be_bytes());
        CustomAddr::from_parts(7, &data)
    }

    fn link(side: usize, generation: u64) -> Link {
        Link {
            peer: peer(if side == 0 { 2 } else { 1 }),
            connection: ConnectionId::new_unchecked(side + usize::try_from(generation).unwrap()),
            route: Route::Relayed {
                relay: if side == 0 { Some(peer(3)) } else { None },
                generation,
            },
        }
    }

    fn pair() -> [Scope; 2] {
        [
            Scope::observed(peer(1), link(0, 1), &address(11, 1)).unwrap(),
            Scope::observed(peer(2), link(1, 1), &address(22, 1)).unwrap(),
        ]
    }

    fn packet(link: Link) -> Received {
        Received {
            peer: link.peer,
            connection: link.connection,
            route: link.route,
            packet: Datagram::new(b"ciphertext fixture").unwrap(),
        }
    }

    #[test]
    fn carrier_frame_capture_preserves_complete_bytes_and_honest_inbound_scope() {
        let mut capture = Capture::new(pair()).unwrap();
        capture.push(peer(1), &packet(link(0, 1)), &address(11, 1));
        capture.push(peer(2), &packet(link(1, 1)), &address(22, 1));
        let transcript = capture.finish().unwrap();
        assert_eq!(transcript.packets.len(), 2);
        assert_eq!(transcript.packets[0].as_bytes(), b"ciphertext fixture");
        assert!(matches!(
            transcript.scopes[1].unwrap().identity.route,
            Route::Relayed { relay: None, .. }
        ));
    }

    #[test]
    fn carrier_frame_capture_rejects_unknown_instance_peer_connection_and_generation() {
        for field in 0..9 {
            let mut capture = Capture::new(pair()).unwrap();
            capture.push(peer(1), &packet(link(0, 1)), &address(11, 1));
            capture.push(peer(2), &packet(link(1, 1)), &address(22, 1));
            let mut wrong = packet(link(0, 1));
            let mut source = address(11, 1);
            let mut local = peer(1);
            match field {
                0 => source = address(99, 1),
                1 => wrong.peer = peer(9),
                2 => wrong.connection = ConnectionId::new_unchecked(77),
                3 => {
                    wrong.route = Route::Relayed {
                        relay: Some(peer(3)),
                        generation: 99,
                    }
                }
                4 => source = address(11, 99),
                5 => source = CustomAddr::from_parts(8, address(11, 1).data()),
                6 => source = CustomAddr::from_parts(7, b"bad layout"),
                7 => wrong.route = Route::Direct,
                _ => local = peer(9),
            }
            capture.push(local, &wrong, &source);
            assert!(capture.finish().is_err());
        }
    }

    #[test]
    fn carrier_frame_capture_successor_does_not_relabel_old_or_empty_scope() {
        let initial = pair();
        let mut capture = Capture::new(initial).unwrap();
        let next = Scope::observed(peer(1), link(0, 2), &address(11, 2)).unwrap();
        let foreign = Scope {
            instance: 99,
            ..next
        };
        assert!(capture.successor(initial[0], foreign).is_err());
        capture.push(peer(1), &packet(link(0, 1)), &address(11, 1));
        capture.push(peer(2), &packet(link(1, 1)), &address(22, 1));
        capture.successor(initial[0], next).unwrap();
        capture.push(peer(1), &packet(link(0, 2)), &address(11, 2));
        capture.push(peer(1), &packet(link(0, 1)), &address(11, 1));
        assert!(capture.finish().is_err());
        let mut empty = Capture::new(initial).unwrap();
        empty.push(peer(1), &packet(link(0, 1)), &address(11, 1));
        empty.push(peer(2), &packet(link(1, 1)), &address(22, 1));
        empty.successor(initial[0], next).unwrap();
        assert!(empty.finish().is_err());
        let mut valid = Capture::new(initial).unwrap();
        valid.push(peer(1), &packet(link(0, 1)), &address(11, 1));
        valid.push(peer(2), &packet(link(1, 1)), &address(22, 1));
        valid.successor(initial[0], next).unwrap();
        valid.push(peer(1), &packet(link(0, 2)), &address(11, 2));
        let transcript = valid.finish().unwrap();
        assert!(!transcript.scopes[0].unwrap().active);
        assert_eq!(transcript.scopes[0].unwrap().identity, initial[0]);
        assert_eq!(transcript.scopes[2].unwrap().identity, next);
        assert_eq!(transcript.packets[0].scope, 0);
        assert_eq!(transcript.packets[2].scope, 2);
    }

    #[test]
    fn carrier_frame_capture_overflow_fails_without_recycling_records() {
        let mut capture = Capture::new(pair()).unwrap();
        capture.push(peer(2), &packet(link(1, 1)), &address(22, 1));
        let packet = packet(link(0, 1));
        for _ in 0..PER_SIDE {
            capture.push(peer(1), &packet, &address(11, 1));
        }
        assert_eq!(capture.packets.len(), PER_SIDE + 1);
        assert!(capture.failed.is_none());
        capture.push(peer(1), &packet, &address(11, 1));
        assert_eq!(capture.packets.len(), PER_SIDE + 1);
        assert!(capture.finish().is_err());
    }
}
