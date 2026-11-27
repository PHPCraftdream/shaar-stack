//! The birthday trial: the last stage of the coordinated punch (leaf BDAY-1, owner's word of
//! 2026-11-27). When a plain punch cannot open a pair because one side's NAT picks a new random
//! external port for each destination (the hard side) and the other side's NAT keeps one port per
//! socket but admits only addresses it has written to (the easy side), the hard side opens many
//! sockets, each writing once to the easy side's endpoint, and the easy side writes once to many
//! random ports of the hard side's address. A port the hard side's NAT drew for a socket that the
//! easy side also wrote to is a hit: both sides then see a datagram that carries the token they
//! agreed on over the authenticated signaling. With N sockets and M probes the chance of a hit is
//! 1 - exp(-N * M / 64512).
//!
//! The datagrams are tiny (21 bytes of payload) and go on dedicated sockets, never through a QUIC
//! handshake. Every number here is a hard cap of the product, not a setting. The probes go only to
//! the peer's own public endpoint that the signaling named, never to a third party.

use std::collections::HashSet;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

mod run;
mod wire;

#[cfg(test)]
mod model;
#[cfg(test)]
mod tests;

// The leaf that wires the trial into the punch uses these; until then only the cases do.
#[allow(unused_imports)]
pub(crate) use run::{
    Datagrams, EasyPlan, HardPlan, Hit, Opener, Trial, UdpOpener, run_easy, run_hard,
};
#[allow(unused_imports)]
pub(crate) use wire::{Kind, SprayMessage, decode, encode};

/// Most sockets the hard side opens in one trial.
pub(crate) const MAX_SOCKETS: usize = 4096;
/// Most probes the easy side writes in one trial.
pub(crate) const MAX_PROBES: usize = 256;
/// Largest payload of one datagram of the trial.
pub(crate) const MAX_DATAGRAM: usize = 64;
/// Most bytes one device sends in one trial, counted as IP datagrams (payload plus headers).
pub(crate) const MAX_SENT_BYTES: u64 = 1 << 20;
/// Longest one trial runs from its start instant.
pub(crate) const TRIAL_WINDOW: Duration = Duration::from_secs(20);
/// Least time between two trials with the same peer.
pub(crate) const MIN_INTERVAL: Duration = Duration::from_secs(600);
/// Header bytes of one IPv4 UDP datagram, counted with its payload.
pub(crate) const UDP_IPV4_HEADER: usize = 28;
/// First port a NAT is assumed to draw from; the range is `FIRST_PORT..=65535`.
pub(crate) const FIRST_PORT: u16 = 1024;
/// Ports in the drawn range.
pub(crate) const PORT_RANGE: usize = 65536 - FIRST_PORT as usize;

/// Bytes of the token the two sides agree on over the signaling.
pub(crate) const TOKEN_LEN: usize = 16;
/// The shared secret of one trial: a datagram without it is not a hit.
pub(crate) type Token = [u8; TOKEN_LEN];

/// Which side of the pair a device plays; the device tells it from what its own walks show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    /// Destination-dependent mapping: opens many sockets.
    Hard,
    /// Endpoint-independent mapping with filtering by address and port: writes many probes.
    Easy,
}

impl Role {
    fn word(self) -> &'static str {
        match self {
            Role::Hard => "hard",
            Role::Easy => "easy",
        }
    }
}

/// What a datagram of the trial says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mark {
    /// "I reached you from here."
    Probe,
    /// "I got your probe."
    Ack,
}

const DATAGRAM_MAGIC: [u8; 4] = *b"spr1";
/// Payload bytes of every datagram of the trial.
pub(crate) const DATAGRAM_LEN: usize = DATAGRAM_MAGIC.len() + TOKEN_LEN + 1;
const _: () = assert!(DATAGRAM_LEN <= MAX_DATAGRAM);

/// The payload of one datagram of the trial.
pub(crate) fn datagram(token: &Token, mark: Mark) -> [u8; DATAGRAM_LEN] {
    let mut bytes = [0_u8; DATAGRAM_LEN];
    bytes[..4].copy_from_slice(&DATAGRAM_MAGIC);
    bytes[4..4 + TOKEN_LEN].copy_from_slice(token);
    bytes[4 + TOKEN_LEN] = match mark {
        Mark::Probe => 1,
        Mark::Ack => 2,
    };
    bytes
}

/// The mark of a datagram that carries `token`; `None` for anything else (a stray packet is
/// never a hit).
pub(crate) fn read_datagram(bytes: &[u8], token: &Token) -> Option<Mark> {
    if bytes.len() != DATAGRAM_LEN || bytes[..4] != DATAGRAM_MAGIC {
        return None;
    }
    let same = bytes[4..4 + TOKEN_LEN]
        .iter()
        .zip(token)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b));
    if same != 0 {
        return None;
    }
    match bytes[4 + TOKEN_LEN] {
        1 => Some(Mark::Probe),
        2 => Some(Mark::Ack),
        _ => None,
    }
}

/// A small generator for ports and tokens. The keyed hasher of the standard library supplies the
/// seed (it is drawn from the operating system); the ports only have to be unpredictable enough
/// not to repeat, and a token that a third party could guess would only cost one wasted dial.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn from_os() -> Self {
        let a = RandomState::new().build_hasher().finish();
        let b = RandomState::new().build_hasher().finish();
        Self(a ^ b.rotate_left(32))
    }

    #[cfg(test)]
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(seed)
    }

    /// The next word (splitmix64).
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound` (rejection sampling, no modulo bias); `bound` must not be zero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let value = self.next_u64();
            if value < zone {
                return value % bound;
            }
        }
    }

    pub(crate) fn token(&mut self) -> Token {
        let mut token = [0_u8; TOKEN_LEN];
        for chunk in token.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_be_bytes()[..chunk.len()]);
        }
        token
    }
}

/// `count` distinct ports drawn uniformly from `FIRST_PORT..=65535`; at most `MAX_PROBES`.
pub(crate) fn random_ports(rng: &mut Rng, count: usize) -> Vec<u16> {
    let count = count.min(MAX_PROBES);
    let mut seen = HashSet::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    while ports.len() < count {
        let port = FIRST_PORT + rng.below(PORT_RANGE as u64) as u16;
        if seen.insert(port) {
            ports.push(port);
        }
    }
    ports
}

/// What one trial of one device used. Counters are shared by the tasks of a trial.
#[derive(Debug)]
pub(crate) struct Counters {
    cap: u64,
    sockets: AtomicU64,
    probes: AtomicU64,
    sent_datagrams: AtomicU64,
    sent_bytes: AtomicU64,
    recv_datagrams: AtomicU64,
    recv_bytes: AtomicU64,
}

impl Counters {
    pub(crate) fn new() -> Self {
        Self::with_cap(MAX_SENT_BYTES)
    }

    pub(crate) fn with_cap(cap: u64) -> Self {
        Self {
            cap,
            sockets: AtomicU64::new(0),
            probes: AtomicU64::new(0),
            sent_datagrams: AtomicU64::new(0),
            sent_bytes: AtomicU64::new(0),
            recv_datagrams: AtomicU64::new(0),
            recv_bytes: AtomicU64::new(0),
        }
    }

    pub(crate) fn note_socket(&self) {
        self.sockets.fetch_add(1, Ordering::Relaxed);
    }

    /// Books one datagram of `payload` bytes against the cap; `false` (and nothing booked) when
    /// it would pass the cap, and the caller must not send it. `probe` marks the first datagram
    /// a socket or a probe port sends, as against an acknowledgement.
    pub(crate) fn reserve_send(&self, payload: usize, probe: bool) -> bool {
        let wire = (payload + UDP_IPV4_HEADER) as u64;
        let mut current = self.sent_bytes.load(Ordering::Relaxed);
        loop {
            if current + wire > self.cap {
                return false;
            }
            match self.sent_bytes.compare_exchange_weak(
                current,
                current + wire,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(seen) => current = seen,
            }
        }
        self.sent_datagrams.fetch_add(1, Ordering::Relaxed);
        if probe {
            self.probes.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    pub(crate) fn note_recv(&self, payload: usize) {
        self.recv_datagrams.fetch_add(1, Ordering::Relaxed);
        self.recv_bytes
            .fetch_add((payload + UDP_IPV4_HEADER) as u64, Ordering::Relaxed);
    }

    pub(crate) fn report(&self) -> Report {
        Report {
            sockets: self.sockets.load(Ordering::Relaxed),
            probes: self.probes.load(Ordering::Relaxed),
            sent_datagrams: self.sent_datagrams.load(Ordering::Relaxed),
            sent_bytes: self.sent_bytes.load(Ordering::Relaxed),
            recv_datagrams: self.recv_datagrams.load(Ordering::Relaxed),
            recv_bytes: self.recv_bytes.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of the counters of one trial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub sockets: u64,
    pub probes: u64,
    pub sent_datagrams: u64,
    pub sent_bytes: u64,
    pub recv_datagrams: u64,
    pub recv_bytes: u64,
}

impl Report {
    /// The operator line of one device and trial: counts only, never an address or a token. The
    /// byte counts are IP datagrams (payload plus 28 bytes of headers each), so they compare with
    /// the counters of a network interface.
    pub(crate) fn line(&self, role: Role, hit: bool, elapsed: Duration) -> String {
        format!(
            "shaar: spray role={} sockets={} probes={} sent_bytes={} recv_bytes={} hit={} elapsed_ms={}",
            role.word(),
            self.sockets,
            self.probes,
            self.sent_bytes,
            self.recv_bytes,
            if hit { "yes" } else { "no" },
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        )
    }
}
