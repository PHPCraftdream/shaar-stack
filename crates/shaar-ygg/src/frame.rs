//! Readiness-probe frames and nonces. Pure data: no I/O, no clock.
//!
//! A frame is `MAGIC | VERSION | kind | nonce` and exactly [`FRAME_LEN`] bytes. The
//! sender's identity is never read from the frame: the Yggdrasil session already
//! authenticates the key that `recv` reports.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};

/// Length of the nonce that pairs a reply with its request.
pub(crate) const NONCE_LEN: usize = 16;
const MAGIC: [u8; 8] = *b"shaar-yg";
const VERSION: u8 = 1;
/// Every probe frame has exactly this length.
pub(crate) const FRAME_LEN: usize = MAGIC.len() + 2 + NONCE_LEN;

/// What a frame asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A readiness request.
    Ping,
    /// The reply to a request, echoing its nonce.
    Pong,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Self::Ping => 1,
            Self::Pong => 2,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Ping),
            2 => Some(Self::Pong),
            _ => None,
        }
    }
}

/// One decoded probe frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) kind: Kind,
    pub(crate) nonce: [u8; NONCE_LEN],
}

impl Frame {
    pub(crate) fn encode(&self) -> [u8; FRAME_LEN] {
        let mut bytes = [0u8; FRAME_LEN];
        bytes[..MAGIC.len()].copy_from_slice(&MAGIC);
        bytes[MAGIC.len()] = VERSION;
        bytes[MAGIC.len() + 1] = self.kind.byte();
        bytes[MAGIC.len() + 2..].copy_from_slice(&self.nonce);
        bytes
    }

    /// `None` for anything that is not exactly one well-formed frame.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FRAME_LEN
            || bytes[..MAGIC.len()] != MAGIC
            || bytes[MAGIC.len()] != VERSION
        {
            return None;
        }
        let kind = Kind::from_byte(bytes[MAGIC.len() + 1])?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[MAGIC.len() + 2..]);
        Some(Self { kind, nonce })
    }
}

/// Unique nonces: a counter makes them distinct, a per-process random hash of the
/// counter makes stale replies from earlier processes unlikely to match. The nonce
/// is not a secret; authenticity comes from the session key.
pub(crate) struct NonceSource {
    counter: AtomicU64,
    mix: RandomState,
}

impl NonceSource {
    pub(crate) fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            mix: RandomState::new(),
        }
    }

    pub(crate) fn next(&self) -> [u8; NONCE_LEN] {
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&count.to_le_bytes());
        nonce[8..].copy_from_slice(&self.mix.hash_one(count).to_le_bytes());
        nonce
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn nonce() -> [u8; NONCE_LEN] {
        std::array::from_fn(|index| u8::try_from(index).expect("index fits a byte"))
    }

    #[test]
    fn encoding_has_the_documented_layout() {
        let ping = Frame {
            kind: Kind::Ping,
            nonce: nonce(),
        };
        let mut expected = b"shaar-yg".to_vec();
        expected.extend_from_slice(&[1, 1]);
        expected.extend_from_slice(&nonce());
        assert_eq!(ping.encode().to_vec(), expected);
        assert_eq!(ping.encode().len(), FRAME_LEN);
        let pong = Frame {
            kind: Kind::Pong,
            nonce: nonce(),
        };
        assert_eq!(pong.encode()[9], 2);
    }

    #[test]
    fn both_kinds_round_trip() {
        for kind in [Kind::Ping, Kind::Pong] {
            let frame = Frame {
                kind,
                nonce: nonce(),
            };
            assert_eq!(Frame::decode(&frame.encode()), Some(frame));
        }
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let good = Frame {
            kind: Kind::Ping,
            nonce: nonce(),
        }
        .encode();
        assert_eq!(Frame::decode(&[]), None);
        assert_eq!(Frame::decode(&good[..FRAME_LEN - 1]), None);
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(Frame::decode(&long), None);
        for (index, bad) in [(0, b'x'), (8, 2), (9, 0), (9, 3), (9, 255)] {
            let mut frame = good;
            frame[index] = bad;
            assert_eq!(Frame::decode(&frame), None, "byte {index} set to {bad}");
        }
    }

    #[test]
    fn nonces_are_distinct_and_count_up() {
        let source = NonceSource::new();
        let mut seen = HashSet::new();
        for expected in 0u64..10_000 {
            let nonce = source.next();
            assert_eq!(nonce[..8], expected.to_le_bytes());
            assert!(seen.insert(nonce), "nonce repeated at {expected}");
        }
    }
}
