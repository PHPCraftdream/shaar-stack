//! Bounded table of probes that wait for a reply. Pure state: callers lock it
//! briefly and never across an `.await`.

use std::collections::HashMap;

use tokio::sync::oneshot;

use crate::ProbeError;
use crate::frame::NONCE_LEN;

/// At most this many probes may wait for a reply at once.
pub const MAX_PENDING_PROBES: usize = 8;

/// One probe waiting for the reply of one peer.
pub(crate) struct Waiter {
    pub(crate) peer: [u8; 32],
    pub(crate) done: oneshot::Sender<()>,
}

#[derive(Default)]
pub(crate) struct Pending {
    waiters: HashMap<[u8; NONCE_LEN], Waiter>,
    closed: bool,
}

impl Pending {
    pub(crate) fn register(
        &mut self,
        nonce: [u8; NONCE_LEN],
        waiter: Waiter,
    ) -> Result<(), ProbeError> {
        if self.closed {
            return Err(ProbeError::Closed);
        }
        if self.waiters.len() >= MAX_PENDING_PROBES {
            return Err(ProbeError::Busy);
        }
        self.waiters.insert(nonce, waiter);
        Ok(())
    }

    /// True when `from` is the awaited peer and `nonce` the awaited one; the waiter
    /// is then released with a result. Anything else leaves the table untouched.
    pub(crate) fn complete(&mut self, nonce: &[u8; NONCE_LEN], from: &[u8; 32]) -> bool {
        if !self
            .waiters
            .get(nonce)
            .is_some_and(|waiter| waiter.peer == *from)
        {
            return false;
        }
        if let Some(waiter) = self.waiters.remove(nonce) {
            let _ = waiter.done.send(());
        }
        true
    }

    pub(crate) fn remove(&mut self, nonce: &[u8; NONCE_LEN]) {
        self.waiters.remove(nonce);
    }

    /// Refuse new probes and release every waiter without a result. Idempotent.
    pub(crate) fn close(&mut self) {
        self.closed = true;
        self.waiters.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.waiters.len()
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot::error::TryRecvError;

    use super::*;

    const PEER: [u8; 32] = [7; 32];
    const OTHER: [u8; 32] = [8; 32];

    fn nonce(byte: u8) -> [u8; NONCE_LEN] {
        [byte; NONCE_LEN]
    }

    fn waiter(peer: [u8; 32]) -> (Waiter, oneshot::Receiver<()>) {
        let (done, reply) = oneshot::channel();
        (Waiter { peer, done }, reply)
    }

    #[test]
    fn only_the_awaited_peer_with_the_awaited_nonce_completes() {
        let mut pending = Pending::default();
        let (entry, mut reply) = waiter(PEER);
        pending.register(nonce(1), entry).expect("register");
        assert!(!pending.complete(&nonce(1), &OTHER), "wrong key");
        assert!(!pending.complete(&nonce(2), &PEER), "wrong nonce");
        assert_eq!(reply.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(pending.len(), 1);
        assert!(pending.complete(&nonce(1), &PEER));
        assert_eq!(reply.try_recv(), Ok(()));
        assert_eq!(pending.len(), 0);
        assert!(!pending.complete(&nonce(1), &PEER), "a reply counts once");
    }

    #[test]
    fn the_table_is_bounded_and_frees_slots() {
        let mut pending = Pending::default();
        let mut replies = Vec::new();
        for index in 0..MAX_PENDING_PROBES {
            let (entry, reply) = waiter(PEER);
            let byte = u8::try_from(index).expect("small index");
            pending.register(nonce(byte), entry).expect("within bound");
            replies.push(reply);
        }
        let (extra, _reply) = waiter(PEER);
        assert_eq!(pending.register(nonce(100), extra), Err(ProbeError::Busy));
        pending.remove(&nonce(0));
        let (again, _reply) = waiter(PEER);
        assert_eq!(pending.register(nonce(100), again), Ok(()));
        assert_eq!(pending.len(), MAX_PENDING_PROBES);
    }

    #[test]
    fn close_releases_waiters_refuses_new_probes_and_is_idempotent() {
        let mut pending = Pending::default();
        let (entry, mut reply) = waiter(PEER);
        pending.register(nonce(1), entry).expect("register");
        pending.close();
        pending.close();
        assert_eq!(reply.try_recv(), Err(TryRecvError::Closed));
        assert_eq!(pending.len(), 0);
        let (late, _reply) = waiter(PEER);
        assert_eq!(pending.register(nonce(2), late), Err(ProbeError::Closed));
    }
}
