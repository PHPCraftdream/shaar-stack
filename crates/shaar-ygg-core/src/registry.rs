//! Process-wide ownership of public keys: two live transports must never share
//! one key (one key is one address). A claim is released by `close` or a failed
//! start; dropping a transport without closing it keeps its key claimed because
//! its core keeps running.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

static CLAIMED: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();

fn claimed() -> &'static Mutex<HashSet<[u8; 32]>> {
    CLAIMED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Exclusive claim on one public key.
pub(crate) struct KeyClaim {
    key: [u8; 32],
    released: AtomicBool,
}

impl KeyClaim {
    /// Claim `key`, or `None` when another live claim holds it.
    pub(crate) fn acquire(key: [u8; 32]) -> Option<Self> {
        let inserted = claimed()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
        inserted.then(|| Self {
            key,
            released: AtomicBool::new(false),
        })
    }

    /// Give the key back. Idempotent: only the first call frees it, so a repeated
    /// release cannot free a key that another claim acquired meanwhile.
    pub(crate) fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            claimed()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_exclusive_until_released() {
        let key = [0xE1; 32];
        let first = KeyClaim::acquire(key).expect("free key is claimed");
        assert!(KeyClaim::acquire(key).is_none(), "claimed key is refused");
        first.release();
        let second = KeyClaim::acquire(key).expect("released key is free again");
        second.release();
    }

    #[test]
    fn a_repeated_release_cannot_free_a_newer_claim() {
        let key = [0xE2; 32];
        let old = KeyClaim::acquire(key).expect("claimed");
        old.release();
        let new = KeyClaim::acquire(key).expect("reclaimed");
        old.release();
        assert!(
            KeyClaim::acquire(key).is_none(),
            "the newer claim still holds the key"
        );
        new.release();
    }

    #[test]
    fn different_keys_do_not_conflict() {
        let a = KeyClaim::acquire([0xE3; 32]).expect("claimed");
        let b = KeyClaim::acquire([0xE4; 32]).expect("claimed");
        a.release();
        b.release();
    }
}
