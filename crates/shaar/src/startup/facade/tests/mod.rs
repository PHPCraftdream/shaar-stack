//! Facade contracts: value types, builders and the direct shape over real loopback QUIC.

mod builders;
mod direct;
mod peers;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::identity::Identity;

/// A per-test directory below `target/`, removed on drop.
pub(super) struct FixtureDir(pub(super) PathBuf);

impl FixtureDir {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/facade-fixtures");
        std::fs::create_dir_all(&base).expect("fixture parent");
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("fresh fixture directory");
        Self(path)
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A deterministic identity; the seed byte names the actor in a test.
pub(super) fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32])
}
