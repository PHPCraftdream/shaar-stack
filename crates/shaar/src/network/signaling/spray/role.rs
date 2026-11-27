//! Which side of the trial a device plays, told from what its own DHT walks measured (leaf
//! BDAY-1b). Nothing is asked of the owner or of an outside source: the votes are the ones every
//! installation collects, and an unclear picture means no trial.

use super::Role;
use crate::network::observe::{MIN_VOTES, VOTES};

/// The role that a pair of vote counts shows: `voted` nodes told the device its address, under
/// `ports` different ports. One port for every vote is a NAT that keeps its mapping (the easy
/// side); at least half as many ports as votes is a NAT that picks a port per destination (the
/// hard side). Everything else (too few votes, a few distinct ports, counts that contradict each
/// other) shows neither, and the device takes no part.
pub(crate) fn classify(voted: u32, ports: u32) -> Option<Role> {
    if voted < MIN_VOTES || ports == 0 || ports > voted {
        return None;
    }
    if ports == 1 {
        return Some(Role::Easy);
    }
    (u64::from(ports) * 2 >= u64::from(voted)).then_some(Role::Hard)
}

/// The role of this device now, from the latest finished query that collected enough votes;
/// `None` before one has finished, or when the process does not feed the record (the embedding
/// application keeps its own tracing subscriber).
pub(crate) fn local_role() -> Option<Role> {
    VOTES
        .latest()
        .and_then(|(voted, ports)| classify(voted, ports))
}
