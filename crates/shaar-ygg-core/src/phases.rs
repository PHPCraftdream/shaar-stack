//! One-shot trace of a node's first moments (leaf YGG-4a): the core ready, each configured link
//! up or down, the first datagram handed to the core and the first one received. It shows where
//! the first seconds of a cold node go. A line carries a phase name, a link index, a count and
//! milliseconds since the node start, never a URI, key, address or error text. A node prints at
//! most [`MAX_LINES`] lines, so a flapping link cannot flood stderr.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

/// Lines one node may print, links and one-shot phases together.
pub(crate) const MAX_LINES: u8 = 16;
/// Lines the links may take; the rest is kept for the three one-shot phases.
pub(crate) const LINK_LINES: u8 = MAX_LINES - 3;

/// A step of the node start that the trace names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    CoreReady,
    PeerUp,
    PeerDown,
    FirstSend,
    FirstRecv,
}

impl Phase {
    const fn token(self) -> &'static str {
        match self {
            Self::CoreReady => "core-ready",
            Self::PeerUp => "peer-up",
            Self::PeerDown => "peer-down",
            Self::FirstSend => "first-send",
            Self::FirstRecv => "first-recv",
        }
    }

    /// The bit that makes a one-shot phase fire once; links fire on every change.
    const fn once_bit(self) -> Option<u8> {
        match self {
            Self::CoreReady => Some(1),
            Self::FirstSend => Some(2),
            Self::FirstRecv => Some(4),
            Self::PeerUp | Self::PeerDown => None,
        }
    }
}

/// `shaar: ygg phase=<name>[ peer=<index> up=<count>] t_ms=<milliseconds>`
pub(crate) fn render(phase: Phase, link: Option<(usize, usize)>, t_ms: u64) -> String {
    let token = phase.token();
    match link {
        Some((peer, up)) => format!("shaar: ygg phase={token} peer={peer} up={up} t_ms={t_ms}"),
        None => format!("shaar: ygg phase={token} t_ms={t_ms}"),
    }
}

/// The clock and the line budget of one node.
pub(crate) struct Phases {
    origin: Instant,
    lines: AtomicU8,
    fired: AtomicU8,
}

impl Phases {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
            lines: AtomicU8::new(0),
            fired: AtomicU8::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Takes one line of the budget, which is `limit` lines in all.
    fn claim_line(&self, limit: u8) -> bool {
        self.lines
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < limit).then_some(used + 1)
            })
            .is_ok()
    }

    /// True for the first call of a one-shot phase and for every call of a link phase.
    fn fires(&self, phase: Phase) -> bool {
        phase
            .once_bit()
            .is_none_or(|bit| self.fired.fetch_or(bit, Ordering::Relaxed) & bit == 0)
    }

    /// Test seam: whether a one-shot phase has fired.
    #[cfg(test)]
    pub(crate) fn has_fired(&self, phase: Phase) -> bool {
        phase
            .once_bit()
            .is_some_and(|bit| self.fired.load(Ordering::Relaxed) & bit != 0)
    }

    /// Prints a one-shot phase the first time it happens. Never blocks and never fails.
    pub(crate) fn mark(&self, phase: Phase) {
        if self.fires(phase) && self.claim_line(MAX_LINES) {
            eprintln!("{}", render(phase, None, self.elapsed_ms()));
        }
    }

    /// True once the links have used their share of the budget.
    pub(crate) fn links_exhausted(&self) -> bool {
        self.lines.load(Ordering::Relaxed) >= LINK_LINES
    }

    /// Prints the change between two snapshots of the configured links: a line for each link
    /// that came up and for each that went down, with the count of links up after the change.
    pub(crate) fn report(&self, before: LinksUp, now: LinksUp) {
        let up = now.count();
        for (phase, bits) in [
            (Phase::PeerUp, now.0 & !before.0),
            (Phase::PeerDown, before.0 & !now.0),
        ] {
            for peer in (0..LinksUp::MAX).filter(|&peer| (bits >> peer) & 1 == 1) {
                if self.claim_line(LINK_LINES) {
                    eprintln!("{}", render(phase, Some((peer, up)), self.elapsed_ms()));
                }
            }
        }
    }
}

/// Which configured links are up, one bit per configured peer in the order of the list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinksUp(u64);

impl LinksUp {
    /// Links beyond this index are not tracked.
    pub const MAX: usize = 64;

    pub(crate) fn set(&mut self, peer: usize) {
        if peer < Self::MAX {
            self.0 |= 1 << peer;
        }
    }

    /// True when the peer at this position of the configured list is up.
    #[must_use]
    pub fn contains(self, peer: usize) -> bool {
        peer < Self::MAX && (self.0 >> peer) & 1 == 1
    }

    /// How many configured links are up.
    #[must_use]
    pub fn count(self) -> usize {
        self.0.count_ones() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_names_the_phase_the_link_the_count_and_the_time_only() {
        assert_eq!(
            render(Phase::CoreReady, None, 12),
            "shaar: ygg phase=core-ready t_ms=12"
        );
        assert_eq!(
            render(Phase::PeerUp, Some((1, 2)), 3_400),
            "shaar: ygg phase=peer-up peer=1 up=2 t_ms=3400"
        );
        assert_eq!(
            render(Phase::PeerDown, Some((0, 1)), 9),
            "shaar: ygg phase=peer-down peer=0 up=1 t_ms=9"
        );
        assert_eq!(
            render(Phase::FirstSend, None, 7),
            "shaar: ygg phase=first-send t_ms=7"
        );
        assert_eq!(
            render(Phase::FirstRecv, None, 8),
            "shaar: ygg phase=first-recv t_ms=8"
        );
    }

    #[test]
    fn a_one_shot_phase_fires_once_and_a_link_phase_every_time() {
        let phases = Phases::new();
        for phase in [Phase::CoreReady, Phase::FirstSend, Phase::FirstRecv] {
            assert!(phases.fires(phase), "{phase:?} must fire the first time");
            assert!(!phases.fires(phase), "{phase:?} must not fire again");
        }
        for phase in [Phase::PeerUp, Phase::PeerDown] {
            assert!(phases.fires(phase));
            assert!(phases.fires(phase));
        }
    }

    #[test]
    fn links_cannot_take_the_lines_of_the_one_shot_phases() {
        let phases = Phases::new();
        for _ in 0..LINK_LINES {
            assert!(!phases.links_exhausted());
            assert!(phases.claim_line(LINK_LINES));
        }
        assert!(phases.links_exhausted());
        assert!(!phases.claim_line(LINK_LINES), "the link share is spent");
        for _ in 0..MAX_LINES - LINK_LINES {
            assert!(phases.claim_line(MAX_LINES), "a one-shot line is kept free");
        }
        assert!(!phases.claim_line(MAX_LINES), "the whole budget is spent");
        assert_eq!(phases.lines.load(Ordering::Relaxed), MAX_LINES);
    }

    #[test]
    fn the_set_of_links_counts_and_ignores_indexes_it_cannot_hold() {
        let mut up = LinksUp::default();
        assert_eq!(up.count(), 0);
        up.set(0);
        up.set(3);
        up.set(3);
        up.set(LinksUp::MAX);
        up.set(usize::MAX);
        assert_eq!(up.count(), 2);
        assert!(up.contains(0) && up.contains(3));
        assert!(!up.contains(1) && !up.contains(LinksUp::MAX) && !up.contains(usize::MAX));
    }

    #[test]
    fn report_stays_inside_the_link_share() {
        let phases = Phases::new();
        let mut one = LinksUp::default();
        one.set(0);
        for _ in 0..LINK_LINES * 2 {
            phases.report(LinksUp::default(), one);
            phases.report(one, LinksUp::default());
        }
        assert_eq!(phases.lines.load(Ordering::Relaxed), LINK_LINES);
        assert!(phases.links_exhausted());
    }
}
