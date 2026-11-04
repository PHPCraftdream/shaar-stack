// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::owner::RuntimeError;

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClockSample {
    pub(super) wall_us: i64,
    pub(super) monotonic_before_us: u64,
    pub(super) monotonic_after_us: u64,
}

#[derive(Clone)]
pub(super) enum Clock {
    System {
        origin: Instant,
    },
    #[cfg(test)]
    Controlled {
        wall: Arc<AtomicI64>,
        monotonic: Arc<AtomicU64>,
    },
}

impl Clock {
    pub(super) fn system() -> Self {
        Self::System {
            origin: Instant::now(),
        }
    }

    pub(super) fn sample(&self) -> Result<ClockSample, RuntimeError> {
        match self {
            Self::System { origin } => {
                let before = monotonic_window(origin.elapsed())?.0;
                let wall_us = wall_micros()?;
                let after = monotonic_window(origin.elapsed())?.1;
                Ok(ClockSample {
                    wall_us,
                    monotonic_before_us: before,
                    monotonic_after_us: after,
                })
            }
            #[cfg(test)]
            Self::Controlled { wall, monotonic } => {
                let monotonic_us = monotonic.load(Ordering::SeqCst);
                Ok(ClockSample {
                    wall_us: wall.load(Ordering::SeqCst),
                    monotonic_before_us: monotonic_us,
                    monotonic_after_us: monotonic_us,
                })
            }
        }
    }
}

fn monotonic_window(elapsed: std::time::Duration) -> Result<(u64, u64), RuntimeError> {
    let micros = u64::try_from(elapsed.as_micros()).map_err(|_| RuntimeError::Clock)?;
    // Include the independent wall/monotonic microsecond rounding uncertainty.
    let upper = micros.checked_add(1).ok_or(RuntimeError::Clock)?;
    Ok((micros.saturating_sub(1), upper))
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestClock {
    wall: Arc<AtomicI64>,
    monotonic: Arc<AtomicU64>,
}

#[cfg(test)]
impl TestClock {
    pub(super) fn new(wall_us: i64) -> Self {
        Self {
            wall: Arc::new(AtomicI64::new(wall_us)),
            monotonic: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn set(&self, wall_us: i64) {
        self.set_wall(wall_us);
    }

    pub(super) fn set_wall(&self, wall_us: i64) {
        self.wall.store(wall_us, Ordering::SeqCst);
    }

    pub(super) fn set_monotonic(&self, monotonic_us: u64) {
        self.monotonic.store(monotonic_us, Ordering::SeqCst);
    }

    pub(super) fn clock(&self) -> Clock {
        Clock::Controlled {
            wall: Arc::clone(&self.wall),
            monotonic: Arc::clone(&self.monotonic),
        }
    }
}

fn wall_micros() -> Result<i64, RuntimeError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::Clock)?;
    i64::try_from(elapsed.as_micros()).map_err(|_| RuntimeError::Clock)
}

#[cfg(test)]
#[test]
fn system_rounding_window_does_not_invent_a_backward_clock() {
    use super::publisher::PublisherState;
    use crate::identity::Identity;
    use iroh_base::{EndpointId, TransportAddr};
    use std::time::Duration;

    let identity = Identity::from_seed([0x61; 32]);
    let key = EndpointId::from_bytes(&identity.public_key_bytes()).expect("valid key");
    let mut publisher = PublisherState::new(key);
    let addresses = [TransportAddr::Ip(
        "127.0.0.1:9001".parse().expect("address"),
    )];
    // Equal-rate clocks: wall 100.001 -> 101.999, monotonic 0.999 -> 2.997 us.
    for (wall_us, nanos) in [(100, 999), (101, 2997)] {
        let (monotonic_before_us, monotonic_after_us) =
            monotonic_window(Duration::from_nanos(nanos)).expect("bounded window");
        publisher
            .replace(
                &identity,
                &addresses,
                ClockSample {
                    wall_us,
                    monotonic_before_us,
                    monotonic_after_us,
                },
            )
            .expect("rounding alone must not revoke publication");
    }
}

#[cfg(test)]
#[test]
fn system_rounding_window_bounds_zero_edges_and_overflow() {
    use std::time::Duration;
    for (nanos, expected) in [
        (0, (0, 1)),
        (999, (0, 1)),
        (1000, (0, 2)),
        (1999, (0, 2)),
        (2000, (1, 3)),
    ] {
        assert_eq!(
            monotonic_window(Duration::from_nanos(nanos)).expect("window"),
            expected
        );
    }
    assert!(matches!(
        monotonic_window(Duration::from_micros(u64::MAX)),
        Err(RuntimeError::Clock)
    ));
    assert!(matches!(
        monotonic_window(Duration::MAX),
        Err(RuntimeError::Clock)
    ));
}

#[cfg(test)]
#[test]
fn controlled_clock_advances_wall_and_monotonic_independently() {
    let control = TestClock::new(100);
    control.set_monotonic(20);
    let clock = control.clock();
    assert_eq!(
        clock.sample().expect("paired sample"),
        ClockSample {
            wall_us: 100,
            monotonic_before_us: 20,
            monotonic_after_us: 20,
        }
    );
    control.set_wall(90);
    assert_eq!(
        clock.sample().expect("wall rollback sample"),
        ClockSample {
            wall_us: 90,
            monotonic_before_us: 20,
            monotonic_after_us: 20,
        }
    );
    control.set_monotonic(30);
    assert_eq!(
        clock.sample().expect("monotonic progress sample"),
        ClockSample {
            wall_us: 90,
            monotonic_before_us: 30,
            monotonic_after_us: 30,
        }
    );
}
