#![forbid(unsafe_code)]
//! Bounded relay lease validation, shared with the prepared dependency.

use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    pub(crate) renew_after: Duration,
    pub(crate) expires_after: Duration,
}

/// Validate both lifetimes before constructing any timer or monotonic deadline.
pub(crate) fn lease(expire: u64, now_since_epoch: Option<Duration>) -> Option<Lease> {
    let now = now_since_epoch?;
    let remaining_seconds = expire.checked_sub(now.as_secs())?;
    if !(1..=86_400).contains(&remaining_seconds) {
        return None;
    }
    let expires_after = Duration::from_secs(expire).checked_sub(now)?;
    Some(Lease {
        renew_after: expires_after - expires_after / 4,
        expires_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_lease_renews_at_three_quarters_without_losing_expiry() {
        for (expire, renew, remaining) in [(104, 3, 4), (3700, 2700, 3600)] {
            assert_eq!(
                lease(expire, Some(Duration::from_secs(100))),
                Some(Lease {
                    renew_after: Duration::from_secs(renew),
                    expires_after: Duration::from_secs(remaining),
                })
            );
        }
    }

    #[test]
    fn minimum_and_maximum_accepted_durations_are_exact() {
        for (expire, renew, remaining) in [(101, 750, 1), (86_500, 64_800_000, 86_400)] {
            assert_eq!(
                lease(expire, Some(Duration::from_secs(100))),
                Some(Lease {
                    renew_after: Duration::from_millis(renew),
                    expires_after: Duration::from_secs(remaining),
                })
            );
        }
    }

    #[test]
    fn expired_zero_and_huge_peer_expiry_never_reach_timer_arithmetic() {
        for expire in [0, 99, 100, 86_501, u64::MAX] {
            assert_eq!(lease(expire, Some(Duration::from_secs(100))), None);
        }
    }

    #[test]
    fn fractional_epoch_time_does_not_extend_the_offered_lease() {
        assert_eq!(
            lease(101, Some(Duration::from_millis(100_900))),
            Some(Lease {
                renew_after: Duration::from_millis(75),
                expires_after: Duration::from_millis(100),
            })
        );
    }

    #[test]
    fn local_clock_before_epoch_fails_without_panicking() {
        assert_eq!(lease(3600, None), None);
    }
}
