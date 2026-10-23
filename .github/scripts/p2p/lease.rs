#![forbid(unsafe_code)]
//! Bounded relay expiry validation, shared with the prepared dependency.

use std::time::Duration;

/// Reject expired, immediate or excessively distant leases before constructing a timer.
pub(crate) fn renewal_delay(expire: u64, now_epoch_seconds: Option<u64>) -> Option<Duration> {
    let remaining = expire.checked_sub(now_epoch_seconds?)?;
    if !(1..=86_400).contains(&remaining) {
        return None;
    }
    Some(Duration::from_secs(remaining - remaining / 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_lease_renews_at_three_quarters() {
        let now = Some(100);
        assert_eq!(renewal_delay(104, now), Some(Duration::from_secs(3)));
        assert_eq!(renewal_delay(3700, now), Some(Duration::from_secs(2700)));
    }

    #[test]
    fn minimum_and_maximum_accepted_durations_are_exact() {
        let now = Some(100);
        assert_eq!(renewal_delay(101, now), Some(Duration::from_secs(1)));
        assert_eq!(
            renewal_delay(86_500, now),
            Some(Duration::from_secs(64_800))
        );
    }

    #[test]
    fn expired_zero_and_huge_peer_expiry_never_reach_timer_arithmetic() {
        let now = Some(100);
        for expire in [0, 99, 100, 86_501, u64::MAX] {
            assert_eq!(renewal_delay(expire, now), None);
        }
    }

    #[test]
    fn local_clock_before_epoch_fails_without_panicking() {
        assert_eq!(renewal_delay(3600, None), None);
    }
}
