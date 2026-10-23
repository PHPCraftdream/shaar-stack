#![forbid(unsafe_code)]
//! Counted raw-datagram admission; the channel, not these counters, publishes data.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
pub(crate) struct Budget {
    used: AtomicUsize,
    capacity: usize,
}

impl Budget {
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            capacity,
        })
    }

    pub(crate) fn reserve(self: &Arc<Self>, amount: usize) -> Option<Lease> {
        let amount = amount.max(1);
        // Relaxed is accounting only; ownership transfer uses the channel's ordering.
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(amount)
                    .filter(|total| *total <= self.capacity)
            })
            .ok()?;
        Some(Lease {
            budget: self.clone(),
            amount,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Lease {
    budget: Arc<Budget>,
    amount: usize,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let previous = self.budget.used.fetch_sub(self.amount, Ordering::Relaxed);
        debug_assert!(previous >= self.amount);
    }
}

#[derive(Debug)]
pub(crate) enum BufferHold {
    Unique { _lease: Lease },
    Shared { _lease: Arc<Lease> },
}

#[derive(Debug)]
pub(crate) enum BufferBatch {
    Unique(Option<Lease>),
    Shared(Arc<Lease>),
}

impl BufferBatch {
    pub(crate) fn new(lease: Lease, coalesced: bool) -> Self {
        if coalesced {
            Self::Shared(Arc::new(lease))
        } else {
            Self::Unique(Some(lease))
        }
    }

    fn hold(&mut self) -> Option<BufferHold> {
        match self {
            Self::Unique(lease) => lease
                .take()
                .map(|lease| BufferHold::Unique { _lease: lease }),
            Self::Shared(lease) => Some(BufferHold::Shared {
                _lease: lease.clone(),
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Queued<T> {
    pub(crate) event: T,
    _packet: Lease,
    _buffer: BufferHold,
}

impl<T> Queued<T> {
    pub(crate) fn new(event: T, packets: &Arc<Budget>, buffer: &mut BufferBatch) -> Option<Self> {
        let packet = packets.reserve(1)?;
        let buffer = buffer.hold()?;
        Some(Self {
            event,
            _packet: packet,
            _buffer: buffer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn exact_capacity_zero_charge_and_overflow_fail_closed() {
        let empty = Budget::new(0);
        assert!(empty.reserve(0).is_none());
        let budget = Budget::new(2);
        let first = budget.reserve(0).unwrap();
        let second = budget.reserve(1).unwrap();
        assert!(budget.reserve(1).is_none());
        drop(first);
        assert_eq!(budget.used.load(Ordering::Relaxed), 1);
        drop(second);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        let large = Budget::new(usize::MAX);
        let maximum = large.reserve(usize::MAX).unwrap();
        assert!(large.reserve(1).is_none());
        drop(maximum);
        assert!(large.reserve(1).is_some());
    }

    #[test]
    fn shared_backing_is_charged_once_until_the_last_owner_drops() {
        let bytes = Budget::new(64);
        let packets = Budget::new(2);
        let mut batch = BufferBatch::new(bytes.reserve(64).unwrap(), true);
        let first = Queued::new(1, &packets, &mut batch).unwrap();
        let second = Queued::new(2, &packets, &mut batch).unwrap();
        assert_eq!((first.event, second.event), (1, 2));
        assert!(Queued::new(3, &packets, &mut batch).is_none());
        assert_eq!(bytes.used.load(Ordering::Relaxed), 64);
        drop(batch);
        drop(first);
        assert_eq!(bytes.used.load(Ordering::Relaxed), 64);
        drop(second);
        assert_eq!(bytes.used.load(Ordering::Relaxed), 0);
        assert_eq!(packets.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn single_buffer_cannot_be_issued_twice_and_rolls_back_packet_reservation() {
        let bytes = Budget::new(32);
        let packets = Budget::new(2);
        let mut batch = BufferBatch::new(bytes.reserve(32).unwrap(), false);
        let queued = Queued::new(7, &packets, &mut batch).unwrap();
        assert!(Queued::new(8, &packets, &mut batch).is_none());
        assert_eq!(packets.used.load(Ordering::Relaxed), 1);
        drop(batch);
        assert_eq!(bytes.used.load(Ordering::Relaxed), 32);
        drop(queued);
        assert_eq!(bytes.used.load(Ordering::Relaxed), 0);
        assert_eq!(packets.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn failed_send_and_receiver_shutdown_return_all_leases() {
        for closed_before_send in [false, true] {
            let bytes = Budget::new(32);
            let packets = Budget::new(2);
            let (sender, receiver) = mpsc::sync_channel(1);
            let mut receiver = Some(receiver);
            if closed_before_send {
                drop(receiver.take());
            }
            let mut batch = BufferBatch::new(bytes.reserve(32).unwrap(), false);
            let result = sender.send(Queued::new((), &packets, &mut batch).unwrap());
            assert_eq!(result.is_err(), closed_before_send);
            drop(result);
            drop(receiver);
            drop(batch);
            assert_eq!(bytes.used.load(Ordering::Relaxed), 0);
            assert_eq!(packets.used.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_budget() {
        let budget = Budget::new(2);
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut workers = Vec::with_capacity(4);
        for _ in 0..4 {
            let (budget, sender) = (budget.clone(), sender.clone());
            workers.push(std::thread::spawn(move || {
                sender.send(budget.reserve(1)).unwrap()
            }));
        }
        drop(sender);
        let mut leases = Vec::with_capacity(4);
        let mut receive_error = None;
        for _ in 0..4 {
            match receiver.recv_timeout(Duration::from_secs(5)) {
                Ok(lease) => leases.push(lease),
                Err(error) => {
                    receive_error = Some(error);
                    break;
                }
            }
        }
        let joined: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        assert!(joined.iter().all(Result::is_ok));
        assert!(receive_error.is_none());
        assert_eq!(leases.iter().filter(|lease| lease.is_some()).count(), 2);
        assert_eq!(budget.used.load(Ordering::Relaxed), 2);
        drop(leases);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }
}
