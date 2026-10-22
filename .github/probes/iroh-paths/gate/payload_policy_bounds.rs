#![forbid(unsafe_code)]
//! Direct tests of the actual Noq receive queue and budget contract.

use super::{Datagram, DatagramState};
use bytes::Bytes;

fn datagram(data: &'static [u8]) -> Datagram {
    Datagram {
        data: Bytes::from_static(data),
    }
}

#[test]
fn empty_receive_cardinality_and_batch_release() {
    let mut state = DatagramState::default();
    for index in 0..32 {
        let notify = state.received(datagram(b""), &Some(4)).unwrap();
        assert_eq!(
            notify,
            index == 0,
            "notify only on empty-to-nonempty transition"
        );
        assert!(
            state.incoming.len() <= 4,
            "empty records consume queue slots"
        );
        assert!(state.recv_buffered <= 4);
    }
    assert_eq!(state.incoming.len(), 4);
    assert_eq!(state.recv_buffered, 4);
    let mut output = [Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new()];
    assert_eq!(state.recv_many(&mut output), 4);
    assert!(output.iter().all(Bytes::is_empty));
    assert!(state.incoming.is_empty());
    assert_eq!(state.recv_buffered, 0);
    assert!(state.received(datagram(b""), &Some(4)).unwrap());
    assert_eq!(state.recv(), Some(Bytes::new()));
    assert_eq!(state.recv_buffered, 0);
}

#[test]
fn mixed_receive_eviction_and_single_dequeue_budget() {
    let mut state = DatagramState::default();
    for data in [
        b"".as_slice(),
        b"ab".as_slice(),
        b"".as_slice(),
        b"z".as_slice(),
    ] {
        state.received(datagram(data), &Some(4)).unwrap();
    }
    assert_eq!(state.incoming.len(), 3, "oldest empty record was evicted");
    assert_eq!(state.recv_buffered, 4);
    assert_eq!(state.recv(), Some(Bytes::from_static(b"ab")));
    assert_eq!(state.recv_buffered, 2);
    assert_eq!(state.recv(), Some(Bytes::new()));
    assert_eq!(state.recv_buffered, 1);
    assert_eq!(state.recv(), Some(Bytes::from_static(b"z")));
    assert_eq!(state.recv_buffered, 0);
    assert!(state.recv().is_none());
}

#[test]
fn zero_disabled_and_oversized_receive_budgets_admit_nothing() {
    let mut state = DatagramState::default();
    assert!(state.received(datagram(b""), &Some(0)).is_err());
    assert!(state.received(datagram(b""), &None).is_err());
    assert!(state.received(datagram(b"oversized"), &Some(4)).is_err());
    assert_eq!(state.recv_buffered, 0);
    assert!(state.incoming.is_empty());
}

#[test]
fn outgoing_oversize_removal_releases_empty_record_charge() {
    // One empty record plus two payload bytes consume three budget units.
    let mut state = DatagramState::default();
    state.outgoing.push_back(datagram(b""));
    state.outgoing.push_back(datagram(b"ab"));
    state.outgoing_total = 3;
    assert!(state.drop_oversized(1));
    assert_eq!(state.outgoing.len(), 1);
    assert_eq!(state.outgoing_total, 1);
    assert!(state.drop_oversized(0));
    assert!(state.outgoing.is_empty());
    assert_eq!(state.outgoing_total, 0);
}
