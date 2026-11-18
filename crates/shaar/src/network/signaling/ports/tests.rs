//! Tests of the fixed port set and of the order that a client key gives it.

use super::{PORT_COUNT, PORTS, RANGE_START, order};

const RANGE_END: u16 = u16::MAX;

/// A key that is easy to vary: `index` in the first four bytes.
fn key_of(index: u32) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..4].copy_from_slice(&index.to_be_bytes());
    key
}

/// Whether a port is one that the set must not hold: a well-known service, a multiple of 1000 or
/// a port made of one repeated digit.
fn is_popular(port: u16) -> bool {
    const SINGLES: [u16; 26] = [
        30033, 30120, 30303, 30718, 31337, 32400, 32469, 32764, 32768, 32769, 32770, 34197, 35357,
        37777, 38000, 41641, 41794, 44818, 47808, 49152, 51413, 51820, 54321, 58846, 62078, 64738,
    ];
    const RANGES: [(u16, u16); 4] = [
        (32410, 32414),
        (33434, 33534),
        (47984, 48010),
        (60000, 61000),
    ];
    let text = port.to_string();
    let repeated = text.bytes().all(|digit| Some(digit) == text.bytes().next());
    port.is_multiple_of(1000)
        || repeated
        || SINGLES.contains(&port)
        || RANGES
            .iter()
            .any(|&(low, high)| (low..=high).contains(&port))
}

#[test]
fn the_set_is_a_hundred_distinct_ascending_ports_inside_the_range() {
    assert_eq!(PORTS.len(), PORT_COUNT);
    assert_eq!(PORT_COUNT, 100);
    assert!(PORTS.windows(2).all(|pair| pair[0] < pair[1]), "{PORTS:?}");
    assert!(
        PORTS
            .iter()
            .all(|&port| (RANGE_START..=RANGE_END).contains(&port))
    );
}

#[test]
fn no_port_of_the_set_is_popular() {
    let popular: Vec<u16> = PORTS
        .iter()
        .copied()
        .filter(|&port| is_popular(port))
        .collect();
    assert!(popular.is_empty(), "{popular:?}");
    // The check itself must recognise what it is meant to exclude.
    for port in [
        31337, 32400, 33434, 51413, 51820, 60500, 40000, 44444, 55555,
    ] {
        assert!(is_popular(port), "{port}");
    }
    for port in [30061, 46735, 63953] {
        assert!(!is_popular(port), "{port}");
    }
}

#[test]
fn the_set_is_spread_over_the_whole_range() {
    let span = u32::from(RANGE_END) - u32::from(RANGE_START) + 1;
    let mut ninths = [0_u32; 9];
    for &port in &PORTS {
        let index = (u32::from(port) - u32::from(RANGE_START)) * 9 / span;
        ninths[usize::try_from(index).expect("a small index")] += 1;
    }
    assert!(ninths.iter().all(|&count| count >= 5), "{ninths:?}");
}

#[test]
fn the_order_is_a_permutation_of_the_set() {
    for index in [0, 1, 7, 1000, u32::MAX] {
        let mut ordered = order(&key_of(index));
        ordered.sort_unstable();
        assert_eq!(ordered, PORTS, "key {index}");
    }
}

#[test]
fn the_order_follows_the_documented_hash() {
    // Computed outside the code under test: SHA-256 of "shaar-port-order/1", the 32 key bytes and
    // the port as two big-endian bytes, with the digests sorted ascending.
    let counting: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).expect("below 32"));
    let ordered = order(&counting);
    assert_eq!(ordered[..5], [32465, 55216, 45579, 63414, 38206]);
    assert_eq!(ordered[PORT_COUNT - 2..], [47950, 44863]);
    let zero = order(&[0_u8; 32]);
    assert_eq!(zero[..5], [56058, 62721, 55069, 56594, 30061]);
}

#[test]
fn the_same_key_always_gets_the_same_order_and_other_keys_get_other_ones() {
    let first = order(&key_of(1));
    assert_eq!(first, order(&key_of(1)));
    for other in 2..50 {
        assert_ne!(first, order(&key_of(other)), "key {other}");
    }
}

#[test]
fn clients_do_not_all_start_with_the_same_port() {
    let mut first_counts = std::collections::HashMap::new();
    for index in 0..1000 {
        *first_counts
            .entry(order(&key_of(index))[0])
            .or_insert(0_u32) += 1;
    }
    // One thousand keys over a hundred ports: about ten each; the order is a fixed function of
    // the key, so these bounds are exact for this input and fail if the hash stops spreading.
    assert!(
        first_counts.len() >= 90,
        "{} first ports",
        first_counts.len()
    );
    assert!(
        first_counts.values().all(|&count| count <= 40),
        "{first_counts:?}"
    );
}
