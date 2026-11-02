// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use crate::common::{ClosestNodes, Id, Node, RoutingTable};
use crate::resource::{ResourceError, StoreBudget};

fn id_at_distance(distance: u8, index: usize) -> Id {
    assert!((1..=160).contains(&distance));
    let mut bytes = [0_u8; 20];
    let bit_from_left = 160 - usize::from(distance);
    bytes[bit_from_left / 8] = 1 << (7 - bit_from_left % 8);
    let suffix = u32::try_from(index)
        .expect("test node identity index")
        .to_be_bytes();
    bytes[16..].copy_from_slice(&suffix);
    Id::from(bytes)
}

fn node(index: usize, distance: u8) -> Node {
    let octets = [
        10,
        ((index / 65_536) % 256) as u8,
        ((index / 256) % 256) as u8,
        (index % 256) as u8,
    ];
    Node::new(
        id_at_distance(distance, index),
        SocketAddrV4::new(
            Ipv4Addr::from(octets),
            u16::try_from(index + 1).expect("test node port"),
        ),
    )
}

#[test]
fn closest_node_entries_hold_budget_leases_through_capacity_and_drop() {
    let budget = Arc::new(StoreBudget::default());
    let mut closest = ClosestNodes::new(Id::from([0_u8; 20]));
    closest.enable_owner_budget(Arc::clone(&budget));

    for index in 0..256 {
        closest
            .add_owned(node(index + 1, (index % 128 + 33) as u8))
            .expect("candidate admitted through boundary");
    }
    assert_eq!(closest.len(), 256);
    assert_eq!(budget.holder_count(), 256);
    assert_eq!(
        closest.add_owned(node(300, 160)),
        Err(ResourceError::CandidateLimit)
    );
    assert_eq!(closest.len(), 256);

    drop(closest);
    assert_eq!(budget.holder_count(), 0);
}

#[test]
fn two_real_routing_tables_share_holders_and_remove_releases_one_lease() {
    let budget = Arc::new(StoreBudget::default());
    let target = Id::from([0_u8; 20]);
    let mut first = RoutingTable::new(target);
    let mut second = RoutingTable::new(target);
    first.enable_owner_budget(Arc::clone(&budget));
    second.enable_owner_budget(Arc::clone(&budget));

    for distance in 33..=160 {
        assert!(
            first
                .add_owned(node(usize::from(distance), distance))
                .expect("first routing holder admitted")
        );
    }
    for distance in 33..=160 {
        assert!(
            second
                .add_owned(node(usize::from(distance) + 256, distance))
                .expect("second routing holder admitted")
        );
    }

    assert_eq!(first.size() + second.size(), 256);
    assert_eq!(budget.holder_count(), 256);
    assert_eq!(
        second.add_owned(node(900, 160)),
        Err(ResourceError::CandidateLimit)
    );

    let removed = *first.nodes().next().expect("stored routing node").id();
    first.remove(&removed);
    assert_eq!(budget.holder_count(), 255);
    assert!(
        second
            .add_owned(node(901, 160))
            .expect("released holder quota is reusable")
    );
    assert_eq!(budget.holder_count(), 256);
}

#[test]
fn simultaneous_closest_stores_share_the_owner_budget_and_coalesce_duplicates() {
    let budget = Arc::new(StoreBudget::default());
    let target = Id::from([0_u8; 20]);
    let mut first = ClosestNodes::new(target);
    let mut second = ClosestNodes::new(target);
    first.enable_owner_budget(Arc::clone(&budget));
    second.enable_owner_budget(Arc::clone(&budget));

    let repeated = node(1, 33);
    first
        .add_owned(repeated.clone())
        .expect("first candidate retained");
    first
        .add_owned(repeated)
        .expect("duplicate candidate coalesced");
    for index in 1..128 {
        first
            .add_owned(node(index + 1, (index % 128 + 33) as u8))
            .expect("first query candidate");
    }
    for index in 0..128 {
        second
            .add_owned(node(index + 300, (index % 128 + 33) as u8))
            .expect("second query shares remaining owner capacity");
    }

    assert_eq!(first.len() + second.len(), 256);
    assert_eq!(budget.holder_count(), 256);
    assert_eq!(
        second.add_owned(node(700, 159)),
        Err(ResourceError::CandidateLimit)
    );
}
