// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

use crate::resource::{ResourceError, StoreBudget, VisitedLease};

#[derive(Debug)]
pub(crate) struct VisitedStore {
    budget: Arc<StoreBudget>,
    entries: HashMap<SocketAddrV4, VisitedLease>,
}

impl VisitedStore {
    pub(crate) fn new(budget: Arc<StoreBudget>) -> Self {
        Self {
            budget,
            entries: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, address: SocketAddrV4) -> Result<bool, ResourceError> {
        if self.entries.contains_key(&address) {
            return Ok(false);
        }
        let lease = self.budget.reserve_visited()?;
        self.entries.insert(address, lease);
        Ok(true)
    }

    pub(crate) fn contains(&self, address: &SocketAddrV4) -> bool {
        self.entries.contains_key(address)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn owner_count(&self) -> usize {
        self.budget.visited_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn multiple_visited_stores_share_limit_and_release_leases_on_drop() {
        let budget = Arc::new(StoreBudget::default());
        let mut first = VisitedStore::new(Arc::clone(&budget));
        let mut second = VisitedStore::new(Arc::clone(&budget));

        for port in 1..=128 {
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            assert!(first.insert(address).expect("first store admits address"));
            assert!(
                !first
                    .insert(address)
                    .expect("duplicate does not charge again")
            );
        }
        for port in 129..=256 {
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            assert!(
                second
                    .insert(address)
                    .expect("second store shares owner budget")
            );
        }

        assert_eq!(first.len() + second.len(), 256);
        assert_eq!(first.owner_count(), 256);
        let overflow = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 257);
        assert_eq!(second.insert(overflow), Err(ResourceError::VisitedLimit));
        assert_eq!(second.len(), 128);

        drop(first);
        assert_eq!(second.owner_count(), 128);
        assert!(
            second
                .insert(overflow)
                .expect("drop releases first store leases")
        );
        assert!(second.contains(&overflow));
    }
}
