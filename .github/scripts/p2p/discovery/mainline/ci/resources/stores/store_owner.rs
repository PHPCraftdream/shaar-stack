// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::resource::ResourceError;

pub(crate) const HOLDER_LIMIT: usize = 256;
pub(crate) const VISITED_LIMIT: usize = 256;

/// Shared aggregate counters for retained candidate holders and visited addresses.
/// Counters account logical entries; clones of a lease are intentionally unsupported.
#[derive(Debug, Default)]
pub(crate) struct StoreBudget {
    holders: AtomicUsize,
    visited: AtomicUsize,
}

impl StoreBudget {
    /// Reserve one holder before inserting its node into an owning store.
    pub(crate) fn reserve_holder(self: &Arc<Self>) -> Result<HolderLease, ResourceError> {
        reserve(&self.holders, HOLDER_LIMIT, ResourceError::CandidateLimit)?;
        Ok(HolderLease {
            budget: Arc::clone(self),
        })
    }

    /// Reserve one visited address before inserting it into an operation's visited set.
    pub(crate) fn reserve_visited(self: &Arc<Self>) -> Result<VisitedLease, ResourceError> {
        reserve(&self.visited, VISITED_LIMIT, ResourceError::VisitedLimit)?;
        Ok(VisitedLease {
            budget: Arc::clone(self),
        })
    }

    pub(crate) fn holder_count(&self) -> usize {
        self.holders.load(Ordering::Acquire)
    }

    pub(crate) fn visited_count(&self) -> usize {
        self.visited.load(Ordering::Acquire)
    }
}

fn reserve(counter: &AtomicUsize, limit: usize, error: ResourceError) -> Result<(), ResourceError> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return Err(error);
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

/// A non-cloneable reservation for one retained candidate holder.
#[derive(Debug)]
pub(crate) struct HolderLease {
    budget: Arc<StoreBudget>,
}

impl Drop for HolderLease {
    fn drop(&mut self) {
        self.budget.holders.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A non-cloneable reservation for one retained visited address.
#[derive(Debug)]
pub(crate) struct VisitedLease {
    budget: Arc<StoreBudget>,
}

impl Drop for VisitedLease {
    fn drop(&mut self) {
        self.budget.visited.fetch_sub(1, Ordering::AcqRel);
    }
}
