// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crate::resource::ResourceError;

pub(crate) const HOLDER_LIMIT: usize = 256;
pub(crate) const VISITED_LIMIT: usize = 256;

/// Shared aggregate counters for retained candidate holders and visited addresses.
/// Counters account logical entries; clones of a lease are intentionally unsupported.
#[derive(Debug, Default)]
pub(crate) struct StoreBudget {
    holders: AtomicUsize,
    visited: AtomicUsize,
    first_error: AtomicU8,
}

impl StoreBudget {
    /// Reserve one holder before inserting its node into an owning store.
    pub(crate) fn reserve_holder(self: &Arc<Self>) -> Result<HolderLease, ResourceError> {
        reserve(&self.holders, HOLDER_LIMIT, ResourceError::CandidateLimit)
            .map_err(|error| self.remember(error))?;
        Ok(HolderLease {
            budget: Arc::clone(self),
        })
    }

    /// Reserve one visited address before inserting it into an operation's visited set.
    pub(crate) fn reserve_visited(self: &Arc<Self>) -> Result<VisitedLease, ResourceError> {
        reserve(&self.visited, VISITED_LIMIT, ResourceError::VisitedLimit)
            .map_err(|error| self.remember(error))?;
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

    /// Inspect the first capacity error without clearing the sticky owner status.
    pub(crate) fn peek_error(&self) -> Option<ResourceError> {
        match self.first_error.load(Ordering::Acquire) {
            1 => Some(ResourceError::CandidateLimit),
            2 => Some(ResourceError::VisitedLimit),
            _ => None,
        }
    }

    /// Return and clear the first capacity error recorded by this owner.
    pub(crate) fn take_error(&self) -> Option<ResourceError> {
        match self.first_error.swap(0, Ordering::AcqRel) {
            1 => Some(ResourceError::CandidateLimit),
            2 => Some(ResourceError::VisitedLimit),
            _ => None,
        }
    }

    fn remember(&self, error: ResourceError) -> ResourceError {
        let code = match error {
            ResourceError::CandidateLimit => 1,
            ResourceError::VisitedLimit => 2,
            _ => return error,
        };
        let _ = self
            .first_error
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Relaxed);
        error
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
