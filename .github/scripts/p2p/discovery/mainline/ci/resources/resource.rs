// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

#[path = "owned_completion.rs"]
mod completion;
#[path = "store_owner.rs"]
mod store_owner;
#[cfg(test)]
#[path = "store_resource_tests.rs"]
mod store_resource_tests;
#[path = "visited_store.rs"]
mod visited_store;

pub use completion::{OwnedPutCompletion, OwnedPutError, OwnedPutOperation};
pub(crate) use completion::ChargedPutReceiver;
pub use completion::OwnedQueryCompletion;
pub(crate) use completion::{ChargedResultReceiver, RequestBudget, RequestLease, RequestReply};
pub(crate) use completion::{ResultBudget, ResultLease};
pub(crate) use store_owner::{HolderLease, StoreBudget, VisitedLease};
pub(crate) use visited_store::VisitedStore;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct OperationId(u64);

impl OperationId {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }
    pub(crate) fn value(self) -> u64 { self.0 }
}

/// Errors reported when an owned Mainline operation exceeds a resource or profile constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResourceError {
    /// The aggregate retained-candidate holder limit of 256 was reached.
    CandidateLimit,
    /// The actor operation or bounded waiting queue is full.
    OperationLimit,
    /// The bounded result backlog was exceeded.
    ResultLimit,
    /// The aggregate visited-address limit of 256 was reached.
    VisitedLimit,
    /// The owned RPC budget was exceeded (128 aggregate, or 16 for one operation).
    RpcLimit,
    /// The native socket transaction identifier space was exhausted.
    TransactionSpaceExhausted,
    /// The owned datagram outbox reached its capacity of 128.
    OutboxFull,
    /// An encoded datagram exceeded the maximum size of 2048 bytes.
    DatagramTooLarge,
    /// Encoding an owned datagram failed.
    Encode,
    /// Enqueuing an owned datagram failed.
    Enqueue,
    /// Sending an owned datagram failed.
    Send,
    /// An operation requiring owned resources was used with another profile.
    NotOwnedProfile,
    /// The actor query was cancelled before its result could be delivered.
    QueryCancelled,
    /// The original absolute caller deadline elapsed.
    DeadlineExceeded,
    /// The mutable item violates the owned unsalted PUT constraints.
    InvalidMutableItem,
}

impl ResourceError {
    pub(crate) fn io_kind(self) -> std::io::ErrorKind {
        match self {
            Self::CandidateLimit
            | Self::VisitedLimit
            | Self::RpcLimit
            | Self::TransactionSpaceExhausted
            | Self::OutboxFull
            | Self::OperationLimit
            | Self::ResultLimit => std::io::ErrorKind::WouldBlock,
            Self::Send => std::io::ErrorKind::BrokenPipe,
            Self::QueryCancelled => std::io::ErrorKind::Interrupted,
            Self::DeadlineExceeded => std::io::ErrorKind::TimedOut,
            Self::InvalidMutableItem => std::io::ErrorKind::InvalidInput,
            Self::DatagramTooLarge | Self::Encode | Self::Enqueue | Self::NotOwnedProfile => {
                std::io::ErrorKind::InvalidInput
            }
        }
    }
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mainline resource admission failed: {self:?}")
    }
}

impl std::error::Error for ResourceError {}
