// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddrV4;
use std::sync::{Arc, OnceLock};

use crate::actor::{Actor, socket::KrpcSocket};
use crate::common::{Id, Node, RequestSpecific, RequestTypeSpecific};
use crate::core::iterative_query::{GetRequestSpecific, IterativeQuery};
use crate::core::put_query::PutQuery;
use crate::core::{PutError, PutQueryError};
use crate::resource::{
    HolderLease, OperationId, OwnedQueryCompletion, RequestBudget, RequestLease, RequestReply,
    ResourceError, ResultBudget, ResultLease, StoreBudget, VisitedLease,
};

#[path = "owned_resources/admission.rs"]
mod admission;
#[path = "owned_resources/failure.rs"]
mod failure;
#[path = "owned_resources/maintenance.rs"]
mod maintenance;
#[path = "owned_resources/queries.rs"]
mod queries;
#[path = "owned_resources/put.rs"]
mod put;
#[path = "owned_resources/tick.rs"]
mod tick;

#[derive(Debug)]
struct PendingRequest {
    target: Id,
    sender: tokio::sync::oneshot::Sender<Result<OwnedQueryCompletion, ResourceError>>,
    deadline: tokio::time::Instant,
}

#[derive(Debug)]
struct PendingAdmission {
    target: Id,
    sender: tokio::sync::oneshot::Sender<RequestReply>,
    deadline: tokio::time::Instant,
    request_lease: Arc<RequestLease>,
}
#[derive(Debug)]
pub(super) struct PendingPut {
    pub(super) target: Id,
    pub(super) request: crate::common::PutMutableRequestArguments,
    pub(super) reply: tokio::sync::oneshot::Sender<Result<crate::resource::ChargedPutReceiver, ResourceError>>,
    pub(super) cleanup: tokio::sync::oneshot::Sender<()>,
    pub(super) cancel: tokio::sync::oneshot::Receiver<()>,
    pub(super) request_lease: Arc<RequestLease>,
    pub(super) deadline: tokio::time::Instant,
}
#[derive(Debug)]
pub(super) struct ActivePut {
    pub(super) operation: OperationId,
    pub(super) result: tokio::sync::oneshot::Sender<Result<crate::resource::OwnedPutCompletion, crate::resource::OwnedPutError>>,
    pub(super) cleanup: tokio::sync::oneshot::Sender<()>,
    pub(super) cancel: tokio::sync::oneshot::Receiver<()>,
    pub(super) result_lease: Arc<ResultLease>,
    pub(super) request_lease: Arc<RequestLease>,
    pub(super) deadline: tokio::time::Instant,
    pub(super) pending_error: Option<ResourceError>,
}
#[derive(Debug)]
struct OwnedWaiter {
    sender: tokio::sync::oneshot::Sender<Result<OwnedQueryCompletion, ResourceError>>,
    deadline: tokio::time::Instant,
    lease: Arc<ResultLease>,
    request_lease: Option<Arc<RequestLease>>,
}

#[derive(Debug)]
pub(crate) struct OwnedActor {
    pub(crate) budget: Arc<StoreBudget>,
    result_budget: Arc<ResultBudget>,
    pub(crate) operations: HashMap<Id, OperationId>,
    pub(crate) maintenance: Option<OperationId>,
    pub(crate) maintenance_retry_at: Option<tokio::time::Instant>,
    pub(crate) terminal: Option<ResourceError>,
    #[cfg(test)]
    pub(crate) put_start_deadline_operation: Option<OperationId>,
    failure_status: Arc<OnceLock<ResourceError>>,
    bootstrap_leases: Vec<HolderLease>,
    completions: HashMap<Id, Vec<OwnedWaiter>>,
    response_operations: HashSet<OperationId>,
    maintenance_nodes: Vec<(SocketAddrV4, u32, HolderLease, VisitedLease)>,
    pending: VecDeque<PendingRequest>,
    admissions: VecDeque<PendingAdmission>,
    put_admissions: VecDeque<PendingPut>,
    active_puts: HashMap<Id, ActivePut>,
    request_budget: Arc<RequestBudget>,
    publication_observer: crate::resource::Observer,
}

impl OwnedActor {
    fn prune_waiters(waiters: &mut Vec<OwnedWaiter>, now: tokio::time::Instant) {
        let mut index = 0;
        while index < waiters.len() {
            if waiters[index].sender.is_closed() {
                waiters.swap_remove(index);
            } else if now >= waiters[index].deadline {
                let waiter = waiters.swap_remove(index);
                let _ = waiter.sender.send(Err(ResourceError::DeadlineExceeded));
            } else {
                index += 1;
            }
        }
    }

    pub(crate) fn owned_request_budget(&self) -> Arc<RequestBudget> {
        Arc::clone(&self.request_budget)
    }

    fn enqueue_admission(
        &mut self,
        target: Id,
        sender: tokio::sync::oneshot::Sender<RequestReply>,
        deadline: tokio::time::Instant,
        request_lease: Arc<RequestLease>,
    ) {
        if self.pending.len() + self.admissions.len() + self.put_admissions.len() >= 16 {
            let _ = sender.send(RequestReply::Error(ResourceError::OperationLimit));
        } else {
            self.admissions.push_back(PendingAdmission {
                target,
                sender,
                deadline,
                request_lease,
            });
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len() + self.admissions.len() + self.put_admissions.len()
    }

    #[cfg(test)]
    pub(crate) fn active_put_len(&self) -> usize {
        self.active_puts.len()
    }

    #[cfg(test)]
    pub(crate) fn put_pending_len(&self) -> usize {
        self.put_admissions.len()
    }

    #[cfg(test)]
    pub(crate) fn reserve_result_for_test(&self) -> Option<Arc<ResultLease>> {
        self.result_budget.acquire()
    }

    pub(crate) fn new(budget: Arc<StoreBudget>, bootstrap_leases: Vec<HolderLease>) -> Self {
        let request_budget = Arc::new(RequestBudget::default());
        let result_budget = Arc::new(ResultBudget::new(request_budget.cancellation_wake()));
        let publication_observer = crate::resource::Observer::default();
        publication_observer.attach_actor_wake(request_budget.cancellation_wake());
        Self {
            budget,
            result_budget,
            operations: HashMap::new(),
            maintenance: None,
            maintenance_retry_at: None,
            terminal: None,
            #[cfg(test)]
            put_start_deadline_operation: None,
            failure_status: Arc::new(OnceLock::new()),
            bootstrap_leases,
            completions: HashMap::new(),
            response_operations: HashSet::new(),
            maintenance_nodes: Vec::new(),
            pending: VecDeque::new(),
            admissions: VecDeque::new(),
            put_admissions: VecDeque::new(),
            active_puts: HashMap::new(),
            request_budget,
            publication_observer,
        }
    }

    fn operation_capacity_available(&self) -> bool {
        let charged = self.operations.values().copied().collect::<HashSet<_>>();
        let total =
            charged.len() + usize::from(self.maintenance.is_some_and(|id| !charged.contains(&id)));
        total < 8
    }

    fn operation_for(
        &mut self,
        target: Id,
        socket: &mut KrpcSocket,
        deadline: tokio::time::Instant,
    ) -> Result<OperationId, ResourceError> {
        if let Some(operation) = self.operations.get(&target) {
            if socket
                .owned_deadline(*operation)
                .is_some_and(|current| current <= tokio::time::Instant::now())
            {
                return Err(ResourceError::DeadlineExceeded);
            }
            return Ok(*operation);
        }
        let charged = self.operations.values().copied().collect::<HashSet<_>>();
        let total =
            charged.len() + usize::from(self.maintenance.is_some_and(|id| !charged.contains(&id)));
        if total >= 8 {
            return Err(ResourceError::OperationLimit);
        }
        let operation = socket.allocate_operation()?;
        socket.register_owned_deadline(operation, deadline)?;
        self.operations.insert(target, operation);
        Ok(operation)
    }

    fn maintenance_operation(
        &mut self,
        socket: &mut KrpcSocket,
        deadline: tokio::time::Instant,
    ) -> Result<OperationId, ResourceError> {
        if let Some(operation) = self.maintenance {
            if socket
                .owned_deadline(operation)
                .is_some_and(|current| current <= tokio::time::Instant::now())
            {
                return Err(ResourceError::DeadlineExceeded);
            }
            return Ok(operation);
        }
        let charged = self.operations.values().copied().collect::<HashSet<_>>();
        let total =
            charged.len() + usize::from(self.maintenance.is_some_and(|id| !charged.contains(&id)));
        if total >= 8 {
            return Err(ResourceError::OperationLimit);
        }
        let operation = socket.allocate_operation()?;
        socket.register_owned_deadline(operation, deadline)?;
        self.maintenance = Some(operation);
        Ok(operation)
    }
}

impl Actor {
    pub(crate) fn enable_owned_resources(&mut self) -> Result<(), ResourceError> {
        if self.owned_resources.is_some() {
            return Ok(());
        }
        let budget = Arc::new(StoreBudget::default());
        let mut bootstrap_leases = Vec::with_capacity(self.core.bootstrap.len());
        for _ in self.core.bootstrap.iter() {
            bootstrap_leases.push(budget.reserve_holder()?);
        }
        self.core
            .routing_table
            .enable_owner_budget(Arc::clone(&budget));
        self.core
            .signed_peers_routing_table
            .enable_owner_budget(Arc::clone(&budget));
        self.core.cached_iterative_queries.clear();
        self.socket.enable_owned_resources();
        self.owned_resources = Some(OwnedActor::new(budget, bootstrap_leases));
        self.socket
            .set_owned_publication_observer(self.owned_publication_observer());
        Ok(())
    }

    pub(crate) fn owned_request_budget(&self) -> Arc<RequestBudget> {
        Arc::clone(
            &self
                .owned_resources
                .as_ref()
                .expect("owned actor initialized")
                .request_budget,
        )
    }

    pub(crate) fn owned_publication_observer(&self) -> crate::resource::Observer {
        self.owned_resources
            .as_ref()
            .expect("owned actor initialized")
            .publication_observer
            .clone()
    }

    pub(crate) fn process_owned_publication_message(
        &mut self,
        message: crate::common::Message,
        from: SocketAddrV4,
    ) {
        let transaction_id = message.transaction_id;
        let has_response = matches!(
            &message.message_type,
            crate::common::MessageType::Response(_) | crate::common::MessageType::Error(_)
        );
        self.process_message(message, from);
        if has_response {
            self.owned_note_response(transaction_id);
            if let Some(owner) = self.owned_resources.as_ref() {
                let _ = owner.publication_observer.processed(transaction_id);
            }
        }
    }

    pub(crate) fn owned_failure_status(&self) -> Arc<OnceLock<ResourceError>> {
        Arc::clone(
            &self
                .owned_resources
                .as_ref()
                .expect("owned actor initialized")
                .failure_status,
        )
    }

    #[cfg(test)]
    pub(crate) fn owned_result_budget(&self) -> Arc<ResultBudget> {
        Arc::clone(
            &self
                .owned_resources
                .as_ref()
                .expect("owned actor initialized")
                .result_budget,
        )
    }

    #[cfg(test)]
    pub(crate) fn owned_has_response_operation(&self, operation: OperationId) -> bool {
        self.owned_resources
            .as_ref()
            .is_some_and(|owner| owner.response_operations.contains(&operation))
    }
}
