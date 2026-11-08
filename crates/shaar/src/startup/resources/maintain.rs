//! Bounded native address publication maintenance and resolver command handling.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use iroh::{EndpointAddr, TransportAddr, Watcher};
use iroh_base::EndpointId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::native_discovery::runtime::owner::{
    PublicationHandle, ResolvedAddresses, RuntimeError, RuntimeOwner,
};
use crate::native_discovery::runtime::publisher::PublicationStatus;

use super::MAX_SNAPSHOT_ADDRESSES;

const COMMANDS: usize = 8;
const RETRIES: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

type ResolveReply = oneshot::Sender<Result<ResolvedAddresses, RuntimeError>>;
type ResolveFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = (
                    &'a mut RuntimeOwner,
                    Result<ResolvedAddresses, RuntimeError>,
                ),
            > + Send
            + 'a,
    >,
>;
type PublishFuture = Pin<Box<dyn Future<Output = Result<(), RuntimeError>> + Send + 'static>>;
type StatusFuture = Pin<Box<dyn Future<Output = Option<PublicationStatus>> + Send + 'static>>;
#[cfg(test)]
type TestReply = oneshot::Sender<Result<(), RuntimeError>>;

pub(crate) enum MaintenanceCommand {
    Status(oneshot::Sender<Option<PublicationStatus>>),
    Resolve(EndpointId, ResolveReply),
    #[cfg(test)]
    Submit(EndpointAddr, oneshot::Sender<Result<(), RuntimeError>>),
    #[cfg(test)]
    Fault(oneshot::Sender<()>),
    #[cfg(test)]
    ResolveIdle(oneshot::Sender<bool>),
}

pub(crate) struct MaintenanceExit {
    pub(crate) owner: RuntimeOwner,
    pub(crate) faulted: bool,
}

pub(crate) struct Maintenance {
    pub(crate) commands: mpsc::Sender<MaintenanceCommand>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<MaintenanceExit>>,
    watcher_stopped: Option<oneshot::Receiver<()>>,
    terminal_failure: Option<MaintenanceJoinFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceJoinFailure {
    Cancelled,
    Panicked,
}

pub(crate) enum MaintenanceJoin {
    /// Boxed: the exit payload carries the whole retained RuntimeOwner, and
    /// a join is a one-shot lifecycle event — one bounded allocation instead
    /// of moving a ~300-byte enum through every close-path observation.
    Exit(Box<MaintenanceExit>),
    Failed(MaintenanceJoinFailure),
}

impl Maintenance {
    pub(crate) fn spawn(
        owner: RuntimeOwner,
        watcher: impl Watcher<Value = EndpointAddr> + Send + 'static,
    ) -> Self {
        let (commands, receiver) = mpsc::channel(COMMANDS);
        let (stop, stopped) = oneshot::channel();
        let (watcher_stopped_tx, watcher_stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            // The wrapper owns the runtime: a fault anywhere in the loop
            // unwinds only to the poll-boundary containment below, so the
            // owner is always handed back for the joined close path instead
            // of dying via abort-only Drop. The poll wrapper is the in-tree
            // proven catch_unwind pattern (server production_join/capacity).
            let mut owner = owner;
            let outcome = {
                let mut loop_future =
                    std::pin::pin!(maintain(&mut owner, watcher, receiver, stopped));
                std::future::poll_fn(|cx| {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        loop_future.as_mut().poll(cx)
                    })) {
                        Ok(poll) => poll.map(Ok),
                        Err(payload) => std::task::Poll::Ready(Err(payload)),
                    }
                })
                .await
            };
            // Truthful stop progress on BOTH exits: the loop future is
            // finished here and the watcher handle is already dropped (by
            // maintain on the normal exit, by unwinding on a fault), so the
            // acknowledgement describes a real stop, not a fault-seam preack.
            let _ = watcher_stopped_tx.send(());
            MaintenanceExit {
                owner,
                faulted: outcome.is_err(),
            }
        });
        Self {
            commands,
            stop: Some(stop),
            task: Some(task),
            watcher_stopped: Some(watcher_stopped),
            terminal_failure: None,
        }
    }

    pub(crate) async fn query_status(
        commands: &mpsc::Sender<MaintenanceCommand>,
    ) -> Option<PublicationStatus> {
        let (reply, response) = oneshot::channel();
        commands
            .send(MaintenanceCommand::Status(reply))
            .await
            .ok()?;
        response.await.ok().flatten()
    }

    /// Resolves through the real Mainline owner; delivery retains query charges.
    pub(crate) async fn resolve(
        commands: &mpsc::Sender<MaintenanceCommand>,
        key: EndpointId,
    ) -> Result<ResolvedAddresses, RuntimeError> {
        let (reply, response) = oneshot::channel();
        commands
            .send(MaintenanceCommand::Resolve(key, reply))
            .await
            .map_err(|_| RuntimeError::Closed)?;
        response.await.map_err(|_| RuntimeError::Closed)?
    }

    #[cfg(test)]
    pub(crate) async fn submit_for_tests(
        commands: &mpsc::Sender<MaintenanceCommand>,
        address: EndpointAddr,
    ) -> Result<(), RuntimeError> {
        let (reply, response) = oneshot::channel();
        commands
            .send(MaintenanceCommand::Submit(address, reply))
            .await
            .map_err(|_| RuntimeError::Closed)?;
        response.await.map_err(|_| RuntimeError::Closed)?
    }

    #[cfg(test)]
    pub(crate) async fn fault_for_tests(commands: &mpsc::Sender<MaintenanceCommand>) {
        let (reply, response) = oneshot::channel();
        commands
            .send(MaintenanceCommand::Fault(reply))
            .await
            .expect("maintenance route");
        response
            .await
            .expect("fault acknowledged before the loop unwinds");
    }

    #[cfg(test)]
    pub(crate) async fn resolve_idle_for_tests(
        commands: &mpsc::Sender<MaintenanceCommand>,
    ) -> bool {
        let (reply, response) = oneshot::channel();
        if commands
            .send(MaintenanceCommand::ResolveIdle(reply))
            .await
            .is_err()
        {
            return false;
        }
        response.await.unwrap_or(false)
    }

    pub(crate) fn signal_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    pub(crate) async fn wait_watcher_stopped(&mut self) -> bool {
        match self.watcher_stopped.as_mut() {
            Some(stopped) => {
                let acknowledged = stopped.await.is_ok();
                self.watcher_stopped = None;
                acknowledged
            }
            None => true,
        }
    }

    /// Only a genuinely pending join is retained; a consumed handle is never
    /// re-polled (a completed JoinHandle would panic on re-await). A terminal
    /// failure is cached and replayed on every later observation. An Exit
    /// always carries the owner back (faulted=true after a caught loop
    /// fault); a JoinError remains possible only if the whole task is aborted.
    pub(crate) async fn join_task(&mut self) -> Option<MaintenanceJoin> {
        if let Some(failure) = self.terminal_failure {
            return Some(MaintenanceJoin::Failed(failure));
        }
        let task = self.task.as_mut()?;
        let result = task.await;
        self.task = None;
        match result {
            Ok(exit) => Some(MaintenanceJoin::Exit(Box::new(exit))),
            Err(error) => {
                let failure = if error.is_cancelled() {
                    MaintenanceJoinFailure::Cancelled
                } else {
                    MaintenanceJoinFailure::Panicked
                };
                self.terminal_failure = Some(failure);
                Some(MaintenanceJoin::Failed(failure))
            }
        }
    }
}

/// Automatically publishes the initial snapshot; retains one current publish,
/// one coalesced latest snapshot, and one bounded retry timer.
async fn maintain(
    owner: &mut RuntimeOwner,
    mut watcher: impl Watcher<Value = EndpointAddr> + Send + 'static,
    mut commands: mpsc::Receiver<MaintenanceCommand>,
    mut stop: oneshot::Receiver<()>,
) {
    let publisher: PublicationHandle = owner.publication_handle();
    // The exclusive owner access is a MOVED `&mut` lease: while a resolver
    // future is active the lease lives inside that future, the slot below is
    // empty, and a second reborrow cannot even be constructed. Completion,
    // cancellation and the stop drain each move the lease back before reuse;
    // on fault unwind only the reference drops — the owner object itself
    // stays in the spawning frame for the joined close.
    let mut owner_lease: Option<&mut RuntimeOwner> = Some(owner);
    let mut latest = Some(snapshot(watcher.get()));
    let mut current: Option<Vec<TransportAddr>> = None;
    let mut publish: Option<PublishFuture> = None;
    let mut publish_admission: Option<oneshot::Receiver<()>> = None;
    let mut status_query: Option<StatusFuture> = None;
    let mut status_reply: Option<oneshot::Sender<Option<PublicationStatus>>> = None;
    let mut retry_at: Option<tokio::time::Instant> = None;
    let mut retry_step = 0usize;
    // Resolver future slot: occupied only while the lease above is moved out.
    let mut resolve: Option<ResolveFuture<'_>> = None;
    let mut resolve_cancel: Option<oneshot::Sender<()>> = None;
    let mut resolve_reply: Option<ResolveReply> = None;
    #[cfg(test)]
    let mut waiting_reply: Option<TestReply> = None;
    #[cfg(test)]
    let mut active_reply: Option<TestReply> = None;
    #[cfg(test)]
    let mut idle_reply: Option<oneshot::Sender<bool>> = None;
    let mut resolve_output: Option<(&mut RuntimeOwner, Result<ResolvedAddresses, RuntimeError>)> =
        None;

    loop {
        if publish.is_none()
            && retry_at.is_none()
            && let Some(next) = latest.take()
        {
            current = Some(next.clone());
            #[cfg(test)]
            {
                active_reply = waiting_reply.take();
            }
            let replace_publisher = publisher.clone();
            let query_publisher = publisher.clone();
            let (admitted, admission) = oneshot::channel();
            publish_admission = Some(admission);
            publish = Some(Box::pin(async move {
                replace_publisher
                    .replace_with_admission(next, admitted)
                    .await
            }));
            if status_reply.is_some() {
                status_query = status_future(query_publisher, publish_admission.take());
            }
        }

        let event = tokio::select! {
            biased;
            _ = &mut stop => Event::Stop,
            update = watcher.updated() => match update {
                Ok(address) => Event::Snapshot(snapshot(address)),
                Err(_) => Event::Stop,
            },
            result = publish_result(&mut publish), if publish.is_some() => Event::Published(result),
            _ = async { resolve_reply.as_mut().expect("guarded resolve reply").closed().await }, if resolve_reply.is_some() => Event::ResolveCanceled,
            result = status_query_result(&mut status_query), if status_query.is_some() => Event::StatusQueried(result),
            command = commands.recv() => Event::Command(command),
            _ = retry(retry_at) => Event::Retry,
            _ = resolve_result(&mut resolve, &mut resolve_output), if resolve.is_some() => {
                Event::Resolved
            }
        };

        match event {
            Event::Stop => break,
            Event::Command(Some(MaintenanceCommand::Status(reply))) => {
                if status_reply.is_some() {
                    let _ = reply.send(None);
                } else if publish.is_some() {
                    status_reply = Some(reply);
                    status_query = status_future(publisher.clone(), publish_admission.take());
                } else {
                    status_reply = Some(reply);
                    status_query = status_future(publisher.clone(), None);
                }
            }
            Event::Command(Some(MaintenanceCommand::Resolve(key, reply))) => {
                // The lease move is the only way to obtain the exclusive
                // reference: while a resolver future is active the slot is
                // empty, so a concurrent resolve answers ResolveBusy.
                if resolve.is_some() || owner_lease.is_none() {
                    let _ = reply.send(Err(RuntimeError::ResolveBusy));
                } else {
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                    let (cancel, canceled) = oneshot::channel();
                    let leased = owner_lease
                        .take()
                        .expect("lease held while the slot is empty");
                    resolve = Some(Box::pin(resolve_owned(leased, key, deadline, canceled)));
                    resolve_cancel = Some(cancel);
                    resolve_reply = Some(reply);
                }
            }
            #[cfg(test)]
            Event::Command(Some(MaintenanceCommand::Submit(address, reply))) => {
                latest = Some(snapshot(address));
                publish = None;
                publish_admission = None;
                status_query = None;
                current = None;
                retry_at = None;
                retry_step = 0;
                if let Some(old) = waiting_reply.replace(reply) {
                    let _ = old.send(Err(RuntimeError::Closed));
                }
                if let Some(old) = active_reply.take() {
                    let _ = old.send(Err(RuntimeError::Closed));
                }
            }
            #[cfg(test)]
            Event::Command(Some(MaintenanceCommand::Fault(reply))) => {
                // No watcher-stop preack here: the wrapper publishes the real
                // stop after catching this panic, exactly as for any ordinary
                // loop fault.
                let _ = reply.send(());
                panic!("injected maintenance loop fault");
            }
            #[cfg(test)]
            Event::Command(Some(MaintenanceCommand::ResolveIdle(reply))) => {
                // Completion barrier, not a snapshot: with an active resolver
                // the reply is deferred to that resolver's completion event;
                // without one it is answered immediately.
                if resolve.is_none() {
                    let _ = reply.send(true);
                } else if let Some(previous) = idle_reply.replace(reply) {
                    let _ = previous.send(false);
                }
            }
            Event::Command(None) => break,
            Event::Snapshot(next) => {
                latest = Some(next);
                publish = None;
                publish_admission = None;
                status_query = None;
                current = None;
                retry_at = None;
                retry_step = 0;
                #[cfg(test)]
                {
                    if let Some(reply) = waiting_reply.take() {
                        let _ = reply.send(Err(RuntimeError::Closed));
                    }
                    if let Some(reply) = active_reply.take() {
                        let _ = reply.send(Err(RuntimeError::Closed));
                    }
                }
            }
            Event::Retry => retry_at = None,
            Event::Published(result) => {
                publish = None;
                publish_admission = None;
                match result {
                    Ok(()) => {
                        current = None;
                        retry_step = 0;
                        #[cfg(test)]
                        if let Some(reply) = active_reply.take() {
                            let _ = reply.send(Ok(()));
                        }
                    }
                    Err(_error) => {
                        #[cfg(test)]
                        if let Some(reply) = active_reply.take() {
                            let _ = reply.send(Err(_error.clone()));
                        }
                        latest = current.take();
                        let delay = RETRIES[retry_step.min(RETRIES.len() - 1)];
                        retry_at = Some(tokio::time::Instant::now() + delay);
                        retry_step = retry_step.saturating_add(1);
                    }
                }
            }
            Event::StatusQueried(status) => {
                status_query = None;
                if let Some(reply) = status_reply.take() {
                    let _ = reply.send(status);
                }
            }
            Event::ResolveCanceled => {
                if let Some(cancel) = resolve_cancel.take() {
                    let _ = cancel.send(());
                }
                resolve_reply = None;
                // Bounded completion recovery: if the select already recorded
                // the output, the lease comes back without re-polling the
                // completed future; otherwise drain the active future (the
                // cancel signal above is already in its biased select) and
                // recover the lease from its output. Dropping the drained
                // backend query requests actor cleanup (pinned contract).
                if let Some((leased, _result)) = resolve_output.take() {
                    resolve = None;
                    owner_lease = Some(leased);
                } else if let Some(mut cancelled) = resolve.take() {
                    let (leased, _result) = cancelled.as_mut().await;
                    owner_lease = Some(leased);
                }
                #[cfg(test)]
                if let Some(reply) = idle_reply.take() {
                    let _ = reply.send(true);
                }
            }
            Event::Resolved => {
                let (leased, result) = resolve_output.take().expect("resolver output recorded");
                resolve = None;
                resolve_cancel = None;
                owner_lease = Some(leased);
                if let Some(reply) = resolve_reply.take() {
                    let _ = reply.send(result);
                }
                #[cfg(test)]
                if let Some(reply) = idle_reply.take() {
                    let _ = reply.send(true);
                }
            }
        }

        #[cfg(test)]
        if publish.is_none() && latest.is_none() && retry_at.is_none() {
            if let Some(reply) = waiting_reply.take() {
                let _ = reply.send(Ok(()));
            }
        }
    }

    commands.close();
    drop(watcher);
    drop(publish.take());
    drop(publish_admission.take());
    drop(status_query.take());
    if let Some(reply) = status_reply.take() {
        let _ = reply.send(None);
    }
    // Stop drain: cancel any active resolver and fail its caller. The lease
    // reference and the resolver future (active or already completed) drop
    // here — only references ever drop; the owner object stays in the
    // spawning frame for the handback below.
    if let Some(cancel) = resolve_cancel.take() {
        let _ = cancel.send(());
    }
    if let Some((_, result)) = resolve_output.take() {
        drop(resolve);
        if let Some(reply) = resolve_reply.take() {
            let _ = reply.send(result);
        }
    } else {
        drop(resolve);
        if let Some(reply) = resolve_reply.take() {
            let _ = reply.send(Err(RuntimeError::Closed));
        }
    }
    #[cfg(test)]
    {
        if let Some(reply) = waiting_reply.take() {
            let _ = reply.send(Err(RuntimeError::Closed));
        }
        if let Some(reply) = active_reply.take() {
            let _ = reply.send(Err(RuntimeError::Closed));
        }
    }
}

enum Event {
    Stop,
    Command(Option<MaintenanceCommand>),
    Snapshot(Vec<TransportAddr>),
    Retry,
    Published(Result<(), RuntimeError>),
    StatusQueried(Option<PublicationStatus>),
    ResolveCanceled,
    Resolved,
}

async fn retry(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn publish_result(publish: &mut Option<PublishFuture>) -> Result<(), RuntimeError> {
    match publish.as_mut() {
        Some(future) => future.as_mut().await,
        None => std::future::pending().await,
    }
}

async fn status_query_result(query: &mut Option<StatusFuture>) -> Option<PublicationStatus> {
    match query.as_mut() {
        Some(future) => future.as_mut().await,
        None => std::future::pending().await,
    }
}

fn status_future(
    publisher: PublicationHandle,
    admission: Option<oneshot::Receiver<()>>,
) -> Option<StatusFuture> {
    Some(Box::pin(async move {
        if let Some(admission) = admission {
            admission.await.ok()?;
        }
        publisher.query_publication_status().await
    }))
}
async fn resolve_owned(
    owner: &mut RuntimeOwner,
    key: EndpointId,
    deadline: tokio::time::Instant,
    mut canceled: oneshot::Receiver<()>,
) -> (&mut RuntimeOwner, Result<ResolvedAddresses, RuntimeError>) {
    let mut operation = Box::pin(owner.resolve_until(key, deadline));
    let result = tokio::select! {
        biased;
        _ = &mut canceled => Err(RuntimeError::Closed),
        result = &mut operation => result,
    };
    // End the backend borrow before the exclusive lease is moved out.
    drop(operation);
    (owner, result)
}

async fn resolve_result<'a>(
    resolve: &mut Option<ResolveFuture<'a>>,
    output: &mut Option<(
        &'a mut RuntimeOwner,
        Result<ResolvedAddresses, RuntimeError>,
    )>,
) {
    match resolve.as_mut() {
        Some(future) => *output = Some(future.as_mut().await),
        None => std::future::pending::<()>().await,
    }
}

/// Consumes at most five IP candidates; over-cap and empty inputs produce an empty replacement.
fn snapshot(address: EndpointAddr) -> Vec<TransportAddr> {
    let mut candidates: Vec<_> = address
        .ip_addrs()
        .take(MAX_SNAPSHOT_ADDRESSES + 1)
        .map(|address| TransportAddr::Ip(*address))
        .collect();
    if candidates.len() > MAX_SNAPSHOT_ADDRESSES {
        candidates.clear();
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    impl Maintenance {
        /// Spawns a task that acknowledges the watcher stop and then panics,
        /// producing a deterministic terminal join failure.
        pub(crate) fn spawn_failing_for_tests() -> Self {
            let (commands, _receiver) = mpsc::channel(COMMANDS);
            let (stop, _stopped) = oneshot::channel();
            let (watcher_stopped_tx, watcher_stopped) = oneshot::channel();
            let task = tokio::spawn(async move {
                let _ = watcher_stopped_tx.send(());
                panic!("injected maintenance task failure");
            });
            Self {
                commands,
                stop: Some(stop),
                task: Some(task),
                watcher_stopped: Some(watcher_stopped),
                terminal_failure: None,
            }
        }
    }

    #[tokio::test]
    async fn terminal_join_failure_is_cached_and_never_repolled() {
        let mut maintenance = Maintenance::spawn_failing_for_tests();
        maintenance.signal_stop();
        assert!(maintenance.wait_watcher_stopped().await);
        assert!(matches!(
            maintenance.join_task().await,
            Some(MaintenanceJoin::Failed(MaintenanceJoinFailure::Panicked))
        ));
        // A second observation replays the cached failure; re-polling the
        // consumed handle would panic and fail this test.
        assert!(matches!(
            maintenance.join_task().await,
            Some(MaintenanceJoin::Failed(MaintenanceJoinFailure::Panicked))
        ));
    }
}
