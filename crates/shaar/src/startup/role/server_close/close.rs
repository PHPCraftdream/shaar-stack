//! The joined-close continuation and bounded session serving of the server role, split verbatim from server.rs for the 700-line rule — no behavior change.

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::ServerConfig;
use crate::network::observe;
use crate::network::{ForwardError, ServeReport, Session};
use crate::path::PathKind;
use crate::startup::StartupError;
use crate::startup::StreamHandler;
use crate::startup::role::server::ServerParts;

impl Drop for ServerParts {
    fn drop(&mut self) {
        // Sync abort-only: no await is possible in `Drop`; the responder
        // task (workers and in-flight bursts together) is cancelled without
        // joining. Aborting drops every probe handle clone, and iroh's
        // endpoint close does not depend on remaining handle clones anyway,
        // so no probe handle can outlive the close.
        if let Some(task) = self.punch_task.take() {
            task.abort();
        }
        // Sync best-effort only: dropping `start` hands close to the owner task.
        if self.joined {
            return;
        }
        self.resources
            .restore_live_owners(self.endpoint.take(), self.payload.take());
    }
}

/// Emits the stable OBS-1 session line for one reaped session and answers
/// whether the outcome is fatal for the serving role (a task failure is).
pub(in crate::startup::role) fn reap_session(
    outcome: &(PathKind, Result<ServeReport, ForwardError>),
) -> bool {
    let (kind, result) = outcome;
    observe::emit(observe::session_line(
        observe::Product::Server,
        observe::RoutePath::from_kind(*kind),
        observe::SessionOutcome::of_session(result),
    ));
    matches!(result, Err(ForwardError::TaskFailure))
}

/// Joined owned close: watch stop, session drain, reservation release while
/// signaling is alive, owner restore, then the ordered composition shutdown.
/// The first truthful error wins.
pub(in crate::startup::role) async fn close_parts(
    mut parts: ServerParts,
) -> Result<(), StartupError> {
    let mut first_error = parts.outcome.take();
    // Abort the punch responder (workers and in-flight bursts together) and
    // join it with a bounded await (Finding 1c); a stuck task degrades to
    // abort-only. Aborting drops every probe handle clone; iroh's endpoint
    // close does not depend on remaining clones, so no probe handle outlives
    // the composition close below (which restores and closes the endpoint).
    if let Some(task) = parts.punch_task.take() {
        task.abort();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }
    // Watch-driven stop, best-effort.
    if let Some((stop_tx, _)) = parts.stop.take() {
        let _ = stop_tx.send(true);
    }
    // Joined drain: first fatal error wins; every session emits its line.
    while let Some(joined) = parts.sessions.join_next().await {
        match joined {
            Ok(outcome) => {
                if reap_session(&outcome) {
                    first_error.get_or_insert(StartupError::Close {
                        stage: "session-drain",
                    });
                }
            }
            Err(_) => {
                first_error.get_or_insert(StartupError::Close {
                    stage: "session-drain",
                });
            }
        }
    }
    // Release the reservation while signaling is still alive.
    if parts.reserved
        && let Some(ops) = parts.relay_ops.take()
    {
        let relay_addr = parts
            .relay_addr
            .expect("reserved implies a pinned relay address");
        if ops.release(relay_addr).await.is_err() {
            first_error.get_or_insert(StartupError::Close {
                stage: "relay-release",
            });
        }
    }
    // Restore the OWNED owners into the retained slot for ordered close.
    // The punch responder was aborted and joined above, so its probe handle
    // clones are gone; iroh's close does not depend on remaining clones.
    parts
        .resources
        .restore_live_owners(parts.endpoint.take(), parts.payload.take());
    // Composition ordered close. An INCOMPLETE attempt keeps the command/join
    // routes owned by `parts.start`; this SAME continuation retries on the
    // accepted 1-second cadence (matching `service_cleanup`) until terminal,
    // so a cancelled shutdown waiter resumes the same owned operation.
    loop {
        let result = parts.start.shutdown().await;
        match result {
            Ok(()) => {
                parts.joined = true;
                return match first_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
            Err(error) => {
                if parts.start.shutdown_pending() {
                    // Incomplete: retain the first error truthfully and retry.
                    first_error.get_or_insert(error);
                    #[cfg(test)]
                    if let Some(events) = parts.events.as_ref()
                        && let Some(StartupError::Close { stage }) = first_error.as_ref()
                    {
                        events.record(crate::startup::role::RoleEvent::ClosePending { stage });
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                // Terminal: cleanup finished, possibly with a close error.
                parts.joined = true;
                first_error.get_or_insert(error);
                return match first_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
        }
    }
}

/// Spawns one accepted session against the fixed loopback target; the gated
/// `join_next` arm keeps the set within `limits.sessions`.
pub(in crate::startup::role) fn spawn_session(
    sessions: &mut JoinSet<(PathKind, Result<ServeReport, ForwardError>)>,
    kind: PathKind,
    mut session: Session,
    config: &ServerConfig,
    stop_rx: &watch::Receiver<bool>,
    handler: Option<&StreamHandler>,
) {
    let target = config.target();
    let handler = handler.cloned();
    let mut stop = stop_rx.clone();
    sessions.spawn(async move {
        let stop = async move {
            if *stop.borrow() {
                return;
            }
            let _ = stop.changed().await;
        };
        // `serve` enforces the fixed loopback target and pre-admitted peer; a handler
        // replaces the target and sees only admitted peers.
        let result = match handler {
            Some(handler) => {
                session
                    .serve_streams(move |peer, stream| handler(peer, stream), stop)
                    .await
            }
            None => session.serve(target, stop).await,
        };
        (kind, result)
    });
}
