//! The joined-close continuation and bounded session serving of the server role, split verbatim from server.rs for the 700-line rule — no behavior change.

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::ServerConfig;
use crate::network::{ForwardError, ServeReport, Session};
use crate::startup::StartupError;

/// Joined owned close: watch stop, session drain, reservation release while
/// signaling is alive, owner restore, then the ordered composition shutdown.
/// The first truthful error wins.
pub(super) async fn close_parts(mut parts: super::server::ServerParts) -> Result<(), StartupError> {
    let mut first_error = parts.outcome.take();
    // Watch-driven stop, best-effort.
    if let Some((stop_tx, _)) = parts.stop.take() {
        let _ = stop_tx.send(true);
    }
    // Joined drain: first fatal error wins, outcomes logged.
    while let Some(result) = parts.sessions.join_next().await {
        match result {
            Err(_) | Ok(Err(ForwardError::TaskFailure)) => {
                first_error.get_or_insert(StartupError::Close {
                    stage: "session-drain",
                });
            }
            Ok(Err(error)) => eprintln!("shaar: session ended: {error}"),
            Ok(Ok(_)) => {}
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
                        events.record(super::RoleEvent::ClosePending { stage: *stage });
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
pub(super) fn spawn_session(
    sessions: &mut JoinSet<Result<ServeReport, ForwardError>>,
    mut session: Session,
    config: &ServerConfig,
    stop_rx: &watch::Receiver<bool>,
) {
    let target = config.target();
    let mut stop = stop_rx.clone();
    sessions.spawn(async move {
        // `serve` enforces the fixed loopback target and pre-admitted peer.
        session
            .serve(target, async move {
                if *stop.borrow() {
                    return;
                }
                let _ = stop.changed().await;
            })
            .await
    });
}
