//! Ordered cleanup over the retained composition slot.
//!
//! Orphan policy: Arc-shared orphan owners are retained only up to
//! `ORPHAN_BOUND`; an unsuccessful `Arc::try_unwrap` is pending ownership and
//! is retained for a later close attempt. Failed orphan closes and retained
//! orphans both prevent a completion claim.

use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use tokio::sync::oneshot;

use shaar_ygg::YggPump;

#[cfg(test)]
use shaar_ygg::YggError;

#[cfg(test)]
use crate::identity::Identity;
#[cfg(test)]
use crate::native_discovery::runtime::owner::{LoopbackPeer, RuntimeOwner};
use crate::network::{SignaledEndpoint, YggEndpoint};

#[cfg(test)]
use crate::network::Limits;

use super::maintain::{MaintenanceExit, MaintenanceJoin};
use super::{ClosingClaims, SharedState, StartupResources, readiness_view, slot_lock};
use crate::native_discovery::runtime::owner::RuntimeError;
use crate::startup::error::StartupError;

const MAINTENANCE_BOUND: Duration = Duration::from_secs(5);

fn closing_claims(shared: &Arc<SharedState>, resources: &StartupResources) -> ClosingClaims {
    let (native_bound, native_transferred, signal_bound, relay_reserved, ygg) =
        readiness_view(shared, Some(resources));
    ClosingClaims {
        native_bound,
        native_transferred,
        signal_bound,
        relay_reserved,
        ygg,
    }
}

/// Releases retained orphan owners abort-only once the bound is reached.
fn retain_orphan_native(shared: &Arc<SharedState>, endpoint: Arc<SignaledEndpoint>) {
    let mut slot = slot_lock(&shared.slot);
    if slot.orphan_native.len() >= super::ORPHAN_BOUND {
        drop(slot);
        // Bounded degradation: release abort-only instead of growing without
        // bound.
        shared.record_error(StartupError::Close {
            stage: "orphan-bound",
        });
        drop(endpoint);
        return;
    }
    slot.orphan_native.push(endpoint);
}

/// Ygg twin of `retain_orphan_native`: same bound, same abort-only release.
fn retain_orphan_ygg(shared: &Arc<SharedState>, pair: (Arc<YggEndpoint>, YggPump)) {
    let mut slot = slot_lock(&shared.slot);
    if slot.orphan_ygg.len() >= super::ORPHAN_BOUND {
        drop(slot);
        // Bounded degradation: release abort-only instead of growing without
        // bound.
        shared.record_error(StartupError::Close {
            stage: "orphan-bound",
        });
        drop(pair);
        return;
    }
    slot.orphan_ygg.push(pair);
}

/// Stops address watching before native close and retains owners when a stage is incomplete.
pub(crate) async fn quiesce_native(shared: &Arc<SharedState>) -> bool {
    let mut resources = {
        let mut slot = slot_lock(&shared.slot);
        let Some(resources) = slot.resources.take() else {
            return false;
        };
        slot.closing = Some(closing_claims(shared, &resources));
        resources
    };
    let mut complete = resources.endpoint.is_none() || resources.native_quiesced;
    if !complete {
        if let Some(maintenance) = resources.maintenance.as_mut() {
            maintenance.signal_stop();
            let watcher_stopped = matches!(
                tokio::time::timeout(MAINTENANCE_BOUND, maintenance.wait_watcher_stopped()).await,
                Ok(true)
            );
            if watcher_stopped {
                match tokio::time::timeout(MAINTENANCE_BOUND, maintenance.join_task()).await {
                    Ok(Some(MaintenanceJoin::Exit(exit))) => {
                        let MaintenanceExit { owner, faulted } = *exit;
                        if faulted {
                            // The loop faulted; the wrapper recovered the
                            // owner, so the real joins stay owned here for
                            // the joined close below.
                            shared.record_error(StartupError::Close {
                                stage: "address-maintenance",
                            });
                        }
                        resources.owner = Some(owner);
                        resources.maintenance = None;
                    }
                    // A JoinError means the whole task was aborted: the owner
                    // is unrecoverable, so the incomplete state is retained —
                    // no joined completion may be claimed.
                    Ok(Some(MaintenanceJoin::Failed(_))) | Ok(None) | Err(_) => {
                        shared.record_error(StartupError::Close {
                            stage: "address-maintenance",
                        });
                    }
                }
            } else {
                shared.record_error(StartupError::Close {
                    stage: "address-maintenance",
                });
            }
        }
        if resources.maintenance.is_none()
            && let Some(owner) = resources.owner.as_mut()
        {
            if resources.withdrawal_done {
                complete = true;
            } else {
                match tokio::time::timeout(MAINTENANCE_BOUND, owner.withdraw()).await {
                    Ok(Ok(())) => {
                        resources.withdrawal_done = true;
                        complete = true;
                    }
                    Ok(Err(RuntimeError::Closed)) => {
                        // A terminal publisher answers withdrawal with
                        // Closed (revoked generation or dead command
                        // channel). Drive Mainline shutdown and retain its
                        // close error, but a finished join is terminal
                        // cleanup proof: a terminal error is not pending
                        // cleanup, so transfer proceeds.
                        match tokio::time::timeout(MAINTENANCE_BOUND, owner.close()).await {
                            Ok(result) => {
                                if result.is_err() {
                                    shared.record_error(StartupError::Close { stage: "mainline" });
                                }
                                if !owner.has_pending_cleanup() {
                                    resources.withdrawal_done = true;
                                    resources.owner = None;
                                    complete = true;
                                } else {
                                    shared.record_error(StartupError::Close {
                                        stage: "publication-withdraw",
                                    });
                                }
                            }
                            Err(_) => {
                                shared.record_error(StartupError::Close { stage: "mainline" })
                            }
                        }
                    }
                    Ok(Err(_)) | Err(_) => shared.record_error(StartupError::Close {
                        stage: "publication-withdraw",
                    }),
                }
            }
        }
    }
    resources.native_quiesced = complete;
    {
        let mut slot = slot_lock(&shared.slot);
        slot.closing = None;
        slot.resources = Some(resources);
    }
    complete
}

/// Attempts each owner once, retaining incomplete Mainline close state for a
/// later shutdown call. Other backends are still attempted independently.
pub(crate) async fn run_ordered_close(
    shared: &Arc<SharedState>,
    #[cfg(test)] mut after_native_close_entered: Option<oneshot::Sender<()>>,
    #[cfg(test)] mut after_native_close_release: Option<oneshot::Receiver<()>>,
) -> bool {
    let mut resources = {
        let mut slot = slot_lock(&shared.slot);
        let claims = slot
            .resources
            .as_ref()
            .map(|resources| closing_claims(shared, resources));
        let taken = slot.resources.take();
        slot.closing = claims;
        taken.unwrap_or(StartupResources {
            endpoint: None,
            native_transferred: false,
            native_quiesced: false,
            maintenance: None,
            owner: None,
            withdrawal_done: false,
            ygg: None,
        })
    };

    let mut watcher_stopped = resources.maintenance.is_none();
    if let Some(maintenance) = resources.maintenance.as_mut() {
        maintenance.signal_stop();
        watcher_stopped =
            tokio::time::timeout(MAINTENANCE_BOUND, maintenance.wait_watcher_stopped())
                .await
                .unwrap_or_default();
        if !watcher_stopped {
            shared.record_error(StartupError::Close {
                stage: "address-maintenance",
            });
        } else {
            match tokio::time::timeout(MAINTENANCE_BOUND, maintenance.join_task()).await {
                Ok(Some(MaintenanceJoin::Exit(exit))) => {
                    let MaintenanceExit { owner, faulted } = *exit;
                    if faulted {
                        // The loop faulted; the wrapper recovered the owner,
                        // so the real joins stay owned here for the joined
                        // close below.
                        shared.record_error(StartupError::Close {
                            stage: "address-maintenance",
                        });
                    }
                    resources.owner = Some(owner);
                    resources.maintenance = None;
                }
                // A JoinError means the whole task was aborted: the owner is
                // unrecoverable, so the incomplete state is retained — no
                // joined completion may be claimed.
                Ok(Some(MaintenanceJoin::Failed(_))) | Ok(None) | Err(_) => {
                    shared.record_error(StartupError::Close {
                        stage: "address-maintenance",
                    });
                }
            }
        }
    }

    let close_state = if watcher_stopped {
        if let Some(owner) = resources.owner.as_mut() {
            if !resources.withdrawal_done {
                match tokio::time::timeout(MAINTENANCE_BOUND, owner.withdraw()).await {
                    Ok(Ok(())) | Ok(Err(RuntimeError::Closed)) => {
                        resources.withdrawal_done = true;
                    }
                    Ok(Err(_)) | Err(_) => shared.record_error(StartupError::Close {
                        stage: "publication-withdraw",
                    }),
                }
            }
            #[cfg(test)]
            let skip_mainline = shared
                .mainline_close_skip_for_tests
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let skip_mainline = false;
            let (result, pending) = if skip_mainline {
                (None, true)
            } else {
                let result = owner.close().await;
                let pending = owner.has_pending_cleanup();
                (Some(result), pending)
            };
            Some((result, pending))
        } else {
            None
        }
    } else {
        None
    };
    if let Some((result, pending)) = close_state {
        if result.as_ref().is_some_and(Result::is_err) || pending {
            shared.record_error(StartupError::Close { stage: "mainline" });
        }
        if !pending {
            // A terminal close may report its persistent first error after
            // joining all resources. Record that error, but do not retain a
            // closed owner or make every later shutdown appear pending.
            resources.owner = None;
        }
        {
            let mut slot = slot_lock(&shared.slot);
            slot.closing = Some(closing_claims(shared, &resources));
        }
    }

    if watcher_stopped {
        if let Some(endpoint) = resources.endpoint.take() {
            let result = endpoint.close().await;
            if result.is_err() {
                shared.record_error(StartupError::Close {
                    stage: "native-signaling",
                });
            }
            #[cfg(test)]
            if result.is_ok()
                && shared
                    .native_close_fault_for_tests
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                shared.record_error(StartupError::Close {
                    stage: "native-signaling",
                });
            }
        }
        {
            let mut slot = slot_lock(&shared.slot);
            slot.closing = Some(closing_claims(shared, &resources));
        }
    }

    #[cfg(test)]
    if let Some(release) = after_native_close_release.take() {
        if let Some(entered) = after_native_close_entered.take() {
            let _ = entered.send(());
        }
        let _ = release.await;
    }

    if watcher_stopped {
        // Retained orphans are pending ownership: close successful unwraps
        // and keep failed unwraps for a later attempt. A stalled watcher
        // leaves every orphan pending. The slot guard is confined to this
        // block: the loop body awaits endpoint closes and re-locks through
        // the retain helpers, so no mutex survives an await or a recursive
        // helper call.
        let orphans_native = {
            let mut slot = slot_lock(&shared.slot);
            std::mem::take(&mut slot.orphan_native)
        };
        for endpoint in orphans_native {
            match Arc::try_unwrap(endpoint) {
                Ok(endpoint) => {
                    if endpoint.close().await.is_err() {
                        shared.record_error(StartupError::Close {
                            stage: "orphan-native",
                        });
                    }
                }
                Err(arc) => retain_orphan_native(shared, arc),
            }
        }
    }

    // Orphan payload closes run unconditionally on every pass: a pair
    // retained mid-pass is drained by the next pass, so progress per pass is
    // bounded and convergent, never a livelock. They still run before the
    // bridge close (the bridge close lives inside the ygg section below);
    // own-payload vs orphan-payload order between themselves is irrelevant
    // (independent endpoints). Failed unwraps stay retained as pending
    // ownership. The guard is confined to the block; the loop body awaits
    // payload closes and re-locks through the retain helper.
    let orphans_ygg = {
        let mut slot = slot_lock(&shared.slot);
        std::mem::take(&mut slot.orphan_ygg)
    };
    for (endpoint, mut pump) in orphans_ygg {
        match Arc::try_unwrap(endpoint) {
            Ok(mut endpoint) => {
                if endpoint.close(&mut pump).await.is_err() {
                    shared.record_error(StartupError::Close {
                        stage: "orphan-ygg",
                    });
                }
            }
            Err(arc) => retain_orphan_ygg(shared, (arc, pump)),
        }
    }

    // Deferred: taken as late as possible, after the own-payload close.
    let payload_pending;
    if let Some(ygg) = resources.ygg.as_mut() {
        if let Some((endpoint, pump)) = ygg.payload.as_mut()
            && endpoint.close(pump).await.is_err()
        {
            shared.record_error(StartupError::Close {
                stage: "ygg-payload",
            });
        }
        ygg.payload = None;

        // Pending payload ownership blocks bridge teardown. Late-pair
        // reachability is ruled out by the single-owner protocol: one
        // composition serves one role, the owner task is the only taker of
        // `slot.resources`, and every role-side orphan producer either runs
        // before any shutdown request exists (close_parts unwrap failures;
        // Drop-body restores while `start` is still alive, so no autonomous
        // pass precedes them) or runs when the owned payload has already been
        // moved out of the dropped continuation (Drop during an in-flight
        // shutdown pass records nothing).
        payload_pending = {
            let slot = slot_lock(&shared.slot);
            !slot.orphan_ygg.is_empty()
        };
        if !payload_pending {
            if let Some(bridge) = ygg.bridge.as_ref() {
                let result = bridge.close().await;
                #[cfg(test)]
                let result = if shared
                    .close_fault_for_tests
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    Err(YggError::Io("synthetic close failure".to_string()))
                } else {
                    result
                };
                if result.is_err() {
                    shared.record_error(StartupError::Close {
                        stage: "ygg-bridge",
                    });
                }
            }
            ygg.bridge = None;
            if let Some(start) = ygg.start.as_mut() {
                if let Err(error) = start.shutdown().await {
                    shared.record_error(error);
                }
                ygg.start = None;
            }
        }
    } else {
        // No own payload: the snapshot is equally fresh here (no close ran).
        payload_pending = {
            let slot = slot_lock(&shared.slot);
            !slot.orphan_ygg.is_empty()
        };
    }
    if !payload_pending {
        resources.ygg = None;
    }
    {
        let mut slot = slot_lock(&shared.slot);
        slot.closing = Some(closing_claims(shared, &resources));
    }

    let mut complete = resources.maintenance.is_none()
        && resources.owner.is_none()
        && resources.endpoint.is_none()
        && resources.ygg.is_none();
    {
        let mut slot = slot_lock(&shared.slot);
        // Retained orphans are pending ownership: they block completion.
        complete = complete && slot.orphan_native.is_empty() && slot.orphan_ygg.is_empty();
        slot.closing = None;
        slot.resources = Some(resources);
    }
    complete
}

#[cfg(test)]
#[path = "close_tests.rs"]
mod tests;
