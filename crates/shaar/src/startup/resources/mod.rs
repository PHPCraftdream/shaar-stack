//! Crate-private shared production resources for composed startup.
//!
//! The composition owns one native endpoint, one Mainline runtime, bounded
//! address publication maintenance, and the retained same-identity Ygg start.
//! A transferred native endpoint or payload pair belongs to the receiving role;
//! callers must explicitly close transferred owners before closing remaining
//! composition resources. No distributed DHT deletion is claimed.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

#[cfg(test)]
use iroh::EndpointAddr;
use iroh_base::EndpointId;
use shaar_ygg::{YggBridge, YggPump};
use tokio::sync::{mpsc, oneshot, watch};

use crate::native_discovery::runtime::owner::{ResolvedAddresses, RuntimeError, RuntimeOwner};
use crate::native_discovery::runtime::publisher::PublicationStatus;
use crate::network::signaling::RelayOperations;
use crate::network::{NetworkError, SignaledEndpoint, YggEndpoint};

use super::error::StartupError;
use super::ygg_start::RetainedYggStart;

mod close;
mod maintain;
mod start;

pub(crate) use maintain::Maintenance;
// The startup facade re-export consumes this path in non-test builds, so
// the former unused-imports expectation is retired, not replaced.
pub(crate) use start::SharedResourcesStart;
#[cfg(test)]
pub(crate) use start::StageControls;

pub(crate) const MAX_SNAPSHOT_ADDRESSES: usize = 4;

/// Bounded number of retained Arc-shared orphan owners per composition.
/// Beyond the bound, excess owners are released abort-only (their Drop)
/// with a recorded error, never accumulated without bound.
pub(crate) const ORPHAN_BOUND: usize = 8;

#[derive(Clone, Debug)]
pub(crate) enum Status {
    Pending,
    Admitted,
    Failed(StartupError),
    Closed,
}

pub(crate) enum OwnerRequest {
    Shutdown(oneshot::Sender<bool>),
    QuiesceNative(oneshot::Sender<bool>),
}

/// One lock over the retained resources and their in-progress closing
/// claims: extraction, claim updates and restore are single critical
/// sections, so readiness never observes an absent-both window.
pub(crate) struct CompositionSlot {
    pub(crate) resources: Option<StartupResources>,
    pub(crate) closing: Option<ClosingClaims>,
    /// Arc-shared native owners whose joined close is still pending (a
    /// retained orphan is pending ownership, not a completed close); the
    /// ordered close closes them, at most ORPHAN_BOUND are retained.
    pub(crate) orphan_native: Vec<std::sync::Arc<SignaledEndpoint>>,
    /// Arc-shared payload pairs recorded the same way as `orphan_native`,
    /// bounded at ORPHAN_BOUND.
    pub(crate) orphan_ygg: Vec<(std::sync::Arc<YggEndpoint>, YggPump)>,
}

pub(crate) struct StartupResources {
    pub(crate) endpoint: Option<SignaledEndpoint>,
    pub(crate) native_transferred: bool,
    pub(crate) native_quiesced: bool,
    pub(crate) maintenance: Option<Maintenance>,
    pub(crate) owner: Option<RuntimeOwner>,
    pub(crate) withdrawal_done: bool,
    pub(crate) ygg: Option<YggResources>,
}

/// Closing claims held inside the slot lock: extraction, claim updates and
/// restore are single critical sections, so readiness never observes an
/// absent-both window.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClosingClaims {
    pub(crate) native_bound: bool,
    pub(crate) native_transferred: bool,
    pub(crate) signal_bound: Option<SocketAddr>,
    pub(crate) relay_reserved: bool,
    pub(crate) ygg: YggPhase,
}

/// Single readiness computation shared by queries and close-time claim updates.
pub(crate) fn readiness_view(
    shared: &SharedState,
    resources: Option<&StartupResources>,
) -> (bool, bool, Option<SocketAddr>, bool, YggPhase) {
    let relay_reserved = resources
        .and_then(|resources| resources.endpoint.as_ref())
        .is_some_and(|endpoint| {
            endpoint
                .relay_operations()
                .has_reservation(shared.configured_relay)
        });
    (
        resources.is_some_and(|resources| resources.endpoint.is_some()),
        resources.is_some_and(|resources| resources.native_transferred),
        resources
            .and_then(|resources| resources.endpoint.as_ref())
            .map(SignaledEndpoint::signaling_addr),
        relay_reserved,
        resources.map_or(YggPhase::None, |resources| {
            resources
                .ygg
                .as_ref()
                .map_or(YggPhase::None, YggResources::phase)
        }),
    )
}

pub(crate) struct YggResources {
    pub(crate) start: Option<RetainedYggStart>,
    pub(crate) bridge: Option<Arc<YggBridge>>,
    pub(crate) payload: Option<(YggEndpoint, YggPump)>,
    pub(crate) payload_transferred: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum YggPhase {
    Admitted,
    PayloadTransferred,
    BridgeOnly,
    None,
}

impl YggResources {
    pub(crate) fn phase(&self) -> YggPhase {
        if self.payload.is_some() {
            YggPhase::Admitted
        } else if self.payload_transferred {
            YggPhase::PayloadTransferred
        } else if self.bridge.is_some() {
            YggPhase::BridgeOnly
        } else {
            YggPhase::None
        }
    }
}

pub(crate) struct SharedState {
    pub(crate) configured_relay: shaar_p2p::RelayAddr,
    pub(crate) slot: Mutex<CompositionSlot>,
    status_tx: watch::Sender<Status>,
    pub(crate) status_rx: watch::Receiver<Status>,
    pub(crate) first_close_error: Mutex<Option<StartupError>>,
    pub(crate) completion_tx: watch::Sender<Option<Result<(), StartupError>>>,
    #[cfg(test)]
    pub(crate) publication_watch_for_tests: Mutex<
        Option<watch::Receiver<crate::native_discovery::runtime::publisher::PublicationStatus>>,
    >,
    #[cfg(test)]
    pub(crate) close_fault_for_tests: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(crate) native_close_fault_for_tests: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(crate) mainline_close_skip_for_tests: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(crate) payload_fault_for_tests: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(crate) cleanup_hold_armed_for_tests: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(crate) cleanup_hold_observer_for_tests: std::sync::Mutex<Option<n0_mainline::Observer>>,
    #[cfg(test)]
    pub(crate) mainline_actor_id_for_tests: std::sync::Mutex<Option<n0_mainline::Id>>,
}

impl SharedState {
    pub(crate) fn set_status(&self, status: Status) {
        self.status_tx.send_replace(status);
    }

    pub(crate) fn record_error(&self, error: StartupError) {
        let mut first = self
            .first_close_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if first.is_none() {
            *first = Some(error);
        }
    }

    pub(crate) fn first_error(&self) -> Option<StartupError> {
        self.first_close_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub(crate) fn slot_lock(
    slot: &Mutex<CompositionSlot>,
) -> std::sync::MutexGuard<'_, CompositionSlot> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Debug)]
pub(crate) struct SharedReadiness {
    pub(crate) publication: Option<PublicationStatus>,
    pub(crate) native_bound: bool,
    pub(crate) native_transferred: bool,
    pub(crate) signal_bound: Option<SocketAddr>,
    pub(crate) relay_reserved: bool,
    pub(crate) ygg: YggPhase,
}

#[derive(Clone)]
pub(crate) struct SharedResources {
    shared: Arc<SharedState>,
    owner_commands: mpsc::Sender<OwnerRequest>,
}

impl fmt::Debug for SharedResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedResources(..)")
    }
}

impl SharedResources {
    pub(crate) fn with_endpoint<R>(&self, f: impl FnOnce(&SignaledEndpoint) -> R) -> Option<R> {
        let slot = slot_lock(&self.shared.slot);
        slot.resources.as_ref()?.endpoint.as_ref().map(f)
    }

    /// Transfers native endpoint ownership only after owner-driven quiescence.
    /// cancel-safe: YES — the owner task retains quiescence; the endpoint never crosses an async reply.
    pub(crate) async fn transfer_native(&self) -> Result<Option<SignaledEndpoint>, StartupError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.owner_commands
            .send(OwnerRequest::QuiesceNative(reply))
            .await
            .map_err(|_| StartupError::Close {
                stage: "native-quiesce",
            })?;
        if !response.await.unwrap_or(false) {
            return Err(StartupError::Close {
                stage: "native-quiesce",
            });
        }
        let mut slot = slot_lock(&self.shared.slot);
        let Some(resources) = slot.resources.as_mut() else {
            return Ok(None);
        };
        if resources.endpoint.is_some() && !resources.native_quiesced {
            return Err(StartupError::Close {
                stage: "native-quiesce",
            });
        }
        let endpoint = resources.endpoint.take();
        if endpoint.is_some() {
            resources.native_transferred = true;
        }
        Ok(endpoint)
    }

    /// Live-role transfer: takes the native endpoint WITHOUT stopping address
    /// maintenance or withdrawing publication, so the retained composition
    /// keeps publishing and resolving while the role owns and serves the
    /// endpoint. Returns the endpoint plus the retained relay-operations
    /// handle so relay reserve/release stay possible after the take.
    /// Synchronous (slot lock only, no await), therefore trivially cancel-safe.
    pub(crate) fn take_native_live(&self) -> Option<(SignaledEndpoint, RelayOperations)> {
        let mut slot = slot_lock(&self.shared.slot);
        let resources = slot.resources.as_mut()?;
        let operations = resources
            .endpoint
            .as_ref()
            .map(SignaledEndpoint::relay_operations);
        let endpoint = resources.endpoint.take();
        if endpoint.is_some() {
            resources.native_transferred = true;
        }
        endpoint.map(|endpoint| (endpoint, operations.expect("operations cloned before take")))
    }

    /// Restores role-transferred owners to the retained slot so the
    /// composition owner's ordered close closes them when a role waiter is
    /// cancelled. Synchronous (slot lock only), therefore trivially
    /// cancel-safe. When the slot is already closing, the owners are recorded
    /// as orphans so the running ordered close still closes them.
    pub(crate) fn restore_live_owners(
        &self,
        endpoint: Option<SignaledEndpoint>,
        payload: Option<(YggEndpoint, YggPump)>,
    ) {
        let mut slot = slot_lock(&self.shared.slot);
        let Some(resources) = slot.resources.as_mut() else {
            // Closing slot: each owner becomes a bounded orphan independently;
            // a bound hit never discards the unrelated pending owner.
            let mut endpoint = endpoint;
            let mut payload = payload;
            match endpoint.take() {
                Some(endpoint) if slot.orphan_native.len() < ORPHAN_BOUND => {
                    slot.orphan_native.push(std::sync::Arc::new(endpoint));
                }
                Some(endpoint) => {
                    drop(slot);
                    // Bounded degradation: release abort-only instead of
                    // growing without bound.
                    self.shared.record_error(StartupError::Close {
                        stage: "orphan-bound",
                    });
                    drop(endpoint);
                    slot = slot_lock(&self.shared.slot);
                }
                None => {}
            }
            match payload.take() {
                Some((ygg, pump)) if slot.orphan_ygg.len() < ORPHAN_BOUND => {
                    slot.orphan_ygg.push((std::sync::Arc::new(ygg), pump));
                }
                Some((ygg, pump)) => {
                    drop(slot);
                    // Bounded degradation: release abort-only instead of
                    // growing without bound.
                    self.shared.record_error(StartupError::Close {
                        stage: "orphan-bound",
                    });
                    drop((ygg, pump));
                    slot = slot_lock(&self.shared.slot);
                }
                None => {}
            }
            return;
        };
        if let Some(endpoint) = endpoint {
            resources.endpoint = Some(endpoint);
            resources.native_transferred = false;
        }
        if let Some((ygg, pump)) = payload {
            let ygg_resources = resources.ygg.get_or_insert_with(|| YggResources {
                start: None,
                bridge: None,
                payload: None,
                payload_transferred: false,
            });
            ygg_resources.payload = Some((ygg, pump));
            ygg_resources.payload_transferred = false;
        }
    }

    /// Records an Arc-shared native endpoint still held by a dialer task at
    /// cancellation time; the ordered close unwraps and closes it once the
    /// owner task outlives every dialer. Synchronous (slot lock only).
    /// Bounded at ORPHAN_BOUND: excess owners are released abort-only with a
    /// recorded error.
    pub(crate) fn record_orphan_native(&self, endpoint: std::sync::Arc<SignaledEndpoint>) {
        let mut slot = slot_lock(&self.shared.slot);
        if slot.orphan_native.len() >= ORPHAN_BOUND {
            drop(slot);
            // Bounded degradation: release abort-only instead of growing
            // without bound.
            self.shared.record_error(StartupError::Close {
                stage: "orphan-bound",
            });
            drop(endpoint);
            return;
        }
        slot.orphan_native.push(endpoint);
    }

    /// Records an Arc-shared payload pair still held by a dialer task at
    /// cancellation time; the ordered close unwraps and closes it. Synchronous
    /// (slot lock only). Bounded at ORPHAN_BOUND like `record_orphan_native`.
    pub(crate) fn record_orphan_ygg(&self, pair: (std::sync::Arc<YggEndpoint>, YggPump)) {
        let mut slot = slot_lock(&self.shared.slot);
        if slot.orphan_ygg.len() >= ORPHAN_BOUND {
            drop(slot);
            // Bounded degradation: release abort-only instead of growing
            // without bound.
            self.shared.record_error(StartupError::Close {
                stage: "orphan-bound",
            });
            drop(pair);
            return;
        }
        slot.orphan_ygg.push(pair);
    }

    /// Transfers paired payload endpoint/pump. Caller closes them before the remaining bridge.
    pub(crate) fn take_ygg_payload(&self) -> Option<(YggEndpoint, YggPump)> {
        let mut slot = slot_lock(&self.shared.slot);
        let ygg = slot.resources.as_mut()?.ygg.as_mut()?;
        let payload = ygg.payload.take();
        if payload.is_some() {
            ygg.payload_transferred = true;
        }
        payload
    }

    pub(crate) async fn reserve_configured_relay(
        &self,
    ) -> Result<shaar_p2p::RelayLease, NetworkError> {
        let (operation, relay) = {
            let slot = slot_lock(&self.shared.slot);
            let operation = slot
                .resources
                .as_ref()
                .and_then(|resources| resources.endpoint.as_ref())
                .map(SignaledEndpoint::relay_operations)
                .ok_or(NetworkError::Closed)?;
            (operation, self.shared.configured_relay)
        };
        operation.reserve(relay).await
    }

    pub(crate) async fn reserve_relay(
        &self,
        relay: shaar_p2p::RelayAddr,
    ) -> Result<shaar_p2p::RelayLease, NetworkError> {
        let operation = {
            let slot = slot_lock(&self.shared.slot);
            slot.resources
                .as_ref()
                .and_then(|resources| resources.endpoint.as_ref())
                .map(SignaledEndpoint::relay_operations)
                .ok_or(NetworkError::Closed)?
        };
        operation.reserve(relay).await
    }

    pub(crate) async fn release_configured_relay(&self) -> Result<(), NetworkError> {
        let (operation, relay) = {
            let slot = slot_lock(&self.shared.slot);
            let operation = slot
                .resources
                .as_ref()
                .and_then(|resources| resources.endpoint.as_ref())
                .map(SignaledEndpoint::relay_operations)
                .ok_or(NetworkError::Closed)?;
            (operation, self.shared.configured_relay)
        };
        operation.release(relay).await
    }

    pub(crate) async fn release_relay(
        &self,
        relay: shaar_p2p::RelayAddr,
    ) -> Result<(), NetworkError> {
        let operation = {
            let slot = slot_lock(&self.shared.slot);
            slot.resources
                .as_ref()
                .and_then(|resources| resources.endpoint.as_ref())
                .map(SignaledEndpoint::relay_operations)
                .ok_or(NetworkError::Closed)?
        };
        operation.release(relay).await
    }

    pub(crate) async fn resolve(&self, key: EndpointId) -> Result<ResolvedAddresses, RuntimeError> {
        let commands = slot_lock(&self.shared.slot)
            .resources
            .as_ref()
            .and_then(|resources| resources.maintenance.as_ref())
            .map(|maintenance| maintenance.commands.clone())
            .ok_or(RuntimeError::Closed)?;
        Maintenance::resolve(&commands, key).await
    }

    pub(crate) async fn readiness(&self) -> SharedReadiness {
        let commands = {
            let slot = slot_lock(&self.shared.slot);
            let resources = slot.resources.as_ref();
            resources
                .and_then(|resources| resources.maintenance.as_ref())
                .map(|maintenance| maintenance.commands.clone())
        };
        let publication = match commands {
            Some(commands) => Maintenance::query_status(&commands).await,
            None => None,
        };
        let (native_bound, native_transferred, signal_bound, relay_reserved, ygg) = {
            let slot = slot_lock(&self.shared.slot);
            match slot.resources.as_ref() {
                Some(resources) => readiness_view(&self.shared, Some(resources)),
                None => slot.closing.as_ref().map_or_else(
                    || readiness_view(&self.shared, None),
                    |claims| {
                        (
                            claims.native_bound,
                            claims.native_transferred,
                            claims.signal_bound,
                            claims.relay_reserved,
                            claims.ygg,
                        )
                    },
                ),
            }
        };
        SharedReadiness {
            publication,
            native_bound,
            native_transferred,
            signal_bound,
            relay_reserved,
            ygg,
        }
    }

    pub(crate) fn ygg_phase(&self) -> YggPhase {
        let slot = slot_lock(&self.shared.slot);
        match slot.resources.as_ref() {
            Some(resources) => resources
                .ygg
                .as_ref()
                .map_or(YggPhase::None, YggResources::phase),
            None => slot
                .closing
                .as_ref()
                .map_or(YggPhase::None, |claims| claims.ygg),
        }
    }

    #[cfg(test)]
    pub(crate) async fn submit_watcher_snapshot_for_tests(
        &self,
        address: EndpointAddr,
    ) -> Result<(), RuntimeError> {
        let commands = slot_lock(&self.shared.slot)
            .resources
            .as_ref()
            .and_then(|resources| resources.maintenance.as_ref())
            .map(|maintenance| maintenance.commands.clone())
            .ok_or(RuntimeError::Closed)?;
        Maintenance::submit_for_tests(&commands, address).await
    }

    /// Test-only completion barrier: the reply resolves from the active
    /// resolver's own completion event, so `true` proves the cancel request
    /// was processed and the resolver future drained. Without an active
    /// resolver it answers immediately.
    #[cfg(test)]
    pub(crate) async fn resolve_idle_for_tests(&self) -> bool {
        let commands = slot_lock(&self.shared.slot)
            .resources
            .as_ref()
            .and_then(|resources| resources.maintenance.as_ref())
            .map(|maintenance| maintenance.commands.clone());
        match commands {
            Some(commands) => Maintenance::resolve_idle_for_tests(&commands).await,
            None => false,
        }
    }

    /// Direct publisher-watch state of the retained Mainline owner, independent
    /// of maintenance removal.
    #[cfg(test)]
    pub(crate) fn mainline_publication_status_for_tests(
        &self,
    ) -> Option<crate::native_discovery::runtime::publisher::PublicationStatus> {
        slot_lock(&self.shared.slot)
            .resources
            .as_ref()
            .and_then(|resources| resources.owner.as_ref())
            .map(RuntimeOwner::publication_status)
    }

    /// Clones the retained Mainline owner's publication observer so tests can
    /// observe held cleanup cancellation directly.
    #[cfg(test)]
    pub(crate) fn mainline_cleanup_observer_for_tests(&self) -> Option<n0_mainline::Observer> {
        self.shared
            .cleanup_hold_observer_for_tests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Test-only Mainline actor routing id, captured at the owner stage so
    /// regressions can assert a resolve target is an isolated owned query.
    #[cfg(test)]
    pub(crate) fn mainline_actor_id_for_tests(&self) -> Option<n0_mainline::Id> {
        self.shared
            .mainline_actor_id_for_tests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Arms the unique Mainline cleanup hold over the retained owner's
    /// publication observer; `Err(())` when the owner stage never stored one.
    #[cfg(test)]
    pub(crate) fn mainline_cleanup_hold_for_tests(&self) -> Result<n0_mainline::CleanupHold, ()> {
        let observer = self.mainline_cleanup_observer_for_tests().ok_or(())?;
        observer.hold_cleanup().map_err(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn arm_native_close_fault_for_tests(&self) {
        self.shared
            .native_close_fault_for_tests
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn arm_mainline_close_skip_for_tests(&self) {
        self.shared
            .mainline_close_skip_for_tests
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn arm_ygg_close_fault_for_tests(&self) {
        self.shared
            .close_fault_for_tests
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) async fn ygg_bridge_probe_for_tests(
        &self,
        peer: [u8; 32],
        budget: std::time::Duration,
    ) -> Result<std::time::Duration, shaar_ygg::ProbeError> {
        let bridge = slot_lock(&self.shared.slot)
            .resources
            .as_ref()
            .and_then(|resources| resources.ygg.as_ref())
            .and_then(|ygg| ygg.bridge.as_ref())
            .cloned()
            .ok_or(shaar_ygg::ProbeError::Closed)?;
        bridge.probe(peer, budget).await
    }

    /// Test-only handle to the retained Yggdrasil bridge (a real `Arc`
    /// clone): probes and the dropped-datagram counter run on it without
    /// borrowing the composition. `Err(())` when no bridge is retained.
    #[cfg(test)]
    pub(crate) fn ygg_bridge_for_tests(&self) -> Result<std::sync::Arc<shaar_ygg::YggBridge>, ()> {
        slot_lock(&self.shared.slot)
            .resources
            .as_ref()
            .and_then(|resources| resources.ygg.as_ref())
            .and_then(|ygg| ygg.bridge.as_ref())
            .cloned()
            .ok_or(())
    }

    #[cfg(test)]
    pub(crate) fn endpoint_for_tests<R>(
        &self,
        f: impl FnOnce(&SignaledEndpoint) -> R,
    ) -> Option<R> {
        self.with_endpoint(f)
    }

    /// Clones the retained owner's publication watch so tests await real
    /// publisher changes instead of polling readiness queries.
    #[cfg(test)]
    pub(crate) fn publication_watch_for_tests(&self) -> Option<watch::Receiver<PublicationStatus>> {
        self.shared
            .publication_watch_for_tests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
