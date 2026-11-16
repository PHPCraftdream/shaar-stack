//! Test-only access to retained production resources and genuine lifecycle barriers.
use super::{
    Maintenance, PublicationStatus, RuntimeError, RuntimeOwner, SharedResources, SignaledEndpoint,
    slot_lock,
};
use iroh::EndpointAddr;
use std::net::SocketAddr;
use std::sync::PoisonError;
use tokio::sync::{mpsc, oneshot, watch};

impl SharedResources {
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
        *self
            .shared
            .mainline_actor_id_for_tests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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

impl Maintenance {
    /// Spawns a task that acknowledges the watcher stop and then panics,
    /// producing a deterministic terminal join failure.
    #[cfg(test)]
    pub(crate) fn spawn_failing_for_tests() -> Self {
        let (commands, _receiver) = mpsc::channel(super::maintain::COMMANDS);
        let (stop, _stopped) = oneshot::channel();
        let (watcher_stopped_tx, watcher_stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = watcher_stopped_tx.send(());
            panic!("injected maintenance task failure");
        });
        Self {
            commands,
            votes: watch::channel(None).1,
            hint: watch::channel(None).1,
            stop: Some(stop),
            task: Some(task),
            watcher_stopped: Some(watcher_stopped),
            terminal_failure: None,
        }
    }
}

pub(crate) struct StageControls {
    pub(crate) after_bridge: Option<(oneshot::Receiver<()>, oneshot::Sender<()>)>,
    pub(crate) after_native_close: Option<(oneshot::Receiver<()>, oneshot::Sender<()>)>,
}

pub(super) struct StageGates {
    pub(super) after_bridge: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    pub(super) after_native_close: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    pub(super) native_bind: Option<SocketAddr>,
}

#[expect(
    clippy::type_complexity,
    reason = "Returns both endpoints of two one-shot stage gates"
)]
pub(super) fn stage_pair() -> (
    (oneshot::Sender<()>, oneshot::Receiver<()>),
    (oneshot::Receiver<()>, oneshot::Sender<()>),
) {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    ((entered_tx, release_rx), (entered_rx, release_tx))
}
