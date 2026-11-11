//! Retained composition startup and its owner-task shutdown route.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use iroh_base::PublicKey;
use shaar_p2p::RelayAddr;
use shaar_ygg::{YggBridge, YggError};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::config::Fallback;
use crate::identity::Identity;
use crate::native_discovery::runtime::owner::RuntimeOwner;
use crate::network::{Allowlist, Limits, SignaledEndpoint, YggEndpoint};
use crate::startup::error::StartupError;
use crate::startup::preflight::ComposedStartupPlan;
use crate::startup::ygg_start::start_ygg_same_identity;

use super::close::{quiesce_native, run_ordered_close};
use super::maintain::Maintenance;
use super::{
    OwnerRequest, SharedResources, SharedState, StartupResources, Status, YggResources, slot_lock,
};

type OwnerCommands = mpsc::Sender<OwnerRequest>;

/// Plan-derived startup inputs, owned so the spawned owner task can take
/// them by value after `start_seamed` resolves the borrowed plan.
struct StartupSettings {
    signaling_bind: Option<SocketAddr>,
    mainline: Option<(std::net::SocketAddrV4, Vec<std::net::SocketAddrV4>)>,
    ygg_peers: Option<Vec<String>>,
    app_peers: Vec<PublicKey>,
    mode: Fallback,
    /// When true, native/signaling and Ygg payload endpoints share ONE
    /// bounded admission pool instead of fresh per-endpoint pools.
    shared_admission: bool,
}

#[cfg(test)]
pub(crate) struct StageControls {
    pub(crate) after_bridge: Option<(oneshot::Receiver<()>, oneshot::Sender<()>)>,
    pub(crate) after_native_close: Option<(oneshot::Receiver<()>, oneshot::Sender<()>)>,
}

#[cfg(test)]
pub(super) struct StageGates {
    pub(super) after_bridge: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    pub(super) after_native_close: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    pub(super) native_bind: Option<SocketAddr>,
}

#[cfg(test)]
#[expect(
    clippy::type_complexity,
    reason = "Returns both endpoints of two one-shot stage gates"
)]
fn stage_pair() -> (
    (oneshot::Sender<()>, oneshot::Receiver<()>),
    (oneshot::Receiver<()>, oneshot::Sender<()>),
) {
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    ((entered_tx, release_rx), (entered_rx, release_tx))
}

/// Retained construction owner. Waiter cancellation never owns partial resources.
pub(crate) struct SharedResourcesStart {
    shared: Arc<SharedState>,
    owner_commands: Option<OwnerCommands>,
    task: Option<JoinHandle<Result<(), StartupError>>>,
    outcome: Option<Result<(), StartupError>>,
}

impl fmt::Debug for SharedResourcesStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedResourcesStart(..)")
    }
}

impl Drop for SharedResourcesStart {
    fn drop(&mut self) {
        // Best-effort signal only; explicit shutdown is the joined path.
        self.owner_commands = None;
    }
}

impl SharedResourcesStart {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "Retained non-shared admission startup contract")
    )]
    pub(crate) fn start(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
    ) -> Self {
        Self::start_shared(identity, plan, limits, false)
    }

    /// When `shared_admission` is true, the native/signaling endpoint and the
    /// Yggdrasil payload endpoint are built over ONE shared admission pool.
    pub(crate) fn start_shared(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
        shared_admission: bool,
    ) -> Self {
        Self::start_seamed(
            identity,
            plan,
            limits,
            false,
            false,
            shared_admission,
            #[cfg(test)]
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn start_with_payload_fault_for_tests(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
    ) -> Self {
        Self::start_seamed(identity, plan, limits, true, false, false, None)
    }

    #[cfg(test)]
    pub(crate) fn start_with_cleanup_hold_for_tests(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
    ) -> Self {
        Self::start_seamed(identity, plan, limits, false, true, false, None)
    }

    #[cfg(test)]
    pub(crate) fn start_paused_for_tests(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
        pause_after_bridge: bool,
        pause_after_native_close: bool,
    ) -> (Self, StageControls) {
        let (after_bridge_gate, after_bridge) = if pause_after_bridge {
            let (gate, control) = stage_pair();
            (Some(gate), Some(control))
        } else {
            (None, None)
        };
        let (after_native_close_gate, after_native_close) = if pause_after_native_close {
            let (gate, control) = stage_pair();
            (Some(gate), Some(control))
        } else {
            (None, None)
        };
        let gates = StageGates {
            after_bridge: after_bridge_gate,
            after_native_close: after_native_close_gate,
            native_bind: None,
        };
        let controls = StageControls {
            after_bridge,
            after_native_close,
        };
        (
            Self::start_seamed(identity, plan, limits, false, false, false, Some(gates)),
            controls,
        )
    }

    #[cfg(test)]
    pub(crate) fn start_shared_seamed_for_tests(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
        shared_admission: bool,
        cleanup_hold: bool,
        pause_after_bridge: bool,
    ) -> (Self, StageControls) {
        let (after_bridge_gate, after_bridge) = if pause_after_bridge {
            let (gate, control) = stage_pair();
            (Some(gate), Some(control))
        } else {
            (None, None)
        };
        let controls = StageControls {
            after_bridge,
            after_native_close: None,
        };
        (
            Self::start_seamed(
                identity,
                plan,
                limits,
                false,
                cleanup_hold,
                shared_admission,
                Some(StageGates {
                    after_bridge: after_bridge_gate,
                    after_native_close: None,
                    native_bind: None,
                }),
            ),
            controls,
        )
    }

    pub(super) fn start_seamed(
        identity: &Identity,
        plan: &ComposedStartupPlan<'_>,
        limits: Limits,
        #[cfg_attr(not(test), allow(unused_variables))] payload_fault: bool,
        #[cfg_attr(not(test), allow(unused_variables))] cleanup_hold: bool,
        shared_admission: bool,
        #[cfg(test)] controls: Option<StageGates>,
    ) -> Self {
        let network = plan.network();
        let signaling = network.signaling();
        let signaling_bind = signaling.map(|settings| settings.bind());
        let configured_relay = signaling.and_then(|settings| {
            RelayAddr::new(*settings.relay_peer_id(), settings.relay_address()).ok()
        });
        let mainline = network
            .mainline()
            .map(|settings| (settings.bind(), settings.bootstrap().to_vec()));
        let ygg_peers = network.ygg().map(|settings| settings.peers().to_vec());
        let app_peers = plan.app_peers().to_vec();
        let mode = plan.fallback();
        let settings = StartupSettings {
            signaling_bind,
            mainline,
            ygg_peers,
            app_peers,
            mode,
            shared_admission,
        };
        let (status_tx, status_rx) = watch::channel(Status::Pending);
        let (completion_tx, _) = watch::channel(None);
        let (owner_commands, mut owner_requests) = mpsc::channel(1);
        let shared = Arc::new(SharedState {
            configured_relay: configured_relay.expect("preflight validated relay settings"),
            slot: std::sync::Mutex::new(super::CompositionSlot {
                resources: None,
                closing: None,
                orphan_native: Vec::new(),
                orphan_ygg: Vec::new(),
            }),
            status_tx,
            status_rx,
            first_close_error: std::sync::Mutex::new(None),
            completion_tx,
            #[cfg(test)]
            publication_watch_for_tests: std::sync::Mutex::new(None),
            #[cfg(test)]
            close_fault_for_tests: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            native_close_fault_for_tests: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            mainline_close_skip_for_tests: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            payload_fault_for_tests: std::sync::atomic::AtomicBool::new(payload_fault),
            #[cfg(test)]
            cleanup_hold_armed_for_tests: std::sync::atomic::AtomicBool::new(cleanup_hold),
            #[cfg(test)]
            cleanup_hold_observer_for_tests: std::sync::Mutex::new(None),
            #[cfg(test)]
            mainline_actor_id_for_tests: std::sync::Mutex::new(None),
        });
        let owner_shared = Arc::clone(&shared);
        let identity = identity.clone();
        let task = tokio::spawn(async move {
            run_startup(
                &owner_shared,
                &identity,
                settings,
                limits,
                &mut owner_requests,
                #[cfg(test)]
                controls,
            )
            .await
        });
        Self {
            shared,
            owner_commands: Some(owner_commands),
            task: Some(task),
            outcome: None,
        }
    }

    /// cancel-safe: YES — the owner task retains construction and publishes status.
    pub(crate) async fn wait(&mut self) -> Result<SharedResources, StartupError> {
        let mut status = self.shared.status_rx.clone();
        loop {
            match &*status.borrow() {
                Status::Admitted => {
                    return Ok(SharedResources {
                        shared: Arc::clone(&self.shared),
                        owner_commands: self
                            .owner_commands
                            .as_ref()
                            .expect("owner command route")
                            .clone(),
                    });
                }
                Status::Failed(error) => return Err(error.clone()),
                Status::Closed => return Err(StartupError::Ygg(YggError::Closed)),
                Status::Pending => {}
            }
            status
                .changed()
                .await
                .map_err(|_| StartupError::Ygg(YggError::Closed))?;
        }
    }

    #[cfg(test)]
    pub(crate) fn completion_observer_for_tests(
        &self,
    ) -> watch::Receiver<Option<Result<(), StartupError>>> {
        self.shared.completion_tx.subscribe()
    }

    /// Executes one bounded cleanup attempt. If Mainline retains cleanup,
    /// returns its first error and keeps the command/join route for repetition.
    /// A canceled caller keeps both routes and can call shutdown again.
    pub(crate) async fn shutdown(&mut self) -> Result<(), StartupError> {
        if let Some(outcome) = &self.outcome {
            return outcome.clone();
        }
        let (reply, response) = oneshot::channel();
        let sent = match self.owner_commands.as_ref() {
            Some(commands) => commands.send(OwnerRequest::Shutdown(reply)).await.is_ok(),
            None => false,
        };
        let complete = if sent {
            response.await.unwrap_or(true)
        } else {
            // The request receiver closed. Join below by borrowing the
            // retained task so a canceled previous waiter cannot race its
            // owner task's terminal result.
            true
        };
        if !complete {
            return Err(self
                .shared
                .first_error()
                .unwrap_or(StartupError::Close { stage: "mainline" }));
        }
        let result = match self.task.as_mut() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(_) => Err(StartupError::Close {
                    stage: "startup-owner",
                }),
            },
            None => self.outcome.clone().unwrap_or(Ok(())),
        };
        self.task = None;
        self.owner_commands = None;
        self.outcome = Some(result.clone());
        result
    }

    /// True while a previous shutdown returned an incomplete-close error and
    /// the command/join routes are retained for repetition. Callers must keep
    /// their operation resumable instead of caching a terminal result.
    pub(crate) fn shutdown_pending(&self) -> bool {
        self.outcome.is_none()
    }
}

async fn run_startup(
    shared: &Arc<SharedState>,
    identity: &Identity,
    settings: StartupSettings,
    limits: Limits,
    owner_requests: &mut mpsc::Receiver<OwnerRequest>,
    #[cfg(test)] controls: Option<StageGates>,
) -> Result<(), StartupError> {
    let StartupSettings {
        signaling_bind,
        mainline,
        ygg_peers,
        app_peers,
        mode,
        shared_admission,
    } = settings;
    #[cfg(test)]
    let (after_bridge, after_native_close, native_bind) =
        controls.map_or((None, None, None), |gates| {
            (
                gates.after_bridge,
                gates.after_native_close,
                gates.native_bind,
            )
        });
    #[cfg(test)]
    let (mut after_bridge_entered, mut after_bridge_release) = after_bridge
        .map_or((None, None), |(entered, release)| {
            (Some(entered), Some(release))
        });
    #[cfg(test)]
    let (after_native_close_entered, after_native_close_release) = after_native_close
        .map_or((None, None), |(entered, release)| {
            (Some(entered), Some(release))
        });
    let (signaling_bind, (mainline_bind, mainline_bootstrap), ygg_peers) =
        match (signaling_bind, mainline, ygg_peers) {
            (Some(signaling), Some(mainline), Some(ygg)) => (signaling, mainline, ygg),
            _ => return finish_fatal(shared, StartupError::NetworkRequired, owner_requests).await,
        };

    // One shared admission pool when requested, created BEFORE the signaling
    // endpoint bind; otherwise each endpoint keeps a fresh per-endpoint pool.
    let shared_slots = if shared_admission {
        Some(Arc::new(tokio::sync::Semaphore::new(limits.sessions)))
    } else {
        None
    };
    let endpoint_result = super::native::bind(
        identity,
        signaling_bind,
        &app_peers,
        limits,
        shared_slots.as_ref().map(Arc::clone),
        #[cfg(test)]
        native_bind,
    )
    .await;
    let endpoint = match endpoint_result {
        Ok(endpoint) => endpoint,
        Err(_) => return finish_fatal(shared, StartupError::NativeBind, owner_requests).await,
    };
    slot_lock(&shared.slot).resources = Some(StartupResources {
        endpoint: Some(endpoint),
        native_transferred: false,
        native_quiesced: false,
        maintenance: None,
        owner: None,
        withdrawal_done: false,
        ygg: None,
    });

    let owner = match RuntimeOwner::start(identity.clone(), mainline_bind, &mainline_bootstrap) {
        Ok(owner) => owner,
        Err(_) => return finish_fatal(shared, StartupError::MainlineStart, owner_requests).await,
    };
    #[cfg(test)]
    {
        *shared
            .publication_watch_for_tests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(owner.publication_watch());
    }
    #[cfg(test)]
    {
        let actor_id: n0_mainline::Id = *owner
            .dht_handle()
            .expect("owned mainline DHT handle")
            .info()
            .await
            .expect("mainline actor info")
            .id();
        *shared
            .mainline_actor_id_for_tests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(actor_id);
    }
    let watcher = {
        #[cfg(test)]
        {
            if shared
                .cleanup_hold_armed_for_tests
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                let observer = owner
                    .dht_handle()
                    .expect("owned mainline DHT handle")
                    .publication_observer();
                *shared
                    .cleanup_hold_observer_for_tests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observer);
            }
        }
        let slot = slot_lock(&shared.slot);
        slot.resources
            .as_ref()
            .and_then(|resources| resources.endpoint.as_ref())
            .map(SignaledEndpoint::native_addr_watcher)
            .expect("native endpoint stage installed")
    };
    let maintenance = Maintenance::spawn(owner, watcher);
    slot_lock(&shared.slot)
        .resources
        .as_mut()
        .expect("native endpoint stage installed")
        .maintenance = Some(maintenance);

    let retained = start_ygg_same_identity(identity, &ygg_peers);
    slot_lock(&shared.slot)
        .resources
        .as_mut()
        .expect("resource slot installed")
        .ygg = Some(YggResources {
        start: Some(retained),
        bridge: None,
        payload: None,
        payload_transferred: false,
    });
    let admitted_result = {
        let mut retained = slot_lock(&shared.slot)
            .resources
            .as_mut()
            .and_then(|resources| resources.ygg.as_mut())
            .and_then(|resources| resources.start.take())
            .expect("retained start installed");
        let result = retained.wait().await;
        slot_lock(&shared.slot)
            .resources
            .as_mut()
            .and_then(|resources| resources.ygg.as_mut())
            .expect("Ygg stage retained")
            .start = Some(retained);
        result
    };
    let admitted = match admitted_result {
        Ok(admitted) => admitted,
        Err(error) => return finish_fatal(shared, error, owner_requests).await,
    };
    let transport = match admitted.take_transport() {
        Some(transport) => transport,
        None => {
            return finish_fatal(shared, StartupError::Ygg(YggError::Closed), owner_requests).await;
        }
    };
    let answer_to = app_peers.iter().map(|key| *key.as_bytes());
    let bridge = Arc::new(YggBridge::new(transport, answer_to));
    slot_lock(&shared.slot)
        .resources
        .as_mut()
        .and_then(|resources| resources.ygg.as_mut())
        .expect("Ygg stage retained")
        .bridge = Some(Arc::clone(&bridge));

    #[cfg(test)]
    if let Some(release) = after_bridge_release.take() {
        if let Some(entered) = after_bridge_entered.take() {
            let _ = entered.send(());
        }
        let _ = release.await;
    }

    let payload = if mode == Fallback::Signal || app_peers.is_empty() {
        None
    } else {
        #[cfg(test)]
        if shared
            .payload_fault_for_tests
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return finish_fatal(shared, StartupError::YggPayload, owner_requests).await;
        }
        let allowlist = match Allowlist::new(&app_peers) {
            Ok(allowlist) => allowlist,
            Err(_) => return finish_fatal(shared, StartupError::YggPayload, owner_requests).await,
        };
        let bind_result = match shared_slots.as_ref() {
            // Shared admission pool with the native/signaling endpoint.
            Some(slots) => {
                YggEndpoint::bind_shared_slots(
                    identity,
                    &bridge,
                    allowlist,
                    limits,
                    Arc::clone(slots),
                )
                .await
            }
            None => YggEndpoint::bind(identity, &bridge, allowlist, limits).await,
        };
        match bind_result {
            Ok(pair) => Some(pair),
            Err(_) => return finish_fatal(shared, StartupError::YggPayload, owner_requests).await,
        }
    };
    slot_lock(&shared.slot)
        .resources
        .as_mut()
        .and_then(|resources| resources.ygg.as_mut())
        .expect("Ygg stage retained")
        .payload = payload;
    shared.set_status(Status::Admitted);
    service_cleanup(
        shared,
        owner_requests,
        None,
        #[cfg(test)]
        after_native_close_entered,
        #[cfg(test)]
        after_native_close_release,
    )
    .await
}

async fn finish_fatal(
    shared: &Arc<SharedState>,
    fatal: StartupError,
    owner_requests: &mut mpsc::Receiver<OwnerRequest>,
) -> Result<(), StartupError> {
    let _ = run_ordered_close(
        shared,
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
    .await;
    // Publish failure only after the acquired prefix has received its first
    // ordered rollback attempt. If cleanup remains pending, later shutdown
    // commands repeat it while waiters can observe the original fatal error.
    shared.set_status(Status::Failed(fatal.clone()));
    service_cleanup(
        shared,
        owner_requests,
        Some(fatal),
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
    .await
}

async fn service_cleanup(
    shared: &Arc<SharedState>,
    owner_requests: &mut mpsc::Receiver<OwnerRequest>,
    fatal: Option<StartupError>,
    #[cfg(test)] mut after_native_close_entered: Option<oneshot::Sender<()>>,
    #[cfg(test)] mut after_native_close_release: Option<oneshot::Receiver<()>>,
) -> Result<(), StartupError> {
    loop {
        let Some(request) = owner_requests.recv().await else {
            let complete = run_ordered_close(
                shared,
                #[cfg(test)]
                None,
                #[cfg(test)]
                None,
            )
            .await;
            if complete {
                return terminal_result(shared, fatal);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        };
        match request {
            OwnerRequest::QuiesceNative(reply) => {
                let complete = quiesce_native(shared).await;
                let _ = reply.send(complete);
            }
            OwnerRequest::Shutdown(reply) => {
                let complete = run_ordered_close(
                    shared,
                    #[cfg(test)]
                    after_native_close_entered.take(),
                    #[cfg(test)]
                    after_native_close_release.take(),
                )
                .await;
                let _ = reply.send(complete);
                if complete {
                    return terminal_result(shared, fatal);
                }
            }
        }
    }
}

fn terminal_result(
    shared: &Arc<SharedState>,
    fatal: Option<StartupError>,
) -> Result<(), StartupError> {
    let result = fatal.map_or_else(|| shared.first_error().map_or(Ok(()), Err), Err);
    shared.set_status(Status::Closed);
    let _ = shared.completion_tx.send_replace(Some(result.clone()));
    result
}
