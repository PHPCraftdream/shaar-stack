//! The composed production client role: key-only service location, retained
//! and cancellation-safe.
//!
//! The service key is the only required locator: without an explicit direct
//! address hint the first dial resolves the key through the owned Mainline
//! runtime. Native priority is fixed (direct, then relay negotiation); the
//! Yggdrasil fallback exists only in `Mode::Standby`. The client keeps
//! independent per-endpoint admission pools — route switching must not
//! contend with a held relay lease (shared admission is the server contract).
//!
//! Cancellation safety: no owner (composition start handle, path owner,
//! endpoint/payload owners, forward workers) ever lives in a waiter local
//! across an await — they all live in [`ClientParts`], inside the retained
//! [`ClientPhase`] or inside the boxed close continuation stored on the role.
//! Ownership retention is the guarantee for BOTH roles: the run-loop awaits
//! are cancel-safe primitives, while the shutdown contract is that the stored
//! continuation resumes the same owned operation until terminal. Cancelling a
//! waiter therefore never drops an owner, and a later call resumes the
//! retained state.
//! Dropping the whole [`ClientRole`] degrades to the synchronous best-effort
//! restore in [`ClientParts::drop`] (no async work in `Drop`): owners that can
//! still be unwrapped are restored into the composition slot, `Arc` clones
//! still shared with dialer tasks are recorded as orphans, and dropping
//! `SharedResourcesStart` hands the joined close to the composition owner
//! task. The pre-close `Side` drop inside the path owner is abort-only and is
//! only reached on that degraded path, never on the joined shutdown path.
//!
//! Ordering: the role never closes a live endpoint itself. The owned owners
//! are restored into the retained composition, and
//! `SharedResourcesStart::shutdown` performs the canonical ordered close
//! (watcher stop, publication withdraw, Mainline close, then native endpoint
//! close, payload before bridge) — see startup/resources/close.rs.

use std::net::SocketAddr;
use std::sync::Arc;

use iroh_base::PublicKey;
use shaar_p2p::RelayAddr;
use shaar_ygg::YggPump;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::config::{ClientConfig, Fallback};
use crate::identity::Identity;
use crate::network::{ForwardError, ForwardStats, Limits, SignaledEndpoint, YggEndpoint};
use crate::path::{Mode, PathKind, StandbyError, StandbyOwner};
use crate::startup::StartupError;
use crate::startup::preflight::preflight_client;
use crate::startup::resources::{SharedResources, SharedResourcesStart};
use crate::startup::role::RoleOptions;
use crate::startup::role::dialers::{
    ErasedClientOwner, MissingYggDialer, NativeDialer, RouteLink, YggDialer,
};
#[cfg(test)]
use crate::startup::role::{RoleEvent, RoleEventLog, emit, emit_payload_acquired};

#[cfg(test)]
#[path = "client_seams.rs"]
mod test_seams;

/// Bound on concurrent local forward workers, mirroring the current binary.
const MAX_FORWARDS: usize = 16;

/// Retained live-role state used by both the `Live` phase and the close continuation.
struct ClientParts {
    start: SharedResourcesStart,
    resources: SharedResources,
    /// `None` once the joined owner close has run.
    owner: Option<Box<dyn ErasedClientOwner>>,
    /// Exactly ONE Arc is owned here; the second clone lives in `NativeDialer`
    /// and is dropped by `drop(owner)` before the exclusive unwrap below.
    native: Option<Arc<SignaledEndpoint>>,
    /// Owned payload pair; one Arc clone lives in `YggDialer`.
    payload: Option<(Arc<YggEndpoint>, YggPump)>,
    listener: Option<TcpListener>,
    lease: Option<(PathKind, Arc<dyn RouteLink>)>,
    workers: JoinSet<Result<ForwardStats, ForwardError>>,
    /// Cached pump outcome: polling a finished pump would spin, so this
    /// disables the pump arm after its first completion.
    pump_finished: bool,
    /// Terminal run error (truthful first error).
    outcome: Option<StartupError>,
    /// Set true only when `close_parts` completed.
    joined: bool,
    #[cfg(test)]
    events: Option<RoleEventLog>,
}

impl ClientParts {
    /// Degraded-path restore (no await, no spawn): unwrappable owners go back
    /// to the retained slot; still-shared Arc clones are recorded as orphans
    /// for the composition's ordered close. Dropping `start` afterwards hands
    /// rollback and close to the composition owner task.
    fn restore_owners_sync(&mut self) {
        // Release the dialers' Arc clones so the unwraps below see at most the pending ones.
        self.owner.take();
        let endpoint = match self.native.take() {
            Some(arc) => match Arc::try_unwrap(arc) {
                Ok(endpoint) => Some(endpoint),
                Err(arc) => {
                    self.resources.record_orphan_native(arc);
                    None
                }
            },
            None => None,
        };
        let payload = match self.payload.take() {
            Some((arc, pump)) => match Arc::try_unwrap(arc) {
                Ok(ygg) => Some((ygg, pump)),
                Err(arc) => {
                    self.resources.record_orphan_ygg((arc, pump));
                    None
                }
            },
            None => None,
        };
        self.resources.restore_live_owners(endpoint, payload);
    }
}

impl Drop for ClientParts {
    fn drop(&mut self) {
        if self.joined {
            return;
        }
        // No async work in `Drop`: workers are aborted by the `JoinSet` drop;
        // the abort-only `Side` drop is only reached here (see path/standby).
        self.restore_owners_sync();
    }
}

/// Retained phase machine of the client role.
enum ClientPhase {
    /// Built, nothing acquired.
    New,
    /// Composition admitted, construction wait in progress.
    Starting(SharedResourcesStart),
    /// Serving; all owners live in `ClientParts`.
    Live(Box<ClientParts>),
    /// Joined close continuation stored ON the role: a cancelled waiter
    /// parks the in-progress cleanup inside the role.
    Closing(std::pin::Pin<Box<super::ClientCloseContinuation>>),
    /// Terminal, truthfully cached result.
    Done(Result<(), StartupError>),
}

/// Public retained client entry point of the shared production role startup.
///
/// Unlike the former one-shot `serve_client`, this role is resumable:
/// `start`/`run`/`shutdown` may be driven by any caller, and every waiter is
/// cancel-safe (see the module doc). The role type is intentionally NOT
/// `Send` (the boxed owner futures are not); no task is spawned from this
/// file except the capped forward workers.
pub struct ClientRole {
    config: ClientConfig,
    identity: Identity,
    limits: Limits,
    options: RoleOptions,
    #[cfg(test)]
    events: Option<RoleEventLog>,
    phase: ClientPhase,
}

impl ClientRole {
    /// Builds the retained role. Sync validation only (`RoleOptions::validate`).
    pub fn new(
        config: ClientConfig,
        identity: &Identity,
        limits: Limits,
        options: RoleOptions,
    ) -> Result<Self, StartupError> {
        Self::build(
            config,
            identity,
            limits,
            options,
            #[cfg(test)]
            None,
        )
    }

    /// cfg(test) constructor that attaches the in-crate event observer; the
    /// production behavior is identical.
    #[cfg(test)]
    pub(crate) fn with_events(
        config: ClientConfig,
        identity: &Identity,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
    ) -> Result<Self, StartupError> {
        Self::build(
            config,
            identity,
            limits,
            options,
            #[cfg(test)]
            Some(events),
        )
    }

    fn build(
        config: ClientConfig,
        identity: &Identity,
        limits: Limits,
        options: RoleOptions,
        #[cfg(test)] events: Option<RoleEventLog>,
    ) -> Result<Self, StartupError> {
        options.validate()?;
        Ok(Self {
            config,
            identity: identity.clone(),
            limits,
            options,
            #[cfg(test)]
            events,
            phase: ClientPhase::New,
        })
    }

    /// Resumable startup.
    /// cancel-safe: YES — partial acquisitions stay owned by the role across
    /// cancelled waiters; a failed wait restores the `Starting` phase so a
    /// retry resumes truthfully.
    pub async fn start(&mut self) -> Result<(), StartupError> {
        // Preflight runs before taking the phase; `start_shared` copies what the owner task needs.
        if matches!(self.phase, ClientPhase::New) {
            let start = {
                let service_key = PublicKey::from_bytes(self.config.server_key_bytes())
                    .map_err(|_| StartupError::InvalidPolicy)?;
                let service_keys = [service_key];
                let plan = preflight_client(&self.config, &self.identity, &service_keys)?;
                SharedResourcesStart::start_shared(&self.identity, &plan, self.limits, false)
            };
            self.phase = ClientPhase::Starting(start);
            return self.resume_start().await;
        }
        match std::mem::replace(&mut self.phase, ClientPhase::Done(Ok(()))) {
            ClientPhase::Starting(start) => self.phase = ClientPhase::Starting(start),
            // Handled above, before the phase take.
            ClientPhase::New => unreachable!("New handled before the phase take"),
            // Already serving: idempotent re-entry.
            phase @ ClientPhase::Live(_) => {
                self.phase = phase;
                return Ok(());
            }
            phase @ ClientPhase::Closing(_) => {
                self.phase = phase;
                return Err(StartupError::Close {
                    stage: "role-closing",
                });
            }
            ClientPhase::Done(result) => {
                self.phase = ClientPhase::Done(result.clone());
                return result;
            }
        }
        self.resume_start().await
    }

    /// Waits for admission, builds the live parts; a seed error enters the
    /// joined `Closing` rollback with its truthful first error.
    async fn resume_start(&mut self) -> Result<(), StartupError> {
        // cancel-safe watch loop; the start handle stays in the phase.
        let waited = match &mut self.phase {
            ClientPhase::Starting(start) => start.wait().await,
            _ => unreachable!("resume_start is only called on Starting"),
        };
        let resources = match waited {
            Ok(resources) => resources,
            // The start handle was never removed: a retry resumes truthfully.
            Err(error) => return Err(error),
        };
        // Fallible validation keeps the phase `Starting`: the `?` retains the
        // start handle; later steps are infallible or seed the parts outcome.
        let service_key = PublicKey::from_bytes(self.config.server_key_bytes())
            .map_err(|_| StartupError::InvalidPolicy)?;
        let ClientPhase::Starting(start) =
            std::mem::replace(&mut self.phase, ClientPhase::Done(Ok(())))
        else {
            unreachable!("resume_start is only called on Starting")
        };
        let policy = self.options.policy;
        let mut seed: Option<StartupError> = None;
        // Live-role transfer; `None` is a truthful failure, never a fallback; the ops handle keeps relay reserve/release possible.
        let (native, ops) = match resources.take_native_live() {
            Some((endpoint, ops)) => (Some(endpoint), Some(ops)),
            None => {
                seed.get_or_insert(StartupError::Close {
                    stage: "native-transfer",
                });
                (None, None)
            }
        };
        // The pair exists only for `Standby`; presence selects the fallback
        // dialer type.
        let payload = resources
            .take_ygg_payload()
            .map(|(ygg_endpoint, pump)| (Arc::new(ygg_endpoint), pump));
        // Same derivation as the composition; unreachable `None` after preflight is a truthful failure, never a fallback.
        let relay_addr = self
            .config
            .network()
            .and_then(|network| network.signaling())
            .and_then(|signaling| {
                RelayAddr::new(*signaling.relay_peer_id(), signaling.relay_address()).ok()
            });
        if relay_addr.is_none() {
            seed.get_or_insert(StartupError::NetworkRequired);
        }
        let mode = match self.config.fallback() {
            Fallback::Signal => Mode::Signal,
            Fallback::Standby => Mode::Standby,
        };
        // Direct-address hint, never required; no candidates means the first dial resolves the service key.
        let candidates: Vec<SocketAddr> = self.config.server_address().into_iter().collect();
        // The fallback dialer clones the payload Arc before the parts take ownership; `StandbyOwner::new` failure seeds `InvalidPolicy`.
        let mut owner: Option<Box<dyn ErasedClientOwner>> = None;
        let mut native_arc: Option<Arc<SignaledEndpoint>> = None;
        if let Some(endpoint) = native {
            let arc = Arc::new(endpoint);
            if let (Some(relay_addr), Some(ops)) = (relay_addr, ops) {
                let ygg_arc = payload.as_ref().map(|(ygg, _)| Arc::clone(ygg));
                let native_dialer = NativeDialer::new(
                    Arc::clone(&arc),
                    service_key,
                    resources.clone(),
                    candidates,
                    relay_addr,
                    ops,
                    #[cfg(test)]
                    self.events.clone(),
                );
                let built = match ygg_arc {
                    // Never dialed when absent: the standby gate blocks the fallback in `Mode::Signal`.
                    Some(ygg) => StandbyOwner::new(
                        native_dialer,
                        YggDialer::new(ygg, service_key),
                        mode,
                        policy,
                    )
                    .map(super::boxed_owner),
                    None => StandbyOwner::new(native_dialer, MissingYggDialer, mode, policy)
                        .map(super::boxed_owner),
                };
                match built {
                    Ok(built) => owner = Some(built),
                    Err(_) => {
                        seed.get_or_insert(StartupError::InvalidPolicy);
                    }
                }
            }
            native_arc = Some(arc);
        }
        let parts = ClientParts {
            start,
            resources,
            owner,
            native: native_arc,
            payload,
            listener: None,
            lease: None,
            workers: JoinSet::new(),
            pump_finished: false,
            outcome: seed,
            joined: false,
            #[cfg(test)]
            events: self.events.take(),
        };
        if parts.outcome.is_some() {
            self.phase = ClientPhase::Closing(Box::pin(close_parts(parts)));
            self.await_closing().await
        } else {
            self.phase = ClientPhase::Live(Box::new(parts));
            Ok(())
        }
    }

    /// Resumable role loop (path policy, local listener, bounded forward
    /// workers, Ygg pump).
    /// cancel-safe: YES — every arm await is a cancel-safe primitive and all
    /// state lives in the retained parts.
    pub async fn run(
        &mut self,
        shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ) -> Result<(), StartupError> {
        match std::mem::replace(&mut self.phase, ClientPhase::Done(Ok(()))) {
            phase @ ClientPhase::Live(_) => {
                self.phase = phase;
            }
            phase @ ClientPhase::Closing(_) => {
                self.phase = phase;
                return Err(StartupError::Close {
                    stage: "role-closing",
                });
            }
            phase @ (ClientPhase::New | ClientPhase::Starting(_)) => {
                self.phase = phase;
                return Err(StartupError::Close {
                    stage: "role-not-started",
                });
            }
            ClientPhase::Done(result) => {
                self.phase = ClientPhase::Done(result.clone());
                return result;
            }
        }
        let listen = self.config.listen();
        let ClientPhase::Live(parts) = &mut self.phase else {
            unreachable!("phase restored to Live above")
        };
        run_parts(parts, listen, shutdown).await
    }

    /// Resumable joined shutdown.
    /// ownership-cancel-safe: YES — the close continuation is boxed and stored
    /// ON the role, so cancelling the waiter parks the in-progress joined
    /// cleanup inside the role and a later call resumes the SAME continuation.
    /// The phase terminalizes only when the continuation finished: joined
    /// cleanup, or a terminal close error. While composition cleanup is
    /// incomplete, the continuation keeps retrying the retained routes.
    pub async fn shutdown(&mut self) -> Result<(), StartupError> {
        // The `Starting` arm keeps the start handle in the phase across the
        // await: no irreplaceable owner lives in a waiter local, and an
        // incomplete composition close leaves the phase `Starting` for retry.
        if let ClientPhase::Starting(start) = &mut self.phase {
            let result = super::shutdown_start(start).await;
            let cached = result.clone();
            self.phase = ClientPhase::Done(cached);
            return result;
        }
        match std::mem::replace(&mut self.phase, ClientPhase::Done(Ok(()))) {
            ClientPhase::New => {
                self.phase = ClientPhase::Done(Ok(()));
                Ok(())
            }
            // Handled above, before the phase take.
            ClientPhase::Starting(_) => unreachable!("Starting handled before the phase take"),
            ClientPhase::Live(parts) => {
                // Store the continuation ON the role before awaiting it: a
                // cancelled waiter leaves the in-progress close parked in the
                // `Closing` phase.
                self.phase = ClientPhase::Closing(Box::pin(close_parts(*parts)));
                self.await_closing().await
            }
            ClientPhase::Closing(continuation) => {
                // Re-seat the removed continuation BEFORE awaiting: the take
                // above replaced the phase, and a resumed waiter must keep
                // polling the SAME stored close operation, not a fresh one.
                self.phase = ClientPhase::Closing(continuation);
                self.await_closing().await
            }
            ClientPhase::Done(result) => {
                self.phase = ClientPhase::Done(result.clone());
                result
            }
        }
    }

    /// Awaits the stored close continuation and terminalizes the phase ONLY
    /// when it finished (joined cleanup or a terminal close error): the
    /// continuation itself keeps retrying while composition cleanup is
    /// incomplete, so this await returns only a truthful terminal result.
    async fn await_closing(&mut self) -> Result<(), StartupError> {
        if let ClientPhase::Closing(continuation) = &mut self.phase {
            let result = continuation.as_mut().await;
            self.phase = ClientPhase::Done(result.clone());
            result
        } else {
            unreachable!("await_closing is only called on Closing")
        }
    }
}

/// The live role loop over retained parts (biased select, same arm order and emission points as
/// before). Once the outcome is set, `run` returns that error immediately; `Ok` closes nothing.
async fn run_parts(
    parts: &mut ClientParts,
    listen: SocketAddr,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Result<(), StartupError> {
    #[cfg(test)]
    emit_payload_acquired(parts.events.as_ref(), parts.payload.is_some());
    // Split borrow of the owned pump for the select arm.
    let mut pump = parts.payload.as_mut().map(|(_, pump)| pump);
    loop {
        // Reap finished forward workers without blocking on the other arms.
        while let Some(result) = parts.workers.try_join_next() {
            match result {
                Ok(Ok(_)) | Ok(Err(ForwardError::PathUnavailable)) => {}
                Ok(Err(ForwardError::TaskFailure)) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "forward-serve",
                    });
                }
                Ok(Err(error)) => eprintln!("shaar: forward worker ended: {error}"),
                Err(_) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "forward-serve",
                    });
                }
            }
        }
        // Terminal: caller must call `shutdown` for the joined close.
        if let Some(error) = parts.outcome.clone() {
            return Err(error);
        }
        // Bind failure is terminal.
        if parts.listener.is_none() {
            let listener = match TcpListener::bind(listen).await {
                Ok(listener) => listener,
                Err(_) => {
                    let error = StartupError::Listener;
                    parts.outcome = Some(error.clone());
                    return Err(error);
                }
            };
            #[cfg(test)]
            if let Ok(address) = listener.local_addr() {
                emit(parts.events.as_ref(), RoleEvent::ListenerReady(address));
            }
            #[cfg(test)]
            emit(parts.events.as_ref(), RoleEvent::Admitted);
            parts.listener = Some(listener);
        }
        tokio::select! {
            biased;
            () = &mut *shutdown => break,
            advanced = parts.owner.as_mut().expect("live parts retain the path owner").follow() => match advanced {
                Ok(kind) => {
                    // The lease owns its `Arc<Session>`: switching routes never
                    // aborts in-flight forward workers.
                    parts.lease = parts
                        .owner
                        .as_ref()
                        .expect("live parts retain the path owner")
                        .route()
                        .map(|route| (kind, route));
                    #[cfg(test)]
                    emit(parts.events.as_ref(), RoleEvent::RouteActive(kind));
                }
                // The owner is closed; end the loop cleanly.
                Err(StandbyError::Closed) => break,
                // Truthful exhaustion of the attempt budget.
                Err(_) => {
                    let error = StartupError::Exhausted;
                    parts.outcome = Some(error.clone());
                    return Err(error);
                }
            },
            accepted = parts.listener.as_mut().expect("listener is bound").accept(),
                if parts.lease.is_some() && parts.workers.len() < MAX_FORWARDS => {
                match accepted {
                    Ok((stream, _)) => {
                        if let Some((_, link)) = parts.lease.as_ref() {
                            let link = Arc::clone(link);
                            // JoinSet cap enforced by the guard above.
                            parts.workers.spawn(async move { link.forward(stream).await });
                        }
                    }
                    // Local accept hiccups never kill the client; the next
                    // loop iteration retries the listener.
                    Err(_) => eprintln!("shaar: local accept failed"),
                }
            }
            result = parts.workers.join_next(), if !parts.workers.is_empty() => {
                match result {
                    Some(Ok(Ok(_))) | Some(Ok(Err(ForwardError::PathUnavailable))) => {}
                    Some(Ok(Err(ForwardError::TaskFailure))) | Some(Err(_)) => {
                        let error = StartupError::Close {
                            stage: "forward-serve",
                        };
                        parts.outcome = Some(error.clone());
                        return Err(error);
                    }
                    Some(Ok(Err(error))) => eprintln!("shaar: forward worker ended: {error}"),
                    None => {}
                }
            }
            driven = async {
                pump.as_mut()
                    .expect("pump arm is guarded")
                    .run()
                    .await
            }, if pump.is_some() && !parts.pump_finished => {
                parts.pump_finished = true;
                if driven.is_err() {
                    eprintln!("shaar: ygg pump stopped");
                }
            },
        }
    }
    Ok(())
}

/// The OWNED close continuation: forward drain, owner close, restore, then
/// the composition's canonical ordered close — never closing a live endpoint
/// itself.
async fn close_parts(mut parts: ClientParts) -> Result<(), StartupError> {
    let mut first_error = parts.outcome.take();
    // Abort+join workers; the first fatal error is kept, others logged; cancelled joins are self-induced shutdown.
    parts.workers.abort_all();
    while let Some(result) = parts.workers.join_next().await {
        match result {
            Ok(Ok(_)) | Ok(Err(ForwardError::PathUnavailable)) => {}
            Err(join_error) if !join_error.is_cancelled() => {
                first_error.get_or_insert(StartupError::Close {
                    stage: "forward-drain",
                });
            }
            Err(_) => {}
            Ok(Err(ForwardError::TaskFailure)) => {
                first_error.get_or_insert(StartupError::Close {
                    stage: "forward-drain",
                });
            }
            Ok(Err(error)) => eprintln!("shaar: forward worker ended: {error}"),
        }
    }
    // Joins both dialer sides; `drop(owner)` releases the dialers and their Arc clones before the exclusive unwraps.
    if let Some(mut owner) = parts.owner.take() {
        if owner.close().await.is_err() {
            first_error.get_or_insert(StartupError::Close {
                stage: "path-owner",
            });
        }
        drop(owner);
    }
    // Restore as OWNED values; unwraps succeed on the normal two-Arc path, failure is a pending orphan.
    let endpoint = match parts.native.take() {
        Some(arc) => match Arc::try_unwrap(arc) {
            Ok(endpoint) => Some(endpoint),
            Err(arc) => {
                parts.resources.record_orphan_native(arc);
                first_error.get_or_insert(StartupError::Close {
                    stage: "native-close",
                });
                None
            }
        },
        None => None,
    };
    let payload = match parts.payload.take() {
        Some((arc, pump)) => match Arc::try_unwrap(arc) {
            Ok(ygg) => Some((ygg, pump)),
            Err(arc) => {
                parts.resources.record_orphan_ygg((arc, pump));
                first_error.get_or_insert(StartupError::Close { stage: "ygg-close" });
                None
            }
        },
        None => None,
    };
    parts.resources.restore_live_owners(endpoint, payload);
    // Canonical composition close: watcher stop + publication withdraw +
    // Mainline close before native endpoint close, payload before bridge.
    // An incomplete attempt keeps routes owned by `parts.start`; this SAME
    // continuation retries every second until terminal, so a cancelled
    // waiter resumes the same operation and the phase terminalizes only
    // when cleanup finishes.
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
                    // Incomplete: retain the first error truthfully and retry;
                    // joined completion has NOT happened yet.
                    first_error.get_or_insert(error);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                // Terminal: cleanup finished, possibly with a recorded
                // persistent close error.
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
