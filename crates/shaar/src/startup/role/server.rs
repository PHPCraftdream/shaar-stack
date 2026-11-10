//! The composed production server role: a retained, cancellation-safe phase
//! machine.
//!
//! One shared bounded admission pool covers native/signaling and Yggdrasil
//! payload paths (the server contract: `start_shared(.., true)`). Sessions
//! on either path are served against the fixed loopback target with
//! watch-driven stop and a bounded, joined session set.
//!
//! Destination-relay reservation lifecycle: after the live transfer of the
//! native endpoint, the server reserves the configured pinned relay address
//! with a bounded retry, storing any in-flight reserve on the role so a
//! cancelled waiter parks it (the carrier record stays `Pending`) and a
//! resumed waiter polls the SAME operation. The reservation is what makes
//! key-directed negotiation through the relay reachable for connecting
//! clients; it is released during the role's joined close while signaling is
//! still alive, and reconciled carrier-side by the endpoint close otherwise.
//!
//! Cancellation contract: waiter cancellation of [`ServerRole::start`],
//! [`ServerRole::run`] or [`ServerRole::shutdown`] never drops an owner —
//! ownership is retained across cancellation by keeping every owner inside
//! the phase. The native and Yggdrasil accept arms are themselves
//! cancellation-unsafe per their SDK contracts (`network/admission/mod.rs`,
//! `network/admission/ygg/mod.rs`): a losing select arm can abandon a
//! consumed handshake, which is not replayed, and the SDK returns the
//! admission slot. Dropping the whole role restores the owned owners into
//! the retained composition synchronously; the composition owner task's
//! ordered close (watcher stop + withdraw + Mainline close, payload before
//! bridge, native endpoint close last) then closes them.

use iroh_base::PublicKey;
use shaar_p2p::RelayAddr;
use shaar_ygg::YggPump;
use tokio::task::JoinSet;

use crate::config::ServerConfig;
use crate::identity::Identity;
use crate::network::signaling::RelayOperations;
use crate::network::{
    Allowlist, ForwardError, Limits, NetworkError, ServeReport, SignaledEndpoint, YggEndpoint,
};
#[cfg(test)]
use crate::path::PathKind;
use crate::startup::StartupError;
use crate::startup::preflight::preflight_server;
use crate::startup::resources::{SharedResources, SharedResourcesStart};
#[cfg(test)]
use crate::startup::role::{RoleEvent, RoleEventLog, emit, emit_payload_acquired};
use crate::startup::role::{RoleOptions, server_close};

/// Bounded reservation attempts: the carrier caps one record at three
/// attempts (`attempts >= 3` answers `capacity()`); slack covers cancellations.
const RELAY_RESERVE_ATTEMPTS: usize = 6;
/// Bounded retry pause; backend teardown and jitter may outlast it, so a
/// retry can still report capacity without starting a reservation. The role
/// cannot inspect backend deadlines; cancelled waiters resume the stored op.
fn reserve_pause(attempts: usize) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << (attempts.saturating_sub(1).min(3)))
}

/// Boxed joined-close continuation; cancellation drops only the poll.
type ServerCloseContinuation = dyn std::future::Future<Output = Result<(), StartupError>>;

/// One stored in-flight reservation operation. The carrier receives the
/// reserve command at this future's first poll; cancelling the start waiter
/// parks it (receiver alive) in `ServerParts` instead of dropping it, so a
/// resumed waiter polls the SAME operation.
type ReserveOperation =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::network::NetworkError>>>>;

/// Everything the live role owns, kept together so cancellation strands nothing.
pub(super) struct ServerParts {
    pub(super) start: SharedResourcesStart,
    pub(super) resources: SharedResources,
    /// Owned native endpoint; `accept` needs `&mut`, so exclusive.
    pub(super) endpoint: Option<SignaledEndpoint>,
    /// Owned Yggdrasil payload pair (endpoint, pump).
    pub(super) payload: Option<(YggEndpoint, YggPump)>,
    /// Relay operations handle cloned at the live transfer.
    pub(super) relay_ops: Option<RelayOperations>,
    /// The configured pinned relay address, if derivation succeeded.
    pub(super) relay_addr: Option<RelayAddr>,
    /// The destination reservation was established at startup.
    pub(super) reserved: bool,
    pub(super) stop: Option<(
        tokio::sync::watch::Sender<bool>,
        tokio::sync::watch::Receiver<bool>,
    )>,
    pub(super) sessions: JoinSet<Result<ServeReport, ForwardError>>,
    /// Set once `YggPump::run` returned its cached outcome; disables the pump.
    pub(super) pump_finished: bool,
    /// Set after a Yggdrasil accept `Closed` or pump error; disables that arm.
    pub(super) ygg_down: bool,
    /// Cached fatal outcome; the loop breaks and `run` returns it.
    pub(super) outcome: Option<StartupError>,
    /// Set by the joined close so `Drop` skips the best-effort restore.
    pub(super) joined: bool,
    /// Role-side reserve attempts, retained across cancellation (the carrier
    /// caps one record at three attempts and forgets failed records).
    pub(super) reserve_attempts: usize,
    /// Earliest next reserve retry, on the controller's backoff scale
    /// (`500ms * 2^attempts + jitter`); retained across cancellation.
    pub(super) reserve_not_before: Option<tokio::time::Instant>,
    /// The stored in-flight reserve operation, if started and not yet resolved.
    pub(super) reserve_op: Option<ReserveOperation>,
    #[cfg(test)]
    pub(super) events: Option<RoleEventLog>,
}

impl Drop for ServerParts {
    fn drop(&mut self) {
        // Sync best-effort only: dropping `start` hands close to the owner task.
        if self.joined {
            return;
        }
        self.resources
            .restore_live_owners(self.endpoint.take(), self.payload.take());
    }
}

impl ServerParts {
    fn new(
        start: SharedResourcesStart,
        resources: SharedResources,
        relay_addr: Option<RelayAddr>,
        #[cfg(test)] events: Option<RoleEventLog>,
    ) -> Self {
        Self {
            start,
            resources,
            endpoint: None,
            payload: None,
            relay_ops: None,
            relay_addr,
            reserved: false,
            stop: None,
            sessions: JoinSet::new(),
            pump_finished: false,
            ygg_down: false,
            outcome: None,
            joined: false,
            reserve_attempts: 0,
            reserve_not_before: None,
            reserve_op: None,
            #[cfg(test)]
            events,
        }
    }
}

/// Retained server phase; owners live in the phase, so cancellation loses nothing.
enum ServerPhase {
    New,
    Starting(SharedResourcesStart),
    Admitted(Box<ServerParts>),
    Live(Box<ServerParts>),
    Closing(std::pin::Pin<Box<ServerCloseContinuation>>),
    Done(Result<(), StartupError>),
}

/// Public retained server role. Intentionally not `Send`: the accept loop
/// split-borrows its payload pair across `select!` arms and the phase holds
/// retained non-Send owners.
pub struct ServerRole {
    config: ServerConfig,
    identity: Identity,
    allowlist: Allowlist,
    limits: Limits,
    options: RoleOptions,
    #[cfg(test)]
    events: Option<RoleEventLog>,
    phase: ServerPhase,
}

impl ServerRole {
    /// Validates the options only; no I/O. The allowlist is taken by value
    /// (not `Clone`) and its keys preflight the composed plan.
    pub fn new(
        config: ServerConfig,
        identity: &Identity,
        allowlist: Allowlist,
        limits: Limits,
        options: RoleOptions,
    ) -> Result<Self, StartupError> {
        options.validate()?;
        Ok(Self {
            config,
            identity: identity.clone(),
            allowlist,
            limits,
            options,
            #[cfg(test)]
            events: None,
            phase: ServerPhase::New,
        })
    }

    /// Test-only constructor attaching the event observer; otherwise identical
    /// to [`ServerRole::new`].
    #[cfg(test)]
    pub(crate) fn with_events(
        config: ServerConfig,
        identity: &Identity,
        allowlist: Allowlist,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
    ) -> Result<Self, StartupError> {
        let mut role = Self::new(config, identity, allowlist, limits, options)?;
        role.events = Some(events);
        Ok(role)
    }

    /// Test-only handle to THIS role's retained Yggdrasil bridge (a real
    /// `Arc<YggBridge>` clone; its dropped-datagram counter is the carrier
    /// peer filter observation). `Err(())` when no live composition.
    #[cfg(test)]
    pub(crate) fn ygg_bridge_for_tests(&self) -> Result<std::sync::Arc<shaar_ygg::YggBridge>, ()> {
        match &self.phase {
            ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                parts.resources.ygg_bridge_for_tests()
            }
            _ => Err(()),
        }
    }

    /// Test-only observer of the armed Mainline cleanup hold; `None` before
    /// the composition's owner stage stored it.
    #[cfg(test)]
    pub(crate) fn mainline_cleanup_observer_for_tests(&self) -> Option<n0_mainline::Observer> {
        match &self.phase {
            ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                parts.resources.mainline_cleanup_observer_for_tests()
            }
            _ => None,
        }
    }

    /// Test-only Mainline cleanup hold over the retained composition.
    #[cfg(test)]
    pub(crate) fn mainline_cleanup_hold_for_tests(&self) -> Result<n0_mainline::CleanupHold, ()> {
        match &self.phase {
            ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                parts.resources.mainline_cleanup_hold_for_tests()
            }
            _ => Err(()),
        }
    }

    /// Builds the real seamed start with shared admission and optional gates.
    /// Attaches the test observer, leaves the role in `Starting`, and returns
    /// controls for the armed gate; `start()` resumes construction.
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "Test seam exposes independent startup gates"
    )]
    pub(crate) fn with_events_seamed_for_tests(
        config: ServerConfig,
        identity: &Identity,
        allowlist: Allowlist,
        limits: Limits,
        options: RoleOptions,
        events: RoleEventLog,
        cleanup_hold: bool,
        pause_after_bridge: bool,
    ) -> Result<(Self, crate::startup::resources::StageControls), StartupError> {
        options.validate()?;
        let keys: Vec<PublicKey> = allowlist.keys().collect();
        let plan = preflight_server(&config, identity, &keys)?;
        let (start, controls) = SharedResourcesStart::start_shared_seamed_for_tests(
            identity,
            &plan,
            limits,
            true,
            cleanup_hold,
            pause_after_bridge,
        );
        // Same composition as `with_events` + the seamed starting phase:
        // `Self::new` validates the options, the role skips `new`'s `New`
        // phase by entering `Starting` directly; `start()` resumes it.
        let mut role = Self::new(config, identity, allowlist, limits, options)?;
        role.events = Some(events);
        role.phase = ServerPhase::Starting(start);
        Ok((role, controls))
    }

    /// Resumable startup: preflight, composition start, live transfer and
    /// the reservation. Cancel-safe: YES — ownership is retained across
    /// cancellation (state lives in the phase); `run`'s accept arms are
    /// individually cancellation-unsafe per the SDK contracts.
    pub async fn start(&mut self) -> Result<(), StartupError> {
        loop {
            // Terminal phases are answered without touching the state.
            if !matches!(
                self.phase,
                ServerPhase::New | ServerPhase::Starting(_) | ServerPhase::Admitted(_)
            ) {
                return match &self.phase {
                    ServerPhase::Live(_) => Ok(()),
                    ServerPhase::Closing(_) => Err(StartupError::Close {
                        stage: "role-closing",
                    }),
                    ServerPhase::Done(result) => result.clone(),
                    _ => unreachable!("terminal phase handled above"),
                };
            }
            match std::mem::replace(&mut self.phase, ServerPhase::New) {
                ServerPhase::New => {
                    // Idempotent: already validated at construction.
                    self.options.validate()?;
                    let keys: Vec<PublicKey> = self.allowlist.keys().collect();
                    let plan = preflight_server(&self.config, &self.identity, &keys)?;
                    // The server contract: ONE shared bounded admission pool.
                    let start = SharedResourcesStart::start_shared(
                        &self.identity,
                        &plan,
                        self.limits,
                        true,
                    );
                    self.phase = ServerPhase::Starting(start);
                }
                ServerPhase::Starting(start) => {
                    // Re-seat before awaiting: state lives in the phase.
                    self.phase = ServerPhase::Starting(start);
                    let ServerPhase::Starting(start) = &mut self.phase else {
                        unreachable!("re-seated starting phase")
                    };
                    let resources = match start.wait().await {
                        Err(error) => return Err(error),
                        Ok(resources) => resources,
                    };
                    // Everything below is synchronous: take the phase back.
                    let start = match std::mem::replace(&mut self.phase, ServerPhase::New) {
                        ServerPhase::Starting(start) => start,
                        _ => unreachable!("re-seated starting phase"),
                    };
                    // `None` after preflight is a truthful startup failure.
                    let relay_addr = self
                        .config
                        .network()
                        .and_then(|network| network.signaling())
                        .and_then(|signaling| {
                            RelayAddr::new(*signaling.relay_peer_id(), signaling.relay_address())
                                .ok()
                        });
                    let payload = resources.take_ygg_payload();
                    // Live-role transfer: `None` fails truthfully.
                    let transferred = resources.take_native_live();
                    let mut parts = ServerParts::new(
                        start,
                        resources,
                        relay_addr,
                        #[cfg(test)]
                        self.events.clone(),
                    );
                    parts.payload = payload;
                    let outcome = match transferred {
                        Some((endpoint, relay_ops)) => {
                            parts.endpoint = Some(endpoint);
                            parts.relay_ops = Some(relay_ops);
                            if parts.relay_addr.is_none() {
                                Some(StartupError::NetworkRequired)
                            } else {
                                None
                            }
                        }
                        // Truthful startup failure, never a silent fallback.
                        None => Some(StartupError::Close {
                            stage: "native-transfer",
                        }),
                    };
                    if let Some(error) = outcome {
                        parts.outcome = Some(error);
                        return self.begin_close(Box::new(parts)).await;
                    }
                    self.phase = ServerPhase::Admitted(Box::new(parts));
                }
                ServerPhase::Admitted(parts) => {
                    // Re-seat before awaiting: state lives in the phase.
                    self.phase = ServerPhase::Admitted(parts);
                    let ServerPhase::Admitted(parts) = &mut self.phase else {
                        unreachable!("re-seated admitted phase")
                    };
                    // Grounded in the carrier controller: a cancelled waiter
                    // parks its in-flight reserve here (no abandonment while
                    // the role lives); the record is stopped only when the
                    // whole role drops the stored receiver. Each attempt
                    // checks `has_reservation` first and pauses on the
                    // controller's own scale; state lives in `parts`.
                    let mut reserve_failed = false;
                    loop {
                        let Some(relay_addr) = parts.relay_addr else {
                            reserve_failed = true;
                            break;
                        };
                        // An already-active record short-circuits for free.
                        if parts
                            .relay_ops
                            .as_ref()
                            .is_some_and(|ops| ops.has_reservation(relay_addr))
                        {
                            parts.reserved = true;
                            break;
                        }
                        // Poll the STORED in-flight operation first: a
                        // cancelled waiter parked its reserve here (command
                        // submitted once), so resumption polls the SAME
                        // future, spending no new attempt.
                        if parts.reserve_op.is_some() {
                            let result = match parts.reserve_op.as_mut() {
                                Some(op) => op.await,
                                None => unreachable!("stored reserve operation checked"),
                            };
                            parts.reserve_op = None;
                            if result.is_ok() {
                                parts.reserved = true;
                                break;
                            }
                            parts.reserve_not_before = Some(
                                tokio::time::Instant::now() + reserve_pause(parts.reserve_attempts),
                            );
                            continue;
                        }
                        if parts.reserve_attempts >= RELAY_RESERVE_ATTEMPTS {
                            reserve_failed = true;
                            break;
                        }
                        if let Some(not_before) = parts.reserve_not_before {
                            if tokio::time::Instant::now() < not_before {
                                tokio::time::sleep_until(not_before).await;
                                continue;
                            }
                            parts.reserve_not_before = None;
                        }
                        // Start ONE stored operation; `relay_ops` is cloned to end the borrow.
                        let ops = parts
                            .relay_ops
                            .clone()
                            .expect("admitted server holds relay operations");
                        parts.reserve_attempts += 1;
                        parts.reserve_op = Some(Box::pin(async move {
                            ops.reserve(relay_addr).await.map(|_| ())
                        }));
                    }
                    if reserve_failed {
                        let mut parts = match std::mem::replace(&mut self.phase, ServerPhase::New) {
                            ServerPhase::Admitted(parts) => parts,
                            _ => unreachable!("re-seated admitted phase"),
                        };
                        parts.outcome = Some(StartupError::RelayReserve);
                        return self.begin_close(parts).await;
                    }
                    self.phase = match std::mem::replace(&mut self.phase, ServerPhase::New) {
                        ServerPhase::Admitted(parts) => ServerPhase::Live(parts),
                        _ => unreachable!("re-seated admitted phase"),
                    };
                    return Ok(());
                }
                // These arms are loop invariants; the predicate above
                // already answered Live/Closing/Done.
                ServerPhase::Live(_) | ServerPhase::Closing(_) | ServerPhase::Done(_) => {
                    unreachable!("terminal phases are answered before the phase take")
                }
            }
        }
    }

    /// Resumable accept loop over the native endpoint and, while the
    /// transferred payload pair is live, the Yggdrasil endpoint, with the
    /// pump drive and a bounded session set. Cancel-safe: YES — ownership
    /// is retained across cancellation (the phase keeps every owner), but
    /// the accept arms themselves are cancellation-unsafe per their SDK
    /// contracts: a losing select arm can abandon a consumed handshake,
    /// which is not replayed; the SDK returns the admission slot.
    pub async fn run(
        &mut self,
        shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
    ) -> Result<(), StartupError> {
        if !matches!(self.phase, ServerPhase::Live(_)) {
            // Terminal or not-yet-live phases are answered untouched.
            let phase = std::mem::replace(&mut self.phase, ServerPhase::Done(Ok(())));
            let error = match &phase {
                ServerPhase::Closing(_) => Some(StartupError::Close {
                    stage: "role-closing",
                }),
                ServerPhase::Done(result) => result.clone().err(),
                _ => Some(StartupError::Close {
                    stage: "role-not-started",
                }),
            };
            self.phase = phase;
            return match error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
        let ServerPhase::Live(parts) = &mut self.phase else {
            unreachable!("re-seated live phase")
        };
        if parts.stop.is_none() {
            parts.stop = Some(tokio::sync::watch::channel(false));
        }
        let outcome = drive_loop(parts, self.limits, &self.config, shutdown).await;
        let parts = match std::mem::replace(&mut self.phase, ServerPhase::Done(Ok(()))) {
            ServerPhase::Live(parts) => parts,
            _ => unreachable!("re-seated live phase"),
        };
        self.phase = ServerPhase::Live(parts);
        match outcome {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Resumable joined shutdown. The joined cleanup is stored as a boxed
    /// continuation, so cancelling this waiter keeps it resumable.
    /// Cancel-safe: YES.
    pub async fn shutdown(&mut self) -> Result<(), StartupError> {
        // Incomplete cleanup leaves the phase `Starting`, so command/join
        // routes stay owned for retry; the result is cached once.
        if let ServerPhase::Starting(start) = &mut self.phase {
            let result = super::shutdown_start(start).await;
            let cached = result.clone();
            self.phase = ServerPhase::Done(cached);
            return result;
        }
        loop {
            match std::mem::replace(&mut self.phase, ServerPhase::Done(Ok(()))) {
                ServerPhase::New => return Ok(()),
                // Handled above, before the phase take.
                ServerPhase::Starting(_) => unreachable!("Starting handled before the phase take"),
                ServerPhase::Done(result) => {
                    self.phase = ServerPhase::Done(result.clone());
                    return result;
                }
                ServerPhase::Admitted(parts) | ServerPhase::Live(parts) => {
                    self.phase = ServerPhase::Closing(Box::pin(server_close::close_parts(*parts)));
                }
                ServerPhase::Closing(continuation) => {
                    self.phase = ServerPhase::Closing(continuation);
                    let ServerPhase::Closing(continuation) = &mut self.phase else {
                        unreachable!("re-seated closing phase")
                    };
                    let result = continuation.as_mut().await;
                    self.phase = ServerPhase::Done(result.clone());
                    return result;
                }
            }
        }
    }

    /// Boxes the joined close continuation and awaits it; `parts.outcome` is seeded first.
    async fn begin_close(&mut self, parts: Box<ServerParts>) -> Result<(), StartupError> {
        self.phase = ServerPhase::Closing(Box::pin(server_close::close_parts(*parts)));
        self.shutdown().await
    }
}

/// Drives the accept loop until a terminal condition; cached outcome if any.
async fn drive_loop(
    parts: &mut ServerParts,
    limits: Limits,
    config: &ServerConfig,
    shutdown: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Option<StartupError> {
    if let Some(error) = parts.outcome.clone() {
        return Some(error);
    }
    #[cfg(test)]
    emit(parts.events.as_ref(), RoleEvent::Admitted);
    #[cfg(test)]
    emit_payload_acquired(parts.events.as_ref(), parts.payload.is_some());
    loop {
        // Reap finished sessions without blocking on the accept arms.
        while let Some(result) = parts.sessions.try_join_next() {
            match result {
                Ok(Ok(_)) | Ok(Err(ForwardError::PathUnavailable)) => {}
                Ok(Err(ForwardError::TaskFailure)) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "session-serve",
                    });
                }
                Ok(Err(error)) => eprintln!("shaar: session ended: {error}"),
                Err(_) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "session-serve",
                    });
                }
            }
        }
        if parts.outcome.is_some() {
            break;
        }
        // Split borrows: endpoint accepts by shared reference, pump mutably.
        let (mut ygg_endpoint, mut pump) = match parts.payload.as_mut() {
            Some(pair) => (Some(&mut pair.0), Some(&mut pair.1)),
            None => (None, None),
        };
        tokio::select! {
            biased;
            () = &mut *shutdown => break,
            // Bounded gate: sessions are reaped before admitting more.
            result = parts.sessions.join_next(), if parts.sessions.len() >= limits.sessions => {
                match result {
                    Some(Ok(Ok(_))) | Some(Ok(Err(ForwardError::PathUnavailable))) => {}
                    Some(Ok(Err(ForwardError::TaskFailure))) | Some(Err(_)) => {
                        parts.outcome = Some(StartupError::Close {
                            stage: "session-serve",
                        });
                        break;
                    }
                    Some(Ok(Err(error))) => eprintln!("shaar: session ended: {error}"),
                    None => {}
                }
            }
            accepted = parts
                .endpoint
                .as_mut()
                .expect("server holds the native endpoint while live")
                .accept() => match accepted {
                Ok(session) => {
                    #[cfg(test)]
                    if let Some(events) = &parts.events {
                        events.capture_native(&session);
                    }
                    #[cfg(test)]
                    emit(parts.events.as_ref(), RoleEvent::SessionAdmitted(PathKind::Native));
                    server_close::spawn_session(
                        &mut parts.sessions,
                        session,
                        config,
                        &parts.stop.as_ref().expect("server holds the stop watch").1,
                    );
                }
                // Endpoint closed: serving cannot continue truthfully.
                Err(NetworkError::Closed) => {
                    parts.outcome = Some(StartupError::Close {
                        stage: "native-accept",
                    });
                    break;
                }
                Err(NetworkError::AccessDenied) => {
                    #[cfg(test)]
                    emit(parts.events.as_ref(), RoleEvent::AdmissionDenied(PathKind::Native));
                    eprintln!("shaar: rejected/failed session");
                }
                Err(NetworkError::Capacity) => {
                    #[cfg(test)]
                    emit(
                        parts.events.as_ref(),
                        RoleEvent::AdmissionCapacity(PathKind::Native),
                    );
                    eprintln!("shaar: rejected/failed session");
                }
                // Single rejected/failed admission attempt; the loop serves on.
                Err(_) => eprintln!("shaar: rejected/failed session"),
            },
            accepted = async {
                ygg_endpoint
                    .as_mut()
                    .expect("ygg accept arm is guarded")
                    .accept()
                    .await
            }, if ygg_endpoint.is_some() && !parts.ygg_down => match accepted {
                Ok(session) => {
                    #[cfg(test)]
                    emit(parts.events.as_ref(), RoleEvent::SessionAdmitted(PathKind::Yggdrasil));
                    server_close::spawn_session(
                        &mut parts.sessions,
                        session,
                        config,
                        &parts.stop.as_ref().expect("server holds the stop watch").1,
                    );
                }
                Err(NetworkError::Closed) => parts.ygg_down = true,
                Err(NetworkError::Capacity) => {
                    #[cfg(test)]
                    emit(
                        parts.events.as_ref(),
                        RoleEvent::AdmissionCapacity(PathKind::Yggdrasil),
                    );
                    eprintln!("shaar: rejected/failed session");
                }
                Err(_) => eprintln!("shaar: rejected/failed session"),
            },
            driven = async {
                pump.as_mut()
                    .expect("pump arm is guarded")
                    .run()
                    .await
            }, if pump.is_some() && !parts.pump_finished => {
                parts.pump_finished = true;
                if driven.is_err() {
                    parts.ygg_down = true;
                }
            },
        }
    }
    parts.outcome.clone()
}
