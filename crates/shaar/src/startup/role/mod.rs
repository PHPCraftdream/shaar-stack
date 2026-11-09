//! The shared production role startup consumed by both binaries and
//! exercised by the 5c controlled fixtures. The roles are retained and
//! cancellation-safe: the `start`/`run`/`shutdown` waiters are cancel-safe
//! and `shutdown` stores its joined close as a boxed continuation on the
//! role. Both roles run the accepted composed startup (5b resources) and
//! drive real path policy; no legacy server address is required, no
//! fallback is rejected as unimplemented, and no silent direct-only
//! fallback exists.

mod client;
mod dialers;
mod server;
mod server_close;

#[cfg(test)]
use crate::path::PathKind;
use crate::path::{ConfigError, Dialer, PolicyConfig, StandbyOwner};
use crate::startup::error::StartupError;
use dialers::ErasedClientOwner;
use dialers::RouteLink;

/// Tuning for the client path policy. Production binaries use
/// [`RoleOptions::default`]; controlled fixtures tighten the same validated
/// struct, never bypass it.
#[derive(Clone, Debug)]
pub struct RoleOptions {
    pub policy: PolicyConfig,
}

impl Default for RoleOptions {
    fn default() -> Self {
        Self {
            policy: PolicyConfig::default(),
        }
    }
}

impl RoleOptions {
    /// Validates the embedded policy so both roles reject degenerate tuning
    /// before any network I/O.
    pub(crate) fn validate(&self) -> Result<(), StartupError> {
        self.policy.validate().map_err(Self::redact)?;
        Ok(())
    }

    /// Redacted: names no parameter values, only that validation rejected
    /// the policy.
    fn redact(_: ConfigError) -> StartupError {
        StartupError::InvalidPolicy
    }
}

/// Waits for terminal composition cleanup; incomplete attempts retain the owner.
/// cancel-safe: YES — only the waiter borrows the retained startup handle.
async fn shutdown_start(
    start: &mut crate::startup::resources::SharedResourcesStart,
) -> Result<(), StartupError> {
    loop {
        let result = start.shutdown().await;
        if !start.shutdown_pending() {
            return result;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Internal event seam, observed only by in-crate tests. Production callers
/// pass no observer; the run functions emit into `None` and behave identically.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoleEvent {
    Admitted,
    ListenerReady(std::net::SocketAddr),
    RouteActive(PathKind),
    SessionAdmitted(PathKind),
    /// Test-only observation of a REAL typed admission denial
    /// (`NetworkError::AccessDenied`) at the server accept seam.
    AdmissionDenied(PathKind),
    /// Test-only observation of a REAL admission-capacity refusal at the
    /// accept seam (one shared bounded pool across paths).
    AdmissionCapacity(PathKind),
    /// Test-only observation of a real pending composition close and the
    /// first retained close error stage in the server continuation.
    ClosePending {
        stage: &'static str,
    },
    /// Test-only observation of the REAL Yggdrasil payload-pair
    /// acquisition result (true = the pair was transferred live).
    YggPayloadAcquired(bool),
}

/// Hard bound on recorded role events. Route switches can repeat without
/// limit, so an unbounded log is not acceptable: once the log holds
/// `MAX_ROLE_EVENTS` events it is sealed — further events are dropped while
/// the retained prefix keeps replaying truthfully. A wait for an event that
/// would only be recorded after the seal times out; bounded fixtures consume
/// events promptly, and the seal is observable behavior, not a silent lie.
#[cfg(test)]
pub(crate) const MAX_ROLE_EVENTS: usize = 4096;

/// Bounded role-event log for the cfg(test) fixtures: the first
/// `MAX_ROLE_EVENTS` events are retained in insertion order and replay
/// truthfully (`find`/`snapshot`/`wait` keep their semantics over the
/// retained prefix); later events are dropped once sealed. `version` wakes
/// waiters. Waiters rescan under the mutex, so no retained event can be
/// missed regardless of scheduling.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct RoleEventLog {
    events: std::sync::Arc<std::sync::Mutex<Vec<RoleEvent>>>,
    version: std::sync::Arc<tokio::sync::watch::Sender<usize>>,
    native_frames: Option<std::sync::Arc<crate::network::RoleFrames>>,
}

#[cfg(test)]
impl RoleEventLog {
    pub(crate) fn new() -> Self {
        let (version, _) = tokio::sync::watch::channel(0usize);
        Self {
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            version: std::sync::Arc::new(version),
            native_frames: None,
        }
    }

    pub(crate) fn observe_native_frames(&mut self) -> std::sync::Arc<crate::network::RoleFrames> {
        assert!(
            self.native_frames.is_none(),
            "native observer already attached"
        );
        let capture = crate::network::RoleFrames::new();
        self.native_frames = Some(std::sync::Arc::clone(&capture));
        capture
    }

    pub(super) fn capture_native(&self, session: &crate::network::Session) {
        if let Some(capture) = &self.native_frames {
            capture.capture(session);
        }
    }

    /// Appends one event and wakes every waiter. Synchronous (mutex only).
    pub(crate) fn record(&self, event: RoleEvent) {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if events.len() >= MAX_ROLE_EVENTS {
            // Sealed: drop the event, no version bump, no wake.
            return;
        }
        events.push(event);
        drop(events);
        // Always notifies: bounded tests consume events promptly.
        self.version.send_modify(|version| *version += 1);
    }

    /// First recorded event matching `pred`, in insertion order.
    pub(crate) fn find(&self, pred: &dyn Fn(&RoleEvent) -> bool) -> Option<RoleEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .copied()
            .find(|event| pred(event))
    }

    /// Ordered snapshot of every recorded event.
    pub(crate) fn snapshot(&self) -> Vec<RoleEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Bounded-wakeup wait: the version mark is borrowed BEFORE the scan, so
    /// an event recorded between scan and wait still wakes this waiter.
    /// cancel-safe: YES — cancellation only abandons the waiter.
    pub(crate) async fn wait(&self, pred: impl Fn(&RoleEvent) -> bool) -> RoleEvent {
        let mut version = self.version.subscribe();
        loop {
            let _ = version.borrow_and_update();
            if let Some(event) = self.find(&pred) {
                return event;
            }
            let _ = version.changed().await;
        }
    }
}

/// Forwards one event into the log when an observer is attached; a no-op
/// otherwise.
#[cfg(test)]
fn emit(events: Option<&RoleEventLog>, event: RoleEvent) {
    if let Some(events) = events {
        events.record(event);
    }
}

/// Test-only observation of the REAL Yggdrasil payload-pair acquisition
/// result; keeps role-side call sites short enough for one-line formatting.
#[cfg(test)]
fn emit_payload_acquired(events: Option<&RoleEventLog>, acquired: bool) {
    emit(events, RoleEvent::YggPayloadAcquired(acquired));
}

/// The boxed joined-close continuation of the retained client role.
pub(super) type ClientCloseContinuation =
    dyn std::future::Future<Output = Result<(), StartupError>>;

/// Boxes a standby owner into the object-safe seam; the futures are NOT
/// `Send` and are polled inline, never spawned.
pub(super) fn boxed_owner<D, F>(owner: StandbyOwner<D, F>) -> Box<dyn ErasedClientOwner>
where
    D: Dialer + 'static,
    D::Link: RouteLink,
    F: Dialer + 'static,
    F::Link: RouteLink,
{
    Box::new(owner)
}

#[cfg(test)]
pub(crate) async fn serve_server_with_events(
    config: &crate::config::ServerConfig,
    identity: &crate::identity::Identity,
    allowlist: crate::network::Allowlist,
    limits: crate::network::Limits,
    options: RoleOptions,
    shutdown: impl std::future::Future<Output = ()>,
    events: RoleEventLog,
) -> Result<(), StartupError> {
    let mut role = server::ServerRole::with_events(
        config.clone(),
        identity,
        allowlist,
        limits,
        options,
        events,
    )?;
    let mut shutdown = std::pin::pin!(shutdown);
    let outcome = match role.start().await {
        Ok(()) => role.run(&mut shutdown).await,
        Err(error) => Err(error),
    };
    let close_result = role.shutdown().await;
    outcome.and(close_result)
}

#[cfg(test)]
pub(crate) async fn serve_client_with_events(
    config: &crate::config::ClientConfig,
    identity: &crate::identity::Identity,
    limits: crate::network::Limits,
    options: RoleOptions,
    shutdown: impl std::future::Future<Output = ()>,
    events: RoleEventLog,
) -> Result<(), StartupError> {
    let mut role =
        client::ClientRole::with_events(config.clone(), identity, limits, options, events)?;
    let mut shutdown = std::pin::pin!(shutdown);
    let outcome = match role.start().await {
        Ok(()) => role.run(&mut shutdown).await,
        Err(error) => Err(error),
    };
    let close_result = role.shutdown().await;
    outcome.and(close_result)
}

pub use client::ClientRole;
pub use server::ServerRole;
