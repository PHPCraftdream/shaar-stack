//! Production [`Dialer`] implementations for the composed client role.
//!
//! Native priority is fixed: direct candidates first — public/reflexive-scope
//! candidates ahead of private/local-scope ones, every private/local connect
//! bounded by a fixed slice (R1) — then punch coordination (leaf L4, only
//! when the relay-less composition carries a punch channel), then
//! key-directed relay negotiation, which
//! exists only when the signaling settings pin a relay (L0), and
//! Yggdrasil only ever on the standby owner's fallback side. All dials are
//! bounded by the caller-supplied attempt deadline; a link completed after
//! the deadline is abandoned, never returned.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use iroh_base::{EndpointId, PublicKey};
use shaar_p2p::{RelayAddr, RelayLease};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

use crate::native_discovery::runtime::owner::{ResolvedAddresses, RuntimeError};
use crate::network::observe::{ResolveObservation, RoutePath, client_route, elapsed_ms, emit};
use crate::network::signaling::{RelayOperations, punch};
use crate::network::{
    ForwardError, ForwardStats, NetworkError, Session, SignaledEndpoint, YggEndpoint,
};
use crate::path::{DialError, Dialer, PathKind, Route, StandbyError, StandbyOwner};
use crate::startup::resources::SharedResources;

#[cfg(test)]
#[path = "../tests/dial_order_tests.rs"]
mod dial_order_tests;

#[cfg(test)]
#[path = "../tests/lease_tests.rs"]
mod lease_tests;

/// Maximum direct addresses carried from one resolve (matches the
/// composition's snapshot bound).
const MAX_CANDIDATES: usize = crate::startup::resources::MAX_SNAPSHOT_ADDRESSES;

/// Hard ceiling for one Mainline resolve inside a dial attempt.
const RESOLVE_BUDGET: Duration = Duration::from_secs(5);

/// Longest an attempt waits for the record lookup while a punch channel exists. A live
/// lookup takes 6 to 10 s against a 3 s attempt, so waiting out the attempt for it only
/// ended every attempt before its punch phase began (live smoke 43784413811: nine
/// attempts, `reason=deadline` after 0 ms, two thirds of them with a candidate).
const RESOLVE_BUDGET_WITH_PUNCH: Duration = Duration::from_secs(1);

/// One lookup at a time on a task of its own. An attempt that gives up waiting leaves the
/// task running and the next attempt collects it: a live lookup outlasts a 3 s attempt and
/// only a lookup that finishes can answer, so cancelling it every attempt answered nothing
/// and made the owner repeat the whole query (live smoke 43788557511: `CandidateLimit`,
/// three times the DHT bytes). `None` is an unfinished or failed lookup.
async fn await_held<T, F>(slot: &mut Option<JoinHandle<T>>, until: Instant, start: F) -> Option<T>
where
    F: FnOnce() -> JoinHandle<T>,
{
    let mut task = slot.take().unwrap_or_else(start);
    match timeout_at(until, &mut task).await {
        Ok(joined) => joined.ok(),
        Err(_) => {
            *slot = Some(task);
            None
        }
    }
}

/// The instant by which the record lookup of this attempt must have answered.
fn resolve_budget(now: Instant, deadline: Instant, punch_present: bool) -> Instant {
    let ceiling = if punch_present {
        RESOLVE_BUDGET_WITH_PUNCH
    } else {
        RESOLVE_BUDGET
    };
    deadline.min(now + ceiling)
}

/// Fixed connect slice for one private/local-scope candidate (R1): a silent
/// candidate must not consume the whole attempt deadline. Public-scope
/// candidates keep the full remaining deadline.
const LOCAL_CANDIDATE_SLICE: Duration = Duration::from_secs(1);

/// A denied or mismatched key is infrastructure-level rejection: retrying
/// the same key through another transport must not evade admission.
fn fatal_peer_error(error: &NetworkError) -> bool {
    matches!(
        error,
        NetworkError::AccessDenied | NetworkError::PeerMismatch
    )
}

/// Direct-then-relay native dialer over the transferred signaling endpoint.
/// The relay phase exists only when a relay is configured (L0).
/// The client role keeps the endpoint behind an [`Arc`] because dialing only
/// uses `&self` methods; the role never accepts native sessions, so no
/// exclusive access is required and no interior mutability is introduced.
/// The punch phase exists only when the channel is present, which the role
/// creates only for the relay-less composition.
pub(crate) struct NativeDialer {
    endpoint: Arc<SignaledEndpoint>,
    peer: PublicKey,
    resources: SharedResources,
    candidates: Vec<SocketAddr>,
    refresh_after_loss: bool,
    /// The record lookup an attempt stopped waiting for; the next attempt collects it.
    pending_resolve: Option<JoinHandle<Result<ResolvedAddresses, RuntimeError>>>,
    /// Configured relay pair (pinned address, retained ops handle); present
    /// only when the signaling settings carry `relay`/`relay_address` (L0).
    /// The reserved lease is owned here and released in [`Dialer::close`].
    relay: Option<(RelayAddr, RelayOperations)>,
    /// NAT hole-punch channel (leaf L4); present only for the relay-less
    /// composition over a retained Yggdrasil bridge.
    punch: Option<punch::PunchChannel>,
    /// Wrapping epoch distinguishing successive punch attempts.
    punch_epoch: u32,
    lease: Option<RelayLease>,
    /// Shared OBS-1 resolve observation written after every route decision.
    note: tokio::sync::watch::Sender<Option<ResolveObservation>>,
    /// Configured hint candidate count; splits the cached observation by source.
    hint_count: usize,
    #[cfg(test)]
    events: Option<super::RoleEventLog>,
}

impl NativeDialer {
    // The test build adds the event log; the production signature stays at seven.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        endpoint: Arc<SignaledEndpoint>,
        peer: PublicKey,
        resources: SharedResources,
        candidates: Vec<SocketAddr>,
        relay: Option<(RelayAddr, RelayOperations)>,
        note: tokio::sync::watch::Sender<Option<ResolveObservation>>,
        punch: Option<punch::PunchChannel>,
        #[cfg(test)] events: Option<super::RoleEventLog>,
    ) -> Self {
        let hint_count = candidates.len();
        Self {
            endpoint,
            peer,
            resources,
            candidates,
            refresh_after_loss: false,
            pending_resolve: None,
            relay,
            punch,
            punch_epoch: 0,
            lease: None,
            note,
            hint_count,
            #[cfg(test)]
            events,
        }
    }

    /// One Mainline resolve (or none) for the route decision. Classifies the
    /// EXISTING resolver result into the stable route-line observation (no new
    /// network call) and fills the candidate list.
    async fn resolve_candidates(
        &mut self,
        deadline: Instant,
    ) -> Result<ResolveObservation, DialError> {
        let listed = self.candidates.len();
        let observation = if listed > 0 {
            // Candidates already carried: the configured hint, or the retained
            // list of an earlier resolve. No lookup happens this dial.
            let (record, hint) = if self.hint_count > 0 {
                (0, listed)
            } else {
                (listed, 0)
            };
            ResolveObservation::cached(record, hint)
        } else {
            let key = EndpointId::from_bytes(self.peer.as_bytes()).map_err(|_| DialError)?;
            let budget = resolve_budget(Instant::now(), deadline, self.punch.is_some());
            let answer = await_held(&mut self.pending_resolve, budget, || {
                let resources = self.resources.clone();
                let fresh = self.refresh_after_loss;
                tokio::spawn(async move {
                    if fresh {
                        resources.resolve_fresh(key).await
                    } else {
                        resources.resolve(key).await
                    }
                })
            })
            .await;
            match answer {
                Some(Ok(resolved)) => {
                    let mut addresses: Vec<SocketAddr> = resolved
                        .addresses()
                        .iter()
                        .take(MAX_CANDIDATES)
                        .copied()
                        .collect();
                    std::mem::swap(&mut self.candidates, &mut addresses);
                    self.refresh_after_loss = false;
                    ResolveObservation::from_answer(Some(self.candidates.len()))
                }
                // A failed or unfinished lookup answers nothing (stable value: timeout).
                Some(Err(_)) | None => ResolveObservation::from_answer(None),
            }
        };
        let _ = self.note.send(Some(observation));
        Ok(observation)
    }

    /// Resolves the negotiation target and reserves the configured relay
    /// exactly once per dialer lifetime over the retained ops handle. With
    /// no configured relay there is no negotiation target (L0). The lease is
    /// owned here and released in [`Dialer::close`]; the address itself comes
    /// from the validated signaling settings, never from the lease
    /// (`RelayLease::relay` consumes the lease).
    async fn ensure_relay(&mut self, relay_addr: RelayAddr) -> Result<(), DialError> {
        if self.lease.is_some() {
            return Ok(());
        }
        let Some((_, ops)) = self.relay.as_ref() else {
            return Err(DialError);
        };
        let ops = ops.clone();
        let lease = ops.reserve(relay_addr).await.map_err(|_| DialError)?;
        self.lease = Some(lease);
        Ok(())
    }
}

/// Dialer-side scope heuristic (R1; documented here because the signed record
/// carries bare socket addresses with no scope information). Private/local
/// scope covers RFC 1918, CGNAT 100.64/10, IPv4 loopback and link-local, and
/// IPv6 loopback and link-local (IPv4-mapped forms count as their embedded
/// IPv4 range). Custom/fabric addresses never arrive as candidates: the
/// record publisher admits bare `TransportAddr::Ip` entries only. Everything
/// else is treated as public/reflexive scope and keeps the full deadline.
fn candidate_is_local(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ipv4_is_local(ip),
        IpAddr::V6(ip) => ipv6_is_local(ip),
    }
}

/// IPv4 ranges of the documented private/local heuristic.
fn ipv4_is_local(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();
    first == 10
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 100 && (64..=127).contains(&second))
        || first == 127
        || (first == 169 && second == 254)
}

/// IPv6 ranges: loopback and link-local, with IPv4-mapped addresses
/// classified as their embedded IPv4 range.
fn ipv6_is_local(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return ipv4_is_local(mapped);
    }
    ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Stable public-first reordering (R1): public/reflexive-scope candidates
/// keep their record order ahead of private/local-scope candidates, which
/// keep theirs.
fn public_first_order(candidates: &mut [SocketAddr]) {
    // `sort_by_key` is stable and `false` (public) sorts before `true` (local); the
    // list is bounded by MAX_CANDIDATES, so this is a handful of comparisons.
    candidates.sort_by_key(|candidate| candidate_is_local(*candidate));
}

/// L0 seam: the relay negotiation target of one attempt. `None` — no relay
/// is configured, so the negotiation phase does not exist for this dialer
/// and the attempt ends typed instead of dialing unconfigured
/// infrastructure or hanging.
fn negotiation_target(relay: &Option<(RelayAddr, RelayOperations)>) -> Option<RelayAddr> {
    relay.as_ref().map(|(relay_addr, _)| *relay_addr)
}

/// The direct-candidate phase of one attempt (R1). Candidates are ordered
/// public-first; each private/local-scope connect is bounded by
/// [`LOCAL_CANDIDATE_SLICE`] capped at the remaining deadline, and a
/// timed-out candidate is removed from the list so one dial never retries it.
/// Returns the completed session, or `None` when the list is exhausted and
/// the caller reaches relay negotiation. `Err` still ends the attempt when
/// the deadline is spent or the peer was denied (`fatal_peer_error`), so the
/// total attempt budget, the retry schedule and the typed `Exhausted` exit
/// are unchanged.
async fn dial_candidate_list<C, Fut>(
    candidates: &mut Vec<SocketAddr>,
    deadline: Instant,
    mut connect: C,
) -> Result<Option<Session>, DialError>
where
    C: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Result<Session, NetworkError>> + 'static,
{
    public_first_order(candidates);
    while let Some(address) = candidates.first().copied() {
        if Instant::now() >= deadline {
            return Err(DialError);
        }
        let connect_deadline = if candidate_is_local(address) {
            deadline.min(Instant::now() + LOCAL_CANDIDATE_SLICE)
        } else {
            deadline
        };
        match timeout_at(connect_deadline, connect(address)).await {
            Ok(Ok(session)) => {
                candidates.clear();
                return Ok(Some(session));
            }
            // Upstream text is redacted: `DialError` carries no payload.
            Ok(Err(error)) => {
                if fatal_peer_error(&error) {
                    return Err(DialError);
                }
                candidates.remove(0);
            }
            // R1: a timed-out candidate is dropped from the list instead of
            // ending the attempt; the next candidate gets the remaining time.
            Err(_) => {
                candidates.remove(0);
            }
        }
    }
    candidates.clear();
    Ok(None)
}

impl Dialer for NativeDialer {
    type Link = Session;

    /// One attempt: direct candidates first — public/reflexive-scope
    /// candidates ahead of private/local-scope ones, every private/local
    /// connect bounded by a fixed slice and a timed-out candidate dropped
    /// from the list (R1) — then relay negotiation only when a relay is
    /// configured, all direct candidates failed and time remains. When the
    /// relay-less composition carries a punch channel, punch coordination runs
    /// between the candidate phase and relay negotiation, bounded by the
    /// remaining attempt deadline. A failed cold Mainline lookup does
    /// NOT end the attempt: the pinned relay is addressed by key alone, so
    /// the dial still reaches relay negotiation. Native priority is
    /// unchanged (direct candidates first, relay negotiation second).
    /// `AccessDenied`/`PeerMismatch` end the attempt immediately — a denied
    /// key is not retried through other infrastructure. The total attempt
    /// budget, the retry schedule and the typed `Exhausted` exit are
    /// unchanged by the slice and drop rules.
    /// cancel-safe: NO — handshakes may complete after cancellation; the
    /// abandoned link closes on drop and the candidate list stays consistent.
    async fn dial(&mut self, deadline: Instant) -> Result<Self::Link, DialError> {
        if Instant::now() >= deadline {
            return Err(DialError);
        }
        let started = std::time::Instant::now();
        // A failed cold lookup only means "no direct candidates": fall through
        // to key-directed relay negotiation instead of aborting the attempt.
        let observation = match self.resolve_candidates(deadline).await {
            Ok(observation) => observation,
            Err(_) => {
                self.candidates.clear();
                ResolveObservation::from_answer(None)
            }
        };
        // One Arc clone per candidate attempt (bounded by MAX_CANDIDATES) so
        // the connect future is owned and the seam stays injectable in tests.
        let endpoint = Arc::clone(&self.endpoint);
        let peer = self.peer;
        let connected = dial_candidate_list(&mut self.candidates, deadline, move |address| {
            let endpoint = Arc::clone(&endpoint);
            async move { endpoint.connect(peer, address).await }
        })
        .await?;
        if let Some(session) = connected {
            #[cfg(test)]
            if let Some(events) = &self.events {
                events.capture_native(&session);
            }
            emit(client_route(
                RoutePath::Native,
                observation,
                elapsed_ms(started),
            ));
            return Ok(session);
        }
        // Punch coordination (leaf L4, design R5): only the relay-less
        // composition carries a punch channel. The phase is bounded by the
        // remaining attempt deadline; every failure falls through to the
        // unchanged typed end of the attempt, so the fallback budget is intact.
        if let Some(channel) = self.punch.as_mut() {
            self.punch_epoch = self.punch_epoch.wrapping_add(1);
            let reflexive = self.resources.public_address();
            let candidates = punch::local_candidates(self.endpoint.local_addr(), reflexive);
            let endpoint = Arc::clone(&self.endpoint);
            if let Some(session) = punch::client_attempt(
                channel,
                move |address| {
                    let endpoint = Arc::clone(&endpoint);
                    async move { endpoint.connect(peer, address).await }
                },
                candidates,
                self.punch_epoch,
                deadline,
                "client",
            )
            .await
            {
                #[cfg(test)]
                if let Some(events) = &self.events {
                    events.capture_native(&session);
                }
                // A punched session is a Native route like any direct one.
                emit(client_route(
                    RoutePath::Native,
                    observation,
                    elapsed_ms(started),
                ));
                return Ok(session);
            }
        }
        // Relay negotiation only when a relay is configured and time remains:
        // exhausting the list exactly at the deadline still ends the attempt
        // inside the unchanged budget. With no configured relay the phase
        // does not exist (L0): the attempt ends typed here — no relay dial
        // is attempted and nothing hangs.
        if Instant::now() >= deadline {
            return Err(DialError);
        }
        let Some(relay) = negotiation_target(&self.relay) else {
            return Err(DialError);
        };
        self.ensure_relay(relay).await?;
        match timeout_at(deadline, self.endpoint.connect_via(self.peer, relay)).await {
            Ok(Ok(session)) => {
                // A Custom negotiation connection is not yet a Native payload route.
                match timeout_at(deadline, session.native_ready()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => return Err(DialError),
                }

                #[cfg(test)]
                if let Some(events) = &self.events {
                    events.capture_native(&session);
                }
                emit(client_route(
                    RoutePath::Native,
                    observation,
                    elapsed_ms(started),
                ));
                Ok(session)
            }
            Ok(Err(_)) => Err(DialError),
            Err(_) => Err(DialError),
        }
    }

    /// Observes payload-path loss even while signaling keeps the connection alive.
    /// cancel-safe: yes — each subscription replays the current path snapshot.
    async fn lost(&mut self, link: &Self::Link) {
        link.native_lost().await;
        // A still-valid record can name the socket of the lost process.
        self.candidates.clear();
        self.refresh_after_loss = true;
    }

    /// Releases the owned relay lease over the retained ops handle. Tolerates
    /// repeated calls. Release failure is swallowed honestly: the endpoint
    /// close performed by the role reconciles carrier-side lease state, so no
    /// error is invented here.
    /// cancel-safe: yes — an interrupted close is resumable by another call.
    async fn close(&mut self) -> Result<(), DialError> {
        // Aborting drops the waiter, which makes the owner cancel the lookup cleanly.
        if let Some(lookup) = self.pending_resolve.take() {
            lookup.abort();
        }
        if self.lease.take().is_some()
            && let Some((relay_addr, ops)) = self.relay.as_ref()
        {
            let _ = ops.release(*relay_addr).await;
        }
        Ok(())
    }
}

/// Yggdrasil fallback dialer over the transferred payload endpoint. As with
/// the native side, dialing only uses `&self`; the role unwraps the [`Arc`]
/// after the standby owner has been joined to close the endpoint exclusively.
pub(crate) struct YggDialer {
    endpoint: Arc<YggEndpoint>,
    peer: PublicKey,
    /// Receives the native dialer's last resolve observation for the route line.
    note: tokio::sync::watch::Receiver<Option<ResolveObservation>>,
}

impl YggDialer {
    pub(crate) fn new(
        endpoint: Arc<YggEndpoint>,
        peer: PublicKey,
        note: tokio::sync::watch::Receiver<Option<ResolveObservation>>,
    ) -> Self {
        Self {
            endpoint,
            peer,
            note,
        }
    }
}

impl Dialer for YggDialer {
    type Link = Session;

    /// One bounded dial of the pinned service key through the Yggdrasil
    /// custom transport. cancel-safe: NO — the handshake may complete after
    /// cancellation; the abandoned session closes on drop.
    async fn dial(&mut self, deadline: Instant) -> Result<Self::Link, DialError> {
        if Instant::now() >= deadline {
            return Err(DialError);
        }
        let started = std::time::Instant::now();
        match timeout_at(deadline, self.endpoint.connect(self.peer)).await {
            Ok(Ok(session)) => {
                // The standby fallback never consults the record itself: its
                // line reports the last native resolve observation, or none.
                let observation =
                    (*self.note.borrow()).unwrap_or_else(|| ResolveObservation::cached(0, 0));
                emit(client_route(
                    RoutePath::YggStandby,
                    observation,
                    elapsed_ms(started),
                ));
                Ok(session)
            }
            Ok(Err(_)) => Err(DialError),
            Err(_) => Err(DialError),
        }
    }

    /// cancel-safe: yes — level-triggered loss observation.
    async fn lost(&mut self, link: &Self::Link) {
        let _ = link.closed().await;
    }

    /// The endpoint is closed by the role; nothing is owned here.
    async fn close(&mut self) -> Result<(), DialError> {
        Ok(())
    }
}

/// Placeholder fallback for `Mode::Signal`.
///
/// Unreachable by construction: the standby owner never dials the fallback
/// in `Mode::Signal` (path/standby/follow.rs standby gate). Its link type is
/// the unit type, so no session could even be routed if the gate were bypassed.
pub(crate) struct MissingYggDialer;

impl Dialer for MissingYggDialer {
    type Link = ();

    async fn dial(&mut self, _deadline: Instant) -> Result<Self::Link, DialError> {
        Err(DialError)
    }

    async fn lost(&mut self, _link: &Self::Link) {}

    async fn close(&mut self) -> Result<(), DialError> {
        Ok(())
    }
}

/// `RuntimeError` redaction: any failure maps to the bare dial failure; no
/// upstream text is carried.
impl From<RuntimeError> for DialError {
    fn from(_: RuntimeError) -> Self {
        DialError
    }
}

/// Type-erased forwarding handle for the active route lease. Both link types
/// are shared as `Arc`, so forward workers keep running across route
/// switches: a new route never aborts in-flight streams — the "no stale
/// snapshot replaces ongoing policy work" property. `Send + Sync` bounds are
/// required because forward workers are spawned into a capped `JoinSet`.
pub(crate) trait RouteLink: Send + Sync + 'static {
    fn forward(
        &self,
        stream: TcpStream,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ForwardStats, ForwardError>> + Send + '_>,
    >;
}

impl RouteLink for Session {
    fn forward(
        &self,
        stream: TcpStream,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ForwardStats, ForwardError>> + Send + '_>,
    > {
        Box::pin(self.forward(stream))
    }
}

/// The `Mode::Signal` placeholder link is never routed (standby gate), so
/// this arm is unreachable in practice; it exists only to satisfy the trait.
impl RouteLink for () {
    fn forward(
        &self,
        _stream: TcpStream,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ForwardStats, ForwardError>> + Send + '_>,
    > {
        Box::pin(std::future::ready(Err(ForwardError::PathUnavailable)))
    }
}

/// Erases the fallback link type of one active route into a shared handle.
fn shared_lease<N, F>(route: Route<N, F>) -> std::sync::Arc<dyn RouteLink>
where
    N: RouteLink,
    F: RouteLink,
{
    match route {
        Route::Native(link) => link as std::sync::Arc<dyn RouteLink>,
        Route::Yggdrasil(link) => link as std::sync::Arc<dyn RouteLink>,
    }
}

/// Object-safe seam over [`StandbyOwner`] so the retained client role needs no
/// generic parameter. The owner's boxed futures are NOT `Send`: the owner is
/// polled inline by the role waiter, never spawned, so this trait carries no
/// `Send` bound and its implementors are intentionally non-`Send`.
pub(crate) trait ErasedClientOwner {
    /// One policy advance; all state lives in the owner, so this is
    /// cancel-safe.
    fn follow<'a>(
        &'a mut self,
        lease: &'a mut Option<(PathKind, Arc<dyn RouteLink>)>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PathKind, StandbyError>> + 'a>>;
    /// A lease on the active route, erased into a shared handle.
    fn route(&self) -> Option<std::sync::Arc<dyn RouteLink>>;
    /// Joined close of both dial sides; the native dialer releases its owned
    /// relay lease here. cancel-safe: YES — resumable by another call.
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DialError>> + '_>>;
}

impl<D, F> ErasedClientOwner for StandbyOwner<D, F>
where
    D: Dialer + 'static,
    D::Link: RouteLink,
    F: Dialer + 'static,
    F::Link: RouteLink,
{
    fn follow<'a>(
        &'a mut self,
        lease: &'a mut Option<(PathKind, Arc<dyn RouteLink>)>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PathKind, StandbyError>> + 'a>>
    {
        // Keep the full waiter alive: its owned timers must survive Pending polls.
        Box::pin(self.follow_observing_route(move |present| {
            if !present {
                *lease = None;
            }
        }))
    }

    fn route(&self) -> Option<std::sync::Arc<dyn RouteLink>> {
        StandbyOwner::route(self).map(shared_lease)
    }

    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DialError>> + '_>> {
        Box::pin(StandbyOwner::close(self))
    }
}
