//! Production [`Dialer`] implementations for the composed client role.
//!
//! Native priority is fixed: direct candidates first, key-directed relay
//! negotiation second, Yggdrasil only ever on the standby owner's fallback
//! side. All dials are bounded by the caller-supplied attempt deadline; a
//! link completed after the deadline is abandoned, never returned.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh_base::{EndpointId, PublicKey};
use shaar_p2p::{RelayAddr, RelayLease};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::native_discovery::runtime::owner::{ResolvedAddresses, RuntimeError};
use crate::network::signaling::RelayOperations;
use crate::network::{
    ForwardError, ForwardStats, NetworkError, Session, SignaledEndpoint, YggEndpoint,
};
use crate::path::{DialError, Dialer, PathKind, Route, StandbyError, StandbyOwner};
use crate::startup::resources::SharedResources;

/// Maximum direct addresses carried from one resolve (matches the
/// composition's snapshot bound).
const MAX_CANDIDATES: usize = crate::startup::resources::MAX_SNAPSHOT_ADDRESSES;

/// Hard ceiling for one Mainline resolve inside a dial attempt.
const RESOLVE_BUDGET: Duration = Duration::from_secs(5);

/// A denied or mismatched key is infrastructure-level rejection: retrying
/// the same key through another transport must not evade admission.
fn fatal_peer_error(error: &NetworkError) -> bool {
    matches!(
        error,
        NetworkError::AccessDenied | NetworkError::PeerMismatch
    )
}

/// Direct-then-relay native dialer over the transferred signaling endpoint.
/// The client role keeps the endpoint behind an [`Arc`] because dialing only
/// uses `&self` methods; the role never accepts native sessions, so no
/// exclusive access is required and no interior mutability is introduced.
pub(crate) struct NativeDialer {
    endpoint: Arc<SignaledEndpoint>,
    peer: PublicKey,
    resources: SharedResources,
    candidates: Vec<SocketAddr>,
    refresh_after_loss: bool,
    /// Retained relay-operations handle of the live-transferred endpoint; the
    /// reserved lease is owned here and released in [`Dialer::close`].
    ops: RelayOperations,
    /// Validated configured relay address, taken from the signaling settings
    /// at construction; the reserved lease carrying it is owned here and
    /// released in [`Dialer::close`]. (`RelayLease::relay` consumes the lease,
    /// so the address is carried separately.)
    relay_addr: RelayAddr,
    lease: Option<RelayLease>,
    #[cfg(test)]
    events: Option<super::RoleEventLog>,
}

impl NativeDialer {
    pub(crate) fn new(
        endpoint: Arc<SignaledEndpoint>,
        peer: PublicKey,
        resources: SharedResources,
        candidates: Vec<SocketAddr>,
        relay_addr: RelayAddr,
        ops: RelayOperations,
        #[cfg(test)] events: Option<super::RoleEventLog>,
    ) -> Self {
        Self {
            endpoint,
            peer,
            resources,
            candidates,
            refresh_after_loss: false,
            relay_addr,
            ops,
            lease: None,
            #[cfg(test)]
            events,
        }
    }

    /// Fills the candidate list from one bounded Mainline resolve when the
    /// configured explicit direct address hint is absent or already spent.
    async fn resolve_candidates(&mut self, deadline: Instant) -> Result<(), DialError> {
        if !self.candidates.is_empty() {
            return Ok(());
        }
        let key = EndpointId::from_bytes(self.peer.as_bytes()).map_err(|_| DialError)?;
        let budget = deadline.min(Instant::now() + RESOLVE_BUDGET);
        let resolved: ResolvedAddresses = match timeout_at(budget, async {
            if self.refresh_after_loss {
                self.resources.resolve_fresh(key).await
            } else {
                self.resources.resolve(key).await
            }
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(DialError),
        };
        let mut addresses: Vec<SocketAddr> = resolved
            .addresses()
            .iter()
            .take(MAX_CANDIDATES)
            .copied()
            .collect();
        std::mem::swap(&mut self.candidates, &mut addresses);
        self.refresh_after_loss = false;
        Ok(())
    }

    /// Reserves the configured relay exactly once per dialer lifetime over
    /// the retained relay-operations handle; the lease is owned here and
    /// released in [`Dialer::close`]. The address itself comes from the
    /// validated signaling settings at construction, never from the lease
    /// (`RelayLease::relay` consumes the lease).
    async fn ensure_relay(&mut self) -> Result<(), DialError> {
        if self.lease.is_some() {
            return Ok(());
        }
        self.lease = Some(
            self.ops
                .reserve(self.relay_addr)
                .await
                .map_err(|_| DialError)?,
        );
        Ok(())
    }
}

impl Dialer for NativeDialer {
    type Link = Session;

    /// One attempt: direct candidates first, relay negotiation only when all
    /// direct candidates failed and time remains. A failed cold Mainline
    /// lookup does NOT end the attempt: the pinned relay is addressed by key
    /// alone, so the dial still reaches relay negotiation. Native priority is
    /// unchanged (direct candidates first, relay negotiation second).
    /// `AccessDenied`/`PeerMismatch` end the attempt immediately — a denied
    /// key is not retried through other infrastructure.
    /// cancel-safe: NO — handshakes may complete after cancellation; the
    /// abandoned link closes on drop and the candidate list stays consistent.
    async fn dial(&mut self, deadline: Instant) -> Result<Self::Link, DialError> {
        if Instant::now() >= deadline {
            return Err(DialError);
        }
        // A failed cold lookup only means "no direct candidates": fall through
        // to key-directed relay negotiation instead of aborting the attempt.
        if self.resolve_candidates(deadline).await.is_err() {
            self.candidates.clear();
        }
        while let Some(address) = self.candidates.first().copied() {
            if Instant::now() >= deadline {
                return Err(DialError);
            }
            match timeout_at(deadline, self.endpoint.connect(self.peer, address)).await {
                Ok(Ok(session)) => {
                    #[cfg(test)]
                    if let Some(events) = &self.events {
                        events.capture_native(&session);
                    }
                    self.candidates.clear();
                    return Ok(session);
                }
                // Upstream text is redacted: `DialError` carries no payload.
                Ok(Err(error)) => {
                    if fatal_peer_error(&error) {
                        return Err(DialError);
                    }
                    self.candidates.remove(0);
                }
                Err(_) => return Err(DialError),
            }
        }
        self.candidates.clear();
        self.ensure_relay().await?;
        let relay = self.relay_addr;
        match timeout_at(deadline, self.endpoint.connect_via(self.peer, relay)).await {
            Ok(Ok(session)) => {
                #[cfg(test)]
                if let Some(events) = &self.events {
                    events.capture_native(&session);
                }
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
        if self.lease.take().is_some() {
            let _ = self.ops.release(self.relay_addr).await;
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
}

impl YggDialer {
    pub(crate) fn new(endpoint: Arc<YggEndpoint>, peer: PublicKey) -> Self {
        Self { endpoint, peer }
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
        match timeout_at(deadline, self.endpoint.connect(self.peer)).await {
            Ok(Ok(session)) => Ok(session),
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
    fn follow(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PathKind, StandbyError>> + '_>>;
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
    fn follow(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<PathKind, StandbyError>> + '_>>
    {
        Box::pin(StandbyOwner::follow(self))
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
