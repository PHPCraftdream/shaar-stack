//! The type-erased route handle and standby owner seam of the retained client role
//! (moved out of `dialers.rs`, which holds the dial sequences).

use std::sync::Arc;

use tokio::net::TcpStream;

use crate::native_discovery::runtime::owner::RuntimeError;
use crate::network::{ForwardError, ForwardStats, Session};
use crate::path::{DialError, Dialer, PathKind, Route, StandbyError, StandbyOwner};

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
