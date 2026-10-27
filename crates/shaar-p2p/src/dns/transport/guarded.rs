use std::{
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use libp2p::{
    Multiaddr, Transport,
    core::transport::{DialOpts, ListenerId, TransportError, TransportEvent},
};
use tokio::time::{Instant, Sleep};

use crate::discovery::roles::{InboundLease, Lease, View};

#[derive(Debug)]
pub(crate) enum Error<E> {
    Authority(io::Error),
    Inner(E),
}
impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => fmt::Display::fmt(error, f),
            Self::Inner(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Inner(error) => Some(error),
        }
    }
}

#[derive(Clone, Copy)]
enum Boundary {
    Context,
    Numeric,
    Child,
}

/// Context wraps the complete upgraded native branch; Numeric sits directly above TCP.
/// Neither boundary applies APP context to a relay transport's rewritten hop.
pub(crate) struct Guard<T> {
    inner: T,
    roles: View,
    boundary: Boundary,
}

impl<T> Guard<T> {
    pub(crate) fn context(inner: T, roles: View) -> Self {
        Self {
            inner,
            roles,
            boundary: Boundary::Context,
        }
    }
    pub(crate) fn child(inner: T, roles: View) -> Self {
        Self {
            inner,
            roles,
            boundary: Boundary::Child,
        }
    }
    pub(crate) fn numeric(inner: T, roles: View) -> Self {
        Self {
            inner,
            roles,
            boundary: Boundary::Numeric,
        }
    }
}

impl<T: Transport + Unpin> Transport for Guard<T>
where
    T::Error: 'static,
{
    type Output = T::Output;
    type Error = Error<T::Error>;
    type ListenerUpgrade = ListenerFuture<T::ListenerUpgrade, T::Output, T::Error>;
    type Dial = DialFuture<T::Dial>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner
            .listen_on(id, address)
            .map_err(|error| error.map(Error::Inner))
    }
    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        options: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if matches!(self.boundary, Boundary::Child)
            && !address
                .iter()
                .any(|part| matches!(part, libp2p::multiaddr::Protocol::P2pCircuit))
        {
            return Err(TransportError::MultiaddrNotSupported(address));
        }
        let authority = match self.boundary {
            Boundary::Context => self
                .roles
                .root_lease(address.as_ref())
                .map(|lease| (lease, None)),
            Boundary::Numeric => self
                .roles
                .numeric_lease(address.as_ref())
                .map(|(lease, endpoint)| (lease, Some(endpoint))),
            Boundary::Child => address
                .iter()
                .filter_map(|part| match part {
                    libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
                    _ => None,
                })
                .last()
                .and_then(|peer| self.roles.current(peer, Instant::now()))
                .filter(|key| self.roles.is_child(*key))
                .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))
                .and_then(|key| self.roles.pending_lease(key, Instant::now()))
                .map(|lease| (lease, None)),
        };
        let (lease, endpoint) =
            authority.map_err(|error| TransportError::Other(Error::Authority(error)))?;
        let deadline = Box::pin(tokio::time::sleep_until(lease.deadline()));
        lease
            .check()
            .map_err(|error| TransportError::Other(Error::Authority(error)))?;
        let future = self
            .inner
            .dial(address, options)
            .map_err(|error| error.map(Error::Inner))?;
        Ok(DialFuture {
            inner: Some(Box::pin(future)),
            lease,
            deadline,
            endpoint,
            done: false,
        })
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll(cx).map(|event| {
            match event {
                TransportEvent::Incoming {
                    listener_id,
                    upgrade,
                    local_addr,
                    send_back_addr,
                } => {
                    let admission = if matches!(this.boundary, Boundary::Context | Boundary::Child)
                    {
                        this.roles
                            .incoming_lease(&local_addr, &send_back_addr)
                            .map(Some)
                    } else {
                        Ok(None)
                    };
                    let upgrade = ListenerFuture::new(upgrade, admission);
                    TransportEvent::Incoming {
                        listener_id,
                        upgrade,
                        local_addr,
                        send_back_addr,
                    }
                }
                other => other.map_upgrade(|upgrade| ListenerFuture::new(upgrade, Ok(None))),
            }
            .map_err(Error::Inner)
        })
    }
}

pub(crate) struct ListenerFuture<F, O, E> {
    inner: Option<Pin<Box<F>>>,
    lease: Option<InboundLease>,
    admission: Option<io::Error>,
    deadline: Pin<Box<Sleep>>,
    done: bool,
    marker: std::marker::PhantomData<fn() -> (O, E)>,
}

impl<F, O, E> ListenerFuture<F, O, E> {
    fn new(inner: F, lease: io::Result<Option<InboundLease>>) -> Self {
        let (lease, admission) = match lease {
            Ok(lease) => (lease, None),
            Err(error) => (None, Some(error)),
        };
        Self {
            inner: Some(Box::pin(inner)),
            lease,
            admission,
            deadline: Box::pin(tokio::time::sleep(Duration::from_secs(10))),
            done: false,
            marker: std::marker::PhantomData,
        }
    }
}

impl<F, O, E> Future for ListenerFuture<F, O, E>
where
    F: Future<Output = Result<O, E>>,
{
    type Output = Result<O, Error<E>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(Error::Authority(io::ErrorKind::BrokenPipe.into())));
        }
        let authority = if let Some(error) = this.admission.take() {
            Err(error)
        } else if this.deadline.as_mut().poll(cx).is_ready() {
            Err(io::ErrorKind::TimedOut.into())
        } else if let Some(lease) = &mut this.lease {
            lease.poll_check(cx)
        } else {
            Ok(())
        };
        if let Err(error) = authority {
            this.done = true;
            drop(this.inner.take());
            return Poll::Ready(Err(Error::Authority(error)));
        }
        let result = match this
            .inner
            .as_mut()
            .expect("unfinished listener retains its future")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        this.done = true;
        drop(this.inner.take());
        if let Some(lease) = &this.lease
            && let Err(error) = lease.check()
        {
            drop(result);
            return Poll::Ready(Err(Error::Authority(error)));
        }
        Poll::Ready(result.map_err(Error::Inner))
    }
}

/// The lease remains a field even after Ready, and drops after the inner future.
/// Safe pinning boxes the dependency future and timer; no candidate address buffer is copied.
pub(crate) struct DialFuture<F> {
    inner: Option<Pin<Box<F>>>,
    lease: Lease,
    deadline: Pin<Box<Sleep>>,
    endpoint: Option<SocketAddr>,
    done: bool,
}

impl<F, O, E> Future for DialFuture<F>
where
    F: Future<Output = Result<O, E>>,
{
    type Output = Result<O, Error<E>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(Error::Authority(io::ErrorKind::BrokenPipe.into())));
        }
        let admission = if this.deadline.as_mut().poll(cx).is_ready() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            this.lease.poll_check(cx)
        };
        if let Err(error) = admission {
            this.done = true;
            drop(this.inner.take());
            return Poll::Ready(Err(Error::Authority(error)));
        }
        let result = match this
            .inner
            .as_mut()
            .expect("unfinished dial retains its future")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        this.done = true;
        drop(this.inner.take());
        if let Err(error) = this.lease.check() {
            drop(result);
            return Poll::Ready(Err(Error::Authority(error)));
        }
        match result {
            Ok(output) => {
                if let Some(endpoint) = this.endpoint
                    && let Err(error) = this.lease.record_numeric(endpoint, Instant::now())
                {
                    drop(output);
                    return Poll::Ready(Err(Error::Authority(error)));
                }
                Poll::Ready(Ok(output))
            }
            Err(error) => Poll::Ready(Err(Error::Inner(error))),
        }
    }
}
