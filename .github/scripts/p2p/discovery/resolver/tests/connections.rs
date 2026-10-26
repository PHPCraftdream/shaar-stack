#![forbid(unsafe_code)]

use super::*;
#[cfg(feature = "__tls")]
use crate::config::ProtocolConfig;
use crate::{net::runtime::TokioRuntimeProvider, TlsConfig};
use futures_util::stream::{self, Empty};
use std::{
    future::{ready, Future, Ready},
    net::Ipv4Addr,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Wake, Waker},
};

#[derive(Clone)]
struct Connection(u8, Option<Arc<PruneProbe>>);

struct PruneProbe {
    context: Arc<PoolContext>,
    drops: Arc<AtomicUsize>,
    secondary_unlocked: Arc<AtomicUsize>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(probe) = &self.1 {
            probe.drops.fetch_add(1, Ordering::Relaxed);
            if probe.context.transport_state.try_lock().is_some() {
                probe.secondary_unlocked.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl DnsHandle for Connection {
    type Response = Empty<Result<DnsResponse, NetError>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, _: DnsRequest) -> Self::Response {
        stream::empty()
    }
}

#[derive(Clone, Default)]
struct Provider {
    runtime: TokioRuntimeProvider,
    calls: Arc<SyncMutex<Vec<Protocol>>>,
    failure: u8,
}

impl ConnectionProvider for Provider {
    type Conn = Connection;
    type FutureConn = Ready<Result<Connection, NetError>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        _: IpAddr,
        config: &ConnectionConfig,
        _: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        self.calls.lock().push(config.protocol.to_protocol());
        match self.failure {
            1 => Err(NetError::Busy),
            2 => Ok(ready(Err(NetError::Timeout))),
            _ => Ok(ready(Ok(Connection(99, None)))),
        }
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn context() -> Arc<PoolContext> {
    Arc::new(PoolContext::new(
        ResolverOpts::default(),
        TlsConfig::new().expect("fixture TLS configuration"),
    ))
}

fn server(provider: Provider, connections: &[(Protocol, u8)]) -> NameServer<Provider> {
    NameServer::new(
        connections
            .iter()
            .map(|&(protocol, id)| (protocol, Connection(id, None))),
        NameServerConfig::udp_and_tcp(Ipv4Addr::LOCALHOST.into()),
        &ResolverOpts::default(),
        provider,
    )
}

fn selected(
    server: &NameServer<Provider>,
    context: &Arc<PoolContext>,
    disable_udp: bool,
) -> ConnectedClient<Provider> {
    let mut future =
        Box::pin(server.connected_mut_client(ConnectionPolicy { disable_udp }, context));
    match poll(future.as_mut()) {
        Poll::Ready(Ok(client)) => client,
        _ => panic!("selection must complete without fixture contention"),
    }
}

#[test]
fn transport_wait_releases_connections_and_wakes() {
    let server = server(Provider::default(), &[(Protocol::Udp, 1)]);
    let context = context();
    let transport = context.transport_state.try_lock().unwrap();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut task = Context::from_waker(&waker);
    let mut future = Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(future.as_mut().poll(&mut task).is_pending());
    assert!(
        server.connections.try_lock().is_some(),
        "CONNECTIONS_HELD_WHILE_WAITING"
    );
    drop(transport);
    assert!(
        wakes.0.load(Ordering::Relaxed) > 0,
        "transport waiter was not registered"
    );
    assert!(matches!(
        future.as_mut().poll(&mut task),
        Poll::Ready(Ok(_))
    ));
    drop(future);
    assert!(server.connections.try_lock().is_some());
    assert!(context.transport_state.try_lock().is_some());
}

#[test]
fn connection_wait_never_retains_transport_state() {
    let server = server(Provider::default(), &[(Protocol::Tcp, 1)]);
    let context = context();
    let connections = server.connections.try_lock().unwrap();
    let mut future = Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(poll(future.as_mut()).is_pending());
    assert!(context.transport_state.try_lock().is_some());
    drop(future);
    drop(connections);
    assert_eq!(selected(&server, &context, false).handle.0, 1);
}

#[test]
fn alternating_contention_rechecks_live_connections_without_lost_wakeup() {
    let server = server(Provider::default(), &[(Protocol::Tcp, 1)]);
    let context = context();
    let transport = context.transport_state.try_lock().unwrap();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut task = Context::from_waker(&waker);
    let mut future = Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(future.as_mut().poll(&mut task).is_pending());
    let mut connections = server
        .connections
        .try_lock()
        .expect("connections must be released");
    connections.clear();
    connections.push(ConnectionState::new(Connection(2, None), Protocol::Udp));
    drop(transport);
    assert!(
        context.transport_state.try_lock().is_some(),
        "TRANSPORT_RESERVED_BEFORE_REPOLL"
    );
    assert!(future.as_mut().poll(&mut task).is_pending());
    assert!(
        context.transport_state.try_lock().is_some(),
        "TRANSPORT_RESERVED_DURING_CONNECTION_WAIT"
    );
    let before = wakes.0.load(Ordering::Relaxed);
    drop(connections);
    assert!(wakes.0.load(Ordering::Relaxed) > before);
    match future.as_mut().poll(&mut task) {
        Poll::Ready(Ok(client)) => {
            assert_eq!(client.handle.0, 2);
            assert_eq!(client.protocol, Protocol::Udp);
            assert!(matches!(client.reuse, ConnectionReuse::Reused));
        }
        _ => panic!("latest connection must be selected"),
    }
    assert!(server.connection_provider.calls.lock().is_empty());
}

fn cancellation_wakes_survivor<T>(mutex: &AsyncMutex<T>, future: impl Future, after_wake: bool) {
    let mut held = Some(mutex.try_lock().unwrap());
    let cancelled_wakes = Arc::new(Wakes::default());
    let cancelled_waker = Waker::from(cancelled_wakes.clone());
    let survivor_wakes = Arc::new(Wakes::default());
    let survivor_waker = Waker::from(survivor_wakes.clone());
    let mut cancelled = Box::pin(future);
    let mut survivor = Box::pin(mutex.lock());
    assert!(cancelled
        .as_mut()
        .poll(&mut Context::from_waker(&cancelled_waker))
        .is_pending());
    assert!(survivor
        .as_mut()
        .poll(&mut Context::from_waker(&survivor_waker))
        .is_pending());
    assert_eq!(survivor_wakes.0.load(Ordering::Relaxed), 0);
    if after_wake {
        drop(held.take());
        assert!(cancelled_wakes.0.load(Ordering::Relaxed) > 0);
        assert_eq!(survivor_wakes.0.load(Ordering::Relaxed), 0);
    }
    drop(cancelled);
    drop(held);
    // Observe notification before polling: a leaked waiter cannot pass via try_lock.
    assert!(
        survivor_wakes.0.load(Ordering::Relaxed) > 0,
        "SURVIVOR_WAKE_LOST_ON_CANCELLATION"
    );
    assert!(poll(survivor.as_mut()).is_ready());
}

#[test]
fn cancellation_releases_both_waiter_registrations() {
    for after_wake in [false, true] {
        for transport in [false, true] {
            let server = server(Provider::default(), &[(Protocol::Udp, 1)]);
            let context = context();
            let future = server.connected_mut_client(ConnectionPolicy::default(), &context);
            if transport {
                cancellation_wakes_survivor(&context.transport_state, future, after_wake);
            } else {
                cancellation_wakes_survivor(&server.connections, future, after_wake);
            }
            assert!(server.connection_provider.calls.lock().is_empty());
        }
    }

    let server = server(Provider::default(), &[(Protocol::Udp, 1)]);
    let context = context();
    let transport = context.transport_state.try_lock().unwrap();
    let cancelled_wakes = Arc::new(Wakes::default());
    let cancelled_waker = Waker::from(cancelled_wakes.clone());
    let mut task = Context::from_waker(&cancelled_waker);
    let mut cancelled =
        Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(cancelled.as_mut().poll(&mut task).is_pending());
    let connections = server.connections.try_lock().unwrap();
    drop(transport);
    assert!(cancelled_wakes.0.load(Ordering::Relaxed) > 0);
    assert!(cancelled.as_mut().poll(&mut task).is_pending());
    let transport = context.transport_state.try_lock().unwrap();
    let transport_wakes = Arc::new(Wakes::default());
    let transport_waker = Waker::from(transport_wakes.clone());
    let connections_wakes = Arc::new(Wakes::default());
    let connections_waker = Waker::from(connections_wakes.clone());
    let mut transport_survivor = Box::pin(context.transport_state.lock());
    let mut connections_survivor = Box::pin(server.connections.lock());
    assert!(transport_survivor
        .as_mut()
        .poll(&mut Context::from_waker(&transport_waker))
        .is_pending());
    assert!(connections_survivor
        .as_mut()
        .poll(&mut Context::from_waker(&connections_waker))
        .is_pending());
    assert_eq!(transport_wakes.0.load(Ordering::Relaxed), 0);
    assert_eq!(connections_wakes.0.load(Ordering::Relaxed), 0);
    drop(cancelled);
    // The secondary waiter was already woken: cancellation must forward that wake.
    assert!(
        transport_wakes.0.load(Ordering::Relaxed) > 0,
        "SECONDARY_WAKE_NOT_FORWARDED"
    );
    drop(connections);
    assert!(
        connections_wakes.0.load(Ordering::Relaxed) > 0,
        "PRIMARY_WAITER_NOT_REMOVED"
    );
    drop(transport);
    assert!(poll(transport_survivor.as_mut()).is_ready());
    assert!(poll(connections_survivor.as_mut()).is_ready());
}

#[test]
fn failed_cached_handle_is_pruned_before_transport_state_is_locked() {
    let server = server(Provider::default(), &[(Protocol::Tcp, 1)]);
    let context = context();
    let drops = Arc::new(AtomicUsize::new(0));
    let secondary_unlocked = Arc::new(AtomicUsize::new(0));
    let probe = Arc::new(PruneProbe {
        context: context.clone(),
        drops: drops.clone(),
        secondary_unlocked: secondary_unlocked.clone(),
    });
    let closed = ConnectionState::new(Connection(7, Some(probe)), Protocol::Tcp);
    closed.meta.set_status(Status::Failed);
    server.connections.try_lock().unwrap().push(closed);
    assert!(context.transport_state.try_lock().is_some());
    assert_eq!(selected(&server, &context, false).handle.0, 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(
        secondary_unlocked.load(Ordering::Relaxed),
        1,
        "PRUNING_HELD_TRANSPORT_STATE"
    );
    assert_eq!(server.connections.try_lock().unwrap().len(), 1);
    assert!(server.connection_provider.calls.lock().is_empty());
}

#[test]
fn reuse_policy_order_and_failed_connection_pruning_are_preserved() {
    let server = server(
        Provider::default(),
        &[(Protocol::Tcp, 1), (Protocol::Udp, 2), (Protocol::Tcp, 3)],
    );
    let context = context();
    {
        let connections = server.connections.try_lock().unwrap();
        for connection in connections.iter() {
            let micros = if connection.handle.0 == 1 { 10 } else { 20 };
            connection
                .meta
                .srtt
                .srtt_microseconds
                .store(micros, Ordering::Release);
        }
    }
    assert_eq!(selected(&server, &context, false).handle.0, 2);
    assert_eq!(selected(&server, &context, true).handle.0, 1);
    server
        .connections
        .try_lock()
        .unwrap()
        .iter()
        .find(|connection| connection.handle.0 == 1)
        .unwrap()
        .meta
        .set_status(Status::Failed);
    assert_eq!(selected(&server, &context, true).handle.0, 3);
    assert_eq!(server.connections.try_lock().unwrap().len(), 2);
    assert!(server.connection_provider.calls.lock().is_empty());
}

#[test]
fn fresh_connection_is_stored_and_then_reused() {
    let server = server(Provider::default(), &[]);
    let context = context();
    let first = selected(&server, &context, true);
    assert!(matches!(first.reuse, ConnectionReuse::Fresh));
    assert_eq!(first.protocol, Protocol::Tcp);
    let next = selected(&server, &context, true);
    assert!(matches!(next.reuse, ConnectionReuse::Reused));
    assert!(Arc::ptr_eq(&first.meta, &next.meta));
    assert_eq!(&*server.connection_provider.calls.lock(), &[Protocol::Tcp]);
}

#[test]
fn immediate_future_and_no_configuration_errors_are_preserved() {
    for failure in [1, 2] {
        let server = server(
            Provider {
                failure,
                ..Provider::default()
            },
            &[],
        );
        let context = context();
        let mut future =
            Box::pin(server.connected_mut_client(ConnectionPolicy { disable_udp: true }, &context));
        match poll(future.as_mut()) {
            Poll::Ready(Err((NetError::Busy, Some(Protocol::Tcp)))) if failure == 1 => {}
            Poll::Ready(Err((NetError::Timeout, Some(Protocol::Tcp)))) if failure == 2 => {}
            _ => panic!("provider error or protocol changed"),
        }
        assert!(server.connections.try_lock().unwrap().is_empty());
    }
    let mut server = server(Provider::default(), &[]);
    server.config.connections.clear();
    let context = context();
    let mut future = Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(matches!(
        poll(future.as_mut()),
        Poll::Ready(Err((NetError::NoConnections, None)))
    ));
    assert!(server.connection_provider.calls.lock().is_empty());
}

#[cfg(feature = "__tls")]
#[test]
fn encryption_state_changes_during_wait_are_not_stale_snapshots() {
    let mut server = server(Provider::default(), &[(Protocol::Udp, 1)]);
    server
        .config
        .connections
        .push(ConnectionConfig::new(ProtocolConfig::Tls {
            server_name: Arc::from("fixture.invalid"),
        }));
    let context = Arc::new(
        PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
            .with_opportunistic_encryption(),
    );
    let transport = context.transport_state.try_lock().unwrap();
    let mut future = Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(poll(future.as_mut()).is_pending());
    let connections = server.connections.try_lock().unwrap();
    drop(transport);
    // A snapshot-before-connections implementation can read the old state here.
    assert!(poll(future.as_mut()).is_pending());
    {
        let mut transport = context.transport_state.try_lock().unwrap();
        transport.complete_connection(server.config.ip, Protocol::Tls);
        transport.response_received(server.config.ip, Protocol::Tls);
    }
    drop(connections);
    match poll(future.as_mut()) {
        Poll::Ready(Ok(client)) => {
            assert_eq!(client.protocol, Protocol::Tls);
            assert!(matches!(client.reuse, ConnectionReuse::Fresh));
        }
        _ => panic!("new encrypted success must prevent plaintext reuse"),
    }
    assert_eq!(&*server.connection_provider.calls.lock(), &[Protocol::Tls]);
}

#[cfg(feature = "__tls")]
#[test]
fn latest_encrypted_failure_allows_existing_plaintext_reuse() {
    let server = server(Provider::default(), &[(Protocol::Udp, 1)]);
    let context = Arc::new(
        PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap())
            .with_opportunistic_encryption(),
    );
    let mut transport = context.transport_state.try_lock().unwrap();
    transport.complete_connection(server.config.ip, Protocol::Tls);
    transport.response_received(server.config.ip, Protocol::Tls);
    let mut future = Box::pin(server.connected_mut_client(ConnectionPolicy::default(), &context));
    assert!(poll(future.as_mut()).is_pending());
    let connections = server.connections.try_lock().unwrap();
    drop(transport);
    // Give a stale-snapshot implementation a chance to capture the success.
    assert!(poll(future.as_mut()).is_pending());
    {
        let mut transport = context.transport_state.try_lock().unwrap();
        transport.error_received(server.config.ip, Protocol::Tls, &NetError::Timeout);
    }
    drop(connections);
    match poll(future.as_mut()) {
        Poll::Ready(Ok(client)) => assert_eq!(client.handle.0, 1),
        _ => panic!("latest failure must permit plaintext reuse"),
    }
    assert!(server.connection_provider.calls.lock().is_empty());
}
