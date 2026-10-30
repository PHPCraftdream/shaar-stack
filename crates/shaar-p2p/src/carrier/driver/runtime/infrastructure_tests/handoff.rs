use super::*;
use crate::discovery::roles::Role;
use crate::{DiscoveredRelay, RelayLease};

/// cancel-safe: yes — selected events are dispatched synchronously; work stays in the Core.
async fn step(source: &mut Carrier, server: &mut MetadataServer) {
    let now = Instant::now();
    source.core.discovery_tick(now);
    source.core.infrastructure_tick(now).unwrap();
    source.core.relay_tick(now).unwrap();
    let deadline = source
        .core
        .discovery_deadline()
        .into_iter()
        .chain(source.core.infrastructure.next_deadline())
        .chain(source.core.relay.next_deadline())
        .chain(source.core.relay.gate.next_deadline())
        .min();
    let timer = async {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        event = source.core.swarm.select_next_some() => source.core.event(event).unwrap(),
        _ = server.swarm.select_next_some() => {},
        _ = timer => {},
    }
}

/// cancel-safe: NO — an admitted discovery remains owned until observed cancellation.
async fn discover(source: &mut Carrier, server: &mut MetadataServer) -> DiscoveredRelay {
    let (reply, mut result) = oneshot::channel();
    source.core.command(Command::Discover(reply));
    loop {
        tokio::select! {
            result = &mut result => {
                let mut candidates = result.unwrap().unwrap();
                assert_eq!(candidates.len(), 1);
                return candidates.pop().unwrap();
            },
            _ = step(source, server) => {},
        }
    }
}

/// cancel-safe: NO — reservation cancellation is reconciled by the Core.
async fn reserve(
    source: &mut Carrier,
    server: &mut MetadataServer,
    candidate: DiscoveredRelay,
) -> io::Result<RelayLease> {
    let (reply, mut result) = oneshot::channel();
    source
        .core
        .command(Command::ReserveDiscovered(candidate, reply));
    loop {
        tokio::select! {
            result = &mut result => return result.unwrap(),
            _ = step(source, server) => {},
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_discovery_handoff_owns_real_reservation_without_role_mutation_or_app_authority() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = MetadataServer::configured(true).await;
        let seed_root = root(server.peer, server.address.port());
        let (mut source, handle, mut incoming) = carrier(&dns, vec![(server.peer, seed_root)]);
        source.core.discovery_witnesses[0] = Some((server.peer, server.address));
        let candidate = discover(&mut source, &mut server).await;
        let key = candidate.key;
        let discovery_deadline = source.core.discovery_deadline().unwrap();
        let view = source
            .core
            .swarm
            .behaviour()
            .inner
            .admission
            .roles_view()
            .unwrap();
        let lease = reserve(&mut source, &mut server, candidate).await.unwrap();
        assert_eq!(lease.relay().peer_id(), server.peer);
        assert_eq!(lease.relay().socket_addr(), server.address);
        assert_eq!(lease.connection_id(), key.connection);
        assert!(lease.expires_at() > Instant::now());
        assert_eq!(view.role(server.peer), Some(Role::Infrastructure));
        assert_eq!(handle.relay_leases().borrow().as_slice(), &[lease]);
        assert!(handle.links().borrow().is_empty());
        assert!(source.core.relay.routes.is_empty());
        assert!(matches!(
            incoming.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let (reply, denied) = oneshot::channel();
        source.core.command(Command::Reserve(lease.relay(), reply));
        assert_eq!(
            denied.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let (reply, denied) = oneshot::channel();
        source
            .core
            .command(Command::Connect(server.peer, server.address, reply));
        assert_eq!(
            denied.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        tokio::time::pause();
        tokio::time::advance(
            discovery_deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        )
        .await;
        source.core.discovery_tick(Instant::now());
        source.core.infrastructure_tick(Instant::now()).unwrap();
        source.core.relay_tick(Instant::now()).unwrap();
        assert!(source.core.discovery_operation.is_none());
        assert_eq!(
            view.infrastructure_live(key),
            Some(server.address),
            "DISCOVERY_RETIREMENT_CLOSED_ADOPTED_CONTROL"
        );
        assert_eq!(handle.relay_leases().borrow().as_slice(), &[lease]);
        tokio::time::resume();
        // Metadata edge injection follows a real authenticated discovery and reservation.
        receive(
            &mut source,
            server.peer,
            key.connection,
            info(&server.public, vec![StreamProtocol::new("/ipfs/kad/1.0.0")]),
        );
        assert!(handle.relay_leases().borrow().is_empty());
        assert!(!source.core.relay.gate.reservation_permit(
            server.peer,
            lease.generation(),
            key.connection
        ));
        assert_eq!(view.role(server.peer), Some(Role::Infrastructure));
        let (reply, mut released) = oneshot::channel();
        source
            .core
            .command(Command::ReleaseRelay(server.peer, reply));
        loop {
            tokio::select! {
                result = &mut released => { result.unwrap().unwrap(); break; },
                _ = step(&mut source, &mut server) => {},
            }
        }
        assert!(source.core.infrastructure_control(key).is_none());
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_discovery_handoff_cancel_keeps_terminal_charges_and_closes_adopted_control() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = MetadataServer::configured(true).await;
        let seed_root = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, seed_root)]);
        source.core.discovery_witnesses[0] = Some((server.peer, server.address));
        let candidate = discover(&mut source, &mut server).await;
        let key = candidate.key;
        let (reply, result) = oneshot::channel();
        source
            .core
            .command(Command::ReserveDiscovered(candidate, reply));
        assert!(source.core.relay.gate.record_count() > 0);
        drop(result);
        source.core.relay_tick(Instant::now()).unwrap();
        assert!(handle.relay_leases().borrow().is_empty());
        assert!(
            source.core.relay.gate.record_count() > 0,
            "WAITER_DROP_FREED_TERMINAL_CHARGE"
        );
        assert!(source.core.infrastructure_control(key).is_some());
        while source.core.infrastructure_control(key).is_some() {
            step(&mut source, &mut server).await;
        }
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_discovery_handoff_reservation_refusal_never_publishes_a_lease() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = MetadataServer::new().await;
        let seed_root = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, seed_root)]);
        source.core.discovery_witnesses[0] = Some((server.peer, server.address));
        let candidate = discover(&mut source, &mut server).await;
        let key = candidate.key;
        assert!(reserve(&mut source, &mut server, candidate).await.is_err());
        assert!(handle.relay_leases().borrow().is_empty());
        assert!(handle.links().borrow().is_empty());
        let view = source
            .core
            .swarm
            .behaviour()
            .inner
            .admission
            .roles_view()
            .unwrap();
        assert_eq!(view.role(server.peer), Some(Role::Infrastructure));
        while source.core.infrastructure_control(key).is_some() {
            step(&mut source, &mut server).await;
        }
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn carrier_discovery_handoff_expired_candidate_has_no_reservation_authority() {
    timeout(Duration::from_secs(35), async {
        let dns = Dns::new().await;
        let mut server = MetadataServer::configured(true).await;
        let seed_root = root(server.peer, server.address.port());
        let (mut source, handle, _incoming) = carrier(&dns, vec![(server.peer, seed_root)]);
        source.core.discovery_witnesses[0] = Some((server.peer, server.address));
        let candidate = discover(&mut source, &mut server).await;
        let deadline = source.core.discovery_deadline().unwrap();
        tokio::time::pause();
        tokio::time::advance(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        )
        .await;
        source.core.discovery_tick(Instant::now());
        tokio::time::resume();
        let (reply, rejected) = oneshot::channel();
        source
            .core
            .command(Command::ReserveDiscovered(candidate, reply));
        assert_eq!(
            rejected.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(handle.relay_leases().borrow().is_empty());
        assert_eq!(source.core.relay.gate.record_count(), 0);
        shutdown(source, &handle).await;
        server.shutdown().await;
        assert!(dns.shutdown().await > 0);
    })
    .await
    .unwrap();
}
