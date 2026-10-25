#![forbid(unsafe_code)]

// Installed as tests::native_retention in the prepared Noq-proto 1.3.0 copy.
use assert_matches::assert_matches;
use testresult::TestResult;

use super::util::{ConnPair, ManyToManyRouting, subscribe};
use crate::{
    ClosePathError, Event, FourTuple, PathAbandonReason, PathError, PathEvent, PathId, PathStatus,
    Side, Side::*, TransportErrorCode, VarInt,
};

fn routes(pair: &mut ConnPair) -> [FourTuple; 2] {
    let client = pair.routes.as_basic().client_addr;
    let server = pair.routes.as_basic().server_addr;
    let mut clients = [client; 3];
    let mut servers = [server; 3];
    for (index, offset) in [(1, 1u16), (2, 2u16)] {
        clients[index].set_port(client.port().checked_add(offset).unwrap());
        servers[index].set_port(server.port().checked_add(offset).unwrap());
    }
    pair.routes = ManyToManyRouting::simple_symmetric(clients, servers).into();
    [
        FourTuple::new(servers[1], Some(clients[1].ip())),
        FourTuple::new(servers[2], Some(clients[2].ip())),
    ]
}

fn retain(pair: &mut ConnPair, route: FourTuple) -> Result<(PathId, bool), PathError> {
    let now = pair.time;
    pair.conn_mut(Client)
        .open_path_ensure_retained(route, PathStatus::Backup, now)
}

fn prune(pair: &mut ConnPair, id: PathId) -> Result<bool, ClosePathError> {
    let now = pair.time;
    pair.conn_mut(Client).close_path_if_unretained(
        now,
        id,
        TransportErrorCode::APPLICATION_ABANDON_PATH.into(),
    )
}

fn events(pair: &mut ConnPair, side: Side) -> Vec<Event> {
    let mut events = Vec::new();
    while let Some(event) = pair.poll(side) {
        assert!(
            !matches!(event, Event::ConnectionLost { .. }),
            "unexpected connection loss: {event:?}"
        );
        events.push(event);
    }
    events
}

fn assert_established(events: &[Event], expected: PathId) {
    assert!(
        events.iter().any(|event| matches!(
            event, Event::Path(PathEvent::Established { id, .. }) if *id == expected
        )),
        "missing establishment for {expected:?}: {events:?}"
    );
    assert_not_abandoned(events, expected);
}

fn assert_not_abandoned(events: &[Event], expected: PathId) {
    assert!(
        !events.iter().any(|event| matches!(
            event,
            Event::Path(PathEvent::Abandoned { id, .. } | PathEvent::Discarded { id, .. })
                if *id == expected
        )),
        "retained path {expected:?} was removed: {events:?}"
    );
}

fn assert_discarded(events: &[Event], expected: PathId) {
    assert!(
        events.iter().any(|event| matches!(
            event, Event::Path(PathEvent::Discarded { id, .. }) if *id == expected
        )),
        "missing discard for {expected:?}: {events:?}"
    );
}

#[test]
fn native_retention_new_path_survives_pruning_before_and_after_establishment() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let [native, competing] = routes(&mut pair);
    let (retained, existed) = retain(&mut pair, native)?;
    assert!(!existed);
    assert_ne!(retained, PathId::ZERO);
    let other = pair.open_path(Client, competing, PathStatus::Backup)?;
    assert_ne!(retained, other);

    // No packets have been driven: retention must precede Established.
    assert!(!prune(&mut pair, retained)?);
    pair.drive();
    for side in [Client, Server] {
        let observed = events(&mut pair, side);
        assert_established(&observed, retained);
        assert_established(&observed, other);
    }
    assert!(!prune(&mut pair, retained)?);
    assert!(prune(&mut pair, other)?);
    pair.drive();
    for side in [Client, Server] {
        let observed = events(&mut pair, side);
        assert_not_abandoned(&observed, retained);
        assert_discarded(&observed, other);
        assert!(pair.paths(side).contains(&retained));
        assert!(!pair.paths(side).contains(&other));
    }
    assert!(!prune(&mut pair, retained)?);
    assert_eq!(
        pair.network_path(Client, retained)?.remote(),
        native.remote()
    );
    Ok(())
}

#[test]
fn native_retention_reuses_pending_and_established_paths() -> TestResult {
    let _guard = subscribe();
    for establish_first in [false, true] {
        let mut pair = ConnPair::builder().enable_multipath().connect();
        let [native, _] = routes(&mut pair);
        let original = pair.open_path(Client, native, PathStatus::Available)?;
        if establish_first {
            pair.drive();
            for side in [Client, Server] {
                assert_established(&events(&mut pair, side), original);
            }
        }
        let before = pair.paths(Client);
        assert_eq!(retain(&mut pair, native)?, (original, true));
        assert_eq!(retain(&mut pair, native)?, (original, true));
        assert_eq!(pair.paths(Client), before);
        assert_eq!(pair.path_status(Client, original)?, PathStatus::Available);
        assert!(!prune(&mut pair, original)?);
        pair.drive();
        for side in [Client, Server] {
            let observed = events(&mut pair, side);
            if establish_first {
                assert_not_abandoned(&observed, original);
            } else {
                assert_established(&observed, original);
            }
        }
    }
    Ok(())
}

#[test]
fn native_retention_pruning_first_allocates_a_different_id() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let [native, _] = routes(&mut pair);
    let abandoned = pair.open_path(Client, native, PathStatus::Backup)?;
    assert!(prune(&mut pair, abandoned)?);
    let (retained, existed) = retain(&mut pair, native)?;
    assert!(!existed);
    assert_ne!(retained, abandoned);
    assert!(!prune(&mut pair, retained)?);
    pair.drive();
    let client_events = events(&mut pair, Client);
    assert_established(&client_events, retained);
    assert!(!client_events.iter().any(|event| matches!(
        event, Event::Path(PathEvent::Established { id, .. }) if *id == abandoned
    )));
    assert!(client_events.iter().any(|event| matches!(
        event,
        Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::ApplicationClosed { error_code },
            ..
        }) if *id == abandoned
            && *error_code == VarInt::from(TransportErrorCode::APPLICATION_ABANDON_PATH)
    )));
    assert_established(&events(&mut pair, Server), retained);
    assert_matches!(prune(&mut pair, abandoned), Err(ClosePathError::ClosedPath));
    assert!(!prune(&mut pair, retained)?);
    assert!(!pair.paths(Server).contains(&abandoned));

    // The peer never saw this path, so it cannot echo PATH_ABANDON to arm PathDrained.
    // Verify owner teardown instead of requiring a per-path Discarded event here.
    pair.close(Client, 0, b"done");
    pair.close(Server, 0, b"done");
    assert!(
        !pair.drive_bounded(100),
        "connection teardown did not quiesce"
    );
    assert!(pair.is_drained(Client));
    assert!(pair.is_drained(Server));
    Ok(())
}

#[test]
fn native_retention_does_not_override_explicit_close_or_leak_to_replacement() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let [native, _] = routes(&mut pair);
    let (retained, _) = retain(&mut pair, native)?;
    pair.drive();
    for side in [Client, Server] {
        assert_established(&events(&mut pair, side), retained);
    }
    pair.close_path(Client, retained, 17u8.into())?;
    pair.drive();
    let client_events = events(&mut pair, Client);
    assert!(client_events.iter().any(|event| matches!(
        event,
        Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::ApplicationClosed { error_code },
            ..
        }) if *id == retained && *error_code == VarInt::from(17u8)
    )));
    assert_discarded(&client_events, retained);
    assert_discarded(&events(&mut pair, Server), retained);
    assert_matches!(prune(&mut pair, retained), Err(ClosePathError::ClosedPath));
    assert!(!pair.paths(Client).contains(&retained));

    let (replacement, existed) = pair.open_path_ensure(Client, native, PathStatus::Backup)?;
    assert!(!existed);
    assert_ne!(replacement, retained);
    assert!(prune(&mut pair, replacement)?);
    Ok(())
}

#[test]
fn native_retention_does_not_override_remote_abandonment() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let [native, _] = routes(&mut pair);
    let (retained, _) = retain(&mut pair, native)?;
    pair.drive();
    for side in [Client, Server] {
        assert_established(&events(&mut pair, side), retained);
    }
    pair.close_path(Server, retained, 19u8.into())?;
    pair.drive();
    let observed = events(&mut pair, Client);
    assert!(observed.iter().any(|event| matches!(
        event,
        Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::RemoteAbandoned { error_code },
            ..
        }) if *id == retained && *error_code == VarInt::from(19u8)
    )));
    assert_discarded(&observed, retained);
    assert_matches!(prune(&mut pair, retained), Err(ClosePathError::ClosedPath));
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));
    Ok(())
}

#[test]
fn native_retention_rejections_preserve_existing_path_state() -> TestResult {
    let _guard = subscribe();
    let mut plain = ConnPair::builder().connect();
    let [native, _] = routes(&mut plain);
    let before = plain.paths(Client);
    assert_matches!(
        retain(&mut plain, native),
        Err(PathError::MultipathNotNegotiated)
    );
    assert_eq!(plain.paths(Client), before);
    assert_matches!(
        prune(&mut plain, PathId::ZERO),
        Err(ClosePathError::MultipathNotNegotiated)
    );

    let mut pair = ConnPair::builder().enable_multipath().connect();
    let [native, _] = routes(&mut pair);
    let now = pair.time;
    let before = pair.paths(Server);
    assert_matches!(
        pair.conn_mut(Server)
            .open_path_ensure_retained(native, PathStatus::Backup, now),
        Err(PathError::ServerSideNotAllowed)
    );
    assert_eq!(pair.paths(Server), before);
    assert_matches!(
        prune(&mut pair, PathId::MAX),
        Err(ClosePathError::ClosedPath)
    );
    assert_matches!(
        prune(&mut pair, PathId::ZERO),
        Err(ClosePathError::LastOpenPath)
    );

    let initial = pair.network_path(Client, PathId::ZERO)?;
    assert_eq!(retain(&mut pair, initial)?, (PathId::ZERO, true));
    assert!(!prune(&mut pair, PathId::ZERO)?);
    assert_matches!(
        pair.close_path(Client, PathId::ZERO, 0u8.into()),
        Err(ClosePathError::LastOpenPath)
    );
    Ok(())
}

#[test]
fn native_retention_capacity_error_does_not_retain_an_unrelated_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let [native, competing] = routes(&mut pair);
    let (retained, _) = retain(&mut pair, native)?;
    let ordinary = pair.open_path(Client, competing, PathStatus::Backup)?;
    let mut unavailable = competing.remote();
    unavailable.set_port(unavailable.port().checked_add(1).unwrap());
    let before = pair.paths(Client);
    assert_matches!(
        retain(&mut pair, FourTuple::from_remote(unavailable)),
        Err(PathError::MaxPathIdReached)
    );
    assert_eq!(pair.paths(Client), before);
    assert!(!prune(&mut pair, retained)?);
    assert!(prune(&mut pair, ordinary)?);
    Ok(())
}

#[test]
fn native_retention_missing_cids_reserves_neither_id_nor_retention() -> TestResult {
    let _guard = subscribe();
    let (mut pair, client_config) = ConnPair::builder().enable_multipath().build_pair();
    let client = pair.begin_connect(client_config);
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    pair.drive_server();
    // Same packet boundary as upstream regression_delayed_path_cids_blocked.
    let (_, server_cids) = pair.client.inbound.pop_last().unwrap();
    pair.drive_client();
    let server = pair.server.assert_accept();
    pair.finish_connect(client, server);
    let mut pair = ConnPair::new(pair, client, server);
    let [native, _] = routes(&mut pair);
    let before = pair.paths(Client);
    assert_matches!(
        retain(&mut pair, native),
        Err(PathError::RemoteCidsExhausted)
    );
    assert_eq!(pair.paths(Client), before);

    let now = pair.time;
    pair.client.inbound.push(now, server_cids);
    pair.drive_client();
    let (ordinary, existed) = pair.open_path_ensure(Client, native, PathStatus::Backup)?;
    assert!(!existed);
    assert_eq!(ordinary, PathId::from(1u8));
    assert!(prune(&mut pair, ordinary)?);
    Ok(())
}
