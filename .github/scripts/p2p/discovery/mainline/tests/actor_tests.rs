// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use tokio::sync::oneshot;

use super::Actor;
use crate::common::{Id, Message, MessageType, Node, RequestSpecific, RequestTypeSpecific};
use crate::resource::ResourceError;
use crate::{OwnedDht, OwnedDhtHandle};

fn ipv4(socket: &UdpSocket) -> SocketAddrV4 {
    match socket.local_addr().expect("socket address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("bound numeric IPv4 socket"),
    }
}

fn loopback() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
}

#[tokio::test]
async fn owned_actor_keeps_socket_until_cleanup_completes() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    let bind = actor.socket.local_addr();

    let (flush_entered, await_flush_entered) = oneshot::channel();
    let (release_flush, await_flush_release) = oneshot::channel();
    actor.socket.owned_flush_gate = Some((flush_entered, await_flush_release));
    let (cleanup_entered, await_cleanup_entered) = oneshot::channel();
    let (release_cleanup, await_cleanup_release) = oneshot::channel();
    actor.owned_cleanup_gate = Some((cleanup_entered, await_cleanup_release));

    let mut owner = OwnedDht::from_actor(actor);
    let clone = owner.handle().clone();
    await_flush_entered.await.expect("actor entered held flush");
    owner.request_stop();
    await_cleanup_entered.await.expect("actor entered cleanup");

    assert!(release_flush.send(()).is_err());
    assert_eq!(
        owner
            .close()
            .await
            .err()
            .expect("held cleanup times out")
            .kind(),
        ErrorKind::TimedOut
    );
    assert_eq!(
        UdpSocket::bind(bind)
            .expect_err("actor retains its socket during cleanup")
            .kind(),
        ErrorKind::AddrInUse
    );

    {
        let mut closing = std::pin::pin!(owner.close());
        let pending = std::future::poll_fn(|cx| {
            let result = std::future::Future::poll(closing.as_mut(), cx);
            std::task::Poll::Ready(result.is_pending())
        })
        .await;
        assert!(pending, "held actor cleanup keeps close pending");
    }

    release_cleanup.send(()).expect("release actor cleanup");
    owner.close().await.expect("actor completes cleanup");
    assert!(clone.info().await.is_err());

    let rebound = UdpSocket::bind(bind).expect("completed cleanup releases socket");
    drop(rebound);
}

#[tokio::test]
async fn owned_actor_keeps_socket_until_receive_returns() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    let bind = actor.socket.local_addr();

    let (recv_entered, await_recv_entered) = oneshot::channel();
    let (release_recv, await_recv_release) = oneshot::channel();
    actor.socket.owned_recv_gate = Some((recv_entered, await_recv_release));

    let mut owner = OwnedDht::from_actor(actor);
    let clone = owner.handle().clone();
    await_recv_entered
        .await
        .expect("actor entered held receive");
    owner.request_stop();

    owner.close().await.expect("actor completes shutdown");
    assert!(release_recv.send(()).is_err());
    assert!(clone.info().await.is_err());

    let rebound = UdpSocket::bind(bind).expect("completed shutdown releases socket");
    drop(rebound);
}

#[tokio::test]
async fn owned_query_failure_is_local_and_shutdown_cancels_retained_handle() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    actor
        .enable_owned_resources()
        .expect("enable owned resources");
    let bind = actor.socket.local_addr();
    let target = Id::random();
    let (sender, receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("admit owned mutable query");
    let query = actor
        .core
        .iterative_queries
        .get_mut(&target)
        .expect("active query");
    for index in 0..255 {
        query.add_candidate(Node::unique(index));
    }
    query.add_candidate(Node::unique(10_000));
    assert_eq!(
        actor.core.iterative_queries[&target].owner_error(),
        Some(ResourceError::CandidateLimit)
    );
    let mut owner = OwnedDht::from_actor(actor);
    let retained: OwnedDhtHandle = owner.handle();
    assert!(matches!(
        receiver.await.expect("query reports resource failure"),
        Err(ResourceError::CandidateLimit)
    ));
    retained.info().await.expect("query failure leaves actor live");
    owner.close().await.expect("join actor after failure");
    assert!(matches!(
        retained.resolve_mutable(target).await,
        Err(ResourceError::QueryCancelled)
    ));
    assert!(matches!(retained.info().await, Err(ResourceError::QueryCancelled)));
    let rebound = UdpSocket::bind(bind).expect("joined actor released its socket");
    drop(rebound);
    drop(retained);
}

#[tokio::test]
async fn numeric_actor_remains_strictly_client_only() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    actor.core.firewalled = false;
    actor.set_server_mode(true);
    assert!(!actor.core.server_mode);
    assert!(!actor.socket.server_mode);

    actor.core.last_table_refresh = std::time::Instant::now()
        .checked_sub(crate::core::REFRESH_TABLE_INTERVAL + Duration::from_secs(1))
        .expect("15-minute refresh interval is representable");
    actor.periodic_node_maintaenance();
    assert!(!actor.core.server_mode);
    assert!(!actor.socket.server_mode);

    let requester = UdpSocket::bind(loopback()).expect("bind requester");
    requester.set_nonblocking(true).expect("set nonblocking");
    let incoming = Message {
        transaction_id: 7,
        version: None,
        requester_ip: None,
        message_type: MessageType::Request(RequestSpecific {
            requester_id: Id::random(),
            request_type: RequestTypeSpecific::Ping,
        }),
        read_only: false,
    };

    actor.core.server_mode = true;
    actor.socket.server_mode = true;
    let wire = incoming.to_bytes().expect("encode incoming ping");
    requester
        .send_to(&wire, actor.socket.local_addr())
        .expect("send ping to actor");
    let (decoded, from) = actor.socket.recv_from().await.expect("receive actual ping");
    assert_eq!(decoded, incoming, "UDP decoder preserves the exact message");
    assert_eq!(from, ipv4(&requester));
    let no_response = actor.handle_incoming_message(decoded, from);
    assert!(
        no_response.is_none(),
        "strict client-only actor rejects responder path"
    );
    actor.core.server_mode = false;
    actor.socket.server_mode = false;
    actor.socket.flush().await;

    let mut bytes = [0_u8; 128];
    assert_eq!(
        requester.recv_from(&mut bytes).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn public_admission_overflow_keeps_actor_and_live_requests() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    let actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let bind = handle
        .info()
        .await
        .expect("actor info before requests")
        .local_addr();
    let target = Id::from([0xc1; 20]);
    let mut requests: Vec<_> = (0..24)
        .map(|_| Box::pin(handle.resolve_mutable(target)))
        .collect();

    for batch in requests.chunks_mut(8) {
        for request in batch.iter_mut() {
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        handle
            .info()
            .await
            .expect("FIFO barrier after admission batch");
        for request in batch.iter_mut() {
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
    }

    assert!(matches!(
        handle.resolve_mutable(target).await,
        Err(ResourceError::OperationLimit)
    ));
    handle
        .info()
        .await
        .expect("overflow does not terminate actor");
    for request in &mut requests {
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }

    drop(requests);
    owner
        .close()
        .await
        .expect("close actor after dropping requests");
    let rebound = UdpSocket::bind(bind).expect("actor shutdown releases its socket");
    drop(rebound);
}

#[tokio::test]
async fn public_distinct_operation_saturation_defers_maintenance() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    actor
        .enable_owned_resources()
        .expect("enable owned resources");
    let (maintenance_reached, await_maintenance) = oneshot::channel();
    actor.owned_maintenance_after_operations = Some((8, maintenance_reached));

    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    let bind = handle
        .info()
        .await
        .expect("actor info before requests")
        .local_addr();
    let mut requests: Vec<_> = (0..8)
        .map(|seed| Box::pin(handle.resolve_mutable(Id::from([seed; 20]))))
        .collect();

    for request in &mut requests {
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        handle
            .info()
            .await
            .expect("FIFO barrier after distinct admission");
    }

    await_maintenance
        .await
        .expect("owned maintenance reached operation threshold");
    handle
        .info()
        .await
        .expect("maintenance completed without rejecting live operations");
    for request in &mut requests {
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }

    let mut ninth = Box::pin(handle.resolve_mutable(Id::from([8; 20])));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(ninth.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    handle
        .info()
        .await
        .expect("ninth distinct operation remains queued");
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(ninth.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;

    drop(ninth);
    drop(requests);
    owner
        .close()
        .await
        .expect("close actor after dropping requests");
    let rebound = UdpSocket::bind(bind).expect("actor shutdown releases its socket");
    drop(rebound);
}

#[tokio::test(start_paused = true)]
async fn owned_actor_deadline_interrupts_held_send_without_transmission() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    bootstrap
        .set_nonblocking(true)
        .expect("set bootstrap nonblocking");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    actor
        .enable_owned_resources()
        .expect("enable owned resources");
    actor.owned_disable_maintenance_for_test = true;
    let bind = actor.socket.local_addr();
    let (maintenance_reached, _await_maintenance) = oneshot::channel();
    actor.owned_maintenance_after_operations = Some((8, maintenance_reached));

    let target = Id::from([0x92; 20]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (result_sender, mut result) = oneshot::channel();
    actor
        .owned_mutable_until(target, result_sender, deadline)
        .expect("admit owned mutable query");

    let (charge_probe, await_charge_probe) = tokio::sync::mpsc::channel(1);
    actor
        .socket
        .install_owned_charge_probe_for_test(await_charge_probe);
    let (send_entered, await_send_entered) = oneshot::channel();
    let (release_send, await_send_release) = oneshot::channel();
    actor
        .socket
        .hold_next_persistent_send_for_test(send_entered, await_send_release);
    let retained = actor.socket.owned_test_state().expect("owned socket state");
    assert_eq!((retained.0, retained.2, retained.3), (1, 1, 1));
    let budget =
        std::sync::Arc::clone(&actor.owned_resources.as_ref().expect("owned actor").budget);
    let mut owner = OwnedDht::from_actor(actor);
    let retained_handle = owner.handle();
    await_send_entered.await.expect("actor entered held send");

    tokio::time::advance(deadline - tokio::time::Instant::now() - Duration::from_millis(1)).await;
    assert!(matches!(
        result.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        budget.visited_count() > 0,
        "visited addresses remain charged before expiry"
    );
    assert!(
        budget.holder_count() > 0,
        "candidate holders remain charged before expiry"
    );
    assert!(
        !release_send.is_closed(),
        "held send has not been interrupted before deadline"
    );
    let (snapshot_sender, snapshot) = oneshot::channel();
    charge_probe
        .send(snapshot_sender)
        .await
        .expect("charge probe receiver is held by gated flush");
    let charged = snapshot.await.expect("read-only charge snapshot");
    assert_eq!((charged.0, charged.2, charged.3), (1, 1, 1));
    assert_eq!(charged.1, retained.1);

    assert!(matches!(
        result.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        !release_send.is_closed(),
        "probe leaves held send gate open"
    );

    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        tokio::time::Instant::now(),
        deadline,
        "completion observed at original deadline without auto-advance"
    );
    assert!(matches!(
        result.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert!(
        release_send.send(()).is_err(),
        "deadline interruption drops held send gate"
    );
    retained_handle
        .info()
        .await
        .expect("retained handle remains usable after expiry");
    assert_eq!(
        budget.visited_count(),
        0,
        "actual expiry cleanup releases admitted visited leases"
    );
    assert_eq!(
        budget.holder_count(),
        1,
        "bootstrap holder persists while actor-owned"
    );
    let mut bytes = [0_u8; 128];
    assert_eq!(
        bootstrap.recv_from(&mut bytes).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );

    owner.close().await.expect("close actor after deadline");
    assert_eq!(
        budget.holder_count(),
        0,
        "owner close releases bootstrap holder"
    );
    let rebound = UdpSocket::bind(bind).expect("actor shutdown releases its socket");
    drop(rebound);
}

#[tokio::test]
async fn public_cancel_interrupts_held_owned_send() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    bootstrap
        .set_nonblocking(true)
        .expect("set bootstrap nonblocking");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    actor
        .enable_owned_resources()
        .expect("enable owned resources");
    let bind = actor.socket.local_addr();

    let (send_entered, await_send_entered) = oneshot::channel();
    let (release_send, await_send_release) = oneshot::channel();
    actor
        .socket
        .hold_next_send_for_test(send_entered, await_send_release);
    let (maintenance_reached, _await_maintenance) = oneshot::channel();
    actor.owned_maintenance_after_operations = Some((8, maintenance_reached));

    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    handle.info().await.expect("actor info before request");

    let mut request = Box::pin(handle.resolve_mutable(Id::from([0x91; 20])));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    await_send_entered.await.expect("actor entered held send");
    drop(request);

    handle
        .info()
        .await
        .expect("actor remains live after cancellation");
    assert!(
        release_send.send(()).is_err(),
        "cancelled send gate is dropped"
    );
    let mut bytes = [0_u8; 128];
    assert_eq!(
        bootstrap.recv_from(&mut bytes).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );

    owner
        .close()
        .await
        .expect("close actor after cancelling request");
    let rebound = UdpSocket::bind(bind).expect("actor shutdown releases its socket");
    drop(rebound);
}

#[tokio::test]
async fn stop_while_flush_held_retains_charges_and_transmits_nothing() {
    let bootstrap = UdpSocket::bind(loopback()).expect("bind bootstrap");
    bootstrap
        .set_nonblocking(true)
        .expect("set bootstrap nonblocking");
    let mut actor = Actor::new_numeric(loopback(), vec![ipv4(&bootstrap)].into_boxed_slice())
        .expect("create numeric actor");
    actor
        .enable_owned_resources()
        .expect("enable owned resources");
    let bind = actor.socket.local_addr();
    let (send_entered, await_send_entered) = oneshot::channel();
    let (release_send, await_send_release) = oneshot::channel();
    actor
        .socket
        .hold_next_send_for_test(send_entered, await_send_release);
    let (maintenance_reached, _await_maintenance) = oneshot::channel();
    actor.owned_maintenance_after_operations = Some((8, maintenance_reached));
    let store_budget =
        std::sync::Arc::clone(&actor.owned_resources.as_ref().expect("owned actor").budget);

    let mut owner = OwnedDht::from_actor(actor);
    let handle = owner.handle();
    handle.info().await.expect("actor info before request");

    let mut request = Box::pin(handle.resolve_mutable(Id::from([0x93; 20])));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(request.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    await_send_entered.await.expect("actor entered held send");
    let holders_before = store_budget.holder_count();
    let visited_before = store_budget.visited_count();
    assert!(holders_before > 0, "bootstrap holder charge retained while held");
    assert!(visited_before > 0, "visited address charge retained while held");

    owner.request_stop();
    owner
        .close()
        .await
        .expect("stopped actor joins despite held flush");

    assert!(
        release_send.send(()).is_err(),
        "stop dropped the held send gate with the abandoned flush"
    );
    let mut bytes = [0_u8; 2048];
    assert_eq!(
        bootstrap.recv_from(&mut bytes).unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "held datagram was never transmitted"
    );
    assert_eq!(store_budget.holder_count(), 0, "join released retained holders");
    assert_eq!(store_budget.visited_count(), 0, "join released retained visited leases");
    assert!(matches!(
        handle.resolve_mutable(Id::random()).await,
        Err(ResourceError::QueryCancelled)
    ));
    let rebound = UdpSocket::bind(bind).expect("joined actor released its socket");
    drop(rebound);
}
