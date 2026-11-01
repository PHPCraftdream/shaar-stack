// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use tokio::sync::oneshot;

use super::Actor;
use crate::OwnedDht;
use crate::common::{Id, Message, MessageType, RequestSpecific, RequestTypeSpecific};

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
    let clone = owner.dht().clone();
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
    let clone = owner.dht().clone();
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
