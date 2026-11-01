// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::OwnedDht;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

fn addr(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn bootstrap() -> (UdpSocket, SocketAddrV4) {
    let socket = UdpSocket::bind(addr(0)).expect("bind numeric loopback bootstrap");
    let address = match socket.local_addr().expect("bootstrap address") {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!("bound IPv4 socket"),
    };
    (socket, address)
}

#[tokio::test]
async fn close_joins_actor_and_releases_exact_bind() {
    let (_bootstrap_socket, bootstrap) = bootstrap();
    let mut owner = OwnedDht::new(addr(0), &[bootstrap]).expect("start owned DHT");
    let clone = owner.dht().clone();
    let bind = owner.dht().info().await.expect("DHT info").local_addr();
    assert_eq!(*bind.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(bind.port(), 0);

    owner.close().await.expect("join actor");
    assert!(
        clone.info().await.is_err(),
        "retained clone is inert after close"
    );
    assert!(
        owner.join.is_none(),
        "successful close consumes join handle"
    );
    owner.close().await.expect("close is idempotent");
    assert!(owner.join.is_none());

    let rebound = UdpSocket::bind(bind).expect("actor released exact numeric bind");
    drop(rebound);
    drop(clone);
    drop(owner);
}

#[tokio::test]
async fn close_reports_aborted_actor_join_failure_and_retains_terminal_error() {
    let (_bootstrap_socket, bootstrap) = bootstrap();
    let mut owner = OwnedDht::new(addr(0), &[bootstrap]).expect("start owned DHT");
    let clone = owner.dht().clone();
    let bind = owner.dht().info().await.expect("DHT info").local_addr();
    assert_eq!(*bind.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(bind.port(), 0);

    owner.join.as_ref().expect("actor join handle").abort();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), owner.close())
        .await
        .expect("aborted actor join completes")
        .expect_err("aborted task is not successful shutdown");
    assert_eq!(first.kind(), io::ErrorKind::Interrupted);
    assert!(owner.join.is_none(), "completed join handle is consumed");

    let second = owner
        .close()
        .await
        .expect_err("terminal failure is retained");
    assert_eq!(second.kind(), first.kind());
    assert!(
        clone.info().await.is_err(),
        "retained clone is inert after actor abort"
    );

    let rebound = UdpSocket::bind(bind).expect("aborted actor released exact numeric bind");
    drop(rebound);
    drop(clone);
    drop(owner);
}

#[tokio::test]
async fn accepts_four_numeric_bootstrap_addresses_and_closes_idle_actor() {
    let (_bootstrap_socket, bootstrap) = bootstrap();
    let nodes = [bootstrap; 4];
    let mut owner = OwnedDht::new(addr(0), &nodes).expect("accept four bootstrap addresses");

    owner.close().await.expect("stop and join idle actor");
}

#[tokio::test]
async fn validates_bootstrap_before_attempting_bind() {
    let (_valid_bootstrap_socket, valid_bootstrap) = bootstrap();
    let occupied = UdpSocket::bind(addr(0)).expect("occupy loopback address");
    let bind = match occupied.local_addr().expect("occupied address") {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!("bound IPv4 socket"),
    };
    let zero_port = addr(0);
    let too_many = [valid_bootstrap; 5];

    for (nodes, expected) in [
        (&[][..], io::ErrorKind::InvalidInput),
        (&too_many[..], io::ErrorKind::InvalidInput),
        (&[zero_port][..], io::ErrorKind::InvalidInput),
        (&[valid_bootstrap][..], io::ErrorKind::AddrInUse),
    ] {
        let error = OwnedDht::new(bind, nodes)
            .err()
            .expect("invalid or occupied bind must fail");
        assert_eq!(error.kind(), expected);
    }
}

#[test]
fn actor_run_keeps_stop_priority_outside_unbiased_work_select() {
    let source = include_str!("../actor.rs");
    let start = source.find("async fn run_inner(").expect("run_inner start");
    let end = source[start..].find("\nfn send(").expect("send function") + start;
    let run_inner = &source[start..end];
    let normalized = run_inner.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(normalized.contains(
        "tokio::select! { biased; _ = wait_stop(&mut stop) => break, keep_running = async {"
    ));
    assert!(normalized.contains("keep_running = async { tokio::select! { msg = receiver.recv()"));
    let work_start = normalized
        .find("keep_running = async {")
        .expect("work future");
    let work_end = normalized[work_start..]
        .find("} => { if !keep_running {")
        .map(|offset| work_start + offset)
        .expect("work future completion");
    let work = &normalized[work_start..work_end];
    assert_eq!(work.matches("tokio::select!").count(), 1);
    assert!(!work.contains("biased;"));
    assert!(work.contains("packet = actor.socket.recv_from()"));
    assert!(work.contains("_ = maintenance.tick()"));
    assert!(normalized.contains("None => { // All senders dropped, shutdown. debug!(\"dht::Dht's actor task was shutdown after Drop.\"); return false; }"));
}
