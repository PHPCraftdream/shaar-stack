// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::actor::Actor;
use crate::common::{
    FindNodeResponseArguments, Id, Message, MessageType, Node, PingResponseArguments,
    PutImmutableRequestArguments, PutRequestSpecific, ResponseSpecific,
};
use crate::core::put_query::PutQuery;
use crate::resource::ResourceError;
use tokio::sync::oneshot;

fn capture() -> (tokio::net::UdpSocket, SocketAddrV4) {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("capture peer bind");
    socket
        .set_nonblocking(true)
        .expect("Tokio requires nonblocking socket");
    let address = match socket.local_addr().expect("capture peer address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 capture bind"),
    };
    (
        tokio::net::UdpSocket::from_std(socket).expect("register capture peer"),
        address,
    )
}

fn bounded_actor(bootstrap: SocketAddrV4) -> Actor {
    let mut actor = Actor::new_numeric(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        vec![bootstrap].into_boxed_slice(),
    )
    .expect("construct numeric actor");
    actor
        .enable_owned_resources()
        .expect("enable actual actor budget");
    actor
}

fn hostile_node(index: usize) -> Node {
    let mut id_bytes = [0u8; 20];
    id_bytes[12..].copy_from_slice(&(index as u64).to_be_bytes());
    let address = SocketAddrV4::new(
        Ipv4Addr::new(
            127,
            0,
            ((index / 250) % 250 + 1) as u8,
            (index % 250 + 1) as u8,
        ),
        (2000 + index % 60_000) as u16,
    );
    Node::new(Id::from(id_bytes), address)
}

async fn receive_request(peer: &tokio::net::UdpSocket) -> (Message, SocketAddrV4) {
    let mut bytes = [0u8; 2048];
    let (length, source) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .expect("actual query datagram arrives")
        .expect("capture peer receives datagram");
    let source = match source {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("actor uses IPv4 socket"),
    };
    (
        Message::from_bytes(&bytes[..length]).expect("decode actual request"),
        source,
    )
}

async fn receive_response(actor: &mut Actor) -> (Message, SocketAddrV4) {
    tokio::time::timeout(Duration::from_secs(2), actor.socket.recv_from())
        .await
        .expect("actual response arrives at actor")
        .expect("socket accepts expected response")
}

#[path = "hostile_resource_tests/completion_tests.rs"]
mod completion;

#[path = "hostile_resource_tests/provenance_tests.rs"]
mod provenance;

#[tokio::test]
async fn socket_validated_hostile_referrals_hit_actual_candidate_limit() {
    let (peer, peer_address) = capture();
    let mut actor = bounded_actor(peer_address);
    let budget =
        std::sync::Arc::clone(&actor.owned_resources.as_ref().expect("owned actor").budget);
    let target = Id::from([0x42; 20]);
    let (sender, receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("typed mutable lookup admitted");
    actor.socket.flush().await;
    let (request, source) = receive_request(&peer).await;
    assert_eq!(source, actor.socket.local_addr());

    let query = actor
        .core
        .iterative_queries
        .get_mut(&target)
        .expect("real Core query");
    for index in 0..255 {
        query.add_candidate(hostile_node(index));
        assert!(
            query.owner_error().is_none(),
            "unique candidate admitted at index {index}"
        );
    }
    assert_eq!(
        budget.holder_count(),
        256,
        "bootstrap plus real query candidates"
    );

    let response = Message {
        transaction_id: request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::FindNode(
            FindNodeResponseArguments {
                responder_id: Id::from([0x21; 20]),
                nodes: (1000..1004).map(hostile_node).collect(),
            },
        )),
        read_only: false,
    };
    peer.send_to(
        &response.to_bytes().expect("encode real KRPC response"),
        source,
    )
    .await
    .expect("send referrals from queried peer");
    let (decoded, from) = receive_response(&mut actor).await;
    assert_eq!(from, peer_address);
    assert_eq!(decoded.transaction_id, request.transaction_id);
    actor.process_message(decoded, from);

    assert_eq!(
        actor.core.iterative_queries[&target].owner_error(),
        Some(ResourceError::CandidateLimit)
    );
    assert_eq!(
        budget.holder_count(),
        256,
        "referrals do not grow retained-holder accounting"
    );
    actor.tick_owned();
    assert!(matches!(
        receiver.await.expect("typed completion"),
        Err(ResourceError::CandidateLimit)
    ));
    assert_eq!(actor.owned_error(), Some(ResourceError::CandidateLimit));
    assert!(actor.core.iterative_queries.is_empty());
    assert_eq!(
        actor.socket.owned_test_state().unwrap().2,
        0,
        "failure cancels actual RPC entries"
    );
}

#[tokio::test]
async fn real_socket_rejects_wrong_source_and_receipt_uses_the_accepted_operation() {
    let (peer, peer_address) = capture();
    let (spoof, _) = capture();
    let mut actor = bounded_actor(peer_address);
    let target = Id::from([0x31; 20]);
    let (sender, receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("register actual typed operation");
    actor.socket.flush().await;
    let (request, destination) = receive_request(&peer).await;
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let reply = Message {
        transaction_id: request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::FindNode(
            FindNodeResponseArguments {
                responder_id: Id::from([0x17; 20]),
                nodes: Box::new([]),
            },
        )),
        read_only: false,
    }
    .to_bytes()
    .expect("encode KRPC response");

    spoof
        .send_to(&reply, destination)
        .await
        .expect("send wrong-source reply");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), actor.socket.recv_from())
            .await
            .expect("wrong-source datagram handled")
            .is_none()
    );
    assert!(
        actor.socket.owned_inflight(request.transaction_id),
        "wrong source leaves actual RPC live"
    );
    assert_eq!(actor.socket.owned_response_operation(), None);

    peer.send_to(&reply, destination)
        .await
        .expect("reply from registered source");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(request.transaction_id);
    assert_eq!(
        actor.socket.owned_response_operation().map(|(_, id)| id),
        Some(operation)
    );
    actor.tick_owned();
    let completion = receiver
        .await
        .expect("typed response result")
        .expect("accepted response completed");
    assert!(completion.network_completed());
    assert!(completion.items().is_empty());
}

async fn terminal_owned_put_response_releases_receipt(success: bool) {
    let (peer, peer_address) = capture();
    let (_maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor
        .owned_ping(maintenance_address)
        .expect("independent maintenance RPC");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let target = Id::from([0x61; 20]);
    let request = crate::common::PutRequestSpecific::PutImmutable(PutImmutableRequestArguments {
        target,
        v: vec![1, 2, 3].into_boxed_slice(),
    });
    actor
        .owned_put(request, None)
        .expect("actual owned PUT admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    actor.socket.flush().await;
    let (get_request, source) = receive_request(&peer).await;
    let response = Message {
        transaction_id: get_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0x62; 20]),
                token: vec![9, 8].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(
        &response.to_bytes().expect("encode actual GET response"),
        source,
    )
    .await
    .expect("send GET response");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(get_request.transaction_id);
    actor.tick_owned();
    assert!(
        !actor.owned_has_response_operation(operation),
        "completed GET receipt is cleared"
    );
    assert!(actor.core.put_queries.contains_key(&target));
    assert!(!actor.core.iterative_queries.contains_key(&target));
    actor.socket.flush().await;

    let (put_request, put_source) = receive_request(&peer).await;
    assert!(matches!(
        &put_request.message_type,
        MessageType::Request(crate::common::RequestSpecific {
            request_type: crate::common::RequestTypeSpecific::Put(_),
            ..
        })
    ));
    let response = Message {
        transaction_id: put_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: if success {
            MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
                responder_id: Id::from([0x63; 20]),
            }))
        } else {
            MessageType::Error(crate::common::ErrorSpecific {
                code: 201,
                description: "PUT rejected".to_owned(),
            })
        },
        read_only: false,
    };
    peer.send_to(
        &response.to_bytes().expect("encode accepted PUT response"),
        put_source,
    )
    .await
    .expect("send PUT success");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(put_request.transaction_id);
    assert!(
        actor.owned_has_response_operation(operation),
        "PUT receipt recorded immediately"
    );
    actor.tick_owned();
    assert!(
        !actor.core.put_queries.contains_key(&target),
        "actual PUT completed"
    );
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert!(
        !actor.owned_has_response_operation(operation),
        "PUT terminal response clears receipt"
    );
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(maintenance)
    );
    assert!(
        actor.socket.operation_rpc_len(maintenance) > 0,
        "independent maintenance RPC survives"
    );
}

#[path = "hostile_resource_tests/put_lifecycle_tests.rs"]
mod put_lifecycle;

#[tokio::test]
async fn newer_owned_mutable_put_replaces_old_receipt_without_disturbing_other_operations() {
    use crate::common::{MutableItem, PutMutableRequestArguments};
    use ed25519_dalek::SigningKey;

    let (peer, peer_address) = capture();
    let (_maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(peer_address);
    actor
        .owned_ping(maintenance_address)
        .expect("independent maintenance RPC");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let signer = SigningKey::from_bytes(&[0x91; 32]);
    let old_item = MutableItem::new(&signer, b"older", 1, None);
    let target = *old_item.target();
    let mut old_put_arguments = PutMutableRequestArguments::from(old_item, None);
    old_put_arguments.cas = Some(0);
    actor
        .owned_put(PutRequestSpecific::PutMutable(old_put_arguments), None)
        .expect("first mutable PUT admitted");
    let old_operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    actor.socket.flush().await;
    let (get_request, source) = receive_request(&peer).await;
    let response = Message {
        transaction_id: get_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::NoValues(
            crate::common::NoValuesResponseArguments {
                responder_id: Id::from([0x92; 20]),
                token: vec![9].into_boxed_slice(),
                nodes: None,
            },
        )),
        read_only: false,
    };
    peer.send_to(&response.to_bytes().expect("encode GET response"), source)
        .await
        .expect("send GET response");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(get_request.transaction_id);
    actor.tick_owned();
    assert!(!actor.owned_has_response_operation(old_operation));
    actor.socket.flush().await;
    let (old_put_request, put_source) = receive_request(&peer).await;
    let reply = Message {
        transaction_id: old_put_request.transaction_id,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
            responder_id: Id::from([0x93; 20]),
        })),
        read_only: false,
    };
    peer.send_to(
        &reply.to_bytes().expect("encode accepted PUT response"),
        put_source,
    )
    .await
    .expect("send accepted PUT response");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(old_put_request.transaction_id);
    assert!(
        actor.owned_has_response_operation(old_operation),
        "old receipt established before replacement"
    );
    assert!(!actor.socket.owned_inflight(old_put_request.transaction_id));

    let new_item = MutableItem::new(&signer, b"newer", 2, None);
    let mut new_put_arguments = PutMutableRequestArguments::from(new_item, None);
    new_put_arguments.cas = Some(1);
    actor
        .owned_put(PutRequestSpecific::PutMutable(new_put_arguments), None)
        .expect("newer unconditional mutable PUT replaces old query");
    let new_operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    assert_ne!(
        new_operation, old_operation,
        "replacement allocates distinct operation"
    );
    assert!(
        !actor.owned_has_response_operation(old_operation),
        "replacement clears old receipt"
    );
    assert!(
        !actor.socket.owned_inflight(old_put_request.transaction_id),
        "replacement cancels old PUT RPC"
    );
    assert!(actor.core.put_queries.contains_key(&target));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().maintenance,
        Some(maintenance)
    );
    assert!(
        actor.socket.operation_rpc_len(maintenance) > 0,
        "replacement leaves maintenance intact"
    );
}

#[tokio::test]
async fn operation_slots_include_maintenance_in_both_orders() {
    let (_peer, bootstrap) = capture();
    let (_maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap);
    actor
        .owned_ping(maintenance_address)
        .expect("maintenance operation admitted");
    let targets: Vec<_> = (1..=7).map(|index| Id::from([index; 20])).collect();
    for target in &targets {
        actor
            .owned_get(
                crate::core::iterative_query::GetRequestSpecific::GetValue(
                    crate::common::GetValueRequestArguments {
                        target: *target,
                        seq: None,
                        salt: None,
                    },
                ),
                None,
            )
            .expect("seven user operations admitted after maintenance");
    }
    let rejected = Id::from([8; 20]);
    assert!(matches!(
        actor.owned_get(
            crate::core::iterative_query::GetRequestSpecific::GetValue(
                crate::common::GetValueRequestArguments {
                    target: rejected,
                    seq: None,
                    salt: None
                }
            ),
            None
        ),
        Err(ResourceError::OperationLimit)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&rejected));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&rejected)
    );

    let (_peer, bootstrap) = capture();
    let (_maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap);
    let targets: Vec<_> = (20..28).map(|index| Id::from([index; 20])).collect();
    for target in &targets {
        actor
            .owned_get(
                crate::core::iterative_query::GetRequestSpecific::GetValue(
                    crate::common::GetValueRequestArguments {
                        target: *target,
                        seq: None,
                        salt: None,
                    },
                ),
                None,
            )
            .expect("eight user operations admitted first");
    }
    assert_eq!(
        actor.owned_ping(maintenance_address),
        Err(ResourceError::OperationLimit)
    );
    assert!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .maintenance
            .is_none()
    );
}

#[tokio::test]
async fn actual_owned_put_ping_response_releases_only_put_receipt() {
    terminal_owned_put_response_releases_receipt(true).await;
}

#[tokio::test]
async fn actual_owned_put_error_response_releases_only_put_receipt() {
    terminal_owned_put_response_releases_receipt(false).await;
}
