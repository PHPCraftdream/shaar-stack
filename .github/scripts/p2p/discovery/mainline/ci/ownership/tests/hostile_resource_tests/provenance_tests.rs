// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

async fn check_shared_get_provenance(get_reply: bool) {
    let (bootstrap, bootstrap_address) = capture();
    let (put_peer, put_address) = capture();
    let (maintenance_peer, maintenance_address) = capture();
    let mut actor = bounded_actor(bootstrap_address);
    actor
        .owned_ping(maintenance_address)
        .expect("independent maintenance RPC");
    let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();
    let target = Id::from([0x71; 20]);
    let request = PutRequestSpecific::PutImmutable(PutImmutableRequestArguments {
        target,
        v: vec![1, 2, 3].into_boxed_slice(),
    });
    actor
        .owned_put(request.clone(), None)
        .expect("actual owned PUT admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let (sender, receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("coalesce typed waiter onto live GET");
    let budget = std::sync::Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let mut put =
        PutQuery::new_owned(request, None, operation, budget).expect("actual owned PutQuery");
    put.start(
        &mut actor.socket,
        &[Node::new_with_token(
            Id::from([0x74; 20]),
            put_address,
            vec![9].into_boxed_slice(),
        )],
    )
    .expect("start actual PUT RPC");
    let put_tid = *put.transaction_ids().first().expect("PUT transaction");
    *actor
        .core
        .put_queries
        .get_mut(&target)
        .expect("actual unstarted PUT entry") = put;
    actor.socket.flush().await;
    let (get_request, _) = receive_request(&bootstrap).await;
    let (put_request, put_source) = receive_request(&put_peer).await;
    assert_eq!(put_request.transaction_id, put_tid);
    let (_maintenance_request, _) = receive_request(&maintenance_peer).await;
    let reply = Message {
        transaction_id: put_tid,
        version: Some([82, 83, 0, 6]),
        requester_ip: None,
        message_type: MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
            responder_id: Id::from([0x72; 20]),
        })),
        read_only: false,
    };
    put_peer
        .send_to(&reply.to_bytes().expect("encode PUT response"), put_source)
        .await
        .expect("send PUT success");
    let (decoded, from) = receive_response(&mut actor).await;
    actor.process_message(decoded, from);
    actor.owned_note_response(put_tid);
    assert!(actor.owned_has_response_operation(operation));
    actor.tick_owned();
    assert!(!actor.core.put_queries.contains_key(&target));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target)
    );
    assert!(actor.owned_has_response_operation(operation));
    assert!(actor.socket.owned_inflight(get_request.transaction_id));
    assert!(actor.socket.operation_rpc_len(maintenance) > 0);
    if get_reply {
        let reply = Message {
            transaction_id: get_request.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Response(ResponseSpecific::FindNode(
                FindNodeResponseArguments {
                    responder_id: Id::from([0x73; 20]),
                    nodes: Box::new([]),
                },
            )),
            read_only: false,
        };
        bootstrap
            .send_to(
                &reply.to_bytes().expect("encode GET response"),
                actor.socket.local_addr(),
            )
            .await
            .expect("send GET response");
        let (decoded, from) = receive_response(&mut actor).await;
        actor.process_message(decoded, from);
        actor.owned_note_response(get_request.transaction_id);
    } else {
        actor
            .socket
            .expire_owned_requests(std::time::Duration::ZERO);
    }
    actor.tick_owned();
    assert_eq!(
        receiver
            .await
            .expect("typed GET completion")
            .expect("GET succeeded")
            .network_completed(),
        get_reply
    );
    assert!(!actor.owned_has_response_operation(operation));
    assert!(
        !actor
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
    if get_reply {
        assert!(actor.socket.operation_rpc_len(maintenance) > 0);
    }
}

#[tokio::test]
async fn shared_live_get_survives_owned_put_completion() {
    check_shared_get_provenance(true).await;
}

#[tokio::test]
async fn put_response_alone_does_not_mark_shared_get_network_completed() {
    check_shared_get_provenance(false).await;
}
