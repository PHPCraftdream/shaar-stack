// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn owned_put_timeout_releases_receipt_and_preserves_success_or_error_semantics() {
    for success in [true, false] {
        let (first_peer, first_address) = capture();
        let (second_peer, second_address) = capture();
        let (_maintenance_peer, maintenance_address) = capture();
        let mut actor = bounded_actor(first_address);
        let target = Id::from([if success { 0x81 } else { 0x82 }; 20]);
        let request = PutRequestSpecific::PutImmutable(PutImmutableRequestArguments {
            target,
            v: vec![1, 2, 3].into_boxed_slice(),
        });
        actor
            .owned_put(
                request,
                Some(
                    vec![Node::new_with_token(
                        Id::from([0x84; 20]),
                        second_address,
                        vec![8].into_boxed_slice(),
                    )]
                    .into_boxed_slice(),
                ),
            )
            .expect("actual owned PUT admitted");
        let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
        actor.socket.flush().await;
        let (get_request, get_source) = receive_request(&first_peer).await;
        let response = Message {
            transaction_id: get_request.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: MessageType::Response(ResponseSpecific::NoValues(
                crate::common::NoValuesResponseArguments {
                    responder_id: Id::from([0x83; 20]),
                    token: vec![7].into_boxed_slice(),
                    nodes: None,
                },
            )),
            read_only: false,
        };
        first_peer
            .send_to(
                &response.to_bytes().expect("encode GET response"),
                get_source.into(),
            )
            .await
            .expect("send GET response");
        let (decoded, from) = receive_response(&mut actor).await;
        actor.process_message(decoded, from);
        actor.owned_note_response(get_request.transaction_id);
        actor.tick_owned();
        assert!(!actor.core.iterative_queries.contains_key(&target));
        assert!(actor.core.put_queries.contains_key(&target));
        actor.socket.flush().await;

        let (first_put, first_source) = receive_request(&first_peer).await;
        let (second_put, _) = receive_request(&second_peer).await;
        assert!(matches!(first_put.message_type, MessageType::Request(_)));
        assert!(matches!(second_put.message_type, MessageType::Request(_)));
        assert_ne!(first_put.transaction_id, second_put.transaction_id);
        actor
            .owned_ping(maintenance_address)
            .expect("queue independent maintenance RPC");
        let maintenance = actor.owned_resources.as_ref().unwrap().maintenance.unwrap();

        let response = Message {
            transaction_id: first_put.transaction_id,
            version: Some([82, 83, 0, 6]),
            requester_ip: None,
            message_type: if success {
                MessageType::Response(ResponseSpecific::Ping(PingResponseArguments {
                    responder_id: Id::from([0x85; 20]),
                }))
            } else {
                MessageType::Error(crate::common::ErrorSpecific {
                    code: 201,
                    description: "PUT rejected".to_owned(),
                })
            },
            read_only: false,
        };
        first_peer
            .send_to(
                &response.to_bytes().expect("encode first PUT response"),
                first_source.into(),
            )
            .await
            .expect("send first PUT response");
        let (decoded, from) = receive_response(&mut actor).await;
        actor.process_message(decoded, from);
        actor.owned_note_response(first_put.transaction_id);
        assert!(actor.owned_has_response_operation(operation));
        assert!(actor.socket.owned_inflight(second_put.transaction_id));

        actor.socket.expire_owned_requests(Duration::ZERO);
        assert!(!actor.socket.owned_inflight(second_put.transaction_id));
        assert!(actor.owned_has_response_operation(operation));
        assert_eq!(
            actor
                .socket
                .owned_response_operation()
                .map(|(tid, id)| (tid, id)),
            Some((first_put.transaction_id, operation))
        );
        assert!(actor.core.put_queries.contains_key(&target));
        assert_eq!(actor.socket.owned_test_state().unwrap().2, 1);
        if success {
            assert!(matches!(
                actor.core.put_queries[&target].check(&actor.socket),
                Ok(true)
            ));
        } else {
            assert!(
                actor.core.put_queries[&target]
                    .check(&actor.socket)
                    .is_err()
            );
        }
        assert!(!actor.socket.owned_inflight(first_put.transaction_id));
        assert!(!actor.core.iterative_queries.contains_key(&target));

        actor.tick_owned();
        assert!(!actor.core.put_queries.contains_key(&target));
        assert!(!actor.core.iterative_queries.contains_key(&target));
        assert!(
            !actor
                .owned_resources
                .as_ref()
                .unwrap()
                .operations
                .contains_key(&target)
        );
        assert!(!actor.owned_has_response_operation(operation));
        assert_eq!(
            actor.owned_resources.as_ref().unwrap().maintenance,
            Some(maintenance)
        );
        assert_eq!(actor.socket.operation_rpc_len(maintenance), 1);
    }
}
