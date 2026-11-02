// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::*;
use crate::core::iterative_query::GetRequestSpecific;
use crate::resource::RequestReply;
use tokio::time::Instant;

#[tokio::test]
async fn ordinary_request_tick_respects_maintenance_isolation() {
    for (isolation, expected_queries) in [(true, 1), (false, 2)] {
        let (peer, bootstrap) = capture();
        let mut actor = bounded_actor(bootstrap);
        actor.owned_disable_maintenance_for_test = isolation;
        let target = Id::from([0xD7; 20]);
        actor.owned_get(
            GetRequestSpecific::GetValue(crate::common::GetValueRequestArguments {
                target,
                seq: None,
                salt: None,
            }),
            None,
        )
        .expect("admit ordinary request");
        actor.tick();
        assert_eq!(actor.core.iterative_queries.len(), expected_queries);
        assert_eq!(actor.owned_resources.as_ref().unwrap().maintenance.is_some(), !isolation);
        actor.socket.flush().await;

        let (first, _) = receive_request(&peer).await;
        match first.message_type {
            MessageType::Request(request) => match request.request_type {
                crate::common::RequestTypeSpecific::GetValue(arguments) => {
                    assert_eq!(arguments.target, target);
                }
                other => panic!("ordinary request tick sent unexpected request: {other:?}"),
            },
            other => panic!("ordinary request tick sent non-request: {other:?}"),
        }

        if !isolation {
            let (second, _) = receive_request(&peer).await;
            match second.message_type {
                MessageType::Request(request) => match request.request_type {
                    crate::common::RequestTypeSpecific::FindNode(arguments) => {
                        assert_eq!(arguments.target, *actor.core.routing_table.id());
                    }
                    other => panic!("maintenance sent unexpected request: {other:?}"),
                },
                other => panic!("maintenance sent non-request: {other:?}"),
            }
        }

        let mut bytes = [0u8; 2048];
        match peer.try_recv_from(&mut bytes) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((length, _)) => panic!("unexpected extra datagram ({length} bytes)"),
            Err(error) => panic!("capture peer receive failed: {error}"),
        }
    }
}

#[tokio::test]
async fn queued_get_admission_wakes_only_when_a_real_resource_is_released() {
    let (_peer, bootstrap) = capture();
    let mut actor = bounded_actor(bootstrap);
    let mut targets = Vec::new();

    for index in 0..8u8 {
        let mut bytes = [0u8; 20];
        bytes[19] = index;
        let target = Id::from(bytes);
        actor.owned_get(
            GetRequestSpecific::GetValue(crate::common::GetValueRequestArguments {
                target,
                seq: None,
                salt: None,
            }),
            None,
        ).expect("admit actual GET");
        targets.push(target);
    }

    let wake = actor.owned_request_budget().cancellation_wake();
    let queued_target = Id::from([0xF9; 20]);
    let lease = actor.owned_request_budget().acquire().expect("request lease");
    let (sender, mut reply) = oneshot::channel();
    actor.owned_admission_until(
        queued_target,
        sender,
        Instant::now() + std::time::Duration::from_secs(10),
        lease,
    );
    assert!(matches!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    assert_eq!(actor.owned_resources.as_ref().unwrap().pending_len(), 1);

    tokio::select! {
        biased;
        _ = wake.notified() => panic!("overload admission must not wake itself"),
        _ = std::future::ready(()) => {}
    }
    actor.maintain_owned_admissions_at(Instant::now());
    assert!(matches!(reply.try_recv(), Err(oneshot::error::TryRecvError::Empty)));
    assert_eq!(actor.owned_resources.as_ref().unwrap().pending_len(), 1);
    tokio::select! {
        biased;
        _ = wake.notified() => panic!("maintaining a blocked admission must not self-wake"),
        _ = std::future::ready(()) => {}
    }

    let operation = actor.owned_resources.as_ref().unwrap().operations[&targets[0]];
    actor.socket.register_owned_deadline(operation, Instant::now()).expect("register deadline");
    actor.expire_owned_operations_at(Instant::now());
    actor.maintain_owned_admissions_at(Instant::now());
    assert!(matches!(reply.try_recv(), Ok(RequestReply::Ready(_))));
    assert!(actor.core.iterative_queries.contains_key(&queued_target));
    for target in targets.iter().skip(1) {
        assert!(actor.core.iterative_queries.contains_key(target));
    }
}

#[tokio::test]
async fn result_lease_release_signals_admission_waiters() {
    let (_peer, bootstrap) = capture();
    let actor = bounded_actor(bootstrap);
    let resources = actor.owned_resources.as_ref().unwrap();
    let lease = resources.reserve_result_for_test().expect("result lease");
    let wake = actor.owned_request_budget().cancellation_wake();
    drop(lease);
    tokio::select! {
        biased;
        _ = wake.notified() => {}
        _ = std::future::ready(()) => panic!("result lease release must wake admission"),
    }
}
