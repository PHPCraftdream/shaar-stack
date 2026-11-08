// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
use super::*;

#[tokio::test]
async fn actual_actor_lazy_admission_bounds_queue_and_releases_cancelled_requests() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = actor.owned_request_budget();
    let mut results = Vec::new();
    for _ in 0..8 {
        let (sender, receiver) = oneshot::channel();
        actor.owned_admission_until(
            target(1),
            sender,
            tokio::time::Instant::now() + Duration::from_secs(30),
            budget.acquire().unwrap(),
        );
        match receiver.await.expect("active request admitted") {
            crate::resource::RequestReply::Ready(result) => results.push(result),
            crate::resource::RequestReply::Error(error) => {
                panic!("unexpected admission error: {error:?}")
            }
        }
    }
    assert_eq!(actor.core.iterative_queries.len(), 1);
    let mut queued_controls = Vec::new();
    for seed in 2..=17 {
        let (sender, receiver) = oneshot::channel();
        actor.owned_admission_until(
            target(seed),
            sender,
            tokio::time::Instant::now() + Duration::from_secs(30),
            budget.acquire().unwrap(),
        );
        queued_controls.push(receiver);
    }
    assert!(queued_controls.iter_mut().all(|receiver| matches!(
        receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    )));
    assert!((2..=17).all(|seed| !actor.core.iterative_queries.contains_key(&target(seed))));
    assert!(budget.acquire().is_none());

    drop(queued_controls.remove(1));
    actor.tick_owned();
    let (sender, mut replacement) = oneshot::channel();
    actor.owned_admission_until(
        target(18),
        sender,
        tokio::time::Instant::now() + Duration::from_secs(30),
        budget.acquire().unwrap(),
    );
    assert!(matches!(
        replacement.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target(18)));

    drop(results.remove(0));
    actor.tick_owned();
    assert!(actor.core.iterative_queries.contains_key(&target(2)));
    assert!(matches!(
        queued_controls[0].try_recv(),
        Ok(crate::resource::RequestReply::Ready(_))
    ));
    drop(queued_controls.pop().expect("last queued receiver"));
    actor.tick_owned();

    let expired = target(99);
    let (sender, mut expired_receiver) = oneshot::channel();
    let expired_request = budget.acquire().expect("released queued request permit");
    actor.owned_admission_until(
        expired,
        sender,
        tokio::time::Instant::now(),
        expired_request,
    );
    assert!(matches!(
        expired_receiver.try_recv(),
        Ok(crate::resource::RequestReply::Error(
            ResourceError::DeadlineExceeded
        ))
    ));
    assert!(!actor.core.iterative_queries.contains_key(&expired));
}

#[tokio::test]
async fn queued_deadlines_expire_without_work_and_promotion_keeps_original_deadline() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = actor.owned_request_budget();
    let base = tokio::time::Instant::now();
    let mut active = Vec::new();
    for _ in 0..8 {
        let (sender, mut receiver) = oneshot::channel();
        actor.owned_admission_until(
            target(1),
            sender,
            base + Duration::from_secs(30),
            budget.acquire().unwrap(),
        );
        let crate::resource::RequestReply::Ready(result) =
            receiver.try_recv().expect("active admission")
        else {
            panic!("admission rejected");
        };
        active.push(result);
    }
    let before = actor.socket.owned_test_state().unwrap();
    assert_eq!(before.2, 1, "coalesced target uses one RPC");
    assert_eq!(before.0, 1, "coalesced target emitted one datagram");
    let (sender, mut expired) = oneshot::channel();
    actor.owned_admission_until(
        target(2),
        sender,
        base + Duration::from_secs(5),
        budget.acquire().unwrap(),
    );
    let (sender, mut promoted) = oneshot::channel();
    actor.owned_admission_until(
        target(3),
        sender,
        base + Duration::from_secs(10),
        budget.acquire().unwrap(),
    );
    assert!(matches!(
        expired.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        promoted.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target(2)));
    assert!(!actor.core.iterative_queries.contains_key(&target(3)));

    drop(active.remove(0));
    actor.maintain_owned_admissions_at(base + Duration::from_secs(6));
    assert!(matches!(
        expired.try_recv(),
        Ok(crate::resource::RequestReply::Error(
            ResourceError::DeadlineExceeded
        ))
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target(2)));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target(2))
    );
    let Ok(crate::resource::RequestReply::Ready(mut promoted_result)) = promoted.try_recv() else {
        panic!("promoted admission");
    };
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target(3)];
    assert!(actor.core.iterative_queries.contains_key(&target(3)));
    let after = actor.socket.owned_test_state().unwrap();
    assert_eq!(after.2, before.2 + 1, "only promoted target opened an RPC");
    assert_eq!(
        after.0,
        before.0 + 1,
        "expired queued target emitted no datagram"
    );

    actor.maintain_owned_admissions_at(base + Duration::from_secs(10));
    assert!(matches!(
        promoted_result.try_recv(),
        Ok(Err(ResourceError::DeadlineExceeded))
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target(3)));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target(3))
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert!(actor.core.iterative_queries.contains_key(&target(1)));
    drop(active);
}

#[tokio::test]
async fn delivered_error_receivers_retain_result_charges_until_dropped() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = actor.owned_request_budget();
    let base = tokio::time::Instant::now();
    let mut errors = Vec::new();
    for _ in 0..8 {
        let (sender, mut admission) = oneshot::channel();
        actor.owned_admission_until(
            target(1),
            sender,
            base + Duration::from_secs(5),
            budget.acquire().expect("request permit"),
        );
        let crate::resource::RequestReply::Ready(result) =
            admission.try_recv().expect("admission delivered")
        else {
            panic!("admission rejected");
        };
        errors.push(result);
    }
    actor.maintain_owned_admissions_at(base + Duration::from_secs(6));
    assert!(!actor.core.iterative_queries.contains_key(&target(1)));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&target(1))
    );

    let (sender, mut ninth) = oneshot::channel();
    actor.owned_admission_until(
        target(20),
        sender,
        base + Duration::from_secs(30),
        budget.acquire().expect("request permit"),
    );
    assert!(
        matches!(ninth.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "ninth admission is queued, not admitted"
    );
    assert!(!actor.core.iterative_queries.contains_key(&target(20)));
    drop(errors.pop().expect("actual error receiver"));
    actor.maintain_owned_admissions_at(base + Duration::from_secs(6));
    let Ok(crate::resource::RequestReply::Ready(mut ninth_result)) = ninth.try_recv() else {
        panic!("ninth admission promoted");
    };
    assert!(actor.core.iterative_queries.contains_key(&target(20)));

    let (sender, mut tenth) = oneshot::channel();
    actor.owned_admission_until(
        target(21),
        sender,
        base + Duration::from_secs(30),
        budget.acquire().expect("request permit"),
    );
    assert!(matches!(
        tenth.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(!actor.core.iterative_queries.contains_key(&target(21)));
    for receiver in &mut errors {
        assert!(matches!(
            receiver.try_recv(),
            Ok(Err(ResourceError::DeadlineExceeded))
        ));
    }
    drop(errors);
    actor.maintain_owned_admissions_at(base + Duration::from_secs(6));
    let Ok(crate::resource::RequestReply::Ready(_tenth_result)) = tenth.try_recv() else {
        panic!("tenth admission promoted");
    };
    assert!(actor.core.iterative_queries.contains_key(&target(21)));
    assert!(matches!(
        ninth_result.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn terminal_failure_keeps_delivered_error_receivers_charged() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let request_budget = actor.owned_request_budget();
    let result_budget = actor.owned_result_budget();
    let mut receivers = Vec::new();
    for _ in 0..8 {
        let (sender, mut admission) = oneshot::channel();
        actor.owned_admission_until(
            target(22),
            sender,
            tokio::time::Instant::now() + Duration::from_secs(30),
            request_budget.acquire().expect("request permit"),
        );
        let crate::resource::RequestReply::Ready(receiver) =
            admission.try_recv().expect("admission delivered")
        else {
            panic!("admission rejected");
        };
        receivers.push(receiver);
    }
    actor.owned_fail(ResourceError::Send);
    assert!(actor.core.iterative_queries.is_empty());
    assert_eq!(actor.socket.owned_test_state().unwrap().2, 0);
    assert!(
        result_budget.acquire().is_none(),
        "undrained terminal errors retain all eight charges"
    );

    drop(receivers.pop().expect("one actual charged receiver"));
    let released = result_budget
        .acquire()
        .expect("dropping one receiver releases its result charge");
    assert!(result_budget.acquire().is_none());
    for receiver in &mut receivers {
        assert!(matches!(receiver.try_recv(), Ok(Err(ResourceError::Send))));
    }
    assert!(
        result_budget.acquire().is_none(),
        "draining errors alone does not release receiver charges"
    );
    drop(receivers);
    let mut permits = Vec::new();
    for _ in 0..7 {
        permits.push(
            result_budget
                .acquire()
                .expect("dropping error receivers releases retained charges"),
        );
    }
    assert!(
        result_budget.acquire().is_none(),
        "retained released permit accounts for the final charge"
    );
    drop(permits);
    drop(released);
}

#[tokio::test]
async fn cancelled_admission_keeps_request_and_result_charges_until_tick_cleanup() {
    let (_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    actor.owned_disable_maintenance_for_test = true;
    let request_budget = actor.owned_request_budget();
    let result_budget = actor.owned_result_budget();
    let admitted_target = target(30);
    let (sender, receiver) = oneshot::channel();
    actor.owned_admission_until(
        admitted_target,
        sender,
        tokio::time::Instant::now() + Duration::from_secs(30),
        request_budget.acquire().expect("request permit"),
    );
    let crate::resource::RequestReply::Ready(admitted) =
        receiver.await.expect("admission delivered")
    else {
        panic!("admission rejected");
    };
    let operation = actor.owned_resources.as_ref().unwrap().operations[&admitted_target];
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);

    drop(admitted);
    assert!(actor.core.iterative_queries.contains_key(&admitted_target));
    assert!(
        actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&admitted_target)
    );
    let observer = actor.owned_publication_observer();
    assert!(
        !observer.has_retired_query(admitted_target),
        "target receipt must not precede the actual query/lease teardown"
    );
    let mut held_requests = Vec::new();
    while let Some(permit) = request_budget.acquire() {
        held_requests.push(permit);
    }
    assert_eq!(held_requests.len(), 23, "cancelled caller request charge stays held");
    let mut held_results = Vec::new();
    while let Some(lease) = result_budget.acquire() {
        held_results.push(lease);
    }
    assert_eq!(held_results.len(), 7, "cancelled caller result charge stays held");

    actor.tick_owned();
    assert!(!actor.core.iterative_queries.contains_key(&admitted_target));
    assert!(
        !actor
            .owned_resources
            .as_ref()
            .unwrap()
            .operations
            .contains_key(&admitted_target)
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert!(
        observer.has_retired_query(admitted_target),
        "target receipt recorded only after transaction/query/lease teardown"
    );

    drop(held_requests);
    drop(held_results);
    let mut restored_requests = Vec::new();
    while let Some(permit) = request_budget.acquire() {
        restored_requests.push(permit);
    }
    assert_eq!(restored_requests.len(), 24, "request capacity restored at cleanup");
    let mut restored_results = Vec::new();
    while let Some(lease) = result_budget.acquire() {
        restored_results.push(lease);
    }
    assert_eq!(restored_results.len(), 8, "result capacity restored at cleanup");
}
