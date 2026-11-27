// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::fmt::Debug;

use super::*;

/// The `Owned put wait` lines (leaf PACE-STALL) printed since the last call. They are read from
/// the log the actor keeps next to the trace, not captured from `tracing`: a thread-local
/// subscriber loses its events when a parallel case without one is the first to hit the callsite
/// (the interest cache is global).
fn waits(actor: &mut Actor) -> Vec<String> {
    std::mem::take(&mut actor.owned_resources.as_mut().expect("owned profile").put_wait_log)
}

/// Failure-only diagnostics of a case: the notes it took are printed as one tagged line when the
/// case panics and never otherwise (a green run prints nothing, which the CI output check also
/// enforces). The clock is the real one; the put's own age is a parameter of each step.
struct Notes {
    started: std::time::Instant,
    lines: Vec<String>,
}

impl Notes {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            lines: Vec::new(),
        }
    }

    fn note(&mut self, label: &str, value: &dyn Debug) {
        self.lines.push(format!(
            "{{\"real_ms\":{},\"label\":{label:?},\"value\":{:?}}}",
            self.started.elapsed().as_millis(),
            format!("{value:?}")
        ));
    }

    fn render(&self, test: &str) -> String {
        format!(
            "[failure diagnostics] {{\"test\":{test:?},\"notes\":[{}]}}",
            self.lines.join(",")
        )
    }
}

impl Drop for Notes {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let thread = std::thread::current();
            eprintln!("{}", self.render(thread.name().unwrap_or("?")));
        }
    }
}

#[test]
fn the_failure_report_of_a_put_case_lists_the_notes_in_order_and_names_the_case() {
    let mut notes = Notes::new();
    notes.note("first", &(1_usize, 2_usize));
    notes.note("second", &Some("two words"));
    let report = notes.render("case");
    assert!(report.starts_with("[failure diagnostics] {\"test\":\"case\",\"notes\":[{"));
    assert!(report.contains("\"label\":\"first\",\"value\":\"(1, 2)\""));
    assert!(report.find("\"first\"").unwrap() < report.find("\"second\"").unwrap());
    assert!(report.contains("\"real_ms\":"));
    assert!(report.ends_with("}]}"));
}

#[tokio::test]
async fn a_put_that_stays_unresolved_prints_a_wait_line_at_ten_and_at_twenty_seconds() {
    let mut notes = Notes::new();
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    actor.owned_disable_maintenance_for_test = true;
    let now = tokio::time::Instant::now();
    let item = crate::common::MutableItem::new(
        &ed25519_dalek::SigningKey::from_bytes(&[0xA9; 32]),
        b"put wait",
        1,
        None,
    );
    let target = *item.target();
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, _cleanup_rx) = oneshot::channel();
    let (cancel, cancel_rx) = oneshot::channel();
    let lease = actor.owned_request_budget().acquire().expect("request lease");
    let deadline = now + Duration::from_secs(300);
    actor.owned_put_admission_until(target, item, reply, cleanup, cancel_rx, deadline, lease);
    actor.maintain_owned_puts_at(now);
    let _result = reply_rx.try_recv().expect("PUT admitted").expect("no admission error");
    let peers: Vec<_> = (0..6).map(|_| captured_peer()).collect();
    let nodes: Vec<Node> = peers
        .iter()
        .enumerate()
        .map(|(index, (_, address))| {
            Node::new_with_token(
                Id::from([0x50 + index as u8; 20]),
                *address,
                vec![7, 8].into_boxed_slice(),
            )
        })
        .collect();
    // With the pacing engaged only a burst of the requests leaves; the rest stays in the outbox.
    actor.socket.collapse_owned_pacing_for_test();
    actor
        .core
        .put_queries
        .get_mut(&target)
        .expect("pending PUT")
        .start(&mut actor.socket, &nodes)
        .expect("start the PUT");
    actor.socket.flush_owned().await;
    let tids = actor.core.put_queries[&target].transaction_ids().to_vec();
    let (inflight, queued, rpc) = actor.socket.owned_request_state(&tids);
    notes.note("inflight, queued, rpc after the flush", &(inflight, queued, rpc));
    notes.note("state of the socket", &actor.socket.owned_test_state());
    assert_eq!(inflight + queued, 6);
    assert!(inflight > 0 && queued > 0, "{inflight} left, {queued} queued");

    actor.maintain_owned_puts_at(now + Duration::from_millis(9_999));
    let before = waits(&mut actor);
    notes.note("lines at 9.999 s", &before);
    assert!(before.is_empty(), "nothing before ten seconds");
    actor.maintain_owned_puts_at(now + Duration::from_secs(10));
    let at_ten = waits(&mut actor);
    notes.note("lines at 10 s", &at_ten);
    assert_eq!(
        at_ten,
        [format!("age_ms=10000 inflight={inflight} queued={queued} attempts=1 rpc={rpc}")]
    );
    actor.maintain_owned_puts_at(now + Duration::from_secs(15));
    assert!(waits(&mut actor).is_empty(), "one line per step");
    actor.maintain_owned_puts_at(now + Duration::from_secs(20));
    let at_twenty = waits(&mut actor);
    notes.note("lines at 20 s", &at_twenty);
    assert_eq!(
        at_twenty,
        [format!("age_ms=20000 inflight={inflight} queued={queued} attempts=1 rpc={rpc}")]
    );
    actor.maintain_owned_puts_at(now + Duration::from_secs(120));
    assert!(waits(&mut actor).is_empty(), "never a third line");
    let active = actor.owned_resources.as_ref().unwrap().active_put_len();
    notes.note("active puts at the end", &active);
    assert_eq!(active, 1);
    drop((cancel, peers));
}

#[tokio::test]
async fn a_put_that_ends_before_ten_seconds_prints_no_wait_line() {
    let mut notes = Notes::new();
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    actor.owned_disable_maintenance_for_test = true;
    let now = tokio::time::Instant::now();
    let item = crate::common::MutableItem::new(
        &ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]),
        b"short put",
        1,
        None,
    );
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, _cleanup_rx) = oneshot::channel();
    let (cancel, cancel_rx) = oneshot::channel();
    let lease = actor.owned_request_budget().acquire().expect("request lease");
    let deadline = now + Duration::from_secs(300);
    actor.owned_put_admission_until(*item.target(), item, reply, cleanup, cancel_rx, deadline, lease);
    actor.maintain_owned_puts_at(now);
    let _result = reply_rx.try_recv().expect("PUT admitted").expect("no admission error");
    cancel.send(()).expect("request cancellation");
    actor.maintain_owned_puts_at(now + Duration::from_secs(1));
    let active = actor.owned_resources.as_ref().unwrap().active_put_len();
    notes.note("active puts one second after the cancellation", &active);
    assert_eq!(active, 0);
    actor.maintain_owned_puts_at(now + Duration::from_secs(10));
    actor.maintain_owned_puts_at(now + Duration::from_secs(20));
    let lines = waits(&mut actor);
    notes.note("lines after twenty seconds", &lines);
    assert!(lines.is_empty());
}

#[tokio::test]
async fn held_put_keeps_operation_charge_after_shared_get_deadline() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    actor.owned_disable_maintenance_for_test = true;
    let now = tokio::time::Instant::now();
    let deadline = now + std::time::Duration::from_secs(5);
    let put_deadline = now + std::time::Duration::from_secs(10);
    let item = crate::common::MutableItem::new(
        &ed25519_dalek::SigningKey::from_bytes(&[0xA8; 32]),
        b"held shared get",
        1,
        None,
    );
    let target = *item.target();
    let (get_sender, mut get_receiver) = oneshot::channel();
    actor.owned_mutable_until(target, get_sender, deadline).expect("actual owned GET admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let observer = actor.owned_publication_observer();
    let hold = observer.hold_cleanup_for_target(target).expect("hold acquired");
    let (reply, mut reply_rx) = oneshot::channel();
    let (cleanup, mut cleanup_rx) = oneshot::channel();
    let (cancel, cancel_rx) = oneshot::channel();
    let lease = actor.owned_request_budget().acquire().expect("actual request lease");
    actor.owned_put_admission_until(target, item, reply, cleanup, cancel_rx, put_deadline, lease);
    actor.maintain_owned_puts_at(now);
    let charged_operation = reply_rx.try_recv().expect("PUT admitted").expect("no admission error");
    cancel.send(()).expect("request cancellation");
    actor.maintain_owned_puts_at(now);
    assert_eq!(cleanup_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty));
    assert_eq!(actor.owned_resources.as_ref().unwrap().active_put_len(), 1);

    actor.expire_owned_operations_at(deadline);
    assert!(matches!(get_receiver.try_recv(), Ok(Err(ResourceError::DeadlineExceeded))));
    assert_eq!(actor.owned_resources.as_ref().unwrap().active_put_len(), 1);
    assert_eq!(actor.owned_resources.as_ref().unwrap().operations.get(&target), Some(&operation));
    assert_eq!(actor.socket.owned_put_deadline_for_test(target), Some(put_deadline));

    hold.release();
    actor.maintain_owned_puts_at(deadline);
    assert!(matches!(
        charged_operation.await,
        Ok(Err(crate::resource::OwnedPutError::Resource(ResourceError::DeadlineExceeded)))
    ));
    assert_eq!(cleanup_rx.try_recv(), Ok(()));
    assert_eq!(actor.owned_resources.as_ref().unwrap().active_put_len(), 0);
    assert!(!actor.owned_resources.as_ref().unwrap().operations.contains_key(&target));
    assert_eq!(actor.socket.owned_put_deadline_for_test(target), None);
}

#[tokio::test]
async fn failed_put_reservation_rolls_back_new_operation_and_preserves_coalesced_get() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let target = *put_request().target();
    let (sender, mut receiver) = oneshot::channel();
    actor
        .owned_mutable(target, sender)
        .expect("live GET operation admitted");
    let operation = actor.owned_resources.as_ref().unwrap().operations[&target];
    let extras: Box<[Node]> = (0..256).map(token_node).collect();
    let result = actor.owned_put(put_request(), Some(extras));
    assert!(matches!(
        result,
        Err(crate::core::put_query::PutError::Query(
            crate::core::put_query::PutQueryError::Resource(ResourceError::CandidateLimit)
        ))
    ));
    assert!(actor.core.iterative_queries.contains_key(&target));
    assert!(!actor.core.put_queries.contains_key(&target));
    assert_eq!(
        actor.owned_resources.as_ref().unwrap().operations[&target],
        operation
    );
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    assert_eq!(budget.holder_count(), 1);
    assert_eq!(budget.visited_count(), 1);
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn owned_put_duplicate_entries_retain_holders_but_visit_and_send_once() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket-owned operation");
    let duplicate = token_node(1);
    let mut put = PutQuery::new_owned(
        put_request(),
        Some(vec![duplicate.clone(), duplicate.clone()].into_boxed_slice()),
        operation,
        Arc::clone(&budget),
    )
    .expect("actual owned PutQuery retains duplicate entries");
    assert_eq!(budget.holder_count(), 3);
    put.start(&mut actor.socket, &[duplicate])
        .expect("nonempty closest nodes");
    assert_eq!(budget.visited_count(), 1);
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    actor
        .socket
        .cancel_owned_transactions(&put.transaction_ids().to_vec());
    drop(put);
    assert_eq!(budget.visited_count(), 0);
    assert_eq!(budget.holder_count(), 1);
}

#[tokio::test]
async fn owned_put_reaches_only_the_nodes_the_per_operation_rpc_cap_allows() {
    // Live finding (2026-11-17): a store phase offers 20 or more closest nodes, more than the 16
    // RPCs one operation may hold; it must store at what fits instead of failing with RpcLimit.
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket operation");
    let extras: Box<[Node]> = (0..17).map(token_node).collect();
    let closest = token_node(100);
    let mut put = PutQuery::new_owned(put_request(), Some(extras), operation, Arc::clone(&budget))
        .expect("actual retained candidate holders");
    put.start(&mut actor.socket, &[closest])
        .expect("a store that reached 16 nodes is not a failure");
    assert_eq!(put.transaction_ids().len(), 16);
    assert_eq!(actor.socket.operation_rpc_len(operation), 16);
    actor
        .socket
        .cancel_owned_transactions(&put.transaction_ids().to_vec());
    drop(put);
    assert_eq!(budget.visited_count(), 0);
    assert_eq!(actor.socket.operation_rpc_len(operation), 0);
    assert_eq!(budget.holder_count(), 1);
}

#[tokio::test]
async fn owned_put_without_any_rpc_room_still_fails_with_the_typed_error() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual socket operation");
    for port in 0..16_u16 {
        actor
            .socket
            .request_owned(
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10100 + port),
                crate::common::RequestSpecific {
                    requester_id: Id::random(),
                    request_type: crate::common::RequestTypeSpecific::Ping,
                },
                operation,
            )
            .expect("RPC room for the operation");
    }
    assert_eq!(actor.socket.owned_rpc_room(operation), 0);
    let mut put = PutQuery::new_owned(put_request(), None, operation, Arc::clone(&budget))
        .expect("actual owned PUT store");
    let result = put.start(&mut actor.socket, &[token_node(100)]);
    assert!(matches!(
        result,
        Err(crate::core::put_query::PutError::Query(
            crate::core::put_query::PutQueryError::Resource(ResourceError::RpcLimit)
        ))
    ));
    assert_eq!(put.transaction_ids().len(), 0);
    actor.socket.cancel_owned_operation(operation);
    drop(put);
    assert_eq!(budget.visited_count(), 0);
}

#[tokio::test]
async fn put_cleanup_removes_only_its_transaction_ids_on_a_shared_operation() {
    let (_bootstrap_peer, bootstrap) = captured_peer();
    let mut actor = actor(bootstrap);
    let budget = Arc::clone(&actor.owned_resources.as_ref().unwrap().budget);
    let operation = actor
        .socket
        .allocate_operation()
        .expect("actual shared operation");
    let mut put = PutQuery::new_owned(
        put_request(),
        Some(vec![token_node(1), token_node(2)].into_boxed_slice()),
        operation,
        Arc::clone(&budget),
    )
    .expect("actual owned PUT store");
    put.start(&mut actor.socket, &[token_node(3)])
        .expect("nonempty closest nodes");
    let unrelated_tid = actor
        .socket
        .request_owned(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10001),
            crate::common::RequestSpecific {
                requester_id: Id::random(),
                request_type: crate::common::RequestTypeSpecific::Ping,
            },
            operation,
        )
        .expect("unrelated RPC shares operation allowance");
    actor
        .socket
        .cancel_owned_transactions(&put.transaction_ids().to_vec());
    assert!(actor.socket.owned_inflight(unrelated_tid));
    assert_eq!(actor.socket.operation_rpc_len(operation), 1);
    actor.socket.cancel_owned_operation(operation);
    drop(put);
    assert_eq!(budget.visited_count(), 0);
    assert_eq!(budget.holder_count(), 1);
}
