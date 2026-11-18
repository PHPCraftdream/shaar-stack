// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use crate::actor::socket::KrpcSocket;
use crate::common::{GetValueRequestArguments, Id, MutableItem, Node};
use crate::core::Response;
use crate::core::iterative_query::{GetRequestSpecific, IterativeQuery};
use crate::resource::{ResourceError, StoreBudget};

fn mutable_response(seq: i64, length: usize, salt: Option<Box<[u8]>>) -> Response {
    let value = vec![0x5a; length];
    let item =
        MutableItem::new_signed_unchecked([0x11; 32], [0x22; 64], &value, seq, salt.as_deref());
    Response::Mutable(item)
}

#[tokio::test]
async fn owned_query_caps_actual_mutable_responses_and_records_logical_byte_bound() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let from = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    for seq in 0..32 {
        query.response(from, mutable_response(seq, 1000, None));
    }
    assert_eq!(query.responses().len(), 32);
    assert_eq!(query.owner_error(), None);
    assert_eq!(
        query
            .responses()
            .iter()
            .map(|response| match response {
                Response::Mutable(item) => item.value().len() + 104,
                _ => 0,
            })
            .sum::<usize>(),
        35328
    );

    query.response(from, mutable_response(32, 1000, None));
    assert_eq!(query.responses().len(), 32);
    assert_eq!(query.owner_error(), Some(ResourceError::ResultLimit));
    assert!(query.is_done(&socket));
}

#[tokio::test]
async fn owned_query_rejects_oversize_and_salted_mutable_results() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut oversize = query(&mut socket, &budget);
    oversize.response(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
        mutable_response(1, 1001, None),
    );
    assert_eq!(oversize.responses().len(), 0);
    assert_eq!(oversize.owner_error(), Some(ResourceError::ResultLimit));

    let mut salted = query(&mut socket, &budget);
    salted.response(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2),
        mutable_response(1, 1000, Some(vec![7].into_boxed_slice())),
    );
    assert_eq!(salted.responses().len(), 0);
    assert_eq!(salted.owner_error(), Some(ResourceError::ResultLimit));
}

#[tokio::test]
async fn legacy_unowned_query_keeps_mutable_response_behavior() {
    let mut query = IterativeQuery::new(
        Id::from([0_u8; 20]),
        Id::from([1_u8; 20]),
        GetRequestSpecific::GetValue(GetValueRequestArguments {
            target: Id::from([1_u8; 20]),
            seq: None,
            salt: None,
        }),
    );
    let from = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3);
    for seq in 0..33 {
        query.response(from, mutable_response(seq, 1000, None));
    }
    assert_eq!(query.responses().len(), 33);
    assert_eq!(query.owner_error(), None);
}

fn candidate(index: usize) -> Node {
    let mut bytes = [0_u8; 20];
    bytes[0] = (index / 128) as u8;
    bytes[19] = index as u8;
    Node::new(
        Id::from(bytes),
        SocketAddrV4::new(
            Ipv4Addr::new(
                10,
                ((index >> 16) & 255) as u8,
                ((index >> 8) & 255) as u8,
                (index & 255) as u8,
            ),
            (index as u16).wrapping_add(1),
        ),
    )
}

fn query(socket: &mut KrpcSocket, budget: &Arc<StoreBudget>) -> IterativeQuery {
    let mut query = IterativeQuery::new(
        Id::from([0_u8; 20]),
        Id::from([1_u8; 20]),
        GetRequestSpecific::GetValue(GetValueRequestArguments {
            target: Id::from([1_u8; 20]),
            seq: None,
            salt: None,
        }),
    );
    let operation = socket.allocate_operation().expect("operation");
    socket
        .register_owned_deadline(
            operation,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .expect("register default operation deadline");
    query.enable_owned(operation, Arc::clone(budget));
    query
}

fn owned_socket() -> KrpcSocket {
    let mut socket = KrpcSocket::client().expect("KRPC test socket");
    socket.enable_owned_resources();
    socket
}

/// Receives the request a visit sent to `capture` and answers it through the socket.
async fn answer_request(
    socket: &mut KrpcSocket,
    capture: &tokio::net::UdpSocket,
    from: SocketAddrV4,
) {
    let mut buffer = [0_u8; 4096];
    socket.flush_owned().await;
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), capture.recv_from(&mut buffer))
        .await
        .expect("request timeout")
        .expect("receive request");
    let request = crate::common::Message::from_bytes(&buffer[..length]).expect("decode request");
    assert!(socket.accept_owned_response(request.transaction_id, from));
}

#[tokio::test]
async fn real_owned_get_runs_at_most_the_round_cap_then_finishes() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let operation = query.operation().expect("owned operation");
    let deadline = socket
        .owned_deadline(operation)
        .expect("registered operation deadline");
    let cap = usize::from(socket.owned_get_round_cap());
    assert_eq!(cap, 6);

    let mut captures = Vec::new();
    for _ in 0..=cap {
        captures.push(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("loopback peer"),
        );
    }
    let destinations: Vec<SocketAddrV4> = captures
        .iter()
        .map(
            |capture| match capture.local_addr().expect("peer address") {
                std::net::SocketAddr::V4(address) => address,
                std::net::SocketAddr::V6(_) => unreachable!("IPv4 peer"),
            },
        )
        .collect();

    query.visit(&mut socket, destinations[0]);
    answer_request(&mut socket, &captures[0], destinations[0]).await;
    assert_eq!(socket.owned_get_rounds(operation), 1);

    let base = tokio::time::Instant::now();
    for round in 1..cap {
        query.add_candidate(Node::new(
            Id::from([round as u8 + 1; 20]),
            destinations[round],
        ));
        let scheduled = base + Duration::from_secs(round as u64);
        query.visit_closest_at(&mut socket, scheduled);
        if let Some(next) = query.owned_next_round() {
            assert!(next <= scheduled + Duration::from_millis(200));
        }
        query.visit_closest_at(&mut socket, scheduled + Duration::from_millis(200));
        answer_request(&mut socket, &captures[round], destinations[round]).await;
        assert_eq!(usize::from(socket.owned_get_rounds(operation)), round + 1);
    }

    query.add_candidate(Node::new(Id::from([cap as u8 + 1; 20]), destinations[cap]));
    query.visit_closest_at(&mut socket, base + Duration::from_secs(cap as u64));
    assert_eq!(query.owner_error(), None);
    assert!(query.is_done(&socket));
    assert_eq!(usize::from(socket.owned_get_rounds(operation)), cap);
    assert_eq!(socket.owned_test_state().unwrap().2, 0);
    assert_eq!(socket.owned_deadline(operation), Some(deadline));
    let mut buffer = [0_u8; 4096];
    assert_eq!(
        captures[cap].try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn owned_get_deadline_stops_next_round_before_emitting_request() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let operation = query.operation().expect("owned operation");
    let deadline = tokio::time::Instant::now();
    socket
        .register_owned_deadline(operation, deadline)
        .expect("register expired deadline");
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
    query.add_candidate(Node::new(Id::from([9_u8; 20]), destination));
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    tracing::subscriber::with_default(EventCapture(Arc::clone(&lines)), || {
        query.visit_closest_at(&mut socket, deadline);
    });
    let lines = lines.lock().unwrap();
    assert!(lines.iter().any(|line| line.starts_with("Owned GET deadline")
        && line.contains(" round=0") && line.contains(" candidates=1")
        && line.contains(" inflight=0")), "{lines:?}");
    assert_eq!(query.owner_error(), Some(ResourceError::DeadlineExceeded));
    assert_eq!(socket.owned_test_state().unwrap().2, 0);
    assert!(query.is_done(&socket));
}

/// Leaf FIX-3c: an admitted owned round is traced with its candidate count and RPC room.
#[tokio::test]
async fn an_admitted_owned_round_is_traced_with_its_candidates_and_room() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);
    query.add_candidate(Node::new(Id::from([2_u8; 20]), destination));
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    tracing::subscriber::with_default(EventCapture(Arc::clone(&lines)), || {
        query.visit_closest_at(&mut socket, tokio::time::Instant::now());
    });
    let lines = lines.lock().unwrap();
    assert!(lines.iter().any(|line| line.starts_with("Owned GET round")
        && line.contains(" round=1") && line.contains(" candidates=1")
        && line.contains(" room=") && line.contains(" timeout_ms=500")), "{lines:?}");
}

#[tokio::test]
async fn owned_get_retry_jitter_zero_and_cap_schedule_actual_requests_at_due_time() {
    for sample in [0_u8, 100_u8] {
        let budget = Arc::new(StoreBudget::default());
        let mut socket = owned_socket();
        let mut query = query(&mut socket, &budget);
        let operation = query.operation().unwrap();
        let base = tokio::time::Instant::now();
        let deadline = base + Duration::from_secs(2);
        socket.register_owned_deadline(operation, deadline).unwrap();
        let peers = [
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        ];
        let addresses: Vec<SocketAddrV4> = peers
            .iter()
            .map(|peer| match peer.local_addr().unwrap() {
                std::net::SocketAddr::V4(address) => address,
                std::net::SocketAddr::V6(_) => unreachable!("IPv4 peer"),
            })
            .collect();
        let mut buffer = [0_u8; 4096];
        query.visit(&mut socket, addresses[0]);
        socket.flush_owned().await;
        let (length, _) = peers[0].recv_from(&mut buffer).await.unwrap();
        let first = crate::common::Message::from_bytes(&buffer[..length]).unwrap();
        assert!(socket.accept_owned_response(first.transaction_id, addresses[0]));

        query.add_candidate(Node::new(Id::from([sample + 1; 20]), addresses[1]));
        query.set_owned_next_jitter(sample);
        query.visit_closest_at(&mut socket, base);
        if sample == 0 {
            assert_eq!(query.owned_next_round(), None);
        } else {
            let due = base + Duration::from_millis(100);
            assert_eq!(query.owned_next_round(), Some(due));
            query.visit_closest_at(&mut socket, due - Duration::from_millis(1));
            socket.flush_owned().await;
            assert_eq!(
                peers[1].try_recv_from(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            query.visit_closest_at(&mut socket, due);
        }
        socket.flush_owned().await;
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), peers[1].recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let second = crate::common::Message::from_bytes(&buffer[..length]).unwrap();
        assert!(socket.accept_owned_response(second.transaction_id, addresses[1]));

        query.add_candidate(Node::new(Id::from([sample + 2; 20]), addresses[2]));
        query.set_owned_next_jitter(200);
        let third_origin = base + Duration::from_millis(300);
        query.visit_closest_at(&mut socket, third_origin);
        let third_due = third_origin + Duration::from_millis(200);
        assert_eq!(query.owned_next_round(), Some(third_due));
        query.visit_closest_at(&mut socket, third_due - Duration::from_millis(1));
        socket.flush_owned().await;
        assert_eq!(
            peers[2].try_recv_from(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        query.visit_closest_at(&mut socket, third_due);
        socket.flush_owned().await;
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), peers[2].recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        let third = crate::common::Message::from_bytes(&buffer[..length]).unwrap();
        assert!(socket.accept_owned_response(third.transaction_id, addresses[2]));
        assert_eq!(socket.owned_deadline(operation), Some(deadline));
    }
}

#[tokio::test]
async fn owned_get_deadline_during_scheduled_retry_emits_no_rpc() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let operation = query.operation().unwrap();
    let initial_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    socket
        .register_owned_deadline(operation, initial_deadline)
        .unwrap();
    let (peer, address) = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map(|peer| {
            let address = match peer.local_addr().unwrap() {
                std::net::SocketAddr::V4(address) => address,
                _ => unreachable!("IPv4 peer"),
            };
            (peer, address)
        })
        .unwrap();
    let (retry_peer, retry_address) = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map(|peer| {
            let address = match peer.local_addr().unwrap() {
                std::net::SocketAddr::V4(address) => address,
                _ => unreachable!("IPv4 peer"),
            };
            (peer, address)
        })
        .unwrap();
    query.visit(&mut socket, address);
    socket.flush_owned().await;
    let mut buf = [0; 4096];
    let (len, _) = peer.recv_from(&mut buf).await.unwrap();
    let message = crate::common::Message::from_bytes(&buf[..len]).unwrap();
    assert!(socket.accept_owned_response(message.transaction_id, address));

    let base = tokio::time::Instant::now();
    let deadline = base + Duration::from_millis(50);
    socket.register_owned_deadline(operation, deadline).unwrap();
    query.set_owned_next_jitter(100);
    query.add_candidate(Node::new(Id::from([8; 20]), retry_address));
    query.visit_closest_at(&mut socket, base);
    assert_eq!(
        query.owned_next_round(),
        Some(base + Duration::from_millis(100))
    );
    query.visit_closest_at(&mut socket, deadline);
    assert_eq!(query.owner_error(), Some(ResourceError::DeadlineExceeded));
    assert!(query.is_done(&socket));
    assert_eq!(socket.owned_test_state().unwrap().2, 0);
    assert_eq!(
        retry_peer.try_recv_from(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn take_owned_responses_moves_the_original_response_allocations() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let from = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    for seq in 0..32 {
        query.response(from, mutable_response(seq, 1000, None));
    }
    let pointers: Vec<*const u8> = query
        .responses()
        .iter()
        .map(|response| match response {
            Response::Mutable(item) => item.value().as_ptr(),
            _ => unreachable!("owned responses are mutable"),
        })
        .collect();
    let taken = query.take_owned_responses();
    assert!(query.responses().is_empty());
    assert_eq!(
        taken
            .iter()
            .map(|response| match response {
                Response::Mutable(item) => item.value().as_ptr(),
                _ => unreachable!("owned responses are mutable"),
            })
            .collect::<Vec<_>>(),
        pointers
    );
    assert_eq!(
        taken
            .iter()
            .map(|response| match response {
                Response::Mutable(item) => item.value().len() + 104,
                _ => 0,
            })
            .sum::<usize>(),
        35328
    );
    drop(query);
    assert_eq!(
        taken
            .iter()
            .map(|response| match response {
                Response::Mutable(item) => item.value().as_ptr(),
                _ => unreachable!("owned responses are mutable"),
            })
            .collect::<Vec<_>>(),
        pointers
    );
}

#[tokio::test]
async fn real_queries_share_candidate_budget_and_drop_releases_leases() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut first = query(&mut socket, &budget);
    let mut second = query(&mut socket, &budget);
    // Other holders leave room for 30 candidates: 20 for the first query, 10 for the second.
    let mut external = Vec::new();
    while budget.holder_count() < 226 {
        external.push(budget.reserve_holder().expect("external holder"));
    }
    for index in 0..128 {
        first.add_candidate(candidate(index));
    }
    assert_eq!(first.closest().len(), 20, "a query keeps its closest 20");
    assert_eq!(first.owner_error(), None);
    for index in 128..256 {
        second.add_candidate(candidate(index));
    }
    assert_eq!(second.closest().len(), 10);
    assert_eq!(second.owner_error(), Some(ResourceError::CandidateLimit));
    assert!(second.is_done(&socket));
    drop(first);
    let mut replacement = query(&mut socket, &budget);
    replacement.add_candidate(candidate(256));
    assert_eq!(replacement.closest().len(), 1);
    assert_eq!(replacement.owner_error(), None);
}

#[tokio::test]
async fn eight_real_queries_share_visited_budget_across_bounded_rpc_batches() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut queries = Vec::new();
    for _ in 0..8 {
        queries.push(query(&mut socket, &budget));
    }
    let mut captures = Vec::new();
    for _ in 0..257 {
        captures.push(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("loopback peer"),
        );
    }
    let destinations: Vec<SocketAddrV4> = captures
        .iter()
        .map(
            |capture| match capture.local_addr().expect("peer address") {
                std::net::SocketAddr::V4(address) => address,
                std::net::SocketAddr::V6(_) => unreachable!("IPv4 peer"),
            },
        )
        .collect();
    let mut buffer = [0_u8; 4096];

    for round in 0..2 {
        for (query_index, query) in queries.iter_mut().enumerate() {
            let start = query_index * 32 + round * 16;
            for address in destinations[start..start + 16].iter().copied() {
                query.visit(&mut socket, address);
            }
        }
        socket.flush_owned().await;
        for query_index in 0..8 {
            let start = query_index * 32 + round * 16;
            for offset in 0..16 {
                let destination = destinations[start + offset];
                let (length, source) = tokio::time::timeout(
                    Duration::from_secs(2),
                    captures[start + offset].recv_from(&mut buffer),
                )
                .await
                .expect("request receipt timeout")
                .expect("receive request");
                let message = crate::common::Message::from_bytes(&buffer[..length])
                    .expect("decode outgoing request");
                let tid = message.transaction_id;
                assert_eq!(
                    source,
                    std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::LOCALHOST,
                        socket.local_addr().port()
                    ))
                );
                assert!(
                    socket.accept_owned_response(tid, destination),
                    "complete actual owner RPC"
                );
            }
            let duplicate = destinations[query_index * 32];
            queries[query_index].visit(&mut socket, duplicate);
        }
    }
    assert!(queries.iter().all(|query| query.owner_error().is_none()));
    assert_eq!(budget.visited_count(), 256);
    queries[0].visit(&mut socket, destinations[256]);
    assert_eq!(queries[0].owner_error(), Some(ResourceError::VisitedLimit));
    assert!(queries[0].is_done(&socket));
    assert_eq!(socket.owned_test_state().unwrap().2, 0);

    let first_operation = queries[0].operation().unwrap();
    socket.cancel_owned_operation(first_operation);
    drop(queries.remove(0));
    let mut replacement = query(&mut socket, &budget);
    replacement.visit(&mut socket, destinations[256]);
    assert_eq!(replacement.owner_error(), None);
    assert_eq!(budget.visited_count(), 225);
}

#[tokio::test]
async fn closest_and_responders_share_candidate_budget() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    for index in 0..128 {
        query.add_candidate(candidate(index));
    }
    assert_eq!(query.closest().len(), 20, "the closest set is capped at 20");
    for index in 128..364 {
        query.add_responding_node(candidate(index));
    }
    assert_eq!(query.owner_error(), None);
    assert_eq!(budget.holder_count(), 256, "closest and responders hold one budget");
    query.add_responding_node(candidate(364));
    assert_eq!(query.owner_error(), Some(ResourceError::CandidateLimit));
    assert!(query.is_done(&socket));
}

#[tokio::test]
async fn a_full_bucket_round_visits_only_what_the_operation_rpc_cap_allows() {
    // A live routing table offers a whole bucket (20) of closest candidates, more than the 16
    // in-flight RPCs one operation may hold: the round must stop at the cap, not fail with it.
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let operation = query.operation().expect("owned operation");
    for index in 0..20 {
        query.add_candidate(candidate(index));
    }
    query.visit_closest_at(&mut socket, tokio::time::Instant::now());
    assert_eq!(query.owner_error(), None);
    assert_eq!(socket.operation_rpc_len(operation), 16);
    assert_eq!(socket.owned_rpc_room(operation), 0);
    assert!(
        !query.is_done(&socket),
        "the four unvisited candidates keep the query alive"
    );
}

#[derive(Default)]
struct EventLine {
    message: String,
    fields: String,
}

impl tracing::field::Visit for EventLine {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields.push_str(&format!(" {}={value:?}", field.name()));
        }
    }
}

struct EventCapture(Arc<std::sync::Mutex<Vec<String>>>);

impl tracing::Subscriber for EventCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = EventLine::default();
        event.record(&mut line);
        self.0
            .lock()
            .unwrap()
            .push(format!("{}{}", line.message, line.fields));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Regression (live attempts 9 and 10): the `Done query` event printed `visited=0` for every
/// owned query because the owned store was not counted, and carried nothing about the NAT.
#[tokio::test]
async fn the_done_query_event_counts_owned_visited_nodes_and_the_address_votes() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let capture = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback peer");
    let destination = match capture.local_addr().expect("peer address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 peer"),
    };
    let mut buffer = [0_u8; 4096];
    query.visit(&mut socket, destination);
    socket.flush_owned().await;
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), capture.recv_from(&mut buffer))
        .await
        .expect("request timeout")
        .expect("receive request");
    let request = crate::common::Message::from_bytes(&buffer[..length]).expect("decode request");
    assert!(socket.accept_owned_response(request.transaction_id, destination));

    let seen = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 40_000);
    let other_port = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 40_001);
    query.add_address_vote(seen);
    query.add_address_vote(seen);
    query.add_address_vote(other_port);

    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    tracing::subscriber::with_default(EventCapture(Arc::clone(&lines)), || {
        assert!(query.is_done(&socket));
    });
    let lines = lines.lock().unwrap();
    let done = lines
        .iter()
        .find(|line| line.starts_with("Done query"))
        .unwrap_or_else(|| panic!("no Done query event in {lines:?}"));
    assert!(done.contains(" visited=1"), "{done}");
    assert!(done.contains(" voted=3"), "{done}");
    assert!(done.contains(" voted_addresses=2"), "{done}");
    assert!(done.contains(" voted_ports=2"), "{done}");
}
