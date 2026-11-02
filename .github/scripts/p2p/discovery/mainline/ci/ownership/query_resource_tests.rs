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

#[tokio::test]
async fn real_owned_get_runs_at_most_three_rounds_then_finishes() {
    let budget = Arc::new(StoreBudget::default());
    let mut socket = owned_socket();
    let mut query = query(&mut socket, &budget);
    let operation = query.operation().expect("owned operation");
    let deadline = socket
        .owned_deadline(operation)
        .expect("registered operation deadline");

    let mut captures = Vec::new();
    for _ in 0..4 {
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

    query.visit(&mut socket, destinations[0]);
    socket.flush_owned().await;
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(2), captures[0].recv_from(&mut buffer))
            .await
            .expect("first request timeout")
            .expect("receive first request");
    let first =
        crate::common::Message::from_bytes(&buffer[..length]).expect("decode first request");
    assert!(socket.accept_owned_response(first.transaction_id, destinations[0]));

    let base = tokio::time::Instant::now();
    query.add_candidate(Node::new(Id::from([2_u8; 20]), destinations[1]));
    query.visit_closest_at(&mut socket, base);
    let second_round = base + Duration::from_millis(100);
    if let Some(next) = query.owned_next_round() {
        assert!(next <= second_round);
    }
    query.visit_closest_at(&mut socket, second_round);
    socket.flush_owned().await;
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(2), captures[1].recv_from(&mut buffer))
            .await
            .expect("second request timeout")
            .expect("receive second request");
    let second =
        crate::common::Message::from_bytes(&buffer[..length]).expect("decode second request");
    assert!(socket.accept_owned_response(second.transaction_id, destinations[1]));

    query.add_candidate(Node::new(Id::from([3_u8; 20]), destinations[2]));
    let third_schedule = base + Duration::from_millis(101);
    query.visit_closest_at(&mut socket, third_schedule);
    if let Some(next) = query.owned_next_round() {
        assert!(next <= base + Duration::from_millis(301));
    }
    query.visit_closest_at(&mut socket, base + Duration::from_millis(301));
    socket.flush_owned().await;
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(2), captures[2].recv_from(&mut buffer))
            .await
            .expect("third request timeout")
            .expect("receive third request");
    let third =
        crate::common::Message::from_bytes(&buffer[..length]).expect("decode third request");
    assert!(socket.accept_owned_response(third.transaction_id, destinations[2]));

    query.add_candidate(Node::new(Id::from([4_u8; 20]), destinations[3]));
    query.visit_closest_at(&mut socket, base + Duration::from_secs(1));
    assert_eq!(query.owner_error(), None);
    assert!(query.is_done(&socket));
    assert_eq!(socket.owned_test_state().unwrap().2, 0);
    assert_eq!(socket.owned_deadline(operation), Some(deadline));
    assert_eq!(
        captures[3].try_recv_from(&mut buffer).unwrap_err().kind(),
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
    query.visit_closest_at(&mut socket, deadline);
    assert_eq!(query.owner_error(), Some(ResourceError::DeadlineExceeded));
    assert_eq!(socket.owned_test_state().unwrap().2, 0);
    assert!(query.is_done(&socket));
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
    for index in 0..128 {
        first.add_candidate(candidate(index));
    }
    for index in 128..256 {
        second.add_candidate(candidate(index));
    }
    assert_eq!(first.closest().len(), 128);
    assert_eq!(second.closest().len(), 128);
    second.add_candidate(candidate(256));
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
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, socket.local_addr().port())
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
    for index in 128..256 {
        query.add_responding_node(candidate(index));
    }
    query.add_candidate(candidate(256));
    assert_eq!(query.owner_error(), Some(ResourceError::CandidateLimit));
    assert!(query.is_done(&socket));
}
