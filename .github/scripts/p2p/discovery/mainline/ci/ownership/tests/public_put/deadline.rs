// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::{net::SocketAddr, time::Duration};

use ed25519_dalek::SigningKey;
use tokio::time::Instant;

use super::*;

async fn receive_deadline_request(
    peer: &tokio::net::UdpSocket,
) -> (Message, std::net::SocketAddrV4) {
    let mut bytes = [0u8; 2048];
    let (length, source) = peer
        .recv_from(&mut bytes)
        .await
        .expect("capture peer receives datagram");
    let source = match source {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("actor uses IPv4 socket"),
    };
    (
        Message::from_bytes(&bytes[..length]).expect("decode actual request"),
        source,
    )
}

#[tokio::test(start_paused = true)]
async fn public_put_until_preserves_entry_deadline_across_retries() {
    let started = Instant::now();
    let (phase_tx, phase_rx) = std::sync::mpsc::sync_channel::<String>(32);
    let mut clock_guard = tokio::task::spawn_blocking(move || {
        let mut phase = String::from("actor startup");
        loop {
            match phase_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(next) => phase = next,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    panic!("wall-clock timeout in {phase}")
                }
            }
        }
    });

    {
        let scenario = async {
            let (peer, peer_address) = capture();
            let mut actor = bounded_actor(peer_address);
            actor.owned_disable_maintenance_for_test = true;
            let mut owner = OwnedDht::from_actor(actor);
            let handle = owner.handle();
            let actor_addr = handle.info().await.expect("actor info").local_addr();
            let entry = Instant::now();
            let deadline = entry + Duration::from_millis(250);
            let phase = |name: &str, attempt: &str| {
                phase_tx
                    .try_send(format!(
                        "phase={name} expected attempt={attempt} elapsed={:?} entry={entry:?} deadline={deadline:?}",
                        entry.elapsed()
                    ))
                    .expect("watchdog active");
            };
            let item = crate::common::MutableItem::new(
                &SigningKey::from_bytes(&[0xD7; 32]),
                b"until-retry-deadline",
                1,
                None,
            );
            let target = *item.target();
            phase("admission", "GET");
            let mut admission = handle
                .put_mutable_until(item, deadline)
                .expect("admit deadline-bounded PUT");
            admission.wait().await.expect("admit owned PUT");
            let mut operation = admission.take_operation().expect("owned PUT operation");

            phase("GET", "GET");
            let (get, source) = receive_deadline_request(&peer).await;
            assert!(matches!(
                &get.message_type,
                MessageType::Request(crate::common::RequestSpecific {
                    request_type: crate::common::RequestTypeSpecific::GetValue(_),
                    ..
                })
            ));
            assert_eq!(source, actor_addr);
            assert_eq!(entry.elapsed(), Duration::ZERO);
            let get_reply = Message {
                transaction_id: get.transaction_id,
                version: Some([82, 83, 0, 6]),
                requester_ip: None,
                message_type: MessageType::Response(ResponseSpecific::NoValues(
                    crate::common::NoValuesResponseArguments {
                        responder_id: Id::from([0xA8; 20]),
                        token: vec![0x44, 0x55].into_boxed_slice(),
                        nodes: None,
                    },
                )),
                read_only: false,
            };
            peer.send_to(&get_reply.to_bytes().expect("encode GET reply"), source)
                .await
                .expect("send GET reply");
            phase("first PUT", "1");
            let (first, first_source) = receive_deadline_request(&peer).await;
            assert!(matches!(
                &first.message_type,
                MessageType::Request(crate::common::RequestSpecific {
                    request_type: crate::common::RequestTypeSpecific::Put(_),
                    ..
                })
            ));
            assert_eq!(first_source, source);
            assert_eq!(entry.elapsed(), Duration::ZERO);
            phase("first retry control", "1");
            handle
                .test_put_control(target, 100)
                .await
                .expect("expire first PUT");
            tokio::time::advance(Duration::from_millis(100)).await;
            phase("second PUT", "2");
            let (second, second_source) = receive_deadline_request(&peer).await;
            assert!(matches!(
                &second.message_type,
                MessageType::Request(crate::common::RequestSpecific {
                    request_type: crate::common::RequestTypeSpecific::Put(_),
                    ..
                })
            ));
            assert_eq!(second_source, source);
            assert_ne!(second.transaction_id, first.transaction_id);
            assert_eq!(entry.elapsed(), Duration::from_millis(100));
            phase("second retry control", "2");
            handle
                .test_put_control(target, 100)
                .await
                .expect("expire second PUT");
            tokio::time::advance(Duration::from_millis(99)).await;
            phase("retry barrier", "3");
            handle.info().await.expect("before-third-attempt timer barrier");
            let mut bytes = [0u8; 2048];
            assert_eq!(
                peer.try_recv_from(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "third PUT waits for its scheduled retry"
            );
            tokio::time::advance(Duration::from_millis(1)).await;
            phase("third PUT", "3");
            let (third, third_source) = receive_deadline_request(&peer).await;
            assert!(matches!(
                &third.message_type,
                MessageType::Request(crate::common::RequestSpecific {
                    request_type: crate::common::RequestTypeSpecific::Put(_),
                    ..
                })
            ));
            assert_eq!(third_source, source);
            assert_ne!(third.transaction_id, second.transaction_id);
            assert_eq!(entry.elapsed(), Duration::from_millis(200));

            tokio::time::advance(Duration::from_millis(50)).await;
            phase("deadline wait", "terminal");
            assert_eq!(entry.elapsed(), Duration::from_millis(250));
            let result = operation.wait().await;
            assert!(
                matches!(
                    &result,
                    Err(OwnedPutError::Resource(
                        crate::resource::ResourceError::DeadlineExceeded
                    ))
                ),
                "unexpected deadline result: {result:?}"
            );
            phase("cleanup", "none");
            operation
                .cancel_and_wait()
                .await
                .expect("observe actual cleanup");
            tokio::time::advance(Duration::from_millis(200)).await;
            phase("close", "none");
            handle.info().await.expect("actor receipt barrier");
            assert_eq!(
                peer.try_recv_from(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "deadline expiry did not send a fourth PUT"
            );
            owner.close().await.expect("close owner");
            drop(UdpSocket::bind(actor_addr).expect("owner released actor socket"));
        };
        tokio::pin!(scenario);
        tokio::select! {
            _ = &mut scenario => {},
            result = &mut clock_guard => panic!(
                "deadline scenario stalled: {result:?}; virtual elapsed {:?}",
                started.elapsed()
            ),
        }
    }
    drop(phase_tx);
    clock_guard
        .await
        .expect("wall-clock guard exits after scenario");
}
