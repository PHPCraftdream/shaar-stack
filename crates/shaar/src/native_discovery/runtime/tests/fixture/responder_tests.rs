// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::time::Duration;

use futures::FutureExt as _;
use n0_mainline::MutableItem;
use serde_bencode::value::Value;
use tokio::net::UdpSocket;

use super::super::super::endpoint_key;
use super::LoopbackPeer;
use crate::identity::Identity;
use crate::native_discovery::runtime::{clock::ClockSample, publisher::PublisherState};

fn dict(entries: impl IntoIterator<Item = (&'static [u8], Value)>) -> Value {
    Value::Dict(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_vec(), value))
            .collect(),
    )
}

fn record(seed: u8) -> MutableItem {
    let identity = Identity::from_seed([seed; 32]);
    let mut publisher = PublisherState::new(endpoint_key(&identity).expect("fixture key"));
    let (_, signed) = publisher
        .replace(
            &identity,
            &[iroh_base::TransportAddr::Ip(
                "127.0.0.1:9001".parse().expect("loopback"),
            )],
            ClockSample {
                wall_us: 1_700_000_000_000_000,
                monotonic_before_us: 0,
                monotonic_after_us: 0,
            },
        )
        .expect("signed fixture record");
    super::super::super::to_mutable(&signed.expect("snapshot")).expect("typed fixture record")
}

fn query(transaction: &[u8], method: &[u8], arguments: Value) -> Vec<u8> {
    serde_bencode::to_bytes(&dict([
        (b"t".as_slice(), Value::Bytes(transaction.to_vec())),
        (b"y".as_slice(), Value::Bytes(b"q".to_vec())),
        (b"q".as_slice(), Value::Bytes(method.to_vec())),
        (b"a".as_slice(), arguments),
    ]))
    .expect("bounded query")
}

fn put(item: &MutableItem, corrupt: bool) -> Vec<u8> {
    let mut signature = item.signature().to_vec();
    if corrupt {
        signature[0] ^= 1;
    }
    query(
        b"pp",
        b"put",
        dict([
            (b"id".as_slice(), Value::Bytes(vec![0x42; 20])),
            (b"token".as_slice(), Value::Bytes(b"ok".to_vec())),
            (b"k".as_slice(), Value::Bytes(item.key().to_vec())),
            (b"sig".as_slice(), Value::Bytes(signature)),
            (b"seq".as_slice(), Value::Int(item.seq())),
            (b"v".as_slice(), Value::Bytes(item.value().to_vec())),
        ]),
    )
}

fn get(item: &MutableItem) -> Vec<u8> {
    query(
        b"gg",
        b"get",
        dict([
            (b"id".as_slice(), Value::Bytes(vec![0x42; 20])),
            (
                b"target".as_slice(),
                Value::Bytes(
                    MutableItem::target_from_key(item.key(), None)
                        .as_bytes()
                        .to_vec(),
                ),
            ),
        ]),
    )
}

/// cancel-safe: NO — terminal test cancellation closes both owned sockets.
async fn receive(socket: &UdpSocket) -> Value {
    let mut packet = [0; 2048];
    let length = socket.recv(&mut packet).await.expect("owned reply");
    serde_bencode::from_bytes(&packet[..length]).expect("reply bencode")
}

fn field<'a>(value: &'a Value, key: &[u8]) -> &'a Value {
    let Value::Dict(fields) = value else {
        panic!("reply dictionary")
    };
    fields.get(key).expect("reply field")
}

#[tokio::test]
async fn resolver_acknowledges_repeated_signed_put_without_replacing_service_record() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut peer = LoopbackPeer::bind().await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("owned sender");
        socket.connect(peer.address).await.expect("owned peer");
        let publication = record(0x71);
        let service = record(0x72);
        let target = MutableItem::target_from_key(service.key(), None);
        // Establish the same capture/ACK boundary as retained Client startup.
        socket.send(&put(&publication, false)).await.expect("initial PUT");
        let captured = peer.serve_until_put().await;
        assert_eq!(captured.key, publication.key());
        assert_eq!(field(&receive(&socket).await, b"t"), &Value::Bytes(b"pp".to_vec()));
        let mut responder = std::pin::pin!(peer.serve_record(&service));
        let exchange = async {
            for _ in 0..2 {
                socket.send(&put(&publication, false)).await.expect("repeated PUT");
                let ack = receive(&socket).await;
                assert_eq!(field(&ack, b"t"), &Value::Bytes(b"pp".to_vec()));
                assert_eq!(field(&ack, b"y"), &Value::Bytes(b"r".to_vec()));
                assert!(matches!(field(&ack, b"r"), Value::Dict(fields) if !fields.contains_key(b"v".as_slice())));
            }
            socket.send(&get(&service)).await.expect("service GET");
            let reply = receive(&socket).await;
            assert_eq!(field(&reply, b"t"), &Value::Bytes(b"gg".to_vec()));
            let item = field(&reply, b"r");
            assert_eq!(field(item, b"k"), &Value::Bytes(service.key().to_vec()));
            assert_eq!(field(item, b"sig"), &Value::Bytes(service.signature().to_vec()));
            assert_eq!(field(item, b"seq"), &Value::Int(service.seq()));
            assert_eq!(field(item, b"v"), &Value::Bytes(service.value().to_vec()));
            assert_ne!(target, MutableItem::target_from_key(publication.key(), None));
        };
        tokio::select! {
            () = exchange => {},
            () = &mut responder => panic!("responder must stay live"),
        }
    }).await.expect("bounded repeated-PUT/GET exchange");
}

#[tokio::test]
async fn resolver_does_not_acknowledge_a_corrupt_signed_put() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut peer = LoopbackPeer::bind().await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("owned sender");
        socket.connect(peer.address).await.expect("owned peer");
        let item = record(0x73);
        socket.send(&put(&item, true)).await.expect("corrupt PUT");
        let outcome = std::panic::AssertUnwindSafe(
            peer.capture_get(MutableItem::target_from_key(item.key(), None)),
        )
        .catch_unwind()
        .await;
        let panic = outcome.expect_err("invalid signature must fail the fixture");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("panic message");
        assert!(
            message.contains("captured signature verifies"),
            "unexpected panic: {message}"
        );
        let mut packet = [0; 2048];
        assert_eq!(
            socket
                .try_recv(&mut packet)
                .expect_err("no corrupt PUT ACK")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    })
    .await
    .expect("bounded corrupt-PUT rejection");
}
