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

/// The accepted no-vote reply envelope for the query transaction (option-off wire shape).
fn reply_envelope(transaction: &[u8], r: Value) -> Value {
    dict([
        (b"r".as_slice(), r),
        (b"t".as_slice(), Value::Bytes(transaction.to_vec())),
        (b"y".as_slice(), Value::Bytes(b"r".to_vec())),
    ])
}

fn responder_id() -> Value {
    Value::Bytes(vec![0x41; 20])
}

fn probe_arguments() -> Value {
    dict([
        (b"id".as_slice(), Value::Bytes(vec![0x42; 20])),
        (b"target".as_slice(), Value::Bytes(vec![0x42; 20])),
    ])
}

fn observed_endpoint(source: std::net::SocketAddrV4) -> Value {
    let mut endpoint = Vec::with_capacity(6);
    endpoint.extend_from_slice(&source.ip().octets());
    endpoint.extend_from_slice(&source.port().to_be_bytes());
    Value::Bytes(endpoint)
}

async fn raw_receive(socket: &UdpSocket) -> Vec<u8> {
    let mut packet = [0; 2048];
    let length = socket.recv(&mut packet).await.expect("owned reply");
    packet[..length].to_vec()
}

fn decode(packet: &[u8]) -> Value {
    serde_bencode::from_bytes(packet).expect("reply bencode")
}

async fn assert_stamped(socket: &UdpSocket, source: std::net::SocketAddrV4, expected: Value) {
    let reply = decode(&raw_receive(socket).await);
    let mut fields = match reply {
        Value::Dict(fields) => fields,
        other => panic!("reply dictionary: {other:?}"),
    };
    let vote = fields
        .remove(b"ip".as_slice())
        .expect("observed-address vote present");
    assert_eq!(vote, observed_endpoint(source));
    assert_eq!(Value::Dict(fields), expected);
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

#[test]
fn namespace_query_sources_are_exact_and_default_stays_loopback_only() {
    for address in ["127.0.0.1", "::1"] {
        let ip = address.parse().expect("loopback IP");
        assert!(super::wire::source_allowed(ip, false));
        assert!(super::wire::source_allowed(ip, true));
    }
    for address in ["203.0.113.1", "203.0.113.2", "203.0.113.10"] {
        let ip = address.parse().expect("owned namespace IP");
        assert!(!super::wire::source_allowed(ip, false));
        assert!(super::wire::source_allowed(ip, true));
    }
    for address in [
        "203.0.113.3",
        "203.0.113.11",
        "10.0.1.2",
        "192.0.2.1",
        "::ffff:203.0.113.1",
        "2001:db8::1",
    ] {
        let ip = address.parse().expect("unadmitted IP");
        assert!(!super::wire::source_allowed(ip, false));
        assert!(!super::wire::source_allowed(ip, true));
    }
}

/// Option-off equivalence: the default fixture pins the accepted pre-change replies exactly
/// (decoded value equality plus byte-length equality; bencode length is independent of the
/// Value::Dict HashMap order, and the encoder path is untouched by the option).
#[tokio::test]
async fn default_peer_replies_stay_byte_equivalent_without_the_observed_address_option() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut peer = LoopbackPeer::bind().await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("owned sender");
        socket.connect(peer.address).await.expect("owned peer");
        let service = record(0x76);
        let mut responder = std::pin::pin!(peer.serve_record(&service));
        let exchange = async {
            for (method, expected) in [
                (
                    b"ping".as_slice(),
                    reply_envelope(b"ff", dict([(b"id".as_slice(), responder_id())])),
                ),
                (
                    b"find_node".as_slice(),
                    reply_envelope(
                        b"ff",
                        dict([
                            (b"id".as_slice(), responder_id()),
                            (b"nodes".as_slice(), Value::Bytes(Vec::new())),
                        ]),
                    ),
                ),
                (
                    b"get".as_slice(),
                    reply_envelope(
                        b"ff",
                        dict([
                            (b"id".as_slice(), responder_id()),
                            (b"token".as_slice(), Value::Bytes(b"ok".to_vec())),
                        ]),
                    ),
                ),
            ] {
                socket
                    .send(&query(b"ff", method, probe_arguments()))
                    .await
                    .expect("bounded fixture probe");
                let reply = raw_receive(&socket).await;
                assert_eq!(decode(&reply), expected);
                assert_eq!(
                    reply.len(),
                    serde_bencode::to_bytes(&expected)
                        .expect("bounded reply encoding")
                        .len()
                );
            }
            socket.send(&get(&service)).await.expect("service GET");
            let served = reply_envelope(
                b"gg",
                dict([
                    (b"id".as_slice(), responder_id()),
                    (b"token".as_slice(), Value::Bytes(b"ok".to_vec())),
                    (b"k".as_slice(), Value::Bytes(service.key().to_vec())),
                    (
                        b"sig".as_slice(),
                        Value::Bytes(service.signature().to_vec()),
                    ),
                    (b"seq".as_slice(), Value::Int(service.seq())),
                    (b"v".as_slice(), Value::Bytes(service.value().to_vec())),
                ]),
            );
            let reply = raw_receive(&socket).await;
            assert_eq!(decode(&reply), served);
            assert_eq!(
                reply.len(),
                serde_bencode::to_bytes(&served)
                    .expect("bounded reply encoding")
                    .len()
            );
        };
        tokio::select! {
            () = exchange => {},
            () = &mut responder => panic!("responder must stay live"),
        }
    })
    .await
    .expect("bounded option-off equivalence exchange");
}

/// Option-on behavior: every reply carries the BEP 42 `ip` vote of the observed requester
/// endpoint (compact IPv4 form) and is otherwise identical to the accepted shape.
#[tokio::test]
async fn observed_address_option_stamps_the_requester_endpoint_into_every_reply() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut peer = LoopbackPeer::bind().await.report_observed(true);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("owned sender");
        socket.connect(peer.address).await.expect("owned peer");
        let std::net::SocketAddr::V4(source) = socket.local_addr().expect("sender endpoint") else {
            panic!("IPv4 loopback sender");
        };
        let service = record(0x77);
        let mut responder = std::pin::pin!(peer.serve_record(&service));
        let exchange = async {
            for (method, expected) in [
                (
                    b"ping".as_slice(),
                    reply_envelope(b"ff", dict([(b"id".as_slice(), responder_id())])),
                ),
                (
                    b"get".as_slice(),
                    reply_envelope(
                        b"ff",
                        dict([
                            (b"id".as_slice(), responder_id()),
                            (b"token".as_slice(), Value::Bytes(b"ok".to_vec())),
                        ]),
                    ),
                ),
            ] {
                socket
                    .send(&query(b"ff", method, probe_arguments()))
                    .await
                    .expect("bounded fixture probe");
                assert_stamped(&socket, source, expected).await;
            }
            socket.send(&get(&service)).await.expect("service GET");
            assert_stamped(
                &socket,
                source,
                reply_envelope(
                    b"gg",
                    dict([
                        (b"id".as_slice(), responder_id()),
                        (b"token".as_slice(), Value::Bytes(b"ok".to_vec())),
                        (b"k".as_slice(), Value::Bytes(service.key().to_vec())),
                        (
                            b"sig".as_slice(),
                            Value::Bytes(service.signature().to_vec()),
                        ),
                        (b"seq".as_slice(), Value::Int(service.seq())),
                        (b"v".as_slice(), Value::Bytes(service.value().to_vec())),
                    ]),
                ),
            )
            .await;
        };
        tokio::select! {
            () = exchange => {},
            () = &mut responder => panic!("responder must stay live"),
        }
        // The PUT acknowledgement carries the same vote.
        let mut put_peer = LoopbackPeer::bind().await.report_observed(true);
        let put_socket = UdpSocket::bind("127.0.0.1:0").await.expect("owned sender");
        put_socket
            .connect(put_peer.address)
            .await
            .expect("owned peer");
        let std::net::SocketAddr::V4(put_source) =
            put_socket.local_addr().expect("sender endpoint")
        else {
            panic!("IPv4 loopback sender");
        };
        let item = record(0x78);
        put_socket
            .send(&put(&item, false))
            .await
            .expect("signed PUT");
        let captured = put_peer.serve_until_put().await;
        assert_eq!(captured.key, item.key());
        assert_stamped(
            &put_socket,
            put_source,
            reply_envelope(b"pp", dict([(b"id".as_slice(), responder_id())])),
        )
        .await;
    })
    .await
    .expect("bounded option-on observed-address exchange");
}
