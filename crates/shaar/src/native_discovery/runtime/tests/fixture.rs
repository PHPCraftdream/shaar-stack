// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub(super) const MAX_PACKET: usize = 2048;
const NODE_ID: [u8; 20] = [0x41; 20];
const TOKEN: &[u8] = b"ok";
type Value = serde_bencode::value::Value;

fn dict(entries: impl IntoIterator<Item = (&'static [u8], Value)>) -> Value {
    Value::Dict(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_vec(), value))
            .collect::<HashMap<_, _>>(),
    )
}

fn field<'a>(value: &'a Value, name: &[u8]) -> Option<&'a Value> {
    let Value::Dict(fields) = value else {
        return None;
    };
    fields.get(name)
}

fn bytes_field<'a>(value: &'a Value, name: &[u8]) -> Option<&'a [u8]> {
    match field(value, name)? {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

fn integer_field(value: &Value, name: &[u8]) -> Option<i64> {
    match field(value, name)? {
        Value::Int(number) => Some(*number),
        _ => None,
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let packet = serde_bencode::to_bytes(value).expect("encode bounded KRPC value");
    assert!(packet.len() <= MAX_PACKET, "bounded KRPC reply");
    packet
}

pub(super) struct LoopbackPeer {
    socket: UdpSocket,
    pub(super) address: SocketAddr,
    pending_puts: Vec<(SocketAddr, Vec<u8>)>,
}

impl LoopbackPeer {
    pub(super) async fn bind() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind owned loopback peer");
        let address = socket.local_addr().expect("peer local address");
        Self {
            socket,
            address,
            pending_puts: Vec::new(),
        }
    }

    pub(super) async fn capture_get(&mut self, target: n0_mainline::Id) -> (SocketAddr, Vec<u8>) {
        loop {
            let mut packet = [0; MAX_PACKET];
            let (length, source) = self
                .socket
                .recv_from(&mut packet)
                .await
                .expect("receive query");
            let parsed: Value = serde_bencode::from_bytes(&packet[..length]).expect("bounded KRPC");
            assert_eq!(bytes_field(&parsed, b"y"), Some(b"q".as_slice()));
            let transaction = bytes_field(&parsed, b"t").expect("transaction id");
            let query = bytes_field(&parsed, b"q").expect("method");
            if query == b"get" {
                let arguments = field(&parsed, b"a").expect("GET arguments");
                let raw = bytes_field(arguments, b"target").expect("GET target");
                let actual =
                    n0_mainline::Id::from(<[u8; 20]>::try_from(raw).expect("target length"));
                if actual == target {
                    return (source, transaction.to_vec());
                }
            }
            let kind = match query {
                b"get" => ReplyKind::Get,
                b"find_node" => ReplyKind::FindNode,
                b"ping" => ReplyKind::Ping,
                _ => panic!("unexpected method while resolving"),
            };
            self.socket
                .send_to(&response(transaction, kind), source)
                .await
                .expect("bootstrap reply");
        }
    }

    pub(super) async fn reply_empty_get(&self, source: SocketAddr, transaction: &[u8]) {
        self.socket
            .send_to(&response(transaction, ReplyKind::Get), source)
            .await
            .expect("actual empty GET response");
    }

    pub(super) async fn reply_get(
        &self,
        source: SocketAddr,
        transaction: &[u8],
        item: &n0_mainline::MutableItem,
    ) {
        let fields = vec![
            (b"id".as_slice(), Value::Bytes(NODE_ID.to_vec())),
            (b"token".as_slice(), Value::Bytes(TOKEN.to_vec())),
            (b"k".as_slice(), Value::Bytes(item.key().to_vec())),
            (b"sig".as_slice(), Value::Bytes(item.signature().to_vec())),
            (b"seq".as_slice(), Value::Int(item.seq())),
            (b"v".as_slice(), Value::Bytes(item.value().to_vec())),
        ];
        let packet = encode(&dict([
            (b"r".as_slice(), dict(fields)),
            (b"t".as_slice(), Value::Bytes(transaction.to_vec())),
            (b"y".as_slice(), Value::Bytes(b"r".to_vec())),
        ]));
        self.socket
            .send_to(&packet, source)
            .await
            .expect("actual GET response");
    }

    pub(super) async fn serve_record(&mut self, item: &n0_mainline::MutableItem) {
        let target = n0_mainline::MutableItem::target_from_key(item.key(), None);
        loop {
            let (source, transaction) = self.capture_get(target).await;
            self.reply_get(source, &transaction, item).await;
        }
    }

    pub(super) async fn serve_until_put(&mut self) -> CapturedPut {
        let captured = self.serve_puts(1).await;
        self.acknowledge_next().await;
        captured.into_iter().next().expect("one captured PUT")
    }

    pub(super) async fn capture_put(&mut self) -> (SocketAddr, Vec<u8>, CapturedPut) {
        let captured = self.serve_puts(1).await;
        let (source, transaction) = self
            .pending_puts
            .last()
            .cloned()
            .expect("pending PUT retained");
        (
            source,
            transaction,
            captured.into_iter().next().expect("one captured PUT"),
        )
    }

    pub(super) async fn acknowledge(&mut self, source: SocketAddr, transaction: &[u8]) {
        self.pending_puts
            .retain(|(pending_source, pending_transaction)| {
                *pending_source != source || pending_transaction.as_slice() != transaction
            });
        let reply = response(transaction, ReplyKind::PutAcknowledgement);
        self.socket
            .send_to(&reply, source)
            .await
            .expect("reply to held PUT");
    }

    pub(super) async fn reject(&mut self, source: SocketAddr, transaction: &[u8]) {
        self.pending_puts
            .retain(|(pending_source, pending_transaction)| {
                *pending_source != source || pending_transaction.as_slice() != transaction
            });
        let error = Value::List(vec![
            Value::Int(201),
            Value::Bytes(b"PUT rejected".to_vec()),
        ]);
        let packet = encode(&dict([
            (b"e".as_slice(), error),
            (b"t".as_slice(), Value::Bytes(transaction.to_vec())),
            (b"y".as_slice(), Value::Bytes(b"e".to_vec())),
        ]));
        self.socket
            .send_to(&packet, source)
            .await
            .expect("reject held PUT");
    }

    pub(super) async fn acknowledge_next(&mut self) {
        let (source, transaction) = self.pending_puts.pop().expect("held PUT exists");
        self.acknowledge(source, &transaction).await;
    }

    pub(super) async fn serve_puts(&mut self, count: usize) -> Vec<CapturedPut> {
        let mut captured = Vec::with_capacity(count);
        while captured.len() < count {
            let mut packet = [0; MAX_PACKET];
            let (length, source) = self
                .socket
                .recv_from(&mut packet)
                .await
                .expect("receive Mainline datagram");
            assert!(length <= MAX_PACKET);
            let parsed: Value =
                serde_bencode::from_bytes(&packet[..length]).expect("bounded KRPC bencode");
            assert_eq!(bytes_field(&parsed, b"y"), Some(b"q".as_slice()));
            let transaction = bytes_field(&parsed, b"t").expect("transaction id");
            assert!(
                matches!(transaction.len(), 2 | 4),
                "valid transaction id length"
            );
            let transaction = transaction.to_vec();
            let query = bytes_field(&parsed, b"q").expect("KRPC method");
            match query {
                b"put" => {
                    assert!(
                        self.pending_puts.len() < 16,
                        "bounded held PUT fixture capacity"
                    );
                    let arguments = field(&parsed, b"a").expect("PUT arguments");
                    let key = bytes_field(arguments, b"k").expect("mutable key");
                    let signature = bytes_field(arguments, b"sig").expect("mutable signature");
                    let value = bytes_field(arguments, b"v").expect("signed DNS value");
                    let sequence = integer_field(arguments, b"seq").expect("mutable sequence");
                    assert_eq!(key.len(), 32);
                    assert_eq!(signature.len(), 64);
                    assert!(value.len() <= 1000);
                    assert!(sequence >= 0);
                    self.pending_puts.push((source, transaction));
                    captured.push(CapturedPut {
                        key: key.to_vec(),
                        signature: signature.to_vec(),
                        value: value.to_vec(),
                        sequence,
                    });
                }
                b"get" => {
                    let reply = response(&transaction, ReplyKind::Get);
                    self.socket
                        .send_to(&reply, source)
                        .await
                        .expect("reply to Mainline query");
                }
                b"find_node" => {
                    let reply = response(&transaction, ReplyKind::FindNode);
                    self.socket
                        .send_to(&reply, source)
                        .await
                        .expect("reply to Mainline query");
                }
                b"ping" => {
                    let reply = response(&transaction, ReplyKind::Ping);
                    self.socket
                        .send_to(&reply, source)
                        .await
                        .expect("reply to Mainline query");
                }
                other => panic!(
                    "unexpected Mainline query: {:?}",
                    String::from_utf8_lossy(other)
                ),
            }
        }
        captured
    }
}

pub(super) struct CapturedPut {
    pub(super) key: Vec<u8>,
    pub(super) signature: Vec<u8>,
    pub(super) value: Vec<u8>,
    pub(super) sequence: i64,
}

enum ReplyKind {
    Get,
    FindNode,
    Ping,
    PutAcknowledgement,
}

fn response(transaction: &[u8], kind: ReplyKind) -> Vec<u8> {
    let mut response = vec![(b"id" as &'static [u8], Value::Bytes(NODE_ID.to_vec()))];
    match kind {
        ReplyKind::Get => response.push((b"token", Value::Bytes(TOKEN.to_vec()))),
        ReplyKind::FindNode => response.push((b"nodes", Value::Bytes(Vec::new()))),
        ReplyKind::Ping | ReplyKind::PutAcknowledgement => {}
    }
    encode(&dict([
        (b"r".as_slice(), dict(response)),
        (b"t".as_slice(), Value::Bytes(transaction.to_vec())),
        (b"y".as_slice(), Value::Bytes(b"r".to_vec())),
    ]))
}
