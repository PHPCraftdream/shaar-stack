// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use super::KrpcSocket;
use crate::common::Message;

const MTU: usize = 2048;
const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn ping(transaction: &[u8; 2]) -> Vec<u8> {
    let mut bytes = b"d1:ad2:id20:".to_vec();
    bytes.extend_from_slice(&[7; 20]);
    bytes.extend_from_slice(b"e1:q4:ping1:t2:");
    bytes.extend_from_slice(transaction);
    bytes.extend_from_slice(b"1:y1:qe");
    bytes
}

fn exact_packet(length: usize) -> Vec<u8> {
    let prefix = ping(b"aa");
    for payload_len in 0..=length {
        let mut packet = prefix[..prefix.len() - 1].to_vec();
        let padding = format!("1:z{payload_len}:");
        packet.extend_from_slice(padding.as_bytes());
        packet.extend(std::iter::repeat_n(b'x', payload_len));
        packet.push(b'e');
        if packet.len() == length {
            assert!(Message::from_bytes(&packet).is_ok());
            return packet;
        }
    }
    panic!("could not construct valid packet of length {length}");
}

fn receiver() -> KrpcSocket {
    KrpcSocket::new_at(
        &crate::actor::config::Config::default(),
        Some(SocketAddrV4::new(LOCALHOST, 0)),
    )
    .expect("bind receiver")
}

fn sender() -> UdpSocket {
    UdpSocket::bind(SocketAddrV4::new(LOCALHOST, 0)).expect("bind sender")
}

#[tokio::test]
async fn rejects_invalid_receive_metadata_at_udp_ingress() {
    for (reported_len, reported_stride) in [(usize::MAX, usize::MAX), (1, 0), (2, 1)] {
        let mut receiver = receiver();
        let sender = sender();
        let sender_addr = match sender.local_addr().expect("sender address") {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => unreachable!(),
        };
        let destination = receiver.local_addr();
        receiver
            .io
            .ingress_override_len
            .store(reported_len, std::sync::atomic::Ordering::Relaxed);
        receiver
            .io
            .ingress_override_stride
            .store(reported_stride, std::sync::atomic::Ordering::Relaxed);

        sender
            .send_to(&ping(b"aa"), destination)
            .expect("send datagram with overridden metadata");
        sender
            .send_to(&ping(b"bb"), destination)
            .expect("send valid sentinel");

        assert!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
                .await
                .expect("receive rejected metadata or sentinel")
                .is_none(),
            "invalid metadata must reject the first datagram"
        );
        let accepted = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
            .await
            .expect("receive valid sentinel")
            .expect("valid sentinel accepted");
        assert_eq!(accepted.0.transaction_id, u16::from_be_bytes(*b"bb") as u32);
        assert_eq!(accepted.1, sender_addr);
    }
}

#[tokio::test]
async fn accepts_valid_datagram_at_mtu() {
    let mut receiver = receiver();
    let sender = sender();
    let sender_addr = match sender.local_addr().expect("sender address") {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => unreachable!(),
    };
    let packet = exact_packet(MTU);
    assert_eq!(
        sender
            .send_to(&packet, receiver.local_addr())
            .expect("send exact MTU packet"),
        MTU
    );

    let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
        .await
        .expect("receive exact MTU packet")
        .expect("valid exact MTU packet accepted");
    assert_eq!(received.0.transaction_id, u16::from_be_bytes(*b"aa") as u32);
    assert_eq!(received.1, sender_addr);
}

#[tokio::test]
async fn rejects_oversize_and_malformed_datagrams_before_valid_sentinel() {
    let mut receiver = receiver();
    let sender = sender();
    let sender_addr = match sender.local_addr().expect("sender address") {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => unreachable!(),
    };
    let destination = receiver.local_addr();
    let prefix = exact_packet(MTU);

    for length in [MTU + 1, 60_000] {
        let mut oversized = prefix.clone();
        oversized.resize(length, b'x');
        assert_eq!(oversized.len(), length);
        assert!(Message::from_bytes(&oversized[..MTU]).is_ok());
        sender
            .send_to(&oversized, destination)
            .expect("send oversized packet");
        sender
            .send_to(&ping(b"bb"), destination)
            .expect("send valid sentinel");

        let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
            .await
            .expect("receive rejection or sentinel");
        let accepted = match first {
            Some(message) => message,
            None => tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
                .await
                .expect("receive sentinel after discarded datagram")
                .expect("valid sentinel accepted"),
        };
        assert_eq!(accepted.0.transaction_id, u16::from_be_bytes(*b"bb") as u32);
        assert_eq!(accepted.1, sender_addr);
    }

    let mut trailing = ping(b"aa");
    trailing.push(b'X');
    let mut truncated = ping(b"aa");
    truncated.pop();
    for malformed in [trailing, truncated] {
        assert!(Message::from_bytes(&malformed).is_err());
        sender
            .send_to(&malformed, destination)
            .expect("send malformed datagram");
        sender
            .send_to(&ping(b"bb"), destination)
            .expect("send valid sentinel");
        let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
            .await
            .expect("receive rejection or sentinel");
        let accepted = match first {
            Some(message) => message,
            None => tokio::time::timeout(Duration::from_secs(1), receiver.recv_from())
                .await
                .expect("receive sentinel after discarded datagram")
                .expect("valid sentinel accepted"),
        };
        assert_eq!(accepted.0.transaction_id, u16::from_be_bytes(*b"bb") as u32);
        assert_eq!(accepted.1, sender_addr);
    }
}
