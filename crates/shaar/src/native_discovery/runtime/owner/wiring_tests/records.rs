// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::endpoint::NativeEndpointError;
use super::super::endpoint_key;
use super::super::tests::fixture::LoopbackPeer;
use super::connect::{now_us, signed_record, signed_record_at};
use super::{bind, free_port, options, peer_v4};
use crate::identity::Identity;
use iroh_base::{RelayUrl, TransportAddr};
use iroh_dns::endpoint_info::{EndpointData, EndpointInfo};
use n0_mainline::MutableItem;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// A validly signed record that also claims a relay: native records admit only IP addresses.
fn relay_claim_record(identity: &Identity, address: SocketAddr) -> MutableItem {
    let relay: RelayUrl = "https://example.com".parse().expect("relay URL");
    let packet = EndpointInfo::from_parts(
        endpoint_key(identity).expect("key"),
        EndpointData::new(vec![
            TransportAddr::Ip(address),
            TransportAddr::Relay(relay),
        ]),
    )
    .to_pkarr_signed_packet(&identity.transport_key(), 30)
    .expect("signed record");
    let sequence = i64::try_from(packet.timestamp().as_micros()).expect("sequence");
    MutableItem::new_signed_unchecked(
        *packet.public_key().as_bytes(),
        packet.signature().to_bytes(),
        packet.encoded_packet(),
        sequence,
        None,
    )
}

/// True when no datagram reaches the socket within a short window.
async fn silent(socket: &UdpSocket) -> bool {
    let mut buffer = [0u8; 2048];
    tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buffer))
        .await
        .is_err()
}

#[tokio::test]
async fn invalid_records_never_start_a_dial_and_a_valid_record_does() {
    let mut peer = LoopbackPeer::bind().await;
    let mut client = bind(
        free_port().await,
        options(free_port().await, peer_v4(&peer)),
    )
    .await
    .expect("client binds");
    // Every record advertises this socket, so any dial shows up as a datagram here.
    let capture = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("capture socket binds");
    let address = capture.local_addr().expect("capture address");
    let hostile = [
        (
            "stale",
            0x71u8,
            signed_record_at(
                &Identity::from_seed([0x71; 32]),
                address,
                now_us() - 400_000_000,
            ),
        ),
        (
            "future",
            0x72,
            signed_record_at(
                &Identity::from_seed([0x72; 32]),
                address,
                now_us() + 60_000_000,
            ),
        ),
        (
            "relay claim",
            0x73,
            relay_claim_record(&Identity::from_seed([0x73; 32]), address),
        ),
    ];
    for (label, seed, item) in &hostile {
        let key = endpoint_key(&Identity::from_seed([*seed; 32])).expect("key");
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = tokio::select! {
            result = client.connect_until(key, deadline) => result,
            _ = peer.serve_record(item) => unreachable!("the record server runs until the connect finishes"),
        };
        assert!(
            matches!(result, Err(NativeEndpointError::Runtime(_))),
            "{label} record must be rejected by resolution"
        );
        assert!(
            silent(&capture).await,
            "{label} record must not start any dial"
        );
    }

    // Positive control: the same capture socket does observe the dial for a valid record.
    let valid = Identity::from_seed([0x74; 32]);
    let key = endpoint_key(&valid).expect("key");
    let item = signed_record(&valid, address);
    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    tokio::select! {
        _ = client.connect_until(key, deadline) => panic!("nothing answers at the capture socket, so the dial cannot complete"),
        _ = peer.serve_record(&item) => unreachable!("the record server runs until the connect finishes"),
        received = capture.recv_from(&mut buffer) => {
            received.expect("a QUIC datagram reached the advertised address");
        }
    }
    client.close().await.expect("client backends joined");
}
