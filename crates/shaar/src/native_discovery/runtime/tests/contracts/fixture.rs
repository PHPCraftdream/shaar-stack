// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use iroh_base::{EndpointId, SecretKey, TransportAddr};
use iroh_dns::endpoint_info::EndpointInfo;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};
use tokio::net::UdpSocket;

/// Owned numeric loopback UDP fixture. Receive detects datagrams larger than 2048 bytes.
pub(super) struct OwnedUdpPeer {
    socket: Arc<UdpSocket>,
}
impl OwnedUdpPeer {
    pub(super) async fn bind_loopback() -> std::io::Result<Self> {
        Ok(Self {
            socket: Arc::new(
                UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).await?,
            ),
        })
    }
    pub(super) fn destination(&self) -> SocketAddr {
        self.socket.local_addr().expect("owned fixture socket")
    }
    pub(super) fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }
    pub(super) async fn recv(&self) -> std::io::Result<DatagramReceipt> {
        let mut bytes = vec![0; 2049];
        let (length, source) = self.socket.recv_from(&mut bytes).await?;
        if length > 2048 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "oversized fixture datagram",
            ));
        }
        bytes.truncate(length);
        Ok(DatagramReceipt {
            source,
            destination: self.destination(),
            bytes,
        })
    }
    pub(super) async fn try_recv(&self) -> std::io::Result<DatagramReceipt> {
        let mut bytes = vec![0; 2049];
        let (length, source) = self.socket.try_recv_from(&mut bytes)?;
        if length > 2048 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "oversized fixture datagram",
            ));
        }
        bytes.truncate(length);
        Ok(DatagramReceipt {
            source,
            destination: self.destination(),
            bytes,
        })
    }
}
pub(super) struct DatagramReceipt {
    pub(super) source: SocketAddr,
    pub(super) destination: SocketAddr,
    pub(super) bytes: Vec<u8>,
}

/// Existing upstream high-level encoder, preserving the ordinary current-time path.
pub(super) fn encode(
    secret: &SecretKey,
    addresses: Vec<SocketAddr>,
) -> iroh_dns::pkarr::SignedPacket {
    EndpointInfo::new(peer(secret))
        .with_ip_addrs(addresses)
        .to_pkarr_signed_packet(secret, 30)
        .expect("upstream signed DNS encoder")
}
/// Proposed narrow timestamped upstream test helper; time unit is Unix microseconds.
pub(super) fn encode_at(
    secret: &SecretKey,
    timestamp_us: u64,
    addresses: Vec<SocketAddr>,
) -> iroh_dns::pkarr::SignedPacket {
    EndpointInfo::new(peer(secret))
        .with_ip_addrs(addresses)
        .to_pkarr_signed_packet_at(secret, 30, timestamp_us)
        .expect("timestamped upstream signed DNS encoder")
}
pub(super) fn record(
    secret: &SecretKey,
    sequence_and_timestamp_us: u64,
    address: SocketAddr,
) -> Vec<u8> {
    encode_at(secret, sequence_and_timestamp_us, vec![address])
        .as_bytes()
        .to_vec()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InvalidRecord {
    WrongKey,
    CorruptSignature,
    Oversize,
    Truncated,
    ByteFlipped,
    Stale,
    TooFarFuture,
    Empty,
}
/// Build malformed samples only by legitimate upstream encoding and narrow byte mutations.
pub(super) fn invalid_record(
    secret: &SecretKey,
    kind: InvalidRecord,
    wall_us: u64,
    address: SocketAddr,
) -> Vec<u8> {
    let timestamp = match kind {
        InvalidRecord::Stale => wall_us
            .checked_sub(300_000_001)
            .expect("stale timestamp range"),
        InvalidRecord::TooFarFuture => wall_us + 30_000_001,
        _ => wall_us,
    };
    let foreign = indexed_key(99);
    let signing_key = if kind == InvalidRecord::WrongKey {
        &foreign
    } else {
        secret
    };
    let mut bytes = record(signing_key, timestamp, address);
    match kind {
        InvalidRecord::CorruptSignature => bytes[32] ^= 1,
        InvalidRecord::Oversize => bytes = vec![0; 1105],
        InvalidRecord::Truncated => bytes.truncate(103),
        InvalidRecord::ByteFlipped => {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        InvalidRecord::Empty => bytes.clear(),
        InvalidRecord::WrongKey | InvalidRecord::Stale | InvalidRecord::TooFarFuture => {}
    }
    bytes
}
pub(super) fn peer(secret: &SecretKey) -> EndpointId {
    EndpointId::from_bytes(secret.public().as_bytes()).expect("public key")
}
pub(super) fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}
pub(super) fn indexed_key(index: u64) -> SecretKey {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&index.to_le_bytes());
    bytes[8] = 0xa7;
    SecretKey::from_bytes(&bytes)
}
pub(super) fn address(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}
pub(super) fn signed_timestamp(bytes: &[u8]) -> u64 {
    iroh_dns::pkarr::SignedPacket::from_bytes(bytes)
        .expect("actual signed PUT packet")
        .timestamp()
        .as_micros()
}

// Intentionally unresolved until the separately reviewed private production adapter is attached.
pub(super) use super::super::test_support::{
    AdmissionBarrier, AdmissionReceipt, Barrier, BootstrapAudit, BootstrapError, CapacityError,
    CleanupBarrier, ClockSample, CloseError, DialReceipt, EgressOutcome, EgressReceipt,
    EventReceipt, HoldPoint, IngressReceipt, OperationReceipt, PeerInspection, Probe, PublishAck,
    PublishError, PutReceipt, PutReply, QueryBarrier, QueryReceipt, RequestHandle, RetryReceipt,
    RpcEvent, RpcOutcome, RpcReceipt, RuntimeError, SendBarrier, Snapshot, TestClock, TestOwner,
};
pub(super) use crate::native_discovery::address::{
    SnapshotError, validate_addresses as validate_snapshot,
};
