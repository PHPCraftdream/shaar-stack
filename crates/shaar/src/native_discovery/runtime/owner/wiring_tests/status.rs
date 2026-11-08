// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use crate::identity::Identity;
use crate::native_discovery::runtime::owner::RuntimeOwner;
use crate::native_discovery::runtime::owner::wiring_tests::{LoopbackPeer, peer_v4};
use crate::native_discovery::runtime::publisher::PublicationStatus;
use iroh_base::TransportAddr;

#[tokio::test]
async fn actual_put_acknowledgment_and_withdrawal_drive_owner_readiness() {
    let mut peer = LoopbackPeer::bind().await;
    let mut owner = RuntimeOwner::start(
        Identity::from_seed([0x85; 32]),
        "127.0.0.1:0".parse().expect("bind"),
        &[peer_v4(&peer)],
    )
    .expect("owner starts");
    let mut request = Box::pin(owner.replace(vec![TransportAddr::Ip(
        "127.0.0.1:9001".parse().expect("address"),
    )]));
    let (source, transaction, _) = tokio::select! {
        held = peer.capture_put() => held,
        result = &mut request => panic!("PUT ended before held acknowledgment: {result:?}"),
    };
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Pending { .. }
    ));
    peer.acknowledge(source, &transaction).await;
    request.await.expect("actual PUT acknowledged");
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Published { .. }
    ));
    owner.withdraw().await.expect("local generation withdrawn");
    assert!(matches!(
        owner.publication_status(),
        PublicationStatus::Unavailable { .. }
    ));
    owner.close().await.expect("joined close");
}
