#![forbid(unsafe_code)]

mod support;
use libp2p::{multiaddr::Protocol, swarm::dial_opts::DialOpts};
use libp2p_relay::{
    client::OperationKind,
    wire_probe::{self as probe, Phase},
};
use std::time::Duration;
use support::Harness;

async fn scenario(phase: Phase) {
    println!("RELAY_WIRE_SOURCE_VARIANT={}", probe::BUILD_VARIANT);
    assert_eq!(
        probe::BUILD_VARIANT,
        env!("RELAY_WIRE_VARIANT"),
        "fixture binary/source mismatch"
    );
    probe::reset(phase);
    let mut harness = Harness::new().await;
    harness.stage(OperationKind::Reserve, 1);
    let address = harness.circuit_address();
    harness.client.listen_on(address).unwrap();
    harness
        .until(|h, p| h.accepted == 2 && h.server_accepted == 2 && p.reserve_serialized == 2)
        .await;
    assert_eq!(probe::snapshot().reserve_started, 2);
    assert!(harness.control.is_some());
    assert_eq!(harness.closed, 0);
    println!("RELAY_WIRE_POSITIVE_INITIAL_AND_AUTOMATIC_RENEWAL_SAME_CONTROL");
    let before = probe::snapshot();
    match phase {
        Phase::Protocol => {
            harness.arm_latest();
            harness.until(|_, p| p.blocked && p.negotiated == 3).await;
            assert_eq!(
                probe::snapshot().reserve_started,
                2,
                "barrier is after serialization"
            );
            println!("RELAY_WIRE_BARRIER_NEGOTIATED_BEFORE_PROTOCOL_ADMISSION");
            probe::release_protocol();
            harness.until(|_, p| p.resumed).await;
            assert_eq!(
                probe::snapshot().reserve_started,
                before.reserve_started,
                "PROTOCOL_POLL_AFTER_REVOCATION"
            );
        }
        Phase::Renewal => {
            harness.arm_latest();
            harness.until(|_, p| p.revoked).await;
            assert_eq!(
                probe::snapshot().requests,
                before.requests,
                "RENEWAL_REQUEST_AFTER_REVOCATION"
            );
        }
        Phase::Reuse => {
            let destination = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            harness.stage(OperationKind::Connect { destination }, 2);
            harness.arm_latest();
            let address = harness.circuit_address().with(Protocol::P2p(destination));
            harness
                .client
                .dial(
                    DialOpts::peer_id(destination)
                        .addresses(vec![address])
                        .build(),
                )
                .unwrap();
            harness.until(|_, p| p.revoked).await;
            assert_eq!(
                probe::snapshot().reuse,
                before.reuse,
                "CONNECTED_REUSE_AFTER_REVOCATION"
            );
        }
    }
    assert!(
        harness.client.is_connected(&harness.relay_peer),
        "disconnect masked revocation"
    );
    assert_eq!(
        harness.closed, 0,
        "ordinary disconnect ran before the gate assertion"
    );
    if phase != Phase::Reuse {
        harness.observe_next_renewal_window().await;
        assert_eq!(harness.accepted, 2, "REVOKED_LEASE_PUBLISHED");
        assert_eq!(
            harness.server_accepted, 2,
            "REVOKED_RESERVE_REACHED_OWNED_RELAY"
        );
        assert_eq!(
            probe::snapshot().reserve_serialized,
            2,
            "REVOKED_RESERVE_SERIALIZED"
        );
        assert_eq!(
            probe::snapshot().reserve_started,
            2,
            "FRESH_RENEWAL_AFTER_REVOCATION"
        );
    } else {
        harness
            .until(|h, _| h.accepted >= 3 && h.server_accepted >= 3)
            .await;
        assert_eq!(
            probe::snapshot().connect_started,
            0,
            "REVOKED_CONNECT_STARTED"
        );
        println!("RELAY_WIRE_INDEPENDENT_RESERVATION_SURVIVED");
    }
    harness.close().await;
    println!("RELAY_WIRE_JOINED_CLEANUP");
}

#[tokio::test(flavor = "current_thread")]
async fn relay_wire_protocol_poll_revocation() {
    tokio::time::timeout(Duration::from_secs(45), scenario(Phase::Protocol))
        .await
        .expect("owned relay protocol fixture outer deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn relay_wire_renewal_admission_revocation() {
    tokio::time::timeout(Duration::from_secs(45), scenario(Phase::Renewal))
        .await
        .expect("owned relay renewal fixture outer deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn relay_wire_connected_reuse_revocation() {
    tokio::time::timeout(Duration::from_secs(45), scenario(Phase::Reuse))
        .await
        .expect("owned relay reuse fixture outer deadline");
}
