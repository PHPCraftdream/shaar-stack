use super::*;
use crate::network::{Allowlist, Endpoint, Limits};
use shaar_p2p::Datagram;
use std::{error::Error, time::Duration};
use tokio::{sync::oneshot, task::JoinSet};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[test]
fn both_transport_keys_match_and_cross_verify_without_exposing_a_seed() {
    let identity = Identity::generate();
    let other = Identity::generate();
    let key = identity.signaling_key().unwrap();
    assert_eq!(
        key.public().to_peer_id().to_bytes(),
        identity.peer_id_bytes()
    );
    assert_eq!(
        peer_id(&identity.transport_key().public()).unwrap(),
        key.public().to_peer_id()
    );
    assert_eq!(format!("{identity:?}"), "Identity(..)");
    let message = b"shaar identity bridge test";
    let signature = key.sign(message).unwrap();
    let signature = iroh_base::Signature::try_from(signature.as_slice()).unwrap();
    assert!(
        identity
            .transport_key()
            .public()
            .verify(message, &signature)
            .is_ok()
    );
    assert!(
        other
            .transport_key()
            .public()
            .verify(message, &signature)
            .is_err()
    );
    assert!(
        identity
            .transport_key()
            .public()
            .verify(b"modified", &signature)
            .is_err()
    );
    let signature = identity.transport_key().sign(message);
    assert!(key.public().verify(message, &signature.to_bytes()));
    assert!(
        !other
            .signaling_key()
            .unwrap()
            .public()
            .verify(message, &signature.to_bytes())
    );
}

#[test]
fn signaling_construction_without_a_runtime_returns_a_typed_initialization_error() {
    let identity = Identity::generate();
    let Err(error) = bind_signaling(&identity, loopback(), &[]) else {
        panic!("signaling construction unexpectedly succeeded without a runtime");
    };
    assert!(matches!(error, NetworkError::Signaling(_)));
    assert_eq!(error.to_string(), "signaling carrier initialization failed");
    assert!(error.source().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn input_count_is_bounded_before_deduplication_and_owned_run_joins() {
    let identity = Identity::generate();
    let peer = Identity::generate().transport_key().public();
    let Err(error) = bind_signaling(&identity, loopback(), &[peer; 17]) else {
        panic!("oversized signaling allowlist was accepted");
    };
    assert!(
        matches!(error, NetworkError::Signaling(ref error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    let (owner, handle, _incoming) = bind_signaling(&identity, loopback(), &[peer; 16]).unwrap();
    assert_eq!(handle.peer_id().to_bytes(), identity.peer_id_bytes());
    owner.run(async {}).await.unwrap();
    assert!(handle.local_addr().await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn real_noise_carriers_and_native_endpoints_use_the_same_sdk_identities() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let a = Identity::generate();
        let b = Identity::generate();
        let other = Identity::generate();
        let pa = a.transport_key().public();
        let pb = b.transport_key().public();
        let unknown = other.transport_key().public();
        let wrong_client = Identity::generate();
        let wrong_public = wrong_client.transport_key().public();
        let native_a = Endpoint::bind(
            &a,
            loopback(),
            Allowlist::new(&[pb]).unwrap(),
            Limits::default(),
        )
        .await
        .unwrap();
        let native_b = Endpoint::bind(
            &b,
            loopback(),
            Allowlist::new(&[pa]).unwrap(),
            Limits::default(),
        )
        .await
        .unwrap();
        let (a_owner, ah, mut a_in) = bind_signaling(&a, loopback(), &[pb]).unwrap();
        let (b_owner, bh, mut b_in) = bind_signaling(&b, loopback(), &[pa, wrong_public]).unwrap();
        let (wrong_owner, wrong_handle, _wrong_in) =
            bind_signaling(&wrong_client, loopback(), &[unknown]).unwrap();
        assert_eq!(peer_id(&native_a.id()).unwrap(), ah.peer_id());
        assert_eq!(peer_id(&native_b.id()).unwrap(), bh.peer_id());
        let mut tasks = JoinSet::new();
        let mut stops = Vec::with_capacity(3);
        for owner in [a_owner, b_owner, wrong_owner] {
            let (stop, stopped) = oneshot::channel();
            stops.push(stop);
            tasks.spawn(owner.run(async {
                let _ = stopped.await;
            }));
        }
        let a_address = ah.local_addr().await.unwrap();
        let b_address = bh.local_addr().await.unwrap();
        let wrong_address = wrong_handle.local_addr().await.unwrap();
        // A separate allowed client avoids racing its failed connection against the positive link.
        // Its incorrect server pin must fail actual Noise, not the server's application allowlist.
        assert!(
            wrong_handle
                .connect(peer_id(&unknown).unwrap(), b_address)
                .await
                .is_err()
        );
        ah.connect(bh.peer_id(), b_address).await.unwrap();
        ah.send(bh.peer_id(), Datagram::new(b"same SDK identity").unwrap())
            .await
            .unwrap();
        let received = b_in.recv().await.unwrap();
        assert_eq!(received.peer.to_bytes(), a.peer_id_bytes());
        assert!(bh.is_current(&received));
        assert_eq!(received.packet.as_bytes(), b"same SDK identity");
        bh.send(ah.peer_id(), received.packet).await.unwrap();
        let received = a_in.recv().await.unwrap();
        assert_eq!(received.peer.to_bytes(), b.peer_id_bytes());
        assert_eq!(received.packet.as_bytes(), b"same SDK identity");
        for stop in stops {
            stop.send(()).unwrap();
        }
        let mut joined = 0;
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
            joined += 1;
        }
        assert_eq!(joined, 3);
        assert!(ah.local_addr().await.is_err());
        assert!(bh.local_addr().await.is_err());
        let _a_rebound = tokio::net::TcpListener::bind(a_address).await.unwrap();
        let _b_rebound = tokio::net::TcpListener::bind(b_address).await.unwrap();
        let _wrong_rebound = tokio::net::TcpListener::bind(wrong_address).await.unwrap();
        native_a.close().await;
        native_b.close().await;
    })
    .await
    .expect("same SDK identity native/Noise proof deadline");
}
