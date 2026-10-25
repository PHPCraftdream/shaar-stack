#![forbid(unsafe_code)]
//! Owned real relay topology; no public infrastructure or direct destination shortcut.

mod fixture;

use fixture::{Group, config, unknown_peer};
use shaar_p2p::{Datagram, RelayAddr, Route};
use std::{io, time::Duration};

#[tokio::test(flavor = "current_thread")]
async fn actual_relay_packets_are_pinned_exact_bounded_reused_and_reopened() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let mut group = Group::start(config()).await;
        let lease = group.b.reserve(group.relay).await.unwrap();
        assert_eq!(lease.relay(), group.relay);
        let snapshots = group.b.relay_leases();
        assert_eq!(snapshots.borrow().as_slice(), &[lease]);
        assert_eq!(group.b.reserve(group.relay).await.unwrap(), lease);
        let connection = group.a.connect_via(group.b.peer_id(), group.relay).await.unwrap();
        let links = group.a.links();
        assert_eq!(links.borrow().len(), 1);
        assert_eq!(links.borrow()[0].connection, connection);
        assert!(matches!(links.borrow()[0].route, Route::Relayed { relay: Some(peer), .. } if peer == group.relay.peer_id()));
        let mut changed_endpoint = group.relay.socket_addr();
        changed_endpoint.set_port(if changed_endpoint.port() == 1 { 2 } else { 1 });
        let changed_relay = RelayAddr::new(group.relay.peer_id(), changed_endpoint).unwrap();
        assert_eq!(group.a.connect_via(group.b.peer_id(), changed_relay).await.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        let mut first_generation = None;
        for bytes in [&[7_u8][..], &[9_u8; shaar_p2p::MAX_DATAGRAM][..]] {
            group.a.send(group.b.peer_id(), Datagram::new(bytes).unwrap()).await.unwrap();
            let received = group.b_in.recv().await.unwrap();
            assert_eq!(received.peer, group.a.peer_id());
            assert!(group.b.is_current(&received));
            assert_eq!(received.packet.as_bytes(), bytes);
            assert!(matches!(received.route, Route::Relayed { relay: None, .. }));
            group.b.send(group.a.peer_id(), received.packet).await.unwrap();
            let received = group.a_in.recv().await.unwrap();
            assert_eq!(received.peer, group.b.peer_id());
            assert_eq!(received.connection, connection);
            assert!(group.a.is_current(&received));
            assert_eq!(received.packet.as_bytes(), bytes);
            let Route::Relayed { relay: Some(relay), generation } = received.route else { panic!("no actual relay route"); };
            assert_eq!(relay, group.relay.peer_id());
            if let Some(previous) = first_generation { assert_eq!(generation, previous); } else { first_generation = Some(generation); }
            assert_eq!(group.a.connect_via(group.b.peer_id(), group.relay).await.unwrap(), connection);
        }
        assert_eq!(group.a.send(group.relay.peer_id(), Datagram::new(b"not an application peer").unwrap()).await.unwrap_err().kind(), io::ErrorKind::NotConnected);
        assert_eq!(group.a.connect_via(unknown_peer(), group.relay).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        group.wait_counts(|counts| counts.circuits >= 1).await;
        group.a.disconnect(group.b.peer_id()).await.unwrap();
        assert!(links.borrow().is_empty());
        group.b.disconnect(group.a.peer_id()).await.unwrap();
        let reopened = group.a.connect_via(group.b.peer_id(), group.relay).await.unwrap();
        assert_ne!(reopened, connection);
        // Local dial completion is not the remote driver's connection-established barrier.
        group.a.send(group.b.peer_id(), Datagram::new(b"reopened readiness").unwrap()).await.unwrap();
        let ready = group.b_in.recv().await.unwrap();
        assert_eq!(ready.peer, group.a.peer_id());
        assert_eq!(ready.packet.as_bytes(), b"reopened readiness");
        group.b.send(group.a.peer_id(), Datagram::new(b"new generation").unwrap()).await.unwrap();
        let received = group.a_in.recv().await.unwrap();
        assert_eq!(received.packet.as_bytes(), b"new generation");
        assert!(matches!(received.route, Route::Relayed { generation, .. } if Some(generation) != first_generation));
        group.b.release_relay(group.relay.peer_id()).await.unwrap();
        assert!(snapshots.borrow().is_empty());
        group.close().await;
        assert!(links.borrow().is_empty());
    }).await.expect("owned relay exact/reopen deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn a_real_reservation_renews_without_extending_an_old_snapshot_or_generation() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut settings = config();
        settings.reservation_duration = Duration::from_secs(8);
        let group = Group::start(settings).await;
        let initial = group.b.reserve(group.relay).await.unwrap();
        let mut snapshots = group.b.relay_leases();
        loop {
            let renewed = snapshots.borrow_and_update().first().copied();
            if let Some(renewed) = renewed {
                assert_eq!(renewed.generation(), initial.generation());
                assert_eq!(renewed.connection_id(), initial.connection_id());
                if renewed.expires_at() > initial.expires_at() {
                    break;
                }
            }
            snapshots.changed().await.unwrap();
        }
        group.wait_counts(|counts| counts.renewed >= 1).await;
        group.b.release_relay(group.relay.peer_id()).await.unwrap();
        assert!(snapshots.borrow().is_empty());
        group.close().await;
    })
    .await
    .expect("actual reservation renewal deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn refusal_never_publishes_a_lease_and_retry_is_bounded_before_another_hop_request() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut settings = config();
        settings.max_reservations = 0;
        let group = Group::start(settings).await;
        assert!(group.b.reserve(group.relay).await.is_err());
        assert!(group.b.relay_leases().borrow().is_empty());
        assert_eq!(
            group.b.reserve(group.relay).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        group.wait_counts(|counts| counts.denied >= 1).await;
        assert_eq!(group.counts.borrow().denied, 1);
        group.b.release_relay(group.relay.peer_id()).await.unwrap();
        group.close().await;
    })
    .await
    .expect("reservation refusal/backoff deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn relay_loss_revokes_the_advertisement_before_the_old_lease_deadline() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut group = Group::start(config()).await;
        group.b.reserve(group.relay).await.unwrap();
        let mut snapshots = group.b.relay_leases();
        assert_eq!(snapshots.borrow().len(), 1);
        group.stop_relay();
        loop {
            let empty = snapshots.borrow_and_update().is_empty();
            if empty {
                break;
            }
            snapshots.changed().await.unwrap();
        }
        assert!(group.b.reserve(group.relay).await.is_err());
        group.b.release_relay(group.relay.peer_id()).await.unwrap();
        group.close().await;
    })
    .await
    .expect("relay loss advertisement revocation deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn a_real_relay_time_limit_closes_the_old_circuit_before_reopen() {
    tokio::time::timeout(Duration::from_secs(35), async {
        let mut settings = config();
        settings.max_circuit_duration = Duration::from_secs(8);
        let mut group = Group::start(settings).await;
        group.b.reserve(group.relay).await.unwrap();
        let first = group
            .a
            .connect_via(group.b.peer_id(), group.relay)
            .await
            .unwrap();
        group
            .a
            .send(
                group.b.peer_id(),
                Datagram::new(b"before time limit").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            group.b_in.recv().await.unwrap().packet.as_bytes(),
            b"before time limit"
        );
        group.wait_counts(|counts| counts.closed >= 1).await;
        group.a.disconnect(group.b.peer_id()).await.unwrap();
        group.b.disconnect(group.a.peer_id()).await.unwrap();
        let next = group
            .a
            .connect_via(group.b.peer_id(), group.relay)
            .await
            .unwrap();
        assert_ne!(next, first);
        group
            .a
            .send(
                group.b.peer_id(),
                Datagram::new(b"after time limit").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            group.b_in.recv().await.unwrap().packet.as_bytes(),
            b"after time limit"
        );
        group.close().await;
    })
    .await
    .expect("owned relay circuit time quota deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn application_and_relay_control_roles_cannot_be_confused() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let group = Group::start(config()).await;
        let application =
            RelayAddr::new(group.b.peer_id(), group.b.local_addr().await.unwrap()).unwrap();
        assert_eq!(
            group.a.reserve(application).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(group.a.relay_leases().borrow().is_empty());
        assert_eq!(group.counts.borrow().reserved, 0);
        group.close().await;
    })
    .await
    .expect("relay identity role separation deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn a_real_relay_byte_limit_closes_the_circuit_and_a_new_circuit_is_usable() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let mut settings = config();
        settings.max_circuit_bytes = 4096;
        let mut group = Group::start(settings).await;
        group.b.reserve(group.relay).await.unwrap();
        let first = group
            .a
            .connect_via(group.b.peer_id(), group.relay)
            .await
            .unwrap();
        group
            .a
            .send(
                group.b.peer_id(),
                Datagram::new(b"positive before quota").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            group.b_in.recv().await.unwrap().packet.as_bytes(),
            b"positive before quota"
        );
        let mut limited = false;
        for _ in 0..16 {
            if group
                .a
                .send(
                    group.b.peer_id(),
                    Datagram::new(&[3; shaar_p2p::MAX_DATAGRAM]).unwrap(),
                )
                .await
                .is_err()
            {
                limited = true;
                break;
            }
        }
        assert!(limited, "owned server byte quota was not sensitive");
        group.wait_counts(|counts| counts.closed >= 1).await;
        group.a.disconnect(group.b.peer_id()).await.unwrap();
        group.b.disconnect(group.a.peer_id()).await.unwrap();
        let next = group
            .a
            .connect_via(group.b.peer_id(), group.relay)
            .await
            .unwrap();
        assert_ne!(next, first);
        group
            .a
            .send(group.b.peer_id(), Datagram::new(b"after quota").unwrap())
            .await
            .unwrap();
        // Earlier whole datagrams may have been admitted before the terminal error.
        loop {
            let packet = group.b_in.recv().await.unwrap();
            if packet.packet.as_bytes() == b"after quota" {
                break;
            }
        }
        group.close().await;
    })
    .await
    .expect("owned relay circuit quota/reopen deadline");
}
