#[path = "relay_fixture.rs"]
mod relay_fixture;

use super::*;
use crate::network::{ALPN, Session};
use iroh::{
    EndpointAddr, TransportAddr,
    endpoint::{QuicTransportConfig, presets},
};
use std::time::Duration;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, UdpSocket},
};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}
fn public(identity: &Identity) -> PublicKey {
    identity.transport_key().public()
}

#[tokio::test(flavor = "current_thread")]
async fn native_app_and_both_joined_backends_close_with_sessions_and_factories_retained() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let a = Identity::generate();
        let b = Identity::generate();
        let client =
            SignaledEndpoint::bind(&a, loopback(), loopback(), &[public(&b)], Limits::default())
                .await
                .unwrap();
        let mut server =
            SignaledEndpoint::bind(&b, loopback(), loopback(), &[public(&a)], Limits::default())
                .await
                .unwrap();
        let native = [client.local_addr(), server.local_addr()];
        let signaling = [client.signaling_addr(), server.signaling_addr()];
        let retained = client.signaling.factory.clone();
        let (control, control_accepted) = tokio::join!(
            client.connect_signaling(server.id(), server.signaling_addr()),
            server.accept()
        );
        let (control, control_accepted) = (control.unwrap(), control_accepted.unwrap());
        assert_eq!(control.peer_id(), server.id());
        assert_eq!(control_accepted.peer_id(), client.id());
        let (connected, accepted) = tokio::join!(
            client.connect(server.id(), server.local_addr()),
            server.accept()
        );
        let (connected, accepted) = (connected.unwrap(), accepted.unwrap());
        let payload = b"native APP while signaling ownership is installed";
        let send = async {
            let (mut send, mut receive) = connected.connection.open_bi().await.unwrap();
            send.write_all(payload).await.unwrap();
            send.finish().unwrap();
            assert_eq!(receive.read_to_end(1024).await.unwrap(), payload);
        };
        let receive = async {
            let (mut send, mut receive) = accepted.connection.accept_bi().await.unwrap();
            let bytes = receive.read_to_end(1024).await.unwrap();
            assert_eq!(bytes, payload);
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
        };
        tokio::join!(send, receive);
        let (a_closed, b_closed) = tokio::join!(client.close(), server.close());
        a_closed.unwrap();
        b_closed.unwrap();
        for address in native {
            let _rebound = UdpSocket::bind(address).await.unwrap();
        }
        for address in signaling {
            let _rebound = TcpListener::bind(address).await.unwrap();
        }
        assert!(
            retained
                .peer_address(peer_id(&public(&b)).unwrap())
                .is_err()
        );
        drop((control, control_accepted, connected, accepted));
    })
    .await
    .expect("signed SDK native APP/joined shutdown deadline");
}

/// cancel-safe: NO — the fixture retains its owner until explicit Iroh and carrier close.
async fn custom_client(owner: &Owned, identity: &Identity) -> iroh::Endpoint {
    iroh::Endpoint::builder(presets::Minimal)
        .secret_key(identity.transport_key())
        .alpns(vec![ALPN.to_vec()])
        .clear_ip_transports()
        .clear_relay_transports()
        .add_custom_transport(owner.factory.clone())
        .transport_config(
            QuicTransportConfig::builder()
                .application_data_filter(|_| false)
                .build(),
        )
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn actual_custom_source_must_match_final_tls_key_even_when_both_keys_are_allowed() {
    tokio::time::timeout(Duration::from_secs(35), async {
        for mismatch in [false, true] {
            let a = Identity::generate();
            let b = Identity::generate();
            let d = Identity::generate();
            let mut server = SignaledEndpoint::bind(
                &b,
                loopback(),
                loopback(),
                &[public(&a), public(&d)],
                Limits::default(),
            )
            .await
            .unwrap();
            let owner = Owned::start(&a, loopback(), &[public(&b)]).unwrap();
            owner.ready().await.unwrap();
            let remote = peer_id(&public(&b)).unwrap();
            owner
                .handle
                .connect(remote, server.signaling_addr())
                .await
                .unwrap();
            let factory = owner.factory.clone();
            let address = owner.factory.peer_address(remote).unwrap();
            let claimed = if mismatch { &d } else { &a };
            let client = custom_client(&owner, claimed).await;
            assert!(
                client.bound_sockets().is_empty(),
                "custom source proof requires no native client shortcut"
            );
            let target = EndpointAddr::from_parts(server.id(), [TransportAddr::Custom(address)]);
            let (connected, accepted) = tokio::join!(client.connect(target, ALPN), server.accept());
            let accepted: Option<Session> = if mismatch {
                assert!(matches!(accepted, Err(NetworkError::PeerMismatch)));
                None
            } else {
                let accepted = accepted.unwrap();
                assert_eq!(accepted.peer_id(), public(&a));
                assert_eq!(connected.as_ref().unwrap().remote_id(), public(&b));
                Some(accepted)
            };
            // A client error is not the rejection oracle; the SDK's typed source mismatch is.
            client.close().await;
            owner.close().await.unwrap();
            server.close().await.unwrap();
            assert!(factory.peer_address(remote).is_err());
            drop((connected, accepted));
        }
    })
    .await
    .expect("actual carrier source/TLS identity binding deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn sdk_negotiates_through_an_owned_relay_and_revokes_leases_on_joined_close() {
    tokio::time::timeout(Duration::from_secs(35), async {
        let relay = relay_fixture::RelayFixture::start().await;
        let a = Identity::generate();
        let b = Identity::generate();
        let client =
            SignaledEndpoint::bind(&a, loopback(), loopback(), &[public(&b)], Limits::default())
                .await
                .unwrap();
        let mut server =
            SignaledEndpoint::bind(&b, loopback(), loopback(), &[public(&a)], Limits::default())
                .await
                .unwrap();
        let udp = [client.local_addr(), server.local_addr()];
        let tcp = [client.signaling_addr(), server.signaling_addr()];
        let lease = server.reserve_relay(relay.address).await.unwrap();
        let leases = server.relay_leases();
        assert_eq!(leases.borrow().as_slice(), &[lease]);
        // The caller supplies only the relay, never the destination's direct TCP address.
        let (connected, accepted) = tokio::join!(
            client.connect_via(server.id(), relay.address),
            server.accept()
        );
        let (connected, accepted) = (connected.unwrap(), accepted.unwrap());
        assert_eq!(connected.peer_id(), server.id());
        assert_eq!(accepted.peer_id(), client.id());
        let (a_closed, b_closed) = tokio::join!(client.close(), server.close());
        a_closed.unwrap();
        b_closed.unwrap();
        assert!(leases.borrow().is_empty());
        for address in udp {
            let _rebound = UdpSocket::bind(address).await.unwrap();
        }
        for address in tcp {
            let _rebound = TcpListener::bind(address).await.unwrap();
        }
        relay.close().await;
        drop((connected, accepted));
    })
    .await
    .expect("SDK owned relay/bootstrap/joined resource deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn startup_rejects_excess_input_and_failed_native_bind_joins_the_signaling_owner() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let identity = Identity::generate();
        let peer = public(&Identity::generate());
        let error = SignaledEndpoint::bind(&identity, loopback(), "127.0.0.1:20052".parse().unwrap(), &[peer; 17], Limits::default()).await.unwrap_err();
        assert!(matches!(error, NetworkError::Signaling(ref error) if error.kind() == std::io::ErrorKind::WouldBlock));
        let _not_started = TcpListener::bind("127.0.0.1:20052").await.unwrap();
        let busy = UdpSocket::bind(loopback()).await.unwrap();
        let error = SignaledEndpoint::bind(&identity, busy.local_addr().unwrap(), "127.0.0.1:20051".parse().unwrap(), &[], Limits::default()).await.unwrap_err();
        assert!(matches!(error, NetworkError::Bind(_)));
        let _joined_rebind = TcpListener::bind("127.0.0.1:20051").await.unwrap();
    }).await.expect("failed startup joined signaling cleanup deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_of_an_admitted_control_handshake_does_not_defeat_explicit_joined_close() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let identity = Identity::generate();
        let remote = public(&Identity::generate());
        let endpoint = SignaledEndpoint::bind(&identity, loopback(), loopback(), &[remote], Limits::default()).await.unwrap();
        let native = endpoint.local_addr();
        let signaling = endpoint.signaling_addr();
        let listener = TcpListener::bind(loopback()).await.unwrap();
        let mut held = {
            let connect = endpoint.connect_signaling(remote, listener.local_addr().unwrap());
            tokio::pin!(connect);
            tokio::select! {
                accepted = listener.accept() => accepted.unwrap().0,
                _ = &mut connect => panic!("control handshake finished without the fixture responding"),
            }
        };
        endpoint.close().await.unwrap();
        let _udp = UdpSocket::bind(native).await.unwrap();
        let _tcp = TcpListener::bind(signaling).await.unwrap();
        let mut bytes = [0; 4096];
        let mut eof = false;
        for _ in 0..8 {
            match held.read(&mut bytes).await {
                Ok(0) => { eof = true; break; }
                Ok(_) => {}
                Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => { eof = true; break; }
                Err(error) => panic!("unexpected TCP closure observation: {error}"),
            }
        }
        assert!(eof, "joined close left the admitted TCP negotiation alive");
    }).await.expect("cancelled control operation joined close deadline");
}
