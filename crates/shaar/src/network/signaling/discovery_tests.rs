use super::super::bind_signaling_with_discovery;
use super::*;
use libp2p_identity::PeerId;
use std::{io, time::Duration};
use tokio::net::{TcpListener, UdpSocket};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn public(identity: &Identity) -> PublicKey {
    identity.transport_key().public()
}

fn seed(identity: &Identity) -> PeerId {
    PeerId::from_bytes(&identity.peer_id_bytes()).unwrap()
}

fn config(peer: PeerId, nameserver: SocketAddr) -> DiscoveryConfig {
    DiscoveryConfig::new(
        vec![(peer, "/dns4/owned.example./tcp/4001".parse().unwrap())],
        vec![nameserver],
    )
    .unwrap()
}

/// cancel-safe: yes — a losing UDP receive does not consume a datagram.
async fn question(server: &UdpSocket) -> SocketAddr {
    let mut bytes = [0; 512];
    let (length, source) = server.recv_from(&mut bytes).await.unwrap();
    let name = b"\x05owned\x07example\x00";
    assert!(length >= 12);
    assert!(
        bytes[..length]
            .windows(name.len())
            .any(|window| window.eq_ignore_ascii_case(name))
    );
    source
}

#[test]
fn configured_discovery_without_runtime_returns_typed_initialization_error() {
    let identity = Identity::generate();
    let remote = Identity::generate();
    let result = bind_signaling_with_discovery(
        &identity,
        loopback(),
        &[],
        config(seed(&remote), "127.0.0.1:53".parse().unwrap()),
    );
    assert!(
        matches!(result, Err(NetworkError::Signaling(ref error)) if error.kind() == io::ErrorKind::Other)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn configured_identity_conflicts_and_peer_limit_fail_before_socket_binding() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let identity = Identity::generate();
        let app = Identity::generate();
        let remote = Identity::generate();
        let occupied = TcpListener::bind(loopback()).await.unwrap();
        let address = occupied.local_addr().unwrap();
        let cases = [
            (seed(&identity), vec![], io::ErrorKind::InvalidInput),
            (seed(&app), vec![public(&app)], io::ErrorKind::InvalidInput),
            (seed(&remote), vec![public(&identity)], io::ErrorKind::InvalidInput),
            (seed(&remote), vec![public(&app); 17], io::ErrorKind::WouldBlock),
        ];
        for (peer, peers, expected) in cases {
            let result = SignaledEndpoint::bind_with_discovery(
                &identity, loopback(), address, &peers, Limits::default(),
                config(peer, "127.0.0.1:53".parse().unwrap()),
            ).await;
            assert!(matches!(result, Err(NetworkError::Signaling(ref error)) if error.kind() == expected),
                "invalid discovery input did not precede occupied signaling listener: {result:?}");
        }
        drop(occupied);
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn configured_and_default_endpoints_keep_identity_and_join_with_factories_retained() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dns = UdpSocket::bind(loopback()).await.unwrap();
        let remote = Identity::generate();
        for configured in [false, true] {
            let identity = Identity::generate();
            let endpoint = if configured {
                SignaledEndpoint::bind_with_discovery(
                    &identity, loopback(), loopback(), &[], Limits::default(),
                    config(seed(&remote), dns.local_addr().unwrap()),
                ).await.unwrap()
            } else {
                SignaledEndpoint::bind(&identity, loopback(), loopback(), &[], Limits::default()).await.unwrap()
            };
            assert_eq!(endpoint.id(), public(&identity));
            assert_eq!(endpoint.signaling.handle.peer_id().to_bytes(), identity.peer_id_bytes());
            assert!(endpoint.relay_leases().borrow().is_empty());
            assert!(endpoint.signaling.handle.links().borrow().is_empty());
            let mut buffer = [0; 512];
            assert!(matches!(dns.try_recv_from(&mut buffer), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock),
                "startup issued DNS before explicit discovery");
            if !configured {
                assert!(matches!(endpoint.discover_relays().await,
                    Err(NetworkError::SignalingOperation(ref error)) if error.kind() == io::ErrorKind::InvalidInput));
            }
            let native = endpoint.local_addr();
            let signaling = endpoint.signaling_addr();
            let retained = endpoint.signaling.factory.clone();
            let handle = endpoint.signaling.handle.clone();
            endpoint.close().await.unwrap();
            assert!(handle.local_addr().await.is_err());
            drop(TcpListener::bind(signaling).await.unwrap());
            drop(UdpSocket::bind(native).await.unwrap());
            drop((retained, handle));
        }
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn configured_endpoint_explicit_discovery_uses_owned_dns_and_joins_after_waiter_cancel() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dns = UdpSocket::bind(loopback()).await.unwrap();
        let identity = Identity::generate();
        let remote = Identity::generate();
        let endpoint = SignaledEndpoint::bind_with_discovery(
            &identity, loopback(), loopback(), &[], Limits::default(),
            config(seed(&remote), dns.local_addr().unwrap()),
        ).await.unwrap();
        let native = endpoint.local_addr();
        let signaling = endpoint.signaling_addr();
        let retained = endpoint.signaling.factory.clone();
        let dns_client = {
            let discovery = endpoint.discover_relays();
            tokio::pin!(discovery);
            tokio::select! {
                source = question(&dns) => source,
                result = &mut discovery => panic!("discovery completed before the held DNS question: {result:?}"),
            }
        };
        assert!(endpoint.signaling.handle.links().borrow().is_empty());
        endpoint.close().await.unwrap();
        drop(TcpListener::bind(signaling).await.unwrap());
        drop(UdpSocket::bind(native).await.unwrap());
        drop(UdpSocket::bind(dns_client).await.unwrap());
        drop(retained);
    }).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn configured_owner_close_joins_discovery_with_waiter_and_factory_retained() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dns = UdpSocket::bind(loopback()).await.unwrap();
        let identity = Identity::generate();
        let remote = Identity::generate();
        let owner = Owned::start(
            &identity, loopback(), &[], Some(config(seed(&remote), dns.local_addr().unwrap())),
        ).unwrap();
        let signaling = owner.ready().await.unwrap();
        let retained = owner.factory.clone();
        let handle = owner.handle.clone();
        let discovery = handle.discover_relays();
        tokio::pin!(discovery);
        let dns_client = tokio::select! {
            source = question(&dns) => source,
            result = &mut discovery => panic!("discovery completed before the held DNS question: {result:?}"),
        };
        let (closed, discovered) = tokio::join!(owner.close(), &mut discovery);
        closed.unwrap();
        assert!(discovered.is_err());
        assert!(handle.local_addr().await.is_err());
        drop(TcpListener::bind(signaling).await.unwrap());
        drop(UdpSocket::bind(dns_client).await.unwrap());
        drop((retained, handle));
    }).await.unwrap();
}
