use super::*;
use crate::discovery::roles::{Owner, Role, Root};
use crate::dns::tests::support::*;
use futures::FutureExt;
use libp2p::{
    Multiaddr,
    multiaddr::Protocol,
    swarm::{DialError, dummy},
};
use std::io;
use tokio::time::Instant;
use tokio::{net::TcpListener, sync::oneshot, task::JoinSet};

fn key() -> Keypair {
    Keypair::generate_ed25519()
}
fn config(seed: PeerId, server: SocketAddr) -> DiscoveryConfig {
    DiscoveryConfig::new(
        vec![(seed, "/dns4/seed.example./tcp/4001".parse().unwrap())],
        vec![server],
    )
    .unwrap()
}

#[tokio::test]
async fn owned_dns_configured_constructor_preserves_numeric_app_packets_and_never_bootstraps() {
    bounded(
        async {
            let server = Server::new().await;
            let ka = key();
            let kb = key();
            let pa = ka.public().to_peer_id();
            let pb = kb.public().to_peer_id();
            let seed = key().public().to_peer_id();
            let (a, ah, _ar) = Carrier::bind_with_discovery(
                ka,
                loopback(),
                vec![pb],
                config(seed, server.address),
            )
            .unwrap();
            assert!(a.core.discovery.as_ref().unwrap().is_seed(&seed));
            assert!(!a.core.allows_application(&seed));
            let (b, bh, mut br) = Carrier::bind(kb, loopback(), vec![pa]).unwrap();
            server.quiet();
            assert_eq!(a.executor.active_tasks().unwrap(), 0);
            let mut roots = JoinSet::new(); // Exactly two caller-owned fixture drivers.
            let mut stops = Vec::with_capacity(2);
            for owner in [a, b] {
                let (stop, stopped) = oneshot::channel();
                stops.push(stop);
                roots.spawn(owner.run(async {
                    let _ = stopped.await;
                }));
            }
            let address = bh.local_addr().await.unwrap();
            let local = ah.local_addr().await.unwrap();
            assert_eq!(
                ah.connect(seed, address).await.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            ah.connect(pb, address).await.unwrap();
            ah.send(pb, Datagram::new(b"numeric configured path").unwrap())
                .await
                .unwrap();
            assert_eq!(
                br.recv().await.unwrap().packet.as_bytes(),
                b"numeric configured path"
            );
            assert!(ah.links().borrow().iter().all(|link| link.peer == pb));
            server.quiet();
            for stop in stops {
                stop.send(()).unwrap();
            }
            while let Some(result) = roots.join_next().await {
                result.unwrap().unwrap();
            }
            assert!(ah.links().borrow().is_empty());
            assert!(ah.local_addr().await.is_err());
            // The established connection may leave TIME_WAIT; the listener-only case is below.
            assert_ne!(local.port(), 0);
            server.quiet();
        },
        "OWNED_DNS_CONFIGURED_NUMERIC_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_private_dns_tcp_noise_path_authenticates_expected_peer_and_denies_wrong_peer() {
    bounded(
        async {
            for wrong_peer in [false, true] {
                let server = Server::new().await;
                let local = key();
                let remote = key();
                let remote_peer = remote.public().to_peer_id();
                let (target, target_handle, _incoming) =
                    Carrier::bind(remote, loopback(), vec![local.public().to_peer_id()]).unwrap();
                let (stop, stopped) = oneshot::channel();
                let mut roots = JoinSet::new(); // One fixture server driver, always joined.
                roots.spawn(target.run(async {
                    let _ = stopped.await;
                }));
                let address = target_handle.local_addr().await.unwrap();
                let expected = if wrong_peer {
                    key().public().to_peer_id()
                } else {
                    remote_peer
                };
                let now = Instant::now();
                let endpoint = address;
                let mut owner = Owner::new(&[], &[]).unwrap();
                owner
                    .admit_identity(expected, Role::ExplicitRelay(endpoint))
                    .unwrap();
                let view = owner.view();
                let dns: Multiaddr =
                    format!("/dns4/owned.example./tcp/{}/p2p/{expected}", address.port())
                        .parse()
                        .unwrap();
                let executor = OwnedExecutor::new();
                let (lifetime, resolver) =
                    OwnedResolver::new(&[server.address], executor.handle()).unwrap();
                let native = relay::native::FreshPorts(tcp::tokio::Transport::new(
                    tcp::Config::default().nodelay(true),
                ));
                let native = Guard::numeric(native, view.clone());
                let transport = libp2p::dns::Transport::with_resolver(
                    native,
                    resolver.with_roles(view.clone()),
                )
                .upgrade(upgrade::Version::V1Lazy)
                .authenticate(noise::Config::new(&local).unwrap())
                .multiplex(yamux::Config::default())
                .timeout(DEADLINE)
                .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                .map_err(io::Error::other)
                .boxed();
                let transport = Guard::context(transport, view.clone())
                    .map_err(io::Error::other)
                    .boxed();
                let mut swarm = Swarm::new(
                    transport,
                    dummy::Behaviour,
                    local.public().to_peer_id(),
                    libp2p::swarm::Config::with_executor(executor.handle())
                        .with_idle_connection_timeout(Duration::from_secs(30)),
                );
                let options = DialOpts::peer_id(expected)
                    .addresses(vec![dns.clone()])
                    .build();
                let connection = options.connection_id();
                let key = owner
                    .admit(expected, connection, now + DEADLINE, now)
                    .unwrap();
                owner
                    .pin_fixture_root(
                        key,
                        Root::new(dns.as_ref(), expected).unwrap(),
                        endpoint,
                        now,
                    )
                    .unwrap();
                swarm.dial(options).unwrap();
                let connected = async {
                    loop {
                        match swarm.select_next_some().await {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => break Ok(peer_id),
                            SwarmEvent::OutgoingConnectionError { error, .. } => break Err(error),
                            _ => {}
                        }
                    }
                };
                let (result, _) = tokio::join!(connected, server.answer(a()));
                owner.terminal(key, result.as_ref().ok().copied(), Instant::now());
                if wrong_peer {
                    assert!(
                        matches!(result, Err(DialError::WrongPeerId { .. })),
                        "DNS_WRONG_PEER_ACCEPTED"
                    );
                } else {
                    assert_eq!(result.unwrap(), remote_peer);
                }
                lifetime.close();
                drop(swarm);
                executor.shutdown().await.unwrap();
                stop.send(()).unwrap();
                roots.join_next().await.unwrap().unwrap().unwrap();

                // The exact same DNS input remains unavailable in the production foundation.
                let executor = OwnedExecutor::new();
                let (lifetime, resolver) =
                    OwnedResolver::new(&[server.address], executor.handle()).unwrap();
                let native =
                    relay::native::FreshPorts(tcp::tokio::Transport::new(tcp::Config::default()));
                let mut production =
                    NumericOnly(libp2p::dns::Transport::with_resolver(native, resolver));
                let options = libp2p::core::transport::DialOpts {
                    role: libp2p::core::Endpoint::Dialer,
                    port_use: libp2p::core::transport::PortUse::New,
                };
                assert!(
                    production.dial(dns, options).is_err(),
                    "FOUNDATION_EXPOSED_UNGUARDED_DNS"
                );
                lifetime.close();
                drop(production);
                executor.shutdown().await.unwrap();
                server.quiet();
            }
        },
        "OWNED_DNS_NOISE_AUTHENTICATION_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_configured_close_rebinds_native_listener_with_handles_retained() {
    bounded(
        async {
            let server = Server::new().await;
            let (owner, handle, _incoming) = Carrier::bind_with_discovery(
                key(),
                loopback(),
                vec![],
                config(key().public().to_peer_id(), server.address),
            )
            .unwrap();
            let closed = owner.core.discovery.as_ref().unwrap().lifetime.observer();
            let (stop, stopped) = oneshot::channel();
            let mut roots = JoinSet::new();
            roots.spawn(owner.run(async {
                let _ = stopped.await;
            }));
            let address = handle.local_addr().await.unwrap();
            stop.send(()).unwrap();
            roots.join_next().await.unwrap().unwrap().unwrap();
            assert!(closed(), "CORE_DROPPED_WITH_DNS_GATE_OPEN");
            let _rebound = TcpListener::bind(address).await.unwrap();
            assert!(handle.local_addr().await.is_err());
            server.quiet();
        },
        "OWNED_DNS_CONFIGURED_NATIVE_REBIND_DEADLINE",
    )
    .await;
}

#[tokio::test]
async fn owned_dns_drop_cancel_and_startup_failure_close_without_claiming_join() {
    let server = Server::new().await;
    for mode in 0..3 {
        let (owner, handle, _incoming) = Carrier::bind_with_discovery(
            key(),
            loopback(),
            vec![],
            config(key().public().to_peer_id(), server.address),
        )
        .unwrap();
        let closed = owner.core.discovery.as_ref().unwrap().lifetime.observer();
        if mode == 0 {
            drop(owner);
        } else {
            let mut run = Box::pin(owner.run(std::future::pending()));
            if mode == 2 {
                assert!(run.as_mut().now_or_never().is_none());
            }
            drop(run);
        }
        assert!(closed(), "CANCELED_CARRIER_LEFT_DNS_ADMISSION_OPEN");
        assert!(handle.commands.is_closed());
    }
    let occupied = TcpListener::bind(loopback()).await.unwrap();
    let result = Carrier::bind_with_discovery(
        key(),
        occupied.local_addr().unwrap(),
        vec![],
        config(key().public().to_peer_id(), server.address),
    );
    assert!(result.is_err());
    server.quiet();
}

#[tokio::test]
async fn owned_dns_numeric_only_guard_rejects_all_public_dns_spellings_before_poll() {
    let server = Server::new().await;
    let executor = OwnedExecutor::new();
    let (lifetime, resolver) = OwnedResolver::new(&[server.address], executor.handle()).unwrap();
    let native = relay::native::FreshPorts(tcp::tokio::Transport::new(tcp::Config::default()));
    let mut transport = NumericOnly(libp2p::dns::Transport::with_resolver(native, resolver));
    for protocol in [
        Protocol::Dns("owned.example.".into()),
        Protocol::Dns4("owned.example.".into()),
        Protocol::Dns6("owned.example.".into()),
        Protocol::Dnsaddr("owned.example.".into()),
    ] {
        let address = Multiaddr::empty().with(protocol).with(Protocol::Tcp(4001));
        let options = libp2p::core::transport::DialOpts {
            role: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        };
        assert!(transport.dial(address, options).is_err());
    }
    assert_eq!(executor.active_tasks().unwrap(), 0);
    lifetime.close();
    drop(transport);
    executor.shutdown().await.unwrap();
    server.quiet();
}
