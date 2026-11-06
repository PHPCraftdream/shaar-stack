use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::identity::Identity;
use iroh::endpoint::{NetReportConfig, PortmapperConfig, QuicTransportConfig, VarInt, presets};
use iroh::{EndpointAddr, TransportAddr, endpoint::IncomingAddr};
use iroh_base::{CustomAddr, PublicKey};
use shaar_ygg::{YggBridge, YggCarrier, YggPump};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::network::{
    ALPN, Allowlist, Limits, NetworkError, STREAM_LIMIT, Session, session::ACCESS_DENIED,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Private custom-only endpoint; native and signaling endpoint construction is unchanged.
pub(crate) struct YggEndpoint {
    inner: iroh::Endpoint,
    carrier: Arc<YggCarrier>,
    allowlist: Allowlist,
    slots: Arc<Semaphore>,
    closed: bool,
}

impl YggEndpoint {
    /// cancel-safe: NO — cancellation does not prove capability revocation and bind completion.
    pub(crate) async fn bind(
        identity: &Identity,
        bridge: &YggBridge,
        allowlist: Allowlist,
        limits: Limits,
    ) -> Result<(Self, YggPump), NetworkError> {
        let local_key = identity.public_key_bytes();
        if bridge.public_key() != local_key {
            return Err(NetworkError::PeerMismatch);
        }
        let peer_keys: Vec<PublicKey> = allowlist.keys().collect();
        if peer_keys.len() > shaar_ygg::MAX_DATAGRAM_PEERS {
            return Err(NetworkError::Capacity);
        }
        let peers: Vec<[u8; 32]> = peer_keys.iter().map(|key| *key.as_bytes()).collect();
        let (carrier, pump) = YggCarrier::attach(bridge, local_key, &peers, HANDSHAKE_TIMEOUT)
            .await
            .map_err(NetworkError::SignalingOperation)?;
        let transport = QuicTransportConfig::builder()
            .application_data_filter(|path| custom_mapped(path.remote()))
            .max_concurrent_bidi_streams(VarInt::from_u32(u32::from(STREAM_LIMIT)))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(256 * 1024))
            .receive_window(VarInt::from_u32(1024 * 1024))
            .send_window(1024 * 1024)
            .datagram_receive_buffer_size(None)
            .datagram_send_buffer_size(0)
            .build();
        let builder = iroh::Endpoint::builder(presets::Minimal)
            .secret_key(identity.transport_key())
            .alpns(vec![ALPN.to_vec()])
            .clear_ip_transports()
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .incoming_limits(limits.sessions, 16 * 1024, 512 * 1024)
            .connection_limit(limits.sessions * 2)
            .transport_config(transport)
            .add_custom_transport(carrier.clone());
        let inner = builder
            .bind()
            .await
            .map_err(|error| NetworkError::Bind(Box::new(error)))?;
        if !inner.bound_sockets().is_empty() {
            inner.close().await;
            return Err(NetworkError::InvalidAddress);
        }
        Ok((
            Self {
                inner,
                carrier,
                allowlist,
                slots: Arc::new(Semaphore::new(limits.sessions)),
                closed: false,
            },
            pump,
        ))
    }

    pub(crate) fn id(&self) -> PublicKey {
        self.inner.id()
    }

    pub(crate) fn peer_address(&self, peer: &PublicKey) -> Result<CustomAddr, NetworkError> {
        self.carrier
            .peer_address(peer.as_bytes())
            .map_err(NetworkError::SignalingOperation)
    }

    fn admit(&self) -> Result<OwnedSemaphorePermit, NetworkError> {
        if self.closed || self.inner.is_closed() {
            return Err(NetworkError::Closed);
        }
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| NetworkError::Capacity)
    }

    /// cancel-safe: NO — connection attempts may be completed remotely after cancellation.
    pub(crate) async fn connect(&self, peer: PublicKey) -> Result<Session, NetworkError> {
        if !self.allowlist.contains(&peer) {
            return Err(NetworkError::AccessDenied);
        }
        let address = self.peer_address(&peer)?;
        let source = IncomingAddr::Custom(address.clone());
        let admission = self.admit()?;
        let remote = EndpointAddr::from_parts(peer, [TransportAddr::Custom(address)]);
        let handshake = async {
            let connection = self
                .inner
                .connect(remote, ALPN)
                .await
                .map_err(NetworkError::from_connect)?;
            if connection.remote_id() != peer
                || !self.source_matches(&source, &connection.remote_id())
            {
                connection.close(VarInt::from_u32(2), b"");
                return Err(NetworkError::PeerMismatch);
            }
            super::Endpoint::session(connection, admission)
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| NetworkError::Deadline)?
    }

    /// cancel-safe: NO — a received Initial/handshake may be consumed before cancellation;
    /// it is not replayed.
    pub(crate) async fn accept(&self) -> Result<Session, NetworkError> {
        let incoming = self.inner.accept().await.ok_or(NetworkError::Closed)?;
        let source = incoming.remote_addr();
        let admission = match self.admit() {
            Ok(admission) => admission,
            Err(error) => {
                incoming.refuse();
                return Err(error);
            }
        };
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .map_err(|_| NetworkError::Deadline)?
            .map_err(|error| NetworkError::Handshake(Box::new(error)))?;
        let peer = connection.remote_id();
        if !self.allowlist.contains(&peer) {
            connection.close(VarInt::from_u32(ACCESS_DENIED), b"");
            return Err(NetworkError::AccessDenied);
        }
        if !self.source_matches(&source, &peer) {
            connection.close(VarInt::from_u32(2), b"");
            return Err(NetworkError::PeerMismatch);
        }
        super::Endpoint::session(connection, admission)
    }

    fn source_matches(&self, source: &IncomingAddr, peer: &PublicKey) -> bool {
        let IncomingAddr::Custom(address) = source else {
            return false;
        };
        self.carrier.authenticated_peer(address).ok().as_ref() == Some(peer.as_bytes())
    }

    /// cancel-safe: yes — both owners retain shutdown progress across cancellation.
    /// The returned pump must be the pump returned with this endpoint by the same bind.
    /// Keep both owners alive across close cancellation; retries resume in each owner.
    pub(crate) async fn close(&mut self, pump: &mut YggPump) -> Result<(), NetworkError> {
        self.closed = true;
        self.slots.close();
        self.inner.close().await;
        pump.close().await.map_err(NetworkError::SignalingOperation)
    }
}

fn custom_mapped(address: std::net::SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V6(ip) => ip.octets()[..8] == [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0, 3],
        IpAddr::V4(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt, StreamExt};
    use iroh::endpoint::{PathEvent, PathEventStream, PathStats};
    use shaar_ygg::{YggConfig, YggError, YggTransport};
    use std::net::TcpListener;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    fn key(seed: u8) -> iroh_base::PublicKey {
        iroh_base::PublicKey::from_bytes(&identity(seed).public_key_bytes()).unwrap()
    }

    fn config(seed: u8, listen: Vec<String>, peers: Vec<String>) -> YggConfig {
        YggConfig {
            seed: [seed; 32],
            listen,
            peers,
            allowed_public_keys: Vec::new(),
            group_password: None,
        }
    }

    async fn listener(seed: u8) -> (YggTransport, u16) {
        for _ in 0..50 {
            let socket = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = socket.local_addr().unwrap().port();
            drop(socket);
            match YggTransport::start(config(
                seed,
                vec![format!("tcp://127.0.0.1:{port}")],
                vec![],
            ))
            .await
            {
                Ok(transport) => return (transport, port),
                Err(YggError::Start { .. }) => tokio::time::sleep(Duration::from_millis(20)).await,
                Err(error) => panic!("fixture listener failed: {error}"),
            }
        }
        panic!("no Ygg listener port available");
    }

    async fn dialer(seed: u8, port: u16) -> YggTransport {
        YggTransport::start(config(
            seed,
            vec![],
            vec![format!("tcp://127.0.0.1:{port}")],
        ))
        .await
        .unwrap()
    }

    struct Frames {
        events: PathEventStream,
        expected: CustomAddr,
        tx: bool,
        rx: bool,
        closed: bool,
    }

    impl Frames {
        fn new(session: &Session, expected: CustomAddr) -> Self {
            let mut frames = Self {
                events: session.connection.path_events(),
                expected,
                tx: false,
                rx: false,
                closed: false,
            };
            frames.checkpoint(session);
            frames
        }

        fn sample(&mut self, remote: &TransportAddr, stats: &PathStats) {
            if matches!(remote, TransportAddr::Custom(address) if address == &self.expected) {
                self.tx |= stats.frame_tx.stream > 0;
                self.rx |= stats.frame_rx.stream > 0;
                assert_eq!(stats.frame_tx.datagram, 0);
                assert_eq!(stats.frame_rx.datagram, 0);
            } else {
                assert_eq!(
                    stats.frame_tx.stream, 0,
                    "STREAM on non-owned path {remote:?}"
                );
                assert_eq!(
                    stats.frame_rx.stream, 0,
                    "STREAM on non-owned path {remote:?}"
                );
                assert_eq!(stats.frame_tx.datagram, 0);
                assert_eq!(stats.frame_rx.datagram, 0);
            }
        }

        fn event(&mut self, event: PathEvent) {
            match event {
                PathEvent::Closed {
                    remote_addr,
                    last_stats,
                    ..
                } => {
                    if matches!(&remote_addr, TransportAddr::Custom(address) if address == &self.expected)
                    {
                        self.closed = true;
                    }
                    self.sample(&remote_addr, &last_stats);
                }
                PathEvent::Lagged { missed, .. } => panic!("path event lagged by {missed}"),
                PathEvent::Opened { .. } | PathEvent::Selected { .. } => {}
                other => panic!("unexpected path event: {other:?}"),
            }
        }

        fn drain(&mut self) {
            while let Some(event) = self.events.next().now_or_never() {
                self.event(event.expect("path events ended before endpoint close"));
            }
        }

        fn checkpoint(&mut self, session: &Session) {
            self.drain();
            for path in session.connection.paths().iter() {
                self.sample(path.remote_addr(), &path.stats());
            }
            self.drain();
        }

        async fn finish(mut self) -> (bool, bool, bool) {
            while let Some(event) = self.events.next().await {
                self.event(event);
            }
            (self.tx, self.rx, self.closed)
        }
    }
    #[tokio::test]
    async fn real_ygg_sessions_authenticate_exchange_and_release_owned_path() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let client_identity = identity(0xA1);
            let server_identity = identity(0xA2);
            let (server_transport, port) = listener(0xA2).await;
            let client_transport = dialer(0xA1, port).await;
            let client_bridge = YggBridge::new(client_transport, [server_identity.public_key_bytes()]);
            let server_bridge = YggBridge::new(server_transport, [client_identity.public_key_bytes()]);
            let (mut client, mut client_pump) = YggEndpoint::bind(
                &client_identity,
                &client_bridge,
                Allowlist::new(&[server_identity.transport_key().public()]).unwrap(),
                Limits::new(2).unwrap(),
            ).await.unwrap();
            let (mut server, mut server_pump) = YggEndpoint::bind(
                &server_identity,
                &server_bridge,
                Allowlist::new(&[client_identity.transport_key().public()]).unwrap(),
                Limits::new(2).unwrap(),
            ).await.unwrap();
            assert!(client.inner.bound_sockets().is_empty());
            assert!(server.inner.bound_sockets().is_empty());
            let (connected, accepted) = tokio::select! {
                result = async { tokio::join!(client.connect(server.id()), server.accept()) } => result,
                result = client_pump.run() => panic!("client writer stopped: {result:?}"),
                result = server_pump.run() => panic!("server writer stopped: {result:?}"),
            };
            let connected = connected.unwrap();
            let accepted = accepted.unwrap();
            assert_eq!(connected.peer_id(), server.id());
            assert_eq!(accepted.peer_id(), client.id());
            let client_address = client.peer_address(&server.id()).unwrap();
            let server_address = server.peer_address(&client.id()).unwrap();
            let mut client_frames = Frames::new(&connected, client_address);
            let mut server_frames = Frames::new(&accepted, server_address);
            let payload: Vec<u8> = (0..96 * 1024)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            let mut exchange = Box::pin(async {
                let client_exchange = async {
                    let (mut send, mut receive) = connected.connection.open_bi().await.unwrap();
                    send.write_all(&payload).await.unwrap();
                    send.finish().unwrap();
                    let echoed = receive.read_to_end(128 * 1024).await.unwrap();
                    assert_eq!(echoed.as_ref(), payload.as_slice());
                };
                let server_exchange = async {
                    let (mut echo_send, mut echo_receive) = accepted.connection.accept_bi().await.unwrap();
                    let incoming = echo_receive.read_to_end(128 * 1024).await.unwrap();
                    assert_eq!(incoming.as_ref(), payload.as_slice());
                    echo_send.write_all(&incoming).await.unwrap();
                    echo_send.finish().unwrap();
                };
                tokio::join!(client_exchange, server_exchange);
            });
            loop {
                client_frames.checkpoint(&connected);
                server_frames.checkpoint(&accepted);
                tokio::select! {
                    biased;
                    event = client_frames.events.next() => client_frames.event(event.expect("client path events ended before endpoint close")),
                    event = server_frames.events.next() => server_frames.event(event.expect("server path events ended before endpoint close")),
                    result = &mut exchange => break result,
                }
            }
            drop(exchange);
            client_frames.checkpoint(&connected);
            server_frames.checkpoint(&accepted);
            drop((connected, accepted));
            let (client_closed, server_closed) = tokio::join!(client.close(&mut client_pump), server.close(&mut server_pump));
            client_closed.unwrap();
            server_closed.unwrap();
            let (client_tx, client_rx, client_closed) = client_frames.finish().await;
            let (server_tx, server_rx, server_closed) = server_frames.finish().await;
            assert!(client_tx && client_rx && client_closed);
            assert!(server_tx && server_rx && server_closed);
            client_bridge.close().await.unwrap();
            server_bridge.close().await.unwrap();
            let replacement = YggTransport::start(config(
                0xA2,
                vec![format!("tcp://127.0.0.1:{port}")],
                vec![],
            )).await.unwrap();
            replacement.close().await.unwrap();
        }).await.expect("Ygg SDK lifecycle deadline");
    }

    #[tokio::test]
    async fn allowed_tls_key_on_another_ygg_identity_never_gets_session() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let server_identity = identity(0xB4);
            let carrier_identity = identity(0xB5);
            let tls_identity = identity(0xB6);
            let (server_transport, port) = listener(0xB4).await;
            let client_transport = dialer(0xB5, port).await;
            let server_bridge = YggBridge::new(server_transport, [carrier_identity.public_key_bytes()]);
            let client_bridge = YggBridge::new(client_transport, [server_identity.public_key_bytes()]);
            let (mut server, mut server_pump) = YggEndpoint::bind(
                &server_identity,
                &server_bridge,
                Allowlist::new(&[
                    carrier_identity.transport_key().public(),
                    tls_identity.transport_key().public(),
                ]).unwrap(),
                Limits::new(1).unwrap(),
            ).await.unwrap();
            let (carrier, mut client_pump) = YggCarrier::attach(
                &client_bridge,
                carrier_identity.public_key_bytes(),
                &[server_identity.public_key_bytes()],
                HANDSHAKE_TIMEOUT,
            ).await.unwrap();
            // An untrusted remote bypasses the SDK's local-key consistency check.
            let client = iroh::Endpoint::builder(presets::Minimal)
                .secret_key(tls_identity.transport_key())
                .alpns(vec![ALPN.to_vec()])
                .clear_ip_transports()
                .add_custom_transport(carrier.clone())
                .bind().await.unwrap();
            let address = carrier.peer_address(&server_identity.public_key_bytes()).unwrap();
            let remote = EndpointAddr::from_parts(server.id(), [TransportAddr::Custom(address)]);
            let (connected, accepted) = tokio::select! {
                result = async { tokio::join!(client.connect(remote, ALPN), server.accept()) } => result,
                result = client_pump.run() => panic!("client writer stopped: {result:?}"),
                result = server_pump.run() => panic!("server writer stopped: {result:?}"),
            };
            assert!(matches!(accepted, Err(NetworkError::PeerMismatch)));
            assert_eq!(server.slots.available_permits(), 1);
            if let Ok(connection) = connected {
                connection.close(VarInt::from_u32(0), b"");
            }
            let (_, closed) = tokio::join!(client.close(), server.close(&mut server_pump));
            closed.unwrap();
            client_pump.close().await.unwrap();
            client_bridge.close().await.unwrap();
            server_bridge.close().await.unwrap();
        }).await.expect("source/TLS mismatch deadline");
    }

    #[test]
    fn custom_mapped_is_exact_prefix_and_rejects_other_address_families() {
        let address: std::net::SocketAddr = "[fd15:070a:510b:3::1]:443".parse().unwrap();
        assert!(custom_mapped(address));
        let host_bits: std::net::SocketAddr = "[fd15:070a:510b:3:abcd::1]:443".parse().unwrap();
        assert!(custom_mapped(host_bits));
        for rejected in [
            "[fd15:070a:510b:1::1]:443",
            "[fd15:070a:510b:0::1]:443",
            "[fd15:070a:510b:4::1]:443",
            "127.0.0.1:443",
            "[2001:db8::1]:443",
            "[::ffff:127.0.0.1]:443",
        ] {
            assert!(!custom_mapped(rejected.parse().unwrap()), "{rejected}");
        }
    }
    #[tokio::test]
    async fn identity_mismatch_capacity_and_outbound_allowlist_are_rejected() {
        let (transport, _) = listener(0xA3).await;
        let bridge = YggBridge::new(transport, []);
        let sdk_identity = identity(0xA3);
        assert!(matches!(
            YggEndpoint::bind(
                &identity(0xA4),
                &bridge,
                Allowlist::default(),
                Limits::default()
            )
            .await,
            Err(NetworkError::PeerMismatch)
        ));
        let keys: Vec<_> = (0..17).map(|seed| key(seed + 1)).collect();
        assert!(matches!(
            YggEndpoint::bind(
                &sdk_identity,
                &bridge,
                Allowlist::new(&keys).unwrap(),
                Limits::default()
            )
            .await,
            Err(NetworkError::Capacity)
        ));
        let (mut endpoint, mut pump) = YggEndpoint::bind(
            &sdk_identity,
            &bridge,
            Allowlist::new(&[key(0xA8)]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            endpoint.connect(key(0xA9)).await,
            Err(NetworkError::AccessDenied)
        ));
        assert_eq!(endpoint.slots.available_permits(), 1);
        endpoint.close(&mut pump).await.unwrap();
        bridge.close().await.unwrap();
    }

    #[tokio::test]
    async fn source_attestation_requires_live_exact_carrier_address() {
        let server_identity = identity(0xB1);
        let peer = key(0xB2);
        let (transport, _) = listener(0xB1).await;
        let bridge = YggBridge::new(transport, [*peer.as_bytes()]);
        let (mut endpoint, mut pump) = YggEndpoint::bind(
            &server_identity,
            &bridge,
            Allowlist::new(&[peer]).unwrap(),
            Limits::new(1).unwrap(),
        )
        .await
        .unwrap();
        let address = endpoint.peer_address(&peer).unwrap();
        let source = IncomingAddr::Custom(address.clone());
        assert!(endpoint.source_matches(&source, &peer));
        assert!(!endpoint.source_matches(&source, &key(0xB3)));
        let forged = IncomingAddr::Custom(CustomAddr::from_parts(address.id(), &[0xA5; 16]));
        assert!(!endpoint.source_matches(&forged, &peer));
        assert!(!endpoint.source_matches(&IncomingAddr::Ip("127.0.0.1:1".parse().unwrap()), &peer));
        pump.close().await.unwrap();
        assert!(!endpoint.source_matches(&source, &peer));
        endpoint.close(&mut pump).await.unwrap();
        bridge.close().await.unwrap();
    }

    #[tokio::test]
    async fn inbound_tls_peer_not_in_allowlist_never_gets_session() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let server_identity = identity(0xAB);
            let client_identity = identity(0xAC);
            let (server_transport, port) = listener(0xAB).await;
            let client_transport = dialer(0xAC, port).await;
            let server_bridge = YggBridge::new(server_transport, [client_identity.public_key_bytes()]);
            let client_bridge = YggBridge::new(client_transport, [server_identity.public_key_bytes()]);
            let (mut server, mut server_pump) = YggEndpoint::bind(
                &server_identity,
                &server_bridge,
                Allowlist::new(&[client_identity.transport_key().public()]).unwrap(),
                Limits::new(1).unwrap(),
            )
            .await
            .unwrap();
            server.allowlist = Allowlist::default();
            let (mut client, mut client_pump) = YggEndpoint::bind(
                &client_identity,
                &client_bridge,
                Allowlist::new(&[server_identity.transport_key().public()]).unwrap(),
                Limits::new(1).unwrap(),
            ).await.unwrap();
            let (connected, accepted) = tokio::select! {
                result = async { tokio::join!(client.connect(server.id()), server.accept()) } => result,
                result = client_pump.run() => panic!("client writer stopped: {result:?}"),
                result = server_pump.run() => panic!("server writer stopped: {result:?}"),
            };
            assert!(matches!(accepted, Err(NetworkError::AccessDenied)));
            if let Ok(session) = connected {
                assert!(matches!(session.closed().await, NetworkError::AccessDenied));
                session.close();
            }
            assert_eq!(server.slots.available_permits(), 1);
            let (client_close, server_close) = tokio::join!(client.close(&mut client_pump), server.close(&mut server_pump));
            client_close.unwrap();
            server_close.unwrap();
            client_bridge.close().await.unwrap();
            server_bridge.close().await.unwrap();
        }).await.expect("inbound allowlist denial deadline");
    }
}
