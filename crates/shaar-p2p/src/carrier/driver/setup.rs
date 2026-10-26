use super::*;

impl Carrier {
    /// Creates one native listener and an immutable allowlist of at most 16 entries.
    /// Requires a Tokio runtime; readiness is published while `run` is polled.
    /// Input count is checked before deduplication. Noise consumes the key;
    /// no raw secret getter is exposed.
    pub fn bind(
        key: Keypair,
        bind: SocketAddr,
        allowed: Vec<PeerId>,
    ) -> io::Result<(Self, CarrierHandle, mpsc::Receiver<Received>)> {
        Self::bind_configured(key, bind, allowed, None)
    }

    /// Prepares a carrier-owned resolver without querying DNS or starting bootstrap.
    /// Public connection commands remain numeric-only until discovery policy is installed.
    pub fn bind_with_discovery(
        key: Keypair,
        bind: SocketAddr,
        allowed: Vec<PeerId>,
        discovery: DiscoveryConfig,
    ) -> io::Result<(Self, CarrierHandle, mpsc::Receiver<Received>)> {
        Self::bind_configured(key, bind, allowed, Some(discovery))
    }

    fn bind_configured(
        key: Keypair,
        bind: SocketAddr,
        allowed: Vec<PeerId>,
        discovery: Option<DiscoveryConfig>,
    ) -> io::Result<(Self, CarrierHandle, mpsc::Receiver<Received>)> {
        if allowed.len() > super::PEER_LIMIT {
            return Err(capacity());
        }
        if let Some(config) = &discovery {
            config.validate_identities(key.public().to_peer_id(), &allowed)?;
        }
        let admission = Admission::new(allowed)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("carrier requires a Tokio runtime"))?;
        let peer = key.public().to_peer_id();
        let executor = OwnedExecutor::new();
        let tcp = relay::native::FreshPorts(tcp::tokio::Transport::new(
            tcp::Config::default().nodelay(true),
        ));
        let noise = noise::Config::new(&key).map_err(io::Error::other)?;
        let (discovery, transport) = match discovery {
            Some(config) => {
                let (lifetime, resolver) =
                    OwnedResolver::new(config.nameservers(), executor.handle())?;
                let transport = NumericOnly(libp2p::dns::Transport::with_resolver(tcp, resolver))
                    .upgrade(upgrade::Version::V1Lazy)
                    .authenticate(noise)
                    .multiplex(yamux::Config::default())
                    .timeout(DEADLINE)
                    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                    .boxed();
                (Some(discovery::State::new(config, lifetime)), transport)
            }
            None => (
                None,
                tcp.upgrade(upgrade::Version::V1Lazy)
                    .authenticate(noise)
                    .multiplex(yamux::Config::default())
                    .timeout(DEADLINE)
                    .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
                    .boxed(),
            ),
        };
        let (transport, relays) = relay::transport(transport, &key)?;
        let behaviour = Behaviour {
            admission,
            relays,
            packets: rpc::Behaviour::with_codec(
                DatagramCodec,
                [(
                    StreamProtocol::new(CONTROL_PROTOCOL),
                    rpc::ProtocolSupport::Full,
                )],
                rpc::Config::default()
                    .with_request_timeout(DEADLINE)
                    .with_max_concurrent_streams(2),
            ),
        };
        let swarm = Swarm::new(
            transport,
            behaviour,
            peer,
            libp2p::swarm::Config::with_executor(executor.handle())
                .with_notify_handler_buffer_size(NonZeroUsize::new(8).expect("nonzero constant"))
                .with_per_connection_event_buffer_size(8)
                .with_max_negotiating_inbound_streams(2)
                .with_idle_connection_timeout(Duration::from_secs(30)),
        );
        // Construct the close owner before listener work, including failed startup.
        let native_listener = ListenerId::next();
        let (sender, commands) = mpsc::channel(QUEUE_LIMIT);
        let (incoming, receiver) = mpsc::channel(QUEUE_LIMIT);
        let (listening, ready) = watch::channel(None);
        let (relay, leases) = relay::State::new();
        let (links, observed_links) = watch::channel(Vec::new());
        let handle = CarrierHandle {
            commands: sender,
            listening: ready,
            leases,
            links: observed_links,
            peer,
        };
        let mut core = Core {
            discovery,
            swarm,
            commands,
            incoming,
            listening,
            links,
            native_listener,
            relay,
            pending: HashMap::with_capacity(PENDING_LIMIT),
            requests: HashMap::with_capacity(REQUEST_LIMIT),
            closing: HashMap::with_capacity(super::PEER_LIMIT + super::RELAY_LIMIT),
        };
        core.native_listener = core
            .swarm
            .listen_on(multiaddr(bind))
            .map_err(io::Error::other)?;
        Ok((Self { core, executor }, handle, receiver))
    }

    /// Stops on caller cancellation signal, last submission-handle drop or incoming-consumer drop.
    /// Drops Swarm before aborting and joining every managed connection/listener task.
    /// cancel-safe: NO — dropping this future aborts tasks but cannot join destruction.
    pub async fn run(mut self, stop: impl Future<Output = ()>) -> io::Result<()> {
        // Keep field drop order across cancellation: Core closes DNS before executor abort.
        let result = self.core.drive(&mut self.executor, stop).await;
        self.core.commands.close();
        let Self { core, executor } = self;
        drop(core);
        let joined = executor.shutdown().await;
        result.and(joined)
    }
}
