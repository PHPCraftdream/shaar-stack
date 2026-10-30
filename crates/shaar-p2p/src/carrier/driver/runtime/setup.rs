use super::*;
use std::sync::Arc;

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
        let roles = match &discovery {
            Some(config) => {
                let seeds: Vec<PeerId> = config.seed_peers().collect();
                let mut owner = discovery::roles::Owner::new(&allowed, &seeds)?;
                for (peer, address) in config.seed_descriptors() {
                    owner.reserve_discovery_address(*peer, address)?;
                }
                Some(owner)
            }
            None => None,
        };
        tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("carrier requires a Tokio runtime"))?;
        let peer = key.public().to_peer_id();
        let executor = OwnedExecutor::new();
        let tcp = relay::native::FreshPorts(tcp::tokio::Transport::new(
            tcp::Config::default().nodelay(true),
        ));
        let noise = noise::Config::new(&key).map_err(io::Error::other)?;
        // One gate per carrier: generation counter, staged intents and owners.
        let gate = relay::gate::Gate::new();
        let admission = match roles {
            Some(owner) => Admission::with_authority(
                allowed,
                owner,
                Some(Arc::new({
                    let gate = gate.clone();
                    move |peer, address| gate.native_permit(peer, address)
                })),
            )?,
            None => Admission::new(allowed)?,
        };
        let mut factory = None;
        let (discovery, transport) = match discovery {
            Some(config) => {
                let view = admission
                    .roles_view()
                    .expect("discovery admission always has authority");
                factory = Some(gate.factory(view.clone()));
                let (lifetime, resolver) =
                    OwnedResolver::new(config.nameservers(), executor.handle())?;
                // Innermost→outermost, per the destination-guard draft tests: TCP, the
                // numeric-lease guard (exact-endpoint checks and witness records directly
                // above the socket), the policy-checked resolver and upgrades, then the
                // root-lease context guard over the complete upgraded branch. NumericOnly
                // is not used here: DNS names pass the fail-closed role-aware resolver and
                // numeric dials pass Guard::numeric instead. Authority errors are flattened
                // into io::Error so both or_transport branches keep the native error type.
                let native = Guard::numeric(tcp, view.clone());
                let upgraded = libp2p::dns::Transport::with_resolver(
                    native,
                    resolver.with_roles(view.clone()),
                )
                .upgrade(upgrade::Version::V1Lazy)
                .authenticate(noise)
                .multiplex(yamux::Config::default())
                .timeout(DEADLINE)
                .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)));
                let transport = Guard::context(upgraded, view)
                    .map_err(io::Error::other)
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
        let relay_roles = admission.roles_view();
        let (transport, relays) = relay::transport(transport, &key, factory, relay_roles)?;
        let protocols = protocols::new(peer, key.public(), admission.roles_view());
        let behaviour = Behaviour {
            admission,
            relays,
            protocols,
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
        let behaviour = boundary::Boundary {
            inner: behaviour,
            dial_event: BehaviourEvent::Dial,
            constrain: |inner, id, peer, original, additional| {
                inner
                    .admission
                    .constrain_additional(id, peer, original, additional)
            },
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
        let (relay, leases) = relay::State::new(gate);
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
            discovery_operation: None,
            #[cfg(test)]
            discovery_witnesses: [None; 4],
            swarm,
            infrastructure: infrastructure::State::new(),
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
        // Join actual owners: cancel/drop every live relay operation, then
        // observe release after Swarm/executor drops the last capability clones.
        let gate = self.core.relay.gate.clone();
        gate.revoke_all();
        let (authority, infrastructure) = self.core.take_infrastructure_shutdown();
        let Self { core, executor } = self;
        drop(core);
        let joined = executor.shutdown().await;
        infrastructure.finish_shutdown(authority).await;
        gate.finish_shutdown();
        let released = gate.join_release().await;
        result.and(joined).and(released)
    }
}
