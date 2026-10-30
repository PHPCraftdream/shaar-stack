use super::*;

impl Core {
    pub(in super::super) fn reserve_relay(&mut self, address: RelayAddr, reply: Reply<RelayLease>) {
        self.reserve_relay_from(address, reply, None);
    }

    pub(super) fn reserve_relay_from(
        &mut self,
        address: RelayAddr,
        reply: Reply<RelayLease>,
        discovered: Option<crate::discovery::roles::AttemptKey>,
    ) {
        if reply.is_closed() {
            return;
        }
        let now = Instant::now();
        if let Some(record) = self.relay.records.get(&address.peer) {
            if record.address != address || record.discovered != discovered {
                let _ = reply.send(Err(io::Error::from(io::ErrorKind::AlreadyExists)));
                return;
            }
            if record.phase == Phase::Active
                && let (Some(expiry), Some(control)) = (record.expiry, record.control)
                && expiry > now
                && !record.addresses.is_empty()
                && self
                    .swarm
                    .behaviour()
                    .inner
                    .admission
                    .connection(&address.peer)
                    == Some(control)
            {
                let _ = reply.send(Ok(RelayLease {
                    relay: address,
                    expires_at: expiry,
                    generation: record.generation,
                    control,
                }));
                return;
            }
            if record.phase != Phase::Failed || now < record.deadline || record.attempts >= 3 {
                let _ = reply.send(Err(capacity()));
                return;
            }
        } else if self.relay.records.len() >= RESERVATIONS {
            let _ = reply.send(Err(capacity()));
            return;
        }
        let deadline = match self.reserve_admission_deadline(discovered, now) {
            Ok(deadline) => deadline,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let authorized = match discovered {
            Some(key) => self.authorize_discovered_relay(address, key),
            None => self.authorize_relay(address),
        };
        if let Err(error) = authorized {
            let _ = reply.send(Err(error));
            return;
        }
        // Stage the trusted intent before listen_on: the patched transport
        // invokes the factory synchronously inside listen_on (kind=Reserve).
        let staged = match discovered {
            Some(key) => {
                self.relay
                    .gate
                    .stage_discovered_reserve(key, address.socket_addr(), deadline)
            }
            None => self
                .relay
                .gate
                .stage_reserve(address.peer, address.socket_addr(), deadline),
        };
        let generation = match staged {
            Ok(value) => value,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let attempts = self
            .relay
            .records
            .get(&address.peer)
            .map_or(1, |record| record.attempts.saturating_add(1));
        match self.swarm.listen_on(address.prefix()) {
            Ok(listener) => {
                self.relay.records.insert(
                    address.peer,
                    Record {
                        address,
                        discovered,
                        listener: Some(listener),
                        control: None,
                        expiry: None,
                        generation,
                        phase: Phase::Pending,
                        deadline,
                        forget_at: now + HISTORY_AGE,
                        attempts,
                        failed: false,
                        addresses: HashSet::with_capacity(ADDRESSES),
                        ready: Some(reply),
                        released: None,
                    },
                );
            }
            Err(error) => {
                self.relay.gate.revoke_generation(
                    address.peer,
                    super::gate::Slot::Reserve,
                    generation,
                );
                self.relay
                    .gate
                    .terminal_reservation(address.peer, generation);
                let _ = reply.send(Err(io::Error::other(error)));
            }
        }
    }

    pub(super) fn stop_reservation(&mut self, peer: PeerId, error: Option<io::Error>) {
        // Withdraw eligibility before changing listener or connection state.
        if self
            .relay
            .records
            .get(&peer)
            .is_some_and(|record| record.discovered.is_some())
        {
            self.relay.gate.revoke(peer, super::gate::Slot::Connect);
        }
        self.relay.gate.revoke(peer, super::gate::Slot::Reserve);
        let Some(record) = self.relay.records.get_mut(&peer) else {
            return;
        };
        if record.phase != Phase::Stopping {
            record.phase = Phase::Stopping;
            record.deadline = Instant::now() + DEADLINE;
            record.expiry = None;
            record.failed = error.is_some();
            if let Some(reply) = record.ready.take() {
                let _ = reply.send(Err(
                    error.unwrap_or_else(|| io::Error::from(io::ErrorKind::Interrupted))
                ));
            }
            if let Some(listener) = record.listener {
                self.swarm.remove_listener(listener);
            }
        }
        // ListenerClosed supplies the terminal outcome.
        let _ = self.swarm.disconnect_peer_id(peer);
        self.relay.dirty = true;
        self.relay.publish(Instant::now());
    }

    pub(in super::super) fn release_relay(&mut self, peer: PeerId, reply: Reply<()>) {
        if let Some(record) = self.relay.records.get_mut(&peer) {
            if record.released.is_some() {
                let _ = reply.send(Err(capacity()));
                return;
            }
            record.released = Some(reply);
            record.failed = false;
            self.stop_reservation(peer, None);
        } else {
            let _ = reply.send(Ok(()));
        }
    }

    pub(in super::super) fn connect_via(
        &mut self,
        peer: PeerId,
        address: RelayAddr,
        reply: Reply<ConnectionId>,
    ) {
        if reply.is_closed() {
            return;
        }
        if !self.swarm.behaviour().inner.admission.allows(&peer) {
            let _ = reply.send(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
            return;
        }
        if self.closing.contains_key(&peer) {
            let _ = reply.send(Err(capacity()));
            return;
        }
        if self
            .relay
            .targets
            .get(&address.peer)
            .is_some_and(|target| target.address != address)
        {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "relay address already pinned",
            )));
            return;
        }
        if let Some(id) = self.swarm.behaviour().inner.admission.connection(&peer) {
            let result = match self.relay.routes.get(&id) {
                Some(Route::Relayed {
                    relay: Some(relay), ..
                }) if *relay == address.peer => Ok(id),
                _ => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "peer has a different carrier route",
                )),
            };
            let _ = reply.send(result);
            return;
        }
        if self.pending.len() >= PENDING_LIMIT
            || self.pending.values().any(|pending| pending.peer == peer)
        {
            let _ = reply.send(Err(capacity()));
            return;
        }
        if let Err(error) = self.authorize_relay(address) {
            let _ = reply.send(Err(error));
            return;
        }
        // Relay dials carry their own bounded, control-bound gate ticket, not
        // a registry attempt key; the shared inbound pending budget is unchanged.
        let ticket = match self.relay.gate.stage_connect(
            address.peer,
            address.socket_addr(),
            peer,
            Instant::now() + DEADLINE,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let options = DialOpts::peer_id(peer)
            .addresses(vec![address.prefix().with(Protocol::P2p(peer))])
            .allocate_new_port()
            .build();
        let id = options.connection_id();
        match self.swarm.dial(options) {
            Ok(()) => {
                self.pending.insert(
                    id,
                    Pending {
                        peer,
                        reply,
                        route: Some(address),
                        attempt: None,
                        operation: Some(ticket),
                    },
                );
            }
            Err(error) => {
                self.relay.gate.revoke_generation(
                    address.peer,
                    super::gate::Slot::Connect,
                    ticket.generation,
                );
                self.relay.gate.terminal(ticket);
                let _ = reply.send(Err(io::Error::other(error)));
            }
        }
    }

    pub(in super::super) fn relay_event(&mut self, event: protocol::client::Event) {
        match event {
            protocol::client::Event::ReservationReqAccepted {
                relay_peer_id,
                connection_id,
                expires_at,
                operation,
                ..
            } => {
                if self
                    .swarm
                    .behaviour()
                    .inner
                    .admission
                    .connection(&relay_peer_id)
                    != Some(connection_id)
                {
                    return;
                }
                let configured_roles = self.swarm.behaviour().inner.admission.has_authority();
                let Some(record) = self.relay.records.get_mut(&relay_peer_id) else {
                    return;
                };
                if configured_roles
                    && (operation
                        .generation()
                        .is_none_or(|generation| generation.get() != record.generation)
                        || !self.relay.gate.reservation_permit(
                            relay_peer_id,
                            record.generation,
                            connection_id,
                        ))
                {
                    return;
                }
                if record.phase == Phase::Stopping
                    || record.phase == Phase::Failed
                    || record.control.is_some_and(|old| old != connection_id)
                {
                    return;
                }
                let expiry = Instant::from_std(expires_at);
                if expiry <= Instant::now() {
                    self.stop_reservation(
                        relay_peer_id,
                        Some(io::Error::from(io::ErrorKind::TimedOut)),
                    );
                    return;
                }
                record.control = Some(connection_id);
                record.expiry = Some(expiry);
                // Generation unification: the accepted operation descriptor's
                // generation is the same counter value staged at listen_on;
                // record/route generations are capability generations.
                if let Some(generation) = operation.generation() {
                    record.generation = generation.get();
                }
                let generation = record.generation;
                self.relay
                    .gate
                    .accepted(relay_peer_id, generation, expiry, connection_id);
                if !record.addresses.is_empty() {
                    record.phase = Phase::Active;
                }
                self.finish_reservation(relay_peer_id);
            }
            protocol::client::Event::OutboundCircuitEstablished { .. }
            | protocol::client::Event::InboundCircuitEstablished { .. } => {
                // Circuit readiness is the later pinned end-to-end Noise Swarm event, not a relay claim.
            }
        }
    }

    fn finish_reservation(&mut self, peer: PeerId) {
        let Some(record) = self.relay.records.get_mut(&peer) else {
            return;
        };
        if record.phase != Phase::Active {
            return;
        }
        let (Some(expiry), Some(control)) = (record.expiry, record.control) else {
            return;
        };
        let lease = RelayLease {
            relay: record.address,
            expires_at: expiry,
            generation: record.generation,
            control,
        };
        let ready = record.ready.take();
        self.relay.dirty = true;
        self.relay.publish(Instant::now());
        if let Some(reply) = ready {
            let _ = reply.send(Ok(lease));
        }
    }

    pub(in super::super) fn relay_listen_address(
        &mut self,
        listener: ListenerId,
        address: Multiaddr,
    ) {
        let local = *self.swarm.local_peer_id();
        let Some(peer) = self
            .relay
            .records
            .iter()
            .find_map(|(peer, record)| (record.listener == Some(listener)).then_some(*peer))
        else {
            return;
        };
        if address.len() > ADDRESS_BYTES {
            self.stop_reservation(
                peer,
                Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "relay advertisement exceeds address budget",
                )),
            );
            return;
        }
        let mut suffix = address.clone();
        let valid = suffix.pop() == Some(Protocol::P2p(local))
            && suffix.pop() == Some(Protocol::P2pCircuit)
            && suffix.pop() == Some(Protocol::P2p(peer));
        let record = self
            .relay
            .records
            .get_mut(&peer)
            .expect("record found in same task");
        if record.phase == Phase::Stopping || record.phase == Phase::Failed {
            return;
        }
        if !valid || (!record.addresses.contains(&address) && record.addresses.len() >= ADDRESSES) {
            self.stop_reservation(
                peer,
                Some(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "untrusted relay advertisement",
                )),
            );
            return;
        }
        record.addresses.insert(address);
        if record.control.is_some() && record.expiry.is_some() {
            record.phase = Phase::Active;
        }
        self.finish_reservation(peer);
    }

    pub(in super::super) fn relay_listener_failed(
        &mut self,
        listener: ListenerId,
        error: io::Error,
    ) {
        if let Some(peer) = self
            .relay
            .records
            .iter()
            .find_map(|(peer, record)| (record.listener == Some(listener)).then_some(*peer))
        {
            let generation = self
                .relay
                .records
                .get(&peer)
                .map(|record| record.generation);
            self.stop_reservation(peer, Some(error));
            if let Some(generation) = generation {
                self.relay.gate.terminal_reservation(peer, generation);
            }
        }
    }

    pub(in super::super) fn relay_listener_closed(
        &mut self,
        listener: ListenerId,
        error: Option<io::Error>,
    ) {
        let Some(peer) = self
            .relay
            .records
            .iter()
            .find_map(|(peer, record)| (record.listener == Some(listener)).then_some(*peer))
        else {
            return;
        };
        let generation = self
            .relay
            .records
            .get(&peer)
            .map(|record| record.generation);
        self.relay
            .records
            .get_mut(&peer)
            .expect("same task")
            .listener = None;
        self.stop_reservation(
            peer,
            error.or_else(|| Some(io::Error::from(io::ErrorKind::ConnectionAborted))),
        );
        if let Some(generation) = generation {
            self.relay.gate.terminal_reservation(peer, generation);
        }
    }

    pub(in super::super) fn relay_connected(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        relayed: bool,
        intended: Option<RelayAddr>,
        generation: Option<u64>,
        local_address: Option<&Multiaddr>,
    ) -> io::Result<()> {
        if !self.swarm.behaviour().inner.admission.allows(&peer) {
            if self
                .relay
                .records
                .get(&peer)
                .is_some_and(|record| record.phase == Phase::Stopping)
            {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
            return Ok(());
        }
        let route = if relayed {
            if let Some(address) = intended {
                let ticket = super::gate::Ticket {
                    relay: address.peer,
                    generation: generation
                        .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?,
                };
                if self.swarm.behaviour().inner.admission.has_authority()
                    && !self.relay.gate.connection_permit(ticket, peer)
                {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                Route::Relayed {
                    relay: Some(address.peer),
                    generation: ticket.generation,
                }
            } else if !self.swarm.behaviour().inner.admission.has_authority() {
                if !self.relay.records.values().any(|record| {
                    record.phase == Phase::Active
                        && record.expiry.is_some_and(|expiry| expiry > Instant::now())
                }) {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                Route::Relayed {
                    relay: None,
                    generation: self.relay.gate.next()?,
                }
            } else {
                let local = local_address
                    .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
                // Incoming transport addresses omit our final advertised peer suffix.
                let qualified = local
                    .clone()
                    .with_p2p(*self.swarm.local_peer_id())
                    .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
                let now = Instant::now();
                let provenance = self
                    .relay
                    .records
                    .iter()
                    .find_map(|(relay, record)| {
                        (record.phase == Phase::Active
                            && record.addresses.contains(&qualified)
                            && record.control.is_some()
                            && record.expiry.is_some_and(|expiry| expiry > now)
                            && self.swarm.behaviour().inner.admission.connection(relay)
                                == record.control)
                            .then_some((*relay, record.generation))
                    })
                    .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
                Route::Relayed {
                    relay: Some(provenance.0),
                    generation: provenance.1,
                }
            }
        } else if intended.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay dial did not use a circuit",
            ));
        } else {
            Route::Direct
        };
        self.relay.routes.insert(id, route);
        Ok(())
    }

    pub(in super::super) fn relay_control_closed(&mut self, peer: PeerId, id: ConnectionId) {
        let route = self.relay.routes.remove(&id);
        // A closed relayed circuit retires its connect operation, never a
        // reservation owner on the unrelated reserve slot.
        if let Some(Route::Relayed {
            relay: Some(relay),
            generation: route_generation,
        }) = route
        {
            self.relay
                .gate
                .revoke_generation(relay, super::gate::Slot::Connect, route_generation);
        }
        if self.relay.records.get(&peer).is_some_and(|record| {
            record.control == Some(id) || record.discovered.is_some_and(|key| key.connection == id)
        }) {
            self.stop_reservation(
                peer,
                Some(io::Error::from(io::ErrorKind::ConnectionAborted)),
            );
        }
    }

    pub(in super::super) fn relay_tick(&mut self, now: Instant) -> io::Result<()> {
        // Expired unestablished gate intents lose eligibility; owners are
        // cancelled and dropped outside all guards inside the gate.
        self.relay.gate.prune_released();
        self.relay.gate.expire(now);
        let mut peers = [None; RESERVATIONS];
        for (slot, peer) in peers.iter_mut().zip(self.relay.records.keys()) {
            *slot = Some(*peer);
        }
        for peer in peers.into_iter().flatten() {
            let record = &self.relay.records[&peer];
            match record.phase {
                Phase::Pending
                    if now >= record.deadline
                        || record
                            .ready
                            .as_ref()
                            .is_some_and(oneshot::Sender::is_closed) =>
                {
                    self.stop_reservation(peer, Some(io::Error::from(io::ErrorKind::TimedOut)));
                }
                Phase::Active if record.expiry.is_none_or(|expiry| expiry <= now) => {
                    self.stop_reservation(peer, Some(io::Error::from(io::ErrorKind::TimedOut)));
                }
                Phase::Stopping => {
                    let gone = record.listener.is_none()
                        && self
                            .swarm
                            .behaviour()
                            .inner
                            .admission
                            .connection(&peer)
                            .is_none()
                        && !self.swarm.behaviour().inner.admission.pending_peer(peer);
                    if gone {
                        let mut record = self.relay.records.remove(&peer).expect("same task");
                        if let Some(reply) = record.released.take() {
                            let _ = reply.send(Ok(()));
                        }
                        if record.failed {
                            record.phase = Phase::Failed;
                            let jitter = self.relay.jitter.hash_one((
                                peer,
                                record.generation,
                                record.attempts,
                            )) % 251;
                            record.deadline = now
                                + Duration::from_millis(
                                    500_u64.saturating_mul(1_u64 << record.attempts.min(4))
                                        + jitter,
                                );
                            record.forget_at = now + HISTORY_AGE;
                            self.relay.records.insert(peer, record);
                        }
                    } else if now >= record.deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "relay teardown deadline",
                        ));
                    }
                }
                Phase::Failed if now >= record.forget_at => {
                    self.relay.records.remove(&peer);
                }
                Phase::Pending | Phase::Active | Phase::Failed => {}
            }
        }
        let mut stale = [None; RELAY_LIMIT];
        let mut slots = stale.iter_mut();
        for (peer, target) in &self.relay.targets {
            let referenced = self.relay.records.contains_key(peer) || self.pending.values().any(|pending| pending.route.is_some_and(|route| route.peer == *peer))
                || self.relay.routes.values().any(|route| matches!(route, Route::Relayed { relay: Some(relay), .. } if relay == peer));
            if !referenced && now >= target.used + HISTORY_AGE {
                *slots.next().expect("target count bounded before insertion") = Some(*peer);
            }
        }
        for peer in stale.into_iter().flatten() {
            if self
                .swarm
                .behaviour()
                .inner
                .admission
                .connection(&peer)
                .is_some()
            {
                if let std::collections::hash_map::Entry::Vacant(entry) = self.closing.entry(peer) {
                    entry.insert(super::Closing {
                        deadline: now + DEADLINE,
                        reply: None,
                    });
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
            } else if !self.swarm.behaviour().inner.admission.pending_peer(peer) {
                self.swarm
                    .behaviour_mut()
                    .inner
                    .admission
                    .forget_relay(peer);
                self.relay.targets.remove(&peer);
            }
        }
        self.relay.publish(now);
        Ok(())
    }
}
