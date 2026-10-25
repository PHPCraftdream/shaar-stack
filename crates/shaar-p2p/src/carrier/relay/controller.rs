use super::*;

impl Core {
    fn authorize_relay(&mut self, address: RelayAddr) -> io::Result<()> {
        if address.peer == *self.swarm.local_peer_id() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if let Some(target) = self.relay.targets.get_mut(&address.peer) {
            if target.address != address {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "relay address already pinned",
                ));
            }
            target.used = Instant::now();
            return Ok(());
        }
        if self.relay.targets.len() >= RELAY_LIMIT {
            return Err(capacity());
        }
        self.swarm
            .behaviour_mut()
            .admission
            .authorize_relay(address.peer)?;
        self.relay.targets.insert(
            address.peer,
            Target {
                address,
                used: Instant::now(),
            },
        );
        Ok(())
    }

    pub(in super::super) fn reserve_relay(&mut self, address: RelayAddr, reply: Reply<RelayLease>) {
        if reply.is_closed() {
            return;
        }
        let now = Instant::now();
        if let Some(record) = self.relay.records.get(&address.peer) {
            if record.address != address {
                let _ = reply.send(Err(io::Error::from(io::ErrorKind::AlreadyExists)));
                return;
            }
            if record.phase == Phase::Active
                && let (Some(expiry), Some(control)) = (record.expiry, record.control)
                && expiry > now
                && !record.addresses.is_empty()
                && self.swarm.behaviour().admission.connection(&address.peer) == Some(control)
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
        if let Err(error) = self.authorize_relay(address) {
            let _ = reply.send(Err(error));
            return;
        }
        let generation = match self.relay.next_generation() {
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
                        listener: Some(listener),
                        control: None,
                        expiry: None,
                        generation,
                        phase: Phase::Pending,
                        deadline: now + DEADLINE,
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
                let _ = reply.send(Err(io::Error::other(error)));
            }
        }
    }

    fn stop_reservation(&mut self, peer: PeerId, error: Option<io::Error>) {
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
        if !self.swarm.behaviour().admission.allows(&peer) {
            let _ = reply.send(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
            return;
        }
        if let Some(id) = self.swarm.behaviour().admission.connection(&peer) {
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
            || self.closing.contains_key(&peer)
        {
            let _ = reply.send(Err(capacity()));
            return;
        }
        if let Err(error) = self.authorize_relay(address) {
            let _ = reply.send(Err(error));
            return;
        }
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
                    },
                );
            }
            Err(error) => {
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
                ..
            } => {
                if self.swarm.behaviour().admission.connection(&relay_peer_id)
                    != Some(connection_id)
                {
                    return;
                }
                let Some(record) = self.relay.records.get_mut(&relay_peer_id) else {
                    return;
                };
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
            self.stop_reservation(peer, Some(error));
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
        self.relay
            .records
            .get_mut(&peer)
            .expect("same task")
            .listener = None;
        self.stop_reservation(
            peer,
            error.or_else(|| Some(io::Error::from(io::ErrorKind::ConnectionAborted))),
        );
    }

    pub(in super::super) fn relay_connected(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        relayed: bool,
        intended: Option<RelayAddr>,
    ) -> io::Result<()> {
        if !self.swarm.behaviour().admission.allows(&peer) {
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
            if intended.is_none()
                && !self.relay.records.values().any(|record| {
                    record.phase == Phase::Active
                        && record.expiry.is_some_and(|expiry| expiry > Instant::now())
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no live relay reservation",
                ));
            }
            Route::Relayed {
                relay: intended.map(|address| address.peer),
                generation: self.relay.next_generation()?,
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
        self.relay.routes.remove(&id);
        if self
            .relay
            .records
            .get(&peer)
            .is_some_and(|record| record.control == Some(id))
        {
            self.stop_reservation(
                peer,
                Some(io::Error::from(io::ErrorKind::ConnectionAborted)),
            );
        }
    }

    pub(in super::super) fn relay_tick(&mut self, now: Instant) -> io::Result<()> {
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
                        && self.swarm.behaviour().admission.connection(&peer).is_none()
                        && !self.swarm.behaviour().admission.pending_peer(peer);
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
            if self.swarm.behaviour().admission.connection(&peer).is_some() {
                if let std::collections::hash_map::Entry::Vacant(entry) = self.closing.entry(peer) {
                    entry.insert(super::Closing {
                        deadline: now + DEADLINE,
                        reply: None,
                    });
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
            } else if !self.swarm.behaviour().admission.pending_peer(peer) {
                self.swarm.behaviour_mut().admission.forget_relay(peer);
                self.relay.targets.remove(&peer);
            }
        }
        self.relay.publish(now);
        Ok(())
    }
}
