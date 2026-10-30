use super::*;
use crate::discovery::roles::{self, InfrastructurePermit, Owner};
use tokio::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Live,
    Closing,
}

struct Entry {
    key: AttemptKey,
    permit: InfrastructurePermit,
    deadline: Instant,
    phase: Phase,
    protocols: u8,
    identified: bool,
    epoch: Option<roles::DiscoveryEpoch>,
}

#[derive(Default)]
pub(super) struct State {
    entries: HashMap<ConnectionId, Entry>,
    #[cfg(test)]
    shutdown_entered: Option<tokio::sync::oneshot::Sender<()>>,
}

impl State {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(roles::INFRASTRUCTURE_CONNECTIONS),
            #[cfg(test)]
            shutdown_entered: None,
        }
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .values()
            .filter(|entry| entry.phase != Phase::Live)
            .map(|entry| entry.deadline)
            .min()
    }

    /// cancel-safe: yes — authority is closed and all owned I/O has already joined.
    pub(super) async fn finish_shutdown(self, mut authority: Option<Owner>) {
        let view = authority.as_ref().map(Owner::view);
        for entry in self.entries.into_values() {
            if let Some(owner) = &mut authority {
                owner.terminal(entry.key, None, Instant::now());
                owner.infrastructure_terminal(entry.key);
            }
            drop(entry.permit);
        }
        #[cfg(test)]
        if let Some(entered) = self.shutdown_entered {
            let _ = entered.send(());
        }
        if let Some(view) = view {
            view.join_infrastructure_release().await;
        }
    }
}

impl Core {
    pub(super) fn infrastructure_empty(&self) -> bool {
        self.infrastructure.entries.is_empty()
    }

    pub(super) fn infrastructure_control(&self, key: AttemptKey) -> Option<protocols::Control> {
        let entry = self
            .infrastructure
            .entries
            .get(&key.connection)
            .filter(|entry| entry.key == key)?;
        let live = entry.phase == Phase::Live
            && self
                .swarm
                .behaviour()
                .inner
                .admission
                .roles_view()
                .is_some_and(|view| view.infrastructure_live(key).is_some());
        Some(protocols::Control {
            key,
            live,
            pending: entry.phase == Phase::Pending,
            identified: entry.identified,
            protocols: entry.protocols,
        })
    }

    pub(super) fn adopt_discovery_control(
        &mut self,
        key: AttemptKey,
        epoch: roles::DiscoveryEpoch,
    ) -> bool {
        if !self
            .infrastructure_control(key)
            .is_some_and(|control| control.live)
        {
            return false;
        }
        let Some(entry) = self
            .infrastructure
            .entries
            .get_mut(&key.connection)
            .filter(|entry| entry.key == key && entry.epoch == Some(epoch))
        else {
            return false;
        };
        entry.epoch = None;
        true
    }

    pub(super) fn discovery_owned_controls(
        &self,
        epoch: roles::DiscoveryEpoch,
    ) -> [Option<protocols::Control>; roles::INFRASTRUCTURE_CONNECTIONS] {
        let view = self.swarm.behaviour().inner.admission.roles_view();
        let mut entries = self
            .infrastructure
            .entries
            .values()
            .filter(|entry| entry.epoch == Some(epoch));
        std::array::from_fn(|_| {
            entries.next().map(|entry| protocols::Control {
                key: entry.key,
                live: entry.phase == Phase::Live
                    && view
                        .as_ref()
                        .is_some_and(|view| view.infrastructure_live(entry.key).is_some()),
                pending: entry.phase == Phase::Pending,
                identified: entry.identified,
                protocols: entry.protocols,
            })
        })
    }

    pub(super) fn discovery_matching_control(
        &self,
        epoch: roles::DiscoveryEpoch,
        peer: PeerId,
        connection: ConnectionId,
    ) -> Option<protocols::Control> {
        self.discovery_owned_controls(epoch)
            .into_iter()
            .flatten()
            .find(|control| control.key.peer == peer && control.key.connection == connection)
    }

    pub(super) fn discovery_fixture(&mut self, key: AttemptKey, root: &libp2p::Multiaddr) {
        #[cfg(test)]
        if let Some((_, endpoint)) = self
            .discovery_witnesses
            .iter()
            .flatten()
            .find(|(peer, _)| *peer == key.peer)
        {
            self.swarm
                .behaviour_mut()
                .inner
                .admission
                .allow_infrastructure_fixture(key, root, *endpoint)
                .unwrap();
        }
        #[cfg(not(test))]
        let _ = (key, root);
    }

    pub(super) fn stage_discovery_dial(
        &mut self,
        options: &DialOpts,
        root: &libp2p::Multiaddr,
        epoch: roles::DiscoveryEpoch,
        deadline: Instant,
    ) -> io::Result<AttemptKey> {
        let peer = options
            .get_peer_id()
            .ok_or_else(|| io::Error::other("discovery dial has no expected peer"))?;
        if self.infrastructure.entries.len() >= roles::INFRASTRUCTURE_CONNECTIONS
            || self
                .infrastructure
                .entries
                .values()
                .any(|entry| entry.key.peer == peer)
            || self.pending.values().any(|entry| entry.peer == peer)
        {
            return Err(capacity());
        }
        let view = self
            .swarm
            .behaviour()
            .inner
            .admission
            .roles_view()
            .ok_or_else(|| io::Error::other("discovery authority unavailable"))?;
        if !view.discovery_epoch_active(epoch, Instant::now()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "discovery epoch retired",
            ));
        }
        // Admission checks the original address list against this exact root before I/O.
        let admission = &mut self.swarm.behaviour_mut().inner.admission;
        let newly_admitted = view.role(peer).is_none();
        admission.admit_identity(peer, roles::Role::Infrastructure)?;
        let (key, permit) =
            match admission.stage_infrastructure(peer, root, options.connection_id(), deadline) {
                Ok(staged) => staged,
                Err(error) => {
                    if newly_admitted && let Some(owner) = admission.discovery_owner() {
                        let _ = owner.forget_identity(peer);
                    }
                    return Err(admission_error(error));
                }
            };
        self.infrastructure.entries.insert(
            key.connection,
            Entry {
                key,
                permit,
                deadline,
                phase: Phase::Pending,
                protocols: 0,
                identified: false,
                epoch: Some(epoch),
            },
        );
        self.discovery_fixture(key, root);
        Ok(key)
    }

    pub(super) fn record_infrastructure_protocols(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        advertised: Option<&[StreamProtocol]>,
    ) -> Option<u8> {
        let entry = self.infrastructure.entries.get_mut(&connection)?;
        if entry.key.peer != peer || entry.phase != Phase::Live {
            return None;
        }
        let view = self.swarm.behaviour().inner.admission.roles_view()?;
        view.infrastructure_live(entry.key)?;
        entry.identified = true;
        let capabilities = advertised.map(protocols::capabilities).unwrap_or(0);
        if entry.protocols == capabilities {
            return None;
        }
        entry.protocols = capabilities;
        Some(capabilities)
    }

    /// Shared explicit native path; public commands perform APP authorization before calling.
    pub(super) fn prepare_native(
        &mut self,
        peer: PeerId,
        address: &libp2p::Multiaddr,
    ) -> io::Result<(DialOpts, Option<AttemptKey>)> {
        if self
            .swarm
            .behaviour()
            .inner
            .admission
            .connection(&peer)
            .is_some()
            || self.pending.values().any(|pending| pending.peer == peer)
            || self
                .infrastructure
                .entries
                .values()
                .any(|entry| entry.key.peer == peer)
        {
            return Err(capacity());
        }
        let infrastructure = self
            .swarm
            .behaviour()
            .inner
            .admission
            .roles_view()
            .is_some_and(|view| view.role(peer) == Some(roles::Role::Infrastructure));
        if infrastructure {
            let selected = self
                .discovery
                .as_ref()
                .and_then(|state| state.seed_address(peer));
            if selected != Some(address) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "infrastructure root not selected",
                ));
            }
            if self.infrastructure.entries.len() >= roles::INFRASTRUCTURE_CONNECTIONS {
                return Err(capacity());
            }
        } else if !self.allows_application(&peer) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "carrier peer not allowed",
            ));
        }
        let options = DialOpts::peer_id(peer)
            .addresses(vec![address.clone()])
            .allocate_new_port()
            .build();
        let id = options.connection_id();
        let attempt = if infrastructure {
            let deadline = Instant::now() + DEADLINE;
            let (key, permit) = self
                .swarm
                .behaviour_mut()
                .inner
                .admission
                .stage_infrastructure(peer, address, id, deadline)
                .map_err(admission_error)?;
            self.infrastructure.entries.insert(
                id,
                Entry {
                    key,
                    permit,
                    deadline,
                    phase: Phase::Pending,
                    protocols: 0,
                    identified: false,
                    epoch: None,
                },
            );
            Some(key)
        } else {
            self.admit_attempt(peer, address, id)
                .map_err(admission_error)?
        };
        Ok((options, attempt))
    }

    pub(super) fn submit_native(
        &mut self,
        options: DialOpts,
        attempt: Option<AttemptKey>,
    ) -> io::Result<(ConnectionId, Option<AttemptKey>)> {
        let id = options.connection_id();
        match self.swarm.dial(options) {
            Ok(()) => Ok((id, attempt)),
            Err(error) => {
                if self.infrastructure.entries.contains_key(&id) {
                    // A synchronous dial rejection leaves no owned dial or connection.
                    self.finish_infrastructure(id);
                } else if let Some(attempt) = attempt {
                    self.terminal(attempt, None);
                }
                Err(io::Error::other(error))
            }
        }
    }

    pub(super) fn dial_native(
        &mut self,
        peer: PeerId,
        address: &libp2p::Multiaddr,
    ) -> io::Result<(ConnectionId, Option<AttemptKey>)> {
        let (options, attempt) = self.prepare_native(peer, address)?;
        self.submit_native(options, attempt)
    }

    pub(super) fn close_infrastructure(&mut self, key: AttemptKey, now: Instant) {
        self.relay_control_closed(key.peer, key.connection);
        self.discovery_lost_control(key);
        let Some(entry) = self
            .infrastructure
            .entries
            .get_mut(&key.connection)
            .filter(|entry| entry.key == key)
        else {
            return;
        };
        if entry.phase != Phase::Closing {
            entry.phase = Phase::Closing;
            entry.deadline = now + DEADLINE;
        }
        entry.protocols = 0;
        self.swarm
            .behaviour_mut()
            .inner
            .admission
            .withdraw_infrastructure(key);
        protocols::update_seed(
            &mut self.swarm.behaviour_mut().inner.protocols,
            key.peer,
            None,
            0,
        );
        // Pending dials stop at their revoked guard; established connections close by ID.
        let _ = self.swarm.close_connection(key.connection);
    }

    pub(super) fn infrastructure_tick(&mut self, now: Instant) -> io::Result<()> {
        if self
            .infrastructure
            .entries
            .values()
            .any(|entry| entry.phase == Phase::Closing && entry.deadline <= now)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "infrastructure close deadline",
            ));
        }
        let mut expired = [None; roles::INFRASTRUCTURE_CONNECTIONS];
        for (slot, entry) in expired.iter_mut().zip(self.infrastructure.entries.values()) {
            if entry.phase == Phase::Pending && entry.deadline <= now {
                *slot = Some(entry.key);
            }
        }
        for key in expired.into_iter().flatten() {
            self.close_infrastructure(key, now);
        }
        Ok(())
    }

    fn finish_infrastructure(&mut self, connection: ConnectionId) {
        if let Some(entry) = self.infrastructure.entries.remove(&connection) {
            self.relay_control_closed(entry.key.peer, entry.key.connection);
            self.discovery_lost_control(entry.key);
            let admission = &mut self.swarm.behaviour_mut().inner.admission;
            admission.terminal(entry.key, None);
            admission.terminal_infrastructure(entry.key);
            protocols::update_seed(
                &mut self.swarm.behaviour_mut().inner.protocols,
                entry.key.peer,
                None,
                0,
            );
            drop(entry.permit);
            if entry.epoch.is_some()
                && let Some(owner) = self.swarm.behaviour_mut().inner.admission.discovery_owner()
            {
                let _ = owner.forget_identity(entry.key.peer);
            }
        }
    }

    pub(super) fn infrastructure_event(&mut self, event: &SwarmEvent<BehaviourEvent>) -> bool {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                if let Some(entry) = self.infrastructure.entries.get(connection_id) {
                    let key = entry.key;
                    let live = key.peer == *peer_id
                        && !endpoint.is_relayed()
                        && self
                            .swarm
                            .behaviour()
                            .inner
                            .admission
                            .roles_view()
                            .is_some_and(|view| view.infrastructure_live(key).is_some());
                    if live && entry.phase == Phase::Pending && Instant::now() < entry.deadline {
                        self.infrastructure
                            .entries
                            .get_mut(connection_id)
                            .expect("same owner")
                            .phase = Phase::Live;
                    } else if !live || entry.phase != Phase::Live {
                        self.close_infrastructure(key, Instant::now());
                    }
                    return true;
                }
                if self
                    .swarm
                    .behaviour()
                    .inner
                    .admission
                    .roles_view()
                    .is_some_and(|view| view.role(*peer_id) == Some(roles::Role::Infrastructure))
                {
                    let _ = self.swarm.close_connection(*connection_id);
                    return true;
                }
            }
            SwarmEvent::OutgoingConnectionError { connection_id, .. } => {
                if self.infrastructure.entries.contains_key(connection_id) {
                    self.finish_infrastructure(*connection_id);
                    return true;
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                if let Some(entry) = self.infrastructure.entries.get(connection_id) {
                    if entry.key.peer == *peer_id {
                        self.finish_infrastructure(*connection_id);
                    }
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    pub(super) fn withdraw_all_infrastructure(&mut self) {
        for entry in self.infrastructure.entries.values() {
            self.swarm
                .behaviour_mut()
                .inner
                .admission
                .withdraw_infrastructure(entry.key);
        }
    }

    pub(super) fn take_infrastructure_shutdown(&mut self) -> (Option<Owner>, State) {
        self.withdraw_all_infrastructure();
        let authority = self.swarm.behaviour_mut().inner.admission.take_authority();
        (authority, std::mem::take(&mut self.infrastructure))
    }
}

#[cfg(test)]
#[path = "infrastructure_tests/mod.rs"]
mod tests;
