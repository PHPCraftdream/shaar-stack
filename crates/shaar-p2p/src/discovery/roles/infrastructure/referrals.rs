//! Query admission shares the role mutex; retained hints contain only bounded scalar data.

use libp2p::{Multiaddr, PeerId, kad::QueryId, multiaddr::Protocol};
use tokio::time::Instant;

use super::super::{AttemptKey, Owner, Role, State, View, denied, full};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Epoch {
    owner: u64,
    serial: u64,
}

pub(in super::super) struct Admission {
    epoch: Epoch,
    local: PeerId,
    deadline: Instant,
    query: Option<QueryId>,
    active: bool,
    sources: [Option<AttemptKey>; super::super::INFRASTRUCTURE_CONNECTIONS],
}

#[derive(Clone, Copy)]
pub(in super::super) struct Hint {
    encoded: Encoded,
    epoch: Option<Epoch>,
    source: usize,
}

#[derive(Clone, Copy)]
struct Encoded {
    bytes: [u8; 256],
    length: u16,
}

impl Encoded {
    fn new(peer: PeerId, address: &Multiaddr) -> Option<Self> {
        let raw = address.as_ref();
        if raw.len() > 256 {
            return None;
        }
        let mut bytes = [0; 256];
        bytes[..raw.len()].copy_from_slice(raw);
        let length = if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
            raw.len()
        } else {
            let mut remaining = &mut bytes[raw.len()..];
            Protocol::P2p(peer).write_bytes(&mut remaining).ok()?;
            256 - remaining.len()
        };
        crate::discovery::address::classify_complete(&bytes[..length], peer).ok()?;
        Some(Self {
            bytes,
            length: u16::try_from(length).ok()?,
        })
    }

    fn same(&self, other: &Self) -> bool {
        self.length == other.length
            && self.bytes[..usize::from(self.length)] == other.bytes[..usize::from(other.length)]
    }
}

fn source_live(state: &State, key: AttemptKey) -> bool {
    !state.closed
        && state.infrastructure.iter().flatten().any(|row| {
            row.key == key
                && !row.withdrawn
                && !row.connection_terminal
                && row.native_terminal
                && row.authenticated.is_some()
        })
}

fn eligible(state: &State, peer: PeerId) -> bool {
    state
        .identities
        .get(&peer)
        .is_none_or(|identity| identity.role == Role::Infrastructure)
}

impl Owner {
    /// Constructor seed roots consume the same lifetime slots without referral provenance.
    pub(crate) fn reserve_discovery_address(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
    ) -> std::io::Result<()> {
        let encoded = Encoded::new(peer, address).ok_or_else(denied)?;
        let mut state = self.view.lock();
        if state.closed
            || state.query_admission.is_some()
            || !state
                .identities
                .get(&peer)
                .is_some_and(|identity| identity.reserved && identity.role == Role::Infrastructure)
        {
            return Err(denied());
        }
        let index = state
            .contacts
            .iter()
            .position(|contact| *contact == Some(peer))
            .ok_or_else(denied)?;
        let hints = &mut state.query_hints[index];
        if hints
            .iter()
            .flatten()
            .any(|hint| hint.encoded.same(&encoded))
        {
            return Ok(());
        }
        let slot = hints
            .iter_mut()
            .find(|hint| hint.is_none())
            .ok_or_else(full)?;
        *slot = Some(Hint {
            encoded,
            epoch: None,
            source: 0,
        });
        Ok(())
    }

    pub(crate) fn begin_discovery_epoch(
        &mut self,
        local: PeerId,
        deadline: Instant,
        now: Instant,
    ) -> std::io::Result<Epoch> {
        let mut state = self.view.lock();
        if state.closed || deadline <= now || deadline > now + std::time::Duration::from_secs(10) {
            return Err(denied());
        }
        if state
            .query_admission
            .as_ref()
            .is_some_and(|query| query.active)
        {
            return Err(full());
        }
        // Retained leases defer retirement; a new operation collects only released roles.
        let State {
            identities,
            attempts,
            infrastructure,
            ..
        } = &mut *state;
        identities.retain(|peer, identity| {
            identity.reserved
                || identity.role != Role::Infrastructure
                || attempts.values().any(|attempt| attempt.key.peer == *peer)
                || infrastructure
                    .iter()
                    .flatten()
                    .any(|row| row.key.peer == *peer)
        });
        state.serial = state.serial.checked_add(1).ok_or_else(full)?;
        let epoch = Epoch {
            owner: state.owner,
            serial: state.serial,
        };
        state.query_admission = Some(Admission {
            epoch,
            local,
            deadline,
            query: None,
            active: true,
            sources: [None; super::super::INFRASTRUCTURE_CONNECTIONS],
        });
        Ok(epoch)
    }

    pub(crate) fn bind_discovery_query(
        &mut self,
        epoch: Epoch,
        query: QueryId,
        now: Instant,
    ) -> std::io::Result<()> {
        let mut state = self.view.lock();
        if state.closed {
            return Err(denied());
        }
        let current = state.query_admission.as_mut().ok_or_else(denied)?;
        if current.epoch != epoch
            || !current.active
            || now >= current.deadline
            || current.query.is_some()
        {
            return Err(denied());
        }
        current.query = Some(query);
        Ok(())
    }

    /// The owner calls this only after exact-connection Identify has advertised DHT.
    pub(crate) fn bind_discovery_source(
        &mut self,
        epoch: Epoch,
        key: AttemptKey,
        now: Instant,
    ) -> std::io::Result<()> {
        let mut state = self.view.lock();
        if !source_live(&state, key) {
            return Err(denied());
        }
        let current = state.query_admission.as_mut().ok_or_else(denied)?;
        if current.epoch != epoch || !current.active || now >= current.deadline {
            return Err(denied());
        }
        if let Some(previous) = current
            .sources
            .iter()
            .flatten()
            .find(|source| source.peer == key.peer)
        {
            return if *previous == key {
                Ok(())
            } else {
                Err(denied())
            };
        }
        let slot = current
            .sources
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(full)?;
        *slot = Some(key);
        Ok(())
    }

    /// Close admission before touching the dependency query or its owned connections.
    pub(crate) fn retire_discovery_epoch(&mut self, epoch: Epoch) {
        let mut state = self.view.lock();
        if let Some(current) = state
            .query_admission
            .as_mut()
            .filter(|current| current.epoch == epoch)
        {
            current.active = false;
        }
    }
}

impl View {
    pub(crate) fn discovery_epoch_active(&self, epoch: Epoch, now: Instant) -> bool {
        let state = self.lock();
        !state.closed
            && state.query_admission.as_ref().is_some_and(|current| {
                current.epoch == epoch && current.active && now < current.deadline
            })
    }

    pub(crate) fn discovery_source(&self, epoch: Epoch, key: AttemptKey) -> bool {
        let state = self.lock();
        state
            .query_admission
            .as_ref()
            .is_some_and(|current| current.epoch == epoch && current.sources.contains(&Some(key)))
    }

    /// Pre-retention policy: no role admission, foreign callback or resource destructor under lock.
    pub(crate) fn admit_query_referral(
        &self,
        query: QueryId,
        source: PeerId,
        peer: PeerId,
        addresses: &[Multiaddr],
    ) -> bool {
        if addresses.is_empty() || addresses.len() > 4 {
            return false;
        }
        let mut validated = [None; 4];
        for (slot, address) in validated.iter_mut().zip(addresses) {
            let Some(encoded) = Encoded::new(peer, address) else {
                return false;
            };
            *slot = Some(encoded);
        }
        let now = Instant::now();
        let mut state = self.lock();
        let Some(current) = state.query_admission.as_ref() else {
            return false;
        };
        if state.closed
            || !current.active
            || current.query != Some(query)
            || now >= current.deadline
            || current.local == peer
            || !eligible(&state, peer)
        {
            return false;
        }
        let Some((source_index, key)) =
            current
                .sources
                .iter()
                .enumerate()
                .find_map(|(index, slot)| {
                    slot.filter(|key| key.peer == source)
                        .map(|key| (index, key))
                })
        else {
            return false;
        };
        if !source_live(&state, key) {
            return false;
        }
        let epoch = current.epoch;
        let Some(index) = state
            .contacts
            .iter()
            .position(|contact| *contact == Some(peer))
            .or_else(|| state.contacts.iter().position(Option::is_none))
        else {
            return false;
        };
        // Transactional fixed-size staging: a rejected fifth address changes no retained hints.
        let mut proposed = state.query_hints[index];
        for encoded in validated.into_iter().flatten() {
            let slot = proposed
                .iter()
                .position(|hint| hint.is_some_and(|hint| hint.encoded.same(&encoded)))
                .or_else(|| proposed.iter().position(Option::is_none));
            let Some(slot) = slot else { return false };
            proposed[slot] = Some(Hint {
                encoded,
                epoch: Some(epoch),
                source: source_index,
            });
        }
        state.contacts[index] = Some(peer);
        state.query_hints[index] = proposed;
        true
    }

    pub(crate) fn discovery_referral_root(
        &self,
        epoch: Epoch,
        peer: PeerId,
        now: Instant,
    ) -> Option<Multiaddr> {
        let encoded = {
            let state = self.lock();
            let current = state.query_admission.as_ref()?;
            if state.closed
                || current.epoch != epoch
                || !current.active
                || now >= current.deadline
                || peer == current.local
                || !eligible(&state, peer)
            {
                return None;
            }
            let index = state
                .contacts
                .iter()
                .position(|contact| *contact == Some(peer))?;
            state.query_hints[index].iter().flatten().find_map(|hint| {
                if hint.epoch != Some(epoch) {
                    return None;
                }
                let key = current.sources.get(hint.source).copied().flatten()?;
                source_live(&state, key).then_some(hint.encoded)
            })?
        };
        // The only allocation materializes a selected dial root after unlocking.
        Multiaddr::try_from(encoded.bytes[..usize::from(encoded.length)].to_vec()).ok()
    }
}
