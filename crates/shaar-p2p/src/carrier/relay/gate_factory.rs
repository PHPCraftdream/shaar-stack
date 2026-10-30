use super::*;

impl GateCore {
    /// The factory takes the precharged capability of the matching staged
    /// generation exactly once: the FULL descriptor (peer, exact address
    /// bytes, kind incl. destination, generation, roles) is validated against
    /// the staged record; a second take for an already claimed generation
    /// fails with WouldBlock, anything unmatched with PermissionDenied.
    pub(super) fn issue(
        &self,
        peer: PeerId,
        address: &Multiaddr,
        kind: OperationKind,
        roles: &roles::View,
        require_pending: bool,
    ) -> io::Result<OperationCapability> {
        let (slot, destination) = match kind {
            OperationKind::Reserve => (Slot::Reserve, None),
            OperationKind::Connect { destination } => (Slot::Connect, Some(destination)),
            // OperationKind is #[non_exhaustive]: unknown kinds fail closed.
            _ => return Err(denied()),
        };
        let Some(parsed) = endpoint(address) else {
            return Err(denied());
        };
        let role = roles.role(peer);
        if role != Some(Role::Infrastructure) && role != Some(Role::ExplicitRelay(parsed)) {
            return Err(denied());
        }
        // Circuit destinations remain application-allowlisted under either provenance.
        if destination.is_some_and(|destination| roles.role(destination) != Some(Role::Application))
        {
            return Err(denied());
        }
        let mut pending_lease = if require_pending {
            match destination {
                Some(destination) => {
                    let now = Instant::now();
                    let key = roles.current(destination, now).ok_or_else(denied)?;
                    if !roles.is_child(key) {
                        return Err(denied());
                    }
                    Some(roles.pending_lease(key, now)?)
                }
                None => None,
            }
        } else {
            None
        };
        // The precharged descriptor carries `multiaddr(endpoint)`; the
        // transport-passed address must be byte-identical so the patched
        // `capture` equality check passes.
        let expected = multiaddr(parsed);
        let records = lock(&self.records);
        let mut candidate: Option<Key> = None;
        let mut claimed = None;
        for (key, record) in records.iter() {
            if key.0 != peer || key.1 != slot {
                continue;
            }
            if record.endpoint != parsed || record.destination != destination {
                continue;
            }
            if record.capability.is_some()
                && matches!(record.state, RecordState::Staged | RecordState::Established)
            {
                // Lowest generation first when several generations match.
                if candidate.is_none_or(|best: Key| key.2 < best.2) {
                    candidate = Some(*key);
                }
            } else if !record.retired() {
                // Live but already claimed (Issued, or Established without a
                // stored capability): a duplicate take is backpressure, while
                // retired tombstones simply do not match.
                claimed.get_or_insert(record.authority);
            }
        }
        let key = match candidate {
            Some(key) => key,
            None => {
                drop(records);
                return Err(
                    if claimed.is_some_and(|authority| authority.permits(roles, peer, parsed)) {
                        super::super::capacity()
                    } else {
                        denied()
                    },
                );
            }
        };
        if *address != expected {
            return Err(denied());
        }
        let authority = records.get(&key).ok_or_else(denied)?.authority;
        drop(records);
        if !authority.permits(roles, peer, parsed) {
            return Err(denied());
        }
        let mut records = lock(&self.records);
        let record = records.get_mut(&key).ok_or_else(denied)?;
        if record.retired()
            || record.authority != authority
            || record.endpoint != parsed
            || record.destination != destination
            || Instant::now() >= record.deadline
        {
            return Err(denied());
        }
        let capability = record
            .capability
            .take()
            .ok_or_else(super::super::capacity)?;
        let hold = record.pending_hold.clone();
        if matches!(record.state, RecordState::Staged) {
            record.state = RecordState::Issued;
        }
        drop(records);
        if let Some(lease) = pending_lease.take() {
            let previous = { lock(&hold).replace(lease) };
            drop(previous);
        }
        Ok(capability)
    }

    /// Owner-side admit: checks generation, staged intent kind, pinned relay
    /// role and endpoint, destination allowlist, dial deadline and the
    /// authenticated control binding (first bind wins, synchronously under
    /// this short lock). Synchronous, bounded, never blocks or awaits.
    pub(super) fn admit(
        &self,
        descriptor: &OperationDescriptor,
        control: Option<ConnectionId>,
    ) -> bool {
        let slot = match descriptor.kind() {
            OperationKind::Reserve => Slot::Reserve,
            OperationKind::Connect { .. } => Slot::Connect,
            // OperationKind is #[non_exhaustive]: unknown kinds fail closed.
            _ => return false,
        };
        let view = { lock(&self.roles).clone() };
        let Some(view) = view else {
            return false;
        };
        let Some(parsed) = endpoint(descriptor.address()) else {
            return false;
        };
        let key = (descriptor.peer(), slot, descriptor.generation().get());
        let authority = {
            let records = lock(&self.records);
            let Some(record) = records.get(&key) else {
                return false;
            };
            record.authority
        };
        if !authority.permits(&view, descriptor.peer(), parsed)
            || !authority.accepts_control(control)
            || matches!(descriptor.kind(), OperationKind::Connect { destination } if view.role(destination) != Some(Role::Application))
        {
            return false;
        }
        let mut records = lock(&self.records);
        let Some(record) = records.get_mut(&key) else {
            return false;
        };
        // Retired tombstones (revoked/expired/replaced) admit nothing, and a
        // re-staged generation carries a fresh number: stale tickets fail
        // closed here.
        if record.retired() || record.endpoint != parsed || record.authority != authority {
            return false;
        }
        match (descriptor.kind(), record.destination) {
            (OperationKind::Reserve, None) => {}
            (OperationKind::Connect { destination }, Some(allowed)) if allowed == destination => {}
            _ => return false,
        }
        if !matches!(record.state, RecordState::Established) && Instant::now() >= record.deadline {
            return false;
        }
        match (record.control, control) {
            (Some(bound), Some(id)) => bound == id,
            (Some(_), None) => false,
            // Capture-time liveness runs before any authenticated bind exists.
            (None, None) => true,
            (None, Some(id)) => {
                record.control = Some(id);
                true
            }
        }
    }
}
