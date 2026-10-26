use super::*;

impl Gate {
    pub(crate) fn test_admit(
        &self,
        peer: PeerId,
        generation: u64,
        address: Multiaddr,
        kind: OperationKind,
        control: Option<ConnectionId>,
    ) -> bool {
        let Some(g) = NonZeroU64::new(generation) else {
            return false;
        };
        self.core
            .admit(&OperationDescriptor::new(peer, address, kind, g), control)
    }

    pub(crate) fn lifetime_observer(&self) -> impl Fn() -> bool + use<> {
        let weak = Arc::downgrade(&self.core);
        move || weak.upgrade().is_some()
    }

    pub(crate) fn record_count(&self) -> usize {
        lock(&self.core.records).len()
    }

    /// Test handle to a record's release flag: true only after the owner AND
    /// every capability clone were dropped.
    pub(crate) fn released_flag(
        &self,
        peer: PeerId,
        slot: Slot,
        generation: u64,
    ) -> Option<Arc<AtomicBool>> {
        lock(&self.core.records)
            .get(&(peer, slot, generation))
            .map(|record| record.released.clone())
    }
}
