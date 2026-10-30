use libp2p::{
    Multiaddr, PeerId, StreamProtocol, identify, identity::PublicKey, kad, swarm::NetworkBehaviour,
};

use crate::{CONTROL_PROTOCOL, discovery::roles::View};

mod guard;
mod owner;

pub(super) use owner::{Control, Operation};

pub(super) const DHT: u8 = 1;
pub(super) const HOP: u8 = 2;
const DHT_PROTOCOL: &str = "/ipfs/kad/1.0.0";
const HOP_PROTOCOL: &str = "/libp2p/circuit/relay/0.2.0/hop";

pub(super) type Behaviour = guard::Guard<Inner>;

// The enclosing Carrier event already reserves its larger inline packet payload.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(super) enum Event {
    Kad(kad::Event),
    Identify(identify::Event),
    RejectedAddress,
}

impl From<kad::Event> for Event {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<identify::Event> for Event {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub(super) struct Inner {
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
}

pub(super) fn new(peer: PeerId, public: PublicKey, view: Option<View>) -> Behaviour {
    let inner = view.as_ref().map(|view| {
        let mut config = kad::Config::new(StreamProtocol::new(DHT_PROTOCOL));
        config.set_kbucket_inserts(kad::BucketInserts::Manual);
        config.set_periodic_bootstrap_interval(None);
        config.set_automatic_bootstrap_throttle(None);
        config.set_caching(kad::Caching::Disabled);
        let referrals = view.clone();
        config.set_query_referral_filter(move |query, source, peer, addresses| {
            referrals.admit_query_referral(query, source, peer, addresses)
        });
        let mut kad = kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), config);
        kad.set_mode(Some(kad::Mode::Client));
        let identify = identify::Behaviour::new(
            identify::Config::new(CONTROL_PROTOCOL.to_owned(), public)
                .with_cache_size(0)
                .with_push_listen_addr_updates(false)
                .with_hide_listen_addrs(true),
        );
        Inner { kad, identify }
    });
    guard::Guard::new(inner, view, || Event::RejectedAddress)
}

pub(super) fn capabilities(protocols: &[StreamProtocol]) -> u8 {
    protocols.iter().fold(0, |bits, protocol| {
        bits | match protocol.as_ref() {
            DHT_PROTOCOL => DHT,
            HOP_PROTOCOL => HOP,
            _ => 0,
        }
    })
}

pub(super) fn update_seed(
    behaviour: &mut Behaviour,
    peer: PeerId,
    address: Option<&Multiaddr>,
    capabilities: u8,
) {
    let Some(inner) = behaviour.as_mut() else {
        return;
    };
    if capabilities & DHT != 0 {
        if let Some(address) = address {
            inner.kad.add_address(&peer, address.clone());
        }
    } else {
        inner.kad.remove_peer(&peer);
    }
}

pub(super) fn start_query(behaviour: &mut Behaviour, target: PeerId) -> Option<kad::QueryId> {
    behaviour
        .as_mut()
        .map(|inner| inner.kad.get_closest_peers(target))
}

pub(super) fn finish_query(behaviour: &mut Behaviour, id: kad::QueryId) {
    if let Some(inner) = behaviour.as_mut()
        && let Some(mut query) = inner.kad.query_mut(&id)
    {
        query.finish();
    }
}

pub(super) fn reject_unowned_query(behaviour: &mut Behaviour, event: kad::Event) {
    if let kad::Event::OutboundQueryProgressed { id, .. } = event {
        finish_query(behaviour, id);
    }
}

#[cfg(test)]
pub(super) fn cached_addresses(behaviour: &mut Behaviour, peer: PeerId) -> Vec<Multiaddr> {
    let Some(inner) = behaviour.as_mut() else {
        return Vec::new();
    };
    inner
        .kad
        .handle_pending_outbound_connection(
            libp2p::swarm::ConnectionId::new_unchecked(usize::MAX),
            Some(peer),
            &[],
            libp2p::core::Endpoint::Dialer,
        )
        .unwrap()
}

#[cfg(test)]
mod tests;
