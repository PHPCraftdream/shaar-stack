use super::*;
use crate::{carrier::admission::Admission, discovery::roles};
use libp2p::swarm::dummy;
use std::{convert::Infallible, time::Duration};

struct Offers {
    addresses: Vec<Multiaddr>,
    calls: usize,
}

impl NetworkBehaviour for Offers {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.calls += 1;
        Ok(std::mem::take(&mut self.addresses))
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[derive(NetworkBehaviour)]
struct Composed {
    admission: Admission,
    offers: Offers,
}

fn peer(value: u8) -> PeerId {
    let mut bytes = [value; 34];
    bytes[0] = 0x12;
    bytes[1] = 32;
    PeerId::from_bytes(&bytes).unwrap()
}

fn root(peer: PeerId, port: u16) -> Multiaddr {
    format!("/ip4/192.0.2.1/tcp/{port}/p2p/{peer}")
        .parse()
        .unwrap()
}

fn composed(
    configured: bool,
    additional: Vec<Multiaddr>,
) -> (Boundary<Composed>, PeerId, ConnectionId, Multiaddr) {
    let peer = peer(1);
    let original = root(peer, 1);
    let id = ConnectionId::new_unchecked(1);
    let mut admission = if configured {
        Admission::with_authority(vec![peer], roles::Owner::new(&[peer], &[]).unwrap(), None)
            .unwrap()
    } else {
        Admission::new(vec![peer]).unwrap()
    };
    admission.stage_native(peer, &original, id).unwrap();
    let boundary = Boundary {
        inner: Composed {
            admission,
            offers: Offers {
                addresses: additional,
                calls: 0,
            },
        },
        validate: |inner, id, peer, original, additional| {
            inner
                .admission
                .validate_additional(id, peer, original, additional)
        },
    };
    (boundary, peer, id, original)
}

#[test]
fn aggregate_boundary_rejects_sibling_foreign_root_after_admission() {
    for additional in [root(peer(1), 2), root(peer(2), 1)] {
        let (mut boundary, peer, id, original) = composed(true, vec![additional]);
        assert!(
            boundary
                .handle_pending_outbound_connection(id, Some(peer), &[original], Endpoint::Dialer,)
                .is_err()
        );
        assert_eq!(boundary.inner.offers.calls, 1);
    }
}

#[test]
fn aggregate_boundary_preserves_current_root_and_contribution_order() {
    let additional = vec![root(peer(1), 1); 3];
    let (mut boundary, peer, id, original) = composed(true, additional.clone());
    assert_eq!(
        boundary
            .handle_pending_outbound_connection(id, Some(peer), &[original], Endpoint::Dialer,)
            .unwrap(),
        additional
    );
    assert_eq!(boundary.inner.offers.calls, 1);
}

#[test]
fn aggregate_boundary_rejects_overbudget_contribution_and_unstaged_connection() {
    let (mut boundary, peer, id, original) = composed(true, vec![root(peer(1), 1); 4]);
    assert!(
        boundary
            .handle_pending_outbound_connection(
                id,
                Some(peer),
                std::slice::from_ref(&original),
                Endpoint::Dialer,
            )
            .is_err()
    );
    assert_eq!(boundary.inner.offers.calls, 1);
    assert!(
        boundary
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(2),
                Some(peer),
                &[original],
                Endpoint::Dialer,
            )
            .is_err()
    );
    assert_eq!(boundary.inner.offers.calls, 1);
}

#[tokio::test(start_paused = true)]
async fn aggregate_boundary_rejects_expired_authority() {
    let (mut boundary, peer, id, original) = composed(true, vec![root(peer(1), 1)]);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(
        boundary
            .handle_pending_outbound_connection(id, Some(peer), &[original], Endpoint::Dialer,)
            .is_err()
    );
}

#[test]
fn aggregate_boundary_preserves_unconfigured_carrier_behavior() {
    let additional = vec![root(peer(2), 2); 5];
    let (mut boundary, peer, id, original) = composed(false, additional.clone());
    assert_eq!(
        boundary
            .handle_pending_outbound_connection(id, Some(peer), &[original], Endpoint::Dialer,)
            .unwrap(),
        additional
    );
}
