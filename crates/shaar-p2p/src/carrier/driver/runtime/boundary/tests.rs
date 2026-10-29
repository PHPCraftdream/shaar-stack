use super::*;
use crate::{carrier::admission::Admission, discovery::roles};
use libp2p::swarm::dummy;
use std::{convert::Infallible, time::Duration};

#[tokio::test(start_paused = true)]
async fn rootless_infrastructure_requires_exact_pending_owner_authority() {
    let peer = peer(1);
    let address: Multiaddr = format!("/ip4/8.8.8.8/tcp/1/p2p/{peer}").parse().unwrap();
    let id = ConnectionId::new_unchecked(1);
    let owner = roles::Owner::new(&[], &[peer]).unwrap();
    let mut admission = Admission::with_authority(vec![], owner, None).unwrap();
    let view = admission.roles_view().unwrap();
    let now = tokio::time::Instant::now();
    let (key, _permit) = admission
        .stage_infrastructure(peer, &address, id, now + Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        view.pending_infrastructure_root(key, now),
        Some(address.clone())
    );
    assert_eq!(
        admission
            .handle_pending_outbound_connection(id, Some(peer), &[], Endpoint::Dialer,)
            .unwrap(),
        vec![address]
    );
    assert!(
        admission
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(2),
                Some(peer),
                &[],
                Endpoint::Dialer,
            )
            .is_err()
    );
    assert!(
        admission
            .handle_pending_outbound_connection(id, None, &[], Endpoint::Dialer,)
            .is_err()
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(
        view.pending_infrastructure_root(key, tokio::time::Instant::now())
            .is_none()
    );
    assert!(
        admission
            .handle_pending_outbound_connection(id, Some(peer), &[], Endpoint::Dialer,)
            .is_err()
    );
}

#[test]
fn rootless_infrastructure_withdrawal_does_not_grant_app_root_discovery() {
    let peer = peer(1);
    let address: Multiaddr = format!("/ip4/8.8.8.8/tcp/1/p2p/{peer}").parse().unwrap();
    let id = ConnectionId::new_unchecked(1);
    let owner = roles::Owner::new(&[], &[peer]).unwrap();
    let mut admission = Admission::with_authority(vec![], owner, None).unwrap();
    let now = tokio::time::Instant::now();
    let (key, _permit) = admission
        .stage_infrastructure(peer, &address, id, now + Duration::from_secs(10))
        .unwrap();
    admission.withdraw_infrastructure(key);
    assert!(
        admission
            .handle_pending_outbound_connection(id, Some(peer), &[], Endpoint::Dialer,)
            .is_err()
    );
    let (mut app, peer, id, _) = composed(true, vec![]);
    assert!(
        app.handle_pending_outbound_connection(id, Some(peer), &[], Endpoint::Dialer,)
            .is_err()
    );
}

#[test]
fn infrastructure_cache_addresses_cannot_widen_the_selected_root() {
    for explicit in [false, true] {
        let peer = peer(1);
        let selected: Multiaddr = format!("/ip4/8.8.8.8/tcp/1/p2p/{peer}").parse().unwrap();
        let foreign = root(self::peer(2), 1);
        for include_selected in [false, true] {
            let mut cached = vec![foreign.clone(); 5];
            if include_selected {
                cached.extend([selected.clone(), selected.clone()]);
            }
            let (mut boundary, _, id, _) = composed(false, cached);
            let owner = roles::Owner::new(&[], &[peer]).unwrap();
            let mut admission = Admission::with_authority(vec![], owner, None).unwrap();
            let (key, _permit) = admission
                .stage_infrastructure(
                    peer,
                    &selected,
                    id,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                )
                .unwrap();
            boundary.inner.admission = admission;
            let original = if explicit {
                vec![selected.clone()]
            } else {
                vec![]
            };
            let additional = boundary
                .handle_pending_outbound_connection(id, Some(peer), &original, Endpoint::Dialer)
                .unwrap();
            let expected = if !explicit || include_selected {
                vec![selected.clone()]
            } else {
                vec![]
            };
            assert_eq!(additional, expected);
            assert_eq!(boundary.inner.offers.calls, 1);
            assert!(!boundary.inner.admission.allows(&peer));
            boundary.inner.admission.withdraw_infrastructure(key);
            assert!(
                boundary
                    .handle_pending_outbound_connection(id, Some(peer), &[], Endpoint::Dialer,)
                    .is_err()
            );
        }
    }
}

struct Offers {
    addresses: Vec<Multiaddr>,
    calls: usize,
    dial: Option<DialOpts>,
    close: Option<PeerId>,
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
        if let Some(opts) = self.dial.take() {
            return Poll::Ready(ToSwarm::Dial { opts });
        }
        if let Some(peer_id) = self.close.take() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: libp2p::swarm::CloseConnection::All,
            });
        }
        Poll::Pending
    }
}

#[derive(Debug)]
enum ComposedEvent {
    Dial(DialOpts),
}

impl From<Infallible> for ComposedEvent {
    fn from(event: Infallible) -> Self {
        match event {}
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ComposedEvent")]
struct Composed {
    admission: Admission,
    offers: Offers,
}

#[test]
fn dependency_dial_handoff_preserves_original_options_and_emits_once() {
    let (mut boundary, peer, _, address) = composed(true, vec![]);
    let opts = DialOpts::peer_id(peer)
        .addresses(vec![address])
        .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
        .allocate_new_port()
        .build();
    let id = opts.connection_id();
    let expected = format!("{opts:?}");
    boundary.inner.offers.dial = Some(opts);
    let mut context = Context::from_waker(std::task::Waker::noop());
    match boundary.poll(&mut context) {
        Poll::Ready(ToSwarm::GenerateEvent(ComposedEvent::Dial(actual))) => {
            assert_eq!(actual.connection_id(), id);
            assert_eq!(actual.get_peer_id(), Some(peer));
            assert_eq!(format!("{actual:?}"), expected);
        }
        other => panic!("dependency dial must reach owner, not Swarm: {other:?}"),
    }
    assert!(boundary.poll(&mut context).is_pending());
}

#[test]
fn dependency_dial_handoff_preserves_non_dial_actions_and_progress() {
    let (mut boundary, peer, _, address) = composed(true, vec![]);
    boundary.inner.offers.dial = Some(DialOpts::peer_id(peer).addresses(vec![address]).build());
    boundary.inner.offers.close = Some(peer);
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        boundary.poll(&mut context),
        Poll::Ready(ToSwarm::GenerateEvent(ComposedEvent::Dial(_)))
    ));
    match boundary.poll(&mut context) {
        Poll::Ready(ToSwarm::CloseConnection {
            peer_id,
            connection: libp2p::swarm::CloseConnection::All,
        }) => assert_eq!(peer_id, peer),
        other => panic!("non-dial action must pass through: {other:?}"),
    }
    assert!(boundary.poll(&mut context).is_pending());
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
        dial_event: ComposedEvent::Dial,
        inner: Composed {
            admission,
            offers: Offers {
                addresses: additional,
                calls: 0,
                dial: None,
                close: None,
            },
        },
        constrain: |inner, id, peer, original, additional| {
            inner
                .admission
                .constrain_additional(id, peer, original, additional)
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
