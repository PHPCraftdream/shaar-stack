#![forbid(unsafe_code)]

#[cfg(test)]
mod retention_behaviour {
    #![forbid(unsafe_code)]

    use super::*;
    use crate::store::MemoryStore;
    use libp2p_core::{multiaddr::Protocol, multihash::Multihash};

    fn peer(value: u8) -> PeerId {
        PeerId::from_multihash(Multihash::wrap(0x12, &[value; 32]).unwrap()).unwrap()
    }

    fn address(port: u16) -> Multiaddr {
        format!("/ip4/192.0.2.1/tcp/{port}").parse().unwrap()
    }

    fn sized_address(bytes: usize) -> Multiaddr {
        let result = Multiaddr::from(Protocol::Dns("x".repeat(bytes - 3).into()));
        assert_eq!(result.as_ref().len(), bytes);
        result
    }

    fn referral(value: u8, multiaddrs: Vec<Multiaddr>) -> KadPeer {
        KadPeer {
            node_id: peer(value),
            multiaddrs,
            connection_ty: ConnectionType::NotConnected,
        }
    }

    fn behaviour(automatic: Option<Duration>) -> Behaviour<MemoryStore> {
        let mut config = crate::Config::new(crate::PROTOCOL_NAME);
        config.set_periodic_bootstrap_interval(None);
        config.set_automatic_bootstrap_throttle(automatic);
        config.set_kbucket_inserts(BucketInserts::Manual);
        let mut result = crate::Behaviour::with_config(peer(0), MemoryStore::new(peer(0)), config);
        result.set_mode(Some(Mode::Client));
        result
    }

    fn lookup() -> (Behaviour<MemoryStore>, QueryId, PeerId) {
        let mut behaviour = behaviour(None);
        assert!(matches!(
            behaviour.add_address(&peer(1), address(1)),
            RoutingUpdate::Success
        ));
        let query = behaviour.get_closest_peers(vec![42]);
        let source = match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Waiting(Some((_, source))) => source,
            _ => panic!("seed must be scheduled"),
        };
        (behaviour, query, source)
    }

    fn filtered_lookup(
        filter: impl Fn(QueryId, PeerId, PeerId, &[Multiaddr]) -> bool + Send + Sync + 'static,
    ) -> (Behaviour<MemoryStore>, QueryId, PeerId) {
        let mut config = crate::Config::new(crate::PROTOCOL_NAME);
        config.set_periodic_bootstrap_interval(None);
        config.set_automatic_bootstrap_throttle(None);
        config.set_kbucket_inserts(BucketInserts::Manual);
        config.set_query_referral_filter(filter);
        let mut behaviour =
            crate::Behaviour::with_config(peer(0), MemoryStore::new(peer(0)), config);
        behaviour.set_mode(Some(Mode::Client));
        behaviour.add_address(&peer(1), address(1));
        let query = behaviour.get_closest_peers(vec![42]);
        let source = match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Waiting(Some((_, source))) => source,
            _ => panic!("seed must be scheduled"),
        };
        (behaviour, query, source)
    }

    #[test]
    fn referral_filter_denies_retention_and_iterator_scheduling() {
        let (mut behaviour, query, source) = filtered_lookup(|_, _, _, _| false);
        let input = [referral(2, vec![address(2)])];
        behaviour.discovered(&query, &source, input.iter());
        assert!(
            behaviour
                .queries
                .get(&query)
                .unwrap()
                .peers
                .addresses
                .is_empty()
        );
        match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Finished(finished) => {
                let peers: Vec<_> = finished.peers.into_peerids_iter().collect();
                assert_eq!(peers, vec![source]);
            }
            _ => panic!("denied referral must not be scheduled"),
        }
    }

    #[test]
    fn referral_filter_receives_query_source_and_can_revoke_later_responses() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let allowed = Arc::new(AtomicBool::new(true));
        let observed = calls.clone();
        let current = allowed.clone();
        let (mut behaviour, query, source) =
            filtered_lookup(move |query, source, candidate, addresses| {
                observed
                    .lock()
                    .unwrap()
                    .push((query, source, candidate, addresses.to_vec()));
                current.load(Ordering::SeqCst)
            });
        let input = [referral(2, vec![address(2)])];
        behaviour.discovered(&query, &source, input.iter());
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[(query, source, peer(2), vec![address(2)])]
        );
        assert_eq!(
            behaviour.queries.get(&query).unwrap().peers.addresses.len(),
            1
        );
        let next = match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Waiting(Some((_, source))) => source,
            _ => panic!("allowed referral must be scheduled"),
        };
        assert_eq!(next, peer(2));
        allowed.store(false, Ordering::SeqCst);
        behaviour.discovered(&query, &next, [referral(3, vec![address(3)])].iter());
        assert!(
            !behaviour
                .queries
                .get(&query)
                .unwrap()
                .peers
                .addresses
                .contains_key(&peer(3))
        );
        behaviour.query_mut(&query).unwrap().finish();
        let count = calls.lock().unwrap().len();
        behaviour.discovered(&query, &next, input.iter());
        assert_eq!(calls.lock().unwrap().len(), count);
    }

    #[test]
    fn referral_filter_shares_one_caller_budget_across_queries() {
        use std::{
            collections::HashSet,
            sync::{Arc, Mutex},
        };
        let retained = Arc::new(Mutex::new(HashSet::from([peer(1)])));
        let budget = retained.clone();
        let (mut behaviour, first, source) = filtered_lookup(move |_, _, candidate, _| {
            let mut retained = budget.lock().unwrap();
            if retained.contains(&candidate) {
                return true;
            }
            if retained.len() == 2 {
                return false;
            }
            retained.insert(candidate);
            true
        });
        behaviour.discovered(&first, &source, [referral(2, vec![address(2)])].iter());
        let second = behaviour.get_closest_peers(vec![43]);
        assert_ne!(first, second);
        behaviour.discovered(&second, &source, [referral(3, vec![address(3)])].iter());
        assert!(
            behaviour
                .queries
                .get(&second)
                .unwrap()
                .peers
                .addresses
                .is_empty()
        );
        assert_eq!(*retained.lock().unwrap(), HashSet::from([peer(1), peer(2)]));
    }

    #[test]
    fn referral_map_is_bounded_before_completion_across_responses() {
        let (mut behaviour, query, source) = lookup();
        let first: Vec<_> = (2..42).map(|id| referral(id, vec![address(1)])).collect();
        behaviour.discovered(&query, &source, first.iter());
        let retained = &behaviour.queries.get(&query).unwrap().peers.addresses;
        assert_eq!(retained.len(), 32);
        for id in 2..34 {
            assert!(retained.contains_key(&peer(id)));
        }
        for id in 34..42 {
            assert!(!retained.contains_key(&peer(id)));
        }
        let source = match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Waiting(Some((_, source))) => source,
            _ => panic!("retained referral must be scheduled"),
        };
        let mut second: Vec<_> = (42..82).map(|id| referral(id, vec![address(2)])).collect();
        second.push(referral(2, vec![address(2); 64]));
        behaviour.discovered(&query, &source, second.iter());
        let retained = &behaviour.queries.get(&query).unwrap().peers.addresses;
        assert_eq!(retained.len(), 32);
        assert!(!retained.contains_key(&peer(42)));
        assert_eq!(retained[&peer(2)].as_slice(), &[address(1), address(2)]);
        assert!(behaviour.queries.get(&query).is_some());
    }

    #[test]
    fn address_bound_deduplicates_and_rejects_oversize_before_retention() {
        let (mut behaviour, query, source) = lookup();
        let boundary = sized_address(256);
        let oversized = sized_address(257);
        let input = [
            referral(
                2,
                vec![oversized.clone(), address(1), address(1), boundary.clone()],
            ),
            referral(2, vec![address(2), address(2), address(3), address(4)]),
            referral(3, vec![oversized]),
            referral(4, vec![]),
            referral(0, vec![address(1)]),
        ];
        behaviour.discovered(&query, &source, input.iter());
        let retained = &behaviour.queries.get(&query).unwrap().peers.addresses;
        assert_eq!(retained.len(), 1);
        assert_eq!(
            retained[&peer(2)].as_slice(),
            &[address(1), boundary, address(2), address(3)]
        );
        let repeated = [referral(2, vec![address(5); 64])];
        behaviour.discovered(&query, &peer(2), repeated.iter());
        let retained = &behaviour.queries.get(&query).unwrap().peers.addresses;
        assert_eq!(retained[&peer(2)].len(), 4);
        assert!(!retained[&peer(2)].contains(&address(5)));
    }

    #[test]
    fn small_lookup_traverses_referral_and_completes_on_empty_response() {
        let (mut behaviour, query, source) = lookup();
        let input = [referral(2, vec![address(2)])];
        behaviour.discovered(&query, &source, input.iter());
        match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Waiting(Some((_, source))) => assert_eq!(source, peer(2)),
            _ => panic!("referral must be scheduled"),
        }
        behaviour.discovered(&query, &peer(2), std::iter::empty());
        match behaviour.queries.poll(Instant::now()) {
            QueryPoolState::Finished(finished) => {
                assert_eq!(finished.peers.addresses.len(), 1);
                let result: Vec<_> = finished.peers.into_peerids_iter().collect();
                assert_eq!(result.len(), 2);
                assert!(result.contains(&peer(1)));
                assert!(result.contains(&peer(2)));
            }
            _ => panic!("empty response must allow completion"),
        }
    }

    #[test]
    fn finish_and_removed_query_do_not_admit_late_referrals() {
        let (mut behaviour, query, source) = lookup();
        behaviour.query_mut(&query).unwrap().finish();
        let input = [referral(2, vec![address(1)])];
        behaviour.discovered(&query, &source, input.iter());
        assert!(
            behaviour
                .queries
                .get(&query)
                .unwrap()
                .peers
                .addresses
                .is_empty()
        );
        assert!(matches!(
            behaviour.queries.poll(Instant::now()),
            QueryPoolState::Finished(_)
        ));
        behaviour.discovered(&query, &source, input.iter());
        assert!(behaviour.queries.get(&query).is_none());
    }

    #[test]
    fn connection_address_changes_preserve_byte_and_unique_address_bounds() {
        let (mut behaviour, query, source) = lookup();
        let input = [referral(
            2,
            vec![address(1), address(2), address(3), address(4)],
        )];
        behaviour.discovered(&query, &source, input.iter());
        for (old, new, expected) in [
            (
                address(1),
                address(5),
                vec![address(5), address(2), address(3), address(4)],
            ),
            (
                address(5),
                address(5),
                vec![address(5), address(2), address(3), address(4)],
            ),
            (
                address(5),
                address(2),
                vec![address(2), address(3), address(4)],
            ),
            (address(3), sized_address(257), vec![address(2), address(4)]),
            (
                address(2),
                sized_address(256),
                vec![sized_address(256), address(4)],
            ),
        ] {
            let endpoint = |address| ConnectedPoint::Dialer {
                address,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };
            behaviour.on_address_change(AddressChange {
                peer_id: peer(2),
                connection_id: ConnectionId::new_unchecked(1),
                old: &endpoint(old),
                new: &endpoint(new),
            });
            let retained = &behaviour.queries.get(&query).unwrap().peers.addresses[&peer(2)];
            assert_eq!(retained.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn constructor_disables_insertion_bootstrap_independently_of_periodic_bootstrap() {
        for automatic in [None, Some(Duration::ZERO)] {
            let mut behaviour = behaviour(automatic);
            let mut context = Context::from_waker(std::task::Waker::noop());
            assert!(
                behaviour
                    .bootstrap_status
                    .poll_next_bootstrap(&mut context)
                    .is_pending()
            );
            for id in 1..4 {
                assert!(matches!(
                    behaviour.add_address(&peer(id), address(1)),
                    RoutingUpdate::Success
                ));
            }
            assert_eq!(
                behaviour
                    .bootstrap_status
                    .poll_next_bootstrap(&mut context)
                    .is_ready(),
                automatic.is_some()
            );
            assert_eq!(behaviour.iter_queries().count(), 0);
            assert!(
                behaviour.bootstrap().is_ok(),
                "manual bootstrap remains available"
            );
            assert_eq!(behaviour.iter_queries().count(), 1);
        }
    }
}

// CLOSEST ITERATOR CONTRACT
#[cfg(test)]
mod retention_closest {
    #![forbid(unsafe_code)]

    use super::*;
    use libp2p_core::multihash::Multihash;

    fn peer(value: u8) -> PeerId {
        PeerId::from_multihash(Multihash::wrap(0x12, &[value; 32]).unwrap()).unwrap()
    }

    fn iterator() -> ClosestPeersIter {
        ClosestPeersIter::new(
            Key::from(peer(0)).into(),
            (1..=40).map(|id| Key::from(peer(id))),
        )
    }

    fn next_peer(iter: &mut ClosestPeersIter, now: Instant) -> PeerId {
        match iter.next(now) {
            PeersIterState::Waiting(Some(peer)) => peer.into_owned(),
            other => panic!("expected contact, got {other:?}"),
        }
    }

    fn retained(iter: &ClosestPeersIter) -> Vec<PeerId> {
        iter.closest_peers
            .values()
            .map(|entry| *entry.key.preimage())
            .collect()
    }

    #[test]
    fn initial_twenty_and_referrals_share_thirty_two_lifetime_states() {
        let mut iter = iterator();
        assert_eq!(iter.closest_peers.len(), 20);
        let source = next_peer(&mut iter, Instant::now());
        assert!(iter.on_success(&source, (21..=80).map(peer)));
        assert_eq!(iter.closest_peers.len(), 32);
        let peers = retained(&iter);
        for id in 1..=32 {
            assert!(peers.contains(&peer(id)));
        }
        assert!(!peers.contains(&peer(33)));
        let source = next_peer(&mut iter, Instant::now());
        assert!(iter.on_success(&source, (81..=120).map(peer)));
        assert_eq!(retained(&iter), peers);
    }

    #[test]
    fn duplicate_referrals_do_not_consume_extra_iterator_slots() {
        let mut iter = iterator();
        let source = next_peer(&mut iter, Instant::now());
        assert!(iter.on_success(&source, [peer(21); 64]));
        assert_eq!(iter.closest_peers.len(), 21);
        let source = next_peer(&mut iter, Instant::now());
        assert!(iter.on_success(&source, (22..=40).map(peer)));
        assert_eq!(iter.closest_peers.len(), 32);
        assert!(!retained(&iter).contains(&peer(33)));
    }

    #[test]
    fn failures_and_timeouts_never_replenish_lifetime_budget() {
        let mut iter = iterator();
        let now = Instant::now();
        let source = next_peer(&mut iter, now);
        assert!(iter.on_success(&source, (21..=80).map(peer)));
        let before = retained(&iter);
        let failed = next_peer(&mut iter, now);
        assert!(iter.on_failure(&failed));
        let late = next_peer(&mut iter, now);
        let next = next_peer(&mut iter, now + Duration::from_secs(11));
        assert!(iter.on_success(&late, (81..=120).map(peer)));
        assert!(iter.on_success(&next, (121..=160).map(peer)));
        assert_eq!(retained(&iter), before);
        assert_eq!(iter.closest_peers.len(), 32);
    }

    #[test]
    fn unknown_failed_and_finished_responses_cannot_insert_states() {
        let mut iter = iterator();
        let before = retained(&iter);
        assert!(!iter.on_success(&peer(200), (21..=80).map(peer)));
        let source = next_peer(&mut iter, Instant::now());
        assert!(iter.on_failure(&source));
        assert!(!iter.on_success(&source, (21..=80).map(peer)));
        iter.finish();
        assert!(!iter.on_success(&source, (21..=80).map(peer)));
        assert_eq!(retained(&iter), before);
        assert!(matches!(
            iter.next(Instant::now()),
            PeersIterState::Finished
        ));
    }

    #[test]
    fn single_iterator_never_yields_more_than_thirty_two_contacts() {
        let mut iter = iterator();
        let mut contacts = Vec::new();
        for _ in 0..33 {
            match iter.next(Instant::now()) {
                PeersIterState::Waiting(Some(source)) => {
                    let source = source.into_owned();
                    assert!(!contacts.contains(&source));
                    contacts.push(source);
                    assert!(iter.on_success(&source, (21..=120).map(peer)));
                    assert!(iter.closest_peers.len() <= 32);
                }
                PeersIterState::Finished => break,
                other => panic!("sequential responses must progress: {other:?}"),
            }
        }
        assert!(iter.is_finished());
        assert!(!contacts.is_empty());
        assert!(contacts.len() <= 32);
    }
}
