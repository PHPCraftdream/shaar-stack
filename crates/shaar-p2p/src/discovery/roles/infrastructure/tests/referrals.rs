use super::*;
use libp2p::{Multiaddr, kad, multiaddr::Protocol};

fn address(peer: PeerId, port: u16) -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4("8.8.8.8".parse().unwrap()))
        .with(Protocol::Tcp(port))
        .with(Protocol::P2p(peer))
}

fn queries(local: PeerId) -> [kad::QueryId; 2] {
    let mut behaviour = kad::Behaviour::new(local, kad::store::MemoryStore::new(local));
    [
        behaviour.get_closest_peers(local),
        behaviour.get_closest_peers(local),
    ]
}

fn authenticate(
    owner: &mut Owner,
    source: PeerId,
    id: usize,
) -> (AttemptKey, InfrastructurePermit) {
    let (key, permit) = stage(owner, source, id);
    let view = owner.view();
    let root = view.lease(key, LeaseKind::Root, Instant::now()).unwrap();
    let numeric = view.lease(key, LeaseKind::Numeric, Instant::now()).unwrap();
    let endpoint = "8.8.8.8:4001".parse().unwrap();
    numeric.record_numeric(endpoint, Instant::now()).unwrap();
    assert_eq!(
        owner.terminal(key, Some(source), Instant::now()),
        Some(endpoint)
    );
    drop((numeric, root));
    (key, permit)
}

fn begin(owner: &mut Owner, local: PeerId, key: AttemptKey, query: kad::QueryId) -> DiscoveryEpoch {
    let now = Instant::now();
    let epoch = owner
        .begin_discovery_epoch(local, now + Duration::from_secs(10), now)
        .unwrap();
    owner.bind_discovery_source(epoch, key, now).unwrap();
    owner.bind_discovery_query(epoch, query, now).unwrap();
    epoch
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_referrals_charge_seed_addresses_without_granting_provenance() {
    let local = peer();
    let source = peer();
    let seed = peer();
    let [query, _] = queries(local);
    let mut owner = Owner::new(&[], &[source, seed]).unwrap();
    for port in 4001..4005 {
        owner
            .reserve_discovery_address(seed, &address(seed, port))
            .unwrap();
    }
    owner
        .reserve_discovery_address(seed, &address(seed, 4001))
        .unwrap();
    assert!(
        owner
            .reserve_discovery_address(seed, &address(seed, 4005))
            .is_err()
    );
    let (key, _permit) = authenticate(&mut owner, source, 1);
    let epoch = begin(&mut owner, local, key, query);
    let view = owner.view();
    assert!(
        view.discovery_referral_root(epoch, seed, Instant::now())
            .is_none()
    );
    assert!(!view.admit_query_referral(query, source, seed, &[address(seed, 4005)]));
    assert!(view.admit_query_referral(query, source, seed, &[address(seed, 4001)]));
    assert!(
        view.discovery_referral_root(epoch, seed, Instant::now())
            .is_some()
    );
    assert!(
        owner
            .reserve_discovery_address(seed, &address(seed, 4001))
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_referrals_bound_complete_encoding_including_omitted_peer_suffix() {
    let local = peer();
    let source = peer();
    let candidate = peer();
    let [query, _] = queries(local);
    let mut owner = Owner::new(&[], &[source]).unwrap();
    let (key, _permit) = authenticate(&mut owner, source, 1);
    let epoch = begin(&mut owner, local, key, query);
    let view = owner.view();
    let sized = |limit| {
        (1..=63)
            .find_map(|last| {
                let name = format!(
                    "{}.{}.{}.{}.",
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(last)
                );
                let address = Multiaddr::empty()
                    .with(Protocol::Dns4(name.into()))
                    .with(Protocol::Tcp(4001));
                (address
                    .clone()
                    .with(Protocol::P2p(candidate))
                    .as_ref()
                    .len()
                    == limit)
                    .then_some(address)
            })
            .unwrap()
    };
    let boundary = sized(256);
    let oversized = sized(257);
    assert!(oversized.as_ref().len() < 256);
    assert!(!view.admit_query_referral(query, source, candidate, &[oversized]));
    assert!(
        view.discovery_referral_root(epoch, candidate, Instant::now())
            .is_none()
    );
    assert!(view.admit_query_referral(query, source, candidate, std::slice::from_ref(&boundary)));
    assert_eq!(
        view.discovery_referral_root(epoch, candidate, Instant::now()),
        Some(boundary.with(Protocol::P2p(candidate)))
    );
    let wrong = address(peer(), 4001);
    assert!(!view.admit_query_referral(query, source, candidate, &[wrong]));
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_referrals_require_exact_query_live_source_and_active_epoch() {
    let local = peer();
    let source = peer();
    let candidate = peer();
    let [query, wrong] = queries(local);
    let mut owner = Owner::new(&[], &[source]).unwrap();
    let view = owner.view();
    let (key, _permit) = authenticate(&mut owner, source, 1);
    let addresses = [address(candidate, 4001)];
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
    let epoch = begin(&mut owner, local, key, query);
    assert!(!view.admit_query_referral(wrong, source, candidate, &addresses));
    assert!(!view.admit_query_referral(query, peer(), candidate, &addresses));
    assert!(view.admit_query_referral(query, source, candidate, &addresses));
    assert_eq!(
        view.role(candidate),
        None,
        "REFERRAL_GRANTED_ROLE_AUTHORITY"
    );
    assert_eq!(
        view.discovery_referral_root(epoch, candidate, Instant::now()),
        Some(addresses[0].clone())
    );
    owner.retire_discovery_epoch(epoch);
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
    assert!(
        view.discovery_referral_root(epoch, candidate, Instant::now())
            .is_none()
    );
    assert!(
        view.infrastructure_live(key).is_some(),
        "QUERY_RETIREMENT_CLOSED_CONTROL"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_referrals_cannot_rebind_source_generation_or_owner_namespace() {
    let local = peer();
    let source = peer();
    let candidate = peer();
    let [query, next_query] = queries(local);
    let mut owner = Owner::new(&[], &[source]).unwrap();
    let (old, permit) = authenticate(&mut owner, source, 1);
    let epoch = begin(&mut owner, local, old, query);
    let view = owner.view();
    let addresses = [address(candidate, 4001)];
    assert!(view.admit_query_referral(query, source, candidate, &addresses));
    owner.infrastructure_withdraw(old);
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
    owner.infrastructure_terminal(old);
    drop(permit);
    let (replacement, _permit) = authenticate(&mut owner, source, 2);
    assert!(
        owner
            .bind_discovery_source(epoch, replacement, Instant::now())
            .is_err()
    );
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
    let mut foreign = Owner::new(&[], &[source]).unwrap();
    let (foreign_key, _foreign_permit) = authenticate(&mut foreign, source, 2);
    assert!(
        owner
            .bind_discovery_source(epoch, foreign_key, Instant::now())
            .is_err()
    );
    assert!(
        foreign
            .bind_discovery_query(epoch, query, Instant::now())
            .is_err()
    );
    owner.retire_discovery_epoch(epoch);
    let next = begin(&mut owner, local, replacement, next_query);
    assert_ne!(epoch, next);
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
    assert!(
        view.discovery_referral_root(next, candidate, Instant::now())
            .is_none()
    );
    assert!(view.admit_query_referral(next_query, source, candidate, &addresses));
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_referrals_validate_whole_list_and_preserve_four_lifetime_address_slots() {
    let local = peer();
    let source = peer();
    let candidate = peer();
    let [query, next_query] = queries(local);
    let mut owner = Owner::new(&[], &[source]).unwrap();
    let (key, _permit) = authenticate(&mut owner, source, 1);
    let epoch = begin(&mut owner, local, key, query);
    let view = owner.view();
    let valid = address(candidate, 4001);
    let invalid: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
    assert!(!view.admit_query_referral(query, source, candidate, &[]));
    assert!(!view.admit_query_referral(query, source, candidate, &[valid.clone(), invalid]));
    assert!(
        view.discovery_referral_root(epoch, candidate, Instant::now())
            .is_none()
    );
    let addresses: Vec<_> = (4001..4005).map(|port| address(candidate, port)).collect();
    assert!(view.admit_query_referral(query, source, candidate, &addresses));
    assert!(!view.admit_query_referral(query, source, candidate, &[address(candidate, 4005)]));
    let repeated: [_; 5] = std::array::from_fn(|_| valid.clone());
    assert!(!view.admit_query_referral(query, source, candidate, &repeated));
    owner.retire_discovery_epoch(epoch);
    let next = begin(&mut owner, local, key, next_query);
    assert!(!view.admit_query_referral(next_query, source, candidate, &[address(candidate, 4005)]));
    assert!(
        view.discovery_referral_root(next, candidate, Instant::now())
            .is_none()
    );
    assert!(view.admit_query_referral(next_query, source, candidate, std::slice::from_ref(&valid)));
    assert_eq!(
        view.discovery_referral_root(next, candidate, Instant::now()),
        Some(valid)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_referrals_share_lifetime_contacts_and_exclude_local_application_and_explicit_roles()
 {
    let local = peer();
    let source = peer();
    let app = peer();
    let explicit = peer();
    let [query, _] = queries(local);
    let mut owner = Owner::new(&[app], &[source]).unwrap();
    owner
        .admit_identity(
            explicit,
            Role::ExplicitRelay("8.8.4.4:4001".parse().unwrap()),
        )
        .unwrap();
    let (key, _permit) = authenticate(&mut owner, source, 1);
    let epoch = begin(&mut owner, local, key, query);
    let view = owner.view();
    for excluded in [local, app, explicit] {
        assert!(!view.admit_query_referral(query, source, excluded, &[address(excluded, 4001)]));
    }
    for _ in 1..32 {
        let candidate = peer();
        assert!(view.admit_query_referral(query, source, candidate, &[address(candidate, 4001)]));
        owner
            .admit_identity(candidate, Role::Infrastructure)
            .unwrap();
        owner.forget_identity(candidate).unwrap();
    }
    let overflow = peer();
    assert!(!view.admit_query_referral(query, source, overflow, &[address(overflow, 4001)]));
    assert!(
        view.discovery_referral_root(epoch, overflow, Instant::now())
            .is_none()
    );
    assert!(
        owner
            .admit_identity(overflow, Role::Infrastructure)
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn discovery_referrals_deadline_is_absolute_and_close_rejects_late_callbacks() {
    let local = peer();
    let source = peer();
    let candidate = peer();
    let [query, _] = queries(local);
    let mut owner = Owner::new(&[], &[source]).unwrap();
    let (key, _permit) = authenticate(&mut owner, source, 1);
    let now = Instant::now();
    assert!(owner.begin_discovery_epoch(local, now, now).is_err());
    assert!(
        owner
            .begin_discovery_epoch(local, now + Duration::from_secs(11), now)
            .is_err()
    );
    let epoch = begin(&mut owner, local, key, query);
    let view = owner.view();
    let addresses = [address(candidate, 4001)];
    assert!(view.admit_query_referral(query, source, candidate, &addresses));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(!view.discovery_epoch_active(epoch, Instant::now()));
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
    assert!(
        owner
            .bind_discovery_source(epoch, key, Instant::now())
            .is_err()
    );
    assert!(
        view.discovery_referral_root(epoch, candidate, Instant::now())
            .is_none()
    );
    owner.close();
    assert!(!view.admit_query_referral(query, source, candidate, &addresses));
}
