// Copyright 2026 PHPCraftdream
// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]

use super::super::{RuntimeError, RuntimeOwner, endpoint_key, to_mutable};
use super::fixture::LoopbackPeer;
use crate::identity::Identity;
use crate::native_discovery::runtime::clock::TestClock;
use crate::native_discovery::runtime::owner::resolver::ResolvedAddresses;
use crate::native_discovery::runtime::publisher::PublisherState;
use iroh_base::TransportAddr;
use n0_mainline::MutableItem;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::Instant;

const WALL: i64 = 1_700_000_000_000_000;

async fn setup() -> (LoopbackPeer, RuntimeOwner, TestClock) {
    let peer = LoopbackPeer::bind().await;
    let SocketAddr::V4(bootstrap) = peer.address else {
        panic!("IPv4 bootstrap");
    };
    let clock = TestClock::new(WALL);
    let owner = RuntimeOwner::start_controlled(
        Identity::from_seed([0x71; 32]),
        "127.0.0.1:0".parse().expect("loopback"),
        &[bootstrap],
        clock.clone(),
    )
    .expect("actual runtime owner");
    (peer, owner, clock)
}

fn record(seed: u8, sequence: i64) -> MutableItem {
    let identity = Identity::from_seed([seed; 32]);
    let mut publisher = PublisherState::new(endpoint_key(&identity).expect("key"));
    let sample = crate::native_discovery::runtime::clock::ClockSample {
        wall_us: sequence,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    };
    let (_, signed) = publisher
        .replace(
            &identity,
            &[TransportAddr::Ip(
                "127.0.0.1:9001".parse().expect("address"),
            )],
            sample,
        )
        .expect("upstream signed record");
    to_mutable(&signed.expect("signed snapshot")).expect("typed item")
}

async fn resolve(
    owner: &mut RuntimeOwner,
    peer: &mut LoopbackPeer,
    item: &MutableItem,
) -> Result<ResolvedAddresses, RuntimeError> {
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("expected key");
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            _ = peer.serve_record(item) => unreachable!("server runs until request completes"),
        }
    })
    .await
    .expect("bounded real resolution")
}

#[tokio::test]
async fn real_get_enters_policy_cache_and_expiry_requires_a_new_network_query() {
    let (mut peer, mut owner, clock) = setup().await;
    let item = record(0x72, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    let first = resolve(&mut owner, &mut peer, &item)
        .await
        .expect("real GET winner");
    assert_eq!(
        first.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(first);

    clock.set_wall(WALL + 29_999_999);
    clock.set_monotonic(29_999_999);
    let cached = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = owner.resolve_until(key, Instant::now() + Duration::from_secs(10)) => result,
            _ = peer.capture_get(MutableItem::target_from_key(item.key(), None)) => {
                panic!("fresh SDK cache must not issue a GET");
            }
        }
    })
    .await
    .expect("cache lookup completes without network")
    .expect("cache hit");
    assert_eq!(
        cached.addresses(),
        &["127.0.0.1:9001".parse::<SocketAddr>().expect("address")]
    );
    drop(cached);

    clock.set_wall(WALL + 30_000_000);
    clock.set_monotonic(30_000_000);
    let refreshed = resolve(&mut owner, &mut peer, &item)
        .await
        .expect("new network receipt");
    assert_eq!(refreshed.addresses().len(), 1);
    drop(refreshed);
    owner
        .close()
        .await
        .expect("actual publisher and socket joins");
}

#[tokio::test]
async fn cancelled_real_get_cannot_cache_a_late_packet_and_later_query_recovers() {
    let (mut peer, mut owner, _) = setup().await;
    let item = record(0x73, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    let target = MutableItem::target_from_key(item.key(), None);
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source, transaction) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = &mut request => panic!("GET completed before held response: {result:?}"),
        }
    })
    .await
    .expect("actual GET captured");
    drop(request);
    peer.reply_get(source, &transaction, &item).await;

    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (next_source, next_transaction) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = &mut request => panic!("cancelled query minted a cache hit: {result:?}"),
        }
    })
    .await
    .expect("new GET is required");
    assert_ne!(
        next_transaction, transaction,
        "late response cannot become the new transaction"
    );
    peer.reply_get(next_source, &next_transaction, &item).await;
    let result = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .expect("new GET completes")
        .expect("new receipt accepted");
    assert_eq!(result.addresses().len(), 1);
    drop(result);
    owner
        .close()
        .await
        .expect("actual joins after cancellation");
}

#[tokio::test]
async fn original_get_deadline_expires_while_a_real_packet_is_held() {
    let (mut peer, mut owner, _) = setup().await;
    let item = record(0x74, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    assert!(matches!(
        owner.resolve_until(key, Instant::now()).await,
        Err(RuntimeError::DeadlineExceeded)
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut request = Box::pin(owner.resolve_until(key, deadline));
    let (source, transaction) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            held = peer.capture_get(MutableItem::target_from_key(item.key(), None)) => held,
            result = &mut request => panic!("unexpected early completion: {result:?}"),
        }
    })
    .await
    .expect("actual GET before original deadline");
    tokio::time::pause();
    tokio::time::advance(deadline.saturating_duration_since(Instant::now())).await;
    let result = request.await;
    assert!(
        matches!(result, Err(RuntimeError::DeadlineExceeded)),
        "original deadline: {result:?}"
    );
    tokio::time::resume();
    peer.reply_get(source, &transaction, &item).await;
    owner.close().await.expect("actual joins after deadline");
}

#[tokio::test]
async fn resolution_clock_fault_revokes_publication_and_stays_terminal_after_catchup() {
    let (mut peer, mut owner, clock) = setup().await;
    let address = TransportAddr::Ip("127.0.0.1:9001".parse().expect("address"));
    let publication = owner.replace(vec![address]);
    let (published, _) = tokio::join!(publication, peer.serve_until_put());
    published.expect("actual PUT acknowledged");
    let item = record(0x75, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    drop(
        resolve(&mut owner, &mut peer, &item)
            .await
            .expect("real GET"),
    );

    clock.set_wall(WALL - 1);
    assert!(matches!(
        owner
            .resolve_until(key, Instant::now() + Duration::from_secs(10))
            .await,
        Err(RuntimeError::Publish(
            crate::native_discovery::runtime::publisher::PublishError::ClockFault
        ))
    ));
    assert!(
        !owner
            .barrier()
            .await
            .expect("actual cleanup barrier")
            .active
    );
    clock.set_wall(WALL + 1);
    assert!(matches!(
        owner
            .resolve_until(key, Instant::now() + Duration::from_secs(10))
            .await,
        Err(RuntimeError::Closed)
    ));
    owner
        .close()
        .await
        .expect("actual joins after terminal clock fault");
}

#[tokio::test]
async fn delivered_sdk_results_retain_eight_actual_backend_result_leases() {
    let (mut peer, mut owner, _) = setup().await;
    let mut held = Vec::new();
    for seed in 0x80..0x88 {
        held.push(
            resolve(&mut owner, &mut peer, &record(seed, WALL))
                .await
                .expect("charged result"),
        );
    }
    let ninth = record(0x88, WALL);
    let key = iroh_base::EndpointId::from_bytes(ninth.key()).expect("ninth key");
    let deadline = Instant::now() + Duration::from_secs(3);
    let blocked = tokio::select! {
        result = owner.resolve_until(key, deadline) => result,
        _ = peer.capture_get(MutableItem::target_from_key(ninth.key(), None)) => {
            panic!("eight delivered results must prevent a ninth actual GET");
        }
    };
    assert!(
        matches!(blocked, Err(RuntimeError::DeadlineExceeded)),
        "bounded admission: {blocked:?}"
    );
    drop(held.pop());
    let recovered = resolve(&mut owner, &mut peer, &ninth)
        .await
        .expect("released result charge reused");
    assert_eq!(recovered.addresses().len(), 1);
    drop(recovered);
    drop(held);
    owner
        .close()
        .await
        .expect("actual joins with result leases released");
}

#[tokio::test]
async fn real_empty_get_is_a_cache_miss_and_signed_invalid_profile_cannot_poison_recovery() {
    use crate::native_discovery::codec::DecodeError;
    use crate::native_discovery::policy::RecordError;
    use crate::native_discovery::runtime::owner::resolver::ResolveError;
    use crate::native_discovery::runtime::publisher::SignedSnapshot;
    use iroh_dns::endpoint_info::{EndpointData, EndpointInfo};

    let (mut peer, mut owner, _) = setup().await;
    let valid = record(0x79, WALL);
    let key = iroh_base::EndpointId::from_bytes(valid.key()).expect("key");
    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let empty_peer = async {
        let target = MutableItem::target_from_key(valid.key(), None);
        loop {
            let (source, transaction) = peer.capture_get(target).await;
            peer.reply_empty_get(source, &transaction).await;
        }
    };
    let empty = tokio::select! {
        result = &mut request => result,
        _ = empty_peer => unreachable!("serve until completion"),
    };
    assert!(matches!(
        empty,
        Err(RuntimeError::Resolve(ResolveError::Policy(
            RecordError::CacheMiss
        )))
    ));
    drop(request);

    let identity = Identity::from_seed([0x79; 32]);
    let data = EndpointData::new(
        [TransportAddr::Ip(
            "0.0.0.0:9001".parse().expect("forbidden IP"),
        )]
        .into_iter()
        .collect(),
    );
    let packet = EndpointInfo::from_parts(key, data)
        .to_pkarr_signed_packet_at(
            &identity.transport_key(),
            30,
            u64::try_from(WALL).expect("timestamp"),
        )
        .expect("upstream signs the deliberately invalid native address");
    let invalid = to_mutable(&SignedSnapshot {
        timestamp_us: WALL,
        bytes: packet.as_bytes().to_vec(),
    })
    .expect("valid signature and typed fields");
    assert!(matches!(
        resolve(&mut owner, &mut peer, &invalid).await,
        Err(RuntimeError::Resolve(ResolveError::Decode(
            DecodeError::InvalidAddress
        )))
    ));
    let recovered = resolve(&mut owner, &mut peer, &record(0x79, WALL + 1))
        .await
        .expect("valid real response after rejection");
    assert_eq!(recovered.addresses().len(), 1);
    drop(recovered);
    owner
        .close()
        .await
        .expect("actual joins after empty and invalid records");
}

#[tokio::test]
async fn completed_real_get_cannot_commit_after_the_original_handoff_deadline() {
    use crate::native_discovery::runtime::clock::ClockSample;
    use crate::native_discovery::runtime::owner::resolver::ResolveError;

    let (mut peer, mut owner, _) = setup().await;
    let item = record(0x7a, WALL);
    let key = iroh_base::EndpointId::from_bytes(item.key()).expect("key");
    let target = MutableItem::target_from_key(item.key(), None);
    let handle = owner.dht_handle().expect("actual actor handle");
    let completion = tokio::select! {
        result = handle.resolve_mutable(target) => result.expect("actual backend completion"),
        _ = peer.serve_record(&item) => unreachable!("serve until completion"),
    };
    assert!(completion.network_completed());
    assert!(!completion.items().is_empty());
    let sample = ClockSample {
        wall_us: WALL,
        monotonic_before_us: 0,
        monotonic_after_us: 0,
    };
    assert!(
        owner
            .resolver
            .begin(key, sample)
            .expect("admit expected key")
            .is_none()
    );
    assert!(matches!(
        owner
            .resolver
            .complete(key, completion, sample, Instant::now())
            .await,
        Err(ResolveError::DeadlineExceeded)
    ));

    let mut request = Box::pin(owner.resolve_until(key, Instant::now() + Duration::from_secs(10)));
    let (source, transaction) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            held = peer.capture_get(target) => held,
            result = &mut request => panic!("expired handoff populated usable cache: {result:?}"),
        }
    })
    .await
    .expect("fresh network query required");
    peer.reply_get(source, &transaction, &item).await;
    drop(request.await.expect("fresh response accepted"));
    owner
        .close()
        .await
        .expect("actual joins after rejected handoff");
}
