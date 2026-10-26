#![forbid(unsafe_code)]

use super::*;
use crate::no_cache_support::{a, alias, message, name, negative, query, Probe, Work};
use crate::proto::{
    op::ResponseCode,
    rr::{rdata::NS, RData, Record},
};

#[test]
fn zero_capacity_never_constructs_moka_and_clones_share_configuration() {
    let probe = Probe::new();
    let enabled = ResponseCache::new(2, TtlConfig::default());
    assert!(enabled.is_enabled());
    assert_eq!(
        probe.count(Work::Build),
        1,
        "constructor observation precondition"
    );
    let enabled_clone = enabled.clone();
    assert!(enabled_clone.is_enabled());
    assert_eq!(probe.count(Work::Build), 1);
    let disabled = ResponseCache::new(0, TtlConfig::default());
    let clone = disabled.clone();
    assert_eq!(
        probe.count(Work::Build),
        1,
        "ZERO_CAPACITY_CONSTRUCTED_MOKA"
    );
    assert!(!disabled.is_enabled());
    assert!(clone.cache.is_none());
    assert!(Arc::ptr_eq(&disabled.ttl_config, &clone.ttl_config));
    drop(disabled);
    assert!(!clone.is_enabled());
    for (capacity, constructions) in [(0, 1), (2, 2)] {
        let mut builder = crate::Resolver::builder_with_config(
            crate::config::ResolverConfig::default(),
            crate::net::runtime::TokioRuntimeProvider::default(),
        );
        builder.options_mut().cache_size = capacity;
        builder.options_mut().use_hosts_file = crate::config::ResolveHosts::Never;
        let resolver = builder.build().expect("offline resolver construction");
        let survivor = resolver.clone();
        drop(resolver);
        survivor.clear_cache();
        assert_eq!(probe.count(Work::Build), constructions);
    }
}

#[test]
fn disabled_storage_skips_upsert_work_and_clear_is_harmless() {
    let probe = Probe::new();
    let q = query("storage.example.", RecordType::A);
    let now = Instant::now();
    let enabled = ResponseCache::new(2, TtlConfig::default());
    enabled.insert(q.clone(), Ok(message(&q, 1)), now);
    assert_eq!(
        probe.count(Work::Storage),
        1,
        "storage observation precondition"
    );
    let disabled = ResponseCache::new(0, TtlConfig::default());
    for clamp in [false, true] {
        disabled.upsert_clamped_ttl(q.clone(), Ok(message(&q, 2)), now, clamp);
        disabled.upsert_clamped_ttl(
            q.clone(),
            Err(negative(&q, ResponseCode::NXDomain, 30)),
            now,
            clamp,
        );
        disabled.upsert_clamped_ttl(q.clone(), Err(NetError::Timeout), now, clamp);
    }
    assert_eq!(
        probe.count(Work::Storage),
        1,
        "DISABLED_CACHE_PERFORMED_STORAGE_WORK"
    );
    disabled.clear_query(&q);
    disabled.clear();
    assert!(disabled.get(&q, now).is_none());
}

#[test]
fn positive_cache_clone_hit_ttl_expiry_and_clear_contract() {
    let q = query("cached.example.", RecordType::A);
    let now = Instant::now();
    let cache = ResponseCache::new(4, TtlConfig::default());
    let other = cache.clone();
    let mut answer = message(&q, 3);
    for r in answer
        .answers
        .iter_mut()
        .chain(&mut answer.authorities)
        .chain(&mut answer.additionals)
    {
        r.ttl = 20;
    }
    cache.insert(q.clone(), Ok(answer.clone()), now);
    drop(cache);
    let hit = other
        .get(&q, now + Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(hit.answers[0].ttl, 17);
    assert_eq!(hit.authorities[0].ttl, 17);
    assert_eq!(hit.additionals[0].ttl, 17);
    assert!(other.get(&q, now + Duration::from_secs(21)).is_none());
    other.clear_query(&q);
    assert!(other.get(&q, now).is_none());
    other.insert(q.clone(), Ok(answer), now);
    assert!(other.get(&q, now).is_some());
    other.clear();
    assert!(other.get(&q, now).is_none());
}

#[test]
fn ghost_domain_upsert_never_extends_existing_ns_deadline() {
    let q = query("example.", RecordType::NS);
    let now = Instant::now();
    let mut first = message(&q, 1);
    first.answers = vec![Record::from_rdata(
        q.name().clone(),
        40,
        RData::NS(NS(name("first.example."))),
    )];
    let mut second = first.clone();
    second.answers = vec![Record::from_rdata(
        q.name().clone(),
        400,
        RData::NS(NS(name("second.example."))),
    )];
    let cache = ResponseCache::new(2, TtlConfig::default());
    cache.upsert_clamped_ttl(q.clone(), Ok(first), now, true);
    let later = now + Duration::from_secs(10);
    cache.upsert_clamped_ttl(q.clone(), Ok(second.clone()), later, true);
    assert_eq!(
        cache.get(&q, later).unwrap().unwrap().answers,
        second.answers
    );
    assert_eq!(
        cache.cache.as_ref().unwrap().get(&q).unwrap().valid_until,
        now + Duration::from_secs(40)
    );
    assert!(cache.get(&q, now + Duration::from_secs(41)).is_none());
    cache.upsert_clamped_ttl(q.clone(), Ok(second), later, false);
    assert_eq!(
        cache.cache.as_ref().unwrap().get(&q).unwrap().valid_until,
        later + Duration::from_secs(400)
    );
}

#[test]
fn per_type_ttl_clamps_preserve_sections_and_query_deadline_rules() {
    let mut config = TtlConfig::from(TtlBounds {
        positive_min_ttl: Some(Duration::from_secs(10)),
        positive_max_ttl: Some(Duration::from_secs(100)),
        ..TtlBounds::default()
    });
    config.with_query_type_ttl_bounds(
        RecordType::NS,
        TtlBounds {
            positive_min_ttl: Some(Duration::from_secs(20)),
            positive_max_ttl: Some(Duration::from_secs(30)),
            ..TtlBounds::default()
        },
    );
    for capacity in [0, 4] {
        let cache = ResponseCache::new(capacity, config.clone());
        let q = query("ttls.example.", RecordType::A);
        let mut answer = message(&q, 1);
        answer.answers = vec![a(q.name(), 0, 1), a(q.name(), 500, 2)];
        answer.authorities[0].ttl = 1;
        answer.additionals[0].ttl = 500;
        assert_eq!(
            cache.clamp_positive_ttls(RecordType::A, &mut answer),
            Duration::from_secs(10)
        );
        assert_eq!(
            answer.answers.iter().map(|r| r.ttl).collect::<Vec<_>>(),
            [10, 100]
        );
        assert_eq!(answer.authorities[0].ttl, 20);
        assert_eq!(answer.additionals[0].ttl, 100);
        answer.answers = vec![
            alias(q.name(), &name("target.example."), 15),
            a(q.name(), 80, 3),
        ];
        assert_eq!(
            cache.clamp_positive_ttls(RecordType::A, &mut answer),
            Duration::from_secs(15)
        );
        answer.answers.clear();
        answer.authorities[0].ttl = 25;
        assert_eq!(
            cache.clamp_positive_ttls(RecordType::NS, &mut answer),
            Duration::from_secs(25)
        );
        answer.authorities.clear();
        assert_eq!(
            cache.clamp_positive_ttls(RecordType::NS, &mut answer),
            Duration::from_secs(20)
        );
    }
}

#[test]
fn negative_cache_bounds_do_not_rewrite_initial_error_and_decrement_hits() {
    let q = query("negative.example.", RecordType::A);
    let now = Instant::now();
    let cache = ResponseCache::new(
        2,
        TtlConfig::from(TtlBounds {
            negative_min_ttl: Some(Duration::from_secs(10)),
            negative_max_ttl: Some(Duration::from_secs(20)),
            ..TtlBounds::default()
        }),
    );
    for (wire, expiry) in [(1, 10), (15, 15), (30, 20)] {
        cache.insert(
            q.clone(),
            Err(negative(&q, ResponseCode::NXDomain, wire)),
            now,
        );
        assert_eq!(
            cache.cache.as_ref().unwrap().get(&q).unwrap().valid_until,
            now + Duration::from_secs(expiry)
        );
        let NetError::Dns(DnsError::NoRecordsFound(error)) =
            cache.get(&q, now).unwrap().unwrap_err()
        else {
            panic!("negative cache error");
        };
        assert_eq!(error.negative_ttl, Some(wire));
        let NetError::Dns(DnsError::NoRecordsFound(error)) = cache
            .get(&q, now + Duration::from_secs(2))
            .unwrap()
            .unwrap_err()
        else {
            panic!("negative cache error");
        };
        assert_eq!(error.negative_ttl, Some(wire.saturating_sub(2)));
        assert_eq!(error.soa.unwrap().ttl, wire.saturating_sub(2));
    }
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_count_zero_without_storage_and_count_shared_positive_entries() {
    let probe = Probe::new();
    let q = query("metrics.example.", RecordType::A);
    let cache = ResponseCache::new(0, TtlConfig::default());
    cache.insert(q.clone(), Ok(message(&q, 1)), Instant::now());
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.clone().entry_count(), 0);
    assert_eq!(probe.count(Work::Build), 0);
    let cache = ResponseCache::new(2, TtlConfig::default());
    cache.insert(q.clone(), Ok(message(&q, 1)), Instant::now());
    assert_eq!(cache.clone().entry_count(), 1);
    cache.clear();
    assert_eq!(cache.entry_count(), 0);
}
