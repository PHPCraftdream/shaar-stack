#![forbid(unsafe_code)]

use super::*;
use crate::no_cache_support::{self as fixture, *};
use std::sync::atomic::Ordering;

#[cfg(feature = "__dnssec")]
#[path = "no_cache_dnssec.rs"]
mod dnssec;
#[path = "no_cache_semantics.rs"]
mod semantics;

fn client(capacity: u64, script: Script, preserve: bool) -> CachingClient<Script> {
    CachingClient::new(capacity, script, preserve)
}

#[test]
fn positive_finalization_moves_all_nonempty_section_buffers() {
    let q = query("move.example.", RecordType::A);
    let original = message(&q, 1);
    assert!(
        !original.answers.is_empty()
            && !original.authorities.is_empty()
            && !original.additionals.is_empty()
    );
    let expected = original.clone();
    let pointers = (
        original.answers.as_ptr(),
        original.authorities.as_ptr(),
        original.additionals.as_ptr(),
    );
    let client = client(0, Script::new(Vec::new()), false);
    let lookup = client.cache(q, Ok(original)).unwrap();
    assert_eq!(lookup.message(), &expected, "message content precondition");
    assert_eq!(
        (
            lookup.answers().as_ptr(),
            lookup.authorities().as_ptr(),
            lookup.additionals().as_ptr()
        ),
        pointers,
        "DISABLED_CACHE_COPIED_POSITIVE_MESSAGE"
    );
}

#[test]
fn error_finalization_skips_cache_clone_and_preserves_original_error() {
    let probe = Probe::new();
    let q = query("error.example.", RecordType::A);
    let enabled = client(2, Script::new(Vec::new()), false);
    assert!(enabled.cache(q.clone(), Err(NetError::Timeout)).is_err());
    assert_eq!(
        probe.count(Work::ErrorClone),
        1,
        "error observation precondition"
    );
    let disabled = client(0, Script::new(Vec::new()), false);
    let error = negative(&q, ResponseCode::NXDomain, 7);
    let NetError::Dns(DnsError::NoRecordsFound(original)) = &error else {
        panic!("fixture error");
    };
    let soa = original.soa.as_deref().unwrap() as *const _;
    let NetError::Dns(DnsError::NoRecordsFound(returned)) =
        disabled.cache(q.clone(), Err(error)).unwrap_err()
    else {
        panic!("returned error");
    };
    assert_eq!(*returned.query, q);
    assert_eq!(returned.negative_ttl, Some(7));
    assert_eq!(returned.soa.as_deref().unwrap() as *const _, soa);
    assert_eq!(
        probe.count(Work::ErrorClone),
        1,
        "DISABLED_CACHE_CLONED_ERROR"
    );
}

#[test]
fn alias_finalization_skips_cache_message_and_preserves_child_lookup() {
    let probe = Probe::new();
    let q = query("child.example.", RecordType::A);
    let alias_query = query("alias.example.", RecordType::A);
    let deadline = Instant::now() + Duration::from_secs(99);
    let child = Lookup::new(message(&q, 1), deadline);
    let enabled = client(2, Script::new(Vec::new()), true);
    assert_eq!(
        enabled.cname(child.clone(), alias_query.clone()).unwrap(),
        child
    );
    assert_eq!(
        probe.count(Work::Alias),
        1,
        "alias observation precondition"
    );
    let pointers = (
        child.answers().as_ptr(),
        child.authorities().as_ptr(),
        child.additionals().as_ptr(),
    );
    let expected = child.clone();
    let disabled = client(0, Script::new(Vec::new()), true);
    let returned = disabled.cname(child, alias_query).unwrap();
    assert_eq!(returned, expected);
    assert_eq!(returned.query(), &q);
    assert_eq!(returned.valid_until(), deadline);
    assert_eq!(
        (
            returned.answers().as_ptr(),
            returned.authorities().as_ptr(),
            returned.additionals().as_ptr()
        ),
        pointers
    );
    assert_eq!(
        probe.count(Work::Alias),
        1,
        "DISABLED_CACHE_BUILT_ALIAS_MESSAGE"
    );
}

#[test]
fn repeated_positive_queries_refresh_only_when_cache_disabled() {
    for capacity in [0, 4] {
        let q = query("repeat.example.", RecordType::A);
        let first = message(&q, 1);
        let second = message(&q, 10);
        let script = Script::new(vec![response(first.clone()), response(second.clone())]);
        let client = client(capacity, script.clone(), false);
        assert_eq!(
            ready(client.lookup(q.clone(), DnsRequestOptions::default()))
                .unwrap()
                .answers()[0]
                .data,
            first.answers[0].data
        );
        let result = ready(
            client
                .clone()
                .lookup(q.clone(), DnsRequestOptions::default()),
        )
        .unwrap();
        assert_eq!(
            result.answers()[0].data,
            if capacity == 0 {
                second.answers[0].data.clone()
            } else {
                first.answers[0].data.clone()
            }
        );
        assert_eq!(script.queries(), vec![q; if capacity == 0 { 2 } else { 1 }]);
    }
}

#[test]
fn repeated_negative_queries_refresh_only_when_cache_disabled() {
    for capacity in [0, 4] {
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let q = query("absent.example.", RecordType::A);
            let script = Script::new(vec![
                negative_response(&q, code, 3600),
                negative_response(&q, code, 7200),
            ]);
            let client = client(capacity, script.clone(), false);
            let first = ready(client.lookup(q.clone(), DnsRequestOptions::default())).unwrap_err();
            let second = ready(client.lookup(q.clone(), DnsRequestOptions::default())).unwrap_err();
            let NetError::Dns(DnsError::NoRecordsFound(first)) = first else {
                panic!("negative result");
            };
            let NetError::Dns(DnsError::NoRecordsFound(second)) = second else {
                panic!("negative result");
            };
            assert_eq!(first.response_code, code);
            assert_eq!(second.response_code, code);
            assert_eq!(first.negative_ttl, Some(3600));
            // SOA data distinguishes entries independently of elapsed cache TTL.
            assert_eq!(
                second.soa.unwrap().data.minimum,
                if capacity == 0 { 7200 } else { 3600 }
            );
            assert_eq!(script.queries().len(), if capacity == 0 { 2 } else { 1 });
        }
    }
}

#[test]
fn noncacheable_errors_always_reach_client_and_preserve_error_kind() {
    for capacity in [0, 4] {
        let q = query("failure.example.", RecordType::A);
        let script = Script::new(vec![Err(NetError::Timeout), Err(NetError::Busy)]);
        let client = client(capacity, script.clone(), false);
        assert!(matches!(
            ready(client.lookup(q.clone(), DnsRequestOptions::default())),
            Err(NetError::Timeout)
        ));
        assert!(matches!(
            ready(client.lookup(q, DnsRequestOptions::default())),
            Err(NetError::Busy)
        ));
        assert_eq!(script.queries().len(), 2);
    }
}

#[test]
fn lookup_cancellation_and_clone_drop_do_not_construct_or_retain_cache() {
    let probe = Probe::new();
    let q = query("pending.example.", RecordType::A);
    let script = Script::pending();
    let client = client(0, script.clone(), false);
    let survivor = client.clone();
    drop(client.lookup(q.clone(), DnsRequestOptions::default()));
    assert!(script.queries().is_empty());
    let mut pending = Box::pin(client.lookup(q, DnsRequestOptions::default()));
    assert!(fixture::poll(pending.as_mut()).is_pending());
    assert_eq!(script.queries().len(), 1);
    assert_eq!(script.drops.load(Ordering::Relaxed), 0);
    drop(pending);
    assert_eq!(script.drops.load(Ordering::Relaxed), 1);
    drop(client);
    assert!(!survivor.cache.is_enabled());
    assert_eq!(probe.count(Work::Build), 0);
}

#[test]
fn returned_lookup_survives_all_client_owners() {
    let q = query("owned.example.", RecordType::A);
    let expected = message(&q, 1);
    let script = Script::new(vec![response(expected.clone())]);
    let client = client(0, script.clone(), false);
    let other = client.clone();
    let lookup = ready(client.lookup(q, DnsRequestOptions::default())).unwrap();
    drop(client);
    drop(other);
    drop(script);
    assert_eq!(lookup.message(), &expected);
}
