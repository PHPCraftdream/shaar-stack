#![forbid(unsafe_code)]

use super::*;
use crate::config::ResolverOpts;
use crate::proto::rr::rdata::{AAAA, TXT};

#[test]
fn first_response_ttl_zero_min_max_and_deadline_are_preserved() {
    for capacity in [0, 4] {
        for (wire, minimum, maximum, expected) in [
            (0, 0, 100, 0),
            (0, 10, 100, 10),
            (50, 10, 100, 50),
            (200, 10, 100, 100),
        ] {
            let mut options = ResolverOpts::default();
            options.positive_min_ttl = Some(Duration::from_secs(minimum));
            options.positive_max_ttl = Some(Duration::from_secs(maximum));
            let cache = ResponseCache::new(capacity, TtlConfig::from_opts(&options));
            let client = CachingClient::with_cache(cache, Script::new(Vec::new()), false);
            let q = query("ttl.example.", RecordType::A);
            let mut answer = message(&q, 1);
            for r in answer
                .answers
                .iter_mut()
                .chain(&mut answer.authorities)
                .chain(&mut answer.additionals)
            {
                r.ttl = wire;
            }
            let before = Instant::now();
            let lookup = client.cache(q, Ok(answer)).unwrap();
            let after = Instant::now();
            assert!(lookup.message().all_sections().all(|r| r.ttl == expected));
            let ttl = Duration::from_secs(u64::from(expected));
            assert!(lookup.valid_until() >= before + ttl);
            assert!(lookup.valid_until() <= after + ttl);
        }
    }
}

#[test]
fn first_negative_error_is_not_rewritten_by_cache_ttl_bounds() {
    for capacity in [0, 4] {
        let mut options = ResolverOpts::default();
        options.negative_min_ttl = Some(Duration::from_secs(100));
        options.negative_max_ttl = Some(Duration::from_secs(200));
        let client = CachingClient::with_cache(
            ResponseCache::new(capacity, TtlConfig::from_opts(&options)),
            Script::new(Vec::new()),
            false,
        );
        let q = query("negative-ttl.example.", RecordType::A);
        for ttl in [0, 1, 500] {
            let result = client
                .cache(q.clone(), Err(negative(&q, ResponseCode::NXDomain, ttl)))
                .unwrap_err();
            let NetError::Dns(DnsError::NoRecordsFound(error)) = result else {
                panic!("negative result");
            };
            assert_eq!(error.negative_ttl, Some(ttl));
            assert_eq!(error.soa.unwrap().ttl, ttl);
            assert_eq!(*error.query, q);
        }
    }
}

#[test]
fn a_aaaa_txt_keep_complete_sections_and_record_order() {
    for capacity in [0, 4] {
        for (kind, data) in [
            (RecordType::A, RData::A(A::new(192, 0, 2, 9))),
            (
                RecordType::AAAA,
                RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)),
            ),
            (
                RecordType::TXT,
                RData::TXT(TXT::new(vec!["first".into(), "second".into()])),
            ),
        ] {
            let q = query("sections.example.", kind);
            let mut answer = message(&q, 1);
            answer.answers = vec![
                Record::from_rdata(q.name().clone(), 3600, data.clone()),
                Record::from_rdata(q.name().clone(), 3600, data),
            ];
            let expected = answer.clone();
            let script = Script::new(vec![response(answer)]);
            let result = ready(
                client(capacity, script.clone(), false)
                    .lookup(q.clone(), DnsRequestOptions::default()),
            )
            .unwrap();
            assert_eq!(result.message(), &expected);
            assert_eq!(script.queries(), [q]);
        }
    }
}

#[test]
fn same_response_cname_preserves_filtering_order_and_deadline() {
    for capacity in [0, 4] {
        for preserve in [false, true] {
            let q = query("alias.example.", RecordType::A);
            let target = name("target.example.");
            let mut answer = message(&q, 1);
            answer.answers = vec![
                alias(q.name(), &target, 10),
                a(&target, 3600, 3),
                a(&target, 3600, 4),
            ];
            let expected_authorities = answer.authorities.clone();
            let expected_additionals = answer.additionals.clone();
            let script = Script::new(vec![response(answer)]);
            let before = Instant::now();
            let result = ready(
                client(capacity, script.clone(), preserve)
                    .lookup(q.clone(), DnsRequestOptions::default()),
            )
            .unwrap();
            let after = Instant::now();
            let mut expected = vec![
                a(&target, if preserve { 3600 } else { 10 }, 3),
                a(&target, if preserve { 3600 } else { 10 }, 4),
            ];
            if preserve {
                expected.insert(0, alias(q.name(), &target, 10));
            }
            assert_eq!(result.answers(), expected);
            assert_eq!(result.authorities(), expected_authorities);
            assert_eq!(result.additionals(), expected_additionals);
            assert_eq!(result.query(), &q);
            assert!(result.valid_until() >= before + Duration::from_secs(10));
            assert!(result.valid_until() <= after + Duration::from_secs(10));
            assert_eq!(script.queries(), [q]);
        }
    }
}

#[test]
fn later_response_cname_returns_child_query_and_existing_ttl_semantics() {
    for capacity in [0, 4] {
        for preserve in [false, true] {
            let q = query("alias.example.", RecordType::A);
            let child = query("child.example.", RecordType::A);
            let mut first = message(&q, 1);
            first.answers = vec![alias(q.name(), child.name(), 10)];
            let second = message(&child, 9);
            let expected_authorities = second.authorities.clone();
            let expected_additionals = second.additionals.clone();
            let mut expected_answers = second.answers.clone();
            if preserve {
                expected_answers.insert(0, alias(q.name(), child.name(), 10));
            }
            let script = Script::new(vec![response(first), response(second)]);
            let before = Instant::now();
            let result = ready(
                client(capacity, script.clone(), preserve)
                    .lookup(q.clone(), DnsRequestOptions::default()),
            )
            .unwrap();
            let after = Instant::now();
            assert_eq!(result.query(), &child);
            assert_eq!(result.answers(), expected_answers);
            assert_eq!(result.authorities(), expected_authorities);
            assert_eq!(result.additionals(), expected_additionals);
            // Preserve upstream behavior: discarded intermediates do not constrain the child deadline.
            let ttl = Duration::from_secs(if preserve { 10 } else { 3600 });
            assert!(result.valid_until() >= before + ttl);
            assert!(result.valid_until() <= after + ttl);
            assert_eq!(script.queries(), [q, child]);
        }
    }
}

#[test]
fn cname_depth_exhaustion_remains_bounded_and_negative() {
    for capacity in [0, 4] {
        for preserve in [false, true] {
            let mut expected_queries = Vec::new();
            let mut replies = Vec::new();
            for hop in 0..8 {
                let q = query(&format!("hop{hop}.example."), RecordType::A);
                let target = name(&format!("hop{}.example.", hop + 1));
                let mut answer = message(&q, 1);
                answer.answers = vec![alias(q.name(), &target, 10)];
                replies.push(response(answer));
                expected_queries.push(q);
            }
            let script = Script::new(replies);
            let result = ready(
                client(capacity, script.clone(), preserve)
                    .lookup(expected_queries[0].clone(), DnsRequestOptions::default()),
            )
            .unwrap_err();
            let NetError::Dns(DnsError::NoRecordsFound(error)) = result else {
                panic!("depth must return negative response");
            };
            assert_eq!(*error.query, expected_queries[7]);
            assert_eq!(script.queries(), expected_queries);
        }
    }
}

#[test]
fn unrelated_name_class_and_type_are_not_accepted_as_answers() {
    for capacity in [0, 4] {
        for mismatch in 0..3 {
            let q = query("requested.example.", RecordType::A);
            let mut answer = message(&q, 1);
            answer.authorities.clear();
            answer.additionals.clear();
            answer.answers.truncate(1);
            match mismatch {
                0 => answer.answers[0].name = name("other.example."),
                1 => answer.answers[0].dns_class = DNSClass::CH,
                2 => answer.answers[0].data = RData::TXT(TXT::new(vec!["wrong type".into()])),
                _ => unreachable!(),
            }
            let script = Script::new(vec![response(answer)]);
            let result = ready(
                client(capacity, script.clone(), false)
                    .lookup(q.clone(), DnsRequestOptions::default()),
            )
            .unwrap_err();
            assert!(matches!(result, NetError::Dns(DnsError::NoRecordsFound(_))));
            assert_eq!(script.queries(), [q]);
        }
    }
}

#[test]
fn special_use_names_never_query_upstream_and_non_in_class_is_ordinary() {
    for capacity in [0, 4] {
        let script = Script::new(Vec::new());
        let client = client(capacity, script.clone(), false);
        for kind in [RecordType::A, RecordType::AAAA, RecordType::PTR] {
            let q = query("localhost.", kind);
            let result = ready(client.lookup(q.clone(), DnsRequestOptions::default())).unwrap();
            assert_eq!(result.query(), &q);
            assert_eq!(result.answers().len(), 1);
            assert_eq!(result.answers()[0].record_type(), kind);
        }
        for (value, code) in [
            ("localhost.", ResponseCode::NoError),
            ("absent.invalid.", ResponseCode::NXDomain),
            ("hidden.onion.", ResponseCode::NXDomain),
        ] {
            let result =
                ready(client.lookup(query(value, RecordType::TXT), DnsRequestOptions::default()))
                    .unwrap_err();
            let NetError::Dns(DnsError::NoRecordsFound(error)) = result else {
                panic!("special-use error");
            };
            assert_eq!(error.response_code, code);
        }
        assert!(script.queries().is_empty());
        let mut q = query("localhost.", RecordType::A);
        q.set_query_class(DNSClass::CH);
        let mut answer = message(&q, 4);
        for r in &mut answer.answers {
            r.dns_class = DNSClass::CH;
        }
        let script = Script::new(vec![response(answer)]);
        let result = ready(
            super::client(capacity, script.clone(), false)
                .lookup(q.clone(), DnsRequestOptions::default()),
        )
        .unwrap();
        assert_eq!(result.answers()[0].dns_class, DNSClass::CH);
        assert_eq!(script.queries(), [q]);
    }
}

#[test]
fn dns_response_error_codes_are_still_classified() {
    for capacity in [0, 4] {
        let q = query("refused.example.", RecordType::A);
        let mut answer = message(&q, 1);
        answer.metadata.response_code = ResponseCode::Refused;
        let script = Script::new(vec![response(answer)]);
        assert!(matches!(
            ready(client(capacity, script, false).lookup(q, DnsRequestOptions::default())),
            Err(NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)))
        ));
    }
}
