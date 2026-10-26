#![forbid(unsafe_code)]

use super::*;
use crate::{
    config::ResolverOpts,
    net::dnssec::BOGUS_CACHE_TTL,
    proto::dnssec::{
        rdata::{DNSSECRData, DNSKEY},
        Algorithm, Proof, PublicKeyBuf,
    },
};

fn key(owner: &Name) -> Record {
    // Structural DNSSEC record fixture, not a signature-verification fixture.
    Record::from_rdata(
        owner.clone(),
        3600,
        RData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::new(
            true,
            false,
            false,
            PublicKeyBuf::new(vec![0; 32], Algorithm::ED25519),
        ))),
    )
}

#[test]
fn validated_bogus_answers_are_rejected_and_secure_answers_survive() {
    for capacity in [0, 4] {
        for proof in [Proof::Bogus, Proof::Secure] {
            let q = query("proof.example.", RecordType::A);
            let mut answer = message(&q, 1);
            for record in &mut answer.answers {
                record.proof = proof;
            }
            let mut script = Script::new(vec![response(answer.clone())]);
            script.verifying = true;
            let result = ready(
                client(capacity, script.clone(), false)
                    .lookup(q.clone(), DnsRequestOptions::default()),
            );
            if proof == Proof::Bogus {
                assert!(matches!(result, Err(NetError::Dns(DnsError::DnssecBogus))));
            } else {
                assert_eq!(result.unwrap().message(), &answer);
            }
            assert_eq!(script.queries(), [q]);
        }
    }
}

#[test]
fn validating_negative_result_clears_only_negative_ttl() {
    for capacity in [0, 4] {
        for verifying in [false, true] {
            let q = query("dnssec-negative.example.", RecordType::A);
            let mut script = Script::new(vec![Err(negative(&q, ResponseCode::NXDomain, 60))]);
            script.verifying = verifying;
            let result = ready(
                client(capacity, script, false).lookup(q.clone(), DnsRequestOptions::default()),
            )
            .unwrap_err();
            let NetError::Dns(DnsError::NoRecordsFound(error)) = result else {
                panic!("negative response");
            };
            assert_eq!(*error.query, q);
            assert_eq!(error.response_code, ResponseCode::NXDomain);
            assert_eq!(error.negative_ttl, if verifying { None } else { Some(60) });
            assert_eq!(error.soa.unwrap().ttl, 60);
        }
    }
}

#[test]
fn do_bit_strips_only_unrequested_dnssec_records_in_all_sections() {
    for capacity in [0, 4] {
        for do_bit in [false, true] {
            for kind in [RecordType::A, RecordType::DNSKEY] {
                let q = query("dnssec-sections.example.", kind);
                let mut answer = message(&q, 1);
                if kind == RecordType::DNSKEY {
                    answer.answers.clear();
                }
                answer.add_answer(key(q.name()));
                answer.add_authority(key(&name("example.")));
                answer.add_additional(key(&name("ns.example.")));
                let mut expected = answer.clone();
                if !do_bit && kind == RecordType::A {
                    expected
                        .answers
                        .retain(|r| r.record_type() != RecordType::DNSKEY);
                    expected
                        .authorities
                        .retain(|r| r.record_type() != RecordType::DNSKEY);
                    expected
                        .additionals
                        .retain(|r| r.record_type() != RecordType::DNSKEY);
                }
                let script = Script::new(vec![response(answer)]);
                let mut options = DnsRequestOptions::default();
                options.edns_set_dnssec_ok = do_bit;
                let result = ready(client(capacity, script, false).lookup(q, options)).unwrap();
                assert_eq!(result.message(), &expected);
            }
        }
    }
}

#[test]
fn bogus_deadline_cap_remains_independent_of_operator_ttl_floor() {
    for capacity in [0, 4] {
        let q = query("bogus-ttl.example.", RecordType::A);
        let mut options = ResolverOpts::default();
        options.positive_min_ttl = Some(Duration::from_secs(3600));
        let cache = ResponseCache::new(capacity, TtlConfig::from_opts(&options));
        let client = CachingClient::with_cache(cache, Script::new(Vec::new()), false);
        let mut answer = message(&q, 1);
        answer.answers[0].proof = Proof::Bogus;
        let before = Instant::now();
        let result = client.cache(q, Ok(answer)).unwrap();
        let after = Instant::now();
        assert_eq!(result.answers()[0].ttl, 3600);
        assert!(result.valid_until() >= before + BOGUS_CACHE_TTL);
        assert!(result.valid_until() <= after + BOGUS_CACHE_TTL);
    }
}
