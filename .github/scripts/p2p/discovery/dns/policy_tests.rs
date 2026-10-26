#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;

use hickory_resolver::proto::rr::rdata::{A, AAAA};
use libp2p_core::Transport as _;

use crate::{retention_support::*, *};

fn address(text: &str) -> Multiaddr {
    text.parse().unwrap()
}

fn answers(v6: bool, count: u16) -> Lookup {
    lookup((1..=count).map(|value| {
        if v6 {
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, value)))
        } else {
            RData::A(A(Ipv4Addr::new(192, 0, 2, u8::try_from(value).unwrap())))
        }
    }))
}

#[test]
fn retention_policy_numeric_rejection_precedes_every_materialization_and_dial() {
    run(async {
        for (name, v6) in [
            ("dns", false),
            ("dns", true),
            ("dns4", false),
            ("dns6", true),
        ] {
            for count in [1, 9] {
                reset();
                let resolver = PolicyResolver::new(
                    FakeResolver::new(move |_| Ok(answers(v6, count))),
                    |encoded| {
                        assert!(!encoded.is_empty());
                        assert_eq!(observed().allocations, 0, "POLICY_AFTER_NUMERIC_ALLOCATION");
                        false
                    },
                );
                let inner = FakeTransport::new(Mode::Success);
                let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
                let result = transport
                    .dial(address(&format!("/{name}/owned/tcp/7")), options())
                    .unwrap()
                    .await;
                assert!(matches!(result, Err(Error::ResolveError(_))));
                assert_eq!(
                    resolver.policy_calls.load(Ordering::SeqCst),
                    usize::from(count.min(4))
                );
                assert_eq!(observed().allocations, 0);
                assert_eq!(observed().pending, 0);
                assert_eq!(observed().errors, 0);
                assert!(inner.dials.lock().is_empty());
            }
        }
    });
}

#[test]
fn retention_policy_numeric_selection_preserves_suffix_budget_and_lifo_order() {
    run(async {
        for (name, v6) in [
            ("dns", false),
            ("dns", true),
            ("dns4", false),
            ("dns6", true),
        ] {
            reset();
            let expected_peer = peer(5);
            let expected: Vec<_> = [2, 4]
                .into_iter()
                .map(|last| {
                    let ip = if v6 {
                        format!("ip6/2001:db8::{last}")
                    } else {
                        format!("ip4/192.0.2.{last}")
                    };
                    address(&format!("/{ip}/tcp/7/p2p/{expected_peer}"))
                })
                .collect();
            let allowed = expected.clone();
            let resolver = PolicyResolver::new(
                FakeResolver::new(move |_| Ok(answers(v6, 9))),
                move |encoded| {
                    allowed
                        .iter()
                        .any(|candidate| candidate.as_ref() == encoded)
                },
            );
            let inner = FakeTransport::new(Mode::Fail);
            let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
            assert_eq!(
                error_count(
                    transport
                        .dial(
                            address(&format!("/{name}/owned/tcp/7/p2p/{expected_peer}")),
                            options()
                        )
                        .unwrap()
                        .await
                ),
                2
            );
            assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 4);
            assert_eq!(
                &*inner.dials.lock(),
                &[expected[1].clone(), expected[0].clone()]
            );
            assert_eq!(observed().allocations, 2);
            assert_eq!(observed().pending, 2);
        }
    });
}

#[test]
fn retention_policy_all_txt_rejected_has_no_materialization_or_error_accumulation() {
    run(async {
        let resolver = PolicyResolver::new(
            FakeResolver::new(|_| {
                Ok(lookup((1..=100).map(|port| {
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/{port}"))
                })))
            }),
            |_| {
                assert_eq!(observed().allocations, 0, "POLICY_AFTER_TXT_ALLOCATION");
                false
            },
        );
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        assert!(matches!(
            transport
                .dial(address("/dnsaddr/owned"), options())
                .unwrap()
                .await,
            Err(Error::ResolveError(_))
        ));
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 100);
        assert_eq!(observed().parses, 100);
        assert_eq!(observed().allocations, 0);
        assert_eq!(observed().pending, 0);
        assert_eq!(observed().errors, 0);
        assert!(inner.dials.lock().is_empty());
    });
}

#[test]
fn retention_policy_txt_receives_complete_prefix_and_suffix_after_validation() {
    run(async {
        let expected_peer = peer(1);
        let wrong_peer = peer(2);
        let candidates: Vec<_> = (1..=3)
            .map(|port| {
                address(&format!(
                    "/ip4/198.51.100.9/ip4/192.0.2.1/tcp/{port}/p2p/{expected_peer}"
                ))
            })
            .collect();
        let expected = candidates[1].clone();
        let allowed = expected.clone();
        let resolver = PolicyResolver::new(
            FakeResolver::new(move |_| {
                Ok(lookup([
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/7/p2p/{wrong_peer}")),
                    txt("missing-prefix"),
                    txt(vec![b'x'; 1025]),
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/1/p2p/{expected_peer}")),
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/2/p2p/{expected_peer}")),
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/2/p2p/{expected_peer}")),
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/3/p2p/{expected_peer}")),
                ]))
            }),
            move |encoded| {
                // Expectations are encoded by the upstream parser before the predicate runs.
                assert!(
                    candidates
                        .iter()
                        .any(|candidate| candidate.as_ref() == encoded),
                    "POLICY_RECEIVED_INCOMPLETE_OR_INVALID_CONTEXT"
                );
                encoded == allowed.as_ref()
            },
        );
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        let result = transport
            .dial(
                address(&format!(
                    "/ip4/198.51.100.9/dnsaddr/root/p2p/{expected_peer}"
                )),
                options(),
            )
            .unwrap()
            .await
            .unwrap();
        assert_eq!(result, expected);
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 3);
        assert_eq!(observed().parses, 6);
        assert_eq!(observed().allocations, 1);
        assert_eq!(inner.dials.lock().len(), 1);
    });
}

#[test]
fn retention_policy_txt_rejections_do_not_consume_the_accepted_limit() {
    run(async {
        let allowed: Vec<_> = (1..=16)
            .map(|n| address(&format!("/ip4/192.0.2.1/tcp/{}", n * 2)))
            .collect();
        let resolver = PolicyResolver::new(
            FakeResolver::new(|_| {
                Ok(lookup((1..=40).map(|port| {
                    txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/{port}"))
                })))
            }),
            move |encoded| {
                allowed
                    .iter()
                    .any(|candidate| candidate.as_ref() == encoded)
            },
        );
        let inner = FakeTransport::new(Mode::Fail);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        assert_eq!(
            error_count(
                transport
                    .dial(address("/dnsaddr/owned"), options())
                    .unwrap()
                    .await
            ),
            16
        );
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 32);
        assert_eq!(observed().parses, 32);
        assert_eq!(observed().allocations, 16);
        assert_eq!(observed().pending, 16);
        let dials = inner.dials.lock();
        assert_eq!(dials.len(), 16);
        assert_eq!(dials[0], address("/ip4/192.0.2.1/tcp/32"));
        assert_eq!(dials[15], address("/ip4/192.0.2.1/tcp/2"));
    });
}

#[test]
fn retention_policy_nested_expansion_is_forwarded_and_gated_at_each_stage() {
    run(async {
        for allow_root in [false, true] {
            reset();
            let expected_peer = peer(3);
            let intermediate = address(&format!(
                "/ip4/198.51.100.9/dns4/leaf/tcp/7/p2p/{expected_peer}"
            ));
            let expected = address(&format!(
                "/ip4/198.51.100.9/ip4/192.0.2.2/tcp/7/p2p/{expected_peer}"
            ));
            let allowed = expected.clone();
            let resolver = PolicyResolver::new(
                FakeResolver::new(move |name| match name {
                    "_dnsaddr.root" => Ok(lookup([txt(format!(
                        "dnsaddr=/dns4/leaf/tcp/7/p2p/{expected_peer}"
                    ))])),
                    "leaf" => Ok(answers(false, 4)),
                    _ => panic!("unexpected nested query"),
                }),
                move |encoded| {
                    allow_root && (encoded == intermediate.as_ref() || encoded == allowed.as_ref())
                },
            );
            let inner = FakeTransport::new(Mode::Success);
            let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
            let result = transport
                .dial(
                    address(&format!(
                        "/ip4/198.51.100.9/dnsaddr/root/p2p/{expected_peer}"
                    )),
                    options(),
                )
                .unwrap()
                .await;
            if allow_root {
                assert_eq!(result.unwrap(), expected);
                assert_eq!(&*resolver.inner.calls.lock(), &["_dnsaddr.root", "leaf"]);
                assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 5);
                assert_eq!(observed().allocations, 2);
                assert_eq!(inner.dials.lock().len(), 1);
            } else {
                assert!(matches!(result, Err(Error::ResolveError(_))));
                assert_eq!(&*resolver.inner.calls.lock(), &["_dnsaddr.root"]);
                assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 1);
                assert_eq!(observed().allocations, 0);
                assert!(inner.dials.lock().is_empty());
            }
        }
    });
}

#[test]
fn retention_policy_direct_non_dns_input_still_bypasses_the_hook() {
    run(async {
        let resolver = PolicyResolver::new(
            FakeResolver::new(|_| panic!("direct input must not resolve")),
            |_| panic!("direct input must not invoke expansion policy"),
        );
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        for input in [
            address("/ip4/127.0.0.1/tcp/7"),
            Multiaddr::from(Protocol::Unix("x".repeat(300).into())),
        ] {
            assert_eq!(
                transport
                    .dial(input.clone(), options())
                    .unwrap()
                    .await
                    .unwrap(),
                input
            );
        }
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(observed().allocations, 0);
        assert_eq!(inner.dials.lock().len(), 2);
    });
}

#[test]
fn retention_policy_cancellation_and_lookup_errors_preserve_ownership() {
    run(async {
        let mut raw = FakeResolver::new(|_| panic!("pending lookup cannot complete"));
        raw.pending = true;
        let resolver = PolicyResolver::new(raw, |_| panic!("pending lookup cannot reach policy"));
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        drop(transport.dial(address("/dns4/pending"), options()).unwrap());
        assert!(resolver.inner.calls.lock().is_empty());
        let mut dial = Box::pin(transport.dial(address("/dns4/pending"), options()).unwrap());
        assert!(futures::poll!(&mut dial).is_pending());
        assert_eq!(resolver.inner.active.load(Ordering::SeqCst), 1);
        drop(dial);
        assert_eq!(resolver.inner.active.load(Ordering::SeqCst), 0);
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 0);
        assert!(inner.dials.lock().is_empty());

        reset();
        let resolver = PolicyResolver::new(
            FakeResolver::new(|_| Err(ResolveError::from("owned lookup failure"))),
            |_| panic!("failed lookup cannot reach policy"),
        );
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        assert_eq!(
            error_count(
                transport
                    .dial(address("/dnsaddr/failed"), options())
                    .unwrap()
                    .await
            ),
            1
        );
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(observed().errors, 1);
        assert_eq!(observed().allocations, 0);
        assert!(inner.dials.lock().is_empty());

        reset();
        let allowed = address("/ip4/192.0.2.2/tcp/7");
        let resolver = PolicyResolver::new(
            FakeResolver::new(|_| Ok(answers(false, 4))),
            move |encoded| encoded == allowed.as_ref(),
        );
        let inner = FakeTransport::new(Mode::Pending);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        let mut dial = Box::pin(
            transport
                .dial(address("/dns4/owned/tcp/7"), options())
                .unwrap(),
        );
        assert!(futures::poll!(&mut dial).is_pending());
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 4);
        assert_eq!(observed().allocations, 1);
        assert_eq!(inner.active.load(Ordering::SeqCst), 1);
        drop(dial);
        assert_eq!(inner.active.load(Ordering::SeqCst), 0);
        assert_eq!(inner.dials.lock().len(), 1);
        assert_eq!(resolver.policy_calls.load(Ordering::SeqCst), 4);
    });
}
