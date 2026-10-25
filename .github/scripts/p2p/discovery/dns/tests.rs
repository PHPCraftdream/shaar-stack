#![forbid(unsafe_code)]

use std::{sync::atomic::Ordering, time::Duration};

use hickory_resolver::proto::rr::rdata::{A, AAAA, TXT};
use libp2p_core::Transport as _;

use crate::{retention_support::*, *};

fn address(text: &str) -> Multiaddr {
    text.parse().unwrap()
}

fn numeric(v6: bool, count: u16) -> Lookup {
    lookup((1..=count).map(|value| {
        if v6 {
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, value)))
        } else {
            RData::A(A(Ipv4Addr::new(192, 0, 2, u8::try_from(value).unwrap())))
        }
    }))
}

#[test]
fn retention_direct_dial_preserves_address_and_never_calls_resolver() {
    run(async {
        let resolver = FakeResolver::new(|_| panic!("direct dial must bypass DNS"));
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        for input in [
            address("/ip4/192.0.2.1/tcp/1234"),
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
        assert_eq!(inner.dials.lock().len(), 2);
        assert!(resolver.calls.lock().is_empty());
        assert_eq!(observed().allocations, 0);
    });
}

#[test]
fn retention_caller_resolver_preserves_numeric_suffix_and_success() {
    run(async {
        let resolver = FakeResolver::new(|name| {
            assert_eq!(name, "owned.example");
            Ok(numeric(false, 1))
        });
        let mut transport =
            Transport::with_resolver(FakeTransport::new(Mode::Success), resolver.clone());
        let expected = peer(7);
        let input = address(&format!("/dns4/owned.example/tcp/1234/p2p/{expected}"));
        let result = transport.dial(input, options()).unwrap().await.unwrap();
        assert_eq!(
            result,
            address(&format!("/ip4/192.0.2.1/tcp/1234/p2p/{expected}"))
        );
        assert_eq!(resolver.calls.lock().len(), 1);
        assert_eq!(observed().allocations, 1);
    });
}

#[test]
fn retention_numeric_fanout_is_capped_before_collection_and_dial() {
    run(async {
        for (name, v6) in [("dns", false), ("dns4", false), ("dns6", true)] {
            reset();
            let resolver = FakeResolver::new(move |_| Ok(numeric(v6, 100)));
            let proto = match name {
                "dns" => Protocol::Dns("owned.example".into()),
                "dns4" => Protocol::Dns4("owned.example".into()),
                _ => Protocol::Dns6("owned.example".into()),
            };
            let result = resolve::<io::Error, _>(&proto, &resolver).await.unwrap();
            let Resolved::Many(ips) = result else {
                panic!("expected multiple addresses")
            };
            assert_eq!(ips.len(), 4);
            assert!(!ips.spilled(), "numeric alternatives must remain inline");
            let inner = FakeTransport::new(Mode::Fail);
            let mut transport = Transport::with_resolver(inner.clone(), resolver);
            assert_eq!(
                error_count(
                    transport
                        .dial(address(&format!("/{name}/owned.example/tcp/9")), options())
                        .unwrap()
                        .await
                ),
                4
            );
            let dials = inner.dials.lock();
            assert_eq!(dials.len(), 4);
            let ip = if v6 {
                "ip6/2001:db8::4"
            } else {
                "ip4/192.0.2.4"
            };
            assert_eq!(dials[0], address(&format!("/{ip}/tcp/9")));
            assert_eq!(observed().allocations, 4);
            assert_eq!(observed().pending, 4);
        }
    });
}

#[test]
fn retention_empty_mismatched_and_failed_lookups_are_errors_not_panics() {
    run(async {
        for input in ["/dns/empty", "/dns4/empty", "/dns6/empty"] {
            for wrong_type in [false, true] {
                let resolver = FakeResolver::new(move |_| {
                    Ok(if wrong_type {
                        lookup([txt("unrelated")])
                    } else {
                        lookup([])
                    })
                });
                let inner = FakeTransport::new(Mode::Success);
                let mut transport = Transport::with_resolver(inner.clone(), resolver);
                assert_eq!(
                    error_count(transport.dial(address(input), options()).unwrap().await),
                    1
                );
                assert!(inner.dials.lock().is_empty());
            }
        }
        let resolver = FakeResolver::new(|_| Err(ResolveError::from("owned lookup failure")));
        let mut transport = Transport::with_resolver(FakeTransport::new(Mode::Success), resolver);
        assert_eq!(
            error_count(
                transport
                    .dial(address("/dnsaddr/failed"), options())
                    .unwrap()
                    .await
            ),
            1
        );
    });
}

#[test]
fn retention_txt_cap_precedes_parsing_and_address_allocation() {
    run(async {
        let resolver = FakeResolver::new(|_| {
            Ok(lookup((1..=100).map(|port| {
                txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/{port}"))
            })))
        });
        let inner = FakeTransport::new(Mode::Fail);
        let mut transport = Transport::with_resolver(inner.clone(), resolver);
        assert_eq!(
            error_count(
                transport
                    .dial(address("/dnsaddr/owned"), options())
                    .unwrap()
                    .await
            ),
            16
        );
        assert_eq!(observed().parses, 16);
        assert_eq!(observed().allocations, 16);
        assert_eq!(observed().pending, 16);
        assert_eq!(inner.dials.lock()[0], address("/ip4/192.0.2.1/tcp/16"));
    });
}

#[test]
fn retention_expected_peer_filter_and_duplicates_precede_retention() {
    run(async {
        let expected = peer(1);
        let wrong = peer(2);
        let resolver = FakeResolver::new(move |_| {
            let wrong = (0..20).map(|_| txt(format!("dnsaddr=/ip4/192.0.2.1/tcp/9/p2p/{wrong}")));
            let valid =
                (0..20).map(|_| txt(format!("dnsaddr=/ip4/192.0.2.2/tcp/9/p2p/{expected}")));
            Ok(lookup(wrong.chain(valid)))
        });
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver);
        let output = transport
            .dial(
                address(&format!("/dnsaddr/owned/p2p/{expected}")),
                options(),
            )
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            output,
            address(&format!("/ip4/192.0.2.2/tcp/9/p2p/{expected}"))
        );
        assert_eq!(inner.dials.lock().len(), 1);
        assert_eq!(observed().allocations, 1);
        assert_eq!(observed().pending, 1);
        reset();
        let resolver = FakeResolver::new(|_| {
            Ok(lookup(
                (0..100).map(|_| RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))),
            ))
        });
        let inner = FakeTransport::new(Mode::Fail);
        let mut transport = Transport::with_resolver(inner.clone(), resolver);
        assert_eq!(
            error_count(
                transport
                    .dial(address("/dns4/duplicates"), options())
                    .unwrap()
                    .await
            ),
            1
        );
        assert_eq!(inner.dials.lock().len(), 1);
        assert_eq!(observed().allocations, 1);
    });
}

#[test]
fn retention_oversized_txt_is_rejected_before_parse_and_invalid_records_are_skipped() {
    run(async {
        let resolver = FakeResolver::new(|_| {
            let oversized = vec![b'x'; 1025];
            let huge_tail = vec![b'x'; 1024];
            Ok(lookup([
                txt(oversized),
                RData::TXT(TXT::from_bytes(vec![
                    b"dnsaddr=/ip4/192.0.2.99",
                    &huge_tail,
                ])),
                txt([0xff]),
                txt("missing-prefix"),
                txt("dnsaddr=missing-slash"),
                txt("dnsaddr=/unknown/9"),
                txt("dnsaddr=/ip4/192.0.2.1/tcp/7"),
            ]))
        });
        let mut transport = Transport::with_resolver(FakeTransport::new(Mode::Success), resolver);
        assert_eq!(
            transport
                .dial(address("/dnsaddr/owned"), options())
                .unwrap()
                .await
                .unwrap(),
            address("/ip4/192.0.2.1/tcp/7")
        );
        assert_eq!(observed().parses, 5);
        assert_eq!(observed().allocations, 1);
        for (size, accepted) in [(1024, true), (1025, false)] {
            reset();
            let first = b"dnsaddr=/ip4/192.0.2.1/tcp/7";
            let tail = vec![b'x'; size - first.len()];
            let answer = lookup([RData::TXT(TXT::from_bytes(vec![first, &tail]))]);
            let resolver = FakeResolver::new(move |_| Ok(answer.clone()));
            let mut transport =
                Transport::with_resolver(FakeTransport::new(Mode::Success), resolver);
            assert_eq!(
                transport
                    .dial(address("/dnsaddr/owned"), options())
                    .unwrap()
                    .await
                    .is_ok(),
                accepted
            );
            assert_eq!(observed().parses, usize::from(accepted));
            assert_eq!(observed().allocations, usize::from(accepted));
        }
    });
}

#[test]
fn retention_numeric_encoded_boundary_is_checked_before_allocation() {
    run(async {
        for (initial, accepted) in [(242, true), (243, false)] {
            reset();
            let mut input = address("/dns6/x");
            input.push(Protocol::Unix("x".repeat(initial - 7).into()));
            assert_eq!(input.as_ref().len(), initial);
            let resolver = FakeResolver::new(|_| Ok(numeric(true, 1)));
            let inner = FakeTransport::new(Mode::Success);
            let mut transport = Transport::with_resolver(inner.clone(), resolver);
            let result = transport.dial(input, options()).unwrap().await;
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(inner.dials.lock().len(), usize::from(accepted));
            assert_eq!(observed().allocations, usize::from(accepted));
            if accepted {
                assert_eq!(result.unwrap().as_ref().len(), 256);
            }
        }
    });
}

#[test]
fn retention_txt_encoded_boundary_and_prefix_are_checked_before_allocation() {
    run(async {
        for (length, accepted) in [(247, true), (248, false)] {
            reset();
            let resolver = FakeResolver::new(move |_| {
                Ok(lookup([txt(format!(
                    "dnsaddr=/unix/{}",
                    "x".repeat(length)
                ))]))
            });
            let inner = FakeTransport::new(Mode::Success);
            let mut transport = Transport::with_resolver(inner.clone(), resolver);
            let result = transport
                .dial(address("/ip4/192.0.2.1/dnsaddr/owned"), options())
                .unwrap()
                .await;
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(observed().allocations, usize::from(accepted));
            if accepted {
                assert_eq!(result.unwrap().as_ref().len(), 256);
            }
        }
    });
}

#[test]
fn retention_dns_input_byte_limit_is_checked_before_lookup() {
    run(async {
        for (size, accepted) in [(256, true), (257, false)] {
            let input = Multiaddr::from(Protocol::Dns4("x".repeat(size - 3).into()));
            assert_eq!(input.as_ref().len(), size);
            let resolver = FakeResolver::new(|_| Ok(numeric(false, 1)));
            let mut transport =
                Transport::with_resolver(FakeTransport::new(Mode::Success), resolver.clone());
            assert_eq!(
                transport.dial(input, options()).unwrap().await.is_ok(),
                accepted
            );
            assert_eq!(resolver.calls.lock().len(), usize::from(accepted));
        }
    });
}

#[test]
fn retention_recursive_fanout_bounds_pending_and_error_history() {
    run(async {
        // Distinct bounded names at every level, all valid DNSADDR multiaddrs.
        let sequence = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = sequence.clone();
        let resolver = FakeResolver::new(move |_| {
            let level = counter.fetch_add(1, Ordering::SeqCst);
            Ok(lookup((0..16).map(|n| {
                txt(format!("dnsaddr=/dnsaddr/n{level}-{n}.example"))
            })))
        });
        let inner = FakeTransport::new(Mode::Fail);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        assert_eq!(
            error_count(
                transport
                    .dial(address("/dnsaddr/root"), options())
                    .unwrap()
                    .await
            ),
            16
        );
        assert_eq!(resolver.calls.lock().len(), 32);
        assert_eq!(sequence.load(Ordering::SeqCst), 32);
        assert_eq!(observed().pending, 32);
        assert_eq!(observed().errors, 16);
        assert!(inner.dials.lock().is_empty());
        assert!(observed().largest_address <= 256);
    });
}

#[test]
fn retention_cycle_stops_at_lookup_budget() {
    run(async {
        let resolver = FakeResolver::new(|_| Ok(lookup([txt("dnsaddr=/dnsaddr/loop")])));
        let mut transport =
            Transport::with_resolver(FakeTransport::new(Mode::Success), resolver.clone());
        let result = transport
            .dial(address("/dnsaddr/loop"), options())
            .unwrap()
            .await;
        assert_eq!(error_count(result), 1);
        assert_eq!(resolver.calls.lock().len(), 32);
        assert_eq!(observed().pending, 1);
    });
}

#[test]
fn retention_unsupported_addresses_do_not_replenish_error_storage() {
    run(async {
        let resolver = FakeResolver::new(|name| {
            if name == "_dnsaddr.root" {
                Ok(lookup(
                    (0..16).map(|n| txt(format!("dnsaddr=/dns4/n{n}/tcp/7"))),
                ))
            } else {
                Ok(numeric(false, 4))
            }
        });
        for (mode, dials, lookups) in [(Mode::Unsupported, 64, 17), (Mode::Fail, 16, 5)] {
            resolver.calls.lock().clear();
            reset();
            let inner = FakeTransport::new(mode);
            let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
            assert_eq!(
                error_count(
                    transport
                        .dial(address("/dnsaddr/root"), options())
                        .unwrap()
                        .await
                ),
                16
            );
            assert_eq!(inner.dials.lock().len(), dials);
            assert_eq!(resolver.calls.lock().len(), lookups);
            assert_eq!(observed().errors, 16);
        }
    });
}

#[test]
fn retention_cancel_before_poll_and_pending_lookup_releases_future() {
    run(async {
        let mut resolver = FakeResolver::new(|_| panic!("pending resolver cannot complete"));
        resolver.pending = true;
        let inner = FakeTransport::new(Mode::Success);
        let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
        let input = address("/dns4/pending");
        drop(transport.dial(input.clone(), options()).unwrap());
        assert!(resolver.calls.lock().is_empty());
        let mut dial = Box::pin(transport.dial(input, options()).unwrap());
        assert!(futures::poll!(&mut dial).is_pending());
        assert_eq!(resolver.active.load(Ordering::SeqCst), 1);
        drop(dial);
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
        assert!(inner.dials.lock().is_empty());
    });
}

#[test]
fn retention_cancel_pending_inner_dial_releases_future_and_stops_alternatives() {
    run(async {
        let resolver = FakeResolver::new(|_| Ok(numeric(false, 4)));
        let inner = FakeTransport::new(Mode::Pending);
        let mut transport = Transport::with_resolver(inner.clone(), resolver);
        let mut dial = Box::pin(
            transport
                .dial(address("/dns4/owned/tcp/7"), options())
                .unwrap(),
        );
        assert!(futures::poll!(&mut dial).is_pending());
        assert_eq!(inner.dials.lock().len(), 1);
        assert_eq!(inner.active.load(Ordering::SeqCst), 1);
        drop(dial);
        assert_eq!(inner.active.load(Ordering::SeqCst), 0);
        assert_eq!(inner.dials.lock().len(), 1);
    });
}

#[test]
fn retention_outer_deadline_includes_lookup_and_inner_dial() {
    run(async {
        for pending_lookup in [true, false] {
            let mut resolver = FakeResolver::new(|_| Ok(numeric(false, 4)));
            resolver.pending = pending_lookup;
            let inner = FakeTransport::new(Mode::Pending);
            let mut transport = Transport::with_resolver(inner.clone(), resolver.clone());
            let mut dial = Box::pin(
                transport
                    .dial(address("/dns4/owned/tcp/7"), options())
                    .unwrap(),
            );
            assert!(futures::poll!(&mut dial).is_pending());
            assert_eq!(
                resolver.active.load(Ordering::SeqCst),
                usize::from(pending_lookup)
            );
            assert_eq!(
                inner.active.load(Ordering::SeqCst),
                usize::from(!pending_lookup)
            );
            assert!(
                ::tokio::time::timeout(Duration::from_millis(1), dial)
                    .await
                    .is_err()
            );
            assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
            assert_eq!(inner.active.load(Ordering::SeqCst), 0);
            assert_eq!(inner.dials.lock().len(), usize::from(!pending_lookup));
        }
    });
}
