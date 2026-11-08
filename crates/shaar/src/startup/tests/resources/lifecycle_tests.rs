//! Held cleanup, transfer, cancel, supersession, and resolution regressions over the retained composition.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;

use iroh::EndpointAddr;
use iroh::TransportAddr;
use iroh_base::EndpointId;

use crate::native_discovery::runtime::owner::LoopbackPeer;
use crate::native_discovery::runtime::publisher::PublicationStatus;
use crate::startup::SharedResourcesStart;
use crate::startup::StartupError;

use super::close_tests::{
    Fixture, admit_and_capture_initial_put, close_transit_and_release_claims, peer_composition,
};
use super::status_tests::{
    acknowledge_initial, close_composition, current_publication, drive_snapshot, endpoint_id,
    finish_submit, hold_snapshot, new_composition, published, stable_published, valid_snapshot,
};
use super::{BUDGET, probe_claim_free, published_on_watch, wait_admitted};

/// Mainline cleanup held by a publication-observer hold keeps shutdown bounded and retryable;
/// the snapshot is a concrete loopback UDP candidate (a wildcard `local_addr()` is rejected).
#[tokio::test]
async fn held_mainline_cleanup_shutdown_stays_bounded_and_retryable() {
    // Exceeds the bounded-stage sum (watcher stop + two 5s bounds + margin).
    const BOUNDED_SHUTDOWN_BUDGET: Duration = Duration::from_secs(30);

    let mut peer = LoopbackPeer::bind().await;
    let (mut start, _, identity, transit, signaling_port, mainline_port) =
        peer_composition(&mut peer, 0xF4, 0xF6, |identity, plan, limits| {
            (
                SharedResourcesStart::start_with_cleanup_hold_for_tests(identity, plan, limits),
                None,
            )
        })
        .await;

    let (resources, (source, transaction, _signed, _item)) =
        admit_and_capture_initial_put(&mut start, &mut peer).await;
    peer.acknowledge(source, &transaction).await;
    // published_on_watch only returns on Published, so the expect IS the oracle.
    let publication = published_on_watch(&resources).await;
    assert!(
        matches!(publication, PublicationStatus::Published { .. }),
        "the retained Mainline owner has actually published before hold: {publication:?}"
    );
    let native_addr = resources
        .endpoint_for_tests(|endpoint| endpoint.local_addr())
        .expect("admitted native endpoint");

    // Arm hold + observer BEFORE submitting; drive until the replacement PUT is
    // captured (flight B active); a REVOKED flight's expiry still hits clean_work.
    let observer = resources
        .mainline_cleanup_observer_for_tests()
        .expect("publication observer seam");
    let hold = resources
        .mainline_cleanup_hold_for_tests()
        .expect("arm mainline cleanup hold");
    let endpoint_id = EndpointId::from_bytes(&identity.public_key_bytes())
        .expect("identity key is an EndpointId");
    // Production binds the native endpoint to the unspecified address, so the
    // wildcard `local_addr()` is rejected by real publisher validation (P09);
    // the candidate below is concrete loopback on the same bound UDP port.
    let candidate = SocketAddr::from(([127, 0, 0, 1], native_addr.port()));
    let address = EndpointAddr::from_parts(endpoint_id, [TransportAddr::Ip(candidate)]);
    {
        let mut submit = Box::pin(resources.submit_watcher_snapshot_for_tests(address));
        let captured_b = tokio::time::timeout(BUDGET, async {
            tokio::select! {
                biased;
                result = &mut submit => panic!("submission must stay pending until its PUT is captured: {result:?}"),
                captured = peer.capture_put_record() => captured,
            }
        })
        .await
        .expect("replacement PUT captured while the submission stays pending");
        let (_source_b, _transaction_b, signed_b, _item_b) = captured_b;
        let record_b = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed_b)
            .expect("captured replacement B record decodes");
        assert_eq!(
            record_b.ip_addrs().copied().collect::<Vec<_>>(),
            vec![candidate],
            "replacement B PUT carries the submitted concrete watcher candidate"
        );
    } // submit borrow ends, B stays active; no PUT capture is re-asserted after release.
    let mut fixture = Fixture {
        start,
        resources,
        transit,
        signaling_port,
        mainline_port,
    };
    // Withdraw revokes the active B flight and blocks in held cancellation cleanup.
    let first = {
        let mut shutdown = std::pin::pin!(fixture.start.shutdown());
        tokio::time::timeout(BOUNDED_SHUTDOWN_BUDGET, async {
            tokio::select! {
                biased;
                result = &mut shutdown => panic!("shutdown must not complete while cleanup is held: {result:?}"),
                _ = observer.wait_cleanup_held() => {}
            }
        })
        .await
        .expect("withdraw entered held cancellation cleanup within the budget");
        tokio::time::timeout(BOUNDED_SHUTDOWN_BUDGET, &mut shutdown)
            .await
            .expect("held cleanup shutdown stays bounded")
            .expect_err("held Mainline cleanup is nonterminal")
    };
    assert_eq!(
        first,
        StartupError::Close {
            stage: "publication-withdraw"
        },
        "the withdraw stage records the first error while cleanup is held"
    );

    // While Mainline is retained, every other backend's resource is released.
    let rebound_native = UdpSocket::bind(native_addr).expect("native UDP owner closes");
    drop(rebound_native);
    let rebound_signaling = TcpListener::bind(("127.0.0.1", fixture.signaling_port))
        .expect("signaling closes despite retained Mainline");
    drop(rebound_signaling);
    probe_claim_free(0xF4, "Ygg owner closes despite retained Mainline").await;
    let occupied = UdpSocket::bind(("127.0.0.1", fixture.mainline_port))
        .expect_err("retained Mainline owner still holds its UDP port");
    assert_eq!(occupied.kind(), std::io::ErrorKind::AddrInUse);

    // Releasing the hold lets the retry terminate with the same first error.
    hold.release();
    let second = tokio::time::timeout(BUDGET, fixture.start.shutdown())
        .await
        .expect("retry after hold release finishes within the budget")
        .expect_err("first error remains cached after terminal cleanup");
    assert_eq!(second, first);
    let rebound = UdpSocket::bind(("127.0.0.1", fixture.mainline_port))
        .expect("terminal retry releases the Mainline port");
    drop(rebound);
    assert_eq!(
        fixture
            .start
            .shutdown()
            .await
            .expect_err("terminal cached error"),
        first
    );
    close_transit_and_release_claims(fixture, 0xF4, 0xF6).await;
}

/// The withdrawal barrier is a held active-B PUT: an unacknowledged replacement stays in flight,
/// so the withdraw revokes an ACTUAL flight and blocks in held cancellation cleanup; a
/// mid-quiesce cancel converges, the retry transfers, and shutdown reports the retained error.
#[tokio::test]
async fn cancelled_native_transfer_retains_owners_and_retry_transfers_usable_endpoint() {
    let mut peer = LoopbackPeer::bind().await;
    let (mut start, _controls, identity, transit, signaling_port, mainline_port) =
        peer_composition(&mut peer, 0xCD, 0xCE, |identity, plan, limits| {
            (
                SharedResourcesStart::start_with_cleanup_hold_for_tests(identity, plan, limits),
                None,
            )
        })
        .await;

    let (resources, (source, transaction, _signed, _item)) =
        admit_and_capture_initial_put(&mut start, &mut peer).await;
    peer.acknowledge(source, &transaction).await;
    assert!(
        matches!(
            published_on_watch(&resources).await,
            PublicationStatus::Published { .. }
        ),
        "the composition published its initial watcher snapshot before the transfer"
    );

    // Arm hold + observer BEFORE submitting: withdrawal must revoke an ACTUAL
    // in-flight PUT (not a published generation) to block in held cleanup.
    let observer = resources
        .mainline_cleanup_observer_for_tests()
        .expect("publication observer seam");
    let hold = resources
        .mainline_cleanup_hold_for_tests()
        .expect("arm mainline cleanup hold");
    // Two serialized withdraw bounds (cancelled attempt + this attempt)
    // plus margin; both fire while the hold stays armed.
    const BOUNDED_ATTEMPT_BUDGET: Duration = Duration::from_secs(30);

    // Real endpoint id and a concrete loopback candidate on the bound native
    // UDP port (the wildcard local_addr() candidate is publisher-rejected).
    let endpoint_id = EndpointId::from_bytes(&identity.public_key_bytes())
        .expect("identity key is an EndpointId");
    let native_addr = resources
        .endpoint_for_tests(|endpoint| endpoint.local_addr())
        .expect("admitted native endpoint");
    let candidate = SocketAddr::from(([127, 0, 0, 1], native_addr.port()));
    let address = EndpointAddr::from_parts(endpoint_id, [TransportAddr::Ip(candidate)]);
    {
        let mut submit = Box::pin(resources.submit_watcher_snapshot_for_tests(address));
        let (_source_b, _transaction_b, signed_b, _item_b) = tokio::time::timeout(BUDGET, async {
            tokio::select! {
                biased;
                result = &mut submit => panic!("submission must stay pending until its PUT is captured: {result:?}"),
                captured = peer.capture_put_record() => captured,
            }
        })
        .await
        .expect("replacement PUT captured while the submission stays pending");
        // The ACK is deliberately WITHHELD so B remains the held flight;
        // decode and assert the captured record BEFORE withholding it.
        let record_b = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed_b)
            .expect("captured replacement B record decodes");
        assert_eq!(
            record_b.endpoint_id, endpoint_id,
            "replacement B carries the composition identity"
        );
        assert_eq!(
            record_b.ip_addrs().copied().collect::<Vec<_>>(),
            vec![candidate],
            "replacement B PUT carries the submitted concrete watcher candidate"
        );
        // B stays active and unacknowledged: its revocation cleanup is the
        // held barrier the transfer attempts below block on.
    }

    // Owned boxed future: dropping the Box destroys the future storage, so
    // the QuiesceNative reply sender genuinely dies with the cancellation
    // (a `pin!` reference would keep the future alive to the scope end).
    let mut transfer = Box::pin(resources.transfer_native());
    tokio::time::timeout(BUDGET, async {
        tokio::select! {
            biased;
            result = &mut transfer => panic!("transfer cannot finish while Mainline cleanup is held: {result:?}"),
            _ = observer.wait_cleanup_held() => {}
        }
    })
    .await
    .expect("transfer withdraw entered held cancellation cleanup within the budget");

    // Finding-5 oracle: while the quiesce holds the slot extracted, readiness
    // still reports the owned resources instead of absence.
    let readiness = resources.readiness().await;
    assert!(
        readiness.native_bound,
        "native endpoint stays claimed during quiesce"
    );
    assert_eq!(
        readiness.ygg,
        crate::startup::YggPhase::BridgeOnly,
        "ygg ownership stays claimed during quiesce"
    );

    // Genuine caller cancellation at the held withdraw: the reply channel
    // dies with the future, so the bounded attempt completes unobserved.
    drop(transfer);

    // The owner task serializes QuiesceNative requests, so this attempt starts
    // after the cancelled attempt's withdraw timed out (recording
    // `publication-withdraw`); with the hold armed, its own 5s bound also
    // fires — ~10s bounded, no release race.
    let second = tokio::time::timeout(BOUNDED_ATTEMPT_BUDGET, resources.transfer_native())
        .await
        .expect("serialized bounded attempts conclude within the budget")
        .expect_err("held cleanup keeps both attempts nonterminal");
    assert_eq!(
        second,
        StartupError::Close {
            stage: "native-quiesce"
        }
    );

    // Honest retention after both attempts.
    let readiness = resources.readiness().await;
    assert!(
        readiness.native_bound && !readiness.native_transferred,
        "owners retained across cancelled and bounded attempts"
    );
    let occupied = UdpSocket::bind(("127.0.0.1", mainline_port))
        .expect_err("retained Mainline owner still holds its UDP port");
    assert_eq!(occupied.kind(), std::io::ErrorKind::AddrInUse);

    // Whether the cancelled attempt's queued withdraw completed after the
    // release or timed out, the retry's fresh withdraw succeeds unblocked.
    hold.release();
    let endpoint = tokio::time::timeout(BUDGET, resources.transfer_native())
        .await
        .expect("retry transfer completes within the budget")
        .expect("withdrawal proof permits the native transfer")
        .expect("native endpoint transferred");
    assert_ne!(
        endpoint.signaling_addr().port(),
        0,
        "usable signaling endpoint"
    );
    let readiness = resources.readiness().await;
    assert!(
        !readiness.native_bound && readiness.native_transferred,
        "readiness is truthful after the transfer"
    );
    // Actual post-transfer native operation through the transferred endpoint's real signaling route.
    let fixture = crate::network::RelayFixture::start().await;
    let fixture_relay = fixture.address;
    let operations = endpoint.relay_operations();
    let lease = tokio::time::timeout(BUDGET, operations.reserve(fixture_relay))
        .await
        .expect("relay reserve completes")
        .expect("transferred endpoint still operates its signaling");
    assert_eq!(lease.relay(), fixture_relay);
    operations
        .release(fixture_relay)
        .await
        .expect("relay release");
    fixture.close().await;
    // Caller closes the transferred owner first (composition doc contract).
    tokio::time::timeout(BUDGET, endpoint.close())
        .await
        .expect("transferred endpoint close completes within the budget")
        .expect("transferred endpoint closes cleanly");
    // The FIRST attempt's withdraw timeout recorded `publication-withdraw`
    // while the hold was armed, so shutdown reports it regardless of the
    // later attempts' outcomes.
    let error = tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .expect("shutdown completes after the transfer")
        .expect_err("the cancelled attempt retains the first error");
    assert_eq!(
        error,
        StartupError::Close {
            stage: "publication-withdraw"
        }
    );
    assert_eq!(
        start.shutdown().await.expect_err("cached first error"),
        error
    );
    close_transit_and_release_claims(
        Fixture {
            start,
            resources,
            transit,
            signaling_port,
            mainline_port,
        },
        0xCD,
        0xCE,
    )
    .await;
}

const SCENARIO_TWO_IDENTITY: u8 = 0xE7;
const SCENARIO_TWO_TRANSIT: u8 = 0xE8;

// Mutation caught: canceling the required Submit future when capture wins, allowing a stale A
// completion to replace the latest readiness state, or publishing invalid input.
#[tokio::test]
async fn pending_submissions_supersede_stale_puts_and_withdraw_invalid_latest() {
    let mut peer = LoopbackPeer::bind().await;
    let (mut start, identity, transit) =
        new_composition(&peer, SCENARIO_TWO_IDENTITY, SCENARIO_TWO_TRANSIT, &[]).await;
    let resources = wait_admitted(&mut start).await;
    let _initial = acknowledge_initial(&resources, &mut peer).await;
    let initial_status = current_publication(&resources).await;
    assert!(matches!(
        initial_status,
        PublicationStatus::Published { .. }
    ));

    // Only after the watcher-derived initial publication is stable do these
    // cases drive the explicit cfg(test) snapshot seam.
    let before = current_publication(&resources).await.generation();
    let (mut submit_a, (source_a, transaction_a, _signed_a, _item_a), status_a) = hold_snapshot(
        &resources,
        &mut peer,
        valid_snapshot(&identity, "127.0.0.1:9210"),
        before,
    )
    .await;
    let generation_a = match status_a {
        PublicationStatus::Pending { generation } => generation,
        other => panic!("captured A is Pending before supersession: {other:?}"),
    };

    let (mut submit_b, (source_b, transaction_b, signed_b, _item_b), status_b) = hold_snapshot(
        &resources,
        &mut peer,
        valid_snapshot(&identity, "127.0.0.1:9211"),
        generation_a,
    )
    .await;
    let generation_b = match status_b {
        PublicationStatus::Pending { generation } if generation != generation_a => generation,
        other => panic!("captured B has its definitive Pending generation: {other:?}"),
    };

    let record_b = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed_b)
        .expect("B's actual captured signed record");
    assert_eq!(record_b.endpoint_id, endpoint_id(&identity));
    assert_eq!(
        record_b.ip_addrs().copied().collect::<Vec<_>>(),
        vec!["127.0.0.1:9211".parse::<SocketAddr>().expect("B address")]
    );
    // Acknowledging old A after B capture must not publish A or alter B's
    // definitive captured-flight generation. Cancellation is local; it does
    // not wait for this old wire acknowledgment before B can be sent.
    peer.acknowledge(source_a, &transaction_a).await;
    let stale_a = tokio::time::timeout(BUDGET, &mut submit_a)
        .await
        .expect("superseded A submit resolves");
    assert!(
        stale_a.is_err(),
        "superseded A is not reported successful: {stale_a:?}"
    );
    let pending_b = current_publication(&resources).await;
    assert_eq!(
        pending_b,
        PublicationStatus::Pending {
            generation: generation_b
        },
        "stale A acknowledgment leaves captured B Pending at its actual generation"
    );

    peer.acknowledge(source_b, &transaction_b).await;
    let result_b = tokio::time::timeout(BUDGET, &mut submit_b)
        .await
        .expect("actual B Submit result after UDP acknowledgment");
    assert!(
        result_b.is_ok(),
        "acknowledged B submit completes: {result_b:?}"
    );
    let published_b = published(&resources).await;
    assert_eq!(
        published_b, generation_b,
        "B's completion publishes its captured flight generation"
    );
    stable_published(&resources, generation_b).await;

    let invalid = [
        EndpointAddr::from_parts(
            endpoint_id(&identity),
            [TransportAddr::Ip(
                "0.0.0.0:9212".parse().expect("unspecified address"),
            )],
        ),
        EndpointAddr::from_parts(endpoint_id(&identity), std::iter::empty()),
        EndpointAddr::from_parts(
            endpoint_id(&identity),
            (0..5).map(|port| {
                TransportAddr::Ip(
                    format!("192.0.2.1:{}", 9300 + port)
                        .parse()
                        .expect("over-cap candidate"),
                )
            }),
        ),
    ];
    for (index, snapshot) in invalid.into_iter().enumerate() {
        let before = current_publication(&resources).await.generation();
        let (mut stale_submit, (source, transaction, _signed_a, _item_a), status_a) =
            hold_snapshot(
                &resources,
                &mut peer,
                valid_snapshot(&identity, &format!("127.0.0.1:{}", 9220 + index)),
                before,
            )
            .await;
        let generation_a = match status_a {
            PublicationStatus::Pending { generation } => generation,
            other => panic!("each invalid case begins with a captured Pending A: {other:?}"),
        };
        let (replacement_submit, withdrawn, replacement_result) =
            drive_snapshot(&resources, snapshot, generation_a).await;
        assert!(
            matches!(withdrawn, PublicationStatus::Unavailable { .. }),
            "latest invalid snapshot is locally withdrawn while A remains held: {withdrawn:?}"
        );

        peer.acknowledge(source, &transaction).await;
        let stale_result = tokio::time::timeout(BUDGET, &mut stale_submit)
            .await
            .expect("stale A submit resolves after supersession");
        assert!(
            stale_result.is_err(),
            "stale A cannot succeed: {stale_result:?}"
        );
        let replacement_result = finish_submit(replacement_submit, replacement_result).await;
        if index == 0 {
            assert!(
                replacement_result.is_err(),
                "unspecified address is rejected by the real publisher validation"
            );
        } else {
            assert!(
                replacement_result.is_ok(),
                "empty or over-cap snapshot is a local withdrawal: {replacement_result:?}"
            );
        }
        let latest = current_publication(&resources).await;
        assert!(
            matches!(latest, PublicationStatus::Unavailable { generation } if generation != generation_a),
            "stale A ACK leaves latest withdrawal in force: {latest:?}"
        );
        // The only PUT expected in this interval was A, already captured and
        // acknowledged above. Invalid input creates no refresh/publication PUT.
        peer.assert_no_put_for(Duration::from_millis(50)).await;
    }

    // Source-reviewed only: maintenance retains one publish plus one latest
    // snapshot; publisher retains one flight plus one queued replacement.
    let before = current_publication(&resources).await.generation();
    let (mut submit_a, (source_a, transaction_a, _signed_a, _item_a), status_a) = hold_snapshot(
        &resources,
        &mut peer,
        valid_snapshot(&identity, "127.0.0.1:9240"),
        before,
    )
    .await;
    let generation_a = match status_a {
        PublicationStatus::Pending { generation } => generation,
        other => panic!("captured A is Pending before replacement: {other:?}"),
    };
    let (mut submit_b, (source_b, transaction_b, signed_b, _item_b), status_b) = hold_snapshot(
        &resources,
        &mut peer,
        valid_snapshot(&identity, "127.0.0.1:9241"),
        generation_a,
    )
    .await;
    let generation_b = match status_b {
        PublicationStatus::Pending { generation } if generation != generation_a => generation,
        other => panic!("captured B has its own Pending generation: {other:?}"),
    };
    let record_b = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed_b)
        .expect("captured in-flight B record");
    assert_eq!(record_b.endpoint_id, endpoint_id(&identity));
    assert_eq!(
        record_b.ip_addrs().copied().collect::<Vec<_>>(),
        vec!["127.0.0.1:9241".parse::<SocketAddr>().expect("B address")]
    );

    let (submit_c, status_c, result_c) = drive_snapshot(
        &resources,
        EndpointAddr::from_parts(endpoint_id(&identity), std::iter::empty()),
        generation_b,
    )
    .await;
    assert!(
        matches!(status_c, PublicationStatus::Unavailable { .. }),
        "latest empty C is locally withdrawn while A and B are held: {status_c:?}"
    );
    let c_result = finish_submit(submit_c, result_c).await;
    assert!(c_result.is_ok(), "empty C withdraws locally: {c_result:?}");
    let withdrawn_c = current_publication(&resources).await;
    assert!(
        matches!(withdrawn_c, PublicationStatus::Unavailable { .. }),
        "completed empty C leaves the actual latest status Unavailable: {withdrawn_c:?}"
    );

    // A and B are stale wire operations now; their acknowledgments must not
    // restore readiness or emit any replacement PUT (bounded supersession
    // with B in flight, not a queue-capacity claim).
    peer.acknowledge(source_a, &transaction_a).await;
    assert!(
        tokio::time::timeout(BUDGET, &mut submit_a)
            .await
            .expect("superseded A submit resolves")
            .is_err(),
        "stale A is canceled locally"
    );
    peer.acknowledge(source_b, &transaction_b).await;
    assert!(
        tokio::time::timeout(BUDGET, &mut submit_b)
            .await
            .expect("superseded captured B submit resolves")
            .is_err(),
        "stale B is canceled locally"
    );

    let latest = current_publication(&resources).await;
    assert_eq!(
        latest, withdrawn_c,
        "stale A and B acknowledgments leave C's actual Unavailable status unchanged"
    );
    peer.assert_no_put_for(Duration::from_millis(50)).await;

    close_composition(
        &mut start,
        transit,
        SCENARIO_TWO_IDENTITY,
        SCENARIO_TWO_TRANSIT,
    )
    .await;
}

/// Cancelled resolve with an unserved record frees the resolver slot: the first GET is admitted
/// while driven, the completion barrier proves the cancel drained, and a SINGLE retry works.
#[tokio::test]
async fn cancelled_resolve_leaves_the_resolver_slot_usable_for_a_retry() {
    let mut peer = LoopbackPeer::bind().await;
    let (mut start, _controls, identity, transit, signaling_port, mainline_port) =
        peer_composition(&mut peer, 0x3C, 0x4C, |identity, plan, limits| {
            (
                SharedResourcesStart::start_with_cleanup_hold_for_tests(identity, plan, limits),
                None,
            )
        })
        .await;

    let (resources, (source, transaction, signed, item)) =
        admit_and_capture_initial_put(&mut start, &mut peer).await;
    peer.acknowledge(source, &transaction).await;
    assert!(matches!(
        published_on_watch(&resources).await,
        PublicationStatus::Published { .. }
    ));
    let key = EndpointId::from_bytes(&identity.public_key_bytes())
        .expect("identity key is an EndpointId");
    let observer = resources
        .mainline_cleanup_observer_for_tests()
        .expect("publication observer seam");
    let actor_id = resources
        .mainline_actor_id_for_tests()
        .expect("mainline actor id seam");

    // Owned boxed future so the drop really cancels the reply sender; the select drives `first` concurrently so the real GET is actually sent.
    let mut first = Box::pin(resources.resolve(key));
    let target = n0_mainline::MutableItem::target_from_key(item.key(), None);
    // Isolation identity: the target is the application-key target, NOT the
    // backend routing id, so its cleanup is an ordinary owned-query teardown.
    assert_ne!(
        target, actor_id,
        "resolve target must not be the routing id"
    );
    assert!(!observer.has_retired_query(target));
    let (_source, _transaction) = tokio::time::timeout(BUDGET, async {
        tokio::select! {
            biased;
            result = &mut first => panic!(
                "the first resolve cannot complete while nothing serves the record: {result:?}"
            ),
            captured = peer.capture_get(target) => captured,
        }
    })
    .await
    .expect("the first resolve's real GET is admitted at the loopback peer");
    // Dropping the Box destroys the future storage; the reply sender dies too.
    drop(first);
    // Completion-barrier receipt: the idle seam answers from the resolver's completion
    // event (never a snapshot), so `true` proves the cancel drained and the dropped
    // backend query's actor cleanup was requested.
    assert!(
        tokio::time::timeout(BUDGET, resources.resolve_idle_for_tests())
            .await
            .expect("maintenance actor answers the idle check"),
        "maintenance drained the cancelled resolver and freed the slot"
    );
    // Backend receipt: the observer records the target only AFTER the actor dropped
    // the cancelled waiter's leases, cancelled the operation's transactions, and removed
    // the iterative query — so the retry cannot attach to a surviving actor query.
    tokio::time::timeout(BUDGET, observer.wait_query_retired(target))
        .await
        .expect("the backend retires the cancelled GET query within the budget");
    // Single retry, real record server driven concurrently; success also excludes ResolveBusy.
    let record = iroh_dns::endpoint_info::EndpointInfo::from_pkarr_signed_packet(&signed)
        .expect("captured service record decodes");
    let resolved = tokio::time::timeout(BUDGET, async {
        tokio::select! {
            result = resources.resolve(key) => result,
            _ = peer.serve_record(&item) => {
                panic!("the real record server terminated while serving the retry")
            }
        }
    })
    .await
    .expect("single retry completes within the budget")
    .expect("freed resolver slot admits the retry");
    assert_eq!(
        resolved.addresses(),
        record.ip_addrs().copied().collect::<Vec<_>>().as_slice(),
        "the retried GET returns the actual published watcher snapshot"
    );

    tokio::time::timeout(BUDGET, start.shutdown())
        .await
        .expect("shutdown after resolve cancellation")
        .expect("shutdown is clean");
    close_transit_and_release_claims(
        Fixture {
            start,
            resources,
            transit,
            signaling_port,
            mainline_port,
        },
        0x3C,
        0x4C,
    )
    .await;
}
