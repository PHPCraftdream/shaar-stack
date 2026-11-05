<!-- Copyright 2026 PHPCraftdream; SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Native publisher runtime tests

This report describes source and authored coverage for the private `native_discovery` runtime. The loopback fixture sends real Mainline PUTs and observes actual receipts/cleanup; it uses no public network, observed/bound-address harvesting, synchronization sleeps, or synthetic success receipts. The changes do not add a public SDK API. The original source pass ran no build or tests. Later actual SDK CI `41812873830` at `d75d6a8` compiled and executed the selected suite on both OS: 77 passed, one deadline/recovery case failed. That failed run is not publisher or P09 acceptance. Corrected runtime `dc96f5a` passed all 78 selected cases on both OS in CI `41824086364`, with independently checked inventories and execution logs. The additional source-preservation change described below still needs fresh exact-SHA CI.

## Runtime contract and authored coverage

- Validate at most four raw IP addresses before deduplication; invalid, relay/custom/Yggdrasil snapshots revoke atomically. An empty replacement withdraws without publishing a packet. Enforce 1000-byte DNS and 1104-byte signed packet limits.
- Before queue admission, retain only native-IP payloads with at most four entries and vector capacity at most four. Discard caller excess capacity; unsupported transports become error payloads rather than retained addresses. The owner still revokes and observes actual old-generation cleanup before returning that validation error. Authored unit cases cover empty/one/four-entry capacity bounds and unsupported payloads; held-cleanup loopback cases ensure invalid IP, relay and custom replacements cannot reply before cleanup release.
- Initial publication and 60-second refresh produce newly signed packets with checked, strictly advancing timestamps and actual PUT receipts. No outer retry loop is added; Mainline retains its bounded attempts/deadline.
- Revoke the active generation before replacement validation. Invalid/empty replacement and withdrawal stop old-generation sends; stale completion cannot acknowledge or mutate the replacement.
- Cancellation during an admitted/held PUT revokes the generation and performs cleanup; local recovery is supported after terminal cleanup, rather than treating every admission error as terminal. A deadline timeout does not detach admitted work or claim cleanup before its receipt.
- The caller's original absolute deadline includes request entry, queueing, old cleanup wait, admission, bootstrap, and native attempts. The caller reports failure when that deadline expires; any remaining cleanup is retained separately, and expired queued work cannot start. Close has a five-second reporting bound; timeout retains ownership, while success means actual publisher and DHT joins. Held cleanup preserves active PUT plus operation/request/result leases while normal cancellation stops the PUT; shared GETs are preserved.
- PUT packets carry the minimum of the original PUT deadline and any existing operation deadline; an earlier operation bound can shorten work but never restart or extend the original caller budget. This is a conservative shared-operation bound, not an independent full-lifetime guarantee. The deadline is an upper bound, not a guarantee of success within ten seconds.
- Timestamp checks include overflow, `i64::MAX`, wall-plus-30-second ceiling, independent wall/monotonic bracket comparison, terminal catch-up, and no resume after rollback.

Authored runtime tests are in `runtime/tests.rs` and its modules: `tests/fixture.rs`, `tests/publication.rs`, `tests/lifetime.rs`, and `tests/bounds.rs`. They cover signed initial publication and real acknowledgement, rejected PUT/local recovery, refresh signature/timestamp, requester cancellation, withdrawal/replacement, stale reply, deadline/cleanup/recovery, retained resources across close timeout/cancellation and eventual joins/socket rebind, and boundary cases. The native PUT-until-retry deadline test is at `.github/scripts/p2p/discovery/mainline/ci/ownership/tests/hostile_resource_tests/public_put_tests.rs`; the GET-preserves-scoped-packet test is at `.github/scripts/p2p/discovery/mainline/ci/resources/tests/lifecycle/lifecycle_tests/put_start_tests.rs`. Existing three-attempt 100/200-jitter coverage is preserved, not newly authored here. Shared-GET deadline coverage exercises actual expiry charged to the shared operation. This is authored source, not evidence that the tests were run. No active-DHT proof is claimed.

## Parent integration status

The dependency and development bindings at `149abfa` passed feature CI `41801292972`
and upstream feature CI `41804945243` on both OS with independent DATA review.
That SHA did not contain this SDK runtime. The following original source-pass
binding checklist describes the dependency capabilities already delivered; it is
not runtime compilation or execution evidence:

- Root exports: `OwnedPutAdmission`, `OwnedPutAdmissionError`, `OwnedPutCleanup`, `Observer`, `CleanupHold` (resource-level Rust exports are authored; generated crate-root exports remain a parent binding requirement).
- Copy `.github/scripts/p2p/discovery/mainline/ci/resources/socket/publication_observer.rs` to generated `src/publication_observer.rs`, and bind the `resource.rs` module path.
- In actor completion hook, replace the current capture-tid/process/owned-note-response block with `actor.process_owned_publication_message(message, from)`. The wrapper processes and notes exactly once; do not change GET provenance.
- At both socket receive `Response` and `Error` paths, change the ignored-stale receipt predicate from `is_expected_response` to `is_expected_owned_publication_response`. Record accepted response only after actor processing.
- Bind normal SDK dependencies directly to the accepted typed Mainline exports and DNS checked-timestamp encoder; add the exact SDK dev dependency `serde_bencode = "=0.2.4"` for the test-only loopback KRPC codec; enable Tokio `test-util` for paused-time tests.
- Parent CI ownership must include new runtime files, the new observer Rust source, and held-PUT tests. These are parent mapping obligations; no ownership scripts were changed here.

System monotonic samples now enclose independent wall/monotonic microsecond
rounding uncertainty: a lower endpoint is one microsecond below the truncated
value (saturating at zero), and the upper endpoint is one above (checked).
An equal-rate, phase-shifted clock regression and zero/boundary/overflow cases
exercise this sampling contract. Controlled-clock samples and strict rollback
checks remain unchanged. All three clock tests passed on both OS in the failed
`d75d6a8` run; this does not certify the remaining runtime cases.

The composed runtime remains private and awaits its existing P09 integration
caller. The non-test dead-code expectation is limited to that unwired module;
no public API or blanket lint suppression is added. Source parsing/formatting
is not compilation. A previous graph proof cannot certify the changed SDK source;
combined source-bound integration remains task #253.

## Disposition of the original #246 contract files (task 47)

The seven original unwired #246 contract files, preserved from primary commit `e4e0046`,
were reconciled scenario by scenario against the accepted runtime at `ad13c2b` and removed
as obsolete proposal sources. They were never executed and are not counted as coverage;
they stay recoverable from Git history. Covered scenarios map to executed suites
(`tests/bounds.rs`, `tests/lifetime.rs`, `tests/publication.rs`, `tests/resolution.rs`,
`owner/resolver_regressions.rs`, `owner/wiring_tests/*`, `native_discovery/tests/*` and the
dependency actor tests). Rejected as stale: the hypothetical cloneable request handle and
ticket API, exactly-two-RPC fixtures, a production fixture-destination allowlist, scripted
reject replies expected to retry three times, and a frozen-wall refresh oracle that
contradicts the paired-clock rollback policy. Ported here: negative records (stale, future
and relay-claiming) never start a dial while a valid record does
(`owner/wiring_tests/records.rs`).

Outstanding real-seam obligations owned by P09 acceptance (task 51): P7 checked network ordering
and equal-sequence conflict recovery through the real GET fixture with multiple responders, P10
cancelling `connect_until` before the GET response, P3 the sample-command wait and the GET sharing
one caller deadline, P4 a dropped unpolled resolve future changing no state, P8 replay and
local-PUT provenance never renewing the cache, and P2 sixty-four signed winners surviving expiry,
conflict and lower-seq replay are authored as real-seam regressions in
`runtime/owner/seam_tests/` (loopback fixture plus the real RuntimeOwner,
NativeDiscoveredEndpoint, resolver and PolicyOwner; paused Tokio time and controlled clocks only)
and are executed and green on both OS in SDK CI run `41959318451` at `be17cd7`. P7 still drives
both newer-responder permutations (each responder holds the newer record in one of the two phases);
datagram arrival order inside one batch is environment-controlled and the winner oracle is
order-independent. P2 still re-resolves all sixty-four winners after expiry, deep-dives conflict,
lower-seq replay and recovery on one slot, and re-checks the sixty-fifth-key capacity bound before
and after. Dependency-level P1 (eight active plus sixteen queued distinct keys) is covered by the
executed fixture tests `actor_admits_eight_distinct_operations_and_rejects_ninth_without_side_effects`,
`queued_get_admission_wakes_only_when_a_real_resource_is_released`,
`actual_actor_lazy_admission_bounds_queue_and_releases_cancelled_requests`,
`public_admission_overflow_keeps_actor_and_live_requests`,
`queued_deadlines_expire_without_work_and_promotion_keeps_original_deadline` and
`promoted_admission_preserves_original_deadline_across_coalesced_waiters`. Dependency-level P5
(caller-visible charges outlive the caller return until actor cleanup) is covered by the executed
`delivered_error_receivers_retain_result_charges_until_dropped`,
`held_send_gate_deadline_cleanup_is_deterministic_actor_cleanup_not_wall_clock_stall`,
`owned_actor_deadline_interrupts_held_send_without_transmission`,
`cancellation_at_real_send_gate_retains_rpc_and_datagram_charges` and
`terminal_failure_keeps_delivered_error_receivers_charged`, plus the authored
`cancelled_admission_keeps_request_and_result_charges_until_tick_cleanup` for the
cancelled-GET window and request-lease retention. Dependency-level P6 (stop while the socket
flush is held) is covered by the executed `owned_actor_keeps_socket_until_cleanup_completes`,
`owned_actor_keeps_socket_until_receive_returns`, `close_joins_actor_and_releases_exact_bind`,
`close_reports_aborted_actor_join_failure_and_retains_terminal_error` and the same
`owned_actor_deadline_interrupts_held_send_without_transmission`, plus the authored
`stop_while_flush_held_retains_charges_and_transmits_nothing` for charge accounting and the
never-transmitted held datagram. The two new dependency-level tests are authored only and await
CI; they have not been executed. This record does not establish P10 pathing, Server/Client
integration or public-network acceptance.

## Remaining gaps / verification

The deadline case previously withheld an ACK but did not keep completion pending
through the caller deadline. Native retries or an earlier operation bound may end
work sooner; the exact failing result variant was not printed and is unknown.
The corrected setup holds actual Mainline cleanup before the real PUT starts,
checks the pending caller, retains the exact `DeadlineExceeded` assertion, waits
for actual held cleanup, releases it, then observes the cleanup barrier and real
recovery publication. Recovery resumes normal Tokio time before UDP exchange;
there are no synchronization sleeps, synthetic success receipts or relaxed errors.

The setup repair passed at `dc96f5a`; the retained contract namespace is not new
execution coverage. Existing Mainline retry/deadline and resource checks remain
separate obligations, without a frozen inventory. Independent
record evidence and SDK regressions are already accepted under #263/#261; they do
not prove this publisher's lifecycle. Full source-bound integration and production
caller wiring remain #253. `Clean` means cleanup confirmed; `Unknown` is terminal.

## Private resolver composition under #253

The private owner now resolves through its actual retained DHT handle using the
caller's original absolute deadline. The same publisher task serializes clock
samples for publication and resolution; a proven rollback revokes publication
and remains terminal. Resolution currently borrows the owner exclusively, so
SDK GETs are serialized without a detached worker or a cache-write race after
caller cancellation. This private seam is not the final startup/TLS integration.

Only an actual opaque backend completion can mark the handoff as network-derived.
Its result lease remains owned by the delivered SDK result, not merely until DNS
decoding ends. Existing key authorization, 64 lifetime slots, signed freshness,
equal-sequence conflict and cache rules remain in `PolicyOwner`. The bounded
field adapter invokes the existing verifier; no custom crypto/DNS/DHT is added.

`tests/resolution.rs` authors real loopback GET cases for cache expiry, late
responses after cancellation, the original deadline, shared terminal clock
faults, eight delivered result leases and recovery, and empty/invalid records.
The ninth result waits in actual backend admission: the expected failure is the
original deadline, not a fabricated immediate `ResultLimit` receipt. These new
cases have not yet run. The previously reviewed `eb1c288` CI passed 80 native
cases on each OS, including both field-adapter regressions; it predates this
resolver source. No P09, startup/TLS or final normal-graph acceptance is claimed.

The resolver commit is transactional: `PolicyOwner::prepare_query` computes
the delivery plan without mutating winner or cache-deadline state (clock
bookkeeping, including an immediate terminal fault on a backward sample,
still runs first), `ResolverState::complete` rechecks the original caller
deadline once after preparation and before the synchronous commit, and only
then `commit_query_deliver`/`commit_query_conflict` mutate state. At the
commit point a current-use wall sample re-checks signed age against the
300-second limit, and the cache deadline is
`R + min(30s, max(0, 300s - max(0, W - signed)))` with `R` the backend
receipt monotonic and `W` that current-use wall time. The receipt itself is
sampled locally from the shared clock clone the moment the backend future
returns, so command-queue delay cannot shift it; the publisher task remains
the mediated fault gate. A terminal clock fault observed by the resolver clears usable cache
deadlines through `note_terminal_clock_fault` while replay watermarks stay retained. The publisher's
terminal routing is unchanged: later publication and resolve after a fault still report `Closed`; making
them report the explicit clock error is deferred to the coordinator leaf, which owns that lifecycle. Synchronous policy work cannot be
interrupted in production, so the paused-clock deadline regression pins the
pre-commit check between preparation and commit via a test-only cooperative
point. Network results and cache hits are charged alike to one owner-wide
eight-result delivery budget; a cache hit beyond it fails with `DeliveryLimit`
before any address allocation, while a network resolution first passes backend
admission and is charged when its result is delivered. The relocated resolver regressions now live in
`runtime/owner/resolver_regressions.rs` (`tests/` stays within its
seven-item limit): a deadline passing during preparation, cached results
exhausting and recovering the shared budget with rejection before
allocation, current-use freshness boundaries driven through the production
sampling path (receipt-anchored 30-second cap), and a result that ages out between
preparation and commit (the controlled wall clock advances at the test-only
cooperative point): exactly 300 seconds of signed age is accepted with no cache
lifetime, one microsecond past it is rejected without any commit. None of these
cases has been executed; GitHub CI remains the only run.

Terminal clock fault reporting (task 44): the owner remembers the first terminal clock
fault it observes (through its own resolve sampling, a rejected replacement, or a local
clock read failure). Later publish and resolve calls then return the explicit
`PublishError::ClockFault` immediately, with no queue, backend or network work; `Closed`
stays only for a genuinely closed owner. The publisher task keeps its internal terminal
routing, so a command already queued before the fault may still be answered `Closed`.
The two catch-up expectations that formerly expected `Closed` now expect the explicit
error for exactly this reason. Validated in-memory options and startup attachment belong to
task 45; nothing here has been executed, and GitHub CI is the only run.
