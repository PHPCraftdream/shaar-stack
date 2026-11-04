<!-- Copyright 2026 PHPCraftdream; SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Native publisher runtime tests

This report describes source and authored coverage for the private `native_discovery` runtime. The loopback fixture sends real Mainline PUTs and observes actual receipts/cleanup; it uses no public network, observed/bound-address harvesting, synchronization sleeps, or synthetic success receipts. The changes do not add a public SDK API. The original source pass ran no build or tests. Later actual SDK CI `41812873830` at `d75d6a8` compiled and executed the selected suite on both OS: 77 passed, one deadline/recovery case failed. That failed run is not publisher or P09 acceptance; the corrected setup below still needs fresh CI.

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

## Remaining gaps / verification

The deadline case previously withheld an ACK but did not keep completion pending
through the caller deadline. Native retries or an earlier operation bound may end
work sooner; the exact failing result variant was not printed and is unknown.
The corrected setup holds actual Mainline cleanup before the real PUT starts,
checks the pending caller, retains the exact `DeadlineExceeded` assertion, waits
for actual held cleanup, releases it, then observes the cleanup barrier and real
recovery publication. Recovery resumes normal Tokio time before UDP exchange;
there are no synchronization sleeps, synthetic success receipts or relaxed errors.

This setup repair has not run. The existing Mainline retry/deadline and resource
checks remain separate obligations, without a frozen inventory. Independent
record evidence and SDK regressions are already accepted under #263/#261; they do
not prove this publisher's lifecycle. Full source-bound integration and production
caller wiring remain #253. `Clean` means cleanup confirmed; `Unknown` is terminal.
