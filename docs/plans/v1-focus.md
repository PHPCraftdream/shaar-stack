# V1 delivery focus and standing reminders

**Distance to v1:** P01–P06 and D1 are accepted; P08 is bootstrap-only; P09 is accepted at `b076458` (record below); P07's adapter is technically accepted in the isolated `shaar-ygg-core` crate at `efa5c62` (leaves 53.1-53.4, record below); the user decided on 2026-11-05 that MPL-2.0 is allowed narrowly for the pinned `ironwood`/`yggdrasil` packages and that this repository is the source-availability mechanism for the modified files, so P07 stays gated only for notices (#72/#73) and any public-peer contact; P10–P16 are not accepted as complete stages. P10 leaves 1 (path policy), 2a (product linkage, `14680c2`) and 2b (readiness bridge, `3248a6a`) are accepted. Next: P10 leaves 3-6 (composition, `signal`/`standby` authorization, startup, efficiency acceptance #214/#215) and the full native/Yggdrasil matrix. Blockers include exact public-peer approval and public-network evidence, notices and separately gated public smoke.

**Decision history — 2026-11-04:** the user superseded the 2026-10-31 decision
that deferred P07 beyond v1. Restore the original one-Ed25519-key architecture:
native iroh/QUIC, Mainline publication/key lookup, libp2p signaling and a
key-derived Yggdrasil path. Yggdrasil participates in negotiation and `standby`
payload fallback; libp2p remains signaling-only in all modes. This scope change
is not permission for third-party integration, public traffic or host changes.

This is an execution-control document, not a new product leaf, proof mechanism,
CI segment, acceptance receipt, or permission to run gated actions. The governing
bounded-delivery rule remains [development plan §6.4](development.md#64-bounded-delivery-commitment-after-the-second-process-review).

## Standing task reminders

The session reminders have `kind=standing-reminder`, `actionable=false`, and
`auto_complete=false`. They are ongoing operator checks, not live executors or
additional runnable product work. Restore them by subject after a session reset;
do not restore completed product tasks from an old checkpoint.

| Reminder | Required check |
| --- | --- |
| #269 — Finish P09, then gated P07, then P10 | Work within existing P09 leaves; do not open P07 in parallel. After P09, satisfy #224 and accept #33/#34 before #214. Add no proof mechanism or CI segment without a specific uncovered failing case. Record acceptance and non-goals before work. |
| #270 — Stop serial CI repair loops | After three consecutive failures of one leaf, stop incremental fix/push cycles. Review all available failures, source assumptions, paths, selectors, formatting and resource costs together; make one reviewed repair commit and report the findings before resuming CI. |
| #271 — One owner and controlled repository state | At session entry, compare HEAD, latest checkpoint, actual executors and peer ownership. If another owner is active, do not launch work. Track dirty-file custody, code divergence and worktree disposition. |
| #272 — Keep gates and v1 distance visible | Collect human decisions early; retain legal/reference/public permissions. Audit worker execution restrictions. Start each checkpoint with the distance line and use 5–8 summary bullets. |

A task status, old lock, commit, watcher, or timer is not execution evidence.
Distinguish currently confirmed state from last-known state. Do not infer that a
native peer session is absent merely because Rush reports no live workers.

## Existing P09 acceptance boundaries

Each row is the one-line acceptance/non-goals record for the existing leaf.

| Existing task | Observable acceptance; non-goals |
| --- | --- |
| #267 — Normal SDK graph | The approved pinned dependency route builds and passes its existing normal/dev and source-bound checks on Linux and Windows, with independently verified exact-SHA receipts and delivery; excludes publisher acceptance, new proof infrastructure, version changes, public traffic, legal clearance and release acceptance. |
| #252 — Publisher | The actual SDK publisher passes the existing generation, refresh, withdrawal, cancellation, original-deadline and joined-cleanup contract cases on Linux and Windows and is delivered; excludes custom DHT/crypto, new public signer/configuration APIs, new transport features and dependency-only acceptance. |
| #261/#263 — Independent reference | A permitted authentic external fixed record with provenance supports the existing signed-record regressions; excludes self-roundtrip as interoperability, expanded retrieval/contact scope without permission, or invented reference bytes. |
| #253 — P09 integration | The accepted graph, publisher and required reference are composed through the existing SDK path and original runtime obligations, with reviewed delivery and cleanup; excludes treating one targeted dependency pass as complete P09 or v1 acceptance. |

### P09 acceptance record (2026-11-05)

Accepted source: `b076458` on `develop`. Evidence: targeted CI run `41975114042` over the whole
sprint diff (base `7810e1d`), green on Linux and Windows, with the locked normal SDK graph
(base58 multibase, no `base256emoji`) verified on both OS, 173 selected `shaar` library cases
executed per OS (selected equals executed; the only non-executed case is the privileged-uid
Ubuntu probe), the 2 graph witness cases and 6 base58 cases, and the mainline dependency
fixtures including the P5/P6 additions (CI run `41964477329`, 128 cases per OS). The seam
regressions P7, P10, P3, P4, P8 and P2 (`runtime/owner/seam_tests/`) and the dependency-level
P1, P5 and P6 coverage are listed in `crates/shaar/src/native_discovery/runtime/tests/README.md`.

Not established by this record: P10 path policy, Server/Client integration, Yggdrasil, public-network
behavior. Known limit: P7 covers both responder permutations, not a controlled datagram arrival
order; P2 deep-dives conflict and replay on one of the sixty-four slots. Shaar source-tree
transitions in `.github/probes/native-graph/fixture/features.py` are tied to the exact `shaar`
tree: any later change under `crates/shaar` needs fresh transition entries from the verification
evidence of both OS.

Observation outside P09: the explicit full campaign (`scope: full`) contains legacy segments
pinned to an older lock (for example the owned-DNS foundation baseline hash) and fails there
independently of P09. Two real defects found on the way are fixed (nested workspace root of the
prepared adapter in the carrier fixture copy; prepared path packages in the observation lock).
Repairing the remaining legacy segments is not scheduled; a full run is not part of this acceptance.

### P07 acceptance and non-goals (recorded 2026-11-05, before implementation)

Observable acceptance: in GitHub CI on Linux and Windows, `shaar-ygg` wraps the pinned
Yggdrasil-ng core (`c9a54f1587bb133a06072596484c972a336db0d2`, with only reviewed lifecycle
corrections) behind a safe Rust API; two instances with fixed test keys exchange authenticated
datagrams addressed by the 32-byte peer key over an owned loopback topology; start, stop and
repeated create/close leave no running task, no live strong reference to the core and no bound
socket (checked by observation, not by `close()` alone); queues are bounded with backpressure;
cancellation, concurrent sends/receives and malformed or oversize input have tested outcomes;
startup failures report a typed error naming the offending field without secrets.

Non-goals: public-network contact or exact public peers (still awaiting the user), TUN, root,
routes, services or the `tun`/`ckr`/`systemd` features, unsafe code, Go or FFI, custom crypto,
the upstream SIMD `salsa20` fork unless separately reviewed, version bumps beyond the pin,
path policy and blockade failover (P10/P13), any libp2p application data, and claiming
interoperability with deployed Yggdrasil nodes from owned fixtures.

Leaf 53.1 (prepared pinned source, isolated `shaar-ygg-core` crate) is accepted at `76b8491`:
Linux and Windows CI executed its two tests; the unpatched core links.

#### Leaf 53.2 acceptance and non-goals (recorded 2026-11-05, before implementation)

Advances scenario step 5 (Yggdrasil path from the same key). Observable acceptance: the
preparation step applies a reviewed, hash-pinned lifecycle patch to the `yggdrasil` crate only
(`ironwood` stays byte-exact), and the provenance receipt records original and patched hashes
of every changed file. In GitHub CI on Linux and Windows, tests in `shaar-ygg-core` create a
core, listen on a loopback port, then `close().await`; after it returns, the runtime's alive
task count reaches its baseline within a bounded poll, a retained `Weak<Core>` no longer
upgrades, and the same port can be bound again. The sequence repeats three times in one process.
Non-goals: key-addressed exchange (53.3), negative controls and typed startup errors (53.4),
an `ironwood` patch (the bounded poll covers its tasks; revisit only if the poll fails),
the adapter API, `start()`/`set_path_notify`, public network, unsafe, version bumps.

Leaf 53.2 is accepted at `630b264`: Linux and Windows CI executed the five `lifecycle` tests
(three create/listen/close cycles with alive-task, `Weak<Core>` and port-rebind observations,
concurrent and repeated close, two cores closed in both orders) and the pinned patched hashes
verified during preparation.

#### Leaf 53.2b acceptance and non-goals (recorded 2026-11-05, before implementation)

Independent review of 53.2 found that the `ironwood` encrypted reader can block `close()` while
it delivers into a full receive queue. Observable acceptance: one hunk-pinned correction of
`crates/ironwood/src/encrypted/mod.rs` (the delivery selects on the cancellation token), and a
CI test on Linux and Windows in which a listener that never reads is flooded by its peer and
still closes within a timeout with the alive-task count back at zero and its port free.
Non-goals: joining the other `ironwood` tasks, any other `ironwood` change, adapter API.

Leaf 53.2b is accepted at `63bcec5`: Linux and Windows CI executed seven `lifecycle` tests; a
throwaway control without the hunk failed the full-queue close test on both OS, the patched
run passed.

#### Leaf 53.3 acceptance and non-goals (recorded 2026-11-05, before implementation)

Advances scenario step 5. Observable acceptance: `shaar-ygg-core` exposes a safe `YggTransport`
(start from a fixed 32-byte seed with listen/peer URIs and an optional allowlist, `send_to` and
`recv` addressed by the 32-byte peer key, `mtu`, `close`) over the lifecycle-patched core. In
GitHub CI on Linux and Windows two transports on loopback exchange datagrams in both directions
by key, `recv` reports the sender's key, payloads of 1 byte, 1000 bytes and exactly `mtu` arrive
intact, `mtu + 1` is rejected with a typed `Oversize` before anything is sent, a receive buffer
below `mtu + 1` is rejected with a typed `BufferTooSmall`, concurrent senders deliver every
datagram of a gentle paced load, and a dropped `recv` future loses no datagram. Both transports
close with no task alive, no live core reference and a free port. Datagram semantics stay
unreliable by contract; the test load is paced, not a loss-free guarantee.
Non-goals: negative controls, the full typed startup errors, the per-key registry and
allowlist enforcement tests (53.4), key-to-address vectors (53.4), public network, TUN,
path policy, any queue added by the adapter, unsafe, version bumps.

Leaf 53.3 is accepted at `3396840`: Linux and Windows CI executed seven `exchange` tests and the
`closing_a_connected_pair_releases_both_cores` unit test next to the two smoke tests (receipts of
run `42033089403`). Open for 53.4: negative controls, full typed startup errors, per-key registry,
allowlist enforcement, key-to-address vectors.

#### Leaf 53.4 acceptance and non-goals (recorded 2026-11-05, before implementation)

Advances scenario steps 5 and 6 (the allowlist). Observable acceptance, in GitHub CI on Linux and
Windows: `YggTransport::start` validates its settings before creating a core and returns
`InvalidConfig { field }` naming only the offending field (`listen`, `peers` or
`group_password`) for blank, scheme-less, unsupported-scheme or whitespace-bearing URIs and an
empty group password, never echoing values; a second live transport with the same key returns
`KeyInUse`, the key is free again after `close()` or a failed start, and a repeated `close()`
cannot release a key another transport now holds; `send_to` and `recv` after `close()` return
`Closed`; with an allowlist on the receiver, a datagram from an allowed key is delivered while a
datagram from a non-allowed key that dials the same listener is not delivered within a bounded
window (observed non-delivery, not the enforcement mechanism); `address_for_key` returns the
yggdrasil-go v0.5.14 golden address for its published key and the documented edge cases of the
pinned core.
Non-goals: public network, path policy, a registry across processes, protocol fuzzing, extra
queues, unsafe, version bumps.

Leaf 53.4 is accepted at `efa5c62`: Linux and Windows CI executed 16 `lib` tests (validation,
key registry, address vectors, core release) and 13 `exchange` tests (run `42035672563`). The
first run (`42035009917`) failed because two tests shared one key pair, which the process-wide
key registry refuses; every test now has its own keys.

With 53.1-53.4 accepted, P07's technical acceptance is met for the isolated crate: the
adapter wraps the pinned, lifecycle-patched core behind a safe API (no unsafe), two instances
exchange datagrams by key on loopback, start and repeated close leave no task, core reference
or socket, queues are the core's own bounded ones, cancellation and concurrent use have tested
outcomes, and startup errors name only the field. Not claimed: interoperability with deployed
Yggdrasil nodes, public-network behaviour, the product-graph connection (P10) and the open
legal and notices items.

### P10 leaves (recorded 2026-11-05, after the independent design consult)

P10 advances scenario steps 3-6 and is split into six ordered leaves, each with one acceptance
criterion tested in GitHub CI on Linux and Windows with owned loopback fixtures only:
1. Deterministic path-policy contract (pure state machine, injected monotonic time).
2. Reviewed product linkage: `shaar-ygg` depends on the isolated `shaar-ygg-core` by path (the
   product lock, native-graph guard, license report and CI selection change in a reviewed way),
   with an authenticated-probe readiness bridge and joined shutdown.
3. Composition of discovery, native selection and signaling-only recovery.
4. Explicit Yggdrasil `signal`/`standby` authorization: payload over Yggdrasil only in `standby`,
   zero prohibited frames on signaling paths, zero target accepts for wrong or disallowed keys;
   exact-key authentication is kept on every route.
5. Product startup composition (Server/Client from the server key alone against owned discovery).
6. Composed recovery and efficiency acceptance (#215): p95 first byte, failover and direct share
   against the agreed criteria, measured with an in-process blockable native transport shim.
Defaults chosen by the engineer, open for the user to override: only new streams must recover
after a failover; an established TCP stream ends with its connection and is never replayed.
Virtual time proves policy deadlines, real loopback timestamps measure end-to-end latency.

#### Leaf 1 acceptance and non-goals (recorded 2026-11-05, before implementation)

Advances scenario steps 3-5. Observable acceptance: in CI, a table-driven event-trace suite for
the private module `crates/shaar/src/path/` yields exactly the expected decisions for both modes
(`signal` never selects Yggdrasil for payload; `standby` may), covering the first attempt, the
backoff schedule and its cap, attempt timeouts at the boundary millisecond, failover only after the
loss grace, switch-back only after sustained native success, stale and reordered generation- or
attempt-tagged events, duplicate evidence that must not restart a cycle, flapping inside the grace
and inside the hold, budget exhaustion and its refill, the loss of both paths, shutdown, and
rejection of invalid parameters. State is fixed-size and retries are bounded.
Non-goals: any I/O, wiring into Session or the binaries, the Yggdrasil dependency, performance
claims, schema or default changes, public network.

P10 leaf 1 is accepted at `6fa54f4`: Linux and Windows CI executed all 19 `path::` cases (16 event
traces with their hand-derived oracles and 3 parameter checks) inside the 192 `shaar` lib cases of
run `42046622007`. The first run failed on rustfmt layout only. An independent trace replay found
two defects before acceptance and both are fixed with regressions: attempt numbers are now unique
for the lifetime of the policy (a refill no longer lets a stale report cancel a new attempt), and a
late owner still learns that the budget is spent. Open: the source-bound native-graph transition
entries for the changed `crates/shaar/src` tree are refreshed only by a run that selects the graph
proof; this targeted run did not select it.

#### Leaf 2a acceptance and non-goals (recorded 2026-11-05)

Advances scenario step 5 (the product graph must contain the Yggdrasil path). Observable acceptance:
in CI on Linux and Windows the product workspace builds with the new locked closure, every
existing guard (native-graph proof, dependency license report and deny, structure, CI selection)
is green with reviewed changes only, and a test in `crates/shaar-ygg` starts two `YggTransport`s
through the product crate on loopback, exchanges a datagram by key and closes with no task left.
Non-goals: bridge readiness semantics, any use from `shaar`, payload paths, public network, new
crypto, version bumps beyond what the lock resolution forces.

P10 leaf 2a is accepted at `14680c2`: Linux and Windows CI (run `42079853285`) executed the
product test `product_link_tests::product_exports_exchange_a_datagram_by_key_and_release_everything`
and both `native_graph_witness` cases, and the native-graph proof accepted the candidate. The
change set: `shaar-ygg` depends on the nested `shaar-ygg-core` by path; the product lock is the
CI-resolved candidate (+33 packages, no removals); `deny.toml` allows MPL-2.0 only for
`ironwood@0.2.1` and `yggdrasil@0.3.1` (user decision 2026-11-05) and the license receipts list
the Yggdrasil provenance; the graph proof is selected when the two linking manifests change; the
format step covers workspace members only because `cargo fmt --all` also formats path
dependencies. Guard change (reviewed by the independent design consult): workspace crates are
identified by name and version, so per-tree transition tuples are no longer needed after every
source edit (raw bindings stay in the proof digest), and `fixture/baseline/ygg_closure.py`
declares the exact closure read from the evidence of both operating systems; the control
comparison requires the candidate to embed every control package, unit and dependency and rejects
anything outside the declaration. The path to acceptance took five failed runs: three mechanical
(selection tests, format scope, an unowned workflow file), the expected guard stop that produced
the evidence, and one obsolete test of the removed tuple policy that the first guard commit
missed. Open: the licenses of the new registry crates were accepted by the existing allow list;
notices (#72/#73) remain.

#### Leaf 2b acceptance and non-goals (recorded 2026-11-05, before implementation)

Advances scenario step 5 (the Yggdrasil path must report real readiness before it is used).
Observable acceptance: in CI on Linux and Windows, `YggBridge` in `crates/shaar-ygg` over a real
loopback `YggTransport` (1) reports a peer ready only after an authenticated round trip: a probe
with a fresh nonce is answered by a served peer with the same nonce from its own key, and the
time until that reply is returned; (2) never reports ready for a key outside the served set, for a key
nobody runs, or when the reply comes from another key even with the right nonce; (3) ignores and
counts malformed frames and keeps serving; (4) bounds waiting probes (`MAX_PENDING_PROBES`) and
removes a cancelled probe at once; (5) `close` joins the owner task, releases every waiting probe
with `Closed`, is idempotent, leaves no task alive and frees the port. The frame codec and the
pending table have pure unit tests with boundary and mutation cases.
Non-goals: payload over Yggdrasil, `signal`/`standby` authorization, use from `shaar`, path policy
wiring, public network, new crypto (authenticity comes from the Yggdrasil session key), version
bumps. The only guard data change is the declared `shaar-ygg` -> `tokio` normal edge.

P10 leaf 2b is accepted at `3248a6a`: Linux and Windows CI (run `42088053558`) executed 16
`shaar-ygg` lib cases each (8 bridge integration tests on real loopback transports, 4 frame and
3 pending-table unit tests, and the product link test) and both `native_graph_witness` cases;
nothing was ignored. It passed on the first run. An independent pre-flight review before the run
led to a fix of the repeated `close` path, a per-kind oracle for the garbage test, a longer hold
in the capacity test and a let-chain for clippy. The only guard change was the declared
`shaar-ygg` -> `tokio` normal edge (the lock already listed `tokio`). Not claimed: payload over
Yggdrasil, interoperability with deployed nodes, behaviour of a second core `close` (the bridge
no longer calls it twice), and any path-policy use of the bridge.

#### Leaf 3 plan and leaf 3a acceptance (recorded 2026-11-05, after the independent design consult)

Leaf 3 composes discovery, native selection and signaling-only recovery as a crate-private
coordinator, `path/owner.rs`, that the caller polls (one owner, no detached task). It is split in
three: 3a resolve and direct dial under the policy (scenario step 3), 3b native loss, grace,
bounded retries and recovery on the same address (step 4, native half), 3c signaling-only
negotiation during the down window (step 4, recovery half). Engineer defaults, open for the user
to override: the whole of leaf 3 stays crate-private (binaries define the public surface in leaf 5);
the signaling address of the server comes from a constructor hint, not from the published record
(the record profile accepted in P09 is not changed); a failed resolve counts as a failed attempt;
`Mode::Signal` only (`standby` and Yggdrasil payload are leaf 4); the production adapter for
`NativeDiscoveredEndpoint` is written in the startup leaf, 3a uses a test-only adapter so no P09
item changes its dead-code status.

Leaf 3a observable acceptance: in CI on Linux and Windows (1) table tests with a scripted dialer
under paused time show that the owner dials at the instants the policy schedules (first at once,
then after 500, 1000 and 2000 ms), gives every dial the policy's attempt deadline, maps failure
and hang to a failed attempt, stops after exactly `max_attempts`, resumes after a cancelled call
without a duplicate attempt, tells the policy about shutdown before dropping the link and joining
the dialer, rejects invalid parameters before any dial, and returns immediately without another
dial when native payload is already available (both before and after the stable-hold horizon);
(2) one loopback test resolves a
signed record for the server key from the owned Mainline fixture, dials the published address
with exact-key QUIC through the owner, reports native as the payload path, forwards exact bytes
both ways through the fixed target, and after the joined close leaves no task and frees both
native ports.
Bounded test-oracle repair: cancellation and invalid-record socket regressions use the existing
controlled clock with records signed at that same fixed wall time. Their real Mainline and QUIC
paths and rejection/positive controls remain intact; system wall-clock adjustments must not
masquerade as cancellation or record-validation failures. Acceptance requires both regressions
and the new owner cases to execute on both operating systems. Existing deliberate clock-fault
regressions remain unchanged. The original Windows failure discarded the retry result, so its
cause is unconfirmed; later green diagnostic runs are not claimed as a cause-level repair.

Non-goals: loss monitoring, signaling, Yggdrasil, address churn, binaries, public API, new
dependencies, `policy.py` changes, any change of the P09 production code.

#### Leaf 3a accepted; leaf 3b acceptance (recorded 2026-11-05)

Leaf 3a is accepted at `780d7b6`: CI `42111786584` executed 139 selected SDK cases on each
operating system, including nine paused-time owner contracts, the resolve-to-forward composition
and both controlled-clock oracle regressions. The exact tested revision is on `develop`.

Leaf 3b advances scenario step 4 (native recovery only). Observable acceptance: in Linux and
Windows CI, a caller-polled private owner observes closure of the active native session, removes
its payload, observes the configured loss grace and bounded retry schedule, and restores a new
native payload after a successful dial. Paused-time contracts cover the grace boundary, failed
and hanging attempts, exhaustion, stale loss generations, cancellation/resumption and shutdown.
A controlled loopback scenario closes the actual peer session, then reconnects by the same key
and address and forwards exact bytes on a new stream. Existing streams are not migrated.
Non-goals: signaling, Yggdrasil, address churn, binaries, public API, new dependencies, public
network execution, efficiency-profile acceptance, and changes to the record or clock policies.
All dirty files in this leaf's worktree are held by the primary executor until reviewed transfer.

#### Leaf 3b accepted; leaf 3c acceptance (recorded 2026-11-05)

Leaf 3b is accepted at `60b5e25`: CI `42117935856` executed 150 selected SDK cases on each
operating system, including ten paused-time recovery contracts and the real same-address QUIC
recovery scenario. Only new streams recover; transferred branches and worktree were removed.

Leaf 3c advances scenario step 4 (signaling-only recovery). Observable acceptance: Linux and
Windows CI show a caller-polled private owner recovering native payload after actual peer loss,
with a real authenticated signaling negotiation in the down window and exact bytes forwarded on
a new native stream. Custom/relay paths carry zero application STREAM and DATAGRAM frames in
both directions, including when the same authenticated connection gains a native path. A delivered
byte requires native STREAM transmit and receive counters, not merely the presence of an IP path.
Healthy native paths never negotiate. Failed or hanging negotiations still allow the native phase
of every uncancelled policy attempt, respecting the original absolute deadline,
backoff and total attempt budget. Scripted paused-time tests pin phase ordering, deadlines,
cancellation/resumption, exhaustion and joined close; socket fixtures pin exact peer keys and
joined resource release. The same test-only negotiation composition is used by both fixtures.

Engineer default: during the down window only, best-effort negotiation receives at most half
the remaining attempt budget; success, error or timeout all proceed to native dialing under the
original deadline. Failed/hanging signaling can therefore consume roughly 1.5 s of the default
3 s attempt, leaving roughly 1.5 s for native; this is a bounded latency tradeoff, not a promise
that every native dial fits. No new policy parameter is added. The control Session closes before
the native dial; it never becomes payload. The signaling address remains a constructor hint.
Only recovery after an observed session loss negotiates here; initial-establishment failures do
not. The frame oracle uses permitted bidi streams, confirms local write admission, retains the
response half during observation, and checks exact per-path counters on both sessions. It
subscribes to lifecycle events before the initial snapshot, checks open-path samples and final
`Closed` statistics, and fails on lost events. Checks continue through the native positive control
and joined shutdown. Uni streams are disabled and cannot prove this boundary; stream-control
metadata alone is not application data. Unexpected accept/read errors still fail.

Consolidated repair after three CI failures (2026-11-06): `42125979299` rejected stream metadata
without reading bytes; `42128744822` read byte `110` on a connection initially custom-only;
`42135358768` reproduced that byte while the first 32 predicate samples denied mapped tuples
(570/578 callbacks in total). These observations did not attribute the byte to its egress path.
Pinned source DATA and independent review established that default QNT/multipath can promote
the connection to native after the initial snapshot. Prefix, config-wrapper and default-receive-
address hypotheses were refuted by the pinned source; no product predicate change is justified.
The three-failure stop was applied before this single reviewed test-oracle repair. It requires
zero custom/relay APP counters, accounts for closed paths without event loss, and permits a byte
only with native tx/rx STREAM evidence. Temporary tuple diagnostics are removed. Actual native
promotion and zero signaling APP counters remain next-CI obligations, not claims from source
reading. The production filter, networking policy, dependency transforms and CI selectors remain
unchanged; no sampled-IP-existence shortcut or endpoint split is used.

Non-goals: production startup wiring, discovery and signaling in one endpoint, policy/owner
semantics changes, relay routing, Yggdrasil/standby, address churn, record/clock changes, public
API, new dependencies, stream migration, public network and efficiency-profile acceptance.

#### Leaf 3c accepted; leaf 4 plan and 4a acceptance (recorded 2026-11-06)

Leaf 3c is accepted at `ff5e609`: CI `42141894144` selected and executed the same 65 cases on
each operating system, including eight paused-time negotiation contracts and three real socket
scenarios. Exact custom/relay zero-APP frame invariants passed through joined shutdown. Prior
byte observations did not identify their carrier; the per-path oracle corrects that distinction.

Leaf 4 advances scenario steps 5–6 in three ordered pieces: 4a binary-transparent datagram demux
in the single bridge reader; 4b an existing reliable stream transport over Ygg with ownership-bound
APP admission; 4c standby policy failover and exact forwarding to the fixed TCP target. A raw
unreliable datagram exchange is not acceptance of reliable service forwarding. The current
`fn(FourTuple) -> bool` callback has no carrier identity: 4b must resolve that authorization boundary
before implementation, without inferring authority from opaque custom addresses or their prefix.

Leaf 4a observable acceptance: Linux and Windows CI use real controlled loopback cores to show
that peer-registered capabilities deliver exact enveloped bytes, including empty, binary and
probe-shaped payloads, independently of readiness probes; unknown/unregistered peers and malformed
frames never reach a capability. A full bounded receiver drops and counts carrier datagrams
without blocking probe replies. Dropping a capability revokes its cloned senders and queued receive
state; re-registering the same peer creates a fresh queue, while unrelated peer capabilities remain
usable. Registration cancellation, deadline, duplicate and capacity boundaries are exercised;
close revokes capabilities, wakes receivers, joins the one reader and transport, releases the key
claim and socket, and can resume after cancellation. All accepted readiness tests remain selected.

The bridge does not decide APP modes: these datagrams may carry QUIC control as well as data.
Only the caller can register a peer, and incoming identity comes from the authenticated Ygg session,
never from envelope bytes. Bounds: 16 live peer registrations, 16 queued datagrams per peer,
16 admitted registration requests, and 16 simultaneous framed sends per bridge. Admission is
non-queued and precedes send-buffer allocation. Probes do not consume the carrier-send budget.
The owner task alone maintains the registry; normal operation and shutdown use the existing
reader task only. If that reader fails,
close may replace it once with a retained cleanup task (never a concurrent reader); cancellation
retains the join, and a failed cleanup returns an error instead of spawning again. A delivered
datagram owns one buffer copy from the shared receive scratch buffer; allocation happens only
after authorization and queue admission.

Carrier envelope: `shaar-qg` (8 bytes), version 1, kind 1, unsigned 16-bit little-endian payload
length, then exactly that many bytes; overhead is 12 bytes. Payload size is bounded by both the
length field and `mtu() - 12`. Unknown versions/kinds, truncation and trailing bytes fail closed.
Existing `shaar-yg` Ping/Pong frames stay byte-identical. Fresh registration isolates local queued
state, not already-transmitted datagrams; later QUIC connection identity rejects stale packets.
Minimal inter-crate methods/types are justified by the sole-reader boundary (`publish = false`),
not a new public SDK mode. Replace `bridge.rs` with a responsibility-scoped `bridge/` module to
keep the seven-item root limit; existing module names and probe tests remain intact.

Non-goals of 4a: reliability or TCP forwarding, QUIC/iroh integration, APP authorization, signal/
standby policy, the `shaar` crate, new dependencies, configuration/schema or version changes,
public peers, TUN/root, release and efficiency acceptance. Full leaf 4 remains open until 4c.

### P10 leaf 4b: reliable Ygg carrier (acceptance recorded 2026-11-06)

Advances scenario step 5. Leaf 4a is accepted at `89ae91b`: CI `42155387218`
selected and executed 32 cases on each operating system (16 existing, 16 new).
Its datagram capability is not reliable-stream or fallback acceptance.

Observable acceptance: controlled Linux and Windows CI uses two real loopback
Ygg cores, with the same Ed25519 seed for each core and its TLS endpoint, to
transfer and echo an exact multi-packet payload through the existing SDK Session
and ALPN. Each endpoint has only its locally owned Ygg custom factory attached,
no native IP transports and no bound UDP sockets. Current registration source
attestation must match the authenticated TLS peer, and the SDK allowlist must
permit that peer before a Session is granted. Per-path STREAM transmit/receive
statistics must positively attribute the payload to Ygg; every other path carries
zero application frames. The oracle includes closed-path final statistics and
fails on lost lifecycle events. Shutdown drains QUIC while the carrier is live,
then revokes registrations, stops and joins its writer, and finally closes the
caller-owned bridge, releasing its key claim and loopback ports.

Ownership boundary: `shaar-ygg` supplies the factory and a caller-driven pump;
the private SDK endpoint reuses Session admission, permits and stream handling.
Factory attachment borrows the existing bridge: runtime local-key mismatch fails
before registration and never consumes an unclosed core. Internal polling/status
helpers must preserve the existing capability's closed/revoked checks. Neither a
custom-address TYPE nor a mapped IP prefix grants authority. A mapped-custom-only
APP predicate is merely a fail-closed egress guard on this exclusively owned
endpoint; existing native/libp2p admission remains unchanged.

Bounds and trade-offs: retain the 16-registration capability limit, with a clear
error rather than silently truncating a larger configured peer set. The general
SDK allowlist remains bounded at 256; this leaf does not reduce its contract.
TX admission has 32 packet slots and 64 distinct waiter slots, with wakeups on
drain and close, no lock across await and no hidden detached writer. Each queued
packet owns a copy because the QUIC callback lends its buffer only for that call;
the existing datagram API then frames it separately. A fixed binding vector keeps
storage small: address-index attestation is O(1), key lookup scans at most 16
bindings, and receive polling visits at most 16 receivers per call. RX never
exposes the raw private capability receiver. Default GSO is one segment; invalid source,
oversize and unsupported segmentation fail explicitly, and empty RX metadata
must not have a zero stride. Additional normal dependency edges are limited to
already locked `iroh` 1.3.0, `iroh-base` 1.3.0, `n0-watcher` 1.0.0 and `noq-udp`
1.3.0. Update only the corresponding lockfile root edges and exact existing
native-graph metadata/unit edge declarations; no blanket graph allowance.

Minimum verification covers the real reliable-stream scenario, runtime own-key
and source/TLS mismatches, allowlist denial, foreign/unknown/revoked addresses,
capacity and constructor cancellation, TX backpressure and distinct waiters,
RX boundaries and revocation, writer failure, and cancellation-resumable joined
close. Written tests are not executed evidence. Compare actual CI selection and
execution receipts; unchanged 3c tests run only when selected or during full P10
acceptance, never by assumption.

Non-goals: 4c standby policy/fixed-TCP failover, binary startup (leaf 5), efficiency
acceptance (leaf 6), new public SDK API or ALPN, dynamic peer-management features,
new packages or versions, new probe/CI families or selection entries, record or
clock changes, configuration/schema knobs, public peers, TUN/root and release.
Full leaf 4 remains open until 4c.

### P10 leaf 4c: standby forwarding (acceptance recorded 2026-11-06)

Advances scenario steps 5 and 6. Leaf 4b is accepted at `53ce7b7`: CI
`42204370310` selected, executed and passed the same 69 cases on each operating
system (25 SDK admission, 2 graph witnesses, 42 Ygg). Both native-graph checks
passed. This is targeted leaf acceptance, not full P10 or efficiency acceptance.

Observable acceptance: controlled Linux and Windows CI first forwards exact TCP
bytes in both directions through the native SDK Session, then makes the real
native endpoint unavailable while retaining the independent Ygg core/carrier.
The runtime owner observes actual native loss and, after the existing loss grace,
selects an authenticated Ygg Session in `standby`; a new local TCP connection then
reaches the same fixed loopback target through existing Session forward/serve.
Per-path STREAM evidence positively attributes that transfer to the owned Ygg
carrier, with no application frames on libp2p and no native promotion masking the
fallback. Restoring the native endpoint permits bounded recovery attempts while
Ygg remains usable; new TCP forwards return to native only after the existing
stable hold. Both transports use the same Ed25519 identity. A forbidden client
never receives a serving Session and causes zero new target TCP connections.
The corresponding `signal` case may negotiate/probe through Ygg but never grants
Ygg payload or forwards application bytes through it. Every owned forward/server
worker, endpoint, pump and bridge is stopped and joined in dependency order, with
key claims, admission charges and listener ports demonstrably released.

The existing pure PathPolicy owns selection, generations, grace, hold and retry
budgets; do not create a second switching algorithm. The current runtime owner
only owns one native link and hardcodes Signal, so a pure-policy trace or a manually
chosen Ygg Session alone cannot satisfy this leaf. Wire actual readiness/loss and
policy decisions to held SDK Sessions. Pending native retries must not hide an
already usable Ygg payload or be recreated on every timer observation. Announcing
a route change must not itself cancel an otherwise valid pending native attempt.
A healthy Ygg TCP forward must not monopolize the owner: recovery and selection
for a new native forward must progress while that Ygg forward remains open.
This clarifies the required usable-fallback-during-recovery boundary, not stream
migration. Preserve accepted native-only and signaling behavior. In-flight TCP streams are not
transparently migrated or replayed; this criterion checks selection for new TCP
connections and promises no seamless survival of an already failed stream.

Minimum verification: real native/Ygg/native TCP transfer with explicit target
accepts and exact bytes; signal-mode denial; denied-client zero-target evidence
with a positive target control; native recovery inside grace, stable-hold boundary,
Ygg loss/recovery, both paths unavailable and exhausted native budget; stale and
simultaneous loss/readiness observations; cancellation during dial, forwarding and
close; capacity/backpressure and idempotent joined shutdown. Timer/interleaving
contracts may use paused-time fixtures; real transport cases must use actual
owned loopback endpoints and event-driven observations, not merely a boolean
fake dial failure. Controlled native endpoint shutdown proves unavailability;
it must not be described as a public-network or packet-filter blockade test.
Keep loss, exhausted native retries and total payload unavailability distinct.

Bounds/non-goals: retain existing policy defaults, Session/stream/admission and
carrier limits; no unbounded retry task, waiter, queue or retired-session growth.
No public SDK API, new ALPN, configuration/schema knobs, new package/version,
new protocol/probe/CI family, DHT/record/clock redesign, public peers, TUN/root or
release. The existing CI impact map may gain only the narrow ownership needed by
new component tests; do not replace targeted selection with a full workspace run.
A responsibility-based module split is allowed where the seven-item or 700-line
limits require it. Binary startup/discovery composition remains leaf 5; p95 and
full P10 acceptance remain leaf 6. Do not claim those from this functional case.

### P10 leaf 5: shared startup (boundary recorded 2026-11-07)

Advances scenario steps 1–6. Functional leaf 4c is accepted at `056a52d`: CI
`42223907072` selected, executed and passed the same 97 cases on Linux and Windows,
including 20 standby-owner cases, five standby fixture cases, constructor-refusal
cleanup and the existing signaling-only contracts. This is not full P10 or
performance acceptance. Current application entry points still bind direct-only
endpoints; the Client requires the otherwise optional `server_address`, and the
Server rejects standby. Component acceptance does not close this startup gap.

Bounded delivery follows three sequential parts, each with its own verification:
5a settings/preflight and identity-safe Ygg start; 5b shared resource composition;
5c role loops used by both binaries and combined key-only acceptance. No part alone
is completed leaf 5. The split isolates configuration/secret handling, resource
ownership and application integration rather than creating unrelated product work.

Combined observable acceptance: both binaries and controlled CI enter the same
shared production startup path. A client configured with the server key and only
independent infrastructure destinations, with no `server_address`, reaches the
fixed loopback TCP target with exact bidirectional bytes. Healthy discovery proves
real signed Mainline publication and lookup; known-relay key-directed signaling
proves native APP delivery and zero APP on relay/custom signaling paths. Standby
also works when Mainline is unavailable, through a separately owned third Ygg
transit core; the client must not receive the service server's native or Ygg TCP
address disguised as bootstrap configuration. Signal permits authenticated Ygg
control readiness but no Ygg payload. Forbidden keys cause no target connections.
Shutdown finishes workers and retained backend operations before releasing owners.

Composition owns one native SignaledEndpoint, one separate Mainline RuntimeOwner,
and the separate same-key Ygg bridge/custom-only endpoint/pump when applicable.
Do not bind NativeDiscoveredEndpoint beside SignaledEndpoint or invent a second
switching algorithm. Both role loops reuse Session forwarding/admission and the
accepted path policy; the non-Send controller stays inline, and bounded workers
receive owned route leases. No public raw endpoint or seed accessor is needed.

Wildcard binds remain valid. Reuse the real endpoint's existing addr/watch_addr
machinery through a narrow internal snapshot/watcher seam, not new interface,
STUN or public-address probing. Only native IP candidates pass unchanged P09
validation, with at most four addresses. Subscribe before the initial read;
coalesce updates instead of queuing them unboundedly. Empty, invalid or over-cap
snapshots must not silently leave obsolete publication active. Explicitly stop
this work at shutdown: closing an endpoint need not disconnect its watcher.
An observed local address is not proof of public reachability.

Operational backend outages and invalid startup configuration are different.
Do not make successful Mainline publication or reachability of every network a
prerequisite for serving through an available alternative. Readiness must say
whether publication succeeded, is pending or is unavailable; never claim a signed
publication that did not complete. Mainline failure must not globally kill a usable
Ygg/relay path. Operations, retries and status storage remain bounded. Fatal
configuration/identity/startup errors roll back acquired owners, and cleanup of
other backends is attempted even when one close fails.

#### 5a acceptance: settings and identity-safe startup

Before network I/O, pure parsing/preflight accepts valid shared infrastructure
settings and rejects missing, malformed, oversized or conflicting settings with a
field-specific diagnostic that does not echo secrets. Legacy configuration text
without a network object remains parseable, but composed startup requires its
infrastructure fields rather than silently using the old direct-only path. Add
one optional shared network object to the existing ktav 0.8 schemas, retaining
unknown-field rejection and the optional direct-address hint.

The necessary settings are Mainline IPv4 bind (default wildcard/ephemeral) and
1–4 numeric IPv4 bootstrap destinations; signaling TCP bind (default wildcard/
ephemeral), one pinned relay identity and numeric destination; and 1–4 bounded Ygg
infrastructure peer URIs. Service nodes initiate Ygg peering; no service-listener,
group-password, DNS-resolver, policy-timing or raw-seed knob is needed. Validate
supported URI syntax before networking, not by trying connections. Composed
startup admits at most 16 raw application-peer entries, matching signaling;
reject overflow before binding without deduplication/truncation to evade the cap.
Generic SDK Allowlist retains its separate 256-entry contract. Infrastructure
identities do not become application peers.

An internal Identity-to-Ygg-start operation uses the same Ed25519 seed without
exposing it publicly, with zeroizing staging and best-effort erasure of temporary
seed-bearing configuration on success, error and cancellation. Audit the actual
callee's ownership, not just a caller-side clone. Controlled CI checks identity
equality, redacted diagnostics, invalid-input paths, retained startup/cleanup and
same-key/port reuse. No claim is made about erasing copies inside reviewed external
cryptographic dependencies. Only an essential edge to an already locked package
(such as zeroize) may be added with a recorded reason and narrow graph review;
there is no package/version bump or general graph-policy exception.

5a non-goals: networking role loops, publication/address watching, relay reservation,
three-core transit forwarding, binary behavior changes, native-budget rearming,
new Session/protocol/ALPN, full P11/P12 or P10 acceptance. Those composition cases
belong to 5b/5c. All parts forbid local builds/tests/Cargo/project Python/dependency
preparation/smoke/benchmarks and public-network execution; actual verification is
GitHub CI. No TUN/root, router changes, n0 infrastructure or release. Keep normal
CI ownership narrow for new modules; add no proof/CI family or full-workspace
fallback. Public-peer execution still needs its separate exact-target/budget gate.

5a accepted at `a7c241c09d80cf0661ef1fba333a841d6978c7e8`: targeted CI
`42406735980` passed on Linux and Windows. Inventories and run logs matched
355 executed and passed cases per OS: SDK 294, graph witnesses 2, Ygg adapter 42,
core 17. This includes 38 new SDK cases and the added core case. Linux also lists
one pre-existing ignored privileged identity-reader test; it was not executed or
counted in 355. The exact green revision was delivered upstream and its task
worktree and branches were removed. This closes only settings/preflight and the
retained same-key start, not shared resource composition or binary readiness.

#### 5b acceptance: shared resource ownership (recorded 2026-11-07)

Advances scenario steps 1 and 3–5. The same production constructor, usable by
both later role loops, acquires one native SignaledEndpoint, a separate Mainline
runtime, and applicable same-key Ygg resources from the accepted settings and
preflight. It must not acquire a second native listener. Controlled CI observes
that the server's signed publication uses validated IP candidates from that actual
endpoint, including wildcard binds; an independently owned resolver obtains the
published snapshot. Infrastructure destinations must not conceal a service-node
address. Relay and third-core Ygg infrastructure remain independently owned.

Address maintenance subscribes before its initial read, bounds candidates by the
unchanged P09 limit of four, coalesces to the latest snapshot, and explicitly stops
before endpoint close. Empty, invalid or over-cap updates cannot silently remain
reported as current published addresses. Specify the actual P09 publication and
expiry semantics from source before implementing withdrawal; stopping local
refresh is not proof that previously distributed DHT data vanished immediately.
Readiness distinguishes pending, successful publication and unavailable discovery.
Operational Mainline failure must leave an otherwise usable alternate transport
owned and available, not fail the whole composition.

Written lifecycle cases must exercise the production owner: fatal-start rollback,
cancellation during admitted startup and shutdown, retained joins, repeated close,
cleanup after one backend failure, and reuse of identities and listening ports.
All resources and maintenance work are bounded, errors are redacted, and cleanup
attempts the remaining owners even after an earlier error. Use the accepted 5a
retained-start ownership operation rather than moving a raw running transport
through a cancellable asynchronous handoff.

Source consultation confirmed that P09 withdrawal revokes the local generation,
cancels superseded PUT work and stops refresh; empty replacement signs no packet.
The existing refresh interval is 60 seconds, signed DNS TTL/cache cap 30 seconds,
and accepted signed age up to 300 seconds. Preserve those contracts: a remote
lookup may still accept an older record after local withdrawal. Generation-aware
current-publication readiness therefore needs a bounded observation seam for
actual initial PUT and refresh outcomes in the existing publisher; one old
acknowledgement is not an indefinitely current readiness receipt. A later stale
completion must not restore the current-generation claim. No tombstone or new
wire format is introduced. An empty application-peer set must not be padded with
a fake peer to satisfy the carrier: keep applicable Ygg control ownership and
defer payload endpoint acquisition until a nonempty authorized set is available.

5b non-goals: application role loops, binary changes, combined key-only TCP
acceptance (5c), native retry-budget rearming, performance or full P10 acceptance,
Amino application-peer lookup, new probing/proof frameworks, public reachability
or public-peer execution. No local builds, tests, Cargo, project Python,
preparation, smoke or benchmarks; verification is GitHub CI. Source-grounded
interface consultation precedes implementation where ownership or publication
semantics are not established; name a concrete blocker rather than weaken this
boundary or invent backend APIs.

#### 5c acceptance: shared production role startup (recorded 2026-11-08)

Advances scenario steps 1–6 after accepted 5b (`20b601c`, CI `42498359015`,
241 selected/executed/passed SDK cases on each OS; targeted, not full P10).
Both Server and Client binaries use shared production startup and role loops,
with accepted network settings and retained 5b resources. The client needs only
the server identity as its service locator; infrastructure addresses identify
independent Mainline/bootstrap, pinned signaling relay and third Ygg transit,
never a hidden service endpoint. Do not require a legacy server address, reject
an otherwise supported fallback as unimplemented, or silently choose direct-only.

Controlled Linux/Windows CI exercises those same production entrypoints: cold
Mainline lookup of a real signed native publication and a forwarded TCP byte;
key-directed negotiation through the pinned relay, native application data and
zero relay application data; Mainline outage with a same-key Ygg standby path
through independent transit; Signal mode with no Ygg application payload; and
a disallowed key causing zero fixed-target connections alongside an allowed
positive control. The server applies one shared bounded admission limit across
paths before forwarding. The client keeps the existing path policy and owned
leases driven while bounded forwarding workers run; no stale path-only snapshot
may replace ongoing policy work. Existing direct-address compatibility remains
explicit rather than becoming the key-only test's undisclosed bootstrap.

Startup, partial rollback and joined shutdown retain acquired owners across
cancelled waiters and expose truthful errors/readiness. Cover cancellation,
capacity, idle policy progress, both fallback modes and cleanup with actual
resource release; reuse existing fixtures and observers instead of a new proof
framework. Small CI ownership mappings are permitted only for new owned source
paths and their actual cases; no full-workspace fallback or new CI family.

Non-goals: complete P11/P12 acceptance, retry-budget rearming (task 32), transition
gap review (33), efficiency/full P10 (25), Amino application-peer lookup, protocol
redesign, public reachability, public-peer traffic, TUN/root or release actions.
No dependency/version changes. No local builds, tests, Cargo, project Python,
preparation, smoke, benchmarks or fake load; verification is GitHub CI. The
criterion and this plan block are primary-owned and remain unchanged by workers.

### P10 acceptance order correction (approved 2026-11-07)

The user approved synchronizing the task list and plan with accepted evidence and
making late native recovery a prerequisite of P10 acceptance. The north-star goal,
balanced efficiency thresholds and existing public-network permission gates do
not change. Work already underway on 5a keeps its recorded boundary.

Remaining order: 5a settings/identity -> 5b shared resource ownership -> 5c actual
binary role loops and key-only startup -> native recovery after retry exhaustion
-> transition evidence gap check for #215 -> balanced metrics and full P10
acceptance -> complete P11/P12 acceptance -> P13 through P16.

The late-recovery case must use the normal retry budget: native is unavailable
long enough to exhaust it while Ygg continues forwarding; native then returns,
is rediscovered with bounded resource use, and carries new connections after the
stable hold without restarting the application. A healthy old Ygg forward remains
independent; no migration or replay is introduced. Specify the renewed-attempt
contract before changing it, preserving bounded active work, backoff, shutdown
and protection against a retry flood. Increasing the fixture budget, shortening
the outage to retain attempts, or omitting the case from direct-share measurements
does not satisfy acceptance. The currently accepted finite-budget implementation
is not evidence that this recovery behavior already exists.

The former broad native/signaling/Ygg task for #215 becomes a finite evidence gap
check before metrics, not another implementation project after P10. Map its
contracts to existing case identities, selected/executed receipts and the new
startup/recovery evidence. Add tests or repair code only for a concrete uncovered
case; stop when the required evidence is sufficient. Do not add a proof framework,
CI family or full-workspace fallback to repeat already accepted component work.

Keep proof levels separate: targeted component acceptance; actual binary key-only
startup through the shared production path; agreed efficiency plus full P10 on
its current tested SHA; the expanded P13 fault/NAT/packet-filter matrix; and
separately gated public interoperability. None substitutes for the next. Missing
proof remains explicit, and an observed failing case is repaired in its owning
work rather than hidden behind an unrelated green run.

Do not expand a leaf beyond its recorded criterion. Pause and identify the actual
scope/dependency boundary before any split. No new product leaf is authorized by
this document while P09 remains open. Once native P09 and its applicable address
integration dependencies are accepted, proceed to existing permission-gated P07,
then start #214 after #33/#34 acceptance rather than another research or proof
campaign. P10, P13 and P16 must retain their P07 dependencies.

### Shared startup 5c accepted (2026-11-10)

Exact `8cbd2d7e2300bb6a2dcb619e1d4d31165208209b`, CI `42754605543`:
Linux and Windows each selected, executed and passed 411 cases (SDK 345,
Client 12, Server 12, Ygg adapter 42). One privileged-UID identity probe on
Linux was explicitly ignored and is not counted as executed. Primary compared
exact case inventories with execution events and receipts, delivered the exact
green revision upstream, preserved local decisions/checkpoints, and removed both
transferred startup worktrees and their task branches. This is targeted shared
startup acceptance, not full P10, efficiency acceptance or complete P11/P12.

### Late native recovery: task 32 contract (recorded 2026-11-10, before code)

Advances steps 3–5 after accepted 5c. In one running Standby composition, native
remains unavailable until the ordinary configured attempt budget is genuinely
spent while authenticated Ygg TCP forwarding continues. Native then becomes
reachable; a genuine renewed native dial discovers it, the configured stable hold
completes, and NEW connections use native without restarting the composition.
An already forwarding Ygg stream remains healthy on its owned lease: no migration,
replay or forced teardown. A manually injected NativeUp observation, a shorter
outage or an increased ordinary attempt budget does not satisfy this case.

Renewed-attempt boundary:
- Keep the normal finite attempt budget unchanged (default `max_attempts = 6`).
  Exhaustion is real and remains observable; do not silently refill that burst
  budget just because Ygg became ready or a caller re-entered `follow`.
- Only a Standby owner retaining a usable authenticated Ygg route may schedule
  post-exhaustion native maintenance. Use the existing `backoff_cap` as a retained
  cooldown: the first maintenance attempt starts no earlier than one cap after
  exhaustion; after a failed maintenance attempt, the next starts no earlier than
  its completion plus one full cap. At most one native attempt is active, with the
  existing `attempt_timeout`; no catch-up burst after a delayed poll.
- Maintenance permits continued recovery over an arbitrarily long outage; it is
  not a claim of a finite lifetime attempt count. It must use constant retained
  state and a bounded attempt rate, not accumulating epochs, tasks or buffers.
  Default cooldown is 4,000 ms and attempt deadline 3,000 ms. No new public mode,
  configuration field, retry multiplier or dependency is introduced.
- A successful native attempt still obeys `stable_hold` (default 5,000 ms) before
  new connections return to native. Only the existing genuinely stable recovery
  may refill the ordinary budget for a later down episode. Failed/unstable probes
  must not discard the healthy Ygg route or refill the burst budget early.
- Preserve distinct monotonic attempt/generation identities, stale-result
  rejection, original in-flight deadlines, and retained cooldown across cancelled
  waiters/re-entry. Shutdown stops future scheduling and joins acquired owners.
  Signal/no-usable-fallback owners retain their finite typed exhaustion behavior.

Observable regressions include deterministic policy/controller deadline, repeated
failed maintenance, cancellation/re-entry, stale completion and shutdown controls;
and a real controlled TCP-forwarding case using the normal budget, long outage,
held Ygg stream and eventual genuine native recovery. The full scenario has a
finite deadline derived from its configured attempt/backoff/hold and cleanup
bounds, with phase-specific diagnostics; no fixed sleep as a readiness oracle.
Required owners/responders stay driven, and the existing admission/capacity and
same-key authentication contracts remain intact. Keep the case available to the
later direct-share/efficiency campaign; do not exclude it to improve metrics.

Non-goals: task 33's full transition gap review, task 25's p95/full P10 campaign,
new protocol/transport/CLI, public peers, TUN/root/router changes, packaging or
release. No local builds/tests/Cargo/project Python/preparation/smoke/benchmarks
or fake load. Verification is targeted GitHub CI with exact selected/executed
receipts, then reviewed exact-green delivery and personal cleanup. The plan and
criterion are primary-owned; workers do not edit them.

## P10 finish correction (approved 2026-11-10)

Applies to #32 → #33 → #25, scenario steps 3–5. Preserve all acceptance
criteria, cumulative CI obligations and failure history. The primary owns this
plan; the live product executor remains read-only on both plan files.

Before each first push, the reviewer must record the following checklist with
source references, derived types and explicit unresolved items. A verdict without
this checklist is incomplete:
- Check each changed API call against exact pinned source, not memory.
- Derive closure, future, `join!` and `select!` types; trace borrows across await
  and the storage/drop boundaries of retained futures.
- Check `expect`/`allow` lint attributes in normal and test feature contexts.
- For every changed parser/oracle, inspect at least one valid and one invalid
  input, including a counterfactual that rejects the broken behavior.

This is source-level compilation-risk review, not proof of compilation. GitHub
CI must still establish compilation and execution on both operating systems.

Target the first CI on the day of first code. More than one day of uncommitted
leaf work requires immediate boundary reassessment. For #32, review the smallest
self-contained model/policy plus unit-test slice first; then production wiring
and fixtures in separate commits, with sequential CI in the same branch. Do not
stage incomplete dependencies, remove tests, discard existing work or rewrite
history to obtain the split. A slice is not full leaf acceptance. Required
integration cases remain obligations until executed on the final candidate.

Fixtures have an explicit review boundary: identity uniqueness, actual publication
barriers, continuously driven owners, deadlines and positive/negative oracles.
During #32/#33 retain monotonic observations for first forwarded byte (known
address and cold DHT), Ygg failover and actual selected data path. #25 reuses these
fixtures for p95 3 s / 10 s first byte, p95 10 s failover and at least 95% direct
share. Do not substitute one run for a distribution, omit failures from the
campaign or start a separate metrics framework. Keep the long-outage case.

Superseding owner decision on 2026-11-10: local cargo fmt and cargo clippy are
allowed, including necessary clippy dependency compilation and third-party
build.rs. Before each leaf push use the exact CI formatting checks for the six
owned packages and separate core manifest, plus offline, locked
`cargo clippy -p <affected-crate> --all-targets -- -D warnings`, with CI features.
The owner approved this fmt boundary after actual fmt-all reached 34 unformatted
pinned Ygg core files; retain its failed receipt and do not alter those bytes.
Pinned source preparation through existing CI prepare-only recipes and the exact
registry proposal recorded in north-star are separately authorized. No fallback
URLs, lock/version changes, test/check/fixture runners or unrelated project Python
are authorized. Standalone local build/test/check, smoke, benchmarks and fake load
remain banned. Report local clippy separately from CI execution and acceptance.
These decisions supersede older blanket Cargo/preparation bans below.

The first two delivery CIs found a real Windows cross-clock rate mismatch, not a
lint failure. The owner explicitly authorized 500 ppm for relative elapsed-time
deficit, while observed rollback, invalid/backward brackets, stalled clocks and
excessive deficit remain terminal. Exact integer comparisons and both adjacent
and fixed-lifetime-anchor checks prevent rounding accumulation and forward-jump
credit. Signed age 300 s/future 30 s and publication timestamp rules do not change.
Real Windows samples and below/at/above-bound controls must run in CI; local lint
or a diagnostic-only green does not accept the repair or late native recovery.

Notices remain primary-owned and off the P10 critical path: at most 20 minutes
of offline review per bounded pass, no new content workers, no new acquisition
without exact permission and no bypass of 404 responses. Missing terms and
provenance remain explicit; partial corpus is not legal clearance.

Executors write only their assigned worktree. A wrong-root write requires STOP
and disclosure, never executor restoration/deletion. Only the primary transfers
reviewed content. No repeat assignment to a boundary-violating executor without
an explicit worktree-only restriction. Preserve exact-green upstream delivery,
selected/executed receipts, personal cleanup and all public-network/release gates.

Aim for #32 acceptance within two CI runs and shorter delivery latency. These
are feedback signals, not correctness gates or permission to game feat/fix labels.
Three consecutive failures still require the consolidated-review stop rule.

## Transition evidence audit for #215 (2026-11-10)

Audit base: exact `2f844c072dca84b70e290be0442586d509949ae0`. The maintained
P10 leaf contracts and acceptance-order correction above define this check;
no missing external issue body is inferred from the historical #215 label.

Late native recovery is accepted at that revision: CI `42826919454` selected,
executed and passed 174 identical case identities on each OS, with zero ignored.
The kernel milestone `bab958d` / CI `42815929877` separately executed all 76
selected cases per OS, including ten new maintenance controls. The real role case
uses the unchanged default six-attempt budget and holds the same old Ygg TCP
stream across real exhaustion, delayed signed-record availability, a genuine
renewed native dial, the latest session's stable hold, and a successful new native
TCP forward. Actual worker leases must be exactly Ygg then Native; route history
alone is not the payload oracle. Admission order and joined release remain checked.
This is functional recovery acceptance, not efficiency or full P10 acceptance.

### Receipt and identity basis

Primary re-read the authentic libtest inventories, execution events and receipts
as inert DATA, without executing their contents or project verification scripts:

| Evidence | Verified execution per OS | Proof level |
| --- | --- | --- |
| 3a, `780d7b6`, CI `42111786584` | 139 SDK cases | Historical direct resolve/key/forward and owner acceptance. |
| 3b, `60b5e25`, CI `42117935856` | 150 SDK cases | Historical native same-key/address loss and new-stream recovery. |
| 3c, `ff5e609`, CI `42141894144` | 65 SDK cases | Scripted phase contracts and actual socket signaling zero-APP. Every one of these case identities is also executed in the current 174-case receipt. |
| 5c, `8cbd2d7`, CI `42754605543` | SDK 345, Client 12, Server 12, Ygg adapter 42: total 411 | Shared production-role composition, binary caller wiring and adapter contracts; not full P11/P12 or full P10. The separate two-case CI-runner self-test is not product evidence and is excluded. |
| Recovery, `2f844c0`, CI `42826919454` | 174 SDK cases | Current functional transition/auth/cancel/close evidence below, including all ten new maintenance controls. |

The Ygg adapter/core crates, root lock and reviewed backend/Ygg preparation
recipes are byte-unchanged between accepted 5c and this audit base. Their 42-case
component evidence is retained as unchanged-component proof, not relabeled as
fresh execution on this SHA. Current real owned-carrier/session tests supplement
it. Later source changes still require the final current-SHA full run in #25.

### Functional contract map

The literal libtest IDs below are present in the verified current 174-case set.
Rows name representative anchors; related boundary/interleaving cases remain in
the same receipt, rather than being inferred from a green job badge.

| Contract | Named case anchors | Boundary of the proof |
| --- | --- | --- |
| Key-only signed discovery, exact-key native and fixed-target bytes | `startup::tests::role_tests::location_cases::key_only_client_resolves_the_signed_publication_and_forwards_a_byte`; `network::admission::tests::wrong_pinned_key_cannot_authenticate_the_real_server` | Real owned discovery and QUIC; no server-address hint. Not public Mainline interoperability. |
| First dial, backoff, absolute deadline, finite Signal exhaustion and invalid config | `path::tests::owner::failed_dials_are_retried_on_the_backoff_schedule`; `path::tests::owner::a_dial_that_hangs_ends_at_its_deadline_and_the_next_one_waits_the_backoff`; `path::tests::owner::a_spent_budget_stops_after_exactly_max_attempts`; `path::tests::owner::invalid_parameters_are_rejected_before_any_dial` | Deterministic scheduling and typed outcomes, not latency distribution. |
| Native loss, grace, stable hold, stale evidence and refill | `path::tests::recovery::grace_expires_even_while_a_retry_dial_is_pending`; `path::tests::recovery::a_loss_at_the_hold_boundary_does_not_refill_a_down_path`; `path::tests::traces::stale_and_reordered_generations_cannot_undo_newer_facts`; `path::tests::traces::a_stale_attempt_report_across_a_refill_cannot_cancel_the_new_attempt` | Paused-time boundaries plus the real recovery compositions; old streams are not migrated or replayed. |
| Down-window signaling cannot carry APP or block native recovery | `network::admission::negotiation_tests::actual_down_window_negotiates_then_restores_native_only_payload`; `network::admission::negotiation_tests::failed_signaling_hint_cannot_prevent_native_recovery`; `network::admission::negotiation_tests::signaling_paths_carry_zero_application_frames_during_native_promotion`; `path::tests::negotiation::hanging_negotiations_reserve_half_the_attempt_for_native` | Actual native promotion and per-path zero signaling APP, through joined close; no sampled-IP-existence shortcut. |
| Signal Ygg remains control-only in production roles | `startup::tests::role_tests::signal_cases::signal_mode_negotiates_but_ygg_never_carries_application_payload`; `network::admission::ygg::standby_tests::forwarding::signal_mode_negotiates_through_ygg_but_never_forwards_payload_through_it` | Authenticated probe positive and forbidden APP negative; not a Boolean readiness claim. |
| Owned Ygg carrier authority is exact and current | `network::admission::ygg::tests::allowed_tls_key_on_another_ygg_identity_never_gets_session`; `network::admission::ygg::tests::source_attestation_requires_live_exact_carrier_address`; `network::admission::ygg::tests::real_ygg_sessions_authenticate_exchange_and_release_owned_path` | Prefix/type alone grants no authority; real carrier, TLS identity and release are checked. Unchanged adapter cases additionally cover revocation and queue/waiter bounds. |
| Real native/Ygg/native forwarding to one target | `network::admission::ygg::standby_tests::forwarding::native_ygg_native_new_tcp_follows_policy`; `startup::tests::role_tests::standby_cases::idle_policy_progress_restores_native_without_disturbing_active_streams` | Genuine fixed-target bytes and actual worker lease choice; endpoint shutdown is not an OS packet-filter or public-NAT test. |
| Ordinary exhaustion versus bounded long-lived maintenance | `path::tests::standby::maintenance::capped_maintenance_preserves_budget_and_ygg_route`; `path::tests::standby::maintenance::maintenance_cooldown_is_completion_based_and_late_poll_starts_one_probe`; `startup::tests::role_tests::standby_cases::idle_policy_progress_restores_native_without_disturbing_active_streams` | Default-budget real-I/O barrier plus exact deterministic cap/no-burst controls. No lifetime-attempt-count claim. |
| Ygg loss, total outage and recovery remain distinct | `path::tests::standby::maintenance::ygg_down_cancels_maintenance_until_restored_and_keeps_failure_deadline`; `path::tests::traces::losing_yggdrasil_inside_the_hold_returns_to_the_live_native_path_at_once`; `network::admission::ygg::standby_tests::outage::exhausted_native_budget_keeps_ygg_usable_then_total_outage_is_unavailable` | No maintenance after fallback loss is observed; Unavailable is not Exhausted or Closed. |
| Allowlist before target, wrong key and shared cross-path admission | `startup::tests::role_tests::denial_cases::disallowed_key_causes_zero_target_connections_and_allowed_key_succeeds`; `network::admission::ygg::standby_tests::denial::forbidden_clients_never_receive_a_serving_session_and_reach_no_target`; `startup::tests::role_tests::lifecycle_cases::capacity::cross_path_capacity_refuses_while_one_shared_slot_is_held` | Zero-target negatives have real allowed-target positives; capacity is shared, not duplicated per path. |
| Cancellation/re-entry does not recreate work or deadlines | `path::tests::standby::maintenance::original_attempt_deadline_and_cooldown_survive_cancelled_follow_reentry`; `path::tests::negotiation::cancelled_negotiation_resumes_without_a_duplicate_attempt`; `startup::tests::role_tests::lifecycle_cases::cancellation::retained_roles_cancel_and_resume_borrowed_waiters` | Retained owners and waiter cancellation; this does not promise survival of a failed transport's existing stream. |
| Shutdown, error custody and release stay joined/retryable | `path::tests::standby::maintenance::shutdown_joins_active_maintenance_and_stops_scheduling`; `startup::tests::resources::close_tests::one_backend_close_error_via_the_real_boundary_still_closes_every_other_owner`; `startup::tests::ygg_start_tests::cancelled_shutdown_is_resumable_and_still_joins` | Actual failure propagation, repeated close and resource/key/port release; no detached retry loop. |

Role observations retain a bounded ordered prefix of 4,096 events. They do not
promise unlimited lossless storage: after sealing, a missing later event times
out. The default-budget acceptance case's finite deadline and capped probe rate
keep its event count far below this bound; required late route/worker events must
be present for the case to pass. No sealed-prefix or dropped-event state is used
to claim an unobserved transition.

### Concrete boundary gap found in this audit

At the maximum representable policy time, saturating deadline arithmetic could
issue a maintenance command with `deadline == now`. The controller rejects that
expired command, but a capped retry could again saturate to the same instant,
creating synchronous retry churn. Saturated hold arithmetic could also shorten
a hold at that final tick. This change closes the policy before processing a
saturated clock; it introduces no new switching algorithm or public parameter.

Two private-boundary regression IDs accompany the repair:
- `path::policy::boundary_tests::saturated_clock_stops_retries_and_cannot_shorten_native_hold`
- `path::policy::boundary_tests::overflowing_maintenance_attempt_identity_closes_without_reuse`

These two cases are new proof obligations for this candidate's CI receipt, not
claims from the earlier 174-case run or local clippy. The saturation case fails
on the old zero-duration command; the identity case checks the existing checked
increment closes rather than reusing an attempt ID. No huge iteration count or
local test execution is needed. Once both are executed successfully, the audit
has no additional functional transition gap to carry into #25.

### Explicit remaining gates, not missing functional implementation

- #25 must measure the agreed p95 first forwarded byte (known 3 s, cold DHT 10 s),
  failover under controlled native blocking (10 s), direct share (at least 95%)
  and bounded resources. Listener/route readiness and a whole echo RTT are not
  the first-forwarded-byte metric. Reuse the real role/target fixtures and actual
  worker path observations; add only their missing measurement hooks, not a new
  protocol, transport framework or CI family.
- Native availability for the direct-share cohort must be independently
  controlled and known, not defined by having already selected Native. Keep the
  long-outage recovery case in the campaign with its real availability phases;
  do not inflate its ordinary budget, shorten the outage or omit adverse samples.
- #25 also owns the explicit current-candidate full P10 run. Targeted 76/174 and
  historical 411 do not substitute; later measurement-code changes require fresh
  proof on their actual SHA.
- P11/P12 complete product entrypoint acceptance, P13's extended fault/NAT and
  packet-filter matrix, separately bounded public interoperability, resources,
  notices and release decisions retain their own dependencies and gates. The
  shared-role/binary-wiring evidence does not silently close those stages.

## Measurement acceptance boundary for #25 (2026-11-10)

Advances scenario steps 3–5 after accepted transition audit `f335e98`:
CI `42846614038` executed all 78 selected cases on each OS, including both
new private-boundary cases, with identical identities and zero ignored. Exact
source is delivered; the task branch/worktree and duplicate refs are removed.
This is not a measured efficiency result or a full P10 pass.

The first bounded slice supplies the missing fixed-target first-byte oracle.
The echo target records its first successful one-byte read using Tokio's
monotonic clock, before writing the echo. Each observation includes the actual
connection ordinal and byte. A 64-entry channel bounds retained observations;
sequential measurements must consume every event. Overflow or missing events
cannot establish a successful sample. An EOF-only connection supplies no event,
additional bytes supply no second event, and cancelling the receiver must not
consume a later observation. Production transport and policy are unchanged.
The accompanying regression is written first; local lint does not execute it.

The oracle slice `7456cdd` is executed: CI `42852611880` selected, executed
and passed 52 identical startup case identities on each OS, including the new
target-byte regression, with zero ignored. This proves the observer, not latency.

The next startup slice fixes 20 sequential fresh-client observations for each
of two cohorts, before execution. Its nearest-rank p95 is the nineteenth ordered
sample. Known-address clients receive the independently bound server socket as
an optional hint; cold clients have no address hint or shared client cache and
must emit a service-key GET before the captured signed record is answered.
Both use default policy. Each timer starts before retained client startup,
including its initial publication, listener, lookup and handshake, and ends at
the actual target read. No Native route barrier delays opening the probe. The
live server socket is independently retained and unblocked for all 40 samples;
eligibility is not inferred from the selected lease. Non-native forwards remain
in the direct-latency distribution as `Duration::MAX`; a missing forward fails
the whole case. Actual leased paths and every sample are printed and retained
in a bounded `p10-startup-samples.csv` inside the existing selected-test receipt
artifact; successful libtest stdout alone is not accessible sample evidence.
Startup-only direct share is reported separately: long-outage availability phases, failover
and final combined direct-share acceptance remain open, not excluded by this
slice. Owners are joined before evaluating aggregate thresholds.

Startup evidence is accepted at `e2ba2ce`, CI `42859609959`: 55 identical
selected = executed = passed product cases per OS, zero ignored, and 40 unique
CSV rows per OS. Independently recomputed nearest-rank p95: Linux known
86,105,721 ns / cold 107,289,695 ns; Windows known 100,202,700 ns / cold
128,831,300 ns. All 40 startup connections on each OS used Native. This is not
combined campaign or full P10 acceptance. Earlier `cdaca7f` CI failed because
the verifier rejected libtest's legitimate 60-second progress notice, despite
54 successful test events per OS. `7307f04` repaired that strict parser, but its
CSV was crate-local and absent from uploaded evidence; the workspace-path
regression in `e2ba2ce` closes that custody gap without changing thresholds.

The next failover slice schedules 20 trials through the existing real standby
fixture, with default policy. A one-client loopback UDP gate first passes the
real native handshake and payload, then silently drops datagrams in BOTH
directions while both endpoints stay open. Two fixed UDP buffers, one pinned
client/upstream pair and one joined task bound the gate; it is not an OS/public
packet-filter test or an arbitrary relay. Timer origin is activation of silent
loss, not a later loss callback or Ygg-ready event; completion is the target's
first successful byte read on a new Ygg TCP forward. Each trial retains its
healthy Native and blocked Ygg phase, and proves packets actually passed and
were dropped. Twenty observations use the same nineteenth-order p95, at most
10 s. Endpoint shutdown alone does not prove this silent-loss criterion.
Source preflight found the pinned path-idle default is 15 s (connection idle
30 s), already longer than this budget. The first path-only tuning was not
sufficient: CI `42864492151` on `97f4971` failed on both OS (101 passed, two
failed). The new 0xCD/0xCE fixture seeds collided with an existing
`peer_composition` cancellation fixture, and silent-loss trial zero did not
return within 30 s. The failed distribution is not accepted. Source inspection
then found Noq refuses a local idle abandonment of the LAST open path with
`LastOpenPath`; awaiting connection closure cannot solve both all-silent loss
and Native-only loss while signaling survives.

The repair bounds connection AND path idle at 6 s, with a 2 s per-path
keepalive, leaving default 2 s policy grace and payload headroom. The SDK
handshake limit remains an upper bound of 10 s; backend idle may expire earlier,
and actual backend timeout errors map to the existing typed `Deadline` result.
Access denial/capacity and other transport failures remain distinct. A private
Native-loss observer consumes replayed `paths_stream` snapshots, returning when
all eligible IP payload paths disappear even if the signaling connection is
still alive; public `Session.closed()` retains its connection-only semantics.
It is event-driven and cancel-safe, without a polling task or an unbounded log.
The already-locked `futures 0.3.34` direct edge moves from dev to normal (it was
already production-transitive through `shaar-p2p`); no package, version, feature
or lock is changed. Packet-loss identities now use the separately checked
0x75/0x76 pair. The trade-off is more idle path control packets (2 s rather than
5 s) and earlier failure of a completely silent peer, bounded per retained path.
No APP is admitted on signaling.

A real same-connection regression must add a Native path to an authenticated
custom signaling connection, forward Native bytes, silently block the Native
route, observe Native loss, and prove the SAME connection still receives fresh
custom control with zero custom APP. Healthy waiter cancellation and re-entry
after loss are checked. Kernel and fixture commits remain separate; this
additional source-review gap is closed only after actual CI execution, not by
the direct-only fixture or local lint.

The combined connection ledger is declared before execution: 40 startup
connections, two existing default-budget long-outage connections, and 40
failover-phase connections (82 total). Native availability is independently
true for all startup connections, BOTH long-outage connections (only discovery
is withheld), and 20 pre-drop Native connections. It is false only for the 20
explicitly packet-blocked phases, which still remain in the ledger. Thus 62
connections are eligible; the original Ygg connection during long discovery
outage remains an adverse eligible sample. Repeated writes on that same held
stream are not new connections. Accept at least 95% Native among all eligible
connections only after all three CSV ledgers, real case receipts and joined
cleanup are verified on the same SHA. None of these next-slice obligations is
claimed executed yet; long-outage duration and ordinary retry budget are unchanged.

The remaining campaign must include all failures and distinguish:
- known-address startup from a fresh key-only cold service-key GET;
- the instant the client is given its configuration/key from a later ready route;
- fixed-target input from listener/route readiness or a whole echoed round trip;
- the independently controlled native availability phases from the selected lease;
- a genuinely new TCP connection from another write on an old held Ygg stream.

Use the existing production-role entrypoints, continuously driven owners,
independent signed-publication barriers, real worker lease events and joined
cleanup. Keep default-budget long-outage recovery and its old Ygg stream in the
campaign. The agreed 3 s / 10 s first-byte, 10 s failover and 95% direct-share
thresholds are unchanged. A target-observer slice or one successful composition
is not a distribution. Measurement fixtures, their rejection controls, bounded
resources and the final explicit current-SHA full P10 run remain open until
actually executed in CI. No new protocol, metrics framework, public peer or
packet-filter/NAT claim is introduced here.

## Audit-adjusted delivery passes (approved 2026-11-09)

The user requested: “скорректируй план под аудит, сгруппируй смежные задачи,
что их удобно было решать за один проход”. Groups below organize shared reading,
ownership and verification; they are not new umbrella tasks or permission to
implement all stages in one unreviewed batch. Task numbers in this section are
session TaskList IDs, not GitHub issue numbers.

### Ordered passes and observable exits

| Pass | Existing tasks and scenario | Work kept together | Exit and boundary |
| --- | --- | --- | --- |
| A — Finish shared startup | #31, internal repair #38; steps 1–6 | Shared production roles, both binary call sites, continuously driven discovery/forwarding fixtures, cancellation/cleanup, shared capacity, Signal/denial/relay oracles | Exact candidate passes relevant Linux/Windows CI; inspect selected/executed/passed receipts, personally deliver exact green and clean transferred worktrees. This is not full P10 or complete P11/P12. |
| B — Close P10 using one transition context | #32 → #33 → #25; steps 3–5; #1 is the acceptance parent | Late native recovery after normal retry exhaustion; immediately map transition evidence; then measure the agreed profile and run explicit full P10 on the final candidate | Sequential checkpoints remain mandatory: accept recovery before gap-check and gap-check before metrics. Fix only concrete uncovered cases. Preserve 3 s known / 10 s cold first byte, 10 s failover, 95% direct share and bounded resources. No public-network substitute. |
| C — Finish the two product entrypoints | #6 and #7; steps 1–6 | Review Server and Client against the same accepted startup/configuration/error/shutdown contracts; share the integration fixture and avoid implementing SDK startup twice | Each binary retains its own acceptance result. Independent file scopes may run in parallel after P10; shared files have one writer. Reuse 5c evidence, add only missing product obligations. |
| D — Integration and interoperability | #8, then #12; steps 1–6 | Controlled P13 path/fault/NAT matrix, followed by separately bounded live interoperability smoke using verified CI binaries | Controlled acceptance and live smoke are distinct receipts. Public smoke is authorized in principle by the user; exact lawful targets/peers and enforceable budgets must be agreed before execution. No TUN/root/router changes, scanning or load testing. |
| E — Resource closure and operational handoff | #9 and #10; steps 1–6 | Resource/complexity review and documentation of the accepted behavior, limits, configuration and recovery | After #8, independent measurement/review and documentation scopes may run in parallel; finalize documentation against the measured final behavior. Do not repeat full P10 merely to produce more evidence. |
| N — Independent notices lane | #13 → #14; distribution prerequisite for steps 1–6 | Exact corpus/provenance inventory and authentic material, then deterministic assembly/checks over accepted inputs | Keep legal files separate from networking. Full package terms, embedded component notices and missing provenance are different classifications. New acquisition requires its own exact-source/request budget. Partial corpus does not unblock #14. |
| F — V1 readiness | #11 after #9, #10 and #14 | Final evidence, remaining gates and clean repository/artifact handoff | Readiness is not release publication. Missing proof and any unexecuted smoke remain explicit. |

### Task consolidation and short feedback loop

- Fold the duplicate startup parent #24 and internal fixture/oracle tracking
  #35/#37 into #31. Their acceptance obligations are retained below, not marked
  complete by deletion. Keep #38 as the bounded current repair until verified.
  #36 is a historical source milestone, not runtime acceptance. Do not restore
  previously deleted completed tasks.
- The combined #31 still requires real signed key-only discovery, genuine native
  payload after signaling, lifetime zero application payload on libp2p/Signal,
  independent Ygg standby, denied zero-target plus allowed positive control,
  shared cross-path capacity, retained waiter cancellation and joined cleanup.
  Preserve actual GET/PUT barriers and completion guards. CLOSE is not RX drain.
- Delegate one coherent contract with an observable exit, non-goals, explicit
  protected scopes and an oracle counterfactual. A contract may span files;
  an arbitrary one-file split is not an acceptance boundary. Review before CI.
- Commit each reviewed, independently meaningful unit in its task worktree and
  send it to targeted CI without unrelated polish. If a new leaf has not reached
  its first CI on the day of first code, reassess its boundary; more than one day
  uncommitted requires immediate slicing review before more implementation.
  This is an escalation threshold, not a deadline that weakens correctness.
- Do not retroactively split the existing 5c candidate to hide failing fixtures,
  erase cumulative selection obligations or reset its failure streak. All
  available failure causes remain part of the consolidated repair review.
- One active writer worktree per executable unit; readonly custody trees are
  not executors. Remove them after verified preservation/integration. Primary
  stays on main; feature work, commits and CI stay in in-repository worktrees.
- Report accepted scenarios and time to verified delivery, not commit-count
  velocity or unsupported percentage-complete estimates. Written, compiled,
  executed, accepted and delivered are separate states. Use background CI watch
  immediately after pushes; the heartbeat is recovery, not execution pacing.
- No local builds/tests/Cargo/project Python/preparation/benchmarks/fake load.
  No new CI family, dependency/version change or release permission is created.

### Custody at this correction

The original startup tree `p10-role-startup-1108` is clean readonly custody at
`8bbb640`; the active repair tree `p10-5c-ci-repair-1109` preserves candidate
`21a4f51`. The independent notices tree owns its unaccepted corpus delta and
bounded reviewer correction. These are not three overlapping startup writers.
All must be preserved until their reviewed transfer or explicit supersession.
The isolated planning tree edits only this plan and the north-star decision log.
A plan correction does not certify any product candidate or authorize pushing
local checkpoint history upstream.

## CI recovery rule

The #267 repair streak already exceeds three failures. The previously authorized
CI `41708784553` at `86e5d5e` finished with failures on both operating systems;
the logs report `invalid compiler probe` in the existing audit. No replacement
executor or CI has been launched under these focus rules. Before the next CI
launch, consolidate all observed failure classes and remaining source/oracle
assumptions into one review and one bounded repair commit.

Known classes to include are package-versus-unit feature contexts, producer/reader
schema agreement, legitimate nested compiler probes, actual stdin provenance,
Cargo/MSVC output aliases, repeated crate types and observations, Windows path
spellings, and peak runner disk retention. A read-only comparison of previously
captured Linux and Windows query observations also found `--version --verbose`;
the current version-query predicate accepts only the single-argument forms.
Include the complete observed query matrix in the consolidated review rather
than launching another one-case patch. Reuse the existing implementation and
checks. Do not add another general verifier, inventory framework, or CI segment.

Use only the already permitted local syntax checks, standalone formatting/parser
previews and manual source/staged review. No local Cargo, builds, tests, project
Python execution, dependency preparation or smoke runs are authorized here.
A passing syntax check is not a passing runtime test.

Every worker prompt must repeat the local-execution prohibition. After terminal
completion, inspect tool/activity evidence as well as source and test oracles.
Report violations; never count a forbidden local run as acceptance evidence.
Keep exact-SHA feature CI, upstream delivery, independent DATA inspection, selected
versus executed receipts and the existing full/public/release boundaries.

## Primary custody and historical worktrees

State inspected on 2026-11-03; refresh this table before acting.

| Item | Observed state and disposition |
| --- | --- |
| Primary `.github/workflows/ci.yml` | Three old explicit `--simple-dns-source` additions in the manual P08 graph commands. The original author is not established. The current coordinator accepts custody under existing P08 task #15. Preserve the draft, do not silently stage it with P09, and reconcile it during the reviewed CI/workflow transfer. The current graph helper already has a default source path; this draft is not evidence of a blocking P09 defect. |
| `direct-integration-151` | Clean, but its tip is not an ancestor of either current primary or recorded upstream develop. Do not declare it transferred or remove it on that assumption; establish the source-equivalent delivery/supersession record first. Do not resume closed #151 work. |
| `direct-server-join-160` | Tip is in primary history, but an uncommitted formatting-only change remains in `crates/shaar-server/src/tests/shutdown.rs`. Preserve or transfer those bytes before cleanup; do not discard them silently. |
| `license-audit-162` | Tip is in primary history, but untracked `docs/plans/licensing.md` remains. It is a historical proposal, not legal clearance. Preserve and compare it with maintained legal documents before cleanup. |
| Publisher and graph worktrees | Retain until their real delivery/transfer/cleanup criteria are met. No background source executor was established by task status alone. |

At inspection, recorded refs showed primary develop ahead/behind origin/develop
by 64/38 commits and origin/main behind primary by 98 commits. These are historical
commit counts, not a source-divergence audit or fresh remote-state claim. Never
push the entire primary checkpoint history as a substitute for source integration.

The audited changes `1abefc9` and `06c6d4d` are present in both primary and graph
ancestry. Their source changes are consistent: root workspace-manifest selection
chooses runnable patch consumers `shaar` and `shaar-p2p`, keeps license selection,
and retains the hard failure for an empty runnable inventory. Do not restore the
contradictory all-package expectation or suppress the empty-inventory guard.

## Integration to main after P09

1. Establish the single owner, freeze the accepted P09 source SHA and inspect fresh
   remote refs. Inventory source differences separately from checkpoint-only history.
2. Reconcile the graph with the accepted newer Mainline source on the exact
   upstream integration base. A previous graph CI cannot certify changed source.
3. Deliver the reviewed source through feature CI and upstream exact-SHA delivery,
   inspect post-delivery evidence, transfer into primary, and remove only verified
   completed worktrees/branches. Preserve unrelated or untransferred changes.
4. Prepare a focused develop-to-main integration diff and report conflicts,
   acceptance scope and remaining human gates. Do not blanket-merge divergent
   histories, force-push, release or publish. Obtain any required merge authority
   before applying that integration.
5. After P09, complete existing permission-gated P07 #224/#33/#34, then start
   #214 when its P09 and P07 dependencies are accepted. Main integration
   preparation must not replace this product critical path.

## User delegation recorded on 2026-11-04

- **Single owner:** the user explicitly confirmed this session as the only writer.
  Do not repeat the question without new evidence of a conflicting owner.
- **Independent reference:** the user delegated obtaining and validating the
  evidence. Existing #263 gets one read-only pass over at most two official
  upstream/reference repositories, ten source-file requests and thirty minutes.
  Pin identities and hashes; stop when sufficient or exhausted. Do not repeat the
  inspected DATA, contact third parties, use public DHT, or execute locally.
  An unavailable independent reference remains an honest acceptance blocker;
  delegation never makes a self-roundtrip an external oracle.
- **Codec:** the user explicitly allowed Base58 or another codec instead of the
  disputed mapping. After P09, inspect dependency and wire-format impact in
  existing #236/#234/#235. Consider Base58BTC first using a legitimately licensed
  implementation, but do not replace protocol-mandated formats blindly. Update
  the existing specification/tests before implementation and verify the resulting
  dependency graph; changing an application encoding alone does not remove a
  transitive base256emoji dependency. No version bump or unverified dependency is
  authorized. Do not claim legal clearance without authentic evidence.
- **Authentic notices:** the user delegated resolving this correctly. After P09
  and existing prerequisites, use one bounded batch of at most two named official
  source/archive locations and ten file requests. Preserve verbatim legal text
  and provenance; stop when sufficient or exhausted. No synthetic licenses,
  rights-holder contact, policy widening or new generator framework is authorized.
- **Public smoke:** remains deferred to P13 until exact targets, traffic/time
  budget and stop conditions are separately approved. No advance blanket approval.
- **Yggdrasil — superseded on 2026-11-04:** the former deferral beyond v1 is
  cancelled by the user. P07 is required after P09 and before P10. Candidate:
  Revertron/Yggdrasil-ng, revision `c9a54f1587bb133a06072596484c972a336db0d2`.
  The user separately approved pinned integration after P09 and made controlled
  blockade resilience mandatory. Public smoke has conditional budget approval,
  not exact-target approval; see the decision record below. Use an isolated safe Rust API, no unsafe,
  Go/FFI, TUN/root/routes, and no custom crypto. Resolve existing task-lifecycle and
  dependency-source findings before acceptance.
- **Future file exchange:** torrent-style transfer is outside v1 and may be
  considered over the completed channel only after a separate request.

The coordinator owns routine technical decisions within these bounds. Escalate
only genuine missing authority or evidence, not routine implementation choices.
Codec/notices work must not displace the critical path: finish P09, then gated P07, then existing P10.

## 2026-11-04 permission decisions and remaining gate

The user explicitly answered the consolidated #224 questions; these permissions
come from those answers, not from scope restoration or an automated notification.

1. **Approved after P09:** integrate Revertron/Yggdrasil-ng at exact revision
   `c9a54f1587bb133a06072596484c972a336db0d2`, including reviewed lifecycle/ownership
   corrections, and verify in GitHub CI on Linux/Windows. No unsafe in the adapter,
   Go/FFI, TUN/root/routes, version changes or custom crypto. Existing source,
   security and lifecycle blockers must be resolved before acceptance. A fresh
   tool refusal must be reported, not bypassed through another executor.
2. **Conditionally approved public smoke:** after P09 and owned P07 checks, at
   most one run per OS; two public peers; four connection attempts total per run;
   120 seconds per run; 64 KiB test application payload and 10 MiB aggregate
   protocol/application RX+TX per run. Stop on a limit or anomaly. No automatic
   reruns, scans, user data or host-network changes. If limits cannot be enforced,
   do not run. **Still awaiting the user: exact peer endpoints.** Show them and
   obtain agreement before any contact; no public execution is authorized yet.
3. **Mandatory v1 acceptance:** controlled blocked native UDP with unavailable
   Mainline/libp2p while an explicitly allowed Yggdrasil path remains available;
   authenticated standby payload fallback, no Yggdrasil application data in signal,
   and never libp2p application payload. Separately authorized public
   interoperability is also required. This tests named conditions, not arbitrary
   DPI, every censorship regime or a complete Internet shutdown.

#224 stays open for exact public-peer approval. #33/#34 remain unstarted until
current P09 is accepted and their applicable gates are satisfied. Local execution,
TUN/root/routes, legal clearance and release permissions are not granted.

## Checkpoint format

First status line: `Distance to v1: accepted / active / not started / next / blockers`.
Use 5–8 short Session summary bullets, then exact live-operation IDs and state,
current SHA, task status, dirty-file custody, decisions and remaining gates.
Include restored P07 in the distance line and list each outstanding user decision
separately; neither scope restoration nor a pending public-run request is a pass.
Do not write a new acceptance claim merely to make the checkpoint look complete.
