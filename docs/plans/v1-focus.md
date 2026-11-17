# V1 delivery focus and standing reminders

**Distance to v1 (updated 2026-11-17):**

- Accepted stages: P01–P12 and D1 (P07 adapter `efa5c62`, P09 `b076458`, P10 path policy and efficiency campaign, P11 Server, P12 Client), P14 (resource measurement dispatch 43642328666 on `c84d9a6`, every budget row inside its ceiling, `docs/verification/scenarios.md` section 11.5) and P15 (SDK and operations documentation). Completed campaigns are not reopened; a later code change still invalidates the tested SHA of an earlier measurement; the re-measurement on the final code is recorded below (EFF-RE, 2026-11-16).
- P13: the namespace matrix ran in three passes (E4 base, E8 extension, E9 remaining rows; report in scenarios section 10). Row A5 (direct path through double cone NAT) was a recorded **negative finding** that started the NAT toolkit below; the relay-less direct punch is now proven in the namespace fixture (group `punch`, dispatch 43743773385 on `119fbe8`) and re-checked after the live-network fixes (dispatch 43794634221 on `70ae253`: `dnat-cone-norelay-signal` and `-standby` direct, route `native`, APP exact 61/61, the DHT-drop guard stays a fallback). With relay fields and with symmetric NAT it stays open. Still open inside closed rows: key-only IPv6 discovery, circuit and Client-side relay exhaustion, other NAT types, long-period keepalive. Gated: real home/mobile/cafe devices.
- Platform scope (2026-11-14): the products compile in CI for Linux, Windows, macOS and Android; the zero-configuration first run is executed in CI on Ubuntu and Windows only. macOS and Android are compiled, never executed; no real device was used.
- NAT toolkit without a helper server (north-star step 4, design in [P13 controlled network](p13-controlled-network.md)): merged L0 (relay-optional composed startup), L1 (dial ordering), L2 and L2b (DHT-voted reflexive IP, fast start), L3a (plain publication setting, default off), L4 and L4d (punch coordination over Yggdrasil control datagrams), L4c (the bridge envelope names its channel, so a datagram reaches only the payload or the control table), L4e steps 1 to 4 (end-reason, window and Offer traces, shorter fast start, a record lookup wait that leaves the punch phase its share), L5 (namespace cases and oracle flips), DHT-L1 (a query round stays within the operation's RPC room) and DHT-L2 (the record lookup outlives the attempt that stopped waiting) and L4b (the same candidate exchange over the authenticated libp2p carrier link when a relay is pinned, as side-channel datagrams beside the QUIC packets; a v1 leaf since 2026-11-16, ordinary-CI proof only). L3b (the encrypted address: `publish_address: encrypted`, one key per Server, the sealed value in `user-data`; ordinary CI green and the namespace pair passed). Open: the relay and symmetric-NAT rows, which only the L6 dispatches can move. L6: six authorized privileged dispatches are used (the fifth, 43867617110 on `b95f1a5`, proved L4b: direct path through two cone NATs with a pinned relay and Yggdrasil closed to the Client; the sixth, 43870509412 on `8be550f`, re-ran the whole `base` group against the changed relay dial sequence: 12 of 12 PASS, failover 7.0 s; the seventh, 43920291161 on `a2dbe17`, the first of the two further dispatches granted on 2026-11-16, proved L3b: both `dnat-cone-encrypted-*` cases ended direct with a sealed record and the five earlier punch cases were unchanged; the eighth and last, 43988889055 on `5c83e48`, was the final regression: the whole `base` group, 12 of 12 product cases and the three controls passed; no authorized dispatch is left).
- Live network: thirteen bounded dispatches ran: one failed at the public relay reservation (43629141158), two did not start inside their windows because GitHub queued the role jobs (the origin margin is now 600 s), ten passed over Yggdrasil standby. Since DHT-L1 the live Mainline DHT works for the owner (lookups complete, both roles learn their public address within 9 to 19 s), and since the lookup cap the coordinated punch runs on both sides: Client and Server probe each other's candidate in the same moment (dispatches 43788557511 and 43793054755). **No direct path was obtained between the two cloud runners** (the thirteenth dispatch, 43870725952 on `8be550f`, shows why in that run: the Server never learned its public address, so it answered none of 30 Offers). The candidate pairs a runner's public IP with the local port of its QUIC socket, which is right only for a NAT that keeps the port; the traces carry no port, so the cause is not established. By the decision of 2026-11-15 this is an observation, neither a pass nor a v1 failure. Whether the live record lookup of the Server now completes between attempts is not visible in the evidence (the route line prints once).
- Notices: N1 corpus and N2 build/checks are in place; the three remaining gaps (`base45`, `enum-assoc`, `if-watch`) are closed and merged (LIC-1). No legal clearance, no release authority.
- Re-measurement on the final code (EFF-RE, 2026-11-16): P14 dispatch 43795953404 on `70ae253` passed with all 38 rows inside their ceilings (`docs/verification/scenarios.md` section 11.6). P10 efficiency criteria come from the explicit full-scope CI run 43797588881 on `361e169` (fork, both OS green; same product code as `70ae253`) and confirmed by the upstream run on the same SHA, recomputed from the retained CSVs with the nearest-rank p95 over 20 samples: known-address first byte 80.4 ms Linux and 113.0 ms Windows (limit 3 s), cold-DHT first byte 100.8 ms and 137.7 ms (limit 10 s), failover to Yggdrasil under all-IP blocking 9.030 s and 9.046 s (limit 10 s), direct share 98.387% on both OS (62 eligible, 61 Native; limit 95%). The upstream full-scope run 43807660315 on the same SHA (both OS green) gives Linux 81.1 ms known, 99.3 ms cold and 9.030 s failover, Windows 143.2 ms, 167.7 ms and 9.053 s, direct share 98.387% on both; the Windows startup values differ by about 30 ms between the two runs and stay far inside their limits. All agreed thresholds pass; the values are close to the campaign of `54e85e2` (failover 9.029 s and 9.037 s). The libtest totals of the `cargo test` step were Linux 1,043 passed, 0 failed, 21 ignored (23 binaries) and Windows 1,050 passed, 0 failed, 15 ignored (23 binaries); the Windows-only SDK-parallelism diagnostic step reported 1,584 passed and 0 failed over 3 binaries.
- CI finding of the same step: the first full-scope run after the NAT leaves (43796417875 on `4b57e02`) failed on both OS at the real-carrier frame proof, because the proof rewrites three product files in a disposable copy and the signaling test file had moved into `signaling/tests/` with the punch change (`74182f4`); every later step was skipped, so no full run had covered the NAT work until `361e169`. Ordinary CI never selected the proof for that move. Fixed in `361e169`: the proof names its rewritten files once, derives the module path from the file location, and `.github/ci/policy.py` selects the proof when one of those files changes.
- Owner decisions of 2026-11-16 (north-star decision log): L4b is a v1 leaf, a single-source reflexive hint is allowed for punch candidates only, the first macOS execution is allowed in CI, the threat-model note for the encrypted address (L3b) may be written (code only after its approval), local clippy stays at 10 % CPU.
- Platform builds (PLAT-4 steps 1 and 2): `Platform build evidence` on the fork, run 43834970372 on `1e6da6c`, built all five targets (`x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-linux-android`). Build only: nothing was executed; the first execution on macOS and any Android execution are separate steps (Android stays gated: no device or emulator).
- First execution on macOS (PLAT-4 step 3, 2026-11-16): the `Process feedback` matrix of `sdk-lock.yml` (dispatch 43846060445 on `7a3bb16`) passed on ubuntu, windows and `macos-latest` (aarch64). The macOS receipt lists 13 reviewed process cases selected and verified passed, including `real_first_run_bootstrap_without_arguments` (first run without configuration) and the composed signal and standby cases; debug products, loopback only. Two findings on the way, both in test fixtures and fixed: the notice-evidence tests used temp dirs under `/var`, a symlink the tool refuses by design (24 failures), and the busy-listener case knew only the Linux and Windows errno texts (macOS reports `os error 48`). Android remains build-only (no device or emulator).
- Punch leaves of the same day: PORT-DIAG (merged `3fa96cb`) traces `shaar: <role> punch ports own=… peer=…` and carries it into the smoke evidence field `ports`, so the next bounded smoke can show whether a cloud NAT rewrites the source port (the candidate is the public IP plus the local QUIC port). HINT-1 lets a side offer the address of its latest DHT window as a punch candidate before two windows agree (never published; a forged vote costs a bounded number of probes at the peer).
- Status 2026-11-17: the final checks of P16 are done on the final candidate `5c83e48` (the product code of `5802273`, the L3b merge; later commits are test code, guard data and documentation). The full-scope run 43966680594 on `fdb461f` is green on Linux and Windows after four failed full-scope runs whose causes (a stale lock digest, the native-graph approvals for L3b, Windows flakes of the frame oracle and of a keepalive assertion) are listed in section 12.4 of `docs/verification/scenarios.md`; a fifth Windows flake of a test fixture (port exclusion, 10013) failed the upstream run 43980926424 and was fixed in `5c83e48`, which is green in fork run 43985999369 and upstream run 43986770266. P10 was recomputed (known address 79.8 ms Linux and 110.6 ms Windows, cold DHT 98.4 and 138.1 ms, failover 9.030 and 9.041 s, direct share 98.387 %), P14 holds on `5802273` (dispatch 43923887074, 38 of 38 rows), the platform builds built four of five targets on `5802273` (macOS aarch64 got no runner in four attempts) and the final dispatch 43988889055 passed. The readiness report is section 12; the owner accepted it with its open risks on 2026-11-16 and added L3b, which is implemented and checked. What remains is the owner's acceptance of the first version, the confirmation of two readings of L3b (a secret provisioned to the client, one key per Server), and the gated rows.
- Blockers and gates: the owner's acceptance of the first version and the confirmation of two readings of L3b (a secret provisioned to the client, one key per Server); device access for real networks; legal clearance and release; no publication, version change, commit or push beyond explicit user requests.

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
| Fork-first verification | Verification CI runs in the fork; upstream `develop` receives only the exact SHA that was green there. `main` holds private checkpoints and merge commits and is not pushed. |
| Go to the goal | The client knows only the key, finds the server through the DHT, connects directly, and falls back to Yggdrasil under blocking. Every leaf names the scenario step it advances; add no proof mechanism or CI segment without a specific uncovered failing case. |
| Stop serial CI repair loops | After three consecutive failures of one leaf, stop incremental fix/push cycles. Review all available failures, source assumptions, paths, selectors, formatting and resource costs together; make one reviewed repair commit and report the findings before resuming CI. |
| Local execution limits | Locally only `cargo fmt`, `cargo clippy`, syntax checks and the agreed pinned preparation. No local build, test, `cargo check`, smoke, benchmark or load; repeat this in every worker prompt and inspect the evidence afterwards. |
| One owner and controlled repository state | At session entry, compare HEAD, latest checkpoint, actual executors and peer ownership. If another owner is active, do not launch work. Track dirty-file custody and worktree disposition; checkpoints are always committed. |
| Honest reports and gates | Distinguish written, compiled, executed in CI and accepted. Collect human decisions early; retain legal/public-network/release permissions. Start each checkpoint with the distance line and use 5–8 summary bullets. |

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

The failover slice schedules 20 trials through the existing real standby
fixture, with default policy. Its original one-address UDP proxy did not cover
alternate Native routes; the consolidated repair below replaces that premise
with an endpoint-wide, SDK-test-feature-only Native IP packet gate. The real
native handshake and payload first pass; Native IP datagrams in BOTH directions
are then silently dropped while both endpoints stay open. One endpoint-scoped
atomic gate covers every native transport sender and IP receive, including
cached reconnects and discovered alternate addresses. It creates no socket,
queue or task, and is absent from default production builds. This is not an
OS/public packet-filter test or an arbitrary relay. Timer origin is activation of silent
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

The earlier repair set connection AND path idle to 6 s, with a 2 s per-path
keepalive. The consolidated budget correction below also accounts for first-send
idle reset, rather than assuming that path-idle alone establishes payload headroom. The SDK
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

CI `42869046520` on `3115cf6` is also failed, not accepted. Each OS selected
370 cases and verified an initial 120-case batch, then stopped at a failed
121-case batch: Linux 120 passed / one failed, Windows 119 passed / two failed.
Across actual execution, Linux has 240 passed / one failed; Windows 239 passed /
two failed. The remaining 129 selected cases were NOT executed on either OS,
including the old cancellation fixture. Its seed collision is repaired in source,
not yet confirmed by execution; an earlier operator claim of its pass was wrong.
The packet-loss fixture wrongly treated an intermediate same-kind
Native generation as the final answer; `follow` explicitly permits such recovery.
It now continues to Ygg under the ORIGINAL block timestamp and outer deadline.
A direct-only endpoint's connection counters retain APP-positive evidence when
a live-path snapshot cannot establish that history; there is still no custom
transport in that fixture. Both initial and recovered Native paths must remain
inside the controlled gate. The Windows same-connection timeout is not declared
fixed: the next bounded diagnostic records actual addresses, route generations,
RTT, control progress and closure state, and rejects an ungated Native path
instead of assuming that one proxy blocks every possible route. Thresholds,
sample count and outage duration are not relaxed. Failure streak is two; a third
failure requires the consolidated-review stop before further CI pushes.

### Consolidated review after three failures (#48)

CI `42874429666` on `5b8a956` is the third consecutive failure. Each OS selected
370 SDK cases: 239 actual passes, two failures and 129 NOT executed, with only
the first 120-case batch receipt-verified. No point-fix push or rerun followed.
Actual traces conclusively show the scope error: a Native retry around eight
seconds uses the real upstream UDP address, bypassing the proxy. The signaling
connection also gains a real upstream Native path and continues receiving fresh
Custom control. Selecting Native or waiting for its loss was correct product
behavior while that alternate route remained usable. Forcing Ygg or fabricating
dial refusal would contradict the north star.

The review covers the earlier seed collision, Noq `LastOpenPath` behavior,
connection-versus-payload liveness, same-kind generation progress, closed-path
frame evidence, complete batch selection, feature contexts, source provenance,
formatting and resource bounds together. Noq's packet builder can reset idle
on the first post-RX ack-eliciting send. A 2 s keepalive plus 6 s idle plus 2 s
policy grace leaves no payload margin. The consolidated repair therefore uses
5 s connection/path idle: nominally 2 + 5 + 2 = 9 s before payload, leaving
headroom inside the unchanged 10 s measured p95. Noq's RFC 3*PTO floor is not
weakened; actual CI timestamps, not this nominal calculation, remain acceptance.
The handshake upper bound stays 10 s with typed earlier backend timeout. No
retry budget, stable hold, controlled outage duration or threshold is reduced.
Existing before-connect hooks cannot
simulate packet loss; disabling NAT traversal is neither used nor smuggled into
the fixture. A one-address proxy cannot establish endpoint-wide unavailability.

The owner explicitly approved one narrow source-contract exception, recorded
in north-star. The single consolidated repair adds a separate empty
`shaar-native-gate` feature to the SAME pinned Iroh package and enables it only
through the SDK dev dependency. Normal product graph checks reject its presence.
SDK gate accessors exist only under `cfg(test)`. No package, version, lock,
download budget, root permission, public target or production runtime option
changes. Source presence is disclosed: backend provenance reports optional test
instrumentation, the disabled default and the owned module hash, rather than
continuing to claim an unmodified source.

The gate is endpoint-scoped and shared by all transport sender clones. Filtering
occurs at final `TransportsSender::poll_send`, after Mixed-address resolution,
and at typed Native-IP ingress before Noq dispatch. Thus alternative addresses,
IPv4/IPv6, address discovery and cached reconnects cannot bypass it. Custom and
Relay transport variants are not filtered; Ygg owns a distinct carrier. The gate
creates no task, socket, queue or packet log. Feature-off builds contain neither
its state/allocation nor packet-hot-path branches/atomics. Allowed TX counts
are attempts, NOT delivery claims. Real Native target bytes before blocking,
actual drops in BOTH directions before shutdown, new Ygg target bytes, fresh
Custom control and zero Custom APP remain independent runtime obligations.

Exact-count patch application and reverse application are validated before any
source write. Four pre-gate source hashes are recorded after existing reviewed
production transformations. Reversing the gate must recover those hashes;
previous archive-equality checks remain after removing only the reviewed delta.
Negative controls cover duplicates, altered/missing feature guards, preexisting
module preservation, source drift, default feature activation and normal graph
feature leakage. The first generated source tree and revised preimage-receipt
draft are preserved separately, never overwritten. All original archive SHA256,
package identities and licenses are still verified by the existing prepare-only
entrypoint, with zero network acquisition and no archive-code execution.

Local preparation completed and the four preimages independently match the
previous prepared Iroh source. Actual compiler artifact receipts distinguish
normal `cargo clippy --lib` features (`tls-ring`, `unstable-custom-transports`)
from SDK `--all-targets` test features (the same two plus `shaar-native-gate`).
Both offline/locked lint contexts and the accepted formatting boundary passed;
Cargo.lock is unchanged. These are compilation/lint and DATA-integrity proofs,
NOT execution of Rust or Python tests. The new gate controls, all campaign cases
and graph/source negative controls still require CI on the repair SHA.

The old proxy is retained only as a separate Native-priority positive control:
when one proxy is blocked, another independently reachable Native address must
still authenticate and forward. Its two healthy Native forwards are outside the
performance cohort; excluding healthy positives cannot inflate Native share.
The actual 20-trial campaign and same-connection regression now use the complete
endpoint gate, keeping the original clock, thresholds, sample count, old Ygg
stream and ordinary retry budget. One personally reviewed consolidated commit
and an explicit SHA/trade-off report are required BEFORE CI resumes. The failure
streak remains three until a real green; full P10 is not accepted by this review.

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

The reviewed gate repair was committed as `303bf62` with parent `5b8a956`,
reported before the fork push, and tested by CI `42893117913`. Both OS jobs failed
before SDK execution with `ValueError: ambiguous driver closure seed: rcgen` in
the existing product driver fixture. The consecutive failure streak is now four,
not reset by local clippy. The retained targeted selection includes the SDK library
and native graph witness, but neither target executed; no fresh case inventory,
failover distribution or three-ledger acceptance was produced.

A joint review of both terminal traces, baseline metadata, selection and driver
source identifies one shared failure: the fixture selects seeds by globally unique
package name, while the legitimate product graph contains rcgen 0.13.2 through
libp2p-tls and 0.14.10 through Yggdrasil. The unchanged pinned Noq archive declares
rcgen 0.14 for its test suite. The bounded follow-up selects exactly the already
locked 0.14.10 fixture identity; it does not remove the older package if a normal
closure edge reaches it, change any lock/version, or weaken identity, feature,
source-path or dependency-edge equality. Missing or duplicate reviewed identities
still fail. Five CI-only graph controls cover order independence, both reachable
versions, missing/changed identity rejection, ambiguity rejection and unreviewed
source rejection. They run inside the existing backend verification step, not a
new CI segment. Local checks are syntax plus the accepted fmt and offline locked
normal/test clippy contexts; Python and Rust tests remain CI-only. One reviewed
follow-up commit and report must precede another fork push; all runtime obligations
above remain open.

CI `42894735758` on the reviewed rcgen follow-up `6d5f737` passed the
previous driver-fixture boundary but failed both OS jobs during the locked native
graph comparison: `features.AuditError: unapproved dependency edge: shaar -> futures`.
The failure streak is five. The SDK campaign and its numerical acceptance again
did not execute. This is not evidence against the failover threshold itself.

The earlier Native-loss observer moved the already locked, production-transitive
futures 0.3.34 dependency from SDK dev to normal dependencies, but omitted its
exact direct edge from the metadata AND compiler-unit declarations. Both terminal
traces and the complete retained metadata/unit deltas were reviewed together.
Full native graph artifact downloads (1,853,413,977 bytes Linux and 1,682,159,109
bytes Windows) both ended with `unexpected EOF`; they were not blindly retried.
Bounded HTTP Range reads recovered only the inert evidence JSON and four needed
metadata/build JSON entries per OS, with ZIP CRC and retained SHA-256 verification.
No downloaded code was imported or executed. An own stdlib DATA reader compared
the complete normal-edge and captured compiler-unit deltas against the literal
existing declarations, including the established Yggdrasil growth and Base58
transition. With the exact observer pair declared, it found no other unexplained
metadata edges, unit edges, unit identities or feature changes on either OS.
This DATA review is not local execution of the project verifier or CI acceptance.

The bounded repair declares only `shaar 0.1.0 -> futures 0.3.34` in both edge sets.
Regression controls cover admission of that pair and rejection of another version,
another owner, unexpected feature growth and removal. Existing checksum, source,
feature, closure and unit identity guards remain unchanged. There are no new
packages, versions, locks, Rust behavior changes or CI segments. Syntax checks and
the accepted formatting/offline locked normal/test clippy boundary passed; the
Python controls and all runtime obligations still require CI. One reviewed repair
commit and report are required before resuming fork CI; only a real success resets
the five-failure streak.

CI `42905449848` on `b9cb3f3` failed both OS graph comparisons with
`unapproved control-to-candidate package removal`; the streak is six and the SDK
campaign remains unexecuted. The preceding DATA review was incomplete: it
compared name/version, features and edges but omitted prepared-source tree/recipe
identity transitions. Its broad statement that no unexplained changes remained
must not be treated as full source-identity proof.

Both current evidence JSONs were recovered by bounded inert ZIP ranges. Their
normal metadata hashes match the previous retained metadata byte-for-byte, and
all backend bindings match the earlier proofs on each OS. Full source-identity
comparison identifies three approved source transitions, not package removals:
Iroh's exact tree/manifest changes and the shared recipe digest change for Iroh,
Noq and Noq-proto introduced by the owner-approved test gate. Noq/Noq-proto tree,
manifest, archive and version are unchanged. After mapping only those exact old
and new source fingerprints for comparison, the remaining package removals are
exactly the three established emoji-chain packages and registry multibase; the
additions are the existing declared Yggdrasil closure and prepared multibase.

The bounded source-contract repair freezes both sides' archive, tree, manifest
and recipe digests in `baseline/backend_sources.py`. It validates the complete
three-package transition before returning comparison copies for package keys and
compiler-unit/dependency-owner identities. Original proof bindings and digests
are never rewritten. A different source/version, missing/partial transition,
forged binding or normal-context test gate is rejected. Feature equality and all
other closure/edge/source guards remain active. CI-only synthetic controls cover
the integrated comparison, non-mutation, drift of each fingerprint on both sides,
partial transitions, unit-owner drift, feature growth and unchanged graphs. The
normal/test feature separation and backend exact patch-reversal controls remain
separate runtime CI obligations; no source is relabeled as unmodified.

This is still a source-contract repair, not P10 acceptance. No Rust behavior,
package/version/lock, preparation recipe, new download authority or CI segment is
changed. Python is checked locally only for syntax; tests remain CI-only. The
accepted fmt and offline locked normal/test clippy boundary must pass, followed
by one personally reviewed repair commit and report before the next fork push.

CI `42910616786` on `122bc04` passed the source/graph boundary and reached
SDK execution, but failed both OS jobs in the partial-proxy positive control:
the second post-drop `connect()` returned `Deadline`. The streak is seven.
Actual SDK receipts select 371 cases per OS: the first 120 are strictly verified;
the next 119 executed with 118 passes and one failure, leaving 132 unexecuted.
Thus observed totals are 238 passed / 1 failed, not 371 executed or accepted.
The old retained-role cancellation case remains among the unexecuted cases; the
separately selected native graph witness target also has no execution claim.

The real all-IP silent-loss campaign and same-connection signaling regression
reported libtest success on both OS. The retained failover CSVs each contain 40
rows: 20 healthy Native/eligible and 20 blocked Yggdrasil/ineligible, all trial
IDs present. Recomputed nearest-rank p95 first-target-byte times are Linux
9,029,807,293 ns and Windows 9,045,538,400 ns. These are authentic observations
from a failed batch, not accepted receipt counts, current-candidate proof or full
P10 acceptance. Startup/long-outage ledgers and the combined share remain open.

The positive-control fixture's missing precondition is a validated alternate
Native path before proxy loss. Its second address was only an endpoint hint;
Iroh resolves it through a peer-level mapped socket and existing route state,
so a fresh post-drop handshake is not a proof of preserving an existing healthy
alternate. The bounded fixture repair authenticates the second connection while
the proxy is healthy and uses the existing `ensure_native_path` readiness barrier
to validate/retain the independent real address before blocking only the proxy.
A new exact TCP forward must then succeed after blocking, with the real address
still observed, two target accepts, two authenticated sessions and joined cleanup.
It does not claim fresh-address discovery or a new handshake after blocking.
Both healthy forwards remain outside the performance cohort. No policy, timeout,
metric threshold, outage clock, trial count, key/allowlist or backend behavior is
changed; no forced route selection or all-IP gate bypass is introduced. Both OS
failures and the complete available receipts were reviewed before this repair.
Local fmt and offline locked normal/test clippy passed; runtime remains CI-only.
One reviewed repair commit/report must precede the next fork push.

CI `42915913841` on `c8b6d87` completed with Linux success and Windows
failure, so the consecutive run failure streak is eight. Linux strict receipts
confirm 371 SDK and two native graph witness cases passed. All three Linux CSVs
contain 82 rows, 62 independently Native-eligible and 61 Native. Linux p95 is
80,876,968 ns known startup, 99,338,821 ns cold startup and 9,029,498,840 ns
all-IP failover. These are Linux-only historical-SHA observations, not two-OS
or full P10 acceptance. Windows again selected 371 SDK cases, strictly verified
the first 120, then executed 118 passes / one failure in the next 119-case batch;
132 remained unexecuted. Its 40-row failover CSV has p95 9,057,522,300 ns but
belongs to an unverified failed batch.

The validated alternate-path positive now passed on Linux but Windows failed at
TCP read with WSAECONNRESET 10054. The old helper did not retain the QUIC close
reason, so the exact causal chain is not claimed experimentally established.
Joint source review identifies a concrete transport configuration race consistent
with that loss: connection idle and path idle are both five seconds. Pinned Noq
kills the entire connection on ConnTimer::Idle but only abandons a lost path on
PathTimer::PathIdle. Equal deadlines provide no interval to retire a silent path
and use a validated backup before the whole connection expires.

The bounded production repair keeps connection idle at five seconds and path
keepalive at two, but retires a silent path at four seconds. A compile-time
invariant requires nominal path idle to precede connection idle. The RFC three-PTO
floor and Noq LastOpenPath behavior are unchanged; full all-IP loss still has the
same global five-second bound and original outage clock, trial count and payload
threshold. This does not assert universal behavior under arbitrary RTT/PTO.
The unchanged partial-proxy regression exercises real alternate-path payload;
its reset is neither ignored nor retried. The echo helper additionally reports
the actual QUIC close reason on a read failure without suppressing the error.
No identity/admission, retry/stable-hold policy, source recipe, package/version/lock
or CI segment changes. Formatting and offline locked normal/test clippy passed;
no local Rust tests ran. One reviewed repair commit/report precedes the next fork
push, and the new mechanism still requires both-OS runtime confirmation.

Targeted CI `42921130515` accepted exact `54e85e2` on both OS: 371 SDK
cases and two native graph witness cases per OS, with selected inventory minus
ignored identities exactly equal to executed identities. This includes the old
retained-role cancellation, alternate-path positive and mixed-signaling loss case.
All three CSVs contain 82 rows per OS, 62 eligible and 61 Native (98.387%). Linux
known/cold/failover p95 is 79,873,855 / 99,200,297 / 9,028,880,651 ns; Windows is
98,668,700 / 129,414,900 / 9,036,649,500 ns. All agreed thresholds pass. The eight
consecutive failures were reset by this actual two-OS success; repair #48 is closed.
The P10 bounded resource review links the fixed two-side owner, nonqueued session
and 16-stream/worker limits, eight commands/results, 64 lifetime resolver keys,
32-record batch and four-address limit to executed capacity/backpressure/cleanup
cases. It makes no P14 RSS/CPU benchmark claim.

The subsequent explicit manual-full CI `42925846018` on the SAME unchanged SHA
failed both OS jobs before the carrier wire case: Cargo refused to update the
disposable strict fixture lock under `--locked`. This is the first failed run
since targeted success, not a continuation of the old eight-run streak. Full P10
is not accepted. Both terminal stderr traces and the strict preparation receipt
were reviewed together; the root lock and reviewed observation lock are unchanged.

The carrier derivation returns immediately for a registry identity already in
the product graph. With serde_json 1.0.154 now present through Yggdrasil, this skips
its reviewed qlog edges to foldhash/indexmap. A local inert-DATA comparison found
this to be the only missing shared observation-lock edge growth; the verified
serde_json archive declares preserve_order -> indexmap + alloc + dep:foldhash.
The bounded repair recursively unions reviewed observation-closure edges even
for existing identities, preserving every product edge, version and checksum.
Expansion is visited once, and only the existing reviewed root closure may add
identities. It never removes `--locked` or asks Cargo to generate a lock locally.
The corresponding reference guard admits only exact serde_json 1.0.154
preserve_order/alloc/indexmap feature growth and the two exact reviewed normal,
untargeted dependency edges, preserving unrelated feature/edge rejection.

Synthetic CI controls cover existing/new observation dependencies, product-only
edge preservation, LF/CRLF, missing derived edges and unrelated features/owners.
They run before wire execution inside the existing carrier step; no new CI
segment or observation framework is introduced. Local Python is syntax-only;
fmt and offline locked relevant clippy contexts must pass before push. No product
Rust behavior, root/reviewed lock, package/version, source recipe or acquisition
budget changes. The reviewed repair requests explicit full scope in its current
commit; final acceptance must use that new SHA's real execution evidence.

Full CI `42928470520` on `02de25b` passed the repaired carrier boundary
but failed both OS jobs at the owned-DNS foundation's frozen lock check. Its
selection receipt confirms full scope via the current commit marker. The retained
Ubuntu carrier receipts independently confirm six strict and six allow-all
bootstrap cases passed, not native-loss/reconnect or complete P10 acceptance.
This is the second failed full run after targeted success. A third consecutive
failure must stop point-fix pushes until the standing consolidated review is complete.

Both DNS failures are `owned DNS changed lock bytes beyond its one direct edge`.
The fixture still freezes the pre-Yggdrasil product lock. The new frozen baseline
is SHA-256 `2085a0ec2e5aca68948173863595eef3b71d2fe3df9862560fc8c9a592409a9a`,
computed by an own inert-DATA reader from the current targeted-CI-verified product
lock after removing ONLY the one owned-DNS direct edge. The normalized product
lock SHA-256 remains `ae186edff0a2fad29ffc4d6f4590a79a975a5ef6112c34606c6d5361be9c0597`.
No lock file is changed or generated locally. The exact bytes/hash check, exact
one-edge reversal, all-package identity comparison and unchanged feature unions
remain mandatory; arbitrary additional bytes still fail.

The same fixture copy predates the SDK's explicit adapter, Yggdrasil-core and
external witness paths. Joint source review therefore includes those path
contexts before another run: copied crate-local paths stay in the copied tree;
prepared-source and witness references are rebased only to the existing caller
repository, never an external path. Caller sources remain untouched, repository
escapes fail, and a hashed manifest-rebase receipt is retained in the existing
artifact. Synthetic controls cover relative/absolute copied-crate paths,
prepared/witness paths, source preservation and rejected escapes. Existing exact
lock LF/CRLF and unexpected-byte controls stay in place. These are CI fixture
corrections, not relaxed dependency provenance or a product behavior change.

Python remains syntax-only locally; the accepted fmt and offline locked relevant
SDK/P2P clippy contexts must pass before one reviewed commit/report and a single
full-marker fork push. No dependency/version/root lock, preparation/download
budget, public-network permission or new CI segment is introduced. Full P10
and exact-green delivery/cleanup remain pending on the new candidate SHA.

Full CI `42934771483` on `c0b052d` passed the repaired DNS boundary but
failed both OS jobs at workspace all-target clippy. The three consecutive full
failures are `42925846018` (carrier observation lock), `42928470520` (DNS frozen
baseline), and `42934771483` (Ygg bridge lib-test lint). The consolidated-review
stop is active: no point-fix push or rerun follows this third failure. Targeted
repair #48 remains historically accepted; full P10 is still not accepted.

Both clippy traces report the same four defects in shaar-ygg: production items
after inline test modules in bridge/carrier.rs and bridge/carrier_pump.rs, plus
two manually implemented no-op Wake instances. Earlier SDK/P2P targeted lint
contexts compiled the Ygg dependency but did not lint its lib-test target. The
local toolchain is 1.97 while CI is pinned to 1.99.1; no version is changed and
local success is not represented as CI lint acceptance. Full-context review
therefore covers all six owned workspace crates with --workspace --all-targets,
plus the separate shaar-ygg-core manifest rather than another narrow SDK-only
lint pass. All remains offline/locked and clippy-only locally.

The single bounded repair places the existing production item blocks before
the test modules and replaces only the two genuinely no-op test wakers with
std::task::Waker::noop(). Counting/notification wakers remain unchanged. An own
stdlib structural DATA check retains unchanged production text before rustfmt
and the exact test identity list. After rustfmt, nonempty production lines and
all seven carrier/two pump test identities independently match the originals.
Workspace and isolated-core all-target clippy both passed under local 1.97; the
generated isolated-core target was preserved under ignored root target after
clippy terminated. No production behavior or test obligation is removed. No lint suppression, feature narrowing, dependency/version/lock/source
recipe change or local test execution is permitted. The previous fixture repairs
retain strict reference checks and passed their respective full-run boundaries;
formatting, source paths, selection and bounded resource evidence are reviewed
in the same pass. One personally reviewed consolidated commit and report must
precede renewed full CI, and only an actual complete success resets this streak.

The consolidated full run `42941884265` on `50298d2` finished Linux
success (52m21s), but GitHub cancelled Windows after the configured 90-minute
job limit: the authenticated annotation states "The job has exceeded the maximum
execution time of 1h30m0s". This is a timeout cancellation, not a new Rust assertion
failure or a green run. The preceding three-failure stop has not been reset.
Full job logs and Windows CSVs are retained alongside the Linux receipts.

Both cargo-test steps completed successfully before cancellation. Their reported
workspace test-summary pass totals are Linux 826 and Windows 843, with zero
reported failures; these totals count executions across test binaries/doc tests,
not a deduplicated logical-case inventory. All nine preserved Ygg regression IDs
are present as passed on both OS. Current-SHA CSV checks retain exactly 82 rows,
62 eligible and 61 Native per OS. Linux known/cold/failover p95 is
91,535,807 / 114,531,994 / 9,027,925,665 ns; Windows is
140,799,000 / 143,371,700 / 9,046,453,200 ns. These prove completed runtime slices,
not completion of the interrupted Windows native-graph proof or final acceptance.

The Windows native-graph step started 83m32s into the job and was cancelled after
6m30s. The same proof previously required approximately 16 minutes on Windows;
this is an insufficient aggregate job budget, not evidence for relaxing an
application deadline. The bounded follow-up grants 120 minutes ONLY to explicit
full Windows checks. Linux and all targeted jobs retain 90 minutes. Every test,
proof, application/failover threshold, sample count, compiler/lock feature context
and gate remains unchanged. The extra 30 minutes covers the measured isolated
three-graph capture and remaining receipts/negative controls; execution remains
bounded and no new CI segment is added. A CI contract pins the exact conditional
selector and default budget to prevent broadening unrelated jobs.

The renewed consolidated review includes both terminal job timings, the previous
three failures, the unchanged production/test bodies, completed runtime evidence
and the interrupted proof. Only workflow budget, its contract and this honest
record change. Local Python remains syntax-only and the accepted fmt/offline
workspace all-target clippy boundary must pass before one reviewed commit/report
and explicit-full fork push. No product test error is suppressed and no source
is promoted upstream until the entire new-SHA full run is accepted.

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

## Public live smoke contract (D2, scenarios E3, task #12): relay-optional, first run executed

Status: **one bounded live smoke executed (fork run 43629141158): the public Mainline
bootstrap nodes and both Yggdrasil peers worked, while the pinned public libp2p
bootstrap used as the signaling relay accepted TCP but gave no reservation, so the
Server never became ready.** The second bounded live smoke (relay-less, fork run
43671098240 on source 289bb1f, contract SHA-256 32671262002e...7134aa) passed: see
"Second run" below. The user's 2026-11-04 and 2026-11-09 decisions authorize
a smoke in principle, and the 2026-11-14 decision authorizes execution through this
default-off contract. The contract is now relay-optional (`libp2p_relay: null`,
approval recorded 2026-11-14); the next run is relay-less. A pass is a bounded
live-network observation, not acceptance of the end-to-end claim. The
machine-readable form is `.github/probes/public-smoke/contract.json`; the recorded
approval binds its exact bytes through the SHA-256 given at dispatch.

**Scenario steps advanced:** 1–3 (signed record in the public Mainline DHT, key-only
Client resolves), 5 (Yggdrasil standby over public peers) and 6 (allowlist check and
one fixed-target request/reply). With `libp2p_relay: null` the composed products start
without any signaling relay fields (leaf L0): the Server publishes through the DHT
record and the Yggdrasil bridge, the Client dials direct candidates and falls back to
Yggdrasil. With a relay pinned, step 4 is covered only on the Server side: the
composed Server must reserve a slot on a libp2p relay to start at all.

**Acceptance (one observable criterion):** in one dispatch, the normal CI-built
`shaar-server` on runner A and `shaar-client` on runner B (two separate GitHub-hosted
Ubuntu runners, so the path is genuinely over the Internet) complete exactly one
request/reply of fixed APP bytes in `standby` mode with a Client configured with the
Server key only, within every budget below. Anything else is a fail, reported as is.
From the third run on (2026-11-15, owner decision "the live smoke additionally attempts a direct
path within its contract and records the observed route either way") the same run also records
whether the coordinated punch produced a direct Native path; that observation never decides
the pass.

**Non-goals:** no `signal`-mode live run (its outcome depends on NAT behaviour between
two cloud NATs, which P13 already covers in a controlled network; the standby run only
observes whether a punch happens to succeed), no load or efficiency measurement, no scanning, no Windows run, no real devices, no release or
legal claim, no retry or rerun, no product change.

### Exact targets

| Network | Target | Operator and why using it is lawful |
|---|---|---|
| Mainline DHT | `dht.libtorrent.org:25401` | Default of libtorrent's documented `dht_bootstrap_nodes` setting; run by the libtorrent project for exactly this purpose (libtorrent blog, 2016-09 "DHT bootstrap node"). |
| Mainline DHT | `router.bittorrent.com:6881` | BitTorrent, Inc. router named in BEP 5 and listed as a bootstrap node in the libtorrent settings reference. |
| Yggdrasil | `tcp://ygg-pa.incognet.io:8883` | IncogNET, Allentown PA. Listed by its operator in the official `yggdrasil-network/public-peers` repository (`north-america/united-states.md`). |
| Yggdrasil | `tcp://mo.us.ygg.triplebit.org:9000` | Triplebit, Kansas City MO. Same list and same basis. |
| libp2p relay | **none** (`libp2p_relay: null`) | The contract is valid and ready without a relay; see the relay-optional paragraph below. |

Honest limits of the legal basis: the public-peers list states no formal terms of use
and no uptime guarantee; its purpose is that anyone may peer with the listed nodes
and its README advises two or three peers. The DHT bootstrap hosts publish no terms
either; they are documented default entry points. The two bootstrap hostnames are
resolved once by the harness (the product accepts only numeric IPv4); every address
must be globally routable or the run aborts before any contact. Beyond the bootstrap
hosts, joining the DHT means exchanging UDP packets with arbitrary volunteer nodes and
asking about 8 of them to store one signed record of at most 1000 bytes; this is
inherent in the protocol and is bounded only by the byte caps below. The record
contains the runner's own interface addresses (the products do not filter private
ones), which are ephemeral.

**Relay optional (2026-11-14):** the first smoke showed exactly why the relay was the
blocker: a public libp2p bootstrap accepts TCP without granting third-party
reservations. Since leaf L0 the composed Server and Client start with **no**
`network.signaling.relay*` fields: the Server skips reservation entirely and serves
through the DHT record and the Yggdrasil bridge; the Client constructs its dialer
without a relay lease and falls back to Yggdrasil. With `libp2p_relay: null` the
contract validates, the ready check reports no blocker, the rendered Server and
Client network sections contain no relay lines, the meter's allowed-address set and
caps cover only Mainline and Yggdrasil, and no relay connection is required or
asserted; the evidence states plainly that no relay was used. A relay may still be
pinned later; it then needs an operator whose published terms permit the use, and
the behavior is exactly as before (one reservation by the Server). The Client's
owned silent loopback relay is used only when a relay is pinned; without one the
Client config carries no relay fields at all.

**Second run, relay-less (2026-11-15, fork run 43671098240, source 289bb1f0d02e, contract
SHA-256 32671262002e0deed31915942c4863a4e8c099a9ceae27a64d4704b57a7134aa):** the
plan, build, Server (runner A) and Client (runner B) jobs all passed, with the products
started without any relay field. Observed by the harness: the Client, configured with the
server key only (`server_address=none`), completed one exact application exchange (43 byte
request, 43 byte reply, content match, first byte and total 0.87 s) through the Server's
fixed target; the Server accepted one connection and the target saw the request; each
role held two Yggdrasil connections to the contract's public peers and no connection to any
unlisted address or relay. Metered per job against the caps: NIC 201,674 B (Server) and
70,820 B (Client) of 5 MiB, Yggdrasil TCP 25,741 B and 18,085 B of 3 MiB, DHT UDP 175,933 B
and 52,735 B of 1.5 MiB, zero violations. Both products exited with code 0 and the Server
stayed alive until the stop. **What this does not prove:** the route is Yggdrasil standby
inferred by exclusion (Native is blocked by construction on the cloud NAT runner, no relay
is configured) and was not directly observed; the harness cannot observe whether the Client
resolved the DHT record (the products log nothing about it; it is inferred only from the
exchange succeeding by key alone); no direct path, no hole punching and no NAT traversal were
exercised; one run on two GitHub-hosted runners is not acceptance of the end-to-end claim,
and real devices were not involved. The evidence artifacts are `public-smoke-server-evidence`
and `public-smoke-client-evidence` of that run.

**Third run, direct-path attempt (2026-11-15, fork run 43751396899, source 5d43914197e8, contract
SHA-256 ba8a28f77f06a85200569051d58f29d3b7f2adf18ec7c1886b737a1c42c5acf3):** the plan, build, Server
(runner A) and Client (runner B) jobs passed. The Client, configured with the server key only,
completed one exact application exchange (43 byte request and reply, first byte and total 0.88 s)
through the Server's fixed target over Yggdrasil standby: each role logged one `ygg-standby` route
and session line, held two Yggdrasil connections and no relay or unlisted connection, and both
products exited with code 0. Metered per job: NIC 316,420 B (Client) and 351,922 B (Server) of
5 MiB, DHT UDP 282,512 B and 317,044 B of 1.5 MiB, zero violations. **Direct-path observation: none,
and no punch exchange took place.** The Client printed six punch attempts, every one with
`candidates=0` (it knew no public address of its own), four of them lasting 0 ms; the Server
printed no punch line (an Offer without candidates starts no probe burst). The cause of the 0 ms
attempts is **not established**: the trace carries no end reason. Hypotheses from the code, none
observed: the 3 s attempt deadline was already spent by the DHT lookup before the punch phase began
(`started >= deadline`), or the control datagram path refused or closed the send. The first
reflexive vote also arrives seconds after start, so early attempts offered no candidate. The next
step is an end-reason token on the punch trace (task NAT-L4e), so that the next live run can tell
these apart. None of this says anything about the cloud NAT: no cloud-NAT punch has been tried
yet. What this does not prove: any direct path,
any hole punching or NAT traversal on a public network, or acceptance of the end-to-end claim.

**Fourth to sixth dispatches, traced binary (2026-11-15, upstream runs 43760623868, 43762751996 and
43772367278, sources `a2abd4a` and `745076f`, same contract digest):** the first two ended before
any exchange because GitHub started a role job after its window had closed (the Server in the
first, both roles in the second, 1 s to 6 min after the shared origin that then carried a 90 s
margin); the late role refused before any public contact and no evidence was written in the second
run. The window origin margin was then widened to 600 s for the idle wait only. The third
(`745076f`) passed: the Client, configured with the server key only, completed one exact exchange
(43 byte request and reply, 6.67 s) through the Server's fixed target over Yggdrasil standby,
both roles logged one `ygg-standby` route and session line, two Yggdrasil connections each, no
relay, zero violations. **Direct-path observation: none, and still no punch exchange.** What the
traces now establish: the Client printed eight punch attempts, every one with `candidates=0`
(`deadline` 2, `no-answer` 6); the Server received eighteen Offers, every one with no candidates,
and answered none; the reflexive watcher of each role never produced an observation, all windows
`skipped` (Client 7, Server 4), so neither side learned a public address in about 33 and 39
seconds. The cloud NAT was therefore never attempted: a punch with nothing to offer cannot start.
The first dispatch's Client alone showed the same (four of four windows skipped). The Client's
windows after the first ended within 0.4 s each, the Server's took roughly 3 to 9 s, so the
skips are not all the 10 s bound. **Not established:** why every window is skipped (lookup error,
no network answer or the 10 s bound; the line did not say). The next leaf step reads
`info().public_address()` even when the window's own lookup did not complete, because the pinned
crate sets that address on any finished query that collected a vote, and adds the lookup and info
tokens to the window line so the following smoke can tell the causes apart.

**Seventh dispatch, window tokens (2026-11-16, upstream run 43776379518, source `6cd0bcf`, same
contract digest):** passed over Yggdrasil standby again (one exact exchange, 43 bytes each way in
6.75 s, zero violations, no direct path, no punch exchange). The window tokens named the cause of
the empty windows. Client: the first window `lookup=incomplete`, the five after it
`lookup=failed:RpcLimit`; Server: `incomplete`, one `failed:DeadlineExceeded`, then
`failed:RpcLimit` four times; `info=none` in every window of both roles, so no public address was
ever held and the read added nothing. The Client printed seven punch attempts and the Server
received twelve Offers, none with candidates. **Observed:** the owned DHT actor refuses the
reflexive lookup with `RpcLimit` on the live network. **Hypothesis, from the pinned source and not
yet proven on the network:** the owned profile caps in-flight RPCs at 16 per operation (128
aggregate) while an iterative query round visits up to `MAX_BUCKET_SIZE_K` = 20 closest candidates
at once, so once the routing table holds a full bucket the 17th visit fails the whole operation;
the namespace and loopback fixtures hold only a handful of DHT nodes and never reached it. If it
holds, every owned operation (record publication, record resolution, the reflexive lookup) fails
on the live Mainline DHT, which fits `resolve=timeout` in every live smoke so far, and the smokes
passed on the Yggdrasil fallback alone. Leaf DHT-L1 caps a round at the operation's remaining
room (the caps themselves unchanged) in the two visit loops of the owned patch, with a query-level
and an actor-level regression test; the next live smoke is the check.

**Eighth dispatch, after DHT-L1 (2026-11-16, upstream run 43779762033, source `8149259`, same
contract digest):** passed over Yggdrasil standby once more (one exact exchange, 43 bytes each way
in 0.84 s, zero violations) and confirmed the leaf on the network: no `RpcLimit` in any window,
lookups end `ok` or bounded with `info=some`, and both roles learned a public address (Client
exposed at 24.0 s, Server at 35.3 s after their starts; two agreeing windows each, the second one
counted although its own lookup hit the 10 s bound, which is what the info read is for). The
route line now reads `resolve=cached` where it read `timeout` before. **First punch exchange on a
public network, and no direct path:** the Server answered two Offers with its candidate and the
Client probed it twice (`reason=probe`, about 2.1 s each, `direct=0`), but the Client had no
candidate of its own yet, so the Server had nothing to probe back and a one-sided probe cannot
open the Server's NAT. The Client's one attempt that did carry a candidate (`candidates=1`) ended
`reason=deadline` after 0 ms: its record lookup spent the 3 s attempt deadline before the punch
phase began. The observation window closed 30 s after the exchange, a few seconds after the
Client's own address was known. **Established:** the cloud NAT has still not been tried with a
coordinated punch; the limits are the 20 to 35 s each side needs to learn its address, the 3 s
attempt budget the punch phase shares with the record lookup, and the 30 s observation window.
The next step shortens the fast-start pauses and widens the observation window (see Timeline).

**Ninth dispatch, shorter fast start and a 45 s window (2026-11-16, upstream run 43784413811,
source `6a3c75b`, contract digest `6ee285ea…`):** passed over Yggdrasil standby (one exact
exchange, 43 bytes each way, zero violations). The fast start worked: the Server exposed its
public address at 9.3 s (was 35.3 s) and the Client at 19.0 s (was 24.0 s), with the window tokens
`lookup=ok info=some` and no `RpcLimit`. **The punch phase never ran:** all nine Client attempts
ended `reason=deadline` after 0 ms, five of them already carrying a candidate, and the Server
received no Offer at all. Cause, from the code and the traces together: `NativeDialer::dial`
waits for the record lookup before the punch phase, the lookup of a cold live DHT takes 6 to 10 s,
and the attempt deadline is 3 s, so every attempt ended inside the lookup (`resolve=timeout`).
The lookup of a record that is not cached is also cancelled when its waiter gives up, so the wait
cannot be lengthened to let it finish. **Established:** with the DHT working, the attempt
deadline shared with the record lookup is what keeps the cloud NAT from ever being tried. The
leaf caps the lookup wait at one second while a punch channel exists (two seconds of the attempt
stay for the Offer, the Answer and the probe burst). **Separate finding, not fixed here:** the
same cancel-on-give-up rule means the record of a Server is practically never resolved on the
live network within a 3 s attempt; the Yggdrasil standby carried every smoke, and the first byte
criterion for a cold DHT lookup holds only in the fixtures. That needs its own leaf (the lookup
must outlive its waiter and cache its answer).

**Tenth dispatch, punch phase unblocked (2026-11-16, upstream run 43788557511, source `429f9f7`,
contract digest `6ee285ea…`):** passed over Yggdrasil standby (one exact exchange, 43 bytes each
way, zero violations). **The first coordinated punch on a public network took place and found no
direct path.** The Client ran ten attempts, every one ending `reason=probe` after about 2 s, six of
them carrying its own candidate (its address was exposed at 14.6 s); the Server received ten
Offers, answered every one, and ran six probe bursts toward the Client's candidate
(`outcome=fallback reason=probe`, 0.5 s each). Both sides therefore probed each other's candidate
in the same moment with the candidate learned from the DHT, and neither QUIC handshake completed.
The candidate pairs a runner's public IP with the local port of its QUIC socket, which is right
only for a NAT that keeps the port; the traces carry no port, so whether the cloud NAT remaps
ports or filters differently is not established, and the contract records this as the observed
route either way. **Side effect found in the same run:** each attempt now waited one second for
the record lookup and then cancelled it, so the owner restarted the whole query every time; the
Client's DHT traffic rose to 1.13 MB (0.35 MB before, cap 1.5 MiB) and one reflexive window ended
`failed:CandidateLimit`. Leaf DHT-L2 stops cancelling: the attempt hands the lookup to a task of
its own, a later attempt collects the same lookup, and the owner's cancel-on-give-up contract is
unchanged.

**Thirteenth dispatch, the first run with the port and role traces (2026-11-16, upstream run 43870725952, source `8be550f`, contract digest `6ee285ea…`):** passed over Yggdrasil standby (one exact exchange, 43 bytes each way, first byte 6.66 s, zero violations). **No direct path, and this time the cause is visible in the evidence: the Server never learned its own public address.** All five of its reflexive windows were `skipped` (lookups: 3 `bounded`, 2 `incomplete`; `info=none` in every window), so it had no candidate and, by the Answer rule, answered none of the 30 Offers it received (20 of them carried a candidate). The Client ran ten attempts, every one ending `reason=no-answer` with at most one candidate offered (its own address was exposed at 22.3 s). The `punch ports` trace never appeared because no Answer was sent, so whether a cloud NAT rewrites the source port is still open. This differs from the tenth dispatch, where both sides learned an address: it is one runner's DHT observation, not a product conclusion, and by the decision of 2026-11-15 it is recorded as an observation. Cost visible in the same run: an Offer that goes unanswered holds the Client for its whole exchange window (up to 1.5 s) in every attempt; answering with an empty candidate list would end the wait at once, which is a possible later leaf, not done here.

### Native is not blocked (third run onward): the direct attempt

The first two runs ended on Yggdrasil standby because no punch existed; the route was then
established by exclusion. Since leaf L4 the relay-less products punch, so nothing blocks
Native any more and no sudo, firewall rule or namespace is used. Both runners sit behind cloud
NATs and the Server's record lists only its private addresses (`publish_address` stays off), so
a direct path exists only if the coordinated punch succeeds: an Offer and Answer over the
Yggdrasil control datagrams, then QUIC probes from both sides toward the NAT egress addresses.
The harness still refuses to start if a runner has a globally routable local address.

- **Contact beyond the targets above:** UDP between the two owned runners' NAT egress addresses
  only, inside the NIC cap; no new third-party target, no scanning. The products print counts
  only (`shaar: <role> punch candidates=<n> outcome=direct|fallback`), never addresses.
- **Timeline:** the Client keeps running `client_punch_observe_s` after the single
  exchange and stops early on a `route path=native` line; the Server stays up
  `client_punch_observe_s + 5` s after its target saw the exchange, bounded by its window end.
  The observation window was 30 s with a 25 s readiness wait and a 20 s exchange budget; after
  the live traces showed that each side needs 20 to 35 s to learn its public address (two
  DHT lookups of 6 to 10 s each), it is 45 s, with a 12 s readiness wait (took 1 to 2 s) and a
  15 s exchange budget (took 0.8 to 6.7 s): the Client now ends at most 92 s after the origin
  (20 + 12 + 15 + 45). The 120 s per-process window and every byte cap are unchanged.
- **Allowed observed paths:** `ygg-standby` (the exchange) and `native` (a punched path);
  `ygg-signal` is a violation. Evidence carries the route sequence, the punch attempt counts and
  `claims.direct_path`, a sentence written from the observed lines only.
- **Meaning of the outcomes:** a direct path is an observation of a public-network punch, an
  unpunched cloud NAT (likely: the cloud SNAT does not keep ports) is recorded as that
  observation, and neither decides v1. The acceptance of the punch is the namespace matrix
  (`scenarios.md` A5). The contract bytes of the first six dispatches had SHA-256
  `ba8a28f77f06a85200569051d58f29d3b7f2adf18ec7c1886b737a1c42c5acf3`; the amended timeline above
  has `6ee285ea56c21e252c01e4114c80582a3d12b5aa55f354b908eac0fb24be3e34`.

### Enforced budgets (per dispatch: one run, zero retries, two runners)

All numbers are the contract file's; the harness also embeds ceilings, so editing the
JSON can only tighten them. They restate the 2026-11-04 conditional bounds.

| Budget | Value | Enforcement |
|---|---|---|
| Runs | 1 per dispatch, Linux only; rerun refused (`GITHUB_RUN_ATTEMPT` must be 1) | Inline check in the plan job and in the harness |
| Product window | at most 120 s per process: Server T0 to T0+105 plus 15 s stop grace, Client T0+20 to at most T0+92 plus grace | Absolute epoch deadlines from one shared origin; SIGINT then kill of the owned PID |
| Job | 15 min step limit, 18 min job limit (the first minutes are an idle wait for the shared origin) | GitHub `timeout-minutes` |
| Yggdrasil TCP connections | at most 2 per job (4 per run) | Metered per socket; a third connection is a violation |
| Relay TCP connections | at most 2 (Server only; only when the contract pins a relay) | Metered per socket; without a relay the row stays zero and is not asserted |
| Bytes per job | NIC rx+tx at most 5 MiB (10 MiB per run); Yggdrasil TCP 3 MiB; relay TCP 256 KiB (zero without a relay); DHT/UDP (NIC minus TCP) 1.5 MiB | Metered every 500 ms; a breach kills the product |
| TCP peers | only the resolved addresses of the allowed hosts | Any other non-loopback TCP peer is a violation |
| APP payload | one exchange, 128 B request and 128 B reply (64 KiB ceiling) | The fixture accepts exactly one connection and one exact request |

Metering uses `/proc/net/dev` (all non-loopback interfaces) and `ss -tine` for sockets
owned by the product PID (inode match). It needs no privilege. It is conservative:
counters are runner-wide, so background traffic counts against the caps and the meter
can over-count but not under-count; sampling is every 500 ms, so an overshoot is at
most one interval; very short failed connection attempts can be missed (the cap on
established connections is what is enforced). UDP bytes are derived, not read per
socket. If `ss` or the counters cannot be read the run is refused (fail closed). A
violation, a meter failure or a crash is a fail: no automatic rerun.

### Dispatch (default off)

The mode lives in `sdk-lock.yml` as input `public_smoke` (default `false`) beside the
existing modes and is exclusive with them. Jobs: `public-smoke-plan` (inputs and
contract validation, harness unit tests, no network), `public-smoke-build` (normal
products with the native packet gate OFF through the existing `product-manifest`
recipe, staged as an artifact kept one day), then `public-smoke-server` and
`public-smoke-client` in parallel on separate runners. Validation order: the 40-hex
revision, attempt number, mode exclusivity and digest shape are checked inline before
the checkout; then the contract schema and ceilings, the recorded approval and the meter
availability; a pinned relay is validated when present, and `null` is a valid,
runnable value. The two roles check the product digests against
the manifest and the window origin before any contact.

The approval is recorded in the contract itself (date 2026-11-14, the user's words,
decision-log reference) and `libp2p_relay` is `null`; any later edit (for example
pinning a relay) changes the digest, which is
`sha256sum .github/probes/public-smoke/contract.json`. Then:

```text
gh workflow run "SDK lockfile preparation" --repo <repo> --ref <branch> \
  -f source_revision=<40-hex SHA of that commit> -f public_smoke=true \
  -f public_smoke_contract_sha256=<that digest>
```

Window origin: the two role jobs start independently, so the build fixes a shared origin
`t0` (build end plus 600 s) and each role waits idle until its offset from it. Two
dispatches on 2026-11-15 (runs 43760623868 and 43762751996, both on a2abd4a) failed with
no public contact from the late role: GitHub started the role jobs 1 s to 6 min after
the origin that then carried a 90 s margin. The margin and the role step and job timeouts
(15 and 18 minutes) were widened for that idle wait only; the contact windows and every
traffic, connection and time cap of the contract are unchanged.

One-command entry (leaf PUNCH-SMOKE, decision of 2026-11-15): the same dispatch as a
script that only drives the `gh` CLI. The compile and the run stay in CI; the script
runs no product and contacts no public target itself.

```text
python -I .github/probes/public-smoke/launch.py plan    --repo <repo> --ref <branch>
python -I .github/probes/public-smoke/launch.py run     --repo <repo> --ref <branch> --out <new dir>
python -I .github/probes/public-smoke/launch.py collect --repo <repo> --run <id> --sha <SHA> --out <new dir>
```

`plan` dispatches nothing: it requires the ref to sit exactly on the SHA, a green
ordinary CI run of that SHA and a contract at that SHA that is approved with one run
per dispatch and zero retries, then prints the exact dispatch inputs (the contract
digest is computed from the bytes at the SHA). `run` checks the same, refuses an
unusable `--out` before spending the single run, dispatches exactly once, makes one
lookup of the run, watches it with a 300 s interval and downloads only the two
evidence artifacts into the new directory. `collect` does the watch and download for
a run that was dispatched elsewhere. A clean pass exits 0; any other run or role
result exits 1 with the evidence still collected; a refused check exits 2; a
dispatched run whose id is not listed yet exits 3 (find the id with `gh run list`
and use `collect`). The unit tests of the script run in the ordinary CI policy suite
and in the dispatch's plan job; they use a fake `gh` and no network.

Digest of the proposal as committed here (not runnable: approval and relay are
`null`): see the delivery report; any edit of the contract changes it.

### Evidence recorded

Per role, `evidence.json` (artifact kept 14 days; never keys, seeds or configs):
revision, run id, contract digest, product digests, native gate off, public keys,
resolved bootstrap and peer addresses, runner addresses, established Yggdrasil and
relay connections with first-seen time, the metered totals against each cap, product
exit code, stderr tail (redacted if key bytes appear), and the APP result. Claim
levels:

- **Observed:** Yggdrasil peer connections, the relay connection (Server, only when
  the contract pins a relay), DHT bootstrap traffic (NIC UDP bytes; destinations are
  not readable), APP bytes and match, the target seeing exactly one valid authorized
  exchange, byte and connection totals, product exit codes.
- **Inferred, not observed:** the route (Yggdrasil standby, by exclusion) and that the
  Client resolved the DHT record. The products log nothing about either, and the
  harness has no privilege to see UDP destinations. A pass therefore proves that a
  key-only Client reached the Server end to end while Native was excluded, not that
  the DHT lookup itself was seen. Closing that gap needs a product-side status line
  or a privileged capture, both out of scope here.
- **Not claimed:** libp2p negotiation across a public relay (Server reservation
  only, and only when one is pinned), hole punching, efficiency, behaviour under a
  different NAT, Windows. A pass is a bounded live-network observation, not
  acceptance of the end-to-end claim.

Identities are disposable: seeds are derived from the run id and attempt, so they
protect nothing and are never uploaded; the allowlist admits one such client key and
the only target is a local echo fixture bound to loopback.

## SDK and command line (approved 2026-11-17)

Owner request and answers are quoted in the decision log of [north-star](north-star.md)
(2026-11-17). Scenario steps advanced: 1 and 2 (an operator generates a Server identity
and hands out its address, the Client is configured with that key only), 3 and 5 (the
generated files carry the public network defaults that make key-only discovery and the
Yggdrasil fallback work without hand-written `network` objects) and 6 (the allowlist
is managed from the command line; an embedding application may serve admitted streams
in-process).

**Overall non-goals:** publishing crates or binaries, packages, installers, a GUI, one
binary that replaces both roles, shell completion files, a libp2p relay default, a new
textual address encoding (the canonical Server address stays the 64-hex public key; the
PeerId and the Yggdrasil IPv6 are printed as derived forms), UDP forwarding, more than
one published service per Server, changes to the wire protocol `shaar/tcp/1`.

Leaves, in delivery order; each records its acceptance before code and ends with a
green fork CI, an exact-SHA upstream run and a merge:

1. **SDK-1, ktav 0.8.1.** Acceptance: `Cargo.lock` pins `ktav` 0.8.1 with its crates.io
   checksum, and the config test suites of `shaar` pass in CI on Linux and Windows with
   no change to any config file shape. Non-goals: the 0.9 draft, any other dependency.
2. **SDK-4, public network defaults.** Acceptance: `network.mainline.bootstrap` also
   accepts `host:port` entries, resolved once at composed startup with a bounded deadline
   to IPv4 addresses (an unresolvable set fails startup with a named field, values never
   echoed); the provisioning API gains a network choice, and the files it writes for
   `init` carry `network` objects with the bootstrap hosts and Yggdrasil peers of the
   public smoke contract (section "Exact targets" above) unless `--private` is given;
   the generated texts parse and pass the composed preflight in CI, and a `localhost`
   bootstrap entry resolves in a CI fixture. The legacy first-run forms keep writing
   direct-only files, so their behaviour and their CI process cases stay unchanged.
   Non-goals: contacting public hosts in CI, a relay default, a peer-selection service.
3. **SDK-2, facade.** Acceptance: a third-party-style integration test in
   `crates/shaar/tests/` builds a Server and a Client only through the facade
   (no ktav text, no file), exchanges exact bytes over a client stream with the
   in-process handler on one side and over the fixed TCP target on the other, and
   proves that a key outside the allowlist reaches neither the handler nor the target.
   Facade items: `Server`/`Client` builders and `from_config_file`, `ServerAddress`
   (parse/print of the 64-hex key, `peer_id`, `ygg_ip`), `AllowList` over
   `ServerAddress`-style keys with the existing file parser moved into the SDK, a client
   `ServiceStream` (`AsyncRead + AsyncWrite`, explicit `finish`), and a server handler
   receiving the admitted peer key and one `ServiceStream`, with the existing stream and
   session caps. Non-goals: making the roles `Send`, a request/response framework, a
   second application protocol.
4. **SDK-3, command line (`clap`).** Acceptance: both binaries accept the subcommands
   `init`, `address`, `run`, `config show|check|set`, plus `allow add|remove|list` and
   `address-key new` on the Server and `connect` on the Client; the existing invocation
   forms (`--config`, positional first run) behave exactly as before; files written by
   the CLI are ktav 0.8 and parse back to the same configuration (round-trip tests);
   process tests in CI drive `init`, `allow add` and a `run`/`connect` exchange.
   Non-goals: interactive prompts, preserving comments of a file rewritten by
   `config set` (the rewrite says so and keeps a `.bak` copy).
5. **SDK-5, guide.** Acceptance: `docs/guide` describes the facade and every
   subcommand with examples that tests compile or execute; full-scope CI green on the
   final SHA. Non-goals: a tutorial site, translated guides.

### SDK and command line: status (2026-11-17)

All five leaves are written and executed in CI; the evidence and its limits are in [limits-and-evidence.md](../guide/limits-and-evidence.md#sdk-and-command-line). SDK-1 (ktav 0.8.1): fork run 44038242102. SDK-4 (host-name bootstrap, public defaults for `init`): fork run 44038409636. SDK-2 (facade): fork run 44043457256 and upstream run 44045761000 on `183b0f7`, merged with SDK-1 and SDK-4. SDK-3 (clap builder API, subcommands, configuration and allowlist editing) and SDK-5 (guide pages, runnable example): fork run 44056317957 on `c1ad2bc`. Changes against the plan above: the facade types are `PeerKey` (one type for a Server address and a Client key, instead of a separate `ServerAddress`), `AllowList` and `ServiceStream`; clap runs without derive and without colour (four packages, no proc macro); `address-key new` replaces a separate `keygen`; the Client's direct shape opens QUIC streams on its session and the composed shape connects to the role's loopback listener. A mistake of this work is recorded in the checkpoint: a worktree removal followed a junction and emptied the shared `target/`; the prepared sources and the offline vendor were rebuilt from the local archive store without the network.

## Closed network and Android harness (decisions of 2026-11-17, design awaiting approval)

Owner words and the recorded decisions are in the decision log of [north-star](north-star.md) (two rows of 2026-11-17); the design, threat model, bounds and open questions are in [closed network](closed-network.md). Nothing in this section is implemented except where a status line says so. Scenario steps advanced: 3, 5 and 6 of the closed-network scenario in the north star.

| Leaf | Observable acceptance | Non-goals | State |
|---|---|---|---|
| AND-1 harness | A debuggable APK built without Gradle runs both product roles on the local x86_64 emulator; an exact payload crosses client, direct QUIC, server and an echo target | Store packaging, real devices, UI, CI execution | In progress, local evidence only |
| CN-1 private DHT | In-process nodes form a private DHT from one bootstrap; records of non-certified keys are rejected; bounds hold under a flood | Public DHT interop | Blocked on the design approval |
| CN-2 registration | Allowlisted relay receives a certificate; unlisted key refused; expiry honoured; signed relay index | Authority rotation | Blocked |
| CN-3 relay | Direct path blocked in the controlled fixture, exact bytes through one relay; relay sees ciphertext only; disallowed client reaches no target | Multi-hop, UDP | Blocked |
| CN-4 signed files | Authority-signed manifest, chunk verification, poisoned chunk rejected | Search, deletion | Blocked, right after CN-3 |
| CN-5 Android node | The app is a relay and a client of the closed network on the local emulator | Real devices | Blocked |

Local execution for the Android work follows the 2026-11-17 row (local build and emulator, `wnice -c 10 -m 10g`); CI keeps executing everything else, and local results are reported as local evidence.

## Two-device live test (decision of 2026-11-17)

Owner words and bounds: the first row of the 2026-11-17 decisions in [north-star](north-star.md). Scenario steps advanced: 1 to 4 of the public scenario (the signed, sealed record; key-only resolution; direct QUIC; coordinated punch), with step 5 observed only if the first two fail.

| Leaf | Observable acceptance | Non-goals | State |
|---|---|---|---|
| PAIR-2 live attempt | The Server runs in the harness app on the phone (mobile network) with `publish_address: encrypted` and a composed public configuration; the Client on the computer holds the Server key and the address key file and no address hint; the Client log shows `candidates=record:<n>` with `n > 0` (the sealed record opened), then the punch line and the route (`route path=native` or `ygg`), and one exact payload returns from the phone's echo target. A control attempt without `address_key_file` must show `record:0`. Any outcome is recorded as observed | Load, more than three attempts, other phones or networks, changing phone settings, long runs, any claim about carrier NAT beyond the one observation, release | Two of three attempts run on 2026-11-17, local evidence of two devices; the exact payload crossed both times over Yggdrasil standby; the sealed record was not shown to open and no direct path appeared (see the result below) |

Procedure, in the order of the bounds: the phone's network and the app's routing (not through the phone's own VPN) are read before each attempt; the NIC counters of the phone interface and of the computer are read before and after and compared with the budgets; each process stops by its own 120 s limit; the app is uninstalled and the temporary keys are deleted afterwards. Secrets (identity seeds, the address key) are created for this test only, never written into the repository, and the public addresses seen in logs stay out of it too.

### Result of 2026-11-17 (observed, local, not an acceptance)

Setup: executables from the CI run 44092750956 at `a932218` (release, Windows for the computer, aarch64 Android inside the debuggable harness app for the phone; the phone on LTE behind a carrier NAT with a private interface address, Wi-Fi off, its own VPN not covering the app: the route lookup for the app's UID left through the mobile interface). The Server on the phone ran the public composed configuration with `publish_address: encrypted`; the Client on the computer held only the Server key and the address key file, then (attempt 2, the control) no key file.

- **Connection.** Both attempts delivered one exact payload (`shaar-live-pair-1` and `-2`, 17 bytes each way) from the computer through the phone's Server to its echo target and back, `session path=ygg-standby result=ok`. The path was Yggdrasil standby, not a direct one.
- **Encrypted address.** Not shown. Both route decisions printed `candidates=record:0,hint:0 resolve=timeout` after 0.8 s and 2.4 s. The code gives a lookup 1 s while a punch channel exists (`RESOLVE_BUDGET_WITH_PUNCH`), and its own comment records that a live lookup takes 6 to 10 s, so the first dial cannot use the record. A lookup that finishes later is kept for the next dial, but nothing in the logs says whether it finished or what it held, and the `candidates=` count of the punch line is the number of candidates the Client itself offers to the Server (`network/signaling/punch/mod.rs`), which rose from 0 to 1 in attempt 1 after its DHT reflexive window reported `info=some` and stayed 0 in the control where it reported `info=none`; it says nothing about the record. The control therefore does not separate the two cases.
- **Punch.** No direct path in either attempt: 43 punch outcomes on the four logs, all `fallback` (29 `reason=probe`, 14 `no-answer`), none `direct`. In attempt 1 the Client offered one candidate (its local port 53935) and the Server answered with its own (49142); both sides probed without a result. In attempt 2 the Client offered none, the Server answered 29 offers with its own candidate (38691) and the Client's probes of it failed. The cause is not isolated: the public address the DHT reports is paired with the local port, so a carrier NAT that remaps ports would make the probes miss (a likely reading, unproven).
- **Budgets.** Per attempt the phone's mobile-interface counters moved by at most 0.24 MB received and 0.18 MB sent (an upper bound for all apps); the computer's counter is machine-wide and cannot be attributed to the process. The Server ran 107 to 110 s, the Client 100 s under a hard limit; the app was uninstalled and the temporary keys deleted; two of three attempts were used.
### Fix cycle (decision of 2026-11-17, "давай чинить всё")

Scenario steps advanced: 1 to 4. Leaves, in order, each with CI proof and a live check:

| Leaf | Observable acceptance | Non-goals |
|---|---|---|
| FIX-1 `config set` pair | `shaar-server config set` can reach `publish_address: encrypted` with `address_key_file` in either order; `config check` and startup stay strict; the guide says how | Changing the sealing, the key format or any other setting |
| FIX-2 observability | The logs carry, as counts and timings only (no addresses, no keys): the late result of a record lookup (`record:N`), the number and outcome of direct attempts to record candidates, and whether each NAT kept the Mainline port (`port_preserved=yes\|no\|unknown`) | New proof infrastructure, address printing |
| FIX-4 live attempt | CI-built Windows and Android executables of the fix branch run the case; the attempt prints the new lines (this leaf comes before FIX-3 because FIX-3 needs its numbers) | More than eight attempts in all |
| FIX-3 record found and used | Chosen by the FIX-4 lines. Reading of the code before them: in attempt 1 the record was probably never found (a silent public candidate would have eaten the 3 s attempt, yet the punch phase ran every time), and the Client's DHT lookups failed repeatedly with `CandidateLimit` (the aggregate bound of 256 retained candidates of the owned profile of the pinned DHT crate). The fix is whichever cause the `record lookup` line names: the resource bound, the 1 s budget while punching, or an address key that cannot open the record | Waiting out the lookup before the first byte, longer attempt deadlines, changes of the DHT crate outside its pinned-patch process |
| FIX-5 direct path | Designed from the FIX-4 numbers: either a mechanism that learns the QUIC socket's external port with the existing arsenal and reaches a direct path through the phone's NAT, or the measured proof that the NAT maps by destination | A helper server, TUN, root, router changes |

Result of the live check after each leaf goes into the record below.

**Measurement of the computer's NAT (2026-11-17, before FIX-4; scratch scripts outside the repository).** From one fixed local UDP port, KRPC `find_node` and `ping` datagrams went to the public bootstrap host `dht.libtorrent.org` and to up to three nodes it returned (about ten datagrams in all, each node's `ip` field names the address it saw; ports only were printed). Result: one local port was seen as three different external ports by three different DHT nodes (two runs, five distinct external ports for five local ports, none equal to its local port), and the same local port kept the same external port toward the same host across two sockets. So the NAT in front of this computer maps by destination (symmetric) and does not keep ports. Consequences, stated as measured and not yet as proof for the phone: (1) the candidate the products offer, the DHT-voted public IP with the local QUIC port, is wrong on this computer for any peer; (2) a direct path between this computer and a peer behind a port-restricted cone NAT or another symmetric NAT cannot be punched at all, whatever the product learns; it needs a peer behind an address-restricted or full-cone NAT, and the peer's external port for its QUIC socket. The phone's NAT has not been measured yet (the phone left adb before the measurement).

**Attempt 3 (2026-11-17 17:30, CI-built executables of `f1b087c`, the first run with the new trace lines; attempt count in this cycle: 3 of 8).** Same setup as the first two attempts (Server on the phone with `publish_address: encrypted`, set with the new `config set` order `publish_address` first; Client on the computer with the key file). The exact payload crossed again over Yggdrasil standby. What the new lines show:

- **The record is never published.** In 70 s the Server printed `record publication outcome=failed:deadline` four times and `failed:resource:CandidateLimit` once. The publication bound in the code was 10 s, a live put needs longer, and the retries after 1, 2, 4 and 8 s keep the DHT budget (256 retained candidates of the owned profile of the pinned DHT crate) in use almost without a pause. So the earlier `record:0` was not "the sealed record cannot be opened" but "no record exists in the DHT".
- **The Client's lookups fail for the same two reasons.** The first `record lookup` ended `failed:deadline` at 10.0 s (`late=yes`); the next ones `failed:resource:CandidateLimit` after about 0.3 s each, while the Client's own publications (`failed:put`; the shared maintenance task publishes for both roles) and its reflexive windows used the same budget.
- **Both NATs rewrite the Mainline port.** `reflexive port mapping=changed` on the computer and on the phone.
- **Budget:** the phone's mobile interface moved by 0.12 MB received and 0.10 MB sent (an upper bound for all apps); the Server ran 71 s, the Client 100 s.
- **Checked live:** `config set publish_address encrypted` before `address_key_file`, then `config check`: ok (FIX-1).

Repair under way (FIX-3): lookup bound 30 s, publication bound 45 s, retry pauses 2, 10, 30 and 60 s. If `CandidateLimit` remains, the next step is to run the DHT operations of one node one after another (lookup before publication before reflexive window) and to decide with the owner whether the Client should publish at all.

**Attempt 4 (2026-11-17 19:08, CI-built executables of `08c382d` with the FIX-3 bounds; attempt count in this cycle: 4 of 8).** Same setup (fresh keys, Server on the phone on LTE, Wi-Fi off, the app's UID routed through the mobile interface and not the phone's VPN). The exact payload (`shaar-live-pair-4`, 17 bytes each way) crossed over Yggdrasil standby again; the route line printed `candidates=record:0,hint:0 resolve=timeout`. The longer bounds did not help; the record is still never published or found:

- **Server:** `record publication` ended `failed:resource:CandidateLimit` on the first try (`retries=0`, about 15 s after start, right after the two reflexive windows), then `DeadlineExceeded`, `DeadlineExceeded`, `CandidateLimit` (`retries=3`). Never `ok`.
- **Client:** 8 `record lookup` lines, none with `record>0`: `failed:policy` once (8.7 s), `failed:deadline` once (10.0 s), and `failed:resource:CandidateLimit` six times, **three of them after 0 to 39 ms**. A failure that fast cannot come from network traffic: the 256-holder budget was already used up when the lookup started, so something retains holders for good.
- **Both NATs rewrite the Mainline port** (`reflexive port mapping=changed` on both). No direct path: every punch outcome was `fallback` (`probe` or `no-answer`), the Client offered 0 candidates at first and 1 later.
- **Budgets:** the phone's mobile interface moved by 0.16 MB received and 0.14 MB sent in all (an upper bound for all apps; the interface was `rmnet_data3` this time); the computer's counter is machine-wide (+10 MB received, +41 MB sent in the window, other programs) and cannot be attributed to the Client, whose traffic mirrors the phone's. **Time bound broken by me:** the Client stopped at its 95 s limit, but I did not stop the Server in time; it ran about 2.5 minutes, past the 120 s limit. Traffic stayed far inside the budgets; the lapse is recorded here and the next attempts stop the Server by a fixed timer.

**Mechanism of `CandidateLimit` (read in the pinned-crate patch, now matched by the 0 ms failures).** One `StoreBudget` of 256 holders per DHT actor is shared by the bootstrap addresses, both routing tables (`routing_table.add_owned` reserves a lease per stored node), the candidate set of every query and the responders of every put. A response from a node not yet in a table calls `routing_table.add`; at 256 that sets `owner_error`, and `owned_note_response` then fails the operation that received the response with `CandidateLimit`. A live routing table grows with every distinct responder, so after the warm-up the tables alone can hold the whole budget and every following lookup, put or reflexive window fails. The existing tests encode this as the contract (`two_real_routing_tables_share_holders…` expects `CandidateLimit` from a full table). Not measured live: the holder count at the moment of failure (the counter is crate-private).

- **Correction (same day):** the first version of this record listed a defect "`address-key new` fails with a forward-slash Windows path". That was wrong. The scratch directory had not been created: a native Windows `mkdir -p` given an MSYS path made `D:\d\dev\…` instead, so the parent of the key file did not exist and the OS error 3 was correct; the retry succeeded because `client init` had created the directory in between. No such defect exists; the stray empty tree was removed. A missing parent directory is still reported only as a bare OS error, which is a message quality matter, not a defect of path handling.
- **Defects found on the way** (not fixed here): `shaar-server config set` cannot enable the encrypted publication, because `publish_address encrypted` is refused without `address_key_file` and `address_key_file` is refused while the mode is not `encrypted` (the file had to be edited by hand); the route line is printed once, so a late record resolution is invisible.

## Checkpoint format

First status line: `Distance to v1: accepted / active / not started / next / blockers`.
Use 5–8 short Session summary bullets, then exact live-operation IDs and state,
current SHA, task status, dirty-file custody, decisions and remaining gates.
Include restored P07 in the distance line and list each outstanding user decision
separately; neither scope restoration nor a pending public-run request is a pass.
Do not write a new acceptance claim merely to make the checkpoint look complete.
