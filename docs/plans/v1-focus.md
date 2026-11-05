# V1 delivery focus and standing reminders

**Distance to v1:** P01–P06 and D1 are accepted; P08 is bootstrap-only; P09 is accepted at `b076458` (record below); P07 is restored to v1 but unaccepted and permission-gated; P10–P16 are not accepted as complete stages. Next: gated P07 (#224/#33/#34), then P10 #214/#215 and the full native/Yggdrasil matrix. Blockers include P07 source/lifecycle evidence, exact public-peer approval and public-network evidence, legal/notices and separately gated public smoke.

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

Do not expand a leaf beyond its recorded criterion. Pause and identify the actual
scope/dependency boundary before any split. No new product leaf is authorized by
this document while P09 remains open. Once native P09 and its applicable address
integration dependencies are accepted, proceed to existing permission-gated P07,
then start #214 after #33/#34 acceptance rather than another research or proof
campaign. P10, P13 and P16 must retain their P07 dependencies.

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
