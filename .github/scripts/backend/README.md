# Reviewed backend source preparation

This directory owns the Noq 1.3.0 application-payload transformation and the
minimal iroh 1.3.0 configuration forwarder. P03's isolated fixtures import the
same functions, rather than maintaining a second production policy.

`prepare.py` consumes separately downloaded, reviewed archives and the pinned
probe lock as **data**. It checks all three complete SHA256 values and lock identities
before creating a fresh output directory, extracts each package separately with
the data filter, verifies package/version/license, and applies exact-count source
edits. It preserves the upstream license files. Existing destinations are refused;
preparation never overwrites a previous source tree. A failed preparation is not
usable; `provenance.json` is emitted only after all edits finish successfully.
No archive code is imported or executed by preparation.

The production source contains application readiness/eligibility, STREAM and
DATAGRAM writer checks, bounded empty-DATAGRAM accounting, the iroh forwarder and
an optional pre-accept incoming-budget bridge. The same-version Noq async wrapper
also receives counted raw-datagram ingress admission.
It does not add explicit path-open/disable-NAT hooks, a Transmit constructor,
fixture tests, or encrypted packet logging. Normal upstream qlog behavior is not
rewritten. Upstream versions and the original standalone lock remain unchanged.

## Pre-accept budgets for SDK endpoint work

Noq's incoming count and per-incoming/aggregate buffered-byte limits belong to its
listener configuration, before the SDK accepts a connection. The byte limits do
not include the first packet; count bounds that separate storage. An application
semaphore alone does not configure this earlier boundary. Noq defaults are 65536
pending entries, 10 MiB per-entry buffering and 100 MiB aggregate buffering.

The shared patch adds `Builder::incoming_limits(count, per_incoming, total)` and
stores the optional values in iroh's StaticConfig factory, including ALPN updates.
Omission preserves upstream defaults. Saturated Initials may be silently dropped;
this is not an authenticated access-denial response. The SDK still needs separate
handshake/active-connection/stream/task admission and lifecycle control.

This P06 prerequisite passed [CI 39886131924](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39886131924)
at `1b6506e` on Linux and Windows. Completed logs confirm both native tests passed
(two tests, zero failures; suite 12.64s/12.83s), with all companion workflows also
successful. The native test observes
and forwards a real complete Initial and checks incoming count 0/1 before accept,
both at bind and after an ALPN update. Positive admission with zero byte budgets
pins the first-packet exclusion; the external Noq config factory also checks byte
limit propagation. Preparation refuses a second listener patch without overwriting
source. Existing Noq queue-budget regressions remain part of backend CI. No new
metrics feature, dependency version or public SDK networking API is introduced.

## Raw datagram queue boundary

The async Noq wrapper used an unbounded channel to forward classified UDP events
to each connection driver (`endpoint.rs:982-991`), before connection flow control.
Its receive work limiter constrains scheduling work, not retained queue size. The
separate protocol-control producer (`endpoint.rs:658-668`) must not be treated as
raw datagram admission or have its lifecycle notifications silently discarded.

The owned `ingress_budget.rs` module and exact `runtime.py` transform bound pending
raw datagrams to 256 per connection and shared retained receive allocations to
8 MiB per endpoint. Metadata is separately bounded by the event-count cap. This
is not a claim about total RSS, kernel buffers, decoded stream windows, pre-accept
storage or all active/draining connections. SDK admission must cover those other
boundaries too. The Noq endpoint receive payload default is 1472 bytes, not 65527.

Admission charges `BytesMut.capacity()` for each actual receive allocation. GRO
slices share one memory lease until the last queued owner drops. Non-GRO packets
move a lease without an additional shared-owner allocation. Record and byte leases
return on processing, failed send, receiver drop and cancellation. Relaxed atomics
are accounting only; channel ownership transfer publishes packet data. Local and
protocol-control messages retain their existing reliable delivery path. Overload
drops whole UDP input, not selected STREAM frames: the original pre-encryption
payload gate is unchanged and still supplies signaling-only enforcement.

This extends source preparation to the already-used `noq` 1.3.0 archive, verified
against its immutable registry digest. Only its Cargo source identity changes to a
prepared path; no version is raised. Provenance records every owned patch source.
[CI 39905452421](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39905452421)
at `a001d2e` passed on both OSes: five ownership/budget/concurrency tests and two
native dependency tests passed, with strict warnings. Completed logs were inspected.
The companion Noq, clean-source/bridge and full NAT workflows also succeeded. Rust
1.99.1's renamed `try_update` API is used without suppressing the deprecated-method
error exposed by the first run. This verifies the ingress layer, not every SDK
resource contract.

## Allocated connection metadata

Protocol Draining does not release a Noq endpoint's ConnectionMeta entry; only
Drained removes it. Releasing an SDK active-session permit on `closed()` therefore
does not itself cap metadata retained during teardown. CID-space exhaustion is
also not a useful application bound for ordinary long connection IDs.

The patch adds optional `EndpointConfig::max_connections` at the actual Noq table,
with an iroh `Builder::connection_limit` bridge before bind. Omission preserves
upstream behavior. Capacity includes accepted, closing and draining connections
until Drained, but not the separately limited pending Incoming queue. Local dials
fail before I/O with a dedicated `ConnectError::TooManyConnections`, not an invented
CID/authentication failure. Excess incoming attempts are dropped early or receive
standard CONNECTION_REFUSED if capacity changes after Initial admission. The local
error variant is an intentional extension of the workspace-only patched Noq API;
no wire format, package version or public SDK API changes.

Tests use the real sans-I/O harness to hold a one-connection quota through
Draining and prove allocation becomes possible after Drained, plus a native zero-
quota dial requiring the exact typed error and no emitted Initial. Source-repeat
and clean/gate parity controls cover the same implementation.

Completed logs at `020d386` were inspected. On both Linux and Windows,
[Noq CI 39910571447](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39910571447)
passed 17 gate tests and the full 444-test suite, including the Draining/Drained
regression. [Workspace CI 39910571177](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39910571177)
passed five ingress-budget tests and all three native dependency tests per OS;
the native suites took 12.64s/12.83s. The exact local quota error/no-Initial test
passed on both OSes. The corrected bridge reads the local StaticConfig owner
before it moves into EndpointInner, without widening visibility or changing limits.
The companion bridge and NAT watchers completed successfully; their latest detailed
logs and artifacts have not been re-inspected. CI remains the only compilation and
runtime environment; this accepts the metadata prerequisite, not the SDK endpoint.

## Joined actor shutdown

The later SDK matrix at `c20503d` again exposed an immediate UDP-rebind failure on
Linux (40 library tests passed, one failed; Windows succeeded). The Noq sender
release alone does not cover every native I/O owner. Inspection also found that
iroh's 100 ms actor grace timeout consumed an AbortOnDropHandle: timeout aborted
the actor but did not join its destructor. That is a definite shutdown gap and a
candidate mechanism for the observed intermittent socket retention; its occurrence
in that particular failed run was not logged, so it is not claimed as proven.

The owned `actor_shutdown.rs` helper retains the handle across the same 100 ms
grace, explicitly aborts on timeout and then awaits termination. Both production
and instrumented bridge preparation install the identical module and call it
outside the actor-task mutex. Source repeat/overwrite guards and provenance include
the helper. No data-path policy, shutdown grace or native-port assertion is weakened.

The SDK integration binary compiles this same helper with three tests:
graceful completion, forced timeout/abort with immediate UDP rebinding, and panic
propagation after resource drop. The timeout case runs on a current-thread runtime,
so abort without join cannot be hidden by another executor thread. The test ports
are dedicated ports outside the standard ephemeral ranges, not repeated retry binds.
[CI 39936878051](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39936878051)
at `4259f43` passed on both OSes; completed logs were inspected. The three actor
cases passed in the dedicated preflight (0.10s/0.11s), and again in the six-test
backend binary (three native dependency cases plus those three actor cases).
The unchanged immediate SDK UDP rebind, 41 library tests, three public SDK matrix
cases, five ingress tests and 88 Python guards also passed per OS. Known-fixture
output scans were clean. Companion Noq/bridge/NAT watchers succeeded; their latest
detailed artifacts were not re-inspected. See the
[SDK acceptance boundary](../../../crates/shaar/src/network/README.md#consolidated-p06-acceptance).

An exact dev-only n0-future 0.3.2 dependency reuses the existing resolved package;
the lock changes only the SDK edge, not any package version/source/checksum.
Its current SHA256 is `87f2ac01c1077ee86901e05ad5883ddd39f38c0eff5c04d7ef9b3a2e55b18632`.
No downloaded code ran locally.

### Nested peer actor destruction

The later `e907c04` [workspace run 39962623899](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39962623899)
failed the public sixteen-stream server UDP rebind on Ubuntu (`AddrInUse`, line
234); Windows passed. Joining the parent actor is not sufficient: its RemoteMap
owns a JoinSet whose drop requests child abort without waiting for child future
destruction. Peer inboxes and pending SendDatagram futures can own native senders.
This is a confirmed source ownership gap, not a traced sole cause of that run.

Preparation now shares the existing native Runtime TaskTracker with peer actors.
A child is tracked **before spawn**; its lease survives until its entire future
is destroyed, including queued messages and pending sends. Parent shutdown still
uses the same 100 ms grace and abort/join; the existing runtime shutdown then waits
for child destruction too. No extra task, channel, per-packet allocation, lock or
shutdown sleep is added. Browser behavior is unchanged and is not newly accepted.

The identical owned `track_child` helper is compiled in the SDK regression binary.
Two added tests cover unpolled/pending child leases and parent graceful exit,
forced abort and panic with immediate native rebind. A pending tracker-wait check
is a deterministic negative control against removing the child lease. Original
public SDK rebind assertions remain unchanged. At `ae16803`, actual completed
[CI 40112714369](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40112714369)
logs confirm both OSes passed five actor preflight cases (0.10s/0.11s), eight backend
cases (five actor plus three native), all three public SDK cases including the
original immediate rebind, and all 41 SDK library cases. The P08 executor/codec
primitives each passed six tests per OS; these are not live carrier acceptance.
Ten P08 Python controls, four lease tests, five ingress tests and 88 structural
controls passed; fixture output scans were clean. All companion watchers succeeded.
The dev-only tokio-util 0.7.20 edge reuses the already resolved reviewed package;
no package version, source or checksum changes.

## Explicit preparation, not a build script

Run the script from the repository root, with Python isolated mode:

```text
python -I .github/scripts/backend/prepare.py --noq-archive <archive-dir>/noq-proto.crate --iroh-archive <other-archive-dir>/iroh.crate --runtime-archive <runtime-archive-dir>/noq.crate --lock .github/probes/iroh-paths/Cargo.lock --destination target/backend
```

Archive acquisition is a separate bounded HTTPS operation; the script does not
fetch from the network and is never called by `build.rs`. All actual dependency
compilation and runtime checks in this project run in GitHub CI, not locally.
Keep downloaded archives, extracted sources and maintained scripts separate.

Trade-off: this unpublished source workspace needs an explicit preparation stage
before Cargo can consume the patched dependencies. It avoids a new public fork,
package publication, checked-in upstream source copies and network-dependent
build-script rewriting. The generated third-party trees are dependency artifacts,
not a way to hide maintained project code from its 700-line/7-item rules. Our
maintained patch scripts and tests remain subject to both limits.

## Verification and current integration boundary

`checks.py` runs only in CI. It compares all six patched Noq runtime files with
the spike's output, requires original bytes for the packet builder/qlog and other
untouched iroh files, checks absence of fixture hooks, and exercises checksum,
size, lock, source-anchor and existing-destination failures. It also prepares a
clean calibration package using the same-version standalone lock. Linux/Windows
CI compile the clean sources and run the real constant deny/allow iroh control
and payload calibration, separately from instrumented wire/NAT fixtures.

[Run 39871119928](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39871119928)
at `3bcd2f6` passed on Linux and Windows. Each OS ran five preparation checks,
18 unit tests and one real deny/allow calibration against the clean sources;
completed job logs were inspected. The instrumented bridge matrix, Noq regression,
workspace CI and physical loss/re-punch regression also completed successfully.

### Verified product lock and dependency test

[Run 39875127492](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39875127492)
at `043b222` passed the staged product workspace on Linux and Windows, including
formatting, clippy and the real native dependency test. Completed logs and both
lock artifacts were inspected. The Linux/Windows locks are byte-identical (SHA256
`2a2ae5b3f1f02df6f767a348562034d14974d1b14cb874fc93332e336704080e`).
All 120 previous registry package identities/checksums are retained; the additional
network dependency closure comes from the reviewed pinned graph. No project or
existing dependency version was raised. The backend family remains exactly 1.3.0.

The actual workspace now adopts that verified lock and the same iroh dependency.
Its root `[patch.crates-io]` entries point to the prepared sources under
`target/backend/{iroh,noq-proto}/`. Preparation is mandatory **before any Cargo
command that resolves the workspace**, including formatting or clippy. A missing
prepared source fails; there is no silent fallback to stock upstream. Main CI
prepares fresh sources before its ordinary `--locked` checks. The temporary
workspace-copy/resolution tool has been removed; normal CI does not regenerate
the committed lock.

The owned test is now `crates/shaar/tests/backend_gate.rs`. It uses real loopback
UDP and public synthetic Ed25519 fixtures, verifies peer identity, control-only
handshake, both payload directions, bounded backpressure, reset and shutdown,
with constant deny/allow calibration. It uses no probe transport or qlog hooks.
RESET_STREAM is allowed control: it can expose lower stream IDs without STREAM
bytes. The test first checks both no-delivery directions, then verifies lower-ID
non-delivery and the exact peer reset code while STREAM/DATAGRAM counters stay zero.
The earlier failure was a fixture interleaving mistake, not a reason to weaken the
payload gate. Full dependency graph resolution and immutable-identity guards also
passed before adoption; `--no-deps` metadata alone was correctly rejected as proof.

Actual-workspace adoption at `6a33fdf` passed Linux/Windows
[CI 39876917468](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39876917468):
formatting, clippy, tests and structural checks, including the native/reset gate
(1.20s/1.37s) and the explicit Linux unprivileged key-reader probe. Completed logs
were inspected. The final
[QUIC regression 39879270527](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39879270527)
at `78a0097` passed all seven topology cases after observer/capture fixes: 126/126
native observations, zero kernel drops, no truncated frame, full ciphertext
correlation, zero custom payload and clean owned-resource teardown. Its artifacts
were independently inspected; legacy NAT and current workspace CI also passed.
The production dependency delivery baseline, raw-ingress hardening and allocated-
connection metadata quota are accepted. None is a working public SDK networking API
or selected-custom transport authority; those remain separate
implementation tasks. Yggdrasil integration's permission/lifecycle gate is unchanged.
