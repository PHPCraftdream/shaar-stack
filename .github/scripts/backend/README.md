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

## Allocated connection metadata — pending CI

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

Authored tests use the real sans-I/O harness to hold a one-connection quota through
Draining and prove allocation becomes possible after Drained, plus a native zero-
quota dial requiring the exact typed error and no emitted Initial. Source-repeat
and clean/gate parity controls cover the same implementation. These additions are
not yet executed; CI is the only compilation/runtime environment.

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

`checks.py` runs only in CI. It compares all four patched Noq runtime files with
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
That production dependency delivery baseline and raw-ingress hardening are accepted;
the allocated-connection extension still needs its fresh CI proof. None is a working public SDK
networking API or selected-custom transport authority; those remain separate
implementation tasks. Yggdrasil integration's permission/lifecycle gate is unchanged.
