# iroh paths probe (P03) — narrowed baseline substage report

Status: **P03 NOT PASSED.** The narrowed custom-only baseline passed in
[CI run 39764087035](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39764087035)
at commit `7bd6bf7449426072c51536916a221e11e7abfd5c`: 13 unit tests and
one integration test passed, with no ignored tests. The integration test
completed in 0.05 seconds. The generated lockfile was inspected and committed
in `b948555`. [Locked-mode run 39764775361](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39764775361)
then passed the same 13 unit tests and integration test (0.06 seconds), with
an explicit `LOCKED mode` log and clippy/tests using `--locked`.
Strict signaling-only enforcement, migration, and real NAT traversal remain
unproven; this result does not close P03.

## 1. Scope of the substage

The reworked probe package (`.github/probes/iroh-paths/`) contains exactly:
`src/{lib,mem_transport,mem_tests,harness,qlog_oracle}.rs`,
`tests/baseline_custom_only.rs`, `ci/ensure-lockfile.sh`, `Cargo.toml`, and
`Cargo.lock` (no `[[bin]]`). It has queue/oracle/admission unit tests and one network
integration test. The latter covers:

- **Custom-only authenticated bootstrap** — a QUIC connection established
  exclusively over an in-memory custom transport, with authentication.
- **Stream echo** — 4 echo roundtrips over a bidirectional stream
  (real accept loop, sequential handling per connection, shared admission
  cap of 8 active stream handlers, single Router consumer).
- **Transport-level counters** — wire-level sent/received byte counters and
  delivered counters observed at the in-memory transport boundary.
- **Scoped qlog positive calibration** — the client-side qlog trace must
  show SENT STREAM frames, proving the oracle detects STREAM activity.

### What was REMOVED from the earlier draft, and why

- **All-packet blackhole phase gate** — removed. It was not an atomic wire
  boundary and it modeled the **wrong contract**: an all-packet gate
  blackholes handshake/ACK/retransmission frames too, so noq sees pure loss
  and the connection cannot bootstrap or survive; and retransmits queued
  before a reopen may egress after reopening. It never implemented
  "signaling-only STREAM exclusion" — only "everything off".
- **Migration tests** (`migration_candidates`) — removed rather than left
  broken.
- **Strict-policy tests** (`strict_policy`) — removed. The strict
  signaling-only requirement remains **UNPROVEN** and blocks dependent
  implementation.
- **NAT stage** (`ci/nat-netns.sh`, role binary `main.rs`, `nat-netns`
  workflow job) — removed.
- Removed files: `src/main.rs`, `src/gate.rs` (gate logic),
  `tests/migration_candidates.rs`, `tests/strict_policy.rs`,
  `ci/nat-netns.sh`.

This baseline is **not an acceptance badge**. P03 remains not passed.

## 2. Confirmed defects fixed in the rework

- `std::task::Waker` misuse (fixed).
- Owned vs referenced `Waker` mismatch (fixed).
- `MemTransport::new` vs `MemNetwork` constructor mismatch — transport
  creation now goes through `MemTransport::pair()`.
- Single-stream echo stall — now a real accept loop with a single Router
  consumer; streams are handled sequentially within each connection.
- Address publisher lifetime — the memory transport factory previously
  owned the only `Watchable`, while its bound endpoint retained just a
  watcher. Dropping the factory disconnected the local-address watcher.
  Run `39759803806` exposed repeated `local addr watcher stopped` warnings;
  iroh 1.3.0's socket actor keeps polling that disconnected branch without
  disabling it, creating a busy loop. Commit `7bd6bf7` retains the publisher
  in the bound endpoint and adds a regression that drops both factories,
  verifies a connected/pending watcher, then verifies disconnection only
  after endpoint destruction. Both the regression and baseline passed in
  run `39764087035`.
- Silent full-queue drops — now bounded backpressure: packet capacity 64,
  at most 64 distinct waiting wakers per lane (deduplicated with `will_wake`),
  and registration under the same short mutex as dequeue. Draining wakes all
  admitted writers outside the lock; an excess waiter gets an explicit error.
  No lock spans an await. Small receive buffers retain the undelivered packet.
- Echo admission now uses a drop guard, releasing capacity on errors and
  cancellation, not only after a successful copy.
- qlog oracle defects — merging of traces, direction confusion, and
  defaulting absent `path_id` to 0 are fixed: per-file `ConnectionTrace`,
  sent/received separated, absent `path_id` tracked separately and never
  folded into path 0; colliding-ID fixtures added.

## 3. Mechanism findings

All observations pinned to iroh/noq **v1.3.0**.

### 3.1 iroh v1.3.0 source paths

- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/socket/transports.rs
- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/socket/transports/custom.rs
- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/socket/biased_rtt_path_selector.rs
- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/endpoint.rs
- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/endpoint/quic.rs
  (public `qlog_from_path`)
- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/endpoint/presets.rs
- https://github.com/n0-computer/iroh/blob/v1.3.0/iroh-base/src/endpoint_addr.rs

### 3.2 noq path scheduling

Tag `noq-v1.3.0` resolves through tag object
`2ce5a20df1f08b3b0c1d61dffa969d6cd9a10a28` to commit
`c1f411562e6078852749b8bcf1190523096a107f`.

- `PathStatus` has only `Available` and `Backup`:
  https://raw.githubusercontent.com/n0-computer/noq/noq-v1.3.0/noq-proto/src/connection/paths.rs
  The docs explicitly state **Backup sends when no Available path exists**.
- `scheduling_info` (~line 1154):
  https://raw.githubusercontent.com/n0-computer/noq/noq-v1.3.0/noq-proto/src/connection/mod.rs
  A validated Backup path has
  `may_send_data = !have_validated_status_available_space`; during the
  handshake it may send without validation (0RTT/0.5RTT). Backup is a
  **priority/fallback tier, NOT a no-data tier**. `PathSchedulingInfo`
  (~line 7300, same file) is private.
- **Direction correction** (explicitly correcting the earlier report): noq
  produces Transmits which **iroh sends** — not the reverse. The earlier
  report's reversal of this direction is wrong.
- `set_priority` affects **stream ordering**, not path affinity; there is
  no per-stream transport restriction:
  https://raw.githubusercontent.com/n0-computer/noq/noq-v1.3.0/noq/src/send_stream.rs

### 3.3 KEYLOG CORRECTION (retraction)

The earlier report's "keylog not wired in iroh 1.3.0" assertion is
**RETRACTED**. iroh v1.3.0 DOES have key logging:

- Public `Builder::keylog(bool)` (~line 742):
  https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/endpoint.rs
- `make_client_config` / `make_server_config` set
  `rustls::KeyLogFile::new()` when enabled:
  https://raw.githubusercontent.com/n0-computer/iroh/v1.3.0/iroh/src/tls.rs

For a **FUTURE** wire-decode oracle: CI sets `SSLKEYLOGFILE` before process
start and the builder calls `keylog(true)`; never call `std::env::set_var`
after Tokio starts; synthetic test keys only. The workflow already exports
`SSLKEYLOGFILE` pointing at `target/iroh-paths/sslkeylog.txt` for this
future use. For this substage **qlog is enough**; wire decoding was NOT
done and is not claimed.

### 3.4 qlog oracle scope

Per-file identity + direction + no path-0 defaulting. The custom-only
calibration is valid because the topology has a single transport; it does
**NOT** prove multipath egress attribution. Directory-loading regression
fixtures collide on path 0 while keeping client/server identities separate;
a valid non-`.qlog` file checks the extension filter.

The entire baseline, including bind and shutdown, uses one absolute deadline.
Connection handles are dropped and both endpoint/router drivers shut down
before the trace directory is parsed once; there is no file-polling sleep loop.
This ordering is based on pinned source and was exercised successfully by
the custom-only integration test in run `39764087035`:
- [iroh socket close](https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/socket.rs#L1129-L1188)
  waits for draining and then joins the endpoint/connection drivers.
- [Router shutdown](https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/protocol.rs#L427-L451)
  joins its run task and closes its endpoint.
- [Noq file factory](https://github.com/n0-computer/noq/blob/noq-v1.3.0/noq-proto/src/config/qlog.rs#L134-L173)
  creates `.qlog` files through a `BufWriter`.
- [n0-qlog 0.2.0 streamer](https://github.com/n0-computer/n0-qlog/blob/7deeea19303dd032b944696af7bd4890e6d0c31e/src/streamer.rs#L390-L394)
  flushes through `finish_log` on drop.

Transport counters count encrypted datagrams; exact plaintext echo equality
is asserted by the application stream helper, not inferred from those counters.

## 4. Narrow conclusion

The current single-connection `PathSelector` sketch **cannot guarantee
STREAM exclusion** merely by Backup/`none()`:

- `Backup` is a priority/fallback tier that **still sends**.
- `none()` only keeps the current selection; it never denies.
- Retransmits follow noq scheduling, not iroh path policy.
- Opaque encrypted custom datagrams cannot safely filter frames at the
  iroh transports layer.

This is **not** a proof that every possible backend extension or
architecture is impossible.

## 5. Future engineering directions (design sketches only — NOT implemented here; no dependency fork, no new public repo, no silent weaker policy)

**(A) Backend-local application-data eligibility hook.** A minimal hook
invoked BEFORE packetization in the backend/transport layer, which still
permits QUIC negotiation/ACK/NAT frames but refuses carrying application
STREAM data on the signaling transport. Requires upstream/noq-side design,
because frame-type knowledge exists only inside noq before encryption.

**(B) Separate authenticated signaling protocol.** A genuinely separate
authenticated signaling protocol running on the correct UDP socket — its
own handshakes and messages, independent of the QUIC data connection.
Requires separate design.

**Liveness explanation.** An all-packet gate blackholes handshake, ACK,
and retransmission frames too, so noq sees pure loss and the connection
cannot bootstrap or survive on that path. Additionally, reopening a gate
risks previously queued retransmits (including old application data)
egressing after reopen — a further reason the gate approach was rejected.

## 6. PENDING items

Each item: what / where / why blocked.

| What | Where | Why blocked |
|---|---|---|
| Direct UDP migration | probe package (removed `tests/migration_candidates.rs`) | depends on unproven strict signaling-only; removed rather than left broken |
| Real NAT traversal | removed NAT netns stage | the old script did not establish observed address translation; a controlled NAT rig must prove translation, not merely separate namespaces |
| Direct-loss phase | probe (future) | blocked on a verified strict signaling mechanism; neither direction A nor B has been selected |
| Repunch phase | probe (future) | blocked on direction A or B; old-data/retransmission risk unsolved |
| Hard signaling-only enforcement | probe / production transport | frame-type knowledge only inside noq pre-encryption; needs upstream design |
| Multipath egress attribution | qlog oracle | current calibration is single-transport only; does not attribute egress across paths |
| Wire-decode keylog oracle | harness (future) | `keylog(true)` + SSLKEYLOGFILE wiring prepared but decoder not implemented |

There are **no `#[ignore]` tests** and **no mock passes** anywhere.

## 7. CI and locking

- One baseline job (`baseline`); no NAT job, no independently re-resolved
  lock job.
- Artifact uploads (`cargo-lock`, `qlog-traces`) with `if: always()` so
  failures still yield evidence.
- Bootstrap lock resolution ran only in CI. The `cargo-lock` artifact from
  successful run `39764087035` was inspected as TOML data and added unchanged
  as the standalone `Cargo.lock`. All external packages use crates.io
  registry sources; there are no external path or Git dependencies.
- Resolved pins: iroh/iroh-base `1.3.0`, noq/noq-proto/noq-udp `1.3.0`, Tokio
  `1.54.1`, and diagnostic tracing-subscriber `0.3.20`. Tokio `1.54.0` was
  yanked; its replacement was user-authorized. Exact Noq family constraints
  prevent the incompatible `noq 1.4.0` / `noq-udp 1.3.0` resolution observed
  during bootstrap.
- Locked-mode repeat `39764775361` at `b948555` printed `LOCKED mode` and
  passed clippy/tests with `--locked`; subsequent runs retain that contract.
- No production Cargo/lock/CI files touched.
- Rust **1.99.1**; `permissions: contents: read`; checkout
  `persist-credentials: false`.

## 8. Limits of the baseline evidence

- Everything is same-host (in-memory transports), not a NAT topology.
- Successful run `39764087035` exercised fmt, clippy, 13 unit tests and the
  custom-only integration test. Assertions cover four exact plaintext echo
  roundtrips, selected custom path, bidirectional encrypted datagram flow,
  and client-trace sent STREAM positive calibration after shutdown.
- No local compilation/tests were run for this baseline investigation;
  local validation was limited to formatting and syntax checks.
- Passing this topology does not establish production shutdown safety,
  concurrent stream service, multipath attribution, or STREAM exclusion.
- The parallel NAT topology calibration fixture is not yet accepted and is
  not evidence for QUIC traversal.
- Failures are investigated at root cause, **not rerun into luck**.
