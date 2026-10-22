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
| Real NAT traversal | future QUIC traversal test using the calibrated `nat-topology` rig | UDP fixture translation is confirmed below; authenticated QUIC candidate exchange and direct traffic across both NATs are not yet tested |
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
- The separate NAT topology calibration below is accepted only as a UDP
  fixture, not as evidence for QUIC traversal.
- Failures are investigated at root cause, **not rerun into luck**.

## 9. Controlled NAT fixture calibration

[Run 39781462112](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39781462112)
at `733351a402c9f1acc3b53e1c89db7fdb375ee8d0` passed the CI selftests and
all four fixture cases. The separate workspace
[CI run 39781462125](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39781462125)
passed at the same revision. The `nat-topology-out` artifact was downloaded
into an isolated directory and inspected as JSON data without executing it.

The normal case observed the following private-to-translated source tuples
at the WAN responder and correlated them with exact original/reply UDP
conntrack tuples (`unreplied: false`):

| Peer | Private source | Receiver-observed translated source | Destination |
|---|---|---|---|
| A | `10.0.1.2:40001` | `203.0.113.1:41013` | `203.0.113.10:41000` |
| B | `10.0.2.2:40002` | `203.0.113.2:41020` | `203.0.113.10:41000` |

Both positive controls, wrong-token delivery/classification, wrong-tuple
sink delivery/isolation, and forwarding-off controls passed. Case outcomes:

- Normal: exit `0`, evidence status `pass`, no failed controls.
- Setup fault: exit `1`, exact `setup-injected` phase after three namespaces;
  the fixture did not start.
- Fixture fault: exit `1`, exact injected exception recorded after responders
  became ready; owned child cleanup succeeded.
- SIGTERM: exit `143`, explicit `interrupted` control and signal reason
  recorded; owned child cleanup succeeded.

All four cleanup artifacts report `cleanup_failed: false`, zero remaining
namespaces, no surviving owned namespace processes or host interfaces, and
unchanged captured host firewall/forwarding state. No local fixture execution
or tests were used. The initial run `39781007420` passed selftests but failed
before topology setup on malformed shell-embedded Python; `733351a` fixed it
and added an embedded-source syntax regression.

This establishes a calibrated, bounded Linux CI topology only. It does not
prove QUIC hole punching, peer-to-peer connectivity across both NATs,
strict STREAM exclusion, migration, re-punching, Windows NAT behavior, or
production root/TUN independence. P03 remains **NOT PASSED**.

## 10. Exact backend gate boundary (source findings, not implementation)

The published `noq-proto 1.3.0` archive was downloaded separately and its
SHA-256 checked against the committed probe lockfile:
`7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f`.
Source inspection only; no downloaded source was executed locally.

The exact source boundaries are:

- `src/connection/mod.rs:1154-1231`, `scheduling_info`: `may_send_data`
  explicitly admits handshake early data and Backup fallback. It is not an
  application-payload-only permission.
- `src/connection/mod.rs:6080-6153`, `populate_packet`: that same flag also
  gates HANDSHAKE_DONE, ACK and ACK_FREQUENCY. Setting it to false for all
  signaling paths would suppress required control traffic; this is not the
  desired gate.
- `src/connection/mod.rs:6504-6516` and `6562-6568`: the production DATAGRAM
  writer and STREAM writer callsites are inside `populate_packet`, before
  encryption. A text search of the full source found no other production
  callsite of `write_stream_frames`; the additional call in
  `streams/state.rs:580-588` is a `cfg(test)` helper.
- `src/connection/streams/state.rs:621-648`: lost STREAM ranges and rejected
  0-RTT ranges return to the stream pending queue. The same guarded writer
  therefore owns fresh and retransmitted STREAM serialization. This is a
  source-level coverage observation, not a tested exclusion guarantee.
- `src/connection/mod.rs:2193-2229`, `space_can_send`, and `6950-6975`,
  `can_send_1rtt`: readiness includes pending STREAM/DATAGRAM data. A writer
  guard alone is inconsistent with this readiness. The assertion at
  `1730-1743` explicitly detects packets announced writable but producing
  only ACKs. Denied payload must not create write readiness or a busy loop.
- `src/connection/spaces.rs:144-158`: ACK/control readiness is separate from
  the stream/datagram checks and must remain available.

The next backend spike must separate **application-payload eligibility**
from existing control scheduling. Its immutable per-network-path policy
must be applied both before payload queue consumption and when calculating
payload readiness; denied STREAM ranges and DATAGRAMs stay queued under
existing bounded backpressure. The policy must apply during handshake,
not only after path validation. Application-path preference must consider
only application-eligible paths: an Available signaling-only path must not
shadow an eligible direct Backup path. Control-path preference remains a
separate decision. New eligible paths must wake pending sends; an all-denied
state must return without generating empty packets or spinning.

The iroh `QuicTransportConfigBuilder` wraps Noq configuration, while its
inner conversion is crate-private (`src/endpoint/quic.rs`). Exposing a new
backend policy therefore also needs an explicit iroh configuration bridge;
the current public `PathSelector` cannot install this enforcement.
Transport identity must be derived from iroh's address mapping, not inferred
from an unauthenticated peer's claimed address or a persistent `PathId`.

A source patch would preserve the single-connection QUIC design but add a
maintenance obligation across both Noq packetization and the iroh wrapper.
No patch, dependency fork, custom cryptographic protocol or production API
was integrated by this investigation. Before choosing that implementation,
its regression proof must cover: both peer directions; fresh and lost STREAM
ranges; 0-RTT and server early data; optional DATAGRAMs; successful control-only
bootstrap; all-denied quiescence/backpressure/cancellation; direct-path
appearance, loss and recovery; and packet/frame-to-physical-egress
correlation with positive and negative calibration. Neither the baseline nor
the UDP NAT fixture supplies that proof.

## 11. iroh configuration bridge and provenance limits

This is source evidence from published iroh 1.3.0, not runtime acceptance.
Two delegated drafts were rejected for unsupported security conclusions;
only the independently checked findings below are retained.

### Configuration installation

- `src/endpoint/quic.rs:93,130,147-168`: the transport builder and config
  wrap private Noq fields; `build()` stores the configured Noq value in an
  `Arc`. Adding a Noq method does not expose it through iroh automatically.
- `src/endpoint/quic.rs:262-265`: existing `send_fairness` demonstrates the
  minimal forwarding-method pattern. A spike-only `application_data_filter`
  forwarder can call the patched Noq setter and return `self`; that proposal
  is not yet compiled or installed in the probe.
- `src/endpoint.rs:1148-1168`: client connect selects an explicit per-connect
  transport config or the endpoint default, constructs a Noq client config,
  and calls `connect_with`.
- `src/socket.rs:249-272`: `StaticConfig::create_server_config` installs the
  endpoint transport config at line 257; `create_client_config` installs the
  selected client transport config at line 270. The actual Noq endpoint
  receives the server config at `src/socket.rs:1022-1027`.

An unconditional deny-all callback is a useful next bridge calibration: it
needs no address classification. It would prove configuration propagation
and payload/control separation only, not selective transport enforcement.

### Prefix, mapping membership, and transport authority are different

- `src/socket/mapped_addrs.rs:95-112`: synthetic address classification is
  syntactic. It does not establish local ownership or ingress provenance.
- `src/socket/remote_map.rs:105-125`: custom paths receive locally generated
  mapped tuples, but IP tuples pass through unchanged.
- `src/socket/transports/ip.rs:205-225` and `src/socket.rs:626-632`: inspected
  native receive branches retain arbitrary IPv6 source addresses; they do
  not reject synthetic address ranges.
- `src/socket/remote_map/remote_state.rs:1541-1555`: advertised IP and custom
  addresses are accepted as reachability input. Rejecting synthetic ranges
  only on native ingress does not address advertised IP routes.
- `src/socket/mapped_addrs.rs:315-376`: mapping keys are addresses, not
  transport-instance/generation capabilities. Existing keys reuse mappings;
  the map exposes no revocation or removal. Reverse lookup is not authority.
- `src/socket/transports.rs:1236-1255`: a custom mapped-address lookup miss
  drops the transmit. This does not authenticate a matching prefix or prove
  which transport generation owns an existing entry.
- `src/socket/transports/custom.rs:90-105`: local senders validate address
  applicability. A peer-supplied `CustomAddr` is not itself that validation.

Therefore the existing stateless `fn(FourTuple) -> bool` spike does **not**
supply an authenticated selective transport policy. A richer context naming
only peer identity and a coarse transport enum would not repair the missing
transport-instance/lifetime binding either. No secure classifier is adopted.
A future design must bind authorization to a locally owned transport instance,
address membership and lifetime; reject unknown/revoked bindings; cover native
and advertised-IP paths; and preserve that binding through packet dispatch.
Replacement or address reuse must not silently authorize queued ciphertext
for a different transport. Dynamic replacement remains unimplemented.

### Required evidence before selective adoption

Keep invalid ciphertext, valid peer migration, unauthorized transport origin,
and stale/reused mapping cases distinct. Changing receive address metadata
alone does not imply QUIC decryption failure. Recovery must drain the original
connection without a second application write; STREAM wire retransmission is
allowed, while exact application bytes and FIN remain mandatory.

Qlog tuple/frame metadata is not a physical-egress oracle. Correlation needs
an independently observed send boundary and full packet decryption material
or calibrated packet-identity instrumentation; header-protection keys alone
cannot decrypt payload frames. Neither this source investigation nor the
new oracle calibration closes P03.
