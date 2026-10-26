# Sha'ar Stack v1 Security Verification Plan

Status: foundation/configuration CI and identity functional checks pass;
[the SDK evidence](sdk-foundation.md) lists exact results and open cases.
**No complete security control below is marked passed by that functional run.**
Each control remains a commitment with its own observable acceptance outcome. Invariant references are I1…I10 from
`docs/architecture/threat-model.md`. The oracle is always external observation (a log with
a failure code, a connection counter, inspection of the network path, resource metrics);
"tests that test their own constant" and mock-success oracles are forbidden.

Revised: 2026-10-22 — the Yggdrasil transport is reconciled to the native Rust
backend (crate `yggdrasil` 0.3.1, pinned commit c9a54f1587bb133a06072596484c972a336db0d2);
Go/cgo is removed; the SEC-FFI section now covers the native adapter boundary.
P03/SEC-PATH remains a blocking gate and is not passed.

Stages: **CI-unit**, **CI-integration**, **P03** (blocking custom transport experiment),
**NAT rig**, **manual rig**.

## Authentication and access

**SEC-AUTH-01 — server impersonation** (I5 adjacent, known-key §5)
- Steps: the client connects to an endpoint impersonating the server, with a different key
  (valid self-signed, not pinned).
- Expected: a *known-key* verification error **before any application data is sent**.
- Oracle: a known-key failure code and zero STREAM on the decoded-frames oracle of the
  SEC-PATH section until failure. An encrypted capture is insufficient. Stage: CI-integration.

**SEC-AUTH-02 — unauthorized client** (I1)
- Steps: an unknown key connects to the server.
- Expected: authentication failure; the target receives zero TCP connections.
- Oracle: connection counter on the test target == 0; log with an allowlist failure code.
  Stage: CI-integration.

**SEC-AUTH-03 — authorized client** (I1, positive control)
- Steps: a key from the allowlist connects and transmits data.
- Expected: exactly one TCP connection to the target after key verification; data delivered.
- Oracle: target counter, echoed data. Stage: CI-integration.

## DHT and untrusted frames

**SEC-DHT-01 — corrupted pkarr signature** (I6)
- Steps: a record in the test DHT with a broken signature.
- Expected: the record is discarded; no panic; no connection is opened to the record's address.
- Oracle: rejection counter; absence of outbound connections. Stage: CI-unit.

**SEC-DHT-02 — size limits and malformed frames; stream fragmentation** (I6, I8)
- Positive: (a) a frame/datagram of exactly the maximum permitted length of the
  corresponding layer passes fully and matches byte-for-byte (positive boundary control);
  (b) frames arriving via partial reads/writes (correct transport stream fragmentation)
  are valid and reassembled correctly.
- Negative: MTU+1 (above the permitted maximum), length overflow, a declared length larger
  than the number of bytes actually received, a truncation inside the header/before the
  length — rejected without desync and without unbounded memory allocation. Zero length —
  per the protocol's requirement (a QUIC packet cannot be empty), not as a universal
  "any zero buffer in any call is an error" without a contract. The datagram upper bound
  (MTU path) and the permitted application frame length do not have to be one number —
  the consistent limit of the corresponding layer is verified.
- pkarr: a record above budget (the limit is a contract confirmed by P01, applied per the
  actual structure/field budget and record overhead) is discarded.
- Expected: rejection on size/validity boundary; bounded buffers; a fragmented valid frame
  and a maximum-length frame are delivered whole, byte-for-byte.
- Oracle: memory peak metric; failure log; byte-for-byte match of delivered data at the
  boundary and of the fragmented frame. Stage: CI-unit.

**SEC-DHT-03 — replay of a stale record** (I6)
- Steps: replay of a valid but stale signed record (old timestamp/seq).
- Expected: rejected as not fresh; a fresh record of the same key is accepted.
- Oracle: accepted/rejected counters. Stage: CI-unit.

**SEC-DHT-04 — DHT failure** (I7)
- Steps: the DHT is unavailable/returns garbage at startup and during operation.
- Expected: degradation (no address), not a panic; bounded retry with backoff.
- Oracle: a finite number of attempts in the log; process alive. Stage: CI-integration.

## Configuration and secrets

**SEC-CFG-01 — malformed ktav config** (I2)
- Steps: each class of incorrectness (unknown field, non-local target, external
  listen, missing allowlist).
- Expected: failure **before network startup** (not a single socket), the message names the field.
- Oracle: exit code/log before ports are opened (netstat/socket counter). Stage: CI-unit.

**SEC-CFG-04 — valid ktav config: successful run up to end-to-end echo** (I2, positive
control)
- Steps: a CI-integration run — a valid ktav 0.8 config with test keys/
  allowlist (ktav 0.8.* syntax, no invented fields), a controlled endpoint and target;
  the client listener actually accepts a local TCP connection; an allowed client sends a
  known payload; the target receives it and returns a response; the client receives the exact
  bytes back.
- Expected: end-to-end payload echo; the parser unit test remains a separate, narrower
  control and does not replace this one — an open socket or a startup log alone is
  insufficient.
- Oracle: exact payload bytes on the target and on the client (echo); a real TCP connection
  on the listener. Stage: CI-integration.

**SEC-CFG-02 — secrets not in logs** (I4)
- Steps: negative runs (SEC-CFG-01, SEC-AUTH-01, SEC-FFI-04) with Debug logging at
  maximum.
- Expected: no seed, no private keys, no hex/base64 fragments of secrets.
- Oracle: grep of CI artifacts for known byte/hex representations of the secret.
  Stage: CI-unit + artifact control.

**SEC-KEY-01 — atomicity of create_new; loading existing** (I3)
- Steps: (a) create_new when the file exists; (b) two concurrent create_new calls;
  (c) a normal startup with an existing valid key.
- Expected: (a) failure without modifying the file; (b) exactly one success; (c) the key **is
  read and loaded**, the file is not modified — a repeated normal startup is not rejected. A
  failure is required only when attempting to create over an existing file and on concurrent
  creation.
- Oracle: file contents/inode unchanged in (a); result of (b) — one error;
  (c) successful load + no write to the file. Stage: CI-unit.

**SEC-KEY-02 — key file permissions at creation** (I4)
- Steps: key file creation on Unix and Windows; in a test build — a controlled pause
  between open and the first write.
- Expected: Unix — mode 0600 set at creation (O_EXCL with mode / umask) without a
  create→write→chmod window; Windows — an ACL restricting access to the owner, set at creation;
  a read attempt by another unprivileged principal during the pause and after the write is
  denied. Explicitly: absolute protection against root/admin/OS compromise is not promised (§3
  threat-model, out of scope).
- Oracle: stat/ACL immediately after creation; the result of a negative read attempt by another
  principal in a test build. Stage: CI-unit (per-OS job).

**SEC-KEY-03 — no secret in Debug** (I4)
- Steps: `format!("{:?}", …)`/Display of all key types in a test.
- Expected: a redacted representation, not secret bytes/hex.
- Oracle: grep of the output for secret representations. Stage: CI-unit.

## Concurrency, resources, life cycle

**SEC-CONC-01 — half-close in both directions** (I8)
- Steps: (a) the client sends a request and performs shutdown(write side) — the target receives
  an EOF and continues to send the response; the entire response up to EOF arrives back; (b) a separate
  scenario: the target sends the response/part of the data first and performs shutdown on its
  write side; the client sees EOF on read but **then continues writing** to its own
  TCP direction; the target continues reading and receives all subsequent bytes until the
  client's EOF. Purpose of (b): it catches premature closing of the remaining half of the
  connection upon receiving a FIN from the target side — "the server performed shutdown" by itself is
  insufficient. (c) the client disconnects mid-transfer; (d) server shutdown with active sessions.
- Expected: both directions (client→server half-close and server→client half-close) are
  verified by separate runs; the QUIC FIN is carried correctly in each direction;
  all tasks finish, descriptors are returned, shutdown without hangs.
- Oracle: task/fd counters before and after == baseline; the received EOF and the full
  response/continued writing on the opposite side; a timeout test for "no hangs". Stage: CI-integration.

**SEC-CONC-02 — stream isolation under reset/timeout** (I8)
- Steps: one QUIC stream of a session receives reset/timeout.
- Expected: neighboring active streams of the same QUIC session keep working and are not
  closed; the failure is isolated to the stream.
- Oracle: data on neighboring streams is delivered after the failure; a log with a failure code
  only for the affected stream. Stage: CI-integration.

**SEC-RES-01 — slow client** (I8)
- Steps: a client reads with artificial delay / does not read at all, several such clients.
- Expected: bounded queues, stage deadline, connection rejection instead of memory growth.
- Oracle: RSS/buffers bounded; new connections receive an explicit rejection, not silence.
  Stage: CI-integration.

**SEC-RES-02 — connection/stream storm** (I8)
- Steps: exceeding the connections/streams limit.
- Expected: rejection above the limit; existing sessions unaffected.
- Oracle: admission counters, limit errors in the log. Stage: CI-integration.

**SEC-RES-03 — slowloris against absolute deadlines** (I8)
- Steps: the client sends one byte before each idle timeout, keeping the
  handshake/frame phase alive.
- Expected: activity does not extend the **absolute** handshake/frame deadline — the connection
  is terminated by the absolute deadline regardless of traffic.
- Oracle: connection lifetime ≤ the absolute deadline; a log with a deadline failure code.
  Explicitly: SEC-RES-01 (a single slowly reading client) does not prove this.
  Stage: CI-integration.

**SEC-FAIL-01 — relay/Ygg path failure** (I7)
- Steps: injection of Ygg path and relay failure in every phase (before direct, during
  operation), including drops/delays/garbage from the relay.
- Expected: path degradation, bounded retry with backoff, no panic and no memory growth.
- Oracle: attempt log (finite number), resource metrics. Stage: CI-integration.

## Data path (P03 — blocking experiment)

Common to SEC-PATH-01/02/03: the oracle is a *decoded-frames oracle*: decoded QUIC frames
with unambiguous attribution to the actual egress path/transport (a test-only hook before
encryption with path metadata, or a test-only keylog + capture + provable decoding). Observing
encrypted packets and the STREAM route does not distinguish from CRYPTO/ACK/negotiation and is
not an oracle by itself. Availability of the hook/keylog in the chosen iroh version is a
condition that P03 confirms; its existence is not asserted. Sensitivity calibration is
mandatory: a positive control — an explicitly permitted STREAM through a custom path must be
detected as a violation; a zero result without calibration is not
proof. Each control is run in all three phases (before direct, during direct failure,
after reconnect) and both modes (signal/standby); app-level data undelivery does not
prove absence of STREAM on the wire. With an insufficient oracle, P03 under I5 remains
**not passed** (gate).

**SEC-PATH-01 — relay before direct** (I5)
- Steps: the establishment phase before a direct path appears; pumping application data;
  runs in signal and standby modes.
- Expected: decoded frames on the signaling path — signaling only (candidates/
  negotiation), zero STREAM; a calibration STREAM on the custom path is detected.
- Oracle: decoded-frames oracle (see above), frames attributed to the egress path. Stage: P03.

**SEC-PATH-02 — relay during direct failure** (I5)
- Steps: breaking the direct path in an active session (fake injection); runs in signal/standby.
- Expected: the session switches to Ygg standby or tears down; zero STREAM through the relay.
- Oracle: decoded-frames oracle against the actual egress path. Stage: P03.

**SEC-PATH-03 — relay after reconnect** (I5)
- Steps: recovery after the break; all reconnect sub-phases; runs in signal/standby.
- Expected: the signaling-only invariant holds in all reconnect sub-phases; Ygg in
  `signal` mode is also signaling only.
- Oracle: decoded-frames oracle. Stage: P03 + NAT rig.

## Yggdrasil adapter boundary (native Rust core)

**SEC-FFI-01 — double start and partial startup failure** (I9)
- Steps: a repeated start of the adapter while the core is running (creating
  the core twice); starting several resources where one
  fails midway (adapter validation or supported startup failures;
  `Core::new` returns `Arc<Self>`, not an error result).
- Expected: an explicit error, state not corrupted; partial failure ends with full
  cleanup of already created resources (not a single leak/semi-alive resource).
- Oracle: error code, health afterwards, resource counters == baseline.
  Stage: CI-integration.

**SEC-FFI-02 — stop without hangs and shutdown cycles** (I9)
- Steps: `close()` during in-flight async `read_from`/`write_to` (cancellation);
  repeated start/stop cycles; concurrent stop/send/recv; task join and drop
  semantics after cancellation. There is no blocking recv thread anymore, but
  cancellation and drop behavior must be proven, not assumed.
- Expected: cancellation completes, all spawned tasks join, resources are freed;
  cycles are resilient.
- Oracle: task/fd counters before/after; a timeout on join. Stage: CI-integration + adapter rig.

**SEC-FFI-03 — concurrent send/recv and boundary parameters** (I9)
- Steps: parallel send/recv from several tasks; calls with boundary lengths:
  MTU (a valid boundary — must pass), MTU+1 and values causing length
  overflow (negative); zero length — per the adapter/core contract, not universal;
  stale/unknown handle (an adapter handle observed after shutdown/unknown state).
- Expected: the safe API rejects invalid states/sizes **before** the core calls
  (validation at the wrapper level; the wrapper owns buffer range semantics —
  payload maximum is buffer length − 1 per the core contract); no UB/deadlocks.
- Oracle: failure codes at the boundary; a stress loop under debug-assertions with stable
  resource counters (counters/debug asserts do not prove absence of UB — see I9, verification
  levels). Stage: adapter rig.

**SEC-FFI-04 — panic containment with limitations** (I9)
- Steps: an induced panic in the Rust adapter and wrapper — only where
  `catch_unwind` is actually used at the adapter boundary.
- Expected: the panic is converted into an error at the boundary where `catch_unwind`
  is configured; **abort is not caught magically**; the process may require fail-closed (a documented shutdown
  instead of "always survives") — "the process always survives" is not promised.
  Panics must not leak across spawned tasks silently.
- Oracle: a log with an error code in the `catch_unwind` configuration; abort behavior matches the
  documented fail-closed. Stage: adapter rig.

**SEC-FFI-05 — levels of boundary verification** (I9)
- Steps: (a) ownership review of the safe adapter (its crate root forbids
  all unsafe) and SAFETY review of unsafe sites in the separate
  isolated native OS FFI (e.g. the Windows key ACL);
  (b) Miri where it works without executing foreign code; (c) sanitizer runs in CI
  (ASan/UBSan/valgrind, where applicable).
- Expected: no level substitutes another; each one's limitations are recorded:
  (a) covers only reviewed code and is not executed; (b) native Rust core
  interaction is not inherently excluded from Miri: unsupported OS/runtime
  operations determine the runnable subset; (c) platform/tool limitations
  are documented.
- Oracle: each level's reports in CI/rig artifacts. Stage: P01/P07 review + CI.

## Supply chain and CI (P02+)

Open gate (2026-10-22): the candidate's upstream workspace patches crates.io
salsa20 to a local SIMD fork; Sha'ar does not inherit or adopt that patch.
The resolved consumption path, origin, and security review must be established
before SEC-SUP-01 can pass for the backend. Its detached tasks and ownership
cycles also block lifecycle acceptance; see [the source gate](rust-ygg.md).

**SEC-SUP-01 — dependencies: pinning/origin/licenses** (I10)
- Steps: independent verification of the lock file, sources (registry/git URL/rev), and licenses
  against the allowlist.
- Expected: everything pinned and compliant with the list; any divergence — build failure.
- Oracle: verification report in CI artifacts. Explicitly: pin ≠ security proof — pinning narrows
  the surface, it does not replace verification. Stage: CI (P02+).

**SEC-SUP-02 — minimal workflow permissions** (I10)
- Steps: YAML verification of all workflow files: top-level `permissions: { contents: read }`,
  privilege elevation only where necessary; actions without excessive permissions.
- Expected: all files comply; otherwise — CI failure.
- Oracle: linter/verification result in CI. Stage: CI (P02+).

**SEC-SUP-03 — secret/cache boundary and fork PRs** (I10)
- Steps: workflow inspection: no secret env in build/cache-producing steps;
  trust boundaries for fork PRs (secrets/environment unavailable to fork runs).
- Expected: no cache-producing step receives secret env; fork PRs have no access
  to secrets.
- Oracle: static verification of workflow files in CI; report in artifacts.
  Stage: CI (P02+).

## Loopback invariants

**SEC-LOOP-01 — non-local target** (I2, I1)
- Steps: a config with a target outside 127.0.0.1.
- Expected: validation failure before networking.
- Oracle: failure log before sockets. Stage: CI-unit.

**SEC-LOOP-02 — non-local client listener** (I2)
- Steps: a config with a listen address not on loopback.
- Expected: validation failure before networking.
- Oracle: failure log before sockets. Stage: CI-unit.

## Carrier destination-role integration (P08)

The carrier owns an `Admission`; its `Owner` is the authoritative destination-role ledger. Application identities come from the allowlist, infrastructure identities from discovery seeds, and explicit-relay endpoints are granted only through its policy API. A native-root witness vetoes unauthorized roots before publication. A child lease governs relay operations; incoming leases remain through terminal state and destroy. Gate's precharged 20-record budget is a separate bounded operation-record budget; the registry's eight-slot budget includes retained child charges. Weak captures and `Notify`-based joining bound task ownership. Private-DNS coverage uses an exact test-only fixture policy; it does not broaden production permission.

Authored source inventory (not executed): `destination_roles_` selects 15 registry cases; `destination_guard_` selects 22 guard cases (including six root-pinning cases). `carrier_destination_` selects 32 cases: 12 in `carrier/driver/roles_gate_tests.rs`, six in `carrier/driver/admission_tests.rs`, seven in `carrier/driver/roles_tests.rs`, three in `carrier/driver/relay_roles_tests.rs`, and four in `carrier/driver/relay_retention_tests.rs` (paths relative to `crates/shaar-p2p/src/`). The relay-role cases are reconstructed from the prior contract after being destructively overwritten; they are not verbatim originals and add no new proof claims. The new hostile-HOP case sends a real RESERVE request and actual HOP bytes; its valid control verifies lease installation and reservation permit. For hostile omission of expiry, it inspects the typed `InvalidReservationExpiration` on the terminal Swarm event, revokes the Reserve gate slot, then dispatches that event and checks the oneshot receives the typed error. This is authored source, not executed. Crucially, the typed terminal Swarm event is intercepted before gate revocation; the test does not demonstrate a typed error queued inside the listener across revocation. B/C remain open. The two retention additions are actual Swarm lifecycle regressions using production `Core::ReleaseRelay` and `Reserve`: same-generation veto and a successor generation with a different snapshot/control. They verify that the original pending reserve returns typed `io::ErrorKind::Interrupted` before teardown, then dispatch a held old accepted event after the successor. This does not prove preservation of a typed relay-protocol terminal error: local `Interrupted` stop is not a wire error. The retained cap keeps the joined release Pending until the final Drop. The expiry microtest captures the cap but exercises a Gate admission helper, not the library-private bind/live path. An existing owned HOP RPC fixture can hold real protocol I/O, but no Carrier proof of a pre-poll barrier has been authored; `.github/scripts/p2p/relay/fixtures/wire/prepare.py` lines 44–47 instruments private `Operation::run`, with protected templates unchanged. These authored source inventories are not execution results or compilation proof, and the task is not complete. Do not infer missing cases as proven. The existing private DNS/Noise test is migrated in `dns/tests/transport.rs`; its `owned_dns_` selector remains 30 and the prepared-DNS `retention_` selector remains 24. The 30 low-level relay operation units and three wire cases plus three counterfactuals do not substitute for those proofs. This inventory does not mark the carrier integration complete.

## What requires a real rig and is not covered by unit tests

- **SEC-PATH-01/02/03** — only P03/NAT rig with inspection of the actual network path.
- **SEC-FFI-02/03/04** (parts about real adapter lifecycle and cancellation) — adapter rig.
- **NAT traversal as such** — NAT rig; **real NATs and public infrastructure
  (Amino DHT, Mainline) are verified separately, success is not guaranteed** — connectivity
  is best-effort (§3 threat-model).
- A unit test on a loopback adapter does not prove behavior in a real network: network
  oracles are valid only when observing the real path.

**Forbidden:** an oracle of the form "the code returns success" without external observation; mock-success;
testing one's own constant (e.g., "the validator accepts a string that it itself
considers valid") without negative mutations. Until the implementation exists, for all listed
controls the status is "not done", not "passed".
