# Sha'ar Stack v1 Threat Model

Status: foundation/configuration CI and the identity functional baseline pass.
Identity/configuration primitives exist; networking, Server/Client operation,
and transport adapters remain unimplemented. This is a requirements document,
not a blanket audit result. [The SDK evidence](../verification/sdk-foundation.md)
records executed checks and remaining privacy cases. Full invariants require
all their stated oracles, including the unpassed P03/NAT and security gates.

Revision note (2026-10-22): reconciled to the native Rust Yggdrasil backend — the
Yggdrasil-ng candidate inspected at revision `c9a54f1587bb133a06072596484c972a336db0d2`
(package `yggdrasil` 0.3.1). No backend dependency has been integrated. Its
[shutdown/ownership source gate](../verification/rust-ygg.md) is unresolved.
The former yggdrasil-go c-archive FFI model is superseded historical reference,
not part of the intended runtime architecture.

## 1. Scope

The model covers Sha'ar Stack v1: the SDK crate `shaar`, the transports
`shaar-ygg` (native Rust adapter, backend acceptance pending), `shaar-p2p`
(libp2p signaling), `shaar-server`, `shaar-client`, work with
the Mainline DHT via pkarr, and ktav 0.8.* configuration. Out of scope: physical security
of the host, security of the OS environment, exploitation of vulnerabilities in upstream
libraries (counted only as a supply-chain risk).

Topology: the device has a single Ed25519 seed that derives the iroh EndpointId, the pkarr
record key, the Yggdrasil `200:…` address, and the libp2p PeerId. The client listens on
loopback TCP; after the client key is checked against an allowlist, the server accepts an
authenticated QUIC stream (QUIC is client↔server) and opens a separate
TCP connection to a fixed internal service (target) on 127.0.0.1.
n0 infrastructure (DNS, iroh relay) is disabled. Data path priority: direct QUIC →
Yggdrasil standby. The libp2p relay is signaling-only (candidate exchange, NAT hole
punching) and is **never** a fallback data path.

## 2. Assets

- **A1. Ed25519 seed** — full compromise: the attacker becomes the identity in all four
  networks (EndpointId, pkarr key, Ygg address, PeerId), can impersonate the node
  and sign pkarr records.
- **A2. Target service** — an internal TCP service on 127.0.0.1 behind the server; access
  to it = access to the protected backend.
- **A3. Authenticated session** — the established client↔server channel; spoofing or
  joining it exposes/corrupts application traffic.
- **A4. Addresses and IP privacy** — the node's real addresses/topology; disclosure via
  pkarr records, the signaling exchange, relay/Ygg metadata.
- **A5. Availability** — the node's ability to accept/establish connections; not protected
  against volumetric attacks (see §3), protected against exhaustion of internal resources
  (queues, threads, descriptors).

## 3. Trust boundaries

**Trusted:**
- the Rust runtime, the operating system;
- a reviewed backend and its cryptographic dependencies, once accepted.
  Yggdrasil-ng and its upstream SIMD patch have not reached that gate; source
  pinning alone does not establish their suitability;
- upstream cryptography: QUIC/TLS of iroh (authenticated encryption on endpoint keys),
  Ed25519, the libp2p noise protocol, pkarr signatures;
- the local user who owns the key file.

**NOT trusted:**
- Mainline DHT nodes — arbitrary responses, poisoning, replay;
- public Amino DHT relays — metadata observation, drops, delays;
- Yggdrasil peers — delays, drops, metadata, replay of records;
- any DHT record **before** verification of signature, freshness, and size limits (the
  budget is a contract to be confirmed by P01; see I6);
- addresses obtained from the DHT, before the peer key is verified;
- a remote peer before its key is verified (client — the known server key; server — the
  allowlist).

**Explicitly NOT defended (out of scope):**
- compromise of the OS or of the legitimate client, including reading the key from
  process memory;
- a global observer correlating traffic across all networks;
- guaranteed NAT traversal — connectivity is best-effort;
- volumetric DDoS on public addresses (only bounded internal resources are defended).

## 4. Separation of responsibilities

**Upstream provides (requirement: no in-house crypto code is written; `_tls` validation
is not disabled):**
- QUIC/TLS authenticated encryption on iroh endpoint keys;
- libp2p noise encryption and identification;
- pkarr record signing/verification;
- Yggdrasil encryption of the `200:…` channel.

**The application must provide (requirements, not facts):**
- allowlist check of the client **before** any connection to the target (I1);
- path policy: libp2p signaling-only in all phases; Yggdrasil in `signal` mode is
  signaling-only (I5; requires the P03 proof);
- resource limits and bounded admissions (I8);
- key storage: atomic creation, permissions, absence from logs (I3, I4);
- validation of the ktav config before any network action (I2);
- handling of untrusted DHT records: signature, size, freshness, replay (I6);
- adapter-boundary safety over the native core (I9); the only expected unsafe surface is
  isolated native OS FFI (e.g. the Windows key ACL);
- supply-chain and CI hygiene (I10).

## 5. Semantics of a single seed across multiple protocols

- **Exact linkability.** Public identifiers in all four networks are derived from one seed
  in a mathematically deterministic way. Given a known public key (or given available
  joint observations), the identifiers are linkable to a single identity;
  deterministic addressing is not necessarily reversible — *all* identifiers cannot be
  recovered from one observed address (e.g. only the Ygg address). Compromising the seed
  compromises all networks. **No anonymity is claimed or provided.**
- **Known-key authentication.** The client must verify *the specific* public key of the
  server (pinned/allowlisted), not "any valid TLS certificate". The server must
  verify the client key against the allowlist before connecting to the target. Otherwise
  a MITM with a valid self-signed certificate succeeds.
- **Publicity of a pkarr record ≠ privacy of the system.** A record (size limits are a
  contract to be confirmed by P01; applied according to the actual budget of the
  structure/field and record overhead) may
  publish relay addresses or IPs; publishing an address into the DHT reveals the existence
  and address of the node to the entire DHT — this is an accepted decision, not a
  vulnerability, but it does not waive the requirements of I4/I6.
- Consequence for the threat model: compromise of the pkarr key = compromise of A1 (same
  seed).

## 6. Invariants (I1…I10)

Each invariant: statement, threat reality, oracle (the observable verification point),
where it is proven. All of them are commitments; none has yet been confirmed by code.

### I1. Allowlist before target
- **Statement:** the server opens no TCP connection to the target until the remote
  party's key matches an allowlist entry.
- **Threat:** anyone on the network who can reach the server's QUIC port gains arbitrary
  access to the internal service (A2).
- **Oracle:** a TCP connection counter on a test target; "zero connections" for an
  unauthorized client.
- **Proof:** CI integration test; then the SEC-AUTH-02 controls in
  docs/verification/security.md.

### I2. Config validation before network; errors without secrets
- **Statement:** any invalid ktav 0.8 configs and CLI arguments are rejected before the
  first network action; error messages contain no seed, private keys,
  or tokens.
- **Threat:** starting with an unsafe configuration (an externally open listen, the
  allowlist disabled); a secret leaking through error text.
- **Oracle:** the process exits with failure before any socket is opened; diff of the
  error output to confirm absence of the secret.
- **Proof:** CI unit tests (parser/validator), SEC-CFG-01, SEC-CFG-02.

### I3. Atomic key creation; distinction between create_new and loading existing
- **Statement:** the *create_new* operation is performed exclusively via O_EXCL (Unix) /
  CREATE_NEW (Windows): if the file exists, creating over it fails; concurrent creation
  by two processes yields exactly one success, and under no path is an overwrite.
  *Normal loading of an existing key* is a separate path: an existing valid key is
  **read** and not overwritten; a normal re-run with an existing key is not rejected.
- **Threat:** an attempt to create over an existing key or a race between two creating
  processes wipes the key → a new identity, data unavailability, DoS.
- **Oracle:** on create_new over an existing file — failure and unchanged file (inode/
  contents); on concurrent creation — one success; on a normal run with an existing
  valid key — successful load, file unchanged.
- **Proof:** CI unit tests (including the concurrent case), SEC-KEY-01.

### I4. Key file permissions at creation; secrets out of Debug/logs/errors/configs
- **Statement:** access-restricting permissions are set **at creation time, before the
  first seed byte is written** — without a create→write→chmod window: on Unix the
  portable path is creation with O_EXCL and mode 0600 in one call (or by setting umask),
  with verification that no window existed; on Windows, an ACL restricting access to the
  owner is set at creation. Additionally: a controlled attempt by another unprivileged
  principal to read the file in the pause between open and the first write (in a test
  build) and after the write must not succeed. Seeds/private keys are not implemented in
  Debug/Display and do not reach logs, errors, or serialized configs. **This document
  does not promise protection from root/admin or OS compromise** (§3, out of scope).
- **Threat:** a local user on the same machine or CI artifacts read the key (A1);
  the window between creation and permission tightening exposes the seed to any local
  reader.
- **Oracle:** permission check immediately after creation; a negative read attempt by
  another principal in the controlled pause (test-only) and after the write; grep checks
  of logs/dumps/artifacts for byte and hex representations of the secret.
- **Proof:** CI unit tests + grep checks of CI artifacts, SEC-KEY-02, SEC-KEY-03.

### I5. Signaling-only in all phases
- **Statement:** application STREAM data is never carried over the libp2p relay — before
  the direct path is established, when it fails, and after reconnect; in `signal` mode
  Yggdrasil likewise carries only signaling (Ygg is the standby for *data*; the relay is
  never a data fallback). A violation of this rule with QUIC/TLS intact is **not**
  automatic decryption but a routing violation: metadata disclosure and dependence on an
  untrusted intermediary path, its limits and cost. Execution through the native Yggdrasil
backend is not
  a default iroh property: custom NAT traversal and the strict path policy are **not yet
  proven**.
- **Threat:** the Amino DHT relay and public Ygg peers are untrusted (§3): metadata,
  limits/cost of someone else's path, active interference by an untrusted relay.
- **Oracle:** observing encrypted packets and routes **does not** distinguish STREAM from
  CRYPTO/ACK/handshake — such an oracle alone is insufficient. The required oracle is a
  *decoded-frames oracle*: decoded QUIC frames with unambiguous binding to the actual
  egress path/transport — e.g. a test-only hook before encryption with path metadata, or
  test-only keylog + capture + demonstrable decoding. The availability of a hook/keylog in
  the chosen iroh version is a **condition that P03 confirms**; its existence is not
  asserted here. Sensitivity calibration is mandatory: a positive control — an
  intentionally permitted STREAM over the custom path **must** be flagged as a violation;
  a null result without such calibration is not proof.
- **Runs:** all three phases (before direct, at direct failure, after reconnect) and both
  modes (signal/standby); app-level data non-delivery does not prove the absence of
  STREAM on the wire.
- **Proof:** **P03 only** + the NAT testbed; controls SEC-PATH-01/02/03. If the oracle is
  insufficient, the I5 part of P03 remains **not passed** (a gate, not a formality).

### I6. Untrusted Mainline/pkarr records
- **Statement:** an address from the DHT is not used until pkarr signature verification
  succeeds and the size limits and freshness requirements are met. The size limits are a
  contract (a budget on the corresponding structure/field and the full record overhead)
  confirmed by P01; the limit is applied according to the actual budget, not as an
  unconditional constant of this document. Replay of an old record must not accept a stale
  address as fresh.
- **Threat:** DHT poisoning directs the client to an attacker's endpoint; exhaustion by
  giant records.
- **Oracle:** a counter of rejected records; no outgoing connections to unsigned/stale
  addresses. The stage and the concrete size budgets follow from P01's results.
- **Proof:** CI unit tests (mutated record fixtures), SEC-DHT-01/02/03.

### I7. Untrusted relay and Ygg peers for availability/metadata
- **Statement:** failure or manipulation by a relay/Ygg peer degrades the path, but causes
  no panic, no unbounded retry, and no fall of data through a signaling-only path.
- **Threat:** an untrusted relay as an active adversary (§3) — drops, delays, replay of
  signaling messages.
- **Oracle:** finite bounded retry with backoff; system state after the failure (no hung
  tasks, no memory growth).
- **Proof:** CI integration (failure injections), SEC-FAIL-01, SEC-DHT-04.

### I8. Bounded admissions and absolute deadlines
- **Statement:** all external inputs pass through bounded quotas: connections, streams,
  queues, packet sizes, caches, retries — each bounded; handshake and connection to the
  target have absolute stage deadlines; correct cancellation, backpressure,
  shutdown/half-close; no descriptor/memory/task leaks on any error paths.
- **Threat:** a slow or malicious client/peer exhausts memory/threads/fds (A5).
- **Oracle:** resource metrics (task, descriptor, RSS counters) before/after negative
  runs; no unclosed tasks after shutdown.
- **Proof:** CI unit tests + CI integration, SEC-RES-01/02/03, SEC-CONC-01/02.

### I9. Adapter-boundary safety over the native core
- **Statement:** in all crates a root `#![forbid(unsafe_code)]` — `shaar-ygg` has no FFI of
  its own; the only expected unsafe is the isolated native OS FFI boundary (e.g. the
  Windows key ACL), which is `#![deny(unsafe_code)]` with a local allow restricted to that
  boundary and SAFETY comments. Adapter obligations toward the pinned Yggdrasil-ng core:
  bounded buffers respecting the core's `read_from` payload-range semantics (max payload =
  buffer length − 1, MTU cap 65535), validation of all inputs before core calls,
  cancellation/close without leaked tasks, no panics escaping task boundaries into the SDK,
  and a correct start/shutdown lifecycle (`Core::new` / `start` / `close`). *The boundary
  requirements are only formulated here; the pinned core's runtime guarantees (datagram
delivery,
  MTU behavior, close/cancel semantics, wire interoperability) are verified by the P07/CI
  experiments — this document asserts nothing about the properties of the external library.*
- **Threat:** UB at the unsafe boundary — memory corruption, executor deadlocks, panic
  propagation into the SDK runtime.
- **Oracle and verification levels (each with explicit limitations):**
  1) static SAFETY/ownership review of the unsafe allow sites — not executed, covers only
  the read code; 2) Miri — only where it runs without executing foreign code (limitation:
  the foreign part does not execute); 3) real sanitizer checks in CI
  (ASan/UBSan/valgrind — where applicable; platform/tool limitations are recorded).
  Stable resource counters, debug assertions, and stress runs **do not** prove the
  absence of UB.
- **Proof:** static review (P07), Miri in CI where possible, a sanitizer run;
  controls SEC-FFI-01/02/03/04/05.

### I10. Supply chain and CI
- **Statement:** dependencies are pinned (lock + pin), sources (crate/go module) are
  reviewed; pin ≠ security proof — pinning narrows the surface and does not replace
  verification of provenance. GitHub Actions has minimal permissions (top-level
  `permissions: { contents: read }`, write only where necessary), actions without
  excessive rights, an explicit ban on passing secret env into build/cache-producing
  steps, and accounting of fork PR trust boundaries. Fuzz/property testing is executable
  **trusted** test code in CI; untrusted inputs under test are data only and must not be
  executed.
- **Threat:** compromise through a dependency or the CI pipeline; a secret leaking from a
  runner.
- **Oracle:** inspection of workflow files (YAML checks of permissions, secret env in
  cache-producing steps); independent verification of lock/sources/licenses; fork PR
  boundaries.
- **Proof:** the P02 CI stage and beyond, SEC-SUP-01/02/03.
