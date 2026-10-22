# Sha'ar Stack — Development Plan

Status: foundation CI (P02), identity (P04) and ktav configuration (P05) acceptance
passed; see [the SDK evidence](../verification/sdk-foundation.md). P03 experimental
acceptance passed for the reviewed patched backend, including physical direct loss
and automatic re-punch; see [the proof boundary](../verification/iroh-paths.md#13-accepted-physical-native-loss-and-automatic-re-punch).
Production dependency delivery must preserve that gate before SDK networking can
claim the same contract. The Yggdrasil adapter (P07) remains unaccepted.
P01 contract research is reconciled to the native Rust requirement.
Date: 2026-10-21. Revised: 2026-10-23 — P03 controlled recovery accepted;
native Rust replaces Go/cgo in the intended architecture. Yggdrasil-ng (`yggdrasil` 0.3.1, source revision
c9a54f1587bb133a06072596484c972a336db0d2) is a candidate, not an integrated
dependency. Its shutdown/ownership source gate is open; see
[the investigation](../verification/rust-ygg.md). Preparation of actual
third-party integration was denied by the tool; source review is not CI proof.

## 1. Goal and scope of the first version

A single repository `shaar-stack`, a Cargo workspace with an SDK, a Server, a Client,
and two transport adapters. The device is identified by an Ed25519 key.
The Client provides a local TCP port; the Server connects the stream to a specified
internal TCP service after checking the client key against an allowlist.

Acceptance criterion: an allowed client reaches the service through the local
port; a disallowed client causes no connections to the target. The connection
is established without TUN, root, route configuration, or router port forwarding.
n0 infrastructure is not used, neither explicitly nor via defaults.

The primary path is direct QUIC. Yggdrasil provides negotiation and fallback.
The libp2p relay is intended exclusively for negotiation, not for application
data. The Mainline DHT publishes and resolves signed address records.
Server and Client startup configs use the ktav 0.8.* format.

Not included: UDP forwarding, multiple published services on the server, a GUI,
a single CLI replacing separate Server and Client, an in-house Yggdrasil
protocol implementation (a reviewed external Rust core is required), DHT
record encryption, system packages, and automated release
publication. New modes, parameters, and dependencies are added only when necessary
for agreed acceptance criteria.

## 2. Normative rules and source materials

- `../../CLAUDE.md` — mandatory development rules.
- `../architecture/keypipe.md` — the original architectural draft.
- API sketches and claims about external infrastructure are not considered verified.
- Information about name availability on crates.io is not a permission
  to reserve names or publish packages.
- Implementation and tests are not run as part of producing this plan.

The 700-line limit applies to code, not to documentation. The 7-element limit
applies to directly nested files and directories of the project.
Unsafe is allowed only inside an isolated FFI boundary with a safe wrapper.
Tests and builds run in GitHub CI by default; local execution requires
an explicit user request. Commits, pushes, sub-agents, and publication are not
permitted by the mere existence of this plan.

## 3. Workspace structure

Target structure, not an instruction to create all components immediately:

```text
shaar-stack/
├── CLAUDE.md
├── Cargo.toml
├── Cargo.lock
├── .gitignore
├── .github/
├── crates/
│   ├── shaar/
│   ├── shaar-ygg/
│   ├── shaar-p2p/
│   ├── shaar-server/
│   ├── shaar-client/
│   └── shaar-platform/
└── docs/
    ├── architecture/
    ├── plans/
    └── verification/
```

Exactly 7 project items at the root; `.git` and the generated `target` are not counted.
Before creating the workspace, move the original draft into `docs/architecture/`
and fix the references. If one more root file is needed, reconsider the layout
first without breaking the limit. Nested directories are checked too.

Dependencies: the Server and Client use `shaar`; the SDK wires in the
`shaar-ygg` and `shaar-p2p` adapters. The adapters do not depend on the SDK, the Server,
or the Client, so no cycle forms. External iroh types are localized in the SDK's
networking layer; the public SDK surface must not needlessly cement unstable
upstream APIs. The small `shaar-platform` leaf supplies atomic Windows
private-file creation; the SDK uses it only on Windows. Its isolated native
FFI keeps the SDK's forbid policy intact. No generic shared crate is added.

## 4. Decisions to be proven before main implementation

### 4.1. Compatibility and contracts

Choose compatible versions of iroh, libp2p, and ktav 0.8.*
from sources and documentation, not from the draft's pseudocode. The Yggdrasil
core is pinned: native Rust crate `yggdrasil` 0.3.1 (Revertron/Yggdrasil-ng,
commit c9a54f1587bb133a06072596484c972a336db0d2, MPL-2.0). The initial
choice of dependencies is not a permission to upgrade versions later.
Pin the Rust toolchain/MSRV required by these versions.

Verify the availability of custom transports, NAT traversal, path observation,
publishing custom addresses, discovery configuration, and fully disabling n0.
For ktav, verify the exact library name, syntax, the supported format branch,
parser behavior, and diagnostics. Do not invent config syntax.

Determine the target OSes of the first version from the native Rust Yggdrasil
core's platform support and the Rust linker, confirmed by our CI. Windows is a
mandatory verification environment; Linux is for server
deployment. If the external stack does not support one of them, escalate the specific
blocker to the user rather than silently dropping the OS.

### 4.2. Blocking iroh experiment

Two endpoints with n0 infrastructure disabled connect over a controlled
custom transport. Observations must show an authenticated connection,
candidate exchange over that path, and the transition to a direct UDP path.

Separately, prove that application STREAM data never travels over the signaling-only
path: before the direct path appears, after it fails, and during re-punching.
Merely stopping packet transmission after the switch to the direct path is insufficient.
Filtering encrypted QUIC packets based on assumptions about their contents
is not an acceptable solution.

An in-memory experiment verifies API capabilities and path migration, but by itself
does not prove traversal of a real NAT. A separate controlled
NAT scenario in CI/a testbed is required; real home and mobile networks are verified later.

Stop conditions: if the iroh version in use does not provide the required negotiation,
migration, or data prohibition, subsequent stages of dependent components are blocked.
Document the confirmed limitation and the minimal alternatives for negotiation.
Silently replacing signaling-only with carrying user traffic is not allowed.

### 4.3. Remaining mandatory checks

- Ed25519 seed, iroh public key, Yggdrasil address, and libp2p PeerId:
  fixed conversion vectors; the PeerId is not equal to the raw key bytes.
- The Yggdrasil core really carries datagrams by public key without TUN:
  verify actual asynchronous `read_from`/`write_to` exchange by 32-byte key
  (`Addr` = peer key; the 1-byte session type is stripped/prepended by the core,
  so the payload maximum is `buf.len() − 1`), MTU boundaries (`mtu()` = inner − 1,
  capped at 65535), cancellation and `close()` semantics (no leaked tasks), and
  actual interoperability with the deployed Yggdrasil network — the upstream
  README's interoperability claim with yggdrasil-go v0.5.x is an upstream claim,
  not our proof.
- Public Amino relays really permit reservation and the needed protocol;
  advertising a relay protocol by itself does not guarantee a free slot.
- Real relay limitations and opening streams on limited connections are verified.
- A signed pkarr record fits the needed addresses accounting for the entire serialization;
  unknown, stale, and oversized records are handled safely.

## 5. Stages and completion criteria

The labels P01–P16 are also used in session task descriptions.
Each stage includes its own tests; their existence does not mean they were run.

### P01. Verify external contracts and formalize architectural decisions

Dependencies: none.

Deliverable: a table of exact versions and APIs, licenses, and limitations; contracts
for keys, transport, configs, and OSes; a verification scenario matrix.
Open questions are marked as unconfirmed, not masked by an API choice.
Acceptance: every key contract has a link to a source or to the specific
P03 experiment; continuation and stop conditions are known.

### P02. Create the workspace skeleton and GitHub CI

Dependencies: P01.

Create the five crates and place documentation according to the target structure.
Configure the unsafe lint policy with a local exception only for FFI.
Add CI for formatting, clippy, tests, and checks of file and directory
limits. Build jobs account for the platform linker requirements of the native Rust core.
Heavy network tests are separated from deterministic checks.

Acceptance: CI checks the workspace on the agreed OSes, rule violations
are caught by the checks, and the skeleton contains no fabricated working implementations.
If the repository is not yet connected to GitHub, CI execution is recorded
as blocked until a remote repository and push permission are provided.

### P03. Prove the feasibility of the custom transport and the signaling policy

Dependencies: P01, P02.

Create the minimal isolated experiment described in section 4.2,
including the controlled NAT. Save the results, chosen APIs, and limitations
in `docs/verification/`. The experiment does not become a spurious public SDK mode.
Acceptance: observations confirm the transition to the direct path, recovery,
and the absence of application data on forbidden paths. Otherwise — a stop
of dependent stages and renegotiation of the architecture.

### P04. Implement identity and secure key storage

Dependencies: P01, P02.

A single Ed25519 seed and verified conversions for all stacks.
Key creation is atomic and never overwrites an existing file; access is restricted
immediately at creation: Unix permissions and the corresponding Windows ACLs.
Read, format, and access errors never lead to silently generating a new identity.
Secrets never reach output or diagnostics; no unnecessary secret copies are created; required staging is zeroized best-effort.

Acceptance: conversion vectors, re-reading, corrupted files,
concurrent creation, and permission errors are covered by tests. The identity is stable.

### P05. Implement ktav 0.8.* startup configs

Dependencies: P01, P02.

Define the minimal Server and Client schemas, mandatory fields, defaults,
and the precedence of CLI arguments over configuration. Separate parsing from startup.
Do not duplicate shared types and checks; do not put the parser in the hot network path.
The secret key is stored separately; the config references it.

Acceptance: real ktav 0.8.* examples parse; erroneous syntax,
invalid values, unknown fields, and source precedence are tested. Errors
occur before the network starts and do not expose secrets.

### P06. Implement the SDK core and direct TCP-over-QUIC

Dependencies: P03, P04.

Create an endpoint without n0, a protocol/ALPN, remote key authentication,
TCP stream multiplexing, bounded backpressure, and explicit shutdown.
Public error types distinguish access denial, path unavailability, and target failure.

Acceptance: direct connection, parallel streams, half-close, stream reset,
cancellation, and endpoint shutdown lose no resources. Failure of an individual stream
does not abort the others. Established TCP sessions make no promise to survive
closing of the whole QUIC connection; new connections may establish a new one.

### P07. Implement the Yggdrasil transport as an isolated adapter over the native Rust core

Dependencies: P03, P04, P06.

Select and verify a native Rust core before implementing `shaar-ygg`.
Yggdrasil-ng (`yggdrasil` 0.3.1, source revision
c9a54f1587bb133a06072596484c972a336db0d2) has unresolved detached-task and
strong-ownership-cycle findings. Calling `close()` alone does not satisfy
SDK shutdown; resolving that gate is mandatory, not optional polish.
Its candidate packet interface is:
`Core::new(SigningKey, Config)`/`start`/`close` lifecycle; bounded read/write
buffers respecting the core's payload range semantics (in-place `read_from`
returns a `Range<usize>` and strips the 1-byte session type; `write_to`
prepends it and returns n − 1); MTU handling (`mtu()` = inner − 1, cap 65535);
cancellation and shutdown without leaked tasks; key→`Addr` mapping (a 32-byte
peer key); explicit state ownership to exclude conflicts between multiple SDK
instances. Feature hygiene: the `tun`/`ckr`/`systemd` features must not be
enabled — no OS routes, no TUN, no root. No unsafe is expected in this adapter
(the crate root forbids unsafe); any native OS FFI stays a separate isolated
boundary. Actual interoperability with the deployed Yggdrasil network is
verified on Linux and Windows CI; the retired Go c-archive ABI check is
historical evidence only, not a prerequisite.

Acceptance: datagram exchange by key without TUN, correct start/stop, startup
errors (adapter validation/startup failures; `Core::new` is not fallible), backpressure and
queue bounds, cancellation, and concurrent operations are covered by tests.
Builds on the target OSes are confirmed in CI.

### P08. Implement the libp2p signaling transport

Dependencies: P03, P04, P06.

Amino bootstrap, discovery and relay reservation, slot renewal,
failure handling, a cache of available peers. Do not treat the infrastructure as
unlimited. Bounded framing of QUIC datagrams over the stream with length checks,
backpressure, re-opening on demand, and bounded retry/backoff.

Acceptance: deterministic checks against an owned test relay cover
limits, reservation expiry, partial read/write, malformed frames, and reconnect.
A separate smoke scenario checks the public infrastructure, but its transient
failure is not masked as a defect of the deterministic test.

### P09. Implement Mainline discovery and address records

Dependencies: P06, P07, P08.

Publication and refresh of signed records, address resolution,
serialization of custom addresses, the record budget, and the IP publication policy.
The Yggdrasil path is computed from the key and is available independently of the DHT.
Acceptance: round-trip of addresses and signatures, the size limit, stale records,
a wrong key, absence of the DHT, and the mode without publishing the home IP are verified.
Do not promise anonymity: the IP may be visible to other layers and to communication peers.

### P10. Implement path selection and recovery

Dependencies: P06, P07, P08, P09.

Data priority: direct QUIC, then Yggdrasil only in `standby`.
In `signal`, alternative paths carry negotiation only.
libp2p carries no application data in any mode.
Path observation, keepalive, channel reactivation, and bounded retries
are implemented on mechanisms confirmed by P03.

Acceptance: a matrix of the two modes, path availability, network changes, and re-punching
confirms the prohibitions, the absence of cyclic switching,
and the absence of unbounded state growth.

### P11. Implement the Server

Dependencies: P05, P06, P10.

Config, allowlist, a fixed target, stream servicing, and a clean stop.
For the first version the target is restricted to loopback; do not add opening other
addresses without a separate requirement. Access is checked before connecting to the target.
Limit the number of connections and streams and the greeting/connection timeouts.
Acceptance: allow and deny, empty/invalid allowlist, unreachable target,
a slow client, limit exhaustion, and shutdown are covered by tests.

### P12. Implement the Client

Dependencies: P05, P06, P10.

Config, a local loopback listener, verification of the server key, connection
reuse, and creating a new connection after one closes. Connection-establishment
coordination does not hold a lock across `.await`. Local connections
and recovery waiting have bounded queues and deadlines.
Acceptance: parallel connections, server failure, wrong key, busy port,
cancellation, recovery for new streams, and shutdown are covered by tests.

### P13. Perform integration and fault-tolerance verification

Dependencies: P11, P12.

A deterministic matrix: direct IPv4/IPv6, various NATs, blocked UDP,
DHT unavailable, relay unavailable/exhausted, Yggdrasil unavailable, network change,
process restarts, both fallback modes. Also test LAN and the absence of n0.
The testbed controls network conditions and does not depend on luck in the public network.

Acceptance: a report with the result of each applicable scenario, evidence
of the data route and of denial to an unauthorized key. A skipped item does not
count as passed. A failing test or flake is investigated and fixed in the same pass.
Real home/mobile network/café scenarios are run separately with user permission
and device access, without unconfirmed NAT claims.

### P14. Verify resources, complexity, and performance

Dependencies: P13.

Check hot-path complexity, allocations per packet/stream, copying,
queue bounds, idle CPU, absence of busy-loops, FFI shutdown,
and resource release after cancellation. Agree on target budgets before measuring.
Run load and long-duration measurements only with explicit permission,
in CI/on a testbed; the existence of this task does not authorize load on the local machine.

Acceptance: reproducible measurements with the environment described, no leaks
and no unbounded queues; optimizations preserve the verified contracts.
Do not claim optimal complexity or lock-freedom without justification.

### P15. Complete SDK and operations documentation

Dependencies: P11, P12, P13.

Describe the public SDK, ktav 0.8.* configs, key creation and the allowlist,
Server/Client startup, path modes, address disclosure, errors, and recovery.
Record the OS, NAT, relay, and FFI limitations, as well as the checks actually
performed. Config examples are exercised in parser tests.
Acceptance: a new user can go from keys to a TCP connection following the
instructions; the documentation promises no unverified properties.

### P16. Verify first-version readiness without publication

Dependencies: P14, P15.

Cross-check the first-version goal, the development rules, and the verification matrix.
Check dependencies, licenses, secrets in artifacts, and build reproducibility
on the pinned stack. Record CI results and open risks.
Acceptance: all mandatory scenarios are confirmed; no blocking questions remain.
Publishing crates, a GitHub release, a version change, commit, and push — only
on a separate explicit user request.

## 6. Order of execution

Critical path:
P01 → P02 → P03 → P06 → P07/P08 → P09 → P10 → P11/P12 → P13 → P14/P15 → P16.
P04 and P05 may run after P02 independently of the P03 experiment;
P06 additionally requires P04, and the Server/Client additionally require P05.
Task independence does not automatically authorize launching sub-agents.

Each stage is closed only after its acceptance criteria are met.
If tests have not yet been run, the implementation is not declared verified.
For an external blocker, the cause and the required user decision are recorded.
Work does not proceed through an unconfirmed key assumption.
