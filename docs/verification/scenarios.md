# Sha'ar Stack Verification Scenario Matrix (P01, P13 report)

Date: 2026-10-21. Revised: 2026-10-22 — reconciled to the native Rust Yggdrasil
backend (crate `yggdrasil` 0.3.1, pinned commit
c9a54f1587bb133a06072596484c972a336db0d2); Go/cgo is removed. Revised:
2026-11-12 — the P13 acceptance report (section 10) was added and the status
column of every table was updated from the accepted evidence recorded in this
repository. Revised again on 2026-11-12 — section 10 rows E1, F1, G2, C2, C4b,
C7 (typed failure) and D3 were closed, and D2 narrowed, by the extension run E8.

Caveat: at the P01 stage nothing was run; the original statuses were all
"planned". The status column now reads `accepted`, `open` or `gated`, each with
its evidence. `planned (no accepted evidence recorded here)` marks rows that no
accepted evidence in this repository maps to; the absence of a mapping is not a
failure and not a pass. Section 10 is the only part of this file that claims
P13 scenario coverage; a stage-level `accepted` in sections 1–9 is not a P13
claim. Level notation: unit — a deterministic test;
CI rig — a controlled rig in CI; P03 — a blocking experiment
(development.md 4.2); manual — real NAT, outside CI, with the user's
permission.

## 1. iroh custom transport and signaling-only

Gate P03: connection establishment, candidate exchange, migration to direct
UDP, and the prohibition of application STREAM data on the signaling-only path in three phases —
before direct appears, after direct failure, and during re-punching.

Oracle (honest observation model):

- The `poll_send`/`poll_recv` byte counters of the test transport see
  ONLY encrypted QUIC datagrams and do NOT distinguish STREAM/CRYPTO/ACK/
  NAT frames; they are suitable only for estimating the total volume per path, NOT
  as proof of "zero STREAM".
- `path.is_selected()`/`rtt` — not proof of the route of all data;
  application-level undelivery does not prove absence of wire leakage.
- The independent oracle is at the decoded-frames level: (a) a test-only trace hook
  before encryption with path attribution, or (b) a capture of wire traffic
  with test-only keys and packet decoding. The very existence of
  such a hook/available decoding in iroh 1.3.0 is NOT confirmed —
  the possibility of a full oracle is a SEPARATE P03 condition
  (the matrix item "verify availability of the oracle mechanism" below).
- For NAT candidates — observation of decoded service frames,
  not counter growth.
- Mandatory negative calibration: a control experiment in which
  a STREAM is EXPLICITLY permitted through the custom transport must confirm
  that the oracle detects the violation; without a positive trigger the gate is
  not passed.
- Stopping `poll_send` after direct appears is NOT counted
  as resolving the contract.

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Connecting two endpoints via the custom transport only, with n0 disabled | Prove that the custom transport is the only path and the connection authenticates | Connection established; `conn.paths()` shows only the custom path | P03 | accepted (P03 stage, iroh-paths.md §§9–13) |
| NAT traversal: candidate exchange over the custom path | Prove negotiation over the signaling path | Candidates transmitted; observation of decoded service frames (NOT counter growth) | P03 | accepted (P03 stage, run 39860587690 at `77c8ab6`) |
| Migration to direct UDP after negotiation | Prove path migration to direct UDP | Decoded STREAM frames travel over the direct path; `path.is_selected()`/rtt — auxiliary | P03 | accepted (P03 stage, run 39860587690 at `77c8ab6`) |
| Application STREAM data before direct appears | Prohibit data on the signaling-only path | Decoded-frames oracle: 0 STREAM frames on the custom path before direct | P03 | accepted (P03 stage, iroh-paths.md §§12–13) |
| Application STREAM data after direct failure | The prohibition must not be lifted under degradation | Upon direct failure, decoded frames contain no STREAM on the custom path | P03 | accepted (P03 stage, run 39867392149 at `7a628e5`) |
| Application STREAM data during re-punching | The prohibition holds across re-punching attempts | Re-punching does not move data onto the signaling path (decoded frames) | P03 | accepted (P03 stage, run 39867392149 at `7a628e5`) |
| Stopping poll_send after direct does not count as resolution | Exclude false confirmation | Observation covers all phases; a mere poll_send stop is rejected | P03 | accepted (P03 stage, iroh-paths.md §13) |
| Verify availability of the oracle mechanism in iroh 1.3.0 | Feasibility of the oracle itself | The existence of a test-only trace hook before encryption or available decoding of captured packets is confirmed or refuted | P03 | accepted (P03 stage, iroh-paths.md §§3.4, 12) |
| Negative oracle calibration: STREAM explicitly permitted through the custom transport | Positive oracle trigger | The oracle detects the violation; without a positive trigger the gate is not passed | P03 | accepted (P03 stage, iroh-paths.md §§12–13) |

## 2. NAT matrix

A controlled rig fixes the NAT scenario types (full cone,
restricted cone, port-restricted, symmetric). For configurations
where direct is unachievable (e.g., symmetric NAT on both sides without
UDP-holepunching), a direct connection is NOT guaranteed. In signal mode the
alternative path is a finite controlled negotiation/bounded wait, then a controlled failure;
standby — switching to Yggdrasil if it is available, otherwise failure. Local
TCP sessions are not required to survive closure of the QUIC connection; after the break
the client establishes a new connection.

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Both sides behind NAT (cone types) | Connection without port forwarding | Connection established through negotiation, data over direct UDP | CI rig | accepted at P03 fixture level (run 39860587690 at `77c8ab6`); product double-NAT direct punching OPEN (§10 A5) |
| Symmetric NAT on both sides without UDP-holepunching | Unreachable direct | A direct connection is NOT guaranteed; signal: bounded wait, then controlled failure; standby: switch to Yggdrasil if available, otherwise failure | CI rig | open for symmetric NAT (§10 A6); the fallback behavior is accepted under double NAT plus UDP blockade (§10 B1, B2) |
| UDP blocked on one/both sides | Behavior without direct UDP | signal: finite negotiation/bounded wait, then controlled failure; standby: switch to Yggdrasil if available, otherwise failure; direct data unavailable, no unbounded retries | CI rig | accepted (§10 B1, B2; run 43229756778 at `ca6c04a`) |
| Both sides on a LAN | Direct local path | Direct connection without external infrastructure | CI rig | open (§10 E1) |
| Network change during operation (interface switch) | Migration and recovery | Connection is restored; no cyclic switching | CI rig | open (§10 D2) |
| QUIC connection closure with active local TCP sessions | Session life cycle | Local TCP sessions are not required to survive closure; after the break the client establishes a new connection | CI rig | accepted (§10 D1; fresh-connection recovery only) |
| NAT-hole keepalive | Keeping the punched mapping alive | Keepalive keeps the path alive without state growth | CI rig | open (§10 D4) |
| Recovery after losing the NAT hole | Re-punching | The path is restored; the repeated scenarios of section 1 run | CI rig | accepted at P03 fixture level (run 39867392149 at `7a628e5`); product namespace case OPEN (§10 D4) |
| Real home/mobile networks | Confirmation outside the rig | Documented observations; no unconfirmed claims about NAT | manual | gated (§10 E2) |

## 3. Relay scenarios (libp2p)

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Own test relay with limits from Config::default | Deterministic limit verification | Limits (128 reservations, 4/peer, 3600 s, 16 circuits, 120 s, 128 KiB, rate limits) are applied | unit | planned (no accepted evidence recorded here) |
| Reservation expiry and renewal | Renewal handling | Renewal is observed via the `ReservationReqAccepted` event with `renewal: true`; the client computes the renewal delay ≈ 3/4 of the remaining term (outbound_hop.rs); after expiry — re-reservation | unit | planned (no accepted evidence recorded here) |
| ResourceLimitExceeded slot failure | No free slot | Explicit handling of the failure; bounded retry/backoff, no masking | unit | planned (no accepted evidence recorded here) |
| Datagram framing over the stream | Bounded framing | Length checks, partial read/write, malformed frames rejected | unit | planned (no accepted evidence recorded here) |
| Reconnect after relay break | Recovery | Re-reservation and stream reopening, state bounded | unit | planned (no accepted evidence recorded here) |
| Public Amino smoke | Availability of a real slot | Separate smoke; temporary failure of public infrastructure is not masked as a defect of deterministic tests | CI rig | gated (§10 E3) |
| Streams on truly limited connections | libp2p-stream behavior on a relayed connection | Confirmed limitation or working behavior is documented | P03 | planned (no accepted evidence recorded here) |
| open_stream over a relayed connection | Verify absence of a code gate | `open_stream` over a relayed connection is not forbidden by code (behaviour.rs without an is_relayed gate) — confirmed by reading v0.57.1; actual relay-server limits — measurement | unit | planned (no accepted evidence recorded here) |

## 4. Yggdrasil native adapter

The native Rust core (pinned commit) exposes a fully async API: `read_from`
(in-place, strips a 1-byte session type), `write_to` (prepends it), `mtu()`,
`Core::new`/`start`/`close`. `Addr` is the 32-byte peer key; the session type
byte is internal to the core.

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Sending/receiving datagrams by 32-byte key | `write_to`/`read_from` contract | `write_to(buf, &Addr)` to a peer key delivers; `read_from` returns `(Range<usize>, Addr)` with a 32-byte key; the session type byte is internal | unit | accepted (leaf 53.3, `3396840`, run 42033089403) |
| MTU boundaries | Packet size boundaries | `mtu()` = inner − 1, cap 65535; payload maximum = buffer length − 1; exceeding is rejected/behaves per the core contract — the exact overflow behavior of `write_to` requires an experiment | unit | accepted (leaf 53.3, `3396840`, run 42033089403) |
| Asynchronous receive | No dedicated blocking OS thread | The core is fully async; receive does not require a dedicated blocking thread; executor rules still apply to blocking on recv — cancellation of a pending `read_from` is verified | unit | accepted (leaf 53.3, `3396840`, run 42033089403) |
| Stop and cancellation | Orderly termination | The adapter stops owned tasks, joins them, and releases the node; upstream `close()` alone has detached-task/strong-cycle blockers documented in rust-ygg.md | unit | accepted (leaf 53.2/53.2b, `630b264`, run 42026035312; the former source gate is closed) |
| Concurrent calls | Concurrency rules | The native concurrency contract (concurrent `read_from`/`write_to`/`close`, shared `&Arc<Core>` use) must be established from the pinned sources and P07 tests. Superseded reference: the old single-queue-recv hazard was a Go-shim finding, not a native-core finding; the test does not replace the SAFETY justification | unit | accepted (leaves 53.2/53.3, `630b264`, `3396840`) |
| Startup errors | Invalid key/config | Adapter validation rejects invalid input before construction and reports supported startup failures; `Core::new` returns `Arc<Self>`, not `Result`, so no upstream error-return contract is assumed | unit | accepted (leaf 53.4, `efa5c62`, run 42035672563) |
| Adapter build and actual interoperability on Linux/amd64 CI | Early CI item | The adapter builds and performs an actual datagram exchange through the native core on Linux/amd64; the retired Go c-archive check (go-abi.md) is historical evidence only, not a prerequisite | CI rig | accepted (leaf 53.3, run 42033089403) |
| Adapter build and actual interoperability on Windows/amd64 CI | Early CI item (next to Linux) | The adapter builds and performs an actual datagram exchange through the native core on Windows/amd64; the retired Go c-archive check is historical evidence only, not a prerequisite | CI rig | accepted (leaf 53.3, run 42033089403) |

## 5. pkarr matrix (unit/CI)

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Signing with the correct key | Correct record signing | The record is signed with the same ed25519 key and accepted | unit | accepted (P09 stage, `b076458`) |
| Signing with the wrong key | Rejection on a foreign signature | The record is rejected | unit | accepted (P09 stage, `b076458`) |
| Round-trip of custom addresses | Preservation through serialization | API level confirmed (endpoint_info.rs v1.3.0); actual libp2p multiaddrs and their sizes — test | unit | accepted (P09 stage, `b076458`) |
| Full record budget | Size limit | DNS part ≤ 1000 bytes (HEADER_SIZE 104, signed packet ≤ 1104 — read in iroh-dns/src/pkarr.rs v1.3.0); pre-select a fitting set of custom addresses; observable publish failure on overflow (PacketTooLarge — do not publish) | unit | planned (no accepted evidence recorded here) |
| Sequence and freshness | fresh/stale/replay handling | After a new record is observed, a smaller seq does not replace it; equal seq with the same content — idempotent re-read, with different — conflict. Replay does not extend the admissible age of the signed record. The DNS TTL cache does not substitute verification of the signed timestamp; the age limit and admissible clock skew are fixed at P09 taking the republication period into account | unit + CI rig | accepted (P09 stage, `b076458`) |
| unknown/malformed records | Safe handling | Malformed records are rejected without panics and do not affect state; malformed attrs are skipped (read in endpoint_info.rs); on PacketTooLarge — do not publish | unit + CI rig | accepted (P09 stage, `b076458`) |

## 6. Keys and addresses

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Fixed vectors seed → pubkey → EndpointId → Ygg 200: → PeerId | Single identity per seed | All derivations match the fixed vectors | unit | accepted (P04 stage; leaf 53.4 golden address vectors, `efa5c62`) |
| PeerId ≠ raw key bytes | Multihash wrapping | `to_peer_id()` is not equal to the raw key bytes | unit | planned (no accepted evidence recorded here) |
| Corrupted key | Failure is safe | A read/format error without silently generating a new identity | unit | accepted (P04 stage, sdk-foundation.md) |
| Foreign key | Access denial | Connection/service not served for an unauthorized key | unit | accepted (§10 G1) |

## 7. ktav 0.8.* configuration

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| Valid configs | Parsing valid files | `from_str/from_file` yields the expected values | unit | accepted (P05 stage, sdk-foundation.md) |
| Default values | Behavior on omission | Defaults are applied according to the schema | unit | accepted (P05 stage, sdk-foundation.md) |
| Syntax errors of all major ErrorKinds | Diagnostics | MissingSeparatorSpace, InvalidTypedScalar, DuplicateKey, KeyPathConflict, EmptyKey, InvalidKey, UnclosedCompound, UnbalancedBracket, InlineNonEmptyCompound, MissingSeparator are detected with span/path | unit | planned (no accepted evidence recorded here) |
| Invalid parameter values | Semantics validation | An error before network startup, naming the field, without disclosing secrets | unit | accepted (P05 stage, sdk-foundation.md) |
| Lost numbers, parse_strict/LossyScalar | API behavior | The actual API behavior (parse/parse_strict) on numbers like `1.10` is checked in P05; the decision on the config parsing policy (strict or not) is made by P05, no prescription is set in advance | unit | planned (no accepted evidence recorded here) |
| Duplicate keys | DuplicateKey/KeyPathConflict | A repeated key and a path conflict are detected | unit | planned (no accepted evidence recorded here) |
| Unknown fields | serde behavior | The actual behavior (ignore/deny_unknown_fields) is confirmed by a test — schema decision at P05 | unit | accepted (P05 stage: unknown fields rejected, sdk-foundation.md) |
| Network startup refusal on config error | Load/startup order | Parsing and validation complete before network services start | unit | accepted (P11/P12 process case `real_process_startup_validation_and_busy_listener`) |

## 8. Isolation from n0 infrastructure

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| presets::Minimal + own transports: absence of calls to iroh.link/n0 relays | n0 disabled by default | Network observation of the rig shows no calls to iroh.link and n0 relays | CI rig | accepted at source-guard level; observed zero-contact OPEN (§10 F1) |
| clear_ip_transports() not used for disabling n0 | Keeping direct UDP | The direct UDP transport remains available | unit | accepted (direct UDP carried the Native cases in run 43229756778; §10 A3, A4) |

## 9. Structural CI checks

| Scenario | Goal | Expected result | Level | Status (2026-11-12) |
|---|---|---|---|---|
| No more than 700 lines per code file | CLAUDE.md rule 2 | Violations are detected by a CI check | CI rig | accepted (`.github/scripts/check_structure.py`, CI structure step) |
| No more than 7 items per directory | CLAUDE.md rule 3 | Violations are detected by a CI check | CI rig | accepted (`.github/scripts/check_structure.py`, CI structure step) |
| forbid/deny unsafe | CLAUDE.md rule 1 | Roots without FFI — forbid; the FFI crate — deny with a local allow | CI rig | accepted (`.github/scripts/check_structure.py`, CI structure step) |
| clippy and fmt | Unified style and lint | CI runs `cargo clippy` and `cargo fmt` | CI rig | accepted (CI `fmt+clippy+test+structure` job) |

## 10. P13 acceptance report (2026-11-12)

Required by development.md P13: every applicable v1 scenario with its evidence,
data route and denial result. Statuses: `accepted` — an executed, verified pass
at the stated evidence level; `open` — applicable, no evidence, nothing is
claimed; `gated` — needs a separate user permission, devices or peers. A skipped
or permission-blocked row is never counted as passed. Evidence levels, from
weakest to strongest for network claims: **policy** (deterministic unit test of
path policy), **in-process role** (real Server/Client roles in one test
process), **normal-process loopback** (CI-built `shaar-server`/`shaar-client`
binaries over owned loopback fixtures), **namespace NAT** (normal binaries as an
unprivileged identity inside owned Linux network namespaces behind nftables NAT
on a disposable GitHub-hosted runner). Everything below was compiled and executed
only in GitHub CI. Real devices, LAN and public networks were not used.

### 10.1 Evidence index

| Ref | Source SHA | CI runs | What it establishes |
|---|---|---|---|
| E1 | `c991637` | fork ordinary 43068220334; manual 43068389482 | Nine normal-process cases per OS (lifecycle, key-only APP, Server-only restart, both modes); nine required component identities mapped to terminal passes on Ubuntu and Windows |
| E2 | `61557cd` | fork ordinary 43083486968; manual 43083590411; upstream 43085630049 | Ten normal-process cases per OS, including composed unauthorized-key denial in both modes |
| E3 | `5d881db` | fork ordinary 43089127905; manual 43089204696; upstream 43090527868 | Eleven normal-process cases per OS, including standby with silent DHT and unavailable Client relay |
| E4 | `ca6c04a` | fork workflow_dispatch 43229756778 (privileged namespace matrix); fork ordinary 43228164983 | Four namespace NAT product cases plus three cleanup controls, all pass; details in 10.4 |
| E5 | `6e730b1` (merged to main as `1844247`) | fork push CI 43231113518; upstream develop CI 43231417573 | Only the supervisor interrupt wait changed after E4 (test code); ordinary CI green. The namespace matrix was not re-dispatched on this SHA |
| E7 | `17b711c` | fork ordinary 43245072242 (plan job 173 Python tests, structure job 132 guard tests, all green) | Ordinary CI of the exact source that E8 executed |
| E8 | `17b711c` | fork workflow_dispatch 43245366525 (privileged namespace matrix, extension); earlier failed dispatches 43241277233 (`72db069`) and 43243607361 (`7f89780`) | Twelve namespace product cases plus three cleanup controls, all pass; details in 10.7 |
| E6 | `d380641` | fork ordinary 43117747747; manual 43118324828; upstream 43119078680 | Runner tool preflight: `ip`, `nft`, `setpriv`, `tcpdump` present; conntrack CLI and the conntrack procfs table absent |

Retained component identities (E1; all in-process role unless marked policy)
pass on Ubuntu and Windows:
`startup::tests::role_tests::standby_cases::mainline_outage_leaves_the_alternate_transport_owned_and_standby_carries_payload`,
`startup::tests::role_tests::signal_cases::signal_mode_negotiates_but_ygg_never_carries_application_payload`,
`startup::tests::role_tests::location_cases::pinned_relay_negotiation_carries_native_payload_with_zero_relay_payload`,
`startup::tests::role_tests::standby_cases::idle_policy_progress_restores_native_without_disturbing_active_streams`,
`path::tests::standby::maintenance::signal_and_unusable_fallback_keep_finite_typed_exhaustion` (policy),
`path::tests::standby::retained::a_total_outage_is_unavailable_and_a_recovering_fallback_ends_it` (policy),
`startup::tests::role_tests::lifecycle_cases::capacity::cross_path_capacity_refuses_while_one_shared_slot_is_held`,
`startup::tests::role_tests::denial_cases::disallowed_key_causes_zero_target_connections_and_allowed_key_succeeds`,
`startup::tests::role_tests::lifecycle_cases::ipv6::key_only_ipv6_forwards_to_the_fixed_target_in_signal_and_standby`.
These are retained older results; they were not re-run on a fresh SHA for this report.

### 10.2 Matrix

Process case ids below are the ignored test functions under
`crates/shaar/tests/identity/process_smoke/` selected by the manual runs.

**A. Direct and NAT paths**

| ID | Scenario | Mode | Status | Evidence | Data route | Level |
|---|---|---|---|---|---|---|
| A1 | Direct IPv4, key-only discovery, exact APP request/reply, half-close/EOF | signal, standby | accepted | E1: `real_composed_key_only_payload_and_server_restart_in_signal_and_standby` | Native QUIC on owned loopback; path exclusion, no child route counters | normal-process loopback |
| A2a | Direct IPv6, key-only, fixed target | signal, standby | accepted (in-process) | E1 identity `...ipv6::key_only_ipv6_forwards_to_the_fixed_target_in_signal_and_standby`; constructor/role leaves `8ca352e`, `e6b1f10` | Native QUIC over IPv6 in one process | in-process role |
| A2b | Direct IPv6 with normal binaries or namespaces | both | open | None. The namespace matrix denies IPv6 forwarding by design and claims no IPv6 NAT | - | - |
| A3 | Single NAT (Client behind Router A, Server on WAN), Native positive control, Ygg transit denied | signal | accepted | E4 case `native-signal`: APP 61/61 bytes, target accepts 1, Client exit 0; Router A `native_snat` 22 pkts / 10,799 B, `udp_nat` 2 pkts, `native_drop` 0, `tcp_drop` 1 pkt (denied Ygg transit); Server published `203.0.113.10:44346` | Native QUIC through Router A masquerade; relay/Ygg APP excluded by rules | namespace NAT |
| A4 | Single NAT, Native positive control, Ygg unavailable | standby | accepted | E4 case `native-standby`: APP 61/61, accepts 1, exit 0; `native_snat` 23 pkts / 10,853 B, `tcp_drop` 4 pkts / 240 B | Native QUIC through Router A masquerade; fallback unavailable yet APP succeeds | namespace NAT |
| A5 | Direct Native hole punching through double NAT | both | open | None at product level. E4 case 3 is fallback, not punching (contract). Experimental fixture only: P03 run 39860587690 at `77c8ab6` | - | P03 fixture only |
| A6 | NAT type variety (symmetric, full cone, others) | both | open | The fixture has one MASQUERADE type with translated ports 41010-41020 | - | - |

**B. Blocked native UDP**

| ID | Scenario | Mode | Status | Evidence | Data route | Level |
|---|---|---|---|---|---|---|
| B1 | Double NAT, all forwarded Native UDP dropped, Client relay TCP denied, only owned Ygg transit TCP open | standby | accepted | E4 case `blocked-standby`: APP 61/61, accepts 1, exit 0, active 1.23 s; Router A `native_drop` 4 pkts / 4,912 B, `native_snat` 0 on both routers, `tcp_nat` 1 and 2 pkts; Server published private `10.0.2.2:47718` | Yggdrasil APP, established by path exclusion plus kernel counters; no Ygg-layer route counter | namespace NAT |
| B2 | Same blockade, Ygg transit reachable | signal | accepted (fail closed) | E4 case `blocked-signal`: local admission then terminal reset, 0 reply bytes, target accepts 0, Client exit 1, active 32.6 s; `native_drop` 24 pkts / 29,472 B, `native_snat` 0 | No application route; Ygg carries no APP in signal | namespace NAT |

**C. Unavailable components**

| ID | Scenario | Mode | Status | Evidence | Data route | Level |
|---|---|---|---|---|---|---|
| C1 | DHT bootstraps silent and Client relay unavailable, default policy | standby | accepted | E3: `real_composed_standby_forwards_when_dht_and_client_relay_are_unavailable`; in-process E1 identity `...mainline_outage_leaves_the_alternate_transport_owned_and_standby_carries_payload` | Yggdrasil by source-backed path exclusion (no direct hint, no DHT reply, relay never accepts); no physical UDP blocking | normal-process loopback; in-process role |
| C2 | DHT unavailable | signal | accepted (finding: no fail-closed) | E8 case `dht-drop-signal`: every DHT query from the Client side dropped (`dht_drop` 3 pkts), yet APP 61/61, target accepts 1, Client exit 0; `native_snat` 16, `relay_tcp` 241 pkts, `ygg_tcp` 45 pkts. The first dispatch refuted the "fail closed" hypothesis (the fixed target saw an admission). In signal mode only Native can carry APP, so the Client found the Server without the DHT through the libp2p relay signaling and used Native | Native QUIC by exclusion (signal mode); relay signaling only | namespace NAT |
| C3 | Late Native recovery after outage with held streams | standby | accepted (in-process) | E1 identity `...idle_policy_progress_restores_native_without_disturbing_active_streams` | Native restored, held streams undisturbed | in-process role |
| C4 | Client relay unavailable | standby; signal | accepted (standby; signal combined with B2) | Standby: C1 and B1 (Router A allows only transit TCP). Signal: B2 fails closed | As C1/B1/B2 | normal-process loopback; namespace NAT |
| C4b | Relay unavailable alone while Native is available | signal | accepted | E8 case `relay-denied-signal`: Client-side router allows only Ygg transit TCP, UDP open; APP 61/61, accepts 1, exit 0, `udp_nat` 2, `native_snat` 20, `ygg_tcp` 41 pkts, `tcp_drop` 0 (the product did not try the relay) | Native QUIC (signal mode: Ygg and relay cannot carry APP) | namespace NAT |
| C5 | Exhausted relay (reservation/circuit limits) | both | open for composed runs | Policy and in-process only: E1 `...signal_and_unusable_fallback_keep_finite_typed_exhaustion` (policy), `...cross_path_capacity_refuses_while_one_shared_slot_is_held` | Finite typed failure; no real relay limit hit | policy; in-process role |
| C6 | Unavailable Yggdrasil while Native is available | signal, standby | accepted | A3, A4 (Ygg transit denied; `tcp_drop` counters) | Native QUIC | namespace NAT |
| C7 | Total outage (Native and Ygg both unavailable), typed failure and recovery | standby | accepted for typed failure; recovery open for composed runs | E8 case `outage-standby`: UDP blocked (`native_drop` 24 pkts) and Client relay and Ygg TCP denied (`tcp_drop` 19 pkts): local admission, terminal reset, 0 reply bytes, target accepts 0, Client exit 1 on its own, active 32.6 s. Recovery after a total outage remains policy only: E1 `...a_total_outage_is_unavailable_and_a_recovering_fallback_ends_it` | No application route | namespace NAT; policy |
| C8 | libp2p carries no APP data | both | accepted (in-process) | E1 identity `...pinned_relay_negotiation_carries_native_payload_with_zero_relay_payload`: Native STREAM, zero Custom/relay APP | Native QUIC after relay negotiation | in-process role |
| C9 | Signal mode never carries APP over Ygg | signal | accepted | E1 identity `...signal_mode_negotiates_but_ygg_never_carries_application_payload`; B2 (zero target accepts with Ygg reachable) | None over Ygg | in-process role; namespace NAT |

**D. Restarts and network change**

| ID | Scenario | Mode | Status | Evidence | Data route | Level |
|---|---|---|---|---|---|---|
| D1 | Console stop/restart of Client and of Server; Server-only restart with the Client retained; fresh-connection recovery | signal, standby | accepted | E1: `real_composed_client_console_stop_and_restart_in_signal_and_standby`, `real_composed_server_console_stop_and_restart_in_signal_and_standby` (lifecycle `ed6fed1`), `real_composed_key_only_payload_and_server_restart_in_signal_and_standby`; process smoke `real_process_console_shutdown_rebind_and_server_restart`. Limits: no transparent old-TCP reconnect; bounded fresh-connection recovery only | Native QUIC to the restarted Server's newly published port | normal-process loopback |
| D2 | Network change (interface/address switch, NAT rebinding) mid-session with recovery | both | partial: Native path loss and recovery accepted; interface or address switch and NAT rebinding open | E8 cases `failover-standby`, `failover-signal` model the loss and return of the Native path with a runtime block table (no interface or address change). Standby: APP 2 over Ygg, then Native back (D3). Signal: after the block APP 2 fails closed (reset, 0 reply bytes, 5.1 s), `native_snat` growth 0, 28 dropped Native pkts (dispatch 3), target accepts stay 1, the Client stays alive and stops with exit 0 | Signal: no application route after the block | namespace NAT |
| D3 | Failover to Yggdrasil within 10 s after Native loss mid-session | standby | accepted (single run; no p95 claim) | E8 case `failover-standby`: APP 1 with Native up (`native_snat` 20 pkts; Ygg was open, so Native carriage of APP 1 is policy plus counters, not exclusion); runtime Native UDP block, APP 2 succeeded exact 61/61 **7.017 s** after block insertion (limit 10 s; run 2: 7.085 s), `native_snat` growth 0 during the block, 32 dropped Native pkts, Ygg TCP +98 pkts; block lifted and Ygg TCP blocked, APP 3 succeeded exact 61/61 **13.061 s** after the lift (fixture bound 40 s), `native_snat` +30 pkts; target accepts 3, 183/183 bytes | APP 2: Yggdrasil by path exclusion (UDP blocked); APP 3: Native by path exclusion (Ygg blocked) | namespace NAT |
| D4 | NAT keepalive; recovery after losing the NAT hole | both | open at product level | P03 fixture only: run 39867392149 at `7a628e5` (iroh-paths.md section 13) | - | P03 fixture only |

**E. LAN, devices, public networks**

| ID | Scenario | Mode | Status | Evidence |
|---|---|---|---|---|
| E1 | LAN: both sides on one L2 segment, no router | both | accepted (owned documentation-range segment; not a real LAN) | E8 cases `lan-signal`, `lan-standby`: Client and Server are single-interface hosts on the `203.0.113.0/24` segment with the DHT/relay/Ygg fixtures; signed record lists exactly `203.0.113.2`; APP 61/61, accepts 1, exit 0 in both modes; both routers forwarded 0 bytes and `udp_nat`, `tcp_nat`, `native_snat` 0; Native UDP sent and received on the segment (rtr_a/rtr_b `lan_sent` 22/19 and `lan_native` 19/22 in signal; `lan_sent` 24/21 and `lan_native` 21/24 in standby). Does not cover RFC 1918 addresses, multicast discovery, Wi-Fi or devices |
| E2 | Real home, mobile, cafe networks and devices | both | gated | Needs separate user permission and device access; no NAT claims are made |
| E3 | Public Yggdrasil/relay interoperability and live smoke (task D2) | both | gated | Authorized in principle on 2026-11-09; exact lawful peers and enforceable budgets are still required |

**F. No n0**

| ID | Scenario | Status | Evidence |
|---|---|---|---|
| F1 | No dependence on n0 infrastructure | accepted at source-guard level and observed zero contact in the namespace matrix | Product endpoints use `presets::Minimal` with no n0 relay, address lookup or port mapping (`crates/shaar/src/network/admission/mod.rs`, `crates/shaar/tests/backend_gate.rs`). E8: in all 12 product cases both routers' observation counters (`outside_fwd`, `outside_out`, `udp53`, `tcp443`: packets to any destination outside `10.0.0.0/8`, `203.0.113.0/24`, loopback and link-scope multicast, and UDP/53 and TCP/443 to such destinations) are exactly 0, with the detector proven live before each case by probes to TEST-NET-1 `192.0.2.77`. Limits: IPv4 only; products in the WAN namespace have no route at all (prevented, not counted); not a packet capture of host namespaces |

**G. Authorization**

| ID | Scenario | Mode | Status | Evidence | Level |
|---|---|---|---|---|---|
| G1 | Unauthorized key causes zero target connections | signal, standby | accepted | E2: `real_composed_denied_key_never_reaches_target_in_signal_and_standby` (authorized control passes first; the denied Client binds locally, gets no APP bytes, ends with terminal EOF/reset and CLI exit 1; Server stays alive and stops cleanly; target accepts are monitored from before the denied start through reaping and the backlog is inspected). In-process: E1 `...disallowed_key_causes_zero_target_connections_and_allowed_key_succeeds` | normal-process loopback; in-process role |
| G2 | Unauthorized key under namespace NAT or over the Ygg fallback path | both | accepted for standby over Ygg; signal over Native open | E8 case `denied-blocked-standby` (Native UDP blocked, Ygg only): authorized control first (APP 61/61, accepts 1, exit 0), then a second Client with a different valid key: terminal reset, 0 reply bytes, target accepts still 1, second Client exit 1, Server stops cleanly. In signal mode over a NAT-ed Native path the denial is covered only by E2 at loopback | namespace NAT |

### 10.3 Denial results

- G1: target accepts 0 for the denied key in both modes. It is a black-box
  differential allowlist check, not an observation of an internal typed
  access-denied counter; child logs show peer access denied twice per OS.
- B2: target accepts 0, APP reply bytes 0, Client exit 1, while Ygg transit was
  reachable; this is the signal-mode no-Ygg-payload result.
- G2 (E8): the unauthorized second Client over the Ygg fallback got 0 reply bytes and
  the target accepted only the authorized control stream (1 accept in total).
- The data route of the denial runs is not separately observed.

### 10.4 Namespace NAT matrix run (E4)

Fork workflow_dispatch 43229756778 on `ca6c04a`, runner image 20261101.186.1,
reviewed contract [p13-controlled-network.md](../plans/p13-controlled-network.md).
Normal CI-built products with `shaar-native-gate` off. Phase status `pass`.

- Four product cases pass: `native-signal`, `native-standby`, `blocked-standby`,
  `blocked-signal`. Three cleanup controls pass: `setup-failure` (exit 1 as
  designed), `live-failure` (exit 1 as designed), `interruption` (exit 143).
  Every case reports zero leftover namespaces, processes and interfaces, and
  unchanged host firewall and `ip_forward`.
- All 18 generated nft rulesets passed `nft --check` inside one throwaway owned
  namespace, removed afterwards, before any case ran.
- Forwarded IP traffic 160,332 B in total against the 64 MiB allocation; artifacts
  115,067 B; privileged phase 53.6 s against 20 min; no quota drop.
- Oracle deviation: the contract asked for observed NAT/conntrack tuples. The runner
  has no conntrack procfs table or CLI (E6), so Native NAT is established by named
  nftables counters (`udp_nat` admission, `native_snat` translated non-DHT UDP toward
  the WAN host, `native_drop` for the blockade) with exact rule identities. No tuple
  is claimed.
- Three earlier dispatches of the same matrix failed before this pass and are
  preserved: 43218411816 (`c265050`) the controller could not find the `cat` tool;
  43220370261 (`9225dcc`) nft rejected a chain named `snat` (reserved word);
  43227388578 (`0800aa4`) all product cases passed their functional oracles but strict
  verification required an identity for a short-lived APP child that is deliberately
  never sampled.

### 10.5 Open and gated rows

Open: A2b, A5, A6, C5 (composed), C7 (composed recovery after a total outage), D2
(interface/address switch and NAT rebinding), D4 (product), G2 (signal over a
NAT-ed Native path). Closed by E8: E1 (owned segment), F1 (observed), C2, C4b, D3,
C7 (typed failure), G2 (standby over Ygg). Gated: E2, E3.

### 10.7 Extension matrix run (E8)

Fork workflow_dispatch 43245366525 on `17b711c`, runner image 20261101.186.1,
contract [p13-controlled-network.md](../plans/p13-controlled-network.md) (extension
section). Phase status `pass`: 12 product cases (the four of 10.4 unchanged plus
`lan-signal`, `lan-standby`, `relay-denied-signal`, `failover-standby`,
`failover-signal`, `denied-blocked-standby`, `dht-drop-signal`, `outage-standby`)
and the three cleanup controls. All 53 generated nft rulesets passed `nft --check`
first. Phase 185.2 s of 20 min, forwarded 582,967 B (largest router quota use
101,583 B of the 2 MiB per-router case quota; budget re-split to 56 MiB allocated of
64 MiB), 269,150 B of artifacts, zero leftover namespaces, host firewall and
`ip_forward` unchanged. Two earlier dispatches failed and are preserved: 43241277233
(`72db069`; `lan-*` failed because the Server published an unreachable LAN-side
candidate first, `failover-signal` and `dht-drop-signal` expected the Client to exit)
and 43243607361 (`7f89780`; only `dht-drop-signal` failed, with the wrong fail-closed
oracle). Fixes were test-harness only; no product code changed. Dispatches used: 3 of
the at most 4 allowed for the extension.

Findings worth keeping: after a Native path is lost mid-session in signal mode the
Client stays alive and fails new streams closed within about 5 s; with the DHT
unreachable the signal-mode Client still connects (relay signaling, then Native).

### 10.6 Non-claims

- Standby Ygg APP in B1 is proven by path exclusion and counters, not by a
  Yggdrasil-layer route counter; child route counters are not observed anywhere.
- Normal-process loopback and in-process results do not imply NAT, LAN, IPv6 or
  public-network behavior.
- E8 timings are one run per case: the 10 s failover result (7.0 s) is not a
  95th-percentile claim, APP 1 of the failover case is not path-excluded, and the
  LAN rows use an owned documentation-range segment, not RFC 1918 addresses or devices.
- The runtime-block failover models the loss and return of the Native path; it is not
  an interface or address switch, NAT rebinding, or an IPv6 or NAT-type result.
- Retained component results (E1) were not revalidated on a fresh SHA; a targeted
  pass is not full-sprint acceptance.
