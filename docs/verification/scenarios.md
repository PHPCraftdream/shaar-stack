# Sha'ar Stack Verification Scenario Matrix (P01, P13 report)

Date: 2026-10-21. Revised: 2026-10-22 — reconciled to the native Rust Yggdrasil
backend (crate `yggdrasil` 0.3.1, pinned commit
c9a54f1587bb133a06072596484c972a336db0d2); Go/cgo is removed. Revised:
2026-11-12 — the P13 acceptance report (section 10) was added and the status
column of every table was updated from the accepted evidence recorded in this
repository. Revised again on 2026-11-12 — section 10 rows E1, F1, G2, C2, C4b,
C7 (typed failure) and D3 were closed, and D2 narrowed, by the extension run E8.
Revised on 2026-11-12 (third time) — rows A2b, A5, A6, C5, C7, D2, D4 and G2 were closed or
recorded as findings by the remaining-row runs E9 (section 10.8).

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
| Both sides behind NAT (cone types) | Connection without port forwarding | Connection established through negotiation, data over direct UDP | CI rig | accepted at P03 fixture level (run 39860587690 at `77c8ab6`); relay-less product double-NAT direct punching proved in the namespace fixture on 2026-11-15 (§10 A5); relay-configured and symmetric cases open |
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
| E9 | `1d36cd5`, `6f7c0ce`, `31fd921` | fork workflow_dispatch, six dispatches of the three groups (section 10.8): nat 43255837358, 43258223283, 43262313789; faults 43257222340, 43262304898; base 43262321962; fork ordinary CI of each SHA (the last one 43259704035 after a re-run of its cancelled Windows leg) | Sixteen further namespace product cases in two new groups next to the unchanged base group; details in 10.8 |
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
| A2b | Direct IPv6 with normal binaries or namespaces | both | accepted for IPv6-only Native data between owned segment hosts (with an explicit IPv6 hint); key-only dial order not accepted | E9 `ipv6-signal`/`ipv6-standby` (faults group, dispatch 43262304898, `31fd921`): Client and Server are hosts on the owned segment (no NAT, no forwarding) with documentation-prefix addresses `2001:db8:13::1` and `::2`; the signed record lists the Server's IPv6 candidate; IPv4 Native UDP between the two hosts is dropped for the whole case (3 and 2 dropped probes), the Client dials the published IPv6 candidate as its `server_address` hint; APP 61/61, accepts 1, exit 0 in both modes; `lan6_native` 19/24 and `lan6_sent` 24/19, `lan_native` (IPv4) 0 on both hosts, forwarded bytes 0, `ipv6_drop` 0, router IPv6 forwarding stays 0. Findings from the first dispatch (43257222340, `1d36cd5`): with both families open and no hint, the path in use differs between runs (the standby run moved to IPv6 in 0.06 s after the IPv4 drop, the signal run did not recover within 40 s: `forwarding setup deadline exceeded`), and the key-only dial tries the published IPv4 candidate first, where a silent candidate consumes the whole attempt (see A5). The hint run is not a key-only discovery proof | Native QUIC over IPv6 (IPv4 UDP dropped, Ygg denied on the Client side) | namespace segment |
| A3 | Single NAT (Client behind Router A, Server on WAN), Native positive control, Ygg transit denied | signal | accepted | E4 case `native-signal`: APP 61/61 bytes, target accepts 1, Client exit 0; Router A `native_snat` 22 pkts / 10,799 B, `udp_nat` 2 pkts, `native_drop` 0, `tcp_drop` 1 pkt (denied Ygg transit); Server published `203.0.113.10:44346` | Native QUIC through Router A masquerade; relay/Ygg APP excluded by rules | namespace NAT |
| A4 | Single NAT, Native positive control, Ygg unavailable | standby | accepted | E4 case `native-standby`: APP 61/61, accepts 1, exit 0; `native_snat` 23 pkts / 10,853 B, `tcp_drop` 4 pkts / 240 B | Native QUIC through Router A masquerade; fallback unavailable yet APP succeeds | namespace NAT |
| A5 | Direct Native hole punching through double NAT | both | tested: **direct path proved without a relay** (`dnat-cone-norelay-*`, 2026-11-15 update below); **and with a pinned relay when a reflexive source exists** (`dnat-cone-relaypunch-*`, 2026-11-16 update below); relay-configured cones without any reflexive source and symmetric NAT still **no direct path** (E9 negative finding, open) | E9 `dnat-cone-*` and `dnat-cone-relay-*` (nat group, dispatches 43258223283 at `6f7c0ce` and 43262313789 at `31fd921`; the first dispatch 43255837358 at `1d36cd5` expected a punch and failed, preserved): both routers use a port-preserving cone NAT (live probe: 3 of 3 datagrams keep the source port on each router). The normal products do not punch: the signed record lists only the Server's private address (`10.0.2.2:<port>`), the Client ends with "no usable path remained within the attempt budget" (exit 1, 32.6 s), target accepts 0, and `peer_sent`/`peer_recv` (translated Native UDP between the two routers) are 0 on both routers, in both modes with Ygg denied. Direct-first: Client-side `relay_tcp` 0, because the silent private first candidate consumes the 3 s attempt, so relay negotiation is never reached (source `crates/shaar/src/startup/role/dialers.rs`; recorded E9 observation). Superseded for the current code by leaf L1 (dial ordering, `docs/plans/p13-controlled-network.md` R1, 2026-11-14): the dialer now orders candidates public/reflexive-scope first, bounds each private/local candidate with a fixed 1 s slice, and drops timed-out candidates from the list, so relay negotiation is reached inside one attempt — compiled and CI evidence pending. Relay-first (Client DHT queries dropped, `dht_drop` 13): relay signaling does happen (`relay_tcp` about 290 and 300 on the two routers) and still no direct path (`native_out` 7 and 8: translated Native UDP left both routers, none reached the other). Likely cause (source-derived, not separately proven): no source of reflexive addresses (Minimal preset, no STUN/QAD, observed addresses ignored), so neither side learns the other's mapped endpoint. Supporting fixture control (recorded, never decisive): two plain UDP sockets with harness-known public endpoints exchanged datagrams through both routers in 4 of 4 cases of 43258223283 (with an unbounded loop, since bounded) and in 2 of 4 cases of 43262313789 (bounded; the other two missed, cause not established, so the control is now recorded without deciding a verdict). Earlier fixture-only evidence: P03 run 39860587690 at `77c8ab6` with configured public candidates. **Update 2026-11-15** (leaves L4 punch over Yggdrasil control datagrams, L2b fast reflexive learning, L3a opt-in publication, L5 cases; design R5 of `p13-controlled-network.md`), relay-less group `punch`, three dispatches, each on a SHA with green fork CI: 43739106115 at `9c7cf7e` FAIL (the Client offered 0 candidates: `SharedResources::public_address()` read the owner that had moved into the maintenance task; fixed), 43742025339 at `d1c2b38` FAIL (1 candidate offered, the Server answered and probed, `peer_recv` 0 on both routers: with the router input chain open, an early peer packet is accepted and, by hypothesis not read from a conntrack table, leaves an entry that moves the port of the later mapping), 43743773385 at `119fbe8` PASS (the routers drop unsolicited UDP on input like a gateway firewall): `dnat-cone-norelay-signal` and `-standby` end with `shaar: client punch candidates=1 outcome=direct`, `route path=native` and APP exact 61/61 (accepts 1), `peer_recv` 29 and 36 (signal) and 23 and 27 (standby), `hole_in` 0 and 4 (early packets dropped); in standby the Client first used `ygg-standby` and switched to Native after the punch; the guard `dnat-cone-dhtdrop-signal` (Client DHT answers dropped, so no reflexive vote) stays a fallback with APP denied. One run per case, two Linux conntrack cone NATs with a stateful input policy, one owned Yggdrasil hub; not a statement about home routers or CGNAT. **Update 2026-11-16** (regression check after DHT-L1, DHT-L2, the shorter fast start and the lookup cap), relay-less group `punch`, fourth privileged dispatch 43794634221 on `70ae253` (green ordinary CI): PASS. `dnat-cone-norelay-signal`: reflexive address exposed after 255 ms, `shaar: client punch candidates=1 outcome=direct reason=direct elapsed_ms=75`, `route path=native candidates=record:1 resolve=found`, APP exact 61/61, 65,155 forwarded bytes; `dnat-cone-norelay-standby`: one `no-answer` attempt, then `outcome=direct` after 19 ms, native route, APP exact 61/61; the guard `dnat-cone-dhtdrop-signal` stays a fallback (`candidates=0`, APP carried over standby for 30.6 s). The three cleanup controls pass. Four of six dispatches used. **Update 2026-11-16 (leaf L4b)**: the punch rendezvous over the authenticated libp2p carrier link of the relay circuit, so a composition with a pinned relay can punch without Yggdrasil. Group `punch` gained `dnat-cone-relaypunch-signal` and `-standby` (the relay is pinned in both configs, the Client-side router allows only the relay TCP service so Yggdrasil carries nothing, the Server publishes the voted endpoint; the oracle was written before the run), fifth privileged dispatch 43867617110 on `b95f1a5` (green fork CI 43866538507 and upstream CI 43867542657): PASS. `dnat-cone-relaypunch-signal`: `shaar: client punch candidates=1 outcome=direct reason=direct elapsed_ms=13`, `route path=native`, APP exact (accepts 1, Client exit 0, 6.7 s active), `peer_sent`/`peer_recv` 40/33 on Router A and 33/39 on Router B, Client-side `ygg_tcp` 0 and `relay_tcp` 134, `hole_in` 0; `dnat-cone-relaypunch-standby`: `outcome=direct` after 11 ms, native route, APP exact, `ygg_tcp` 0, `relay_tcp` 136, `peer_sent`/`peer_recv` 37/31 and 31/36. In the same dispatch the relay-less cases and the guard behaved as before (`norelay-signal` direct after 73 ms, `norelay-standby` direct after 1,023 ms, `dhtdrop-signal` fail closed with accepts 0 and exit 1) and the cleanup controls passed. The relay-configured cones that have no reflexive source (`dnat-cone-relay-*`, Client DHT dropped) were not re-run and stay fail-closed controls. One run per case, two Linux conntrack cone NATs with a stateful input policy, one owned relay fixture; not a statement about home routers, CGNAT or public relays. Five of six dispatches used. **Regression of the changed relay dial sequence** (sixth and last dispatch 43870509412 on `8be550f`, group `base`, green fork and upstream CI): PASS, all 12 product cases and the cleanup controls: `dht-drop-signal` (relay-first) APP exact with `relay_tcp` 272, `relay-denied-signal` APP exact, `failover-standby` to Yggdrasil in 7.0 s (bound 10 s), `failover-signal` fail closed, `blocked-*`, `denied-blocked-standby`, `lan-*`, `native-*` and `outage-standby` as accepted before. Six of six dispatches used; the relay-configured cones without a reflexive source (`dnat-cone-relay-*`) and the `faults` rows were not re-run | Direct Native, APP exact: relay-less (Yggdrasil rendezvous) or with a pinned relay (carrier rendezvous) once a reflexive source exists; symmetric NAT and relay cones without a reflexive source: none | namespace NAT |
| A6 | NAT type variety (symmetric, full cone, others) | both | tested for two types (port-preserving cone, fully random ports); other types open | E9 `dnat-sym-*` (dispatch 43258223283): both routers use `masquerade fully-random` (live probe: 0 of 3 datagrams keep the port). `signal`: fail closed (terminal reset, 0 reply bytes, target accepts 0, Client exit 1, 32.6 s) although Ygg TCP was reachable (`ygg_tcp` present, unused for APP). `standby`: exact APP 61/61 through Yggdrasil in 1.2 s (accepts 1, exit 0, Client-side `ygg_tcp` 126 pkts); `peer_*` 0 on both routers. The cone cases of A5 end the same way, so symmetric mapping did not change the outcome | Yggdrasil in `standby` (by counters and by the signal-mode fail-closed control); none in `signal` | namespace NAT |

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
| C5 | Exhausted relay (reservation/circuit limits) | both | accepted for reservation exhaustion at Server startup; circuit exhaustion and Client-side exhaustion not separately run | E9 `relay-full-*` (faults group, dispatch 43257222340, `1d36cd5`): the owned relay allows two reservations; two filler Servers (other identities, same binary) hold them, then the real Server exits by itself with status 1 and `relay reservation failed at startup` after 23.1 s (bounded retries; both modes), fillers alive until stopped, target accepts 0, zero forwarded bytes. The Client reserves only after every direct candidate failed, so Client-side exhaustion ends as in C4, C4b, B1 and B2. Policy and in-process results remain as before: E1 `...signal_and_unusable_fallback_keep_finite_typed_exhaustion` (policy), `...cross_path_capacity_refuses_while_one_shared_slot_is_held` | Finite typed failure; no application route | namespace; policy; in-process role |
| C6 | Unavailable Yggdrasil while Native is available | signal, standby | accepted | A3, A4 (Ygg transit denied; `tcp_drop` counters) | Native QUIC | namespace NAT |
| C7 | Total outage (Native and Ygg both unavailable), typed failure and recovery | standby | accepted (typed failure and recovery) | E8 case `outage-standby`: UDP blocked (`native_drop` 24 pkts) and Client relay and Ygg TCP denied (`tcp_drop` 19 pkts): local admission, terminal reset, 0 reply bytes, target accepts 0, Client exit 1 on its own, active 32.6 s. E9 `recover-standby` (dispatch 43257222340): runtime blocks of Native UDP (24 dropped pkts) and Ygg TCP (36 dropped pkts) before the first APP; APP 1 failed closed, the Client ended with status 1; both blocks removed, a fresh Client started and APP 2 succeeded exact 61/61 **0.083 s** after the removal (fixture bound 40 s; includes the Client start); final Client exit 0, target accepts 1. In-process: E1 `...a_total_outage_is_unavailable_and_a_recovering_fallback_ends_it` | No application route during the outage; Native after recovery | namespace NAT; policy |
| C8 | libp2p carries no APP data | both | accepted (in-process) | E1 identity `...pinned_relay_negotiation_carries_native_payload_with_zero_relay_payload`: Native STREAM, zero Custom/relay APP | Native QUIC after relay negotiation | in-process role |
| C9 | Signal mode never carries APP over Ygg | signal | accepted | E1 identity `...signal_mode_negotiates_but_ygg_never_carries_application_payload`; B2 (zero target accepts with Ygg reachable) | None over Ygg | in-process role; namespace NAT |

**D. Restarts and network change**

| ID | Scenario | Mode | Status | Evidence | Data route | Level |
|---|---|---|---|---|---|---|
| D1 | Console stop/restart of Client and of Server; Server-only restart with the Client retained; fresh-connection recovery | signal, standby | accepted | E1: `real_composed_client_console_stop_and_restart_in_signal_and_standby`, `real_composed_server_console_stop_and_restart_in_signal_and_standby` (lifecycle `ed6fed1`), `real_composed_key_only_payload_and_server_restart_in_signal_and_standby`; process smoke `real_process_console_shutdown_rebind_and_server_restart`. Limits: no transparent old-TCP reconnect; bounded fresh-connection recovery only | Native QUIC to the restarted Server's newly published port | normal-process loopback |
| D2 | Network change (interface/address switch, NAT rebinding) mid-session with recovery | both | accepted for Native path loss and recovery, Client address switch and NAT state loss with new mapping; no dedicated external-port-range change | E8 `failover-*` model loss and return of the Native path with a runtime block table (signal: after the block APP 2 fails closed, reset, 0 reply bytes, 5.1 s, `native_snat` growth 0, 28 dropped pkts, target accepts stay 1, the Client stays alive and stops with exit 0). E9 `switch-signal`/`switch-standby` (nat group, dispatch 43258223283): APP 1, the Client host moves from 10.0.1.2 to 10.0.1.3 on the same interface, APP 2 succeeded exact 61/61 **1.43 s** (signal) and **0.70 s** (standby) later (bound 40 s), `native_new` +1 (a new NAT mapping from the new address), `native_snat` +31 and +19, accepts 2; Ygg denied on the Client side, so Native carried both APPs. NAT rebinding is covered by D4 (the mapping is recreated; whether the external port changed is not asserted) | Native QUIC (Ygg denied) | namespace NAT |
| D3 | Failover to Yggdrasil within 10 s after Native loss mid-session | standby | accepted (single run; no p95 claim) | E8 case `failover-standby`: APP 1 with Native up (`native_snat` 20 pkts; Ygg was open, so Native carriage of APP 1 is policy plus counters, not exclusion); runtime Native UDP block, APP 2 succeeded exact 61/61 **7.017 s** after block insertion (limit 10 s; run 2: 7.085 s), `native_snat` growth 0 during the block, 32 dropped Native pkts, Ygg TCP +98 pkts; block lifted and Ygg TCP blocked, APP 3 succeeded exact 61/61 **13.061 s** after the lift (fixture bound 40 s), `native_snat` +30 pkts; target accepts 3, 183/183 bytes | APP 2: Yggdrasil by path exclusion (UDP blocked); APP 3: Native by path exclusion (Ygg blocked) | namespace NAT |
| D4 | NAT keepalive; recovery after losing the NAT hole | both | accepted for loss of the NAT mapping and recovery (single NAT); long-period keepalive on real devices open | E9 `hole-signal`/`hole-standby` (dispatch 43258223283): APP 1, then Router A's WAN link is cycled down and up (masquerade drops every entry bound to that interface), APP 2 succeeded exact 61/61 **0.058 s** later in both modes (bound 40 s), `native_new` +1 (the old mapping was gone and a new one was created), `native_snat` +11 and +8, `hole_in` 0 and 1 (UDP reaching the router itself after the flush), accepts 2; Ygg denied, so Native carried both. The fast recovery reflects an idle connection with sub-millisecond RTT in the fixture; it is not a keepalive-interval or NAT-timeout measurement. Earlier fixture-only: P03 run 39867392149 at `7a628e5` | Native QUIC (Ygg denied) | namespace NAT |

**E. LAN, devices, public networks**

| ID | Scenario | Mode | Status | Evidence |
|---|---|---|---|---|
| E1 | LAN: both sides on one L2 segment, no router | both | accepted (owned documentation-range segment; not a real LAN) | E8 cases `lan-signal`, `lan-standby`: Client and Server are single-interface hosts on the `203.0.113.0/24` segment with the DHT/relay/Ygg fixtures; signed record lists exactly `203.0.113.2`; APP 61/61, accepts 1, exit 0 in both modes; both routers forwarded 0 bytes and `udp_nat`, `tcp_nat`, `native_snat` 0; Native UDP sent and received on the segment (rtr_a/rtr_b `lan_sent` 22/19 and `lan_native` 19/22 in signal; `lan_sent` 24/21 and `lan_native` 21/24 in standby). Does not cover RFC 1918 addresses, multicast discovery, Wi-Fi or devices |
| E2 | Real home, mobile, cafe networks and devices | both | gated | Needs separate user permission and device access; no NAT claims are made |
| E3 | Public Yggdrasil/relay interoperability and live smoke (task D2) | both | gated | Authorized in principle on 2026-11-09; execution through the default-off contract authorized on 2026-11-14. The contract is relay-optional (`libp2p_relay: null`) with the approval recorded; since leaf L0 the composed products start without signaling relay fields. The first bounded live smoke (fork run 43629141158) proved the public Mainline bootstrap nodes and both Yggdrasil peers but failed at the pinned public relay reservation; the relay-less follow-up (fork run 43671098240, source 289bb1f) passed as a bounded live observation: the key-only Client completed one exact 43 byte exchange through the Server over public Yggdrasil peers within every cap, with the Yggdrasil route inferred by exclusion and the DHT resolution not directly observable. A third run (fork run 43751396899 at `5d43914`, direct-path attempt) passed with the route directly observed as Yggdrasil standby and no punch exchange (all six Client attempts offered no candidate, four lasted 0 ms): no direct path on a public network has been observed yet. A pass stays a bounded live-network observation, not acceptance of the end-to-end claim (`docs/plans/v1-focus.md`, section "Public live smoke contract") |

**F. No n0**

| ID | Scenario | Status | Evidence |
|---|---|---|---|
| F1 | No dependence on n0 infrastructure | accepted at source-guard level and observed zero contact in the namespace matrix | Product endpoints use `presets::Minimal` with no n0 relay, address lookup or port mapping (`crates/shaar/src/network/admission/mod.rs`, `crates/shaar/tests/backend_gate.rs`). E8: in all 12 product cases both routers' observation counters (`outside_fwd`, `outside_out`, `udp53`, `tcp443`: packets to any destination outside `10.0.0.0/8`, `203.0.113.0/24`, loopback and link-scope multicast, and UDP/53 and TCP/443 to such destinations) are exactly 0, with the detector proven live before each case by probes to TEST-NET-1 `192.0.2.77`. Limits: IPv4 only; products in the WAN namespace have no route at all (prevented, not counted); not a packet capture of host namespaces |

**G. Authorization**

| ID | Scenario | Mode | Status | Evidence | Level |
|---|---|---|---|---|---|
| G1 | Unauthorized key causes zero target connections | signal, standby | accepted | E2: `real_composed_denied_key_never_reaches_target_in_signal_and_standby` (authorized control passes first; the denied Client binds locally, gets no APP bytes, ends with terminal EOF/reset and CLI exit 1; Server stays alive and stops cleanly; target accepts are monitored from before the denied start through reaping and the backlog is inspected). In-process: E1 `...disallowed_key_causes_zero_target_connections_and_allowed_key_succeeds` | normal-process loopback; in-process role |
| G2 | Unauthorized key under namespace NAT or over the Ygg fallback path | both | accepted | E8 case `denied-blocked-standby` (Native UDP blocked, Ygg only): authorized control first (APP 61/61, accepts 1, exit 0), then a second Client with a different valid key: terminal reset, 0 reply bytes, target accepts still 1, second Client exit 1, Server stops cleanly. E9 `denied-native-signal` (faults group, dispatch 43257222340): single NAT, Server in WAN, Native over the NAT, Ygg denied: authorized control first (APP exact, accepts 1, exit 0, `native_snat` 95 pkts), then the second Client with a different key got terminal reset, 0 reply bytes, accepts stayed 1, exit 1, Server stopped cleanly | namespace NAT |

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

Closed by E8: E1 (owned segment), F1 (observed), C2, C4b, D3, C7 (typed failure), G2
(standby over Ygg). Closed by E9: A2b (IPv6-only Native data with an explicit hint), C5
(reservation exhaustion), C7 (recovery), D2 (Client address switch), D4 (NAT state loss),
G2 (signal over a NAT-ed Native path), A6 (two NAT types). Recorded as a negative finding
by E9: A5 (no direct path through double NAT). Still open inside closed rows: key-only
IPv6 discovery (A2b), circuit and Client-side relay exhaustion (C5), other NAT types (A6),
long-period NAT keepalive and real-device rebinding (D2, D4). Gated: E2, E3.

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

### 10.8 Remaining-row matrix runs (E9)

Contract: [p13-controlled-network.md](../plans/p13-controlled-network.md) (remaining-row
section). Runner image 20261101.186.1. Every dispatch ran on a SHA whose ordinary fork CI was
green (the last CI, 43259704035, needed a re-run of its Windows leg that the platform had
cancelled while queued) and started with `nft --check` of all generated rulesets (112, then
120 after the NAT probes; all passed). The six dispatches of the cap:

| Dispatch | Run | Source | Group | Result |
|---|---|---|---|---|
| 1 | 43255837358 | `1d36cd5` | nat | fail: `dnat-cone-signal` and `dnat-cone-standby` expected a punch and failed (the A5 finding); the other six cases and three controls passed |
| 2 | 43257222340 | `1d36cd5` | faults | fail: only `ipv6-*` (family race, see A2b); `denied-native-signal`, `recover-standby`, `relay-full-*` and the controls passed |
| 3 | 43258223283 | `6f7c0ce` | nat | pass: 10 cases and 3 controls (the cone cases now expect fail closed; relay-first cases added; the fixture punch control looped without a bound: about 50,000 datagrams per side in 2 s, a load defect fixed afterwards) |
| 4 | 43262304898 | `31fd921` | faults | pass: 6 cases and 3 controls; phase 137.9 s, forwarded 172,029 B of 32 MiB allocated |
| 5 | 43262313789 | `31fd921` | nat | fail: 8 of 10 cases and 3 controls passed; `dnat-cone-signal` and `dnat-cone-relay-signal` failed at the fixture punch control (host A received 0 datagrams), before any product started; this is a fixture result, not a product result |
| 6 | 43262321962 | `31fd921` | base | pass: the twelve accepted cases and 3 controls unchanged; phase 203.5 s, forwarded 609,232 B |

Dispatches 1 to 6 were all used. After dispatch 5 the control was changed to a recorded,
non-decisive receipt and a drop of unsolicited inbound UDP before conntrack confirmation was
added to its probe table as a hypothesis for the misses (an unsolicited packet would otherwise
create a conntrack entry that takes the peer's preserved source port). **That last change
(branch head) was not dispatched**: the cap was reached. The nat group therefore needs one
more dispatch to verify it; the product verdicts of the nat group (A5, A6, D2, D4) were
produced by dispatches 3 and 5 on code that the head changes only in the control.

Product findings worth keeping:

- Double NAT: no direct path with either mapping flavor and either dial order (A5, A6) as of E9; superseded for the relay-less cone case by the 2026-11-15 `punch` group (A5) and for the pinned-relay cone case with a reflexive source by the 2026-11-16 `relaypunch` cases (dispatch 43867617110).
- A silent published candidate consumes the whole 3 s native attempt, so relay negotiation is
  not attempted (A5 direct-first, A2b without a hint).
- Relay exhaustion at Server startup is a finite typed failure after 23.1 s (C5).
- Native recovered within 0.06 s of a NAT state flush and within 0.7 to 1.4 s of a Client
  address switch in the fixture (D4, D2); these are one-run, idle-connection values.
- After a total outage the Client ends by itself with status 1; a fresh Client reaches the
  Server 0.08 s after the blocks are lifted (C7).

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
- E9 timings are one run per case. The A5 and A6 results are for two Linux conntrack mapping
  flavors and an owned relay; they say nothing about real home routers, CGNAT or other NAT
  types, and the likely cause of A5 is source-derived. The A2b proof uses an explicit hint.
- Retained component results (E1) were not revalidated on a fresh SHA; a targeted
  pass is not full-sprint acceptance.

## 11. P14 resources, complexity and performance (2026-11-12)

Status: measurement accepted at source `c84d9a6` (loopback, one GitHub-hosted runner, one run).
Dispatch 43642328666 passed all 19 rows of the direct case and all 19 rows of the composed
case (11.5). The owner approved the proposed budgets on 2026-11-14 as provisional ceilings
(decision log); they are tightened later from recorded values, not now. Earlier dispatches
43628161108 and 43630351232 (source `3be11f9`) passed the composed case and failed the direct case
in the "memory per concurrent stream" phase on finding 12 (a QUIC `MAX_STREAMS` credit
defect, fixed in `c84d9a6` with a regression test executed in CI on Linux and Windows).
Findings 1, 2, 3, 5 and 12 are fixed and CI-verified; findings 4 and 6 to 10 are open.
Nothing here claims optimal complexity or lock-freedom.

Step advanced: end-to-end step 6 (server forwards to the fixed target) and the
efficiency criterion "bounded resource use per connection and per resolver".

### 11.1 Static review findings

Reviewed: native admission and forwarding, the composed server/client role loops,
the signaling bridge and owner, the Yggdrasil carrier, the executor and the
discovery publisher loop. Positive structure: every queue, map and task set found is
fixed-size (admission pool at most 32 slots; 16 streams per session; JoinSet worker
sets gated by `len() <` the limit; Ygg send queue 32, receive queue 16 per peer and
16 peers; p2p bridge queue 32; executor 64 tasks; allowlist 256 keys; policy map keyed
by allowlisted keys only), pumps are caller-driven, shutdown joins its tasks, and
timers are event-driven (no polling loops; the only periodic work is the 60 s
publication refresh and the 1 s retry of a pending close).

| # | Severity | Location | Finding | State |
|---|---|---|---|---|
| 1 | High | `crates/shaar/src/network/admission/mod.rs:295-318`, `startup/role/server.rs:586` | `Endpoint::accept` awaits the whole inbound handshake (up to 10 s) before the next `Incoming` is taken, and charges a shared admission slot before authentication. One unvalidated or silent Initial stalls every new connection for up to 10 s (`admission/tests.rs:179` shows the 10 s deadline); a few packets per second keep it stalled or exhaust the 32-slot pool. Pre-auth availability, not a data leak. | fixed, tests written (compile and CI evidence pending): accept drives inbound handshakes concurrently in a per-endpoint pending set capped at the session limit, separate from the slot pool — a parked Initial holds no slot and never delays another peer; over-cap attempts are refused; slots are charged only after authentication. Tests in `admission/tests.rs`: `silent_initial_does_not_stall_a_second_peer` (second peer admitted within a 5 s bound while a silent Initial is parked; failed on the serial accept), `pending_handshake_cap_bounds_silent_initials` (pending set capped at `pending_cap`, zero slots held by silent peers, over-cap attempt refused within 3 s) and the rewritten `dropped_accept_retains_the_in_flight_handshake`. Not proven: behavior under real multi-attacker load or non-loopback timing. |
| 2 | Medium | `startup/role/client/run_loop.rs` local accept arm | A failing local `accept` (descriptor exhaustion fails again at once) re-entered the loop with no pause: busy loop plus a log line per iteration. | fixed: 10 ms doubling to 1 s, reset on success, shutdown stays responsive; unit tests `accept_backoff_tests` |
| 3 | Medium | `network/forwarding/pump.rs` (`pump`) | Forwarded TCP sockets kept Nagle enabled, adding delayed-ACK latency to small interactive writes in both directions. | fixed: `set_nodelay(true)` on both the client-accepted and the server-connected socket; test `tuning_tests` (the helper contract; wiring by review) |
| 4 | Medium | `crates/shaar-ygg/src/bridge/carrier_pump.rs:77-88` | One writer task serves all peers; a 1 s send timeout for one peer ends the writer and closes the whole carrier (`shared.close()`), so one stuck peer takes down the Yggdrasil path for all. Peers are allowlisted, so availability only. | reported |
| 5 | Low | `startup/role/server.rs:253-322` | The loop rebuilds the native `accept()` each iteration; when another arm wins (Ygg accept, pump end) an in-flight native handshake is dropped (documented cancel-unsafe contract). Fix belongs with finding 1. | fixed, tests written (compile and CI evidence pending): fixed with finding 1 — native `Endpoint::accept` is cancel-safe per its doc contract, so a losing select arm parks the polled attempt in the endpoint and the next loop iteration completes it; no accept-future retention is needed. Covered by `dropped_accept_retains_the_in_flight_handshake` (same handshake completes after the accept future is dropped). The Yggdrasil accept arm keeps its cancel-unsafe contract. |
| 6 | Low | `startup/role/server.rs:611,619,622,648,650`; `crates/shaar-server/src/main.rs:284` | One blocking `eprintln!` per failed or rejected handshake on an executor thread, unbounded rate under a handshake flood. | reported |
| 7 | Low | `shaar-ygg/src/bridge/carrier_state.rs:226`, `shaar-p2p/src/bridge/state.rs:260` | `next()` rebuilds the 64-slot waiter array (about 1 KiB write) and scans it for every dequeued datagram even with no waiters: O(64) per packet. Candidate: waiter counter; measure first. | reported |
| 8 | Low | `carrier_state.rs:193`, `datagrams.rs:102,305`, `shaar-p2p/src/bridge/state.rs:226` | One heap copy per datagram at queue admission, one for the carrier envelope and one at delivery (about three per Ygg datagram); bounded by the queues above, standby path only. | reported |
| 9 | Low | `shaar-ygg/src/bridge/mod.rs:137` | The single reader answers an allowed peer's ping inline for up to 500 ms, delaying datagram reads. | reported |
| 10 | Low | `crates/shaar-client/src/main.rs:318` | The legacy coordinator dials inside its select arm (up to attempts times 10 s), so worker reaping and session-loss detection pause meanwhile; shutdown is still observed. | reported |
| 11 | Info | `network/forwarding/pump.rs`, `protocol.rs` | Per stream two 8 KiB `tokio::io::copy` buffers; setup is bounded to 10 s, an established stream has no idle deadline (bounded by 16 streams per session and the 5 s native QUIC idle timeout). | accepted |
| 12 | High | `crates/shaar/src/network/admission/mod.rs` transport config; `crates/shaar/src/network/admission/ygg/mod.rs` (same line) | quinn announces `MAX_STREAMS` credit with a 1/8-window hysteresis (`queue_max_stream_id`), so the peer's announced stream budget trails freed streams by up to `window / 8`. Advertising exactly `STREAM_LIMIT` (16) let the announced budget sit at 14 credits in the direct measurement: 221 drained streams (20 warm-up + 200 latency + 1 bulk) put the last announcement at free 219, so one held stream blocked in `open_bi` with no credit, hit the 10 s setup deadline, and the client reset the local connection (`forwarding setup deadline exceeded`, then `smoke: Connection reset by peer`; dispatches 43628161108 and 43630351232 at 3be11f9). Composed passed because its one extra drained exchange (the `b"first"` probe) landed the trail at 0 and announced exactly 16 credits — the direct and composed forwarding paths are equivalent; the asymmetry was stream-count arithmetic, not a product path difference. Not finding 10: no dial occurred inside the failure window. The harness retry (10 s) cannot cover a full 10 s client setup deadline, so the harness cannot mask this class and no budget changes. | fixed, test written (compile and CI evidence pending): the advertised window is `STREAM_LIMIT + 2` (`window - window / 8 >= STREAM_LIMIT`; app-level semaphore and the `serve` gate stay at 16); regression test `sixteen_concurrent_streams_open_after_a_drained_stream` (one drained stream, then 16 held concurrent forwards over real loopback endpoints) fails on the bare 16 window and passes with the margin. Proven so far: the mechanism from the quinn-proto 0.11.12 source and both dispatches' timings (the failing phase consumed one 10 s deadline in both). Not yet proven: the regression test run and the fixed direct measurement passing all rows in CI. |

Hot-path complexity: per forwarded byte the SDK adds no per-packet work on Native
(copy loop and QUIC only); admission and allowlist lookups are O(log n) with n at
most 256; per-session state is O(1). Worst-case memory is bounded by transport
windows: per session 1 MiB receive plus 1 MiB send, per stream 256 KiB receive
window, 16 streams, so at most 32 sessions times 2 MiB = 64 MiB of QUIC window plus
about 8 MiB of copy buffers and the Ygg queues (at most 32 datagrams sending and
256 receiving, each up to the carrier MTU). These are bounds, not measurements.

### 11.2 Budgets (proposed 2026-11-12, approved 2026-11-14 as provisional ceilings)

Environment: one GitHub-hosted `ubuntu-latest` runner, release build, loopback
only, `/proc` sampling, 20 warm-up exchanges first. Idle window 30 s (direct) or 65 s
(composed standby, to include a 60 s refresh). The first run is calibration; budgets
are ceilings with roughly 2x margin and will be tightened from recorded values.

| Budget | Direct | Composed standby |
|---|---|---|
| Steady RSS per process | at most 48 MiB | at most 96 MiB |
| Peak RSS (VmHWM) after 64 MiB echo | at most 96 MiB | at most 160 MiB |
| Idle CPU per process (one core) | at most 1.0% | at most 2.0% |
| Server RSS added by the first session | at most 4 MiB | at most 4 MiB |
| RSS per concurrent stream (16 held) | at most 512 KiB | at most 512 KiB |
| New-connection round trip p95 (200 sequential) | at most 100 ms | at most 100 ms |
| Bulk echo throughput (64 MiB) | at least 20 MiB/s | at least 20 MiB/s |
| Back-pressure: bytes accepted by a never-reading target | at most 32 MiB | at most 32 MiB |
| RSS growth during that stall | at most 12 MiB per process | at most 12 MiB per process |
| Leak check after 15 (direct) or 6 (composed) client restarts | server fds at most +2, threads at most +2, RSS at most +max(4 MiB, 10%) | same |
| Server stop to exit | at most 5 s | at most 5 s |

Task count is observed through threads and descriptors only (a tokio task count is
not visible from outside the process).

### 11.3 Harness (dispatched by the resource measurement workflow)

`crates/shaar/tests/identity/process_smoke/composed/resources/` holds two ignored
tests, `measure_resource_budget_direct` (legacy direct config) and
`measure_resource_budget_composed` (standby over the owned relay, Mainline fixture
and Yggdrasil transit, reusing the P13 composed fixtures), plus `/proc` sampling and
traffic helpers with their own unit tests. They run only through
`.github/ci/run.py resource-build` / `resource-run`, selected by the default-off
`resource_measurement` input of `.github/workflows/sdk-lock.yml` (exclusive with the
other modes; ubuntu only; unprivileged, no public network, no lock generation). Hard
caps: 300 s and 540 s test deadlines, 16 minute step timeout, 64 MiB bulk, 96 MiB
stall cap, loopback addresses only. Each case writes `<mode>.json`; the job fails if
any row violates its budget or a report is empty, and uploads `target/ci-resources/`. Two dispatches ran at source 3be11f9; their status is recorded at the section top.

### 11.4 Non-claims

The accepted measurement is one dispatch at source `c84d9a6` on one shared GitHub-hosted
runner over loopback: it is a pass/fail check against provisional ceilings, not a 95th
percentile or a capacity claim. Signal-mode composed, Yggdrasil-carried payload
throughput, IPv6, public-network and long-duration (hours) behavior are not covered.
Findings 4 and 6 to 10 are open (see 11.1).

### 11.5 Results (dispatch 43642328666, source `c84d9a6`, both cases passed)

| Measure | Direct | Composed standby | Ceiling (direct / composed) |
|---|---|---|---|
| Steady RSS, server / client (MiB) | 15.8 / 16.1 | 22.8 / 22.5 | 48 / 96 |
| Peak RSS after 64 MiB echo, server / client (MiB) | 18.2 / 18.8 | 24.5 / 24.1 | 96 / 160 |
| Server RSS added by the first session (MiB) | 1.46 | 1.04 | 4 |
| Idle CPU, server / client (%) | 0.07 / 0.03 | 0.06 / 0.14 | 1 / 2 |
| New-connection round trip p50 / p95 (ms) | 0.53 / 0.58 | 0.54 / 0.60 | p95 100 |
| Bulk echo throughput (MiB/s) | 135.8 | 73.9 | at least 20 |
| RSS per held stream, server / client (KiB) | 0 / 0.75 | 0 / 0 | 512 |
| Bytes accepted by a never-reading target (MiB) | 8.25 | 8.38 | 32 |
| RSS growth during that stall (MiB) | 0 / 0 | 0.004 / 0 | 12 |
| Server growth after 15 (direct) or 6 (composed) client restarts: fds / threads / RSS (MiB) | 0 / 0 / 0.85 | 0 / 0 / 0.22 | 2 / 2 / 4 |
| Server stop to exit (ms) | 2.8 | 4.0 | 5000 |

Every value is far inside its provisional ceiling, so the ceilings can be tightened by a
large factor once more runs exist; this section does not tighten them. The first two
dispatches also show that composed values are stable between runs (steady RSS 22.8 to 25.4 MiB,
p95 0.41 to 0.60 ms). The raw reports are the `resource-budget` artifact of the dispatch.

### 11.6 Re-measurement on the final code (dispatch 43795953404, source `70ae253`, both cases passed)

Task EFF-RE re-ran the same harness after the NAT leaves, DHT-L1 and DHT-L2 (loopback only,
release products, no public network, the same ceilings). Both cases passed with 19 rows each, all 38 rows
inside their ceilings. The later commits up to `361e169` change only documents, CI probes and the CI
selection map, so this measurement stays valid for that product code. One run per mode.

| Measure | Direct | Composed standby | Section 11.5 (direct / composed) |
|---|---|---|---|
| Steady RSS, server / client (MiB) | 16.3 / 16.1 | 23.5 / 23.0 | 15.8 / 16.1 and 22.8 / 22.5 |
| Peak RSS after 64 MiB echo, server / client (MiB) | 18.6 / 18.5 | 25.2 / 24.5 | 18.2 / 18.8 and 24.5 / 24.1 |
| Server RSS added by the first session (MiB) | 1.64 | 0.98 | 1.46 and 1.04 |
| Idle CPU, server / client (%) | 0.03 / 0.00 | 0.06 / 0.12 | 0.07 / 0.03 and 0.06 / 0.14 |
| New-connection round trip p50 / p95 (ms) | 0.53 / 0.59 | 0.55 / 0.59 | 0.53 / 0.58 and 0.54 / 0.60 |
| Bulk echo throughput (MiB/s) | 137.2 | 78.4 | 135.8 and 73.9 |
| RSS per held stream, server / client (KiB) | 0 / 0.75 | 0 / 0.50 | 0 / 0.75 and 0 / 0 |
| Bytes accepted by a never-reading target (MiB) | 8.06 | 6.19 | 8.25 and 8.38 |
| RSS growth during that stall (MiB) | 0 / 0 | 0 / 0 | 0 / 0 and 0.004 / 0 |
| Server growth after client restarts: fds / threads / RSS (MiB) | 0 / 0 / 0.70 | 0 / 0 / 0.11 | 0 / 0 / 0.85 and 0 / 0 / 0.22 |
| Server stop to exit (ms) | 3.2 | 3.8 | 2.8 and 4.0 |

The largest change against 11.5 is the composed steady RSS, +0.7 MiB, far inside its ceiling of 96 MiB. The
ceilings are not tightened here. The raw reports are the `resource-budget` artifact of the dispatch.

## 12. P16 first-version readiness (2026-11-16)

Prepared on `65617d3` (the product code is that of `f166782`, the L4b merge; everything after it is documentation and the
namespace harness). This is the cross-check that development plan P16 asks for. It creates no evidence of its own: every
statement cites a run or a section above. Whether the first version is accepted is the owner's decision; the open risks and
gates the owner must weigh are in 12.5.

### 12.1 The end-to-end scenario, step by step

| Step | What is established | Evidence | Limits |
|---|---|---|---|
| 1. Server publishes a signed record under its key | accepted | A1; real signed Mainline record in the composed role tests; live DHT works since DHT-L1 | A reflexive address is published only with `publish_address: plain` (default off, owner decision 2026-11-15) |
| 2. Client knows only the Server key | accepted | A1 (key-only discovery, exact APP) | |
| 3. Client resolves the record and tries direct QUIC | accepted | A1, A3, A4; P10 first byte in 12.2 | On a live DHT the record lookup outlives a 3 s attempt (DHT-L2 hands it to a task of its own); the first-byte criterion for a cold lookup is proven in the fixtures only |
| 4. Negotiate over libp2p or Yggdrasil signaling and hole-punch | tested in the namespace fixture: direct path through two port-preserving cone NATs with a stateful input policy, exact APP, **without a relay** (Yggdrasil rendezvous, 2026-11-15 and again 2026-11-16) and **with a pinned relay while Yggdrasil is closed to the Client** (carrier rendezvous, dispatch 43867617110) | A5 | Not established: symmetric NAT (A6: no direct path, `standby` carries over Yggdrasil), CGNAT, real home networks, and any direct path between the two cloud runners of the live smoke (13 bounded dispatches, none obtained; see 12.5) |
| 5. UDP blocked: Yggdrasil | accepted | B1 (`standby` exact), B2 (`signal` fails closed), C7, D3 (failover 7.0 s in the namespace run 43870509412, 9.03 to 9.05 s in the P10 fixture) | Public Yggdrasil interoperability is a bounded observation (E3) |
| 6. Allowlist, then one fixed TCP target | accepted | G1, G2 (also over the Yggdrasil path), C8 and C9 (libp2p and `signal` carry no APP) | |

Every namespace row above was executed once per case; the matrix does not claim a distribution.

### 12.2 Efficiency criteria of 2026-11-05, recomputed on the final product code

Source: the retained `p10-*.csv` files of the full-scope fork run 43861074349 on `f166782` (both OS green), nearest-rank p95
over 20 samples, read with a stdlib script as inert data.

| Criterion | Limit | Linux | Windows |
|---|---|---|---|
| First byte, known address | 3 s | 112.2 ms | 111.6 ms |
| First byte, cold DHT lookup | 10 s | 114.1 ms | 128.0 ms |
| Failover to Yggdrasil under blocking of every IP path | 10 s | 9.029 s | 9.051 s |
| Share of connections that end on the direct path | 95 % | 98.387 % (61 of 62) | 98.387 % (61 of 62) |

All four hold. The known-address value is about 30 ms above the campaign of `361e169` (80.4 to 81.1 ms on Linux); samples
move by that much between runs on shared runners and both startup limits are far away. The criteria are measured in
a controlled fixture, never on the public network.

### 12.3 Resources (P14), re-measured on the final code

Dispatch 43875890398 on `65617d3` (release products, loopback only): **38 of 38 rows inside their ceilings** (19 direct, 19
composed). Composed steady RSS 23.6 MiB server and 23.0 MiB client against 96 MiB, idle CPU 0.08 % and 0.14 % against 2 %,
round trip p95 0.457 ms, bulk echo 95.0 MiB/s against a floor of 20, 6.4 MiB accepted from a never-reading target against 32,
server growth after client restarts 0 fds, 0 threads and 0.19 MiB, server stop in 4.2 ms. The ceilings stay as approved on
2026-11-14.

### 12.4 CI and legal checks on the final code

- Full-scope fork run 43861074349 on `f166782`: green on Linux and Windows. Libtest totals: Linux 1,057 passed, 0 failed, 21
  ignored (23 binaries); Windows 1,064 passed, 0 failed, 15 ignored (23 binaries); the Windows-only SDK-parallelism
  diagnostic step 1,611 passed and 0 failed over 3 binaries. Later commits (harness cases,
  documentation) were checked by targeted runs: fork 43866538507 and 43873666590, upstream develop 43867542657, 43869466418
  and 43874597907, all green on both OS.
- Privileged namespace matrix, all six authorized dispatches used: 43867617110 (`punch`, 5 of 5 cases) and 43870509412
  (`base`, 12 of 12 cases) on the final product code; earlier dispatches are indexed in 10.1.
- Platform builds (build only, nothing executed, packaged or released): fork run 43874797967 on `65617d3`: Linux
  x86_64, Windows x86_64, macOS aarch64 and Android aarch64 built. **macOS x86_64 was not built on this SHA**: the job never
  started in three attempts (the first run and two re-runs, each cancelled after about 15 minutes of queueing with "The job
  was not acquired by Runner of type hosted even after multiple attempts" and GitHub's notice about macOS arm64 runner
  capacity), so this is a runner-capacity event with no build output either way. The same target built from the same
  sources up to `1e6da6c` (fork run 43834970372), and the macOS aarch64 job built the final sources with the same toolchain
  in this run. A re-run when capacity returns would close the row. Android stays build-only: no device or emulator ran it.
- First execution on macOS: the `Process feedback` matrix of 2026-11-16 (run 43846060445) ran the 13 reviewed process
  cases on `macos-latest` (aarch64) and passed; debug products, loopback only.
- Licence gate: cargo-deny reports `licenses ok` in the full-scope run, and the Linux notice manifest of that run lists 371
  linked packages, 0 release blockers, 13 reviewed not-distributed identities and `release_ready` true (the Windows manifest
  is retained in the same run and was not re-read in this pass). The licence texts are authentic upstream files; the
  elections of 2026-11-14 are an engineering decision, not legal advice.
- Reproducibility: every build uses the pinned toolchain 1.99.1, the locked graph and prepared sources with verified
  checksums. Byte-for-byte reproducibility of the binaries is not claimed and was not tested.
- Secrets: the unit oracles of `security.md` (SEC-CFG-02, SEC-KEY-03) cover logs and `Debug` output; the live smoke evidence
  schema carries public keys only. No repository-wide scan of CI artifacts for secret material exists.

### 12.5 Open risks and gates for the owner

| # | Item | Kind | State |
|---|---|---|---|
| 1 | Encrypted reflexive address (L3b, the opt-in of 2026-11-15) | owner decision made, work open | On 2026-11-16 the owner decided that L3b is part of the first version, with exactly two publication options, open and encrypted with a key the client must know (design note v3, `p13-controlled-network.md` section 7). The leaf has started; no cryptographic code is merged yet. Finishing it reopens the final checks: a full-scope run, the platform builds and a re-measurement on the new product code |
| 2 | Direct path between real networks | product risk, bounded observation | Thirteen live dispatches: ten passed over Yggdrasil, none obtained a direct path between the two cloud runners. The last one (43870725952) shows the Server never learned its public address (five reflexive windows skipped), so it answered none of 30 Offers. By the decision of 2026-11-15 this is an observation, neither a pass nor a failure. Further live work stays inside the recorded contract |
| 3 | Real devices and networks (E2), Android execution | gated | No home, mobile or cafe network and no device ran the products; Android is build-only |
| 4 | NAT variety (A6) | not established | Only port-preserving cone (direct) and fully random ports (no direct path, `standby` carries) were run |
| 5 | Long-period NAT keepalive (D4), circuit exhaustion and Client-side relay exhaustion (C5) | not established | Single NAT recovery and Server reservation exhaustion are accepted; the rest needs real devices or a new case |
| 6 | The reflexive address comes from the Mainline DHT only | design limit | A side that cannot learn it offers no candidate; an unanswered Offer holds the Client for up to 1.5 s per attempt (answering with an empty list would end the wait; not done) |
| 7 | Windows flake `pinned_relay_negotiation_carries_native_payload_with_zero_relay_payload` (FLAKE-W1) | open defect | A diagnostic is merged; the fix waits for a repeat of the failure. It did not repeat in the six Windows runs listed in 12.4 |
| 8 | Privileged dispatches | resource | All six authorized dispatches are used; any further namespace run needs a new grant |
| 9 | Public-network, legal, release gates | gated | Publishing crates, a release, a version change, commit and push, public peers beyond the recorded contract and legal clearance of the notices stay separate explicit requests |

### 12.6 What this section does and does not conclude

Every mandatory scenario of the matrix is accepted, or tested with its limits recorded, or gated as listed above. On
2026-11-16 the owner accepted this report with its open risks and added L3b to the first version, so the first version is
accepted only together with item 1 once that is implemented and its final checks are repeated. The version has **not** been shown to punch through real home or cloud NATs;
what is shown is the mechanism in the controlled fixture, the fail-closed and fallback behavior around it, and a live
fallback over Yggdrasil that works every time it was tried. Nothing here is published, tagged or versioned.
