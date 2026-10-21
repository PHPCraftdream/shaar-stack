# Sha'ar Stack Verification Scenario Matrix (P01)

Date: 2026-10-21. Caveat: at the P01 stage nothing was run —
no tests, no builds, no experiments. All P01 statuses in the tables are
"planned". Level notation: unit — a deterministic test;
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

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Connecting two endpoints via the custom transport only, with n0 disabled | Prove that the custom transport is the only path and the connection authenticates | Connection established; `conn.paths()` shows only the custom path | P03 | planned |
| NAT traversal: candidate exchange over the custom path | Prove negotiation over the signaling path | Candidates transmitted; observation of decoded service frames (NOT counter growth) | P03 | planned |
| Migration to direct UDP after negotiation | Prove path migration to direct UDP | Decoded STREAM frames travel over the direct path; `path.is_selected()`/rtt — auxiliary | P03 | planned |
| Application STREAM data before direct appears | Prohibit data on the signaling-only path | Decoded-frames oracle: 0 STREAM frames on the custom path before direct | P03 | planned |
| Application STREAM data after direct failure | The prohibition must not be lifted under degradation | Upon direct failure, decoded frames contain no STREAM on the custom path | P03 | planned |
| Application STREAM data during re-punching | The prohibition holds across re-punching attempts | Re-punching does not move data onto the signaling path (decoded frames) | P03 | planned |
| Stopping poll_send after direct does not count as resolution | Exclude false confirmation | Observation covers all phases; a mere poll_send stop is rejected | P03 | planned |
| Verify availability of the oracle mechanism in iroh 1.3.0 | Feasibility of the oracle itself | The existence of a test-only trace hook before encryption or available decoding of captured packets is confirmed or refuted | P03 | planned |
| Negative oracle calibration: STREAM explicitly permitted through the custom transport | Positive oracle trigger | The oracle detects the violation; without a positive trigger the gate is not passed | P03 | planned |

## 2. NAT matrix

A controlled rig fixes the NAT scenario types (full cone,
restricted cone, port-restricted, symmetric). For configurations
where direct is unachievable (e.g., symmetric NAT on both sides without
UDP-holepunching), a direct connection is NOT guaranteed. In signal mode the
alternative path is a finite controlled negotiation/bounded wait, then a controlled failure;
standby — switching to Yggdrasil if it is available, otherwise failure. Local
TCP sessions are not required to survive closure of the QUIC connection; after the break
the client establishes a new connection.

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Both sides behind NAT (cone types) | Connection without port forwarding | Connection established through negotiation, data over direct UDP | CI rig | planned |
| Symmetric NAT on both sides without UDP-holepunching | Unreachable direct | A direct connection is NOT guaranteed; signal: bounded wait, then controlled failure; standby: switch to Yggdrasil if available, otherwise failure | CI rig | planned |
| UDP blocked on one/both sides | Behavior without direct UDP | signal: finite negotiation/bounded wait, then controlled failure; standby: switch to Yggdrasil if available, otherwise failure; direct data unavailable, no unbounded retries | CI rig | planned |
| Both sides on a LAN | Direct local path | Direct connection without external infrastructure | CI rig | planned |
| Network change during operation (interface switch) | Migration and recovery | Connection is restored; no cyclic switching | CI rig | planned |
| QUIC connection closure with active local TCP sessions | Session life cycle | Local TCP sessions are not required to survive closure; after the break the client establishes a new connection | CI rig | planned |
| NAT-hole keepalive | Keeping the punched mapping alive | Keepalive keeps the path alive without state growth | CI rig | planned |
| Recovery after losing the NAT hole | Re-punching | The path is restored; the repeated scenarios of section 1 run | CI rig | planned |
| Real home/mobile networks | Confirmation outside the rig | Documented observations; no unconfirmed claims about NAT | manual | planned |

## 3. Relay scenarios (libp2p)

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Own test relay with limits from Config::default | Deterministic limit verification | Limits (128 reservations, 4/peer, 3600 s, 16 circuits, 120 s, 128 KiB, rate limits) are applied | unit | planned |
| Reservation expiry and renewal | Renewal handling | Renewal is observed via the `ReservationReqAccepted` event with `renewal: true`; the client computes the renewal delay ≈ 3/4 of the remaining term (outbound_hop.rs); after expiry — re-reservation | unit | planned |
| ResourceLimitExceeded slot failure | No free slot | Explicit handling of the failure; bounded retry/backoff, no masking | unit | planned |
| Datagram framing over the stream | Bounded framing | Length checks, partial read/write, malformed frames rejected | unit | planned |
| Reconnect after relay break | Recovery | Re-reservation and stream reopening, state bounded | unit | planned |
| Public Amino smoke | Availability of a real slot | Separate smoke; temporary failure of public infrastructure is not masked as a defect of deterministic tests | CI rig | planned |
| Streams on truly limited connections | libp2p-stream behavior on a relayed connection | Confirmed limitation or working behavior is documented | P03 | planned |
| open_stream over a relayed connection | Verify absence of a code gate | `open_stream` over a relayed connection is not forbidden by code (behaviour.rs without an is_relayed gate) — confirmed by reading v0.57.1; actual relay-server limits — measurement | unit | planned |

## 4. Yggdrasil FFI

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Sending/receiving datagrams by 32-byte key | ReadFrom/WriteTo contract | `ReadFrom` returns an `iwt.Addr` of 32 key bytes; `WriteTo` to such an address delivers | unit | planned |
| MTU boundaries | Packet size boundaries | `MTU()` = PacketConn.MTU() − 1, cap 65535; exceeding is discarded with an error | unit | planned |
| Blocking receive on a dedicated OS thread | CLAUDE.md rule 7 | Receive does not block the async executor; the thread terminates correctly | unit | planned |
| Stop and cancellation of reading | Orderly termination | `Stop()` completes: cancel, links.shutdown, Close; receive is interrupted without leaks | unit | planned |
| Concurrent calls | Concurrency rules | Lifecycle contract: a single receiving worker thread per recv, a SEPARATE control/stop path (admission stop, no new operations allowed); handle release after all calls cease and recv completes; serializing everything through a single queue, including the blocking recv, is inadmissible (Stop/WriteTo would hang behind recv). Exact safety of concurrent ReadFrom/Stop and handle transfer — source reading and P07 tests; the test does not replace the SAFETY justification | unit | planned |
| Startup errors | Invalid certificate/secret | `core.New` without an ed25519 certificate returns an error; panics do not cross the ABI | unit | planned |
| Building c-archive on Windows | Early CI item | Static support of `-buildmode=c-archive` for windows confirmed by reading supported.go (go1.25.0); actual cross-language linking is to be verified: Rust x86_64-pc-windows-gnu + Go windows/amd64 + gcc (MinGW); MSVC-ABI spike — a separate decision | CI rig | planned |
| Building c-archive on Linux/amd64 | Early CI item (next to Windows) | Static support for linux/amd64 confirmed by reading supported.go; actual linking: x86_64-unknown-linux-gnu + gcc/ld | CI rig | planned |

## 5. pkarr matrix (unit/CI)

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Signing with the correct key | Correct record signing | The record is signed with the same ed25519 key and accepted | unit | planned |
| Signing with the wrong key | Rejection on a foreign signature | The record is rejected | unit | planned |
| Round-trip of custom addresses | Preservation through serialization | API level confirmed (endpoint_info.rs v1.3.0); actual libp2p multiaddrs and their sizes — test | unit | planned |
| Full record budget | Size limit | DNS part ≤ 1000 bytes (HEADER_SIZE 104, signed packet ≤ 1104 — read in iroh-dns/src/pkarr.rs v1.3.0); pre-select a fitting set of custom addresses; observable publish failure on overflow (PacketTooLarge — do not publish) | unit | planned |
| Sequence and freshness | fresh/stale/replay handling | After a new record is observed, a smaller seq does not replace it; equal seq with the same content — idempotent re-read, with different — conflict. Replay does not extend the admissible age of the signed record. The DNS TTL cache does not substitute verification of the signed timestamp; the age limit and admissible clock skew are fixed at P09 taking the republication period into account | unit + CI rig | planned |
| unknown/malformed records | Safe handling | Malformed records are rejected without panics and do not affect state; malformed attrs are skipped (read in endpoint_info.rs); on PacketTooLarge — do not publish | unit + CI rig | planned |

## 6. Keys and addresses

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Fixed vectors seed → pubkey → EndpointId → Ygg 200: → PeerId | Single identity per seed | All derivations match the fixed vectors | unit | planned |
| PeerId ≠ raw key bytes | Multihash wrapping | `to_peer_id()` is not equal to the raw key bytes | unit | planned |
| Corrupted key | Failure is safe | A read/format error without silently generating a new identity | unit | planned |
| Foreign key | Access denial | Connection/service not served for an unauthorized key | unit | planned |

## 7. ktav 0.8.* configuration

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| Valid configs | Parsing valid files | `from_str/from_file` yields the expected values | unit | planned |
| Default values | Behavior on omission | Defaults are applied according to the schema | unit | planned |
| Syntax errors of all major ErrorKinds | Diagnostics | MissingSeparatorSpace, InvalidTypedScalar, DuplicateKey, KeyPathConflict, EmptyKey, InvalidKey, UnclosedCompound, UnbalancedBracket, InlineNonEmptyCompound, MissingSeparator are detected with span/path | unit | planned |
| Invalid parameter values | Semantics validation | An error before network startup, naming the field, without disclosing secrets | unit | planned |
| Lost numbers, parse_strict/LossyScalar | API behavior | The actual API behavior (parse/parse_strict) on numbers like `1.10` is checked in P05; the decision on the config parsing policy (strict or not) is made by P05, no prescription is set in advance | unit | planned |
| Duplicate keys | DuplicateKey/KeyPathConflict | A repeated key and a path conflict are detected | unit | planned |
| Unknown fields | serde behavior | The actual behavior (ignore/deny_unknown_fields) is confirmed by a test — schema decision at P05 | unit | planned |
| Network startup refusal on config error | Load/startup order | Parsing and validation complete before network services start | unit | planned |

## 8. Isolation from n0 infrastructure

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| presets::Minimal + own transports: absence of calls to iroh.link/n0 relays | n0 disabled by default | Network observation of the rig shows no calls to iroh.link and n0 relays | CI rig | planned |
| clear_ip_transports() not used for disabling n0 | Keeping direct UDP | The direct UDP transport remains available | unit | planned |

## 9. Structural CI checks

| Scenario | Goal | Expected result | Level | P01 status |
|---|---|---|---|---|
| No more than 700 lines per code file | CLAUDE.md rule 2 | Violations are detected by a CI check | CI rig | planned |
| No more than 7 items per directory | CLAUDE.md rule 3 | Violations are detected by a CI check | CI rig | planned |
| forbid/deny unsafe | CLAUDE.md rule 1 | Roots without FFI — forbid; the FFI crate — deny with a local allow | CI rig | planned |
| clippy and fmt | Unified style and lint | CI runs `cargo clippy` and `cargo fmt` | CI rig | planned |
