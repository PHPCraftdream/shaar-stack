| Composed operator contract (client logs its own key, composed `bind` rejected, 16-key allowlist limit named by field, bound addresses printed, SIGTERM stop) | Fork CI 43254724532 at `56448f5` (unit and SDK role tests, Linux and Windows; the SIGTERM tests are Unix-only and ran on Linux); process-feedback dispatch 43256530867 at `56448f5`, case `real_composed_operator_contract_bind_allowlist_output_and_service_stop` passed on Linux and Windows (Windows stops with Ctrl-Break) | Loopback with owned DHT, relay and Yggdrasil fixtures. SIGTERM under a real service manager was not exercised. |
# Limits, platforms and the checks actually performed

This page separates what was written, what ran in GitHub CI, and what has no evidence at all. No local build or test run contributed to any statement here.

## Limits by area

### Operating systems

- Evidence exists for Linux (Ubuntu CI runners, amd64) and Windows (CI runners, amd64) only. **Unverified**: macOS, BSD, ARM, mobile, containers.
- Key-file permission checks exist for Unix (mode bits) and Windows (owner-only ACL). On other platforms only type and size are checked.
- The controlled NAT and UDP-blockade fixture is Linux-only (network namespaces on a disposable runner). Windows was never run under NAT conditions.
- No TUN, VPN, root privilege or router change is used or required. The products need outbound UDP (QUIC, Mainline) and outbound TCP (libp2p relay when configured, Yggdrasil peers) and bind local UDP and TCP sockets.

### NAT and direct QUIC

- Direct QUIC is attempted to the published or hinted addresses; relay negotiation helps hole punching. Nothing guarantees a direct path.
- **Verified** (fixture): one NAT in front of the client with Native data in both modes; two NATs with all forwarded UDP denied, where `standby` carries exact bytes over Yggdrasil and `signal` fails closed.
- **Negative result** (fixture, `docs/verification/scenarios.md` §10 A5 and A6): with a cone NAT on each side, or with fully random NAT ports, and Yggdrasil denied, the products do **not** establish a direct path: the Client ends with "no usable path remained within the attempt budget" and the target accepts nothing. A published but silent candidate can consume the whole 3 s native attempt before relay negotiation starts. With Yggdrasil available, `standby` still delivers exact bytes (1.2 s in the random-port case). Expect the Yggdrasil path, not hole punching, to carry traffic behind two NATs.
- **Not established**: hole punching through any double NAT (see above), carrier-grade NAT, other NAT types, key-only IPv6 discovery (the IPv6-only case worked only with an explicit `server_address` hint), NAT keepalive over long periods on real devices, real home or mobile networks.
- No port mapping (UPnP/NAT-PMP) is used, and no n0 infrastructure.

### Relay (libp2p)

- The relay is signaling only: it never carries application bytes (**Verified** in the controlled fixtures by an oracle that requires zero application STREAM/DATAGRAM frames on relay and custom paths).
- The relay is optional (leaf L0, 2026-11-14 owner decision: DHT and Yggdrasil are the only helper infrastructure). With `network.signaling.relay` and `relay_address` both present, behavior is unchanged: the Server reserves the relay at startup (typed `relay reservation failed at startup` on a dead relay) and the Client reaches relay negotiation after its direct candidates. With neither field present, the composed startup starts with no relay connection at all: the Server skips reservation, the Client dials direct candidates and then the Yggdrasil path. Exactly one of the two fields is a configuration error naming the missing field. This repository contains no relay program. Only owned test relays were used in CI. **Unverified**: public Amino relays, relay capacity and rate limits in production, relay outages beyond the owned-fixture outage case; the relay-less startup is covered by unit, config and role tests only — no end-to-end relay-less run has been executed yet.

### Yggdrasil

- The adapter wraps a pinned, lifecycle-patched Yggdrasil-ng core (commit `c9a54f1587bb133a06072596484c972a336db0d2`, MPL-2.0 for the pinned `ironwood` and `yggdrasil` packages) behind a safe Rust API. Peers are dialed from the `network.ygg.peers` list (1 to 4 URIs); the transport opens no listening port and no TUN device.
- **Unverified**: interoperability with deployed Yggdrasil nodes and any contact with the public Yggdrasil network. Only owned loopback and namespace transit peers were used.
- Yggdrasil datagrams are unreliable by contract; the product carries payload over a reliable stream layer built on them (**Verified** in fixtures only).

### FFI and unsafe

- Every ordinary crate root, test and binary carries `#![forbid(unsafe_code)]`. The only FFI is the Windows key-file ACL code in `crates/shaar-platform`, isolated behind a safe interface. The Yggdrasil adapter has no unsafe code, no Go and no FFI. Dependencies are not audited for their own unsafe code.

### Resources and performance

- Bounds that exist in code: 1 MiB config, 256 allowlist entries (16 in the composed shape), 32 server sessions, 1 client session, 16 streams per session, 16 local client workers, a per-endpoint pending-handshake cap equal to the session limit (kept separate from the slot pool), at most 4 bootstrap nodes, 4 Yggdrasil peers and 4 published addresses.
- **No performance, load, long-duration or efficiency claims are made.** The agreed efficiency criteria in `docs/plans/north-star.md` (first byte, failover time, direct share) are targets measured in controlled fixtures only; P14 measured resources on loopback in CI (one dispatch at `c84d9a6`, both cases passed against provisional ceilings: idle CPU under 0.2%, steady RSS under 23 MiB per process, no descriptor, thread or memory growth after repeated client restarts), which is a pass/fail check on a shared runner, not a capacity, long-duration or 95th-percentile claim; behaviour over hours, on real networks and with many concurrent peers is **Unverified**. See `docs/verification/scenarios.md` section 11.

### Other

- One fixed TCP target per server; no UDP forwarding; no GUI; one process per role.
- The client listener does not authenticate local applications: any local process that can reach `listen` uses the client's access. The listener is loopback-only; protect the host.
- Legal notices of third-party material are incomplete (`docs/legal/`); this guide gives no license clearance, and no release has been made.

## Platforms

The dispatch workflow "Platform build evidence" builds release executables of both products for the targets below, and its job summary states plainly that the result is build-only evidence.

| Target | Built in CI | Executed in CI | Devices |
|---|---|---|---|
| x86_64-unknown-linux-gnu | yes; run evidence: _to be filled after the first dispatch_ | Ordinary CI compiles and executes the selected unit, SDK and real-process tests on Ubuntu runners | Never run on devices |
| x86_64-pc-windows-msvc | yes; run evidence: _to be filled after the first dispatch_ | Ordinary CI compiles and executes the selected tests on Windows runners | Never run on devices |
| aarch64-apple-darwin | built in CI only; run evidence: _to be filled after the first dispatch_ | Nothing — macOS has never executed anything in this repository's CI | Never |
| x86_64-apple-darwin | built in CI only; run evidence: _to be filled after the first dispatch_ | Nothing | Never |
| aarch64-linux-android | built in CI only; run evidence: _to be filled after the first dispatch_ | Nothing | Never |

No GUI, no APK, no system packages, no installers, and no release publication are produced; the separate first-run effort is out of scope here.

## Checks actually performed

All runs below are GitHub Actions runs on the owner's CI; "executed" means the test case ran and passed in the cited log or receipt.

| Area | Evidence | Scope and limit |
|---|---|---|
| Native SDK (admission, allowlist, fixed-target forwarding, shutdown, UDP rebinding) | CI 39936878051 at `4259f43`, Linux and Windows | Loopback. Recorded in `crates/shaar/src/network/README.md`. |
| Direct-only Server and Client as real processes (D1) | CI 40807774299 and 40813234362 at `341e14b`; 40814009922 at `86080b9`, Linux and Windows | Loopback: exact forwarding, startup validation, empty allowlist and wrong pin rejected with zero target connections, target recovery, console shutdown, same-port rebinding, server restart. Recorded in `docs/direct-only-usage.md`. |
| Mainline publication and resolution | `b076458`, targeted run 41975114042 (173 selected library cases per OS), mainline fixtures run 41964477329 | Owned DHT fixtures; no public DHT. Recorded in `docs/plans/v1-focus.md`. |
| Yggdrasil adapter | `efa5c62`, run 42035672563 (16 library and 13 exchange tests per OS) | Loopback pairs; recorded in `docs/plans/v1-focus.md`. |
| Composed Server and Client as real processes: key-only discovery, exact bytes, server-only restart with the same live client, in `signal` and `standby` | Fork runs 43068220334 (ordinary) and 43068389482 (manual process lane) at `c9916375b5ac8881bf151651afcf01f6f5848bf0`; receipts in `docs/checkpoints/2026-11-11-1858.md` | Owned DHT, relay and transit fixtures. Related merged proofs (composed allowlist denial `14d3aed`, standby through DHT and relay outage `3aa2f22`, composed lifecycle `d535d7a`) were merged as verified; their run identifiers were not re-read for this guide. |
| P13 controlled NAT and UDP blockade, normal CI-built products | Fork dispatch 43229756778 on `ca6c04a`: four product cases and three cleanup controls passed; upstream CI 43231417573 green on `6e730b1` (merge `1844247`) | Linux namespaces on a disposable runner, owned addresses only: single NAT Native in both modes, double NAT with UDP blocked gives Yggdrasil payload in `standby` and fail-closed in `signal`. Contract: `docs/plans/p13-controlled-network.md`. |
| P13 remaining rows (double NAT, NAT types, NAT state loss, address switch, relay exhaustion, IPv6, signal denial, outage recovery) | Fork dispatches on `31fd921`/`6f7c0ce` (fork branch before integration): base 43262321962 (12 cases, pass), faults 43262304898 (6 cases, pass), nat 43258223283 (10 cases, pass); nat 43262313789 failed at the harness-side punch control in two cases before any product started | Same fixture limits as above. The verdicts for A5/A6 are negative results. The final head change (record-only punch control) was not dispatched. See `docs/verification/scenarios.md` §10. |
| Examples and messages of this guide | Tests `config::guide_examples_tests` (crates/shaar), `tests::allowlist::documented_*` (crates/shaar-server), `guide_keygen_*` in `crates/shaar/tests/sdk_network.rs`, and the CI selection test in `.github/ci/test_run.py` | Written together with the guide. Their CI execution is reported in the P15 delivery record, not here. They check parsing, validation messages and the key example, not network behaviour. |

## Not performed (explicitly open)

- Public-network interoperability beyond one bounded smoke: the smoke is authorized through its default-off contract (2026-11-14). One relay-less run passed over Yggdrasil standby (run 43671098240); a run with a public libp2p relay failed at the relay reservation (run 43629141158). Neither observed a direct path or a hole punch, and neither is an acceptance of the end-to-end claim.
- Real home, mobile or LAN device tests; a product mechanism that learns public (reflexive) addresses, without which double-NAT hole punching does not happen (§10 A5).
- Long-duration, public-network and many-peer resource behaviour; P16 first-version readiness; notices and license corpus completion.
- Building outside the CI recipes, running under a service manager (SIGTERM is handled but no unit file or manager was exercised), packaging and releases.
