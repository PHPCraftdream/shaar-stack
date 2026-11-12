# Limits, platforms and the checks actually performed

This page separates what was written, what ran in GitHub CI, and what has no evidence at all. No local build or test run contributed to any statement here.

## Limits by area

### Operating systems

- Evidence exists for Linux (Ubuntu CI runners, amd64) and Windows (CI runners, amd64) only. **Unverified**: macOS, BSD, ARM, mobile, containers.
- Key-file permission checks exist for Unix (mode bits) and Windows (owner-only ACL). On other platforms only type and size are checked.
- The controlled NAT and UDP-blockade fixture is Linux-only (network namespaces on a disposable runner). Windows was never run under NAT conditions.
- No TUN, VPN, root privilege or router change is used or required. The products need outbound UDP (QUIC, Mainline) and outbound TCP (libp2p relay, Yggdrasil peers) and bind local UDP and TCP sockets.

### NAT and direct QUIC

- Direct QUIC is attempted to the published or hinted addresses; relay negotiation helps hole punching. Nothing guarantees a direct path.
- **Verified** (fixture): one NAT in front of the client with Native data in both modes; two NATs with all forwarded UDP denied, where `standby` carries exact bytes over Yggdrasil and `signal` fails closed.
- **Not established**: hole punching through arbitrary double NAT, symmetric NAT, carrier-grade NAT, IPv6 firewall or NAT behaviour (the fixture denied IPv6 forwarding), NAT keepalive over long periods on real devices, real home or mobile networks.
- No port mapping (UPnP/NAT-PMP) is used, and no n0 infrastructure.

### Relay (libp2p)

- The relay is signaling only: it never carries application bytes (**Verified** in the controlled fixtures by an oracle that requires zero application STREAM/DATAGRAM frames on relay and custom paths).
- You must supply a libp2p relay (`network.signaling.relay` and `relay_address`, a numeric address). This repository contains no relay program. Only owned test relays were used in CI. **Unverified**: public Amino relays, relay capacity and rate limits in production, relay outages beyond the owned-fixture outage case.

### Yggdrasil

- The adapter wraps a pinned, lifecycle-patched Yggdrasil-ng core (commit `c9a54f1587bb133a06072596484c972a336db0d2`, MPL-2.0 for the pinned `ironwood` and `yggdrasil` packages) behind a safe Rust API. Peers are dialed from the `network.ygg.peers` list (1 to 4 URIs); the transport opens no listening port and no TUN device.
- **Unverified**: interoperability with deployed Yggdrasil nodes and any contact with the public Yggdrasil network. Only owned loopback and namespace transit peers were used.
- Yggdrasil datagrams are unreliable by contract; the product carries payload over a reliable stream layer built on them (**Verified** in fixtures only).

### FFI and unsafe

- Every ordinary crate root, test and binary carries `#![forbid(unsafe_code)]`. The only FFI is the Windows key-file ACL code in `crates/shaar-platform`, isolated behind a safe interface. The Yggdrasil adapter has no unsafe code, no Go and no FFI. Dependencies are not audited for their own unsafe code.

### Resources and performance

- Bounds that exist in code: 1 MiB config, 256 allowlist entries (16 in the composed shape), 32 server sessions, 1 client session, 16 streams per session, 16 local client workers, at most 4 bootstrap nodes, 4 Yggdrasil peers and 4 published addresses.
- **No performance, load, long-duration or efficiency claims are made.** The agreed efficiency criteria in `docs/plans/north-star.md` (first byte, failover time, direct share) are targets measured in controlled fixtures only; P14 (resources and performance) has not been run, so idle CPU, memory growth and leak behaviour are **Unverified**.

### Other

- One fixed TCP target per server; no UDP forwarding; no GUI; one process per role.
- The client listener does not authenticate local applications: any local process that can reach `listen` uses the client's access. The listener is loopback-only; protect the host.
- Legal notices of third-party material are incomplete (`docs/legal/`); this guide gives no license clearance, and no release has been made.

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
| Examples and messages of this guide | Tests `config::guide_examples_tests` (crates/shaar), `tests::allowlist::documented_*` (crates/shaar-server), `guide_keygen_*` in `crates/shaar/tests/sdk_network.rs`, and the CI selection test in `.github/ci/test_run.py` | Written together with the guide. Their CI execution is reported in the P15 delivery record, not here. They check parsing, validation messages and the key example, not network behaviour. |

## Not performed (explicitly open)

- Public-network interoperability and smoke (public DHT, public relay, public Yggdrasil peers): needs the owner's approval of exact targets and budgets.
- Real home, mobile or LAN device tests; arbitrary double-NAT hole punching.
- P14 resource and performance measurements; P16 first-version readiness; notices and license corpus completion.
- Building outside the CI recipes, running under a service manager (SIGTERM is handled but no unit file or manager was exercised), packaging and releases.
