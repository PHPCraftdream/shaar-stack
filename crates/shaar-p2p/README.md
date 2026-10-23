# P08 source/API gate — implementation not accepted

The product crate is still a scaffold. Dependency resolution and compilation of
an isolated candidate workspace are CI gates, not proof of a working transport.
No candidate dependency is adopted into the product manifest/lock by this gate.

## Reviewed candidate family

| Package | Version | Verified archive SHA256 |
| --- | --- | --- |
| libp2p | 0.57.1 | `9bd752f66522780daa3acfd0103a2dccb3921e4c09db5f777bfca98227c8e74d` |
| libp2p-swarm | 0.48.0 | `57ccbe1baeaef036ffde4b265871e11c64d29464036bba635378f356bcdca854` |
| libp2p-relay | 0.22.0 | `e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a` |
| libp2p-request-response | 0.30.0 | `ca1d1f3a4d7b7080eb959098f276f57ecbc3102f7d3d46f109ccdaa00d2842d9` |

The parent crate requires Rust 1.88; project CI is pinned to 1.99.1. Its identity
requirement 0.3.0 matches the existing graph. Existing bytes 1.12.1, futures 0.3.34
and Tokio 1.54.1 satisfy the corresponding declared ranges; the full transitive
graph is not assumed compatible until the CI identity guard passes.

The gate stages the full candidate workspace, runs real `cargo metadata` without
`--no-deps`, checks nonempty resolved nodes and the reviewed family, preserves every
previous package name/version/source/checksum, and compiles the candidate crate
with `--locked`. The product lock is not rewritten. Both OS artifacts must be
reviewed before adoption. No local Cargo resolution, build or test is used.

## Frozen graph compatibility correction — pending CI

The first gate at `24840d3`, run `39950547435`, passed eight Python controls and
four owned lease-boundary tests on both OSes. Full metadata then correctly rejected
seven changed existing identities, before candidate compilation or adoption. The
Linux/Windows rejected locks were byte-identical, SHA256
`8132466bce47af15ccaae37ec5c2cafa07caec31a55d9c48614411b61bd932a9`.

Swarm 0.48.0's target-specific manifest hard-pins wasm-bindgen-futures =0.4.58,
which forced wasm-bindgen 0.2.129 ->0.2.108, wasm-bindgen-futures 0.4.79 ->0.4.58,
and js-sys/web-sys 0.3.106 ->0.3.85 plus matching macro/shared package downgrades.
Cargo's full lock includes these dependencies even for native compilation. They
were not accepted; the existing identity-preservation guard is unchanged.

No compatible newer Swarm patch release was available in the registry at review.
The preparer now verifies the original Swarm archive and applies a manifest-only
compatibility change to the already-resolved wasm-bindgen-futures =0.4.79. Its
Swarm version and every upstream Rust source byte are unchanged. Provenance records
the old/new requirement and native-source scope; metadata must resolve both this
prepared Swarm and the bounded relay paths. This does not claim a WASM build or
runtime acceptance. It preserves, rather than raises, existing product versions.
A fresh CI gate must still verify all prior identities and compile the candidate.

## Rejected shortcuts and selected boundaries

`libp2p-stream` 0.5.0-alpha was inspected, not adopted. Its `src/shared.rs:106-108`
removes a closed connection from `connections` but leaves `senders` entries behind.
The resulting history is not bounded by the active connection count. Its
`src/control.rs:36-43` also explicitly says excessive Control clones defeat its
channel backpressure. Safe Rust and an official crate name do not prove the
required bounded lifecycle.

The non-alpha request-response codec is the candidate carrier. It supports the
required length-bounded framed datagrams and opens substreams on demand over a
reused authenticated TCP/Noise/Yamux connection. The trade-off is per-datagram
substream overhead; application TCP data never belongs on that path. The owning
actor must cap requests before submission and submit only after connection
establishment, rather than assume handler concurrency alone bounds pending maps.
The inspected 0.30.0 codec uses native generic futures, not an async-trait shim.

Swarm 0.48.0's default Tokio executor (`src/executor.rs:41-44`) drops each spawned
JoinHandle. The product needs a bounded managed executor that retains results and
joins task destruction during shutdown. Short internal critical sections may be
needed for the synchronous Executor interface; no lock may span an await, and
formal lock-freedom is not assumed for dependencies.

## Hostile relay expiry gate

Relay 0.22.0's `src/protocol/outbound_hop.rs:202-216` subtracts local wall time from
an untrusted u64 expiry, then constructs a futures-timer Delay without an upper
bound. The reviewed futures-timer 3.0.3 constructor (`src/native/delay.rs:36-37`)
uses `Instant::now() + duration`; an enormous peer expiry can reach overflowing
instant arithmetic before a reservation event reaches the adapter. An already
expired zero-duration reply can also cause immediate renewal attempts.

The source-data preparer validates the original archive/package/license, preserves
licenses, and installs the exact owned `lease.rs` helper before constructing the
timer. It accepts only future leases of 1..=86400 seconds, preserving the existing
three-quarter renewal rule, and rejects expired, oversized or unrepresentable local
clock inputs. Rejecting a valid but longer-than-one-day offered lease is an explicit
resource/compatibility trade-off, not an assertion about all public relay policies.
The same std-only helper has authored boundary tests in CI. Source anchors and
provenance fail closed; no archive code runs during preparation. Real malformed
reservation-wire tests remain required in the owned relay integration phase.

## Remaining implementation and acceptance

P08 is decomposed into dependency/safety gate, bounded carrier and owned executor,
Amino/relay/Iroh integration, then consolidated owned-relay and separate public
smoke evidence. Each implementation leaf adds and executes its own tests; the last
leaf is not permission to postpone bugs or test failures.

Signaling-only enforcement remains the reviewed Noq pre-packetization gate. An
opaque encrypted custom sender cannot classify application STREAM after encryption.
Authenticated connection/circuit/generation metadata must define custom provenance;
a peer-claimed address or a synthetic prefix is not transport authority. An owned
relay needs decoded-frame/path attribution with positive sensitivity calibration;
application non-delivery alone is insufficient.

Public Amino nodes are untrusted and finite. Discovery must verify relay support,
handle refusal/expiry and apply bounded caches, retries and backoff. A separate
public smoke may report external availability failure; it cannot replace or mask
the deterministic owned-relay contract. No Yggdrasil integration gate is lifted,
and no n0 infrastructure, TUN, root, router forwarding or local native smoke is
introduced by this work.
