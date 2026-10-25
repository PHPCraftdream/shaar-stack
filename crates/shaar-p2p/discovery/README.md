# Amino bootstrap preflight: exact locked-family report

> Source baseline: `a8e26b0`. This is an implementation preflight, not runtime acceptance.
> Numeric budgets below are recommendations, not newly approved configuration requirements.
> Source citations use archive-relative crate/version paths; generated extraction trees need not be retained.
>
> Follow-up: [DNS resolver ownership and retention](dns-ownership.md) verifies the
> locked Hickory task-provider boundary and identifies additional pre-decode limits.

## Archive provenance

Each archive was fetched into a fresh ignored directory, SHA256 checked against Cargo.lock
(or the existing maintained preparer digest for path-patched relay/swarm), then extracted
as DATA with traversal/link checks. No source archive code or build script ran locally.

| Crate | Version | Verified archive SHA256 |
| --- | --- | --- |
| libp2p | 0.57.1 | `9bd752f66522780daa3acfd0103a2dccb3921e4c09db5f777bfca98227c8e74d` |
| libp2p-kad | 0.49.0 | `973caa45045e53f3cf1cf3d596888b82602b30640fd75485836c81aa66e7c38a` |
| libp2p-identify | 0.48.0 | `b2dd130b2cbbcecb55e923c5ba4183e6b9af542b4251680017300c693a6e183c` |
| libp2p-dns | 0.45.0 | `18694695e98ff9ce26ee245fdede7cd0b4186cb793b25da3258d9c053400a291` |
| libp2p-relay | 0.22.0 | `e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a` |
| libp2p-swarm | 0.48.0 | `57ccbe1baeaef036ffde4b265871e11c64d29464036bba635378f356bcdca854` |

Parent spot checks independently confirmed: Kademlia's test-only automatic-bootstrap
setter and pre-result referral retention; DNS A/AAAA queue expansion and pre-cap TXT
collection; Identify's zero-sized cache disabling; and QueryMut::finish forwarding
to iterator cleanup rather than socket abort. Remaining source conclusions retain
their explicit observed/inferred/recommendation labels and verification limitations.


## 1. Finding and evidence boundary

**OBSERVED — source inspection only:** The existing dependencies provide the necessary wire protocols, but simply adding Kademlia, Identify, and the DNS transport to the current derived behaviour does **not** establish a small, hard-bounded discovery implementation.

Two important limitations survive ordinary owner-side limits:

1. Kademlia retains referrals and their addresses **inside an active query before the application receives its final result**.
2. DNS limits resolution work and accepted dial attempts, but those limits are **not** equivalent to a small bound on decoded DNS addresses or intermediate allocations.

**RECOMMENDATION:** Keep the integration inside the existing signaling carrier, with fixed infrastructure roles and owner-controlled admission. For a strict small-cardinality guarantee, include narrowly reviewed dependency preparation changes for Kademlia referral retention and DNS expansion. Do not describe an outer cache cap or a query timeout as proving those internal bounds.

The reviewer changed no files and executed no builds, tests, downloaded code or network probes. The parent fetched archive bytes as untrusted DATA and independently verified their digests before source inspection. The prepared product dependency trees are absent at `target/p2p` in this worktree; prepared API conclusions below come from the actual preparation transformations and their production call sites, **not** from pretending that upstream archives contain the product API.

### Exact family

| Crate | Locked version | Evidence |
|---|---:|---|
| `libp2p` | 0.57.1 | `Cargo.lock:2040-2043` |
| `libp2p-kad` | 0.49.0 | `Cargo.lock:2175-2178` |
| `libp2p-identify` | 0.48.0 | `Cargo.lock:2136-2139` |
| `libp2p-dns` | 0.45.0 | `Cargo.lock:2121-2124` |
| `libp2p-relay` | 0.22.0, prepared path dependency | `Cargo.lock:2285-2287`, `Cargo.toml:18-20` |
| `libp2p-swarm` | 0.48.0, prepared path dependency | `Cargo.lock:2323-2325`, `Cargo.toml:18-20` |

The required features are already enabled; this work does not require a new package, feature family, or version change: `crates/shaar-p2p/Cargo.toml:8-12`.

For readable citations below, these aliases denote **exact relative path prefixes**:

- **K** = `libp2p-kad-0.49.0/src/`
- **I** = `libp2p-identify-0.48.0/src/`
- **D** = `libp2p-dns-0.45.0/src/`
- **R** = `libp2p-relay-0.22.0/src/`
- **S** = `libp2p-swarm-0.48.0/src/`

## 2. Protocol roles and trust

**RECOMMENDATION — fixed roles, not a configurable mode framework:**

- **Bootstrap seed:** a locally selected, expected `PeerId` plus bounded transport addresses. Its purpose is entry into Amino, not authority over application identities or relay selection.
- **DHT infrastructure peer:** a bounded, temporary referral candidate. Its addresses remain untrusted until transport validation and expected-peer authentication.
- **Identify capability source:** authenticated peer metadata. Exact advertised protocol membership is a capability hint, not authorization or availability.
- **HOP candidate:** an infrastructure peer advertising `/libp2p/circuit/relay/0.2.0/hop`.
- **Active reservation:** a separate state established only by the reservation/listener lifecycle below.
- **Application signaling peer:** remains in the existing immutable application allowlist. Discovery must never add an infrastructure peer to that allowlist.

**OBSERVED:** The Amino-compatible DHT protocol name in this family is `/ipfs/kad/1.0.0`; HOP and STOP are distinct relay protocols:

- `K/protocol.rs:49-51`
- `R/protocol.rs:31-36`

**INFERRED:** Neither proximity to a DHT key nor inclusion in a bootstrap list demonstrates HOP support, reservation capacity, or successful relaying. Public Kubo/Amino nodes must not be treated as automatically available HOP relays. No public node availability was checked.

**OBSERVED:** Current admission already separates application and relay identities, rejects overlap, limits infrastructure authorization, and rejects unsolicited infrastructure inbound connections:

- `crates/shaar-p2p/src/carrier/admission.rs:58-83`
- `crates/shaar-p2p/src/carrier/admission.rs:143-157`

Extend that separation to discovery infrastructure; do not implement discovery by broadly relaxing `permits()`.

## 3. Kademlia: APIs, limits, and cancellation

### Correct local use

**OBSERVED:**

- `get_closest_peers(key)` starts a **local iterative query** and returns `QueryId`; it does not publish a record or discover application services by itself: `K/behaviour.rs:723-731`.
- `bootstrap()` requires a nonempty routing table and begins a self-lookup: `K/behaviour.rs:984-998`.
- Bootstrap then refreshes farther buckets, continuing under the same query ID and emitting intermediate progress: `K/behaviour.rs:1452-1515`.
- Completion must use `OutboundQueryProgressed { id, result, step, .. }` and `step.last`, not “first event means done”: `K/behaviour.rs:2766-2776`, `K/behaviour.rs:1501-1539`.
- A closest-peer timeout can contain partial peers; partial data is not success: `K/behaviour.rs:1745-1755`.

**RECOMMENDATION:** Use only bootstrap plus bounded closest-peer lookup where needed. Do not add record publishing, provider discovery, generic record APIs, or a public DHT server role.

Pin the behaviour to `Some(Mode::Client)`. Default client mode is otherwise allowed to become server mode after an external address is confirmed: `K/behaviour.rs:1110-1127`. Client inbound Kademlia upgrades are denied: `K/handler.rs:610`.

### Routing/address insertion

**OBSERVED:**

- `add_address` qualifies the address with the supplied peer ID and rejects incompatible qualification: `K/behaviour.rs:581-585`.
- It can update an existing address set, insert a peer, return pending insertion, or fail; pending insertion can cause a dial of the incumbent: `K/behaviour.rs:587-645`.
- `remove_address` removes the peer when its last address disappears; `remove_peer` also removes pending entries: `K/behaviour.rs:651-700`.
- Rust-libp2p requires explicit Identify-to-Kademlia wiring: `K/lib.rs:25-34`.

**RECOMMENDATION:** Select `BucketInserts::Manual`; only the owner may admit routing entries, after role/address validation. Enforce the global peer cap **before** `add_address`, reconcile replacement/expiry through `remove_address`/`remove_peer`, and account for pending entries. A bucket-size setting alone is not a global peer/address cap.

### Automatic bootstrap is a real integration trap

**OBSERVED:** `set_periodic_bootstrap_interval(None)` disables periodic bootstrap only. New routing insertions below `K_VALUE` still schedule automatic bootstrap:

- `K/behaviour.rs:410-417`
- `K/behaviour.rs:617-618`
- `K/behaviour.rs:1438-1449`
- `K/behaviour.rs:2591-2595`

The setter disabling automatic bootstrap is `#[cfg(test)] pub(crate)`, **not a production public API**: `K/behaviour.rs:439-455`.

Automatic bootstrap avoids starting another while a bootstrap is active, but manual callers can still start more: `K/bootstrap.rs:76-83`, `K/bootstrap.rs:102-106`.

**RECOMMENDATION:** For a strict owner-enforced one-query budget, narrowly expose or otherwise disable automatic insertion-triggered bootstrap in prepared Kademlia source. Do not claim that disabling periodic bootstrap solves this.

### Query limits are not retention limits

**OBSERVED:**

- Default `k = 20`, iterative parallelism `α = 3`: `K/lib.rs:77-101`.
- Query timeout defaults to 60 seconds; substream timeout defaults to 10 seconds: `K/behaviour.rs:240-248`, `K/behaviour.rs:384-390`.
- Parallelism limits iterative waiting, not every category of query: `K/behaviour.rs:260-275`.
- Referrals are copied into `query.peers.addresses` before owner-visible completion: `K/behaviour.rs:1218-1237`.
- The closest-peer iterator inserts newly reported peers without a small cardinality check in that insertion loop: `K/query/peers/closest.rs:197-221`.
- Kademlia supplies both routing-table addresses and active-query addresses to outbound dials: `K/behaviour.rs:2249-2279`.
- Queries can independently queue dials: `K/behaviour.rs:2640-2665`.

**INFERRED:** A cap on the final result, application cache, concurrent connections, or `α` does not prove a cap on internal query referrals. The 16-KiB default packet ceiling limits one decoded Kademlia packet, not all referrals accumulated across a query: `K/protocol.rs:49-51`.

**RECOMMENDATION:** Bound referral peer count, addresses per peer, address bytes, and total contacts per query **before dependency retention**, including the iterator’s peer set. Ignore excess referrals deterministically. This requires a narrow prepared-source change or equivalent verified interception before those insertions; ordinary post-result filtering is too late.

### Cancellation and timeouts

**OBSERVED:** `query_mut(&id).finish()` exists. It marks the query iterator finished; the pool later removes it. It is not a socket-abort API:

- `K/behaviour.rs:555-563`
- `K/behaviour.rs:3377-3380`
- `K/query.rs:441-456`
- `K/query.rs:219-228`

The configured timeout is checked in specific waiting states, after query iteration; it is not an unconditional wall-clock check at API submission: `K/query.rs:192-209`.

**RECOMMENDATION:**

- Store `QueryId`, epoch/generation, owner deadline, and cancellation status.
- On cancel/deadline: mark the owner operation canceled **first**, call `finish()` if still accessible, and reject subsequent results for that generation.
- Do not free pending dial/resource charges merely because the waiter disappeared.
- Retire infrastructure connections and pending work separately; finish is not evidence that already queued dials or negotiated streams vanished.
- Prevent bootstrap continuation from creating more useful work after cancellation; a bounded epoch reset/drop is the conservative fallback if the dependency cannot prove that cleanup contract.

## 4. Identify: validate advertisements, not just their syntax

**OBSERVED:**

- Incoming public key must derive the authenticated remote peer ID: `I/handler.rs:250-260`.
- Parsed protocol strings are validated syntactically: `I/protocol.rs:185-195`.
- Signed peer records are used only when they match the Identify public key; otherwise parsing falls back to unsigned listen addresses: `I/protocol.rs:230-243`.
- Behaviour filtering checks only a **terminal** `/p2p` component; addresses without that component pass: `I/behaviour.rs:679-686`.
- Identify emits `Received` with both `peer_id` and `connection_id`, then may automatically cache/propagate addresses: `I/behaviour.rs:461-482`.
- The message codec ceiling is 4096 bytes: `I/protocol.rs:121`, `I/protocol.rs:163`.
- `with_cache_size(0)` disables its discovery cache: `I/behaviour.rs:229-232`, `I/behaviour.rs:279-283`.

**RECOMMENDATION:**

1. Disable Identify’s independent address cache; keep one owner-controlled bounded cache.
2. Accept metadata only for the exact currently admitted connection/generation.
3. Compare exact protocol identifiers:
   - DHT protocol for routing eligibility;
   - HOP for relay-support candidacy;
   - STOP is **not** HOP.
4. Retain only the required capability bits, not arbitrary agent strings or the complete protocol list.
5. Validate every accepted address against a small grammar: supported TCP transport, expected terminal peer identity, bounded length/component count, nonzero port, and allowed destination scope.
6. Reject circuit, UDP/QUIC, WebSocket, unrelated peer suffixes, nested/unsupported address forms, and arbitrary DNS expansion unless explicitly handled by the bounded DNS boundary.
7. Do not treat `observed_addr` as the remote peer’s listening address or automatically confirm it as local external reachability.

Authentication proves which peer supplied metadata; it does not prove the advertised endpoint is reachable, publicly routable, or willing to reserve relay capacity.

## 5. DNS: transport-owned resolution, not a peer-discovery result API

**OBSERVED:**

- The Tokio DNS wrapper creates its resolver from system configuration or explicit resolver options: `D/lib.rs:69-90`.
- Resolution happens asynchronously inside the dial future; the wrapper owns the resolver and unresolved-address work: `D/lib.rs:204-226`.
- Per DNS dial limits are 32 lookups, 16 applicable TXT expansions per lookup, and 16 accepted underlying dial attempts: `D/lib.rs:121-134`, `D/lib.rs:265-279`, `D/lib.rs:288-319`.
- TXT suffix matching preserves constraints such as a requested `/p2p/<expected>` suffix: `D/lib.rs:262-273`.
- A/AAAA alternatives are collected and pushed without the TXT cardinality limit: `D/lib.rs:254-260`, `D/lib.rs:423-496`.
- TXT addresses are parsed into a vector **before** the applicable-TXT cap is applied: `D/lib.rs:504-531`.

**INFERRED:** Those constants do not prove a four-address cache limit or a hard small intermediate allocation limit. Also, one Swarm dial slot can encompass multiple sequential resolved-address attempts.

**RECOMMENDATION:**

- Keep resolution inside the carrier-owned transport lifecycle; do not add a detached DNS task or pretend DNS exposes a public “resolve these seeds into a peer list” API.
- Always dial with an expected `PeerId`. DNS records are location hints, not identity authority.
- Put the overall timeout outside DNS resolution and all resulting transport attempts.
- Bound accepted DNS input bytes, component count, roots, recursion, expansion count, intermediate address count, and error accumulation.
- Enforce destination policy again on **resolved numeric addresses before TCP opens**, preventing DNS rebinding into disallowed destinations.
- For strict small expansion bounds, narrow the prepared DNS implementation at collection/queue insertion, not merely after successful dialing.
- Avoid a second DNS-answer cache. The discovery cache stores bounded peer-address hints with a conservative owner TTL; it must not claim to preserve authoritative DNS TTLs, which this transport result does not expose.

**Limitation:** Resolver internals and resolver-task shutdown were not established from the six supplied crate sources. Their memory/cancellation guarantees require separate evidence before claiming total dependency-wide resource closure.

## 6. HOP advertisement versus successful reservation

**OBSERVED — actual prepared product contract:**

The relay archive is transformed to publish:

- validated monotonic reservation expiry;
- authenticated relay `connection_id`;
- relay connection context on circuit events;
- early rejection of canceled transport requests.

Evidence: `.github/scripts/p2p/prepare.py:43-110`.

Lease validation accepts remaining whole-second differences only in `1..=86_400`, computes fractional remaining duration without extending the offered lease, and renews at three quarters:

- `.github/scripts/p2p/lease.rs:13-23`
- `.github/scripts/p2p/prepare.py:57-68`

The swarm preparation changes the wasm dependency requirement, explicitly leaving native source unchanged: `.github/scripts/p2p/prepare.py:141-165`.

**OBSERVED:** The upstream reservation exchange can refuse reservations, report resource exhaustion, omit required fields, or return invalid/empty addresses despite successful protocol negotiation: `R/protocol/outbound_hop.rs:169-200`.

Current product acceptance requires:

- exact authenticated control connection;
- a record not already stopping/failed;
- future monotonic expiry;
- validated listener advertisement;
- both expiry/control and addresses before activation.

Evidence:

- `crates/shaar-p2p/src/carrier/relay/controller.rs:221-256`
- `crates/shaar-p2p/src/carrier/relay/controller.rs:289-339`

**RECOMMENDATION:** Preserve that lifecycle. HOP advertisement only permits a bounded reservation attempt. Never publish a lease on Identify receipt, TCP connection, HOP negotiation, or `listen_on()` admission.

Circuit-established relay events are not end-to-end signaling readiness; current code deliberately waits for pinned Noise/Swarm authentication: `crates/shaar-p2p/src/carrier/relay/controller.rs:258-261`.

## 7. Proposed small owner state

**RECOMMENDATION — concrete implementation budget, not an observed existing feature:**

| State | Fixed bound / lifetime |
|---|---|
| Seed descriptors | At most 4 pinned peers; input-count check before deduplication |
| Discovery peer ledger | 32 total, including seeds, referrals, failed/backoff entries |
| Addresses | At most 4 per peer, 256 encoded bytes each; canonical deduplication |
| Discovery query | 1 active query, plus its charged cleanup state |
| Query contacts | At most 32 attempted peer contacts per query |
| Discovery connections | At most 4 established, sharing the existing total pending cap of 8 |
| Cached hints/capabilities | Same 32-entry ledger, five-minute maximum freshness |
| Failed candidates | Same ledger; 60-second history |
| Retry policy | At most 3 attempts per retained candidate; exponential backoff with bounded jitter and a 60-second ceiling |
| Relay targets/reservations | Preserve existing 8 target / 2 reservation limits |
| Owner deadlines | 10-second DNS/dial/substream admission budget; 30-second overall discovery epoch |
| Queues | Reuse existing bounded command/result paths; no unbounded waiter list |

The existing carrier already has peer/relay/pending/queue/request constants: `crates/shaar-p2p/src/carrier/mod.rs:14-18`. Existing relay limits are two reservations, four advertisements, and 256 bytes per advertisement: `crates/shaar-p2p/src/carrier/relay/mod.rs:35-40`.

Use a single owner and fixed-size or capacity-checked maps. At these small limits, bounded scans for expiry are appropriate; do not introduce a separate unbounded timer heap.

**Cleanup requirements:**

- Expire stale address/capability hints; remove corresponding Kademlia routing addresses.
- Revoke HOP eligibility on fresh Identify updates that omit HOP.
- Canceling discovery must not release an independently active reservation.
- Reservation release, expiry, or control loss immediately revokes its published lease.
- Do not reuse a connection generation, query result, listener event, or cached capability across replacement.
- Retain cleanup charges until terminal events; reject new work rather than growing a tombstone ledger.
- If teardown exceeds its deadline, terminate that owned discovery epoch/carrier rather than silently accumulating resources.

Existing relay teardown already waits for listener, established connection, and pending admission disappearance, with terminal teardown timeout and bounded history: `crates/shaar-p2p/src/carrier/relay/controller.rs:442-520`.

## 8. Minimum production boundaries

**RECOMMENDATION:**

1. **Carrier behaviour/owner:** add one small discovery component alongside admission, relay client, and packet behaviour; integrate its timer and events into the existing owner loop. Current composition and loop are at `crates/shaar-p2p/src/carrier/driver.rs:30-54`, `:216-257`.
2. **Admission:** add bounded discovery infrastructure roles without expanding application authorization. Preserve distinct relay/application identities and unsolicited-infrastructure rejection.
3. **Composed behaviour boundary:** validate/cap the **aggregate** dial addresses before Swarm consumes them. An admission child returning `Ok(Vec::new())` cannot sanitize addresses supplied by another child. Swarm extends its address list from the behaviour result: `S/lib.rs:458-499`.
4. **Native transport boundary:** DNS wrapping, overall timeout, and resolved numeric-destination guard.
5. **Prepared dependency boundary:** narrow Kademlia retention/automatic-bootstrap controls and DNS expansion bounds if hard small-cardinality guarantees are required. Maintain checksum/anchor/provenance discipline; do not substitute upstream archive APIs for prepared APIs.
6. **Relay selection handoff:** convert only an owner-validated numeric endpoint and expected peer into the existing pinned `RelayAddr`; no need to broaden `RelayAddr` into a generic arbitrary-multiaddr API. Current representation is `crates/shaar-p2p/src/carrier/relay/mod.rs:42-73`.

Keep SDK identity, signaling envelopes, packet codec, bridge, application session policy, Noq packetization, and Ygg backend outside this change.

**Required invariant, unchanged:** Libp2p carries signaling only. Noq `NativeOnly` must continue denying all custom APP before packetization. This review does not independently re-prove the prepared Noq implementation. Ygg integration remains permission-gated; no n0 relay, TUN, root requirement, system/router route manipulation, or additional routing mechanism is introduced.

## 9. Failure and wrong-peer handling

**OBSERVED:** Swarm checks expected versus obtained peer identity and emits `WrongPeerId`: `S/connection/pool.rs:706-719`.

**RECOMMENDATION:**

- Wrong peer: fail the exact dial, retain no capability or address authority from the obtained peer, charge bounded failure/backoff state.
- DHT-only node: eligible for bounded DHT use, not relay reservation.
- STOP-only node: not a HOP candidate.
- HOP-advertising node that refuses/exhausts/times out: unavailable candidate, no lease.
- Valid reservation on stale control connection: ignore/revoke; never transfer to successor connection.
- Valid control acceptance without listener address, or listener address without acceptance: pending until deadline, never active.
- Foreign terminal `/p2p`, unsupported transport, private/special destination, malformed/overbudget referral: reject before retention/dial.
- Caller cancellation before admission: no new work.
- Cancellation after admission: suppress success publication, finish query, clean resources, tolerate late terminal events without resurrection.
- Full peer/address/query/connection budget: immediate bounded failure; no implicit retry task.
- Connection loss or protocol withdrawal: invalidate current capability generation and affected work, then apply bounded backoff.

## 10. GitHub CI: deterministic ownership versus public availability

**RECOMMENDATION — deterministic owned fixtures, required for correctness:**

1. **Local DHT topology:** owned seed and additional DHT peer; prove referral traversal, exact protocol, manual routing insertion, no record/provider publication, and no server-mode transition.
2. **Bounds:** adversarial replies with excessive unique referrals, addresses, duplicates, oversized addresses, and unsupported transports; assert dependency-internal retention bounds, not only final output sizes.
3. **Automatic bootstrap:** insert below 20 peers and verify there is no uncharged query; test periodic disabling separately.
4. **Identify:** correct/wrong public key, foreign peer suffix, signed-record fallback, exact DHT/HOP/STOP distinctions, stale connection, protocol withdrawal, and no automatic cache bypass.
5. **Owned DNS server:** A/AAAA fan-out, TXT fan-out, recursive/cyclic DNSADDR, malformed TXT, mismatched peer suffix, NXDOMAIN, timeout, and numeric destination-policy rejection. Assert attempts and intermediate cardinalities.
6. **Relay:** DHT-only peer, STOP-only peer, HOP-advertising refusal, resource exhaustion, malformed expiry, successful reservation, renewal, stale control event, listener closure, expiry, release, and end-to-end wrong peer.
7. **Cancellation/interleavings:** before command admission, during DNS, pending TCP/Noise, active query, bootstrap progress, reservation acceptance/listener event ordering, and shutdown.
8. **Resource closure:** all owner ledgers empty, snapshots revoked, listeners closed, pending/established charges released, owned executor tasks joined.
9. **Preserved product policy:** infrastructure cannot deliver application signaling packets; exact-generation signaling remains intact; all custom APP stays denied before Noq packetization.

Use owner deadlines/eventual assertions with explicit bounds. Do not assume Tokio paused time controls dependency `futures_timer::Delay`; the supplied bootstrap implementation uses that timer: `K/bootstrap.rs:6-7`.

The current graph verification checks prepared relay/swarm resolution paths, rather than merely matching versions: `.github/scripts/p2p/graph.py:94-104`. Preserve and extend that evidence for any additional prepared boundary. Existing CI definitions are evidence of intended checks, **not evidence that they passed**: `.github/workflows/ci.yml:136-155`.

**Separate optional public availability smoke:**

- Explicit/manual or scheduled, time-bounded, with pinned seed identities and bounded attempts.
- Record DNS, expected-peer connection, Identify, and DHT query outcomes separately.
- Attempt reservation only for an eligible HOP candidate; report reservation outcome independently.
- Treat public refusal, rate limiting, timeout, and no-HOP results as availability observations, not deterministic correctness failures.
- Do not claim successful relay availability from successful Amino bootstrap.

**Final status:** Source-only preflight completed; parent integrated this report after checking critical source claims. No new production code, builds, tests or public availability smoke are accepted by this document. Strict small internal Kademlia/DNS bounds and prepared resolver shutdown remain implementation/verification obligations, not runtime-verified properties.