# P08 — native carrier accepted; relay/Iroh integration pending

The dependency/source gate and native carrier prerequisite are accepted.
The product adopts the byte-reviewed CI graph and bounded source preparation.
Framing, managed-executor and native TCP/Noise/Yamux carrier contracts have verified
Linux/Windows CI tests. This is not a working Amino/relay/Iroh transport or complete
P08 acceptance.

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
with `--locked`. [CI 39954741915](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39954741915)
at `bdda8c1` passed on both OSes; completed logs and both artifact sets were inspected.
Eight Python controls, four std-only lease tests and actual candidate compilation
passed per OS. The scaffold had zero behavior tests; no transport success is inferred.
Both candidate locks were byte-identical, SHA256
`9359c11d87070869f2f9d3076ace7805343645612ac7572abe2da8bc4e96e43e`:
all 376 earlier identities were retained, 125 added, zero removed or changed.
Source/helper provenance matched the maintained files. That reviewed lock and
manifest are now adopted; normal CI prepares both source overrides **before any
Cargo resolution**. Missing source fails, not silent stock-upstream fallback.
Optional candidate re-verification supports both the old scaffold and the adopted
manifest without duplicate patch entries. No local Cargo resolution, build or test
was used as evidence.

## Frozen graph compatibility correction

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
The corrected CI gate cited above verified all prior identities and compiled the
candidate on both OSes before this graph was adopted.

## Verified carrier primitives

`Datagram` accepts 1..=1500 bytes in a fixed inline buffer. Its Debug output contains
only the length. The request codec writes a big-endian u16 length, exact payload
and EOF; the response is byte zero and EOF. Zero/oversized lengths, truncation,
trailing bytes and nonzero acknowledgements fail closed. No bytes are allocated
according to an unchecked peer length. A partial read/write is terminal and must
not be replayed on the same substream. This framing budget is not a claim that an
opaque datagram contains only signaling: trusted Noq enforcement remains mandatory.

`OwnedExecutor` owns at most 64 background tasks, including completed results not
yet observed. Cloneable handles permit submission but not shutdown ownership.
Admission is checked before spawning; exhaustion or missing runtime is reported
to the sole completion observer rather than spawning unbounded work or panicking.
A short mutex is required by the synchronous `Executor::exec(&self, ...)` contract
and mutable JoinSet; it is never held across an await, I/O or future destruction.
An AtomicWaker plus registration-before-check handles empty-to-nonempty transitions.
`shutdown(self)` closes admission, takes the JoinSet out of the mutex, aborts and
joins every result, including after state poison. Drop is an abort fallback only.
Retained submission handles cannot keep native task I/O alive after joined shutdown.

Authored tests cover exact min/max framing with one-byte partial I/O, malformed
lengths/EOF/trailing data/acknowledgements and underlying errors; executor capacity,
normal/panic/poison/runtime failures, cancelled completion observation and physical
UDP rebinding while submission handles remain alive. Completed logs of
[CI 40112714369](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40112714369)
at `ae16803` confirm all six executor and six codec tests passed on Linux/Windows.
These are primitives, not live carrier/relay interoperability acceptance.

## Native carrier — accepted prerequisite

`Carrier::bind` consumes a libp2p identity, one native TCP listen address and an
immutable allowlist of at most 16 input entries, checked before deduplication.
It requires an active Tokio runtime and returns a sole driver, cloneable submission
handle and bounded incoming receiver. The caller drives `run(stop)` and awaits it;
there is no detached root task. Dropping the run future aborts but cannot join.

An admission behaviour runs before the request-response behaviour: at most eight
pending Noise negotiations and one authenticated connection per allowed peer.
Unknown authenticated peers and duplicate connections are rejected before protocol
handler creation. There is no attacker-extendable peer/address history. An address
is one typed SocketAddr on an explicit connect command, not an unbounded cache.
Noise authenticates the configured PeerId; packet bodies never declare the source.
Received packets carry the real local Swarm ConnectionId and authenticated peer.

Command and incoming queues each hold at most 32 records. Submission uses try_send,
not queued channel waiters. The request ledger is capped at 32 **before** calling
request-response's ID-allocating send method, and sends require a live authenticated
connection. Negotiating inbound streams and request-response active streams are
each capped at two per connection. Swarm background tasks retain the existing
64-task executor cap. These are separate bounds, not a total RSS claim.

Connect reuses a live connection; disconnect waits for its close event; another
explicit connect reopens on demand. Transport negotiation, whole RPC and pending
disconnect have ten-second deadlines. The adapter starts its own RPC deadline at
ID admission: request-response's worker timeout starts only after substream
negotiation and does not bound the preceding queues. Expiry reports TimedOut and
closes that peer, retaining each ID's charge until the dependency's terminal event.
Dropping a waiter does not release a still-retained request slot. A stuck disconnect
fails the driver and joins all managed I/O instead of hanging indefinitely.
There are no automatic retries or hidden delivery replays; cancellation after
admission may be ambiguous.
Amino discovery, address TTLs, retry/backoff and relay lifecycle belong to the next
integration leaf, not a new retry mode in this carrier.

A successful acknowledgement means admission to the remote bounded queue, not
application consumption. A full queue omits the acknowledgement and discards that
packet; callers must not assume every failure proves non-delivery. Consuming the
queue permits subsequent admission. On explicit stop, last-handle drop, incoming
consumer drop or fatal error, Swarm is dropped before executor abort/join. Retained
handles and received records do not retain native listener or connection sockets.

Authored tests cover real TCP/Noise exact bidirectional min/max payloads, connection
reuse and reopen, source provenance, denied/wrong-pinned peers, full incoming queue
and resumption, bounded command cancellation, pending admission reclamation, silent
Noise timeout and native listener rebind after joined shutdown with handles alive.
At `a79c36a`, [CI 40114098040](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40114098040)
passed all nine native cases plus six executor cases on Ubuntu. Windows passed 14
and failed the connection-reuse/reopen case with TCP AddrInUse (10048). The exact
initial-versus-reopened call was not logged separately. Pinned libp2p-tcp 0.45.0
reuses the listener address by default (`src/lib.rs:379-413`); its fresh-port retry
handles AddrNotAvailable, not Windows AddrInUse. The corrected adapter explicitly
uses Swarm DialOpts::allocate_new_port(), not a test sleep or blind retry. Signaling
dials need no listener-port hole punching; QUIC direct-path NAT policy is unchanged.
The original reuse/reopen assertions are retained. The corrected both-OS proof is
recorded below.

Additional authored fault controls fill the actual request ledger before submission
33, cancel a waiter without returning its slot, invoke the production expiry action
and require all charged IDs to survive until terminal dependency events. A real
Noise peer deliberately withholds acknowledgements; further controls cover fatal
close deadline, incoming-consumer drop and last-handle drop with listener rebind.
At `c13a93e`, [CI 40115045999](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40115045999)
completed successfully on Linux and Windows. Actual completed job logs were read,
not inferred from watcher exit codes. Each OS passed:

- 19 library tests: 13 native carrier/admission/fault cases plus six executor cases;
  library suites took 10.04s/10.06s.
- Six codec integration tests, including fragmented min/max frames and rejection controls.
- Ten P08 source/graph Python controls, four relay lease cases and five ingress cases.
- Existing SDK: 41 library, eight backend (five actor plus three native), and three
  public API cases, including the unchanged sixteen-stream immediate UDP rebind.
- 88 structural/scanner controls, formatting and clippy; fixture output scans clean.
  The separate Linux unprivileged-reader probe also passed.

GitHub jobs metadata repeatedly returned HTTP 502, empty or stale step arrays;
watchers failed because of those API errors. Direct bounded job-log downloads and
the final run conclusion independently supplied acceptance evidence. No test or
workflow was rerun to obtain the result. The service-side reporting delay's cause
is unknown; it is not attributed to a test, runtime or product-code defect.

This accepts the native carrier prerequisite only. No Amino/relay/Iroh bridge,
common SDK identity binding, signaling-only decoded-frame proof, public-network
availability, total RSS/performance or arbitrary cancel/retry safety is claimed.

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
timer. It rejects expired, oversized or unrepresentable local clock inputs and
requires an epoch-second difference of 1..=86400. Rejecting a valid longer offered
lease is an explicit resource/compatibility trade-off, not a claim about all public
relay policies. Source anchors and provenance fail closed; no archive code runs
during preparation.

### Actual reservation expiry boundary — accepted prerequisite

The relay client's public acceptance event originally exposed `renewal` and circuit
`limit`, but not reservation expiry. Circuit duration is not a reservation lease.
The prepared source now carries the validated `expires_at: web_time::Instant` from
HOP response parsing through the private reservation/handler to
`client::Event::ReservationReqAccepted`. The deadline is not recomputed at event
receipt. Upstream package versions, wire messages and Swarm Rust source stay unchanged.

The owned helper returns both remaining and renewal durations. Fractional UTC time
is retained: rounding it down to whole seconds could extend a lease by almost one
second. A monotonic sample is taken **before** the wall-clock sample, then remaining
time is added with checked arithmetic before any timer construction. Scheduler
delay between those samples can shorten the local lease, not extend it. Renewal is
three quarters of the actual remaining duration; a full one-second lease renews at
750 ms rather than the earlier whole-second rounding to one second. Five authored
std-only cases cover normal/min/max/fractional/invalid-clock or expiry boundaries.

An authored real TCP/Noise fixture serves circuit-v2 HOP protobuf replies using
already-resolved prost 0.14.4, prost-codec 0.4.0 and asynchronous-codec 0.7.0 as
exact dev-only edges. Their published archive bytes were checked against the
existing lock; package identities/versions do not change. The fixture checks a
golden STATUS encoding, valid-response sensitivity, and typed rejection of omitted,
zero, expired, two-day and u64::MAX expiry. Its valid lease is deliberately distinct
from its one-second circuit limit. Both Swarms are dropped before managed task
abort/join on success and rejection; a task panic cannot count as valid rejection.
This exercises reservation parsing/events, not a complete relay server or circuits.
The [circuit-v2 reference](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md)
defines UTC UNIX expiry and separate circuit limits; the stricter maximum-lease
policy is local.

Implementation `6e2c84e` initially passed the full Ubuntu matrix; Windows stopped
before HOP tests on a separate pre-existing SDK client UDP rebind failure. That
failure was corrected by awaiting netwatch's kernel close in `5395a6a`, without
changing this relay implementation or its rejection oracles. Actual completed
[CI 40122403791](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40122403791)
logs confirm both OSes passed all five shared lease cases, all 12 P08 source/graph
controls and all three HOP wire/fixture tests (0.14s/0.10s). The native positive
response distinguishes the real 60-second reservation from its one-second circuit
limit; every hostile reply reaches the exact typed expiry rejection without
advertisement or a task panic. Both managed task groups are joined after each case.

This accepts only the reservation parsing/expiry boundary. Relay reservation and
circuit lifecycle, authenticated stale-generation handling, Amino discovery,
common SDK/Iroh identity and full signaling-only relay frame proof remain separate
implementation and acceptance work.

### Authenticated relay connection context — verified API prerequisite

A PeerId alone does not identify a physical connection generation. A queued
acceptance must not be reassigned to a newer connection if the peer reconnects
before consumption; looking up only the newest connection cannot prove its origin. The
prepared public reservation and inbound/outbound circuit events now carry the
actual authenticated relay control ConnectionId from on_connection_handler_event.
Inbound events also identify the authenticated relay; their src_peer_id remains a
relay-announced claim until end-to-end Noise authentication succeeds.

The strengthened real HOP fixture compares the event's ConnectionId with the actual
Swarm connection-established event, rather than trusting an address or packet body.
Source/provenance controls require all three public event paths to copy that exact
context. Wire messages and package versions are unchanged. This is an authored
source/API prerequisite for the owned reservation/circuit state machine, not proof
that stale-event rejection or a working relay carrier is already implemented.
At `4791003`, actual completed [CI 40125792125](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40125792125)
logs confirm both OSes passed 13 source/graph controls and the three real HOP/fixture
cases, including the new reservation-to-connection assertion. Native carrier,
codec and SDK/kernel-close regressions also passed. The live circuit-event paths
and owned stale-generation policy remain part of the pending lifecycle integration.

### Cancelled relay transport work — authored, pending CI

The upstream listener close path reported ListenerClosed before closing its
from-behaviour receiver. A ListenReq already queued to the behaviour could therefore
be processed after the close callback and insert a dead listener into pending maps
or start an unwanted dial. Discarding only the eventual transport object is too late.
Prepared source now closes that receiver before enqueueing ListenerClosed, rejects
closed ListenReq or cancelled DialReq before any map/dial admission, and rechecks
cancellation before the handler allocates a reservation or circuit request.

Each skipped message makes progress and yields with a wake for remaining work;
there is no recursive drain or unbounded per-poll loop. Four authored controls use
the actual relay transport/behaviour APIs: live reservation/circuit requests must
reach dial admission, while 64 listener-close and 64 circuit-future cancellations
must never produce a dial or handler action. These deterministic controls do not
need network timing or a success-by-nondelivery timeout. Their runtime outcomes are
pending CI; complete reservation/circuit ownership is still not accepted.

## Owned relay lifecycle — authored, pending CI

The carrier composes a circuit-v2 client with native TCP/Noise/Yamux. `reserve`
creates or reuses a locally owned reservation; `relay_leases` observes bounded
snapshots, not ownership or authority to extend a copied lease. Publication requires
an actual authenticated control ConnectionId, validated future expiry and a bounded
advertisement for the local peer. Renewal updates expiry without replacing the
reservation generation. Cancellation, expiry, listener failure and control loss
revoke publication; teardown waits for listener and control termination, with a
ten-second fatal fence. A new generation cannot reuse an old physical control.

Application identities (at most 16) and infrastructure relay identities (at most
eight) are disjoint. Infrastructure RPC packets never enter the incoming queue.
At most two reservation records exist, each retaining at most four distinct
advertisements of at most 256 encoded bytes. Failures retain bounded 60-second
history; retries are explicit, at most three per history, with exponential cooldown
and non-cryptographic jitter. There is no automatic payload retry. Idle unreferenced
relay targets expire after 60 seconds, with managed disconnect before reclamation.
These fixed policies trade public relay compatibility for predictable state; they
are not a new configurable discovery subsystem.

`connect_via` pins the application peer through end-to-end Noise. `Received.route`
distinguishes native libp2p TCP from an actual relayed circuit; neither denotes
native QUIC application-data permission. Outbound circuits retain the configured
relay identity; inbound relay-hop attribution is explicitly unknown, rather than
invented from a relay's claim. The authenticated peer, local ConnectionId and local
circuit generation remain available. Existing different routes require explicit
disconnect before replacement. All native TCP dials, including internal relay
behaviour control dials, force fresh local ports; listener-port reuse is not needed
for this signaling transport.

Before Noise, each raw relayed stream has a combined read/write budget of 1 MiB
(including Noise/Yamux overhead) and an absolute 120-second lifetime. Exhaustion
returns an error, never a successful empty read. Two cold timer allocations preserve
independent read/write task wakeups; there is no new per-packet wrapper allocation.
Lower server quotas still terminate circuits normally. No retry resumes a partial
frame. State transitions use fixed bounded scans and allocate lease snapshots only
when changed, not per packet; this is not a whole-process RSS guarantee.

Authored units exercise role/capacity separation, stale contexts, malformed and
oversized advertisements, advertisement deduplication/caps, non-busy retry cooldown,
fresh-port dial policy, exact shared byte budgets, partial-write terminal behavior
and independent deadline wakeups. Seven authored integration scenarios use an owned
Rust relay and two signal drivers, with no direct destination shortcut: exact
bidirectional 1/1500-byte packets, reuse/reopen and generations, renewal, refusal,
physical relay loss, real server time/byte quotas and role rejection. The fixture
retains and joins exactly three root tasks. These tests have NOT yet been executed;
controller acceptance is pending actual Linux/Windows CI, not inferred from the
previous expiry or native-carrier proofs. Common SDK identity, Iroh custom transport,
Amino discovery and consolidated signaling-only frame proof remain separate leaves.

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
