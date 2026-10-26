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

## Owned relay lifecycle — real-path CI proof

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
retains and joins exactly three root tasks.

At `36c026e`, actual completed [CI 40173783110](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40173783110)
logs confirm Linux and Windows passed all seven real relay scenarios (8.11s/8.10s),
30 P2P library tests, six codec cases, four cancellation controls, three HOP wire
cases, 14 source controls and the existing SDK/structural regression matrix. The
first runtime attempt at `4169051` passed six relay scenarios but exposed a fixture
ordering error: local dial completion did not establish remote driver readiness
before its reverse send. The exact forward-packet/remote-receive barrier corrected
that ordering without sleeps, retries or weaker generation assertions.

An additional virtual-time controller regression was authored after that run: a
published lease is revoked at its local deadline, a late renewal cannot resurrect
it, and a copied lease does not extend. It is not included in the earlier 30-test
count. This is a controller transition test with injected authenticated context,
not another real-network expiry proof. Common SDK identity, Iroh custom transport,
Amino discovery and consolidated signaling-only frame proof remain separate leaves.

At `9626c37`, completed [CI 40174230988](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40174230988)
confirmed that additional expiry regression on Linux and Windows: 31 P2P library
tests and all seven real relay scenarios passed, with the full matrix successful.
The integrated controller worktree was removed only after all changed files were
verified byte-identical to tracked product files and this CI proof was read.

## Current link observations — accepted prerequisite

A queued `Received` can outlive its physical connection. `CarrierHandle::links`
therefore exposes at most 16 application-link observations, sorted by authenticated
peer and carrying the actual ConnectionId and route. Infrastructure connections are
excluded. Publication occurs only on connection lifecycle changes, not per packet.
A bounded cold scan and small Vec are chosen over maintaining another hot shared
index. Closing links are removed before a disconnect completes or timeout replies
are delivered; synchronous Core destruction publishes an empty final snapshot,
including cancellation/fatal exits. This is not async work in Drop or a joined I/O
promise: `Carrier::run` still owns actual task abort/join.

`is_current` compares a queued record with that current observation and refuses
closed submission handles. A copied snapshot does not pin a link, promise future
liveness, or grant QUIC application-data permission. Observation and subsequent I/O
are not one atomic operation; the Iroh adapter still needs instance/generation
binding and final authenticated-peer validation. Noq's NativeOnly policy is unchanged.

Authored controls cover real native queued-record rejection across disconnect and
reopen, forged connection/route metadata, retained observers after shutdown, timeout
revocation, fatal/last-handle/consumer terminal exits and real owned-relay link
metadata. At `b5174a9`, completed [CI 40175458904](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40175458904)
logs confirm Linux and Windows passed all 32 P2P library tests, seven real relay
scenarios, 14 source controls and the full regression matrix. This prerequisite is
not the full Iroh adapter or the common SDK identity bridge.

## Common SDK identity construction — accepted prerequisite

`shaar::network::bind_signaling` constructs the existing caller-driven carrier from
an SDK Identity, one TCP bind address and at most 16 public peer keys before
deduplication. It returns the owner, submission handle and bounded incoming receiver;
the caller must drive and await the owner for joined cleanup. This constructor does
not install an Iroh custom transport or make SDK Endpoint::close own a separate
carrier. Native QUIC construction and its NativeOnly filter remain unchanged.

The crate-private Identity conversion uses libp2p-identity 0.3.0's reviewed
ed25519_from_bytes API with a Zeroizing staging buffer. There is no new public
seed/key getter and no custom cryptographic algorithm. Staging erasure remains
best-effort: dependency-internal temporary copies and compiler/OS copies are not
covered by this guarantee. Identity error formatting remains redacted. The existing
exact libp2p-identity dependency moves from dev-only to production use; it was
already in the product lock and carrier graph, with no new package or version.

Authored tests cross-verify signatures with the pinned Iroh/libp2p libraries,
reject wrong keys and modified messages, reuse all three existing P04 RFC vectors
through the production constructor, and check bounds/runtime/error behavior. A real
Noise topology uses the same SDK identities as simultaneously bound native Iroh
endpoints, rejects an allowed client's incorrect server pin, exchanges exact packets
and joins all three owned signaling roots before listener rebinding. At `b46e2d8`,
actual completed [CI 40176806269](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40176806269)
logs confirm all four new SDK units and the P04 vector-constructor case passed on
Linux and Windows: 45 SDK library tests, 32 P2P library tests, seven real relay
scenarios and the full regression matrix succeeded. This is identity-construction
proof, not a custom Iroh transport, Amino discovery or full signaling-only frame/path
acceptance.

## Generation-bound send admission — accepted prerequisite

A snapshot check followed by `send(peer, ...)` is not atomic with closing or reopening
a circuit. `send_on(Link, ...)` queues the exact expected authenticated connection
and route alongside the datagram. The sole carrier owner checks these before the
request-response ID is allocated. Stale, closing and wrong-route generations cannot
transfer queued work to a successor link. Existing peer-only send semantics, bounded
request charges, remote-admission acknowledgement and ambiguous post-admission
cancellation are unchanged.

The pinned request-response `src/lib.rs:566-583` queues NotifyHandler::One for the
selected connected ID. Admission permits only one physical connection per peer, and
all behaviour callbacks are driven by the same Swarm owner. No await or connection
event can interleave exact-link validation and that request submission. This does
not make a subsequent remote acknowledgement proof of application consumption.

Authored tests retain an actual command queued before close, reopen the real Noise
link, then dispatch that old command and require rejection before any local request
charge. A positive generation-bound packet must still arrive exactly on the new
link. Native tests also reject forged routes, and the owned relay scenario rejects
a changed generation on the same physical connection before exchanging min/max
packets through the pinned link. At `642e8a5`, completed
[CI 40177845591](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40177845591)
logs confirm both OSes passed 33 P2P library tests, including the queued-before-reopen
case, seven real relay scenarios and the full regression matrix. Factory/batching,
address binding, multi-waiter backpressure and SDK ownership are separate from this
admission method.

## Caller-driven Iroh adapter — component CI proof

`SignalingTransport::attach` consumes the carrier's sole incoming receiver and returns
a single-bind custom-transport factory plus `SignalingPump`. The caller owns both
carrier and pump execution. The pump uses eight fixed async worker futures, allocated
once through a bounded join, rather than detached tasks or a per-packet growing future
set. Each worker submits through exact-link send_on. Local send completion means
bounded queue admission, not remote delivery; QUIC owns control retransmission, and
failed or stale RPCs are never replayed on a successor link.

Outbound and delivered-input queues each hold at most 32 records. A semaphore serves
at most eight fixed consumer waiters. Up to 64 distinct send wakers are registered
before returning Pending, with deduplication; overflow returns WouldBlock, not a
permanently unwakeable future. Dequeue, binding refresh and close wake registered
senders outside the critical section. The registry is a fixed array, so cancellation
cannot extend a waiter history indefinitely. The short synchronous mutex protects
queue admission and at most 16 mappings; it never spans an await, network I/O or
foreign-future destruction. Formal lock-freedom is not claimed.

Opaque custom addresses contain a checked process-local instance and per-link epoch,
16 bytes cached inline by the pinned address type. They are local references, not
portable peer announcements or secret capabilities. Source bindings are minted from
actual current peer/ConnectionId/Route observations, and both the pump and receive
boundary reject stale records. Maps are cardinality-bounded; refresh is cold, while
packet lookup uses the epoch index. No new address/body field grants application-data
permission. Batches validate slice lengths and the platform BATCH_SIZE; GSO splitting
is not supported. Close revokes queue admission and address bindings synchronously;
it is not an asynchronous I/O join promise.

A direct edge to existing iroh-base 1.3.0 is needed for the public CustomAddr API;
only that workspace dependency edge is added to the lock, with all package
identities, versions, sources and checksums preserved. Authored units cover namespace
and epoch invalidation, counter exhaustion, state poison, bounded multi-waiter wakeup
and queue shutdown. Real TCP/Noise carrier tests cover exact 1/1500-byte adapter
packets and owned four-root cleanup; a separate injected-boundary case covers batches.
A real Iroh handshake test disables every IP/relay transport and permits no custom
APP frames, requiring the actual custom carrier to complete control traffic. These
tests passed on both OSes at `a8e26b0`, completed
[CI 40182149229](https://github.com/PHPCraftdream/shaar-stack/actions/runs/40182149229):
all five new bridge cases, 38 P2P library tests, seven relay scenarios and the full
regression matrix succeeded. The first adapter attempt stopped before runtime on
Rust 1.99.1's deprecated fetch_update spelling; try_update preserved the checked
counter and ordering without a lint suppression or version change.

This component proof is not final SDK ownership or consolidated frame/path
acceptance. A generic factory is not positive application-data authority: the
trusted Noq NativeOnly filter remains mandatory, before packetization/encryption.
No opaque custom sender can enforce that policy by inspecting encrypted bytes.

## Joined SDK owner and source identity — authored, pending CI

`shaar::network::SignaledEndpoint` composes the native SDK endpoint with one retained
signaling coordinator. Its constructor accepts at most 16 input public peer keys
before deduplication, validates native addressing before startup, waits for signaling
readiness and awaits signaling cleanup on a failed native bind. The original native
Endpoint API remains available and unchanged. The new owner's close returns a typed
result: Iroh drains while signaling is available, then both carrier and pump results
are observed and their owned work is joined. Session/factory handles do not own the
coordinator or native sockets. Drop/cancel is only an abort fallback; it must not be
misrepresented as an async joined-close guarantee.

A custom IncomingAddr is captured before TLS completion. Before a Session is created,
the current locally minted source resolves to an actual authenticated Link; its peer
must equal the canonical libp2p identity of the final TLS key. Reopened/stale epochs
fail lookup. Allowlisting both A and D is insufficient to let carrier peer A forward
QUIC from identity D and become an SDK Session for D. Outbound custom negotiation also
rechecks the exact source binding after the pinned TLS handshake. None of these checks
grants APP permission on custom paths; the NativeOnly packetization policy is unchanged.

Independent configured-reviewer and @fh source reviews agreed on a graceful-close
race: a ready receive refresh could return BrokenPipe after the shared adapter was
closed but before the outer select observed its close notification. The terminal
finalizer now normalizes only BrokenPipe with already-closed state, before performing
its own cleanup. It reads the protected state rather than a potentially lagging watch
notification; other errors are retained. Deterministic authored regressions cover the
classification order and notification gap. This is not a sleep, retry or diagnostic
suppression. Final lease observations are also cleared on owner destruction rather
than leaving a closed endpoint's advertisement as the last watch value.

New SDK tests are authored, not yet executed: valid custom identity versus A/D
laundering with both ACL entries and a client with no IP shortcut; public direct
signaling negotiation plus native APP exchange; owned relay reservation/bootstrap
without a destination direct-TCP shortcut; final lease revocation; immediate native
UDP/control-TCP rebind with sessions/factories retained; failed startup; cancelled
admitted control handshake followed by explicit joined close; cancellation while
close awaits its coordinator; and both child-completion/error orders. The relay
fixture reuses exact already-locked libp2p/futures packages as dev-only SDK edges;
all package versions, identities, sources and checksums remain preserved.

SDK integration acceptance still requires actual Linux/Windows CI. Consolidated
single-connection frame/path attribution with positive allow-all calibration,
Amino discovery and separate public-network smoke remain independent later leaves.

## Native after custom negotiation — diagnosed; correction pending CI

SDK run `40193934972` localized the remaining Linux failure: both custom and later
native-requested handshakes succeeded, but the APP-bearing second connection exposed
only custom paths; the client buffered a request and the server waited for a stream.
Windows passed that run. A native Iroh connect argument is a cached peer-address hint,
not proof that this connection has an established native path. The NativeOnly filter
correctly prevented APP fallback; neither a retry nor native-first test reordering
would correct the integration gap.

The reviewed backend bridge now exposes a completed-client-connection operation for
one original explicitly supplied native address. SDK native connect, after TLS/source
and ALPN checks, establishes that path on the same new connection before publishing
Session, within the unchanged total deadline. The unpublished Session is the existing
close-on-drop guard. Custom connects and accepted/server connections do not invoke it;
no actor-wide hint replay, selector relaxation, retries or new pending queues appear.
The bridge additionally observes exact PathId establishment: bare Noq ensure can be
ready for an internally created QNT path that is still validating. It also handles
abandonment, event lag and connection close explicitly. Source preparation reverses
only this exact owned method before original-byte equality checks.

Authored regressions retain the original custom-first/native-second payload scenario,
check an established exact native path on the second connection, repeat ensure without
allocating another PathId, reject invalid/native-reserved/server-side inputs, and test
an unreachable explicit candidate: no client Session is published, its new connection
closes, the prior control connection remains open, and explicit endpoint close joins.
These corrections and new cases are not yet runtime-accepted. Forced pending-QNT and
capacity-exhaustion interleavings are source-reviewed but must not be described as
newly executed runtime coverage.

The first correction exposed a second readiness boundary: main CI `40199013113`
passed 52 SDK cases on each OS but native connect returned RemoteCidsExhausted before
path admission. Initial additional-path CIDs arrive separately from the TLS Connected
notification. Preparation now forwards one bounded informational event after the
first successfully accepted CID for a PathId, and the same native operation waits on
that actual state change only for this error. No sleep, retry task, actor queue,
deadline extension, hard-limit suppression or APP policy change is involved.
Unreachable-path testing now requires observed native transmission and excludes
arbitrary admission errors. This event/readiness correction still requires CI.

## Carrier-owned DNS foundation — authored, pending CI

`DiscoveryConfig::new` validates one to four pinned TCP/DNS seed descriptors and
one to four numeric nameserver endpoints, counting inputs before deduplication.
Addresses are at most 256 encoded bytes; DNS names are absolute, ASCII-canonical,
and case-normalized. Peer suffixes must match. Numeric resolvers may be private or
loopback and use custom nonzero ports; unusable, scoped and IPv4-mapped endpoints
are rejected. `Carrier::bind_with_discovery` rejects local/application/seed identity
overlap before listener work. The legacy `bind` stays numeric-only and does not
construct a resolver. Neither constructor queries DNS or starts bootstrap.

Configured carriers retain seed descriptors as infrastructure reservations that
cannot authorize application packets or link/bridge observations. Their native
path contains FreshPorts TCP, the prepared DNS transport with a private owned
resolver, Noise, Yamux and the existing overall timeout; relay composition is
unchanged. An outer numeric-only gate currently rejects every DNS dial before
resolution. Real DNS/Noise fixtures are private; there is no public discovery
command or permissive-address mode. This intentionally keeps untrusted DNS input
unavailable until the next wire and destination-role unit is integrated.

The resolver uses only explicit in-memory UDP/TCP connections and the supplied
numeric endpoints. Hosts and search loading, opportunistic encryption, persistence
and the default spawning provider are not used. The prepared zero-capacity branch
avoids Moka construction and cache-only copies; this is not zero total allocation
or removal of the Moka package. Moka 0.12.16 has no maintenance worker to join.
Four resolver-call permits are shared across clones and retained until each future
terminates or is destroyed. Admission is immediate, with no waiting queue. Fixed
options allow one retry, one nameserver request at a time, four requests per TCP
connection and a two-second per-request timeout; the carrier's complete-dial
10-second timeout remains outside DNS and authentication.

DNS background work uses exactly the Swarm's existing 64-task executor. A private
irreversible gate linearizes admission at a sequentially consistent open-state
load and closure at its swap. Every previously unpolled operation checks admission
when first polled; socket polls check it too. Work already admitted before closure
may finish its current poll, so closure is not a destruction barrier. Watch
cancellation registers before that check and wakes pending lookup, socket-creation
and background owners. There is no additional task registry, user-defined gate
mutex or foreign-future polling/destruction under a new guard; dependency-internal
watch/executor synchronization is not claimed lock-free. UDP validates every send
against its exact configured server endpoint, not just the socket's bind argument.

Core closes commands and the DNS gate before destroying Swarm, resolver and dial
owners; `run` then awaits the existing executor shutdown. Whole-carrier field order
is retained across cancellation. Startup failure, Drop and canceled close remain
abort-only, never a joined resource claim. Raw lookup futures and sockets are not
public capabilities. Fixtures retain resolver/provider/submission handles across
joined close, observe caller-owned UDP socket rebind and pooled TCP EOF, and hold
a real bound socket in an unpolled TCP-connect future before background spawning.
That last barrier is not evidence of a kernel-level SYN in flight.

The only product dependency delta is the explicit `shaar-p2p -> hickory-resolver
0.26.3` edge with default features disabled and `tokio` requested. Package versions,
identities and other lock edges are unchanged. CI compares full host-resolved
metadata against the same workspace without that edge, requiring unchanged feature
unions and rejecting encrypted resolver protocol features. System-configuration
support remains enabled transitively by libp2p-dns; its presence is not permission
to call it. The baseline lock reversal is checked against an immutable digest.

The foundation adds 30 owned local Rust fixtures and five graph negative controls
for CI only; no local Cargo, compilation or tests were run. DNS fixture allocation
retains TCP while binding UDP at the same endpoint, retries only `AddrInUse` up to
16 attempts, and propagates other errors. Deterministic controls exercise a real
UDP collision, retry exhaustion, non-collision errors and occupied TCP admission.
Endpoint controls distinguish same-IP/different-port from same-port/different-IP
rejection at UDP bind, TCP connect and repeated UDP sends. Fixtures require real
`::1` UDP queries and UDP-to-TCP fallback with IPv6 socket-family assertions,
not merely AAAA answers carried over IPv4. Both local families exercise occupied bind failures and
incompatible-family errors. UDP remains unconnected: a mismatched local-family
bind can succeed, while its actual send fails; production semantics are unchanged.

Wire length/header gates, TCP pre-prefix validation, pre-materialization/numeric discovery-role policy, bounded
Kademlia/Identify ownership, `discover_relay`, SDK forwarding and Amino discovery
remain unimplemented by this unit. No public-network availability is claimed.

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
