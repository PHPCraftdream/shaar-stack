# Amino DNS: resolver ownership and retention boundary

Source-only prerequisite for the bounded Amino integration. This document does not
accept a resolver implementation, runtime shutdown, or public-network availability.
Baseline: `ee69093`. No downloaded source, build script, compiler, or test ran locally.

## Verified source identity

Archives were downloaded into separate fresh ignored directories, checked against
Cargo.lock, and extracted as data. References below are archive-relative.

| Package | Version | SHA256 |
| --- | --- | --- |
| hickory-resolver | 0.26.3 | `3f3da5255c95d5a716857d54b5b8f4e8d67c3484d3beaaaae2ce25063b3ba981` |
| hickory-net | 0.26.3 | `c480823ed7c2c5d0f09c41020cb6b7c28029ce60ec42dc942158dcf22f8e0a4d` |
| hickory-proto | 0.26.3 | `12b92608f679a6fa515dd1d15c1ff89443026e391200a2c840c7afcba482893d` |

The already verified libp2p-dns 0.45.0 archive is documented in [the preflight](README.md).
Aliases used below: **R** = `hickory-resolver-0.26.3/src/`, **N** =
`hickory-net-0.26.3/src/`, **P** = `hickory-proto-0.26.3/src/`, **D** =
`libp2p-dns-0.45.0/src/`.

## Observed task ownership

1. `N/runtime.rs:138-149`: the default `TokioHandle` contains an
   `Arc<Mutex<JoinSet<()>>>`. Every `spawn_bg` spawns into that set and then reaps
   already finished tasks. Admission has no configured task-count limit here.
2. `N/runtime.rs:152-171`: `TokioRuntimeProvider` clones that handle. Its public
   implementation exposes I/O construction and handle creation, not joined shutdown.
3. `N/runtime.rs:220-223`: reaping uses `try_join_next`; the result is discarded.
   This is not an awaited task-destruction barrier or propagation of task failure.
4. `R/resolver.rs:95-101`: the resolver is cloneable and owns shared context,
   client cache, hosts, and search-name state. Dropping one resolver clone is not
   evidence that all lookup, connection, provider, or background owners disappeared.
5. UDP exchange creation calls `provider.create_handle().spawn_bg(bg)` at
   `N/udp/udp_client_stream.rs:422-428`. TCP exchange creation does the same at
   `N/tcp/tcp_client_stream.rs:50-67`.
6. `N/xfer/dns_exchange.rs:79-96` keeps a request-stream sender in the response
   stream. At `:163-187`, loss of an individual request recipient does not stop
   the exchange; only exhaustion of all request senders asks the stream to shut
   down. It then continues polling the underlying stream to completion.
7. `R/name_server.rs:444-454` also routes opportunistic probe work through the
   connection provider's runtime handle. A spawn adapter must cover every enabled
   protocol, not just the main lookup future.

**Conclusion:** the default provider cannot establish the project's explicit
joined-close guarantee through this public API. A caller timeout or resolver Drop
must not be reported as an awaited kernel-resource close. This observation alone
is not a proof that a specific lookup leaks permanently; clone reachability and
actual task destruction need a runtime witness.

## Available customization, and the libp2p constructor gap

- `N/runtime.rs:244-283` defines the public `RuntimeProvider` interface. It has
  associated handle, timer, UDP and TCP types. The handle implements `Spawn`, whose
  `spawn_bg` signature is at `N/runtime.rs:346-348`.
- `R/connection_provider.rs:48-107` provides a blanket `ConnectionProvider`
  implementation for a runtime provider. UDP and TCP use that provider; the TCP
  path forwards `max_active_requests`.
- `R/resolver.rs:119-135` accepts a caller-provided provider through
  `Resolver::builder_with_config`. Building the resolver creates the pool and
  retry/cache wrappers at `:523-575`.
- `D/lib.rs:139-144` keeps transport fields private. The public Tokio constructor
  at `:79-90` constructs its own default provider. Passing `ResolverOpts` does not
  replace that provider or expose its task owner.
- Although the DNS `Resolver` trait is public at `D/lib.rs:555-590`, this alone
  does not provide an external constructor for `Transport<T, CustomResolver>`.

**Recommended minimum integration boundary:** retain Hickory's existing protocol
implementation. Supply a small safe runtime-provider adapter whose `Spawn` handle
submits to the existing bounded `OwnedExecutor`. Delegate I/O/timers without ever
calling the default provider's spawning handle. Add a narrowly owned, checksum-
and-anchor-verified libp2p-dns constructor for the caller-provided resolver. Do not
patch Hickory with a second independent task registry just to obtain shutdown.

The existing owner is `crates/shaar-p2p/src/executor.rs`: admission is capped at 64
before spawn (`:137-174`), overflow is terminally observable, and `shutdown`
(`:110-134`) closes admission, takes the JoinSet outside its lock, aborts and awaits
every task. Drop remains abort-only. Reusing it also means DNS and Swarm tasks share
that total budget; it is not permission to allocate another 64-task pool silently.

An adapter is not implemented or runtime-verified by this report. Required order:
stop commands and DNS/dial admission, drop Swarm/resolver/lookup owners, then await
the executor shutdown. Retained submission handles must reject new tasks after
closure. Cancellation of that shutdown still has only the documented abort-only
fallback.

## Observed memory and work controls

| Boundary | Source observation | What it does not prove |
| --- | --- | --- |
| Resolver cache | `R/config.rs:532-534` counts responses, not bytes. `R/cache.rs:39-45` forwards capacity to Moka. | A small address cardinality, immediate hard eviction, or no maintenance work inside Moka. Moka internals were not inspected here. |
| Retry and nameserver parallelism | `R/config.rs:516-524,561-575` exposes request timeout, attempts, per-query server concurrency, and per-multiplexed-connection active-request count. | An overall DNSADDR epoch deadline or global active-query limit. |
| TCP active requests | `N/xfer/dns_multiplexer.rs:202-210` rejects at the configured active-request cap before allocating a query ID. | A total connection/background-task count. |
| Exchange queue | `N/xfer/dns_exchange.rs:51-66` uses a futures bounded channel; `N/xfer/mod.rs:484` supplies buffer size 32. | An exact global 32-request limit across cloned senders, exchanges and nameservers. |
| Response queue | `N/xfer/dns_multiplexer.rs:235-247,378` uses buffer size 8 per active request. | A global byte budget. |
| UDP wire input | `N/udp/mod.rs:30`, `N/udp/udp_client_stream.rs:140,217` cap that receive buffer at 4096 bytes and the request payload size. | A small decoded-record count or bounded accumulated DNSADDR alternatives. |
| TCP wire input | `N/tcp/tcp_stream.rs:334-340` reads a u16 length and allocates that many bytes. | The same 4096-byte UDP bound for TCP; TCP can allocate up to 65,535 bytes per frame. |
| DNS question decoding | `P/op/message.rs:665-679` allocates `Vec::with_capacity(counts.queries)` before reading the questions. | A small allocation inferred from a short malformed packet. The count is header-controlled, up to 65,535. |
| Other decoded records | `P/op/message.rs:419-425` initially reserves at most 8 records, then decoding may grow the vector. | A hard 8-record response limit. |
| Hosts and search state | `R/resolver.rs:95-101,565-568` retains hosts/search state and can load the system hosts file. | A bound implied only by the remote peer/address ledger. |

The libp2p DNSADDR/A/AAAA retention findings in the preflight still apply. Dropping
excess final addresses does not undo allocations already made by DNS decoding,
cache insertion, or intermediate multiaddr collection.

## Implementation obligations

These are requirements to verify, not new public configuration knobs:

1. Validate and bound seed DNS input, nameserver/search configuration and all
   intermediate roots before constructing resolver state. Use absolute names to
   avoid an uncontrolled search-list multiplication. Keep system configuration
   loading off async executor threads when it can block.
2. Bound outer lookup count, concurrent/charged work, resolver attempts, nameserver
   parallelism and total deadline separately. A per-request timeout is insufficient.
3. Decide explicitly whether the resolver cache is bypassed or independently
   justified. Do not claim `cache_size = 0` establishes no allocations or tasks
   without checking the implementation behind that option.
4. Reject overbudget DNS wire length and header counts before decoded retention.
   Preserve the existing parser and DNS validation rather than writing a new DNS
   implementation. Apply any prepared-source guard at the smallest reviewed boundary,
   and account for all other consumers of a workspace-wide patched package.
5. Cap DNSADDR TXT parsing and A/AAAA alternatives before their vectors/queues grow.
   Recheck numeric destination policy before TCP opens; DNS answers are not identity
   authority. Pin the expected peer at Noise/Swarm admission.
6. Keep background spawning exclusively inside the bounded joined owner. Prove
   shutdown with pending DNS and TCP work, resolver/handle clones retained, and actual
   native socket destruction. A future returning an error is not that witness.

## CI acceptance still required

- Owned UDP and TCP DNS fixtures: valid A/AAAA/TXT, truncated UDP/TCP fallback,
  NXDOMAIN, silence, malformed packets, excessive question/record header counts,
  large TCP frames, excessive TXT alternatives and recursive/cyclic DNSADDR.
- Bounds before decode/retention, not just final result sizes. Distinguish wire
  bytes, decoded records, intermediate addresses, requests, tasks and cache entries.
- Task admission at the shared limit, overflow error delivery, child panic, and
  rejected submissions after shutdown. No default-provider spawn bypass.
- Cancellation before admission, pending resolution, queued request, native dial,
  and shutdown; stale completion cannot revive a canceled generation.
- Explicit close with retained factories/handles/resolver clones proves no live
  tasks and kernel rebindability. Canceled close promises only abort fallback.
- No regression in signaling-only, relay identity/lease provenance, or custom APP
  denial. Public bootstrap availability remains a separate smoke result.

Source review stops here: the ownership mechanism and additional pre-retention
boundaries are identified. Implementation and runtime acceptance remain open.

## Task 85 follow-up: constructor and expansion only

The prepared libp2p-dns 0.45.0 boundary now supplies
`Transport::with_resolver(inner, resolver)` and fixed pre-retention expansion
limits. See [the exact prepared contract and CI proof path](README.md#12-task-85-prepared-dns-expansion-boundary).
The historical constructor-gap observation above describes the stock archive;
only that API gap and libp2p-owned expansion retention are addressed by this leaf.
The stock Tokio constructor still constructs its default runtime provider.

Prepared source is checksum/license/VCS/anchor pinned and reverses byte-exactly to
the original library. Numeric collection is capped at four before collection;
TXT acceptance is capped at 16 before parsing another candidate, with a 1,024-byte
whole-record text gate. The existing component parser writes into a fixed
256-byte buffer before any Multiaddr allocation. Pending candidates and error
history are bounded at 32 and 16 respectively. First-character-string semantics,
expected suffix matching, direct pass-through and the outer-timeout composition
are preserved. No second answer cache is added.

Source APIs used by the helper are `multiaddr-0.19.1/src/protocol.rs:141-289,476-620`
(`from_str_parts`, `write_bytes`) and `src/lib.rs:298-319` (upstream slash/component
parsing). Its archive SHA256 is
`fd707c05eadfb37577f01cbec206726feeecf0b9edea259aee6fc9bc541ee253` from the product
lock. The unchanged DNS fixture lock selects multiaddr 0.19.0, SHA256
`d96879ec0057cf5f99543c5333f6818c1473081684ae7ad55da21b6ea65ba214`; source comparison
confirms identical component string parsing/encoding APIs. The fixture's
hickory-resolver 0.26.1 archive SHA256 is
`f0d58d28879ceecde6607729660c2667a081ccdc082e082675042793960f178c`, and
hickory-proto 0.26.1 is
`0bab31817bfb44672a252e97fe81cd0c18d1b2cf892108922f6818820df8c643`.
`lookup.rs:53-70`, `lookup_ip.rs:68-72`, `rr/record.rs:163` and
`rr/rdata/txt.rs:78-85` provide the real Lookup/record constructors used by owned
fixtures. All supplemental archives were treated as data, not executed.

The 16 added Rust contracts and 9 Python controls passed on Windows and Linux in
CI runs `40223815897` and `40224856427`. This is scoped transport-expansion
acceptance, not resolver/socket lifecycle acceptance. Fake-future cancellation
demonstrates only the transport's local cancellation path. Hickory wire/decoded-record allocations, resolver cache,
arbitrary error payload bytes, task admission, joined shutdown with retained
handles, real sockets, numeric destination policy and owner epoch integration
remain open. The ownership conclusion above is unchanged: dropping or timing out
a stock resolver is not proof of awaited task or kernel-resource destruction.

## Task 92: concrete runtime, I/O and cancellation boundaries

Source-only follow-up on baseline `3999dd0`; the archive identities and aliases
above still apply. No provider implementation or runtime acceptance is claimed.
The product graph selects Hickory 0.26.3 and Tokio 1.54.1. The DNS archive fixture
uses Hickory 0.26.1/Tokio 1.53.1; the supplied Hickory archives' own locks use
Tokio 1.52.0. Those fixture graphs cannot substitute for product-graph acceptance.

### Exact adapter and import surface

`N/runtime.rs:244-348` defines `RuntimeProvider`, `Spawn`, `DnsUdpSocket` and
`DnsTcpStream`. `Spawn::spawn_bg` accepts a `Send + 'static` future returning `()`
and returns no admission result. `RuntimeProvider` supplies handle, timer, UDP
and TCP associated types; its TCP/bind methods return boxed `Send` futures.
The UDP socket must remain unconnected. Gate both polling methods:
`poll_recv_from` and `poll_send_to`; the default async methods delegate to them.
`DnsTcpStream` uses futures-I/O traits, not Tokio's traits directly.
`TokioTime` supplies timers without a new spawn owner (`N/runtime.rs:376-395`).

Construct through `Resolver::builder_with_config(config, provider)` and the
prepared `Transport::with_resolver`, not the stock Tokio transport constructor.
Stock `D/lib.rs:107-110` reexports only resolver configuration and the error,
not `RuntimeProvider` or `Resolver`. A direct dependency on the already resolved
Hickory package, or an explicitly reviewed reexport, is still needed; do not
assume an import through libp2p-dns exists. This is an import-surface choice,
not permission to migrate dependency versions.

### A task cap is not socket ownership

Forward `spawn_bg` to the existing `ExecutorHandle::exec`: DNS and Swarm share
one 64-task cap, not two independent pools. The executor releases its mutex
before rejecting/dropping a foreign future and takes its JoinSet outside the
mutex before abort-and-join (`crates/shaar-p2p/src/executor.rs:110-174`).
Completed-but-unreaped tasks conservatively retain slots; the owner must keep
observing results. An exchange task completing with `()` is not DNS success:
stream errors are logged before that completion (`N/xfer/dns_exchange.rs:148-158`).
Observe the actual lookup result separately.

Two ownership paths prevent a provider-only shutdown claim:

- UDP request sockets are created and held by the returned lookup/request future,
  not necessarily the exchange background task
  (`N/udp/udp_client_stream.rs:192-222,422-445`). The provider retained by that
  stream also retains the executor submission capability. Explicit owner shutdown
  must break task/provider retention; dropping one handle is insufficient.
- TCP awaits `connect_tcp` before calling `spawn_bg`
  (`N/tcp/tcp_client_stream.rs:50-88`). Task-cap rejection may happen after a TCP
  socket has connected. It bounds background tasks, not all preceding I/O.

Keep admitted lookups and connection futures bounded and carrier-owned; do not
export raw resolver futures as independently retained capabilities. Close DNS
admission and an I/O epoch gate, drop active lookup/dial owners and Swarm, then
await the existing executor shutdown. Retained provider/resolver/submit handles
must not restart I/O after closure. Cancellation of close remains abort-only.

Queued cancellation has a distinct boundary. The exchange calls
`io_stream.send_message` before discovering a canceled response recipient
(`N/xfer/dns_exchange.rs:163-177`). TCP serialization can already enqueue output
and active state (`N/xfer/dns_multiplexer.rs:249-267`); removing a canceled active
request does not retract that output (`:147-172`). If cancellation before dequeue
must mean no send, add an exact recipient-cancellation check before `send_message`.
Do not promise rollback after serialization/admission.

### Dependency locking still needs a narrow correction

- `R/name_server.rs:265-275` holds the connections mutex while awaiting
  `cx.transport_state()`. The comment calling this a short lock does not remove
  the await. A provider wrapper cannot correct it. Establish a coherent snapshot
  and lock order before changing this same-version dependency code.
- `R/name_server_pool.rs:941-944` discards the result of map removal while its
  temporary mutex guard still exists. The removed `SharedLookup` contains a
  boxed shared foreign future (`:984-995`). Move removal into a scoped local,
  release the guard, then destroy the value. A concrete deadlock is not proved;
  whether this is the last reference depends on the other waiters.
- That active-request map has no explicit cardinality admission at insertion
  (`R/name_server_pool.rs:150-195`). Background-task admission is not a bound on
  unique concurrent lookup keys. Bound outer lookups separately.

### Earliest wire and destination gates

UDP allocates a receive buffer no larger than 4096 and copies a received packet
before source/transaction checks (`N/udp/udp_client_stream.rs:140,217-273`). Gate
length and header counts in the socket polling wrapper, before exposing the
slice. Discard unrelated invalid datagrams without making spoofed input a fatal
query error; bound per-poll discard work and arrange a correct wakeup. Explicitly
handle oversize detection and Windows truncation behavior: a full receive buffer
alone cannot distinguish a complete packet from a truncated larger packet.

TCP reads two length bytes and allocates the declared body immediately
(`N/tcp/tcp_stream.rs:309-340`). A framing-aware read wrapper must validate the
prefix and fixed 12-byte DNS header before replaying the complete prefix to
Hickory, otherwise that allocation is already authorized. Preserve partial reads,
Pending, empty output buffers, EOF distinctions and consecutive frames. Use the
existing `Header::read`/`BinDecoder`, not another DNS parser; widen count sums.
`P/op/message.rs:665-679` reserves QDCOUNT before parsing any questions.

A proposed discovery-only profile is 12-4096 wire bytes, at most one question and
64 combined answer/authority/additional records. These are proposed limits, not
implemented acceptance: they reject some valid large responses. A wire envelope
also does not prove the transport's 1024-byte TXT limit occurs before Hickory's
TXT allocations. Keep that distinction explicit.

There are two destination policies:

1. Validate configured DNS-server endpoints and recheck before TCP creation/UDP
   bind. Because UDP remains unconnected, check every `poll_send_to` target
   against the approved endpoint too.
2. Validate fully composed discovery Multiaddr encoding before
   `Encoded::address()` in `.github/scripts/p2p/discovery/dns/bounds.rs`, then
   recheck every actual numeric native dial immediately above TCP inside DNS.
   Include direct numeric input, DNS/DNS4/DNS6 replacement, DNSADDR TXT, inherited
   prefix/suffix composition, nested resolution and behavior-generated dials.

Do not impose a new public-only policy on the existing public `Carrier::connect`
or `RelayAddr::new`: their loopback/private endpoint behavior is intentional.
The extra policy belongs to internal discovery roles, not a global SDK change.

Restrict this initial provider profile to UDP/TCP before resolver construction.
TLS encrypts the bytes a raw TCP DNS framing gate would inspect (`N/tls.rs:97-112`).
H2 and H3 have direct Tokio driver spawning (`N/h2.rs:200-210,291-300`;
`N/h3/h3_client_stream.rs:315-328,411-425`); QUIC/H3 select TokioRuntime and can bind
UDP separately. Leave `quic_binder` unsupported. Optional persistence and Moka
cache lifecycle require separate proof; `cache_size = 0` still constructs Moka
and does not establish a genuinely allocation-free no-cache path.

### Discriminating product-graph CI cases

Require owned UDP/TCP fixtures for success, NXDOMAIN, silence and UDP-to-TCP
fallback; exact wire limits and limit+1; split length/header/body, consecutive
frames and EOF at each stage; hostile QDCOUNT and combined RR counts before body
allocation; malformed/TXT bounds and spoofed IDs. Assert destination rejection
before materialization and before any socket operation through every route.

Fill the shared 64-task budget with mixed DNS/Swarm work; reject the 65th from a
clone without polling it, permit reentrant rejected-future destruction and observe
owner failure. Separately test queued cancellation before dequeue and after TCP
serialization, pending UDP lookup, pending TCP connect, established exchange,
lookup error/timeout, panic and unavailable runtime. Close with resolver/provider/
submission handles retained: prove task destruction, UDP rebind and TCP closure
on Windows/Linux. Keep the shutdown future owned across observation deadlines;
never turn dropping it into a joined-close claim. Verify enabled protocol/features
in CI so later feature unification cannot silently invalidate the UDP/TCP proof.

## Task 97: prepared resolver locking correction

The root patch selects the exact **hickory-resolver 0.26.3** archive identified
above. Only that package's registry source/checksum is removed from the product
lock; its version, dependency edges and all other package identities remain
unchanged. All resolver consumers use this preparation, not only libp2p DNS.
No runtime provider, protocol configuration, cache policy or public SDK API is
added or changed.

### Semantics established before the change

Existing-connection selection combines the live connection list with the live
encrypted-transport history. `ConnectionPolicy::select_connection` preserves its
protocol policy, encrypted preference, UDP preference, SRTT comparison and tie
order. In particular, a recent encrypted success can prohibit reusing an existing
plaintext connection. A copied boolean or transport-state snapshot taken before
waiting for the connection list would not preserve that decision.

The preparation instead retains two lock futures and polls them together:

1. Poll the connection-list lock.
2. Once acquired, prune failed connections before polling the transport-state
   lock, preserving the original destructor lock scope.
3. If transport state is pending, release the connection guard, reset only its
   lock future, and return Pending with the transport waiter retained.
4. Select only when both locks are acquired in the same Ready poll. Release both
   before any subsequent await.

This uses neither a stale snapshot nor a new version counter. A connection-list
update while transport state is unavailable is observed when both locks are
acquired. A transport-state update while the list is unavailable is also observed.
Neither guard survives a Pending return. Each adapter poll polls each lock future
at most once; mutex waiters provide wakeups, without a retry spin loop.
Cancellation drops the pending lock futures without admitting a new connection.
This removes the original serialization of unrelated list access while waiting
for transport state; it does not promise FIFO scheduling or starvation freedom.

The pending-future argument depends on the actual mutex, not merely absence of a
Rust guard. Both fields use `futures_util::lock::Mutex`, not Tokio Mutex
(`R/name_server.rs:21,55`; `R/name_server_pool.rs:19,492`). Additional archives were
verified against their respective locks and inspected only as DATA:

| Package | Version / graph | Archive SHA256 |
| --- | --- | --- |
| futures-util | 0.3.34 / product | `0d50a92467f8ba5dd6e3ee5d4bd04d73ab2e4e1c44474a0674821dfce14b79bc` |
| futures-util | 0.3.32 / archive fixture | `389ca41296e6190b48053de0321d02a77f32f8a5d2461dd38762c0593805c6d6` |

Their `src/lock/mutex.rs` files are byte-identical (SHA256
`9ec6ca7274dbc53b864152e096ecc41709a9875d0612fc3a1b157ed6faaa004b`). At lines
103-109, `try_lock` sets `IS_LOCKED`; lines 186-193 clear it before notifying a
waiter. `Waiter::wake` at lines 63-67 only records `Woken` and invokes the waker:
there is no permit transfer or reservation. `MutexLockFuture::poll` at lines
338-370 acquires only while polled and immediately returns Ready on success.
Pending retains only a waiter registration. Drop removes it and forwards a
consumed wake when necessary (lines 162-181,374-382). The completed connection
lock future is reset before reuse; the transport future is never polled again
after Ready. The retained transport waiter therefore holds no lock while a new
connection-lock wait is pending. This proof must be revisited if that dependency
implementation changes; it does not generalize to permit-reserving mutexes.

The alternating-contention fixture probes transport `try_lock` both immediately
after notification, before selector repoll, and while the selector waits for the
connection list. Cancellation is exercised with both waiter registrations live.
No copied transport history or version-revalidation assumption is needed. Each
selection can retain one waiter per mutex; outer lookup admission remains a
separate, unimplemented cardinality bound. The primitive itself uses a short
synchronous waiter-registry mutex and explicitly disclaims fairness; neither it
nor this acquisition protocol is described as lock-free.

Selection policy, configured connection order, error/protocol pairs and the
existing unlocked new-connection path are unchanged. Pruning runs immediately
after acquiring the connection list and before polling transport state, as in the
original lock ordering. It can destroy generic cached connection handles: moving
it after secondary-lock acquisition would widen their destructor lock scope.
Reacquiring the list may prune newly failed entries again, without a new allocation
or snapshot. A closed-handle Drop fixture probes transport state with nonblocking
`try_lock` while that state is initially free and asserts pruning did not acquire
it. This does not redesign the original primary-lock destructor scope. Atomic
status/SRTT observations retain their upstream concurrency semantics; this is not
a new atomic snapshot of independently changing connection metrics.

`ActiveRequestCleanup::drop` removes the same key under the same mutex, moves the
removed `SharedLookup` outside an explicit lock scope, and only then destroys it.
Other shared waiters still retain their future/result. No asynchronous destructor,
new task, registry or lock-free claim is introduced. The short synchronous map
mutex still serializes deduplication; foreign-future destruction is outside it.

### Preparation and rollback

`.github/scripts/p2p/discovery/resolver/` holds the exact reversible patch,
preparer, CI fixtures and checks. Production changes are confined to the two
locking sites and their imports, the root unsafe prohibition and a standalone
workspace boundary. The preparer checks archive size/SHA256, package identity,
MIT/Apache license bytes, manifest, archive lock, VCS identity, the entire original
file-hash tree and unique anchors. Verification reverses the patch byte-exactly
and reconstructs the full receipt. Changed recipes, added files, source drift and
receipt drift fail closed. Existing destinations are never overwritten, including
a partially prepared destination after interruption.

Full resolved metadata must select
`target/p2p/resolver/hickory-resolver-0.26.3/Cargo.toml`; registry fallback,
duplicate resolver packages, wrong paths and altered existing lock edges are
rejected. Candidate staging rewrites this patch alongside the existing prepared
signaling packages. Rollback removes only this root patch and restores this exact
registry source/checksum after coordinated graph validation; it requires no data
migration or deletion of user data. Do not remove unrelated prepared overrides.

### CI proof scope, not a local pass

Owned Rust tests are appended inside the actual prepared `name_server` and
`name_server_pool` modules. Held-lock barriers and explicit polling demonstrate
connection-list availability while transport state is pending, the converse,
alternating contention/wakeup registration, cancellation, current-list selection,
policy/order, fresh versus reused connections and preserved errors. Cleanup tests
use a foreign future whose destructor calls `try_lock` and reenters the actual
registry without blocking, including retained shared waiters and error results.
The TLS schedules first allow a snapshot-before-connections implementation to
read transport state while the connection list remains locked, then mutate that
state before releasing the list. Both success and failure transitions must affect
the final selection. Cancellation queues distinct counting-waker survivors behind
the canceled selector and checks their notifications before repoll/completion:
before wake, after wake but before repoll, and with both registrations live after
alternating contention. Uncontended acquisition alone is not a deregistration
witness.

Separate counterfactual fixtures revert only connection acquisition or only
shared-lookup cleanup, leaving the other correction intact. Their receipts identify
the exact production source delta and before/after hashes; controls compare every
other fixture file byte-for-byte. Each fixture runs its corresponding unchanged
discriminating test. CI requires the exact assertion marker and failed-test count,
not merely a nonzero compiler/process result.

CI requires 12 common Rust contracts in the plain/archive and host-product lanes,
14 with the two additional TLS-state contracts, and 13 Python controls. The
cached-handle pruning regression is included in every Rust lane.

The archive lane keeps the unchanged published Cargo.lock (SHA256
`f66318e14be75c418cd2e86705564bd4e6d6cfc6d7ef4ee9456fe91f0105791a`). Its Tokio
1.52.0 and futures-util 0.3.32 differ from product Tokio 1.54.1/futures-util 0.3.34.
The published manifest omits `test_support`; only explicitly enumerated upstream
test modules are disabled in the fixture, never production bodies. This lane is
not an upstream-suite pass. A separate archive-only `tls-ring` feature lane
executes live encrypted-success/failure mutations during contention using fake
connections, not a real TLS handshake; production features are not changed.

The host-product fixture uses the same prepared function bodies and owned tests.
Its generated manifest selects only product-resolved packages, exact versions and
resolved feature unions. Dependency anchors reproduce feature unification from
other product consumers. Verification compares host-filtered package identities,
features and non-root dependency edges, permits only the documented root anchors
and host-condition flattening, and rejects new lock identities/checksums. The
fixture does not inherit upstream dev-dependencies. Receipts distinguish this
host feature-union proof from the archive/TLS lane and preserve both lock files.

Tests and controls are added for GitHub CI, **not run locally**. Source/data
transformation, syntax inspection and standalone formatting do not establish a CI
pass. This correction does not bound lookup cardinality, fix queued DNS exchange
cancellation, establish cache or socket lifecycle, or implement task admission,
wire/header limits or discovery destination policy. P08 acceptance remains open.

### Task 97 scoped CI acceptance

Commit `95bb0fc`, CI `40251607124`: Windows and Linux passed 12 common resolver
contracts, 14 contracts in the additional archive TLS profile, 13 preparation
controls, and the same 12 common contracts with product identities and host feature
unions. Separate one-fault counterfactuals failed their exact assertions:
`CONNECTIONS_HELD_WHILE_WAITING` and `FOREIGN_FUTURE_DROPPED_UNDER_LOCK`.
Compilation or zero selected tests cannot satisfy either control. The product
receipts cover 99 Linux and 103 Windows closure packages; the parent inspected
resolved feature records, source deltas and the unchanged lock identities.
SDK 58-test suites, existing driver proofs and high-PTO cleanup controls also
passed. This accepts the two locking corrections, not DNS provider/wire/cache
ownership or complete Amino discovery. No tests ran locally.

## Task 101: actual Moka and zero-capacity cache boundary

Source-only follow-up. **M** denotes `moka-0.12.16/`; R, N and P retain the
Hickory 0.26.3 aliases above. The Moka archive is 251546 bytes, with product-lock
SHA256 `4293f18e7567a1caf3c584855554377025c65e0aa445344d04171f5ad63d19b9`.
The inspected extracted Moka and resolver files matched their verified archives.
No dependency code or binary was executed.

### Zero capacity does not mean no construction or copies

`R/src/resolver.rs:558-563` constructs `ResponseCache` unconditionally.
`R/src/cache.rs:39-46` constructs Moka and an `Arc<TtlConfig>` even at capacity
zero. Moka still creates shared inner/housekeeper state, zero-capacity channel
objects, a one-segment main map and a 64-segment initializer waiter map
(`M/src/sync/base_cache.rs:152-186,1022-1034`;
`M/src/sync/cache.rs:732-760`; `M/src/sync/value_initializer.rs:49-69`).
The timer wheel initially has empty buckets, not eagerly populated expiry state.

On the ordinary Hickory response-cache path, zero capacity does prevent retained
entries and populated maintenance logs. Disabled reads return before read logging
(`M/src/sync/base_cache.rs:265-280`). Insertion still hashes the key and allocates
`Arc<K>` before its disabled-map check (`M/src/sync/cache.rs:1476-1485`).
Maintenance itself immediately returns at zero capacity
(`M/src/sync/base_cache.rs:1190-1198`). Thus a zero-entry assertion alone cannot
prove suppression of construction or transient cache work.

Hickory creates cache-only data before those checks:

- Positive finalization clamps TTLs, clones the complete Message into Lookup and
  sends the original Message to insertion (`R/src/caching_client.rs:531-544`).
- Error finalization clones the error solely for insertion (`:546-548`).
- Recursive CNAME finalization constructs an alias-cache Message and clones all
  answer/authority/additional records, then returns the original child Lookup
  (`:520-528`).
- `ResponseCache::upsert_clamped_ttl` computes cache-side lifetime and allocates
  an `Arc<Result<Message, NetError>>` before Moka rejects storage
  (`R/src/cache.rs:69-108`).

### Maintenance runs on callers, not background workers

**Moka 0.12.16's sync cache starts no maintenance background threads.** Removal
of those threads is explicit in `M/README.md:95-98`. The concrete housekeeper
contains locks, timestamps and configuration; its maintenance methods call the
cache directly (`M/src/common/concurrent/housekeeper.rs:26-74,105-126`).
The 300 ms interval is an eligibility threshold checked during operations, not
a periodic background task. This does not establish that the whole resolver or
all other dependencies are thread-free.

For positive capacity, Hickory's limit counts responses, not bytes; the default
is 8192 (`R/src/config.rs:532-534,698-700`). Moka's default weight is one.
Insertion precedes policy-log processing, so the capacity is not a hard
pre-retention admission bound. Read/write operation logs each hold 384 entries,
with flush thresholds 64 and interval 300 ms
(`M/src/common/concurrent/constants.rs:1-13`). Full read logs drop observations;
full write logs can retry synchronously with 50-microsecond sleeps
(`M/src/sync/cache.rs:1819-1842`). Do not describe this path as wholly asynchronous
or lock-free. Entry-count limits do not establish byte bounds.

Clones share cache state and TTL configuration; lookup futures can retain them.
Expired entries become unreadable before physical removal. Hickory clear-all is
Moka timestamp invalidation, not immediate reclamation. Final owner destruction
and crossbeam epoch flushing are not an awaited global reclamation barrier.
Returned Lookups and active requests retain their own data independently.

### Minimal forward change and compatibility boundary

Recommended design, **not yet implemented**:

1. Make only ResponseCache's private Moka storage optional. Existing capacity
   zero must take a genuinely lazy branch that never calls the Moka builder;
   eagerly evaluated `then_some(builder.build())` is insufficient. Keep TTL
   configuration available independently. Disabled reads miss; writes/upserts
   return before cache-only lifetime/entry construction; clears are harmless and
   metric entry count is zero. Add at most a crate-private enabled predicate.
2. In CachingClient, preserve positive TTL clamping and valid-until calculation,
   but move the processed Message into Lookup when storage is absent. Return the
   original error without an insertion clone. In the CNAME path return the child
   Lookup before constructing its otherwise-unused alias-cache Message.
3. Keep nonzero behavior and public signatures unchanged. Do not replace
   CachingClient with a raw DnsHandle: special-use names, validation, name/class/
   type checks, CNAME recursion/depth, DNSSEC/Bogus treatment, DO-bit stripping,
   record sections/order and per-type/NS TTL rules remain required.

Negative min/max TTL affects cache lifetime; it must not start rewriting the
first returned negative error. The CNAME child Lookup's query, ordering and
deadline must not be rewritten as part of copy removal. This is not a claim of
zero allocations: parser output, Lookup, CNAME work, TTL configuration and other
resolver state still allocate.

ResponseCache is publicly exported and also used by recursor construction,
reads, writes and ghost-domain upserts (`R/src/lib.rs:206`;
`R/src/recursor/handle.rs:131,174,426,511-515,555-557,610,686-689`;
`R/src/recursor/mod.rs:419,457,539-540`). Preserve those method signatures and
positive-capacity semantics. A forward-resolver copy fix does not automatically
remove recursor callers' clones.

Extend the same-version prepared resolver while retaining Task 97 byte-exactly.
Rollback removes only the new cache transformations and related fixture changes;
no persistent cache-data migration is required. Do not remove the resolver root
patch or undo its locking corrections to roll back this leaf.

### Required discriminating CI cases

- Observe the actual private Moka-construction boundary: zero capacity makes no
  cache; positive capacity constructs once; cloning does not reconstruct it.
  Zero entry count alone passes against the unfixed implementation.
- Two distinct sequential same-query responses: zero capacity calls the client
  twice and returns both in order; positive capacity returns a cached first
  result. Include positive, NXDOMAIN/NODATA and noncacheable errors.
- For copy removal, prove ownership transfer of the real section-vector buffers
  at positive finalization, and suppression of error/alias cache-only work with
  scoped fixture probes. Counterfactual original branches must fail those exact
  assertions, not process RSS, timing or thread-count heuristics.
- Preserve A/AAAA/TXT, section ordering, zero/min/max/per-type TTL and NS deadline
  rules, CNAME same/subsequent-response behavior, both preserve-intermediates
  settings, recursion exhaustion, wrong name/class/type and special-use errors.
  Include a DNSSEC feature lane for Bogus, negative TTL and DO-bit semantics.
- Cancel unpolled/pending lookups and drop resolver clones while another remains;
  returned Lookups stay valid independently. These are not socket/task-close
  proofs. Protect nonzero cache hit/expiry/clear/metrics/clone sharing and relevant
  recursor compilation/upsert contracts with product identity/feature receipts.

Disabling this response cache does not disable DNSSEC's separate validation cache
(`N/src/dnssec/mod.rs:101,1576-1584`), bound active lookup cardinality or wire/parser
allocations, or establish provider/task/socket ownership. Those obligations and
complete P08 readiness remain open.

## Task 102: prepared zero-capacity response-cache path

The same-version resolver preparation now implements Task 101's optional private
Moka storage. `cache_size = 0` takes a lazy constructor branch; reads miss, writes
and ghost-domain upserts return before cache-only TTL/entry work, clear operations
are harmless, and the metrics entry count is zero. The separate `Arc<TtlConfig>`
remains available. Positive-capacity storage and public method signatures remain.

`CachingClient` still performs answer validation, DNSSEC verdict handling,
DO-bit stripping, CNAME processing and TTL clamping. Its zero-capacity positive
path moves the processed Message into Lookup, its error path avoids the insertion
clone, and its recursive-CNAME path returns the existing child Lookup before
building the unused alias-cache Message. Initial negative-error contents and the
child query, record order and deadline are not rewritten. These changes remove
specific cache-only work, not all parser/Lookup allocations or every DNS cache.
Recursor caller-side clones and DNSSEC's separate validation cache are unchanged.

### Preparation and isolated rollback

`resolver/cache_patch.py` is a separate reversible recipe with pinned original
`src/cache.rs` and `src/caching_client.rs` hashes. The existing original-tree,
archive, license, package, recipe and receipt checks still apply. Eighteen upstream
unit-test accesses to the now-optional private storage are adapted explicitly and
reversed exactly; their assertions are not removed. The fixture's pre-existing
upstream-test exclusions remain explicit because the published package omits
`test_support`.

The accepted Task 97 production transformations remain byte-identical. Its owned
`connections.rs` and `cleanup.rs` fixtures move byte-for-byte into `resolver/tests/`
to preserve the seven-item directory limit. Rollback of this leaf reverses only
`cache_patch.py` and its associated fixture/recipe additions, retaining the
prepared resolver root override and Task 97 locking corrections. No dependency
version, product lock edge, public configuration mode or Moka source is changed.

### Added CI contracts, not a local runtime result

The cache fixture has 23 common Rust contracts, four additional DNSSEC contracts,
and one additional metrics contract. The archive feature lane enables
`dnssec-ring,metrics,recursor,serde`; the product lane retains exactly the verified
host product feature union. The shared ghost-domain upsert method is exercised
with controlled request timestamps, while the recursor feature is compiled; this
is not a recursor-network or cryptographic-signature-validation acceptance claim.
Six additional Python preparation controls supplement, rather than replace, the
existing 13. The 12 common/14 TLS locking contracts and their two counterfactuals
remain selected independently.

Contracts cover actual Moka construction and resolver-option forwarding, clone
sharing, repeated distinct positive and negative responses, noncacheable errors,
nonempty section-buffer transfer, initial error preservation, alias-message work,
TTL and section ordering, per-type/NS rules, CNAME same/later-response behavior,
recursion exhaustion, special-use and invalid answers, DNSSEC verdicts and DO-bit
semantics, cancellation and retained returned Lookups. No sleeps, process RSS or
thread-count heuristics are used. Deadline checks enclose the call's timestamp;
cache expiration checks supply explicit request times.

Five separate cache counterfactuals restore only constructor, positive-copy,
error-copy, alias-copy or disabled-write work. Their receipts contain the exact
selected source file and prepared/counterfactual hashes; other source files and
locking fixes are unchanged. The constructor counterfactual retains the optional
field type but always constructs `Some(Moka)`. The disabled-write counterfactual
uses a local zero-capacity Moka fallback to restore write-side work without
changing construction/read behavior. The other three restore the corresponding
original copy behavior. Fixture-only thread-local observations are reversible
statement/expression instrumentation, not replacement production bodies.
Positive-capacity preconditions prove each work probe is live. CI requires the
specific selected test, assertion marker and exactly one failed test; compilation
failure, setup failure or zero selected tests is not evidence.

Each cache counterfactual uses its own initially absent target directory. CI
rejects an existing directory and requires verbose Cargo logs identifying both
compilation of the selected counterfactual resolver path and execution of its own
test binary. This prevents copied same-name/version fixture roots from reusing a
fixed binary through a shared target directory. The source-delta receipt remains
necessary but is not a compiled-artifact witness by itself. Separate targets cost
additional dependency compilation and disk space; isolation takes precedence over
cache reuse and does not depend on modification timestamps.

These contracts and controls are **added for GitHub CI, not run locally**. Local
source-data preparation, syntax inspection and formatting do not establish a
runtime pass. Moka 0.12.16 has no maintenance background worker to register or join.
Provider/socket/task lifecycle, wire/parser limits, active-query admission and
complete P08 acceptance remain open.
