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
