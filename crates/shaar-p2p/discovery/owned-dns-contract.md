# Carrier-owned DNS and discovery integration contract

Task 104 source/API decision, following accepted resolver locking and zero-capacity
cache prerequisites. This is an implementation contract, not an implemented DNS
provider, Amino discovery result, resource proof or public-network smoke result.

## Compatibility and the necessary additive input

The current synchronous `Carrier::bind` builds raw TCP, Noise and Yamux and accepts
numeric application/relay destinations. Keep it unchanged. Do not silently load
system resolver configuration, change application authorization or start bootstrap.

Add a validated, in-memory discovery input and a configured constructor:

```rust
pub struct DiscoveryConfig {
    // Private validated seed and numeric nameserver data.
}

impl DiscoveryConfig {
    pub fn new(
        seeds: Vec<(PeerId, Multiaddr)>,
        nameservers: Vec<SocketAddr>,
    ) -> io::Result<Self>;
}

impl Carrier {
    pub fn bind_with_discovery(
        key: Keypair,
        bind: SocketAddr,
        allowed: Vec<PeerId>,
        discovery: DiscoveryConfig,
    ) -> io::Result<(Self, CarrierHandle, mpsc::Receiver<Received>)>;
}
```

The private constructor implementation can accept `Option<DiscoveryConfig>`.
Construction validates and prepares ownership; it performs no DNS query or
bootstrap. The eventual bounded `discover_relay` command returns an authenticated,
currently valid `RelayLease`, not merely a DNS answer, connection or advertisement.
No additional public low-level SDK binding helper is needed just to duplicate
forwarding. A later additive SignaledEndpoint constructor uses the existing
identity conversion, coordinator, factory and pump.

Validation is pure and runs before listener/socket creation:

- One to four pinned seed descriptors, counted before deduplication.
- Supported bounded TCP/DNS seed grammar; at most 256 encoded bytes per address.
- Canonical absolute resolver names; consistent expected-peer suffixes; no circuit
  seed addresses or unsupported transport components.
- One to four numeric nameservers, counted before deduplication; nonzero ports
  and usable destinations. Explicit private/loopback resolvers and custom ports
  remain supported; their trust does not transfer to DNS answers.
- Cross-check local, seed and application identities before allocating network
  resources. Infrastructure must not become an application peer.

Do not expose Hickory types, resource-ceiling knobs, unsafe-address flags or a
protocol-selection mode through this input. Applications that want OS defaults
load and normalize them in their startup/configuration layer before entering the
async runtime. The carrier performs no blocking file/registry/hosts loading or
unowned `spawn_blocking` fallback. ktav loading stays outside SDK networking.

## Construction and ownership

For the configured path, create the existing OwnedExecutor, one private DNS
lifetime gate and one resolver/provider pair before constructing Swarm/listener.
Use Resolver::builder_with_config, supplied numeric nameservers with UDP/TCP
connection configurations, cache_size zero, hosts disabled, no search list,
bounded attempts/concurrency and no opportunistic encrypted protocols/persistence.
Never use Resolver::builder or the default provider's spawning handle here.

The native composition is:

```text
FreshPorts(TCP) -> numeric role guard -> prepared DNS/owned resolver
               -> Noise -> Yamux -> complete-dial deadline
```

Keep the existing relay composition. DNS and Swarm share the same total 64-task
executor; there is no second pool. Limit admitted resolver-call futures to four,
with immediate rejection rather than a waiting queue. Keep raw providers,
resolvers, sockets and lookups private.

UDP sockets can belong to caller-polled lookup futures. TCP can connect before
background-task admission. Both kinds of work must remain inside carrier-owned
lookup/dial futures, not merely in the executor's task count. Completion of a
background `()` future is not lookup success.

The irreversible I/O gate has a defined admission/closure synchronization point.
Check it at lookup/spawn/socket admission and when previously created but unpolled
operations first run. Previously admitted work may still exist during closure;
only joined shutdown proves its destruction. Cancellation wakes registered
waiters. No await, I/O polling, rejected-future or foreign-resource destruction
occurs under a gate guard. Do not label a channel/atomic automatically lock-free.

Carrier close order: close commands/discovery admission, close the DNS gate and
wake cancellation, drop owned lookup/dial/Core/Swarm/resolver state, then await
OwnedExecutor::shutdown. Retained capabilities cannot restart I/O. Dropped startup
or close remains abort-only. SDK still closes native QUIC before signaling.

## Wire and destination boundary

Adopt a fixed private UDP/TCP DNS profile: 12-4096 message bytes excluding the TCP
length prefix, at most one question and 64 combined answer/authority/additional
records, using widened count arithmetic and upstream Header/BinDecoder parsing.

UDP validates before exposing bytes to Hickory. Detect oversized/truncated input
on both OSes; unrelated invalid packets must not become a spoofing-triggered fatal
lookup error. Bound discard work per poll and arrange correct wakeups. TCP stages
the length and fixed header before releasing the complete prefix to Hickory, so
its body allocation cannot precede validation. Preserve partial reads, Pending,
empty buffers, EOF and consecutive frames. Decoded TXT expansion bounds are not
pre-TXT-allocation guarantees.

Roles are internal: application peers and explicit relays retain their existing
numeric/private/loopback behavior; discovery infrastructure/discovered relays use
the strict discovery policy; DNS I/O targets exactly the configured nameserver.
UDP checks every send target, not only the bind argument.

Swarm appends/checks the expected peer suffix before Transport::dial. Use that
context and still authenticate through Noise; the suffix is not authority.
Introduce only the smallest defaulted prepared resolver-trait validation hook
before Encoded::address(), then repeat numeric policy immediately above TCP.
Cover direct numeric, DNS/DNS4/DNS6, DNSADDR TXT, inherited prefix/suffix and nested
resolution. Use upstream multiaddr decoding, not another protocol parser.

## Request-driven discovery owner

Use the existing bounded command/result channel, one active Kademlia query plus
charged cleanup, one 32-peer ledger including failures and seeds, four addresses
per peer, four established discovery connections, existing eight-pending total
and a 30-second epoch. Disable periodic and insertion-triggered automatic
bootstrap. Per-iterator Kademlia retention is not a global contact budget.

Each dial has one absolute deadline, min(admitted_at + 10 seconds, epoch_deadline),
covering queue time, all address alternatives, DNS recursion/fallback and
authentication. Do not reset it between attempts. Use one address attempt at a
time per discovery peer. DNS wrapping raw TCP can finish before later Noise
failure; do not promise exhaustive authenticated retries across DNS alternatives.

Sanitize the composed behaviour's aggregate addresses, including child-generated
ones. An admission child returning an empty vector does not sanitize another
child. Keep Admission::allows strictly application-only for packet authorization,
Received delivery, link snapshots and bridge address minting. Exact current DHT
and HOP support are required; STOP, a referral or Identify syntax is insufficient.
Relay handoff retains expected peer, numeric provenance, expiry and generation.

Cancellation marks the operation generation canceled, stops admission, finishes
its query and cancels owned lookup/dial futures. Suppress late publication; retain
charges until actual destruction or terminal events. Independently active
reservations remain intact. Already serialized DNS TCP output cannot be unsent.

## Delivery sequence and proof obligations

1. Validated inputs, compatibility-preserving constructor refactor, private DNS
   lifetime/runtime/lookup admission and real private transport fixtures. This
   foundation must not claim that Amino discovery is implemented.
2. Wire wrappers and pre-materialization/numeric role policy.
3. Composed behaviour, owner command and bounded discovery state.
4. Configured SDK forwarding through the existing retained coordinator.

A direct pinned hickory-resolver 0.26.3 dependency adds one explicit edge to an
already resolved package; do not migrate versions or widen libp2p-DNS reexports.
Verify graph/feature changes. Use owned DNS/TCP/DHT/relay fixtures, no public
availability dependency. Invalid config must cause no network work; prove legacy
numeric behavior, custom nameserver ports, wire/policy rejection before allocation
or connect, wrong-peer denial, shared task/lookup limits, cancellation/late-result
charges, one overall deadline and retained-handle joined socket release.

Local fixtures may use a private test-only exact-endpoint allowance, never a public
permissive policy. The same response must also be rejected under the unchanged
production destination policy. n0, TUN, root/router routes and Ygg integration stay
outside this contract. No further dependency preflight is required to begin the
first implementation unit.
