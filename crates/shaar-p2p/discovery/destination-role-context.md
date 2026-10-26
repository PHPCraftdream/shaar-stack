# Destination roles and dial authority

Task 110 design against `ad7a021`. This is a private implementation contract and
source investigation, not an implemented policy or runtime acceptance. It extends
[the owned DNS contract](owned-dns-contract.md), without reopening its constructor,
resolver ownership, prepared expansion, or wire-envelope decisions. Task 109 owns
wire/parser/socket wrappers; this document does not prescribe edits to those files.

## 1. Decision

Use **one bounded, carrier-owned role/attempt registry**, read by both the owned
resolver's borrowed expansion predicate and the numeric guard immediately above
`FreshPorts(TCP)`. An immutable constructor context is sufficient for application
membership and nameserver endpoints, but **not** for explicit relays, discovered
peers, expiry, canceled attempts, or discovered-relay handoff.

A terminal peer suffix selects an already registered context. It never registers
a peer, changes a role, proves authentication, or grants application authority.
Missing, ambiguous, foreign, expired, canceled, and unregistered contexts fail
closed. Do not use “unknown peer means application” or “known relay means exempt.”

Keep legacy `Carrier::bind` on its existing raw transport. In the configured
carrier, application and explicitly requested relay numeric destinations keep
their existing private/loopback compatibility. Discovery infrastructure, including
pinned seeds and discovered relays, always uses strict discovery destination
policy, even when its input was numeric and no resolver was invoked. DNS-server
I/O remains a separate exact-`SocketAddr` capability, never a PeerId role.

Do not remove the current outer `NumericOnly` safety barrier until the replacement
outer context admission, expansion predicate, final numeric guard, and composed
behaviour admission all exist. Installing only the resolver predicate is unsafe:
direct numeric input bypasses it, and initial DNS input needs authorization before
its first query.

## 2. Source map and current authority

Paths in this section are relative to `crates/shaar-p2p/`.

| Owner / location | Observed contract and integration consequence |
| --- | --- |
| `src/carrier/mod.rs:14-18,51-59,80-87,142-164` | 16 application peers, 8 relay targets, 8 pending connections, command/request queues of 32. Public commands carry `SocketAddr` or `RelayAddr`, not arbitrary DNS addresses. `connect` and `connect_via` explicitly permit admitted work to finish after waiter cancellation. Do not silently change that contract. |
| `src/carrier/admission.rs:20-84,126-168` | Application membership is immutable, sorted, and separate from the mutable relay set. `allows` is application-only; `permits` admits application or relay connections. Infrastructure inbound connections are rejected. Add infrastructure connection admission without widening `allows`. |
| `src/carrier/driver.rs:101-159` | Configured path currently builds `NumericOnly(DNS(FreshPorts(TCP)))`, then Noise, Yamux and a 10-second timeout. Raw bind has no DNS wrapper. `relay::transport` combines the resulting native branch with the circuit branch. |
| `src/discovery/mod.rs:18-104` | Configuration validates 1–4 seeds and 1–4 numeric nameservers before deduplication. State currently contains only config and DNS lifetime: no query, discovery ledger, generation, or discovery command exists. Seeds are reserved against APP overlap, not admitted for outbound infrastructure dials yet. |
| `src/discovery/mod.rs:119-181` | Seed grammar accepts numeric, DNS/DNS4/DNS6 plus TCP, or DNSADDR, with optional consistent terminal PeerId. `usable` is not a public-only discovery classifier. Private numeric seeds currently pass, explicitly protected by `src/discovery/tests.rs:66-70`. |
| `src/carrier/driver.rs:405-489` | `Connect` checks APP membership and numeric usability, then constructs expected-peer `DialOpts`. Its `Core.pending` insertion occurs **after** `swarm.dial`; a transport context cannot wait for that insertion. |
| `src/carrier/relay/controller.rs:4-33,35-108,147-218` | `authorize_relay` creates a pinned target and admission role before `listen_on`/circuit dial. `Reserve` and `ConnectVia` are local explicit authority today. There is no discovered-origin field. Failed starts can leave a bounded target for history cleanup; that must not leave a live dial permit. |
| `src/carrier/relay/mod.rs:42-108,140-168` | `RelayAddr` contains only peer and numeric endpoint. `RelayLease` adds expiry, reservation generation and control connection. `Route::Relayed` has a separate local route generation; inbound relay attribution intentionally remains `None`. None of these generations is currently a discovery/dial epoch. |
| `src/dns/mod.rs:30-35,108-131` | `OwnedResolver` is cloned by DNS; it currently uses the default-true prepared `permits_address`. It needs a shared read capability, not an independently captured immutable relay list. |
| `src/dns/runtime.rs:55-65,100-182`; `src/dns/sockets.rs:44-56` | DNS provider admits configured numeric nameservers; UDP sends must equal that socket's configured server, including port. Local resolver support is intentional and does not allow local addresses in discovery answers. These are Task 109 integration boundaries, not role-registry members. |

APP separation is load-bearing beyond connection admission:

- `driver.rs:242-275,362-403,580-615` filters packet sends, received signaling and
  link publication through application authorization and current connection/route.
- `carrier/mod.rs:128-139` checks received records against the current link snapshot.
- `src/bridge/driver.rs:91-115` admits a received record only through that current
  link; `src/bridge/mod.rs:74-89` mints/resolves addresses from those observations.

A seed, DHT peer, HOP advertisement, DNS answer, or relay control connection must
never enter `application_connections`, `Link`, `Received` application delivery, or
bridge source minting. A circuit **to an independently allowed APP peer** may
produce its ordinary APP link; its infrastructure hop does not become that peer.
Noq custom-APP denial and signaling-only behavior remain unchanged.

## 3. Actual suffix and transport path

The following sources were inspected as checksum-verified archive DATA. Prepared
recipes were inspected separately; no downloaded code was executed. Archive names
below are portable citations, not required checkout locations.

| Source | Exact bytes identified by SHA256 |
| --- | --- |
| `libp2p-swarm-0.48.0` | `57ccbe1baeaef036ffde4b265871e11c64d29464036bba635378f356bcdca854` |
| `libp2p-relay-0.22.0` | `e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a` |
| `libp2p-dns-0.45.0` | `18694695e98ff9ce26ee245fdede7cd0b4186cb793b25da3258d9c053400a291` |
| `libp2p-core-0.44.0` | `c2b1a55b9d5e51389db344a609d8c2ff35eabd870a8400067d66d2b1b6f8df68` |
| `libp2p-tcp-0.45.0` | `e753c9e69fec40b3687e38a25e34fc5dfa9c6d0e29614c9b4d28ee7dc8c32a7a` |
| `multiaddr-0.19.1` | `fd707c05eadfb37577f01cbec206726feeecf0b9edea259aee6fc9bc541ee253` |

### Swarm is the identity-suffix boundary, not a role channel

`libp2p-swarm/src/lib.rs:458-554` calls the composed behaviour's pending-outbound
callback, optionally extends the supplied addresses, deduplicates them, then calls
`address.with_p2p(expected)` before each transport dial. `multiaddr/src/lib.rs:139-144`
accepts an identical terminal peer, rejects a different terminal peer, or appends
one. It does **not** validate every interior component.

`libp2p-core/src/transport.rs:74-83` passes only endpoint direction and port-use
policy in transport `DialOpts`: **no ConnectionId, application role, query ID, or
attempt generation reaches the transport this way**. Peer identity must therefore
index private state admitted earlier by the composed behaviour. Endpoint direction
is not the destination role.

A wrapper around the composed behaviour must validate both the explicit address
slice and the complete address vector returned by its children. Reject the whole
request on invalid explicit addresses; filter/bound returned hints before returning
them. An admission child returning `Ok(Vec::new())` cannot remove another child's
addresses. Validate suffixes and byte lengths **including the suffix Swarm will
append**, before creating the pending context. A currently accepted 256-byte
suffixless seed can become overbudget after qualification; do not defer that check
to a later DNS allocation failure.

### Relay rewrites the context to its own hop

`relay/mod.rs:110-130` tries the circuit transport before the native transport.
`RelayAddr::prefix` produces:

```text
/ipX/relay-address/tcp/port/p2p/RELAY/p2p-circuit
```

A circuit dial adds `/p2p/APP`. In
`libp2p-relay/src/priv_client/transport.rs:182-224,265-312`, parsing separates
`relay_peer_id`, `relay_addr`, and destination peer. The relay PeerId is removed
from `relay_addr`; the circuit and destination are not passed to native TCP.

`libp2p-relay/src/priv_client.rs:340-434` handles both `ListenReq` and `DialReq`:
if no direct relay control connection exists, it emits new
`DialOpts::peer_id(RELAY).addresses([relay_addr]).extend_addresses_through_behaviour()`.
That is a **second Swarm connection ID**. Swarm appends `/p2p/RELAY`, so the native
role is the relay's, not APP's. If a control connection already exists, the child
sends a handler command instead: there is no new native transport check. Therefore
role revocation must also prevent control-connection reuse and stop affected
listener/handler work; a TCP-only fix cannot establish revocation.

The prepared `.github/scripts/p2p/prepare.py:69-110` adds control-connection event
context and rejects canceled relay transport requests. It does not add dial role
metadata or preserve an outer APP attempt ID on the relay-hop dial. The swarm
preparation changes its manifest, not native suffix/dial logic (`:141-165`).

### DNS retains the suffix but loses the resolved endpoint at Swarm level

`libp2p-dns/src/lib.rs:204-338` clones the resolver into its dial future, replaces
DNS components, matches DNSADDR suffixes, then forwards fully numeric addresses to
its inner transport. The prepared `discovery/dns/{patch.py,bounds.rs}` calls
`permits_address` on the complete fixed-buffer encoding before `Encoded::address`.
Direct numeric inputs do not invoke this expansion hook.

Do not infer the selected numeric endpoint from `SwarmEvent::ConnectionEstablished`:
Swarm wraps the outer address before awaiting transport (`lib.rs:519-544`), and the
pool constructs the endpoint from that address (`connection/pool.rs:667-680`). DNS
returns a stream, not its selected numeric Multiaddr. The discovery-to-relay handoff
therefore needs a **private numeric-success witness** from the final numeric guard,
associated with the exact pending attempt; see section 5. Re-resolving the hostname
or parsing the original Swarm endpoint is not equivalent provenance.

### The final guard must cover socket creation and first polling

`libp2p-tcp/src/lib.rs:359-419` creates a socket synchronously inside `dial`, but calls
native `connect` in the returned future. Check immediately before forwarding
`dial`, and again before polling that future, including its first poll. A future
created before revocation must not first connect after revocation without another
admission check. `FreshPorts` prevents the listener-port-reuse fallback.

TCP's parser (`:682-705`) works backward and can ignore outer prefixes and multiple
peer components. Do not rely on TCP rejecting malicious composed prefixes. The
role guard accepts only the complete narrow grammar below, with no ignored bytes.

## 4. Roles and destination grammar

Private role classification, not a new public mode:

| Role | Authority source | Destinations / lifetime |
| --- | --- | --- |
| Application | Constructor allowlist plus admitted local connection intent | Existing numeric TCP usability and private/loopback support; no discovery-derived authorization or DNS input. |
| Explicit relay | Local `Reserve` / `ConnectVia` with an explicitly constructed `RelayAddr` | Exactly the pinned numeric endpoint, existing private/loopback support; bounded target and operation lifecycle. |
| Discovery infrastructure | Pinned seed descriptor, or bounded owner admission of a referral during its live discovery operation | Strict numeric policy; supported bounded DNS roots and expansions; no APP overlap, local identity, unsolicited inbound, or uncharged automatic work. |
| Discovered relay | Owner-validated infrastructure handoff with numeric witness and current capability/control context | Strict numeric policy survives conversion to relay operations and snapshots; independent reservation ownership can outlive discovery query cancellation. |
| DNS nameserver | Validated constructor endpoint | Exactly configured IP and port for DNS I/O only; no PeerId/role promotion. |

One peer cannot simultaneously receive permissive explicit-relay and strict
infrastructure authority. Keep seed identity reservations for the carrier lifetime.
Reject an explicit relay request conflicting with a live/retiring discovery identity,
and reject discovery referrals overlapping an explicit target or APP identity.
Do not silently select the most permissive role. After non-seed state fully drains
and expires, a genuinely new local explicit request may create a new explicit
operation; remote metadata cannot perform that transition.

### Borrowed complete-address validation

Use `libp2p::multiaddr::Protocol::from_bytes` repeatedly over the borrowed slice
(`multiaddr/src/protocol.rs:291-389`); consume all bytes and match a small sequence.
It borrows DNS text and parses PeerId through upstream code. Do not allocate a
`Multiaddr`/`Vec`/formatted string to inspect the expansion, and do not write a
varint, protocol-number, multihash, or IP-text parser. Upstream malformed-input
errors can allocate; this is a no-owned-address guarantee, not a universal
zero-allocation claim.

At the native/DNS boundaries require exactly one expected terminal `/p2p/PEER`:

- Numeric: `/ip4/IP/tcp/N/p2p/PEER` or `/ip6/IP/tcp/N/p2p/PEER`.
- Unresolved infrastructure: `/dns[4|6]/absolute-name./tcp/N/p2p/PEER`, or
  `/dnsaddr/absolute-name./p2p/PEER` (plain `/dns/` is supported too).
- Nonzero TCP port, at most 256 encoded bytes, and at most three components.
  DNSADDR has two components. Intermediate DNSADDR-to-DNSADDR or DNSADDR-to-DNS
  candidates obey the same rules; nested resolution is not multiple transport
  prefixes in a single candidate.
- Reject circuits here, repeated IP/TCP/P2p components, interior peers, arbitrary
  inherited prefixes, unsupported transports, zone components, and trailing bytes.
  The composed behaviour separately permits only the existing pinned circuit
  shape for an APP destination and a registered relay hop.

Constructor/owner validation normalizes root names with `absolute_name`. At the
borrowed expansion boundary, enforce the same bounded absolute-ASCII name contract
without creating an owned Multiaddr. Reuse Hickory's name validation where needed;
its bounded name allocation is distinct from forbidden address materialization.
Do not call `to_string` on every candidate or claim the name validator is free.
A name accepted syntactically still cannot authorize an IP or PeerId.

### Strict IP scope: existing requirement versus decision still needed

`README.md` sections 4, 5 and 9 require rejecting private/special discovery
endpoints and checking before TCP. `dns-ownership.md:294-307` and
`owned-dns-contract.md:115-125` explicitly exempt existing APP/explicit-relay
numeric behavior, not discovery. The general threat model establishes untrusted
DHT/relay metadata and bounded admission, but does **not** enumerate a complete
IP special-use table. Current `usable` is not that table.

Implement one private, deterministic `discovery_ip_allowed(IpAddr)` used by seed
admission, referral/Identify retention, the expansion predicate, and final numeric
connect admission. Required rejection classes are unspecified, loopback, private
IPv4/ULA, link-local, multicast, broadcast, and IPv4-mapped IPv6. Never classify a
mapped private address as globally usable IPv6. Reject IPv6 scope/zone input at
its typed input boundary; Multiaddr IP6 itself has no SocketAddr scope field.

**Concrete remaining policy decision, before enabling discovery:** pin the exact
special-use prefix table and boundary tests. Recommended conservative first profile:
exclude IPv4 `0/8`, RFC1918, `100.64/10`, `127/8`, `169.254/16`, special-purpose
`192.0.0/24`, documentation nets, `192.88.99/24`, benchmarking `198.18/15`, and
`224/4` plus `240/4`; for IPv6 admit only reviewed global-unicast space and exclude
special-purpose, documentation, benchmarking, transition/translation and reserved
subranges, including Teredo/6to4. Do not implement “not private” as “public,” or
assert this prose is an exhaustive IANA table. Decide and document exceptions
(such as globally reachable special-purpose anycasts) explicitly; no public
unsafe-address switch or new dependency is needed. Pin the reviewed table in the
private implementation/tests rather than depend on changing platform routes.
This is address-scope filtering, not proof of reachability or protection against
an administrator routing a globally numbered address into an internal network.

**Constructor compatibility decision:** recommend rejecting strict-policy-invalid
numeric seeds before listener creation. This intentionally tightens the foundation's
private-seed constructor tests, not APP, explicit-relay, or nameserver behavior.
If config remains a syntax-only descriptor instead, reject those seeds at owner
admission before DNS/materialization/dial and document that distinction. Do not
report the present constructor as already enforcing the strict policy. In either
choice, the final numeric guard is mandatory and identical.

## 5. Minimal private state and ownership

Names below are implementation sketches, not public signatures or a new trait
hierarchy. Use existing standard-library/Tokio facilities and existing libp2p traits.

- `DestinationRoles`: one shared read handle and an owner-only write handle.
  Immutable APP IDs remain a sorted bounded slice. Mutable entries represent
  relay/discovery identities, origin, current eligibility, owner generation and
  endpoint constraint. DNS nameservers stay in the existing provider.
- `DestinationRole`: `Application`, `ExplicitRelay`, `Discovery`, `DiscoveredRelay`.
  A role is never inferred from DNS output or a protocol advertisement.
- `AttemptKey`: expected peer, Swarm `ConnectionId`, and checked monotonic local
  serial; discovery attempts additionally retain their discovery epoch in owner
  state. Do not reuse reservation or route generations for this purpose.
- `Attempt`: immutable key/role/endpoint constraint/absolute deadline; revocable
  state, terminal-observed flag, and outstanding native-root-future count. A bounded
  numeric-success slot holds `Option<SocketAddr>` for that key. Cancellation is
  monotonic; no flag is reset to revive an old token.
- `AttemptLease`: internal token retained by the complete native dial future from
  outer admission through DNS, TCP, Noise and Yamux. Destruction releases its live
  future charge, including unpolled futures. Inner numeric futures keep the same
  attempt alive while they can still publish a numeric-success witness.
- `RelayOrigin`: explicit or discovered provenance. Store it in `Target` and
  `Record`; preserve a private origin marker in a discovered `RelayAddr` returned
  through `RelayLease::relay()`. Public `RelayAddr::new` still creates explicit
  input. A marker is not a transferable capability: stale or foreign discovered
  values must match current local target/record provenance before reuse.

Registration is transactional: establish trusted intent, validate identity/grammar/
budget, admit the aggregate pending request, then publish the attempt **before**
Swarm can invoke transport. Roll back a failed registration without leaving any
active permit. Existing `Core.pending` replies can still be inserted after `dial`,
but are not the transport authority store. Behaviour-generated relay dials register
in the composed pending callback using the existing pinned target and its live
reservation/circuit intent, not the child's supplied suffix as authority.

### Why the registry needs a one-pending-attempt-per-peer rule

The prepared resolver hook receives bytes, not an attempt ID; core transport
options do not contain one either. Choose the narrow implementation: **at most one
pending native attempt per peer**, and do not replace/rearm that peer's attempt
until its terminal event has been reconciled and all its native future leases are
destroyed. Reject duplicate pending attempts instead of letting old DNS work read a
successor's more permissive context. Keep canceled entries charged as tombstones.
A terminal event alone is not a future-destruction witness.

For discovery, give Swarm one selected root address at a time. The four retained
hints are alternatives for subsequent charged attempts, not four parallel DNS
roots. The existing DNS wrapper may try its bounded numeric expansions sequentially.
An authenticated failure after TCP success does not restart DNS alternatives under
a fresh deadline. APP/explicit-relay commands already supply a single root.

An outer private native-context wrapper replaces `NumericOnly` and captures the
current attempt lease before calling the complete native upgraded transport. It
checks initial address/role authorization before DNS can run and retains the lease
until that entire future is dropped. The resolver hook and numeric guard consult
the same still-current peer entry. The numeric guard captures the exact key, not
merely a peer lookup to repeat later, and rechecks key/revocation/deadline before
forwarding TCP `dial` and before its future polls. Thus suffix-only lookup cannot
silently retarget an old future to a replacement generation.

On numeric TCP success, the guard records the selected numeric endpoint for that
exact key. Only a matching authenticated `ConnectionEstablished` can promote it to
a discovery address hint or relay handoff input. Wrong-peer, canceled, failed Noise,
and stale-generation outcomes discard it. Do not register an endpoint by observing
a TCP attempt alone. The witness requires no second address cache and no DNS TTL
claim. Preserve it in the owner ledger before retiring the attempt.

### Discovered relay handoff without authority laundering

The discovery owner creates a private handoff only after checking current peer,
connection generation, numeric-success provenance, strict IP/grammar, hint freshness,
and exact HOP eligibility. The handoff creates a relay target with discovered
origin and an independent reservation operation generation. It is not implemented
by calling the existing explicit `reserve_relay(address, reply)` unannotated.

The reservation still requires the current authenticated control connection,
future validated lease expiry, and listener advertisement. An active reservation
may retain its discovered role after the query epoch is canceled; transfer ownership
before releasing query charges. Query cancellation cannot revoke an independently
owned reservation. Conversely, a stale handoff cannot create a new reservation.
A fresh Identify update withdrawing HOP removes eligibility for new attempts;
conservative recommendation: stop affected reservation work rather than permitting
renewal under withdrawn capability. A change must never upgrade discovered origin
to explicit origin. Keep strict policy even when the public lease is copied and
its `relay()` value later reaches `connect_via`.

Retaining provenance only in an evictable peer map is insufficient: after eviction,
a copied discovered `RelayAddr` otherwise looks exactly like a new explicit input.
The private marker closes that handoff gap; current-local lookup still decides
whether it is usable. A user deliberately reconstructing an explicit address with
`RelayAddr::new` is a new local request, not remote authority; reject conflicts
with currently reserved discovery identities as above.

### Synchronization and bounds

The sole owner writes role/attempt state, but libp2p executor tasks poll DNS/native
dial futures concurrently. `&mut Core` alone cannot serve the synchronous resolver
predicate. Use one short `std::sync::Mutex` around a capacity-checked indexed
registry, or an equivalently justified existing primitive; no new lock-free
snapshot dependency is warranted. An immutable snapshot without revocation would
retain stale authority. Do not claim the mutex design is lock-free.

Parse borrowed bytes outside the registry guard. Under the guard perform only
bounded lookup, comparisons, numeric field updates, and token accounting. Move
removed owned values out, unlock, then destroy them. Release every role-registry
guard before transport `dial`, future/socket polling, callbacks, wakeups, watch
publication, await, or foreign future/resource destruction. Never acquire DNS's
inner transport mutex from inside a registry critical section. The upstream DNS
wrapper already serializes access to its inner transport; this design must not add
an inverse lock order or claim to remove that existing dependency lock.

Define revocation linearization at the registry's state change. A policy check
completed before revocation may already have admitted one I/O poll; it can finish
outside the guard. Revocation forbids subsequent admissions, not retroactive
rollback of a connect syscall. Cancel/wake the owned attempt and close resulting
connections; only joined shutdown proves resource destruction. This is the same
admission-versus-destruction distinction as the existing DNS lifetime gate.

Fixed bounds:

- APP identities: 16 immutable; explicit relay targets: 8; discovery ledger: 32,
  including seeds, discovered relay references, failed/backoff and retiring entries.
  Discovered relay targets also consume the existing 8-target budget, not a second
  unrestricted target table. Shared identity index has at most 56 distinct peers.
- Pending attempts: existing shared 8 connection slots, including relay control
  dials and circuit dials, not 8 additional DNS slots. Discovery established
  connections: 4; relay reservations: 2. Application/relay admission's existing
  `16 + 8` established ceiling must be explicitly extended/accounted for the
  separate discovery budget, not accidentally reused as proof of a four-peer cap.
- At most four address hints per discovery peer, 256 bytes each: 32,768 encoded
  bytes, excluding container overhead. No copies into a second role-address ledger;
  store numeric endpoint constraints inline and root constraints in already owned
  bounded address storage. No answer-derived registry insertion from the hook.
- One attempt object per charged connection. At most four aggregate root addresses
  per pending connection is a defensive ceiling (32 root leases across 8 slots);
  the discovery policy selects only one. Inner DNS attempts are sequential per
  root. Guard checks allocate no address/vector; token allocation is per admitted
  attempt, not per DNS answer, packet or check.
- Expected hash lookup is O(1), worst case bounded by 56 identities / 8 attempts;
  borrowed decoding is O(address bytes), capped at 256 and three accepted
  components. Hint deduplication scans at most four; expiry scans at most 32 plus
  the existing relay state. Do not scan all peers on every decoded component.
- Full registries reject before useful work, with no eviction of live authority,
  no unbounded waiter queue, and no reuse of canceled slots until destruction.
  Serial overflow fails closed. Existing four-lookup and 64-task limits remain
  shared, independent limits rather than proofs of role cardinality.

## 6. Exact update and revocation points

| Existing point | Required role/attempt update |
| --- | --- |
| `bind_configured`, before `listen_on` | Create immutable APP context, reserve pinned seed identities, construct one shared role view for resolver/guards/admission. No seed attempt, query or network bootstrap merely from registration. |
| `Core::command(Connect)` | After existing membership/address/capacity checks and before `swarm.dial`, stage numeric APP intent keyed by `options.connection_id`. Reject closed replies before staging. Preserve admitted-waiter-cancellation semantics. |
| `authorize_relay`, `reserve_relay`, `connect_via` | Record explicit or discovered origin and exact endpoint before any listener/circuit request; do not treat a seed as permissive explicit relay. Live reservation/circuit intent authorizes the later child-generated relay-hop attempt, including an already queued child request. |
| Composed `handle_pending_outbound_connection` | Validate aggregate hints and trusted intent; register the exact attempt before returning. Charge the common pending bound. Duplicate peer, unknown intent, no current discovery epoch, wrong suffix or full registry denies the request. |
| `Admission::established` and outbound-established callback | Recheck exact current attempt and role before creating handler authority; do not merely test `permits(peer)`. Preserve inbound APP-only rule and one established connection per peer. |
| `Admission::on_swarm_event(DialFailure/ListenFailure)`; immediate `swarm.dial` error | Retire only the matching attempt. These callbacks may happen synchronously before `Core.pending` exists; rollback must be idempotent. Do not delete a successor by PeerId alone. |
| `Core::event(ConnectionEstablished)` | Match connection ID, expected peer, noncanceled role and numeric witness; promote infrastructure provenance separately from `relay_connected`'s APP route publication. Late establishment is closed and cannot publish a link, hint, capability or lease. |
| `OutgoingConnectionError`, including `WrongPeerId` | Discard numeric witness and capability eligibility; retain bounded failure/backoff history and cleanup charge until leases are gone. Obtained wrong peer is not registered. |
| `ConnectionClosed` / `relay_control_closed` | Remove only matching control/connection generation, revoke its Identify capabilities and dependent handoffs; remove APP routes exactly as today. |
| `stop_reservation` (`Pending` cancellation/deadline, release, listener error/closure, expiry, control loss) | Revoke operation eligibility before `remove_listener`/disconnect; suppress renewal, queued new control attempts and publication. Do not revoke another independent reference solely because one waiter disappeared. |
| `relay_tick` stopping completion and target-history eviction | Separate operation revocation from target-history retention. Retained target != active dial permit. Reclaim only after listener, admission pending/connected and attempt leases are gone. Preserve 60-second bounded history and terminal teardown deadline. |
| Discovery cancel/deadline / hint expiry / capability withdrawal | Mark epoch/eligibility revoked first, finish active query, remove routing hints, cancel only affected owned attempts, and reject late events. Independent active reservation references survive epoch cancellation. Retain cleanup charges; fail the owner on teardown deadline rather than grow tombstones. |
| `Core::drop` / explicit close | Close role admission before DNS lifetime closure and Swarm destruction; wake canceled attempts outside locks. Existing `Carrier::run` drops Core before joined executor shutdown. Retained read handles cannot reopen the registry. |

`Swarm::disconnect_peer_id` does abort pending connections: swarm
`connection/pool.rs:374-393` drops abort notifiers; `pool/task.rs:94-127` races that
notification against the dial. The public method returns `Err(())` if no established
connection existed even though pending abort was requested (`lib.rs:639-643`). Do
not mistake that return value for “nothing canceled.” It is peer-wide, not an
exact-ConnectionId abort API. Use it only when the owner knows it is not killing
an independently active reservation/control reference. Per-attempt cancellation
can instead wake the private native wrapper and return an error for its exact
key; existing shared lifetime closure is reserved for carrier-wide teardown.

No claim that receiving a terminal event joins all task destruction follows from
this API. Explicit future-lease destruction and the existing executor shutdown
remain separate witnesses. A root wrapper must retain its lease through Noise,
not drop it when the inner TCP future first succeeds.

## 7. Discovery integration boundary, not circular authority

No discovery behaviour or `discover_relay` command exists in this baseline. The
next owner integration must add it through the bounded command channel, not infer
an active query from the existence of a configured resolver.

For seed attempts the owner has a pinned descriptor. For referrals the trusted
fact is **a charged local operation permitting bounded infrastructure exploration**,
not that the remote referral is truthful. Admit a peer into the 32-peer ledger only
after rejecting local/APP/explicit-relay overlap, validating its hints and charging
the current epoch/contact budget. Its role remains untrusted infrastructure until
Noise authentication; neither authentication nor Identify promotes it to APP.

Kademlia can emit dials from query-internal referrals before a final owner-visible
query result (`README.md` sections 3 and 8). A generic pending-outbound callback
must not register every unknown peer as discovery just because a query is active.
Preserve the **origin of child-generated dial requests** at the composed behaviour
boundary: intercept the Kademlia child's dial output while its current owner query
is charged, admit/validate the peer and addresses there, then let the aggregate
pending callback consume that intent. Relay-generated requests use relay target
intent instead; request-response dials cannot borrow either origin. A small private
adapter implementing the existing `NetworkBehaviour`, or explicit composition,
can retain this origin without a new public trait or dependency.

The precise missing product surface is this owner/query-to-child-dial intent
handoff, not another DNS resolver API. The prepared Kademlia recipe already bounds
referral retention and disables automatic bootstrap; it does not supply owner role
or epoch authority. Implement the handoff with the discovery owner, retaining one
active query, 32 lifetime charged contacts and a 30-second epoch. Do not enable
unknown-peer admission in the earlier role-guard leaf to compensate for its absence.
Identify is accepted only on the current authenticated connection/generation and
may update bounded capabilities/hints; it cannot create its own connection authority.

## 8. Smallest implementation slices and observable proof

1. **Private role context plus numeric compatibility.** Add the shared registry and
   borrowed classifier, wire the configured transport's outer/inner guards and
   `OwnedResolver::permits_address`, then stage/retire existing APP and explicit
   relay intents. Keep public DNS closed except owner-admitted internal fixture
   operations. This slice can prove policy and revocation without pretending the
   missing Kademlia owner exists.
2. **Provenance-preserving relay handoff.** Add private origin fields and numeric
   witness promotion, preserve explicit relay behavior, and exercise strict
   discovered-origin reuse/expiry with internal owner fixtures.
3. **Discovery owner integration.** Add bounded query/child-origin admission and
   actual request-driven discovery using the same registry. Only then replace the
   remaining no-public-DNS safety restriction for real discovery operations.

Expected maintained code touch points (not edits made by this design):

- `src/discovery/mod.rs`, `tests.rs`: config/owner context, identity separation and
  numeric-seed decision; new private `roles.rs` and `address.rs` can separate state
  from grammar/scope classification within the existing directory item budget.
- `src/dns/mod.rs`, `transport.rs`: shared role read handle, expansion predicate,
  outer context guard and final numeric guard/future. Keep provider/wire wrapper
  work separate and coordinate tests with Task 109 rather than duplicate it.
- `src/carrier/driver.rs`, `admission.rs`: constructor plumbing, transactional intent
  registration, exact attempt lifecycle and aggregate behaviour admission. Driver
  is already 641 lines: move composition into a purpose-specific submodule before
  exceeding 700. The carrier directory already has seven items; reuse/reorganize
  its `driver` module into a directory rather than adding an eighth sibling.
- `src/carrier/relay/{mod.rs,controller.rs}`: private origin, handoff, per-operation
  eligibility, control reuse and revocation. `CarrierHandle` needs no new role knob;
  its later discovery command belongs to the owner slice.
- Existing carrier/DNS/relay tests plus focused private role tests. The DNS tests
  directory already has seven items; extend/split by responsibility without an
  eighth direct item. No bridge implementation change is needed to admit infra;
  its existing denial must instead remain an invariant.

Smallest sufficient CI proof matrix, using owned fixtures and passive counters:

| Case | Required observation, not merely a final error |
| --- | --- |
| Configured and legacy numeric APP; explicit relay | Loopback/private successes remain, wrong APP identities remain denied, public methods still accept only numeric endpoints. Legacy raw bind performs no DNS work. |
| Nameserver isolation | Explicit local/custom-port NS succeeds; the same local address supplied as a discovery answer is denied. No NS endpoint creates a peer role. Reuse Task 109 exact-send-target proofs. |
| Seed/referral direct numeric | Strict forbidden destination denied before inner TCP `dial`/socket creation, despite no DNS hook invocation. Allowed global numeric grammar reaches the owned inner transport. |
| DNS/DNS4/DNS6 and DNSADDR | Denied complete candidates produce zero `Encoded::address` materializations and zero inner dials; an allowed candidate provides a positive control. Include all-rejected, mixed order, nested DNS and rebinding from an allowed answer to a forbidden answer. |
| Suffix and inherited composition | Missing/wrong/unregistered terminal peer, repeated peer, interior APP peer, forged circuit/prefix, duplicate TCP/IP and unsupported protocols cannot select permissive authority. Exercise actual Swarm qualification and actual relay child dial, not only a helper predicate. |
| Role downgrade / revocation | Pause after expansion but before inner dial, after TCP future construction but before its first poll, and during pending DNS/Noise. Revoke strict or explicit operation authority; no subsequent admission or late success publication. An already admitted poll is accounted for, not falsely reported rolled back. |
| Same-peer replacement | Cancel an attempt, retain its native future, attempt new registration: bounded rejection. After terminal reconciliation plus destruction, a new serial may start; old completions cannot use it. Unknown/stale origin never falls back to explicit/APP. |
| Wrong peer | A numeric TCP success followed by Noise/Swarm `WrongPeerId` yields no promoted numeric hint, capability, relay lease, APP link or bridge address for either obtained or expected infrastructure peer. |
| Numeric witness / handoff | DNS-selected numeric endpoint, not unresolved Swarm address, is stored only on authenticated exact-attempt success. Discovered relay remains strict through reserve, renewal, lease copy, `relay()` and `connect_via`, including after original discovery epoch cancellation. |
| Relay reuse and late events | Existing control connection cannot bypass revoked eligibility. Old listener, control ID, lease generation, Identify withdrawal and late acceptance cannot resurrect target/lease or affect a successor. An independently active reservation survives unrelated query cancellation. |
| Cancellation and shutdown | Before command admission: no work. Pending discovery: revoke then cancel/wake, retain charges to destruction. Existing APP waiter cancellation semantics remain. Closed registry with retained resolver/read handles cannot reopen; joined close remains the resource barrier. |
| Capacity and complexity | Fill 32 discovery identities, 8 targets, 8 total pending, 4 discovery-established, 2 reservations and four hints independently; next admission fails before allocation/dial. Canceled entries do not free slots early; duplicate inputs do not bypass pre-dedup limits; serial overflow is terminal. |
| No circular authority | DNS/TXT/Identify cannot insert registry roles; Kademlia dial without a charged source intent fails. Infrastructure cannot deliver signaling packets, appear in `links()`, or mint bridge sources; a separate allowed APP circuit still works. |

Use a private test-only exact-endpoint fixture allowance only where an owned local
network is needed. For each such fixture, run the same input against unchanged
production scope classification and assert rejection. Do not add a public bypass.
Pre-materialization counters belong to the actual prepared hook site, native
connect observations to the actual guarded transport, and handoff assertions to
current connection/generation state. No Cargo commands, builds, tests, runtime
smokes, workflow changes or public-network probes were performed for this document.
