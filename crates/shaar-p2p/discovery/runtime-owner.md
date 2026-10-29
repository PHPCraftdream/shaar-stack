# Bounded discovery runtime: implementation contract

Status: implementation plan for task 139, not runtime acceptance. Baseline
`b56dbbc` passed full candidate and post-integration CI on Linux and Windows.
The Carrier still has no Kademlia or Identify behaviour at this baseline.

## Accepted boundaries

- Prepared Kademlia accepts an optional pre-retention referral predicate. Its
  per-query and iterator caps remain independent of the global owner budget.
- The composed Carrier boundary validates all child-contributed dial addresses.
- Dependency `ToSwarm::Dial` becomes an owner event carrying the original
  `DialOpts`. The owner calls the same `Swarm::dial` used by the dependency path.
  Connection IDs, dial conditions and port selection must not be reconstructed.
- Infrastructure authority is separate from the immutable APP allowlist.
  Existing `prepare_native` permits only the exact configured seed root.

## Rootless dependency dials

The locked Swarm calls `handle_pending_outbound_connection` with addresses from
`DialOpts`, before appending addresses returned by the composed behaviour.
A Kademlia dial may have no explicit addresses. Admission currently requires one
explicit root, so simply adding Kademlia would reject its dials.

The runtime must perform this sequence:

1. Receive the unchanged dependency dial at the sole Carrier owner.
2. Check the active query epoch, expected infrastructure identity, source-control
   generation, owner deadline, contact budget and connection/pending budgets.
3. Select one validated ledger root. Stage that root and the infrastructure
   permit against the original `DialOpts::connection_id` before submitting it.
4. For an address-less infrastructure dial, let Admission contribute only the
   already staged root. This is lookup of existing authority, not admission of
   arbitrary Kademlia addresses.
5. After all children run, restrict the infrastructure contribution to that exact
   selected root. A routing or query cache must not append a second endpoint.
   Preserve the existing fail-closed APP and explicit-relay paths.
6. On synchronous submission failure, reconcile the exact infrastructure entry
   immediately. On asynchronous failure, keep all charges until terminal events
   and permit release. Query completion alone does not release dial charges.

Do not rebuild `DialOpts` merely to inject an address: allocating a replacement
connection ID would disconnect dependency bookkeeping from the real dial.

## One lifetime ledger

Use one bounded identity/contact ledger shared by initial routing and referral
admission. Its 32 slots include seeds, rejected-after-contact peers, failed
attempts and retained cleanup state. A failed contact does not replenish the
lifetime budget. Each peer retains at most four unique validated addresses of
at most 256 encoded bytes; seeds consume the same slots.

A single active query has an epoch and monotonic owner deadline. The predicate
must reject unrelated or retired query IDs and reporting peers without the exact
current authenticated infrastructure control generation. Retained hints carry
that provenance; replacing or losing the source control revokes their usefulness
without freeing lifetime contact slots. Local, APP and explicit-relay identities
must not be promoted into discovery infrastructure.

The dependency callback needs synchronous pre-retention decisions. If a shared
ledger lock is necessary, justify it explicitly: bounded pure validation and
state updates only, no await, network operation, foreign callback or resource
cleanup under the lock. Avoid reciprocal registry/ledger lock acquisition.

## Behaviour and owner wiring

- Construct Kademlia in fixed client mode with manual routing insertion.
- Disable both periodic and insertion-triggered automatic bootstrap.
- Disable Identify's independent address cache.
- Retain exact DHT/HOP capability bits only for the current authenticated
  connection. STOP is not HOP. Observed addresses do not become dial authority.
- Insert routing addresses only after owner admission. Referrals remain hints,
  never APP or relay-reservation authority.
- Drive owner deadlines and cleanup in the existing Carrier loop; no detached
  tasks, additional unbounded queue or independent retry executor.
- Keep at most four infrastructure connections, including pending/closing
  ownership, and preserve the aggregate pending cap of eight.
- Close query authority before finishing the dependency query. Retire owned
  connections separately and join existing executor ownership on shutdown.

Constructor validation must remain free of DNS queries and bootstrap. Any runtime
startup path must use validated explicit configuration and remain testable using
owned fixtures; deterministic CI must not contact public seed infrastructure.

## Required acceptance

The implementation is not accepted merely because the preparation or wrapper
unit tests pass. CI must exercise the actual Carrier path through:

1. An owned seed and referred DHT peer, including a rootless dependency dial and
   expected-peer authentication through the staged native boundary.
2. More than 32 unique referrals across responses, duplicate/oversized/unsupported
   addresses, seeds sharing the contact budget and failed contacts retaining it.
3. Exact query/control binding, late responses, control replacement and expired
   hints; no stale result can stage a new dial or advertise HOP eligibility.
4. Identify DHT-only, HOP, STOP-only and capability withdrawal cases, with no
   automatic cache or external-address authority bypass.
5. Cancellation during DNS/dial/query, concurrent pending pressure, timeout,
   connection loss and bounded shutdown with terminal resource accounting.
6. Existing APP authorization, relay generation and strict signaling-only tests.

No public-network smoke, automatic reservation, Ygg integration, new dependency,
version bump or production-readiness claim is included in task 139.
