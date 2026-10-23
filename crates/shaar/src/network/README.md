# Native SDK admission boundary

`Endpoint` binds one native socket with the Minimal preset, no n0 preset, relay,
port mapping or external lookup. The caller supplies the exact public peer key
and native socket address. It offers only `shaar/tcp/1` and never exposes early
data, a raw iroh builder/connection, or a cloneable endpoint. The crate-private
identity bridge clones the safe SecretKey object, not seed bytes.

An immutable sorted allowlist accepts at most 256 input entries, rejects oversize
input before allocation, deduplicates once and uses O(log n) authenticated lookup.
Empty denies all inbound peers. Outbound TLS pins the exact supplied server key;
server-side client authorization happens after a complete handshake and before
returning a Session. A successful outbound handshake is not confirmation that a
future TCP forwarding request has been accepted. No target TCP socket is opened
by this layer. Forwarding and target errors belong to the next P06 layer.

## Bounds and ownership

- Limits accepts 1..=32 session slots, shared by outbound handshakes and returned
  sessions. `accept(&mut self)` serializes inbound handshakes. Admission uses only
  immediate semaphore acquisition, never an unbounded waiter queue. Tokio's proven
  semaphore owns its internal synchronization; the SDK holds no lock across await
  and does not claim formal lock-freedom for dependency internals.
- Each started handshake has a 10-second deadline. A waiting accept with no Initial
  remains caller-owned and cancellable; no SDK task is spawned or detached.
- The Noq listener retains at most the configured session count of pending Initials,
  16 KiB subsequent bytes each and 512 KiB aggregate. The first packet is outside
  these byte counts and separately bounded by the Initial count.
- Allocated metadata has twice the session count, including protocol closing/drain
  state. Closed Session handles continue holding their SDK slot until dropped;
  dropping one releases that slot, not the separate Noq metadata quota.
- Transport flow control is 16 concurrent bidirectional streams, no unidirectional
  streams, 256 KiB per-stream receive credit, 1 MiB aggregate receive credit and
  1 MiB unacknowledged send bytes. Application DATAGRAM receiving is disabled and
  its send budget is zero. These are protocol windows, not a total heap/RSS proof.
  The shared raw-ingress layer additionally bounds retained UDP input independently.
- The existing native-only application policy denies every internal synthetic
  fabric subnet. This is denial, not authorization of a selected custom transport.

Sessions contain no Endpoint clones. Session drop requests synchronous immediate
connection close; it cannot perform asynchronous drain. `Endpoint::close(self)`
waits for backend shutdown and then drops the sole SDK endpoint owner, including
when Session handles still exist. Cancellation of close does not promise completion
of drain. Handshake cancellation returns SDK slots via ownership, but consumed
Initials are not replayed and backend metadata may persist until Drained.

## Verification scope

The authored tests cover real loopback authentication, allowlist denial, wrong
pinned key, admission saturation without a new Initial, observed-Initial outbound
cancellation, stalled inbound handshake deadline, invalid address/policy bounds,
and explicit close/UDP rebinding while Session handles remain alive. They run in
GitHub CI only. Until its results are inspected, this implementation is not accepted.
TCP pumps, target status, multiplexed stream lifecycle and end-to-end cancellation
are separate P06 leaves; this admission layer does not claim to implement them.
