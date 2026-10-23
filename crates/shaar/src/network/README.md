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

The first Windows run at `538f399` passed formatting, clippy and nine of the ten
network tests, but immediate UDP rebinding failed with AddrInUse while Session
handles remained alive. Absence of Endpoint clones alone is insufficient: Noq's
retained connection State owns a UDP sender, which holds iroh's Socket and native
senders. The shared runtime patch now makes that sender optional and releases it
when the connection driver finishes or is cancelled, outside the connection state
lock. Read-only closed connection handles no longer need native I/O ownership.
The original immediate-rebinding regression is unchanged. After correcting the
Rebind event's optional-sender assignment, `a0c9098` passed the real test on both OSes.

## Verification scope

The authored tests cover real loopback authentication, allowlist denial, wrong
pinned key, admission saturation without a new Initial, observed-Initial outbound
cancellation, stalled inbound handshake deadline, invalid address/policy bounds,
and explicit close/UDP rebinding while Session handles remain alive. They run in
GitHub CI only. Completed job logs for
[CI 39921459207](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39921459207)
at `a0c9098` were inspected: all ten admission tests passed on Linux and Windows;
library suites passed 24 tests with zero failures in 13.55s/13.30s, respectively.
All three native dependency tests and five ingress-budget tests also passed per OS.
This accepts endpoint admission, not the entire P06 stage.

## Fixed-target forwarding

`Session::forward(tcp)` owns one local TCP socket and one bidirectional QUIC stream.
It admits at most 16 calls without queued admission. Under `shaar/tcp/1`, the client
writes request byte 1; the server reads it before opening its locally configured,
validated nonzero loopback target. No peer supplies a host or port. Server status
0 means target connected, 1 means target unavailable, 2 means invalid request.
Unknown request/status values fail closed. Setup is bounded by ten seconds. No
TCP application bytes are read by the client pump before a successful status.

`Session::serve(target, stop)` owns at most 16 tasks in a JoinSet and never accepts
another stream while full. Each task owns its stream and TCP socket. The two copy
futures run concurrently with fixed Tokio copy buffers, no application data queue
and borrowed TCP halves, not additional per-half Arc allocations. EOF finishes only
the corresponding write direction; a completed QUIC send also awaits its final ACK
or peer stop. Stream failure/cancellation resets the affected pair, not the session.
Typed error mapping inspects actual backend error variants, never peer text.

On `stop`, serve closes the session, aborts outstanding workers and awaits every
terminal result. Per-stream I/O failures are counted and isolated; worker panic is
reported as TaskFailure after cleanup. Report counters saturate at u64::MAX. Dropping
the serve future is only an abort fallback and cannot promise joined shutdown;
callers use the stop future and await serve for that guarantee. Whole-connection
loss terminates its TCP sessions; it does not promise TCP survival across reconnect.

Admission lives under `admission/`, forwarding under `forwarding/`; the public
admission API is unchanged. Forwarding tests are authored alongside implementation,
including both half-close orders, four-way concurrent streams, malformed request,
target failure, stream reset/cancellation isolation, setup timeout, status ordering,
capacity and joined shutdown. This forwarding layer awaits its own CI proof;
consolidated P06 acceptance remains a separate leaf.
