# Noq application-payload gate: initial CI spike

Status: **INITIAL REGRESSIONS PASSED; P03 NOT PASSED.**
[CI run 39791470171](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39791470171)
at `fb10e20` passed five policy tests, including the multipath scenario, and
the complete backend library suite: 432 tests, including those five, with
0 failures or ignored tests. This is an isolated proof-of-mechanism on checksum-pinned
`noq-proto 1.3.0`, not a production fork or iroh integration. The production
workspace and existing standalone baseline lock are unchanged.

## Boundary

`prepare.py` verifies the published archive against both the reviewed checksum
and the existing probe lock, extracts it into a fresh directory, and applies
exact-count transformations. Changed upstream text fails closed. The source
and published upstream test lock remain CI-generated artifacts, not maintained
copies of the full dependency. Scripts stay outside extracted source.

The patch adds an immutable, trusted function-pointer policy over `FourTuple`.
It must be pure, deterministic and nonblocking; an untrusted peer cannot choose
or replace the function. It allocates nothing per packet. An application-ready
bit is separate from ACK, close, path-specific and other control readiness.
STREAM and DATAGRAM writers check application eligibility before consuming the
queues; original control scheduling is retained. Application preference ignores
forbidden paths, so an Available control-only path does not shadow an eligible
Backup path. Default configuration preserves the original scheduling.

This adds a maintenance obligation in Noq packetization/configuration. A later
iroh configuration bridge and authenticated transport-address mapping are still
required; inferring transport identity from peer-claimed addresses is not
acceptable. No custom cryptographic protocol, public dependency fork, or public
trait hierarchy is introduced here.

## Initial authored regressions

The tests are inserted as a module of the real upstream sans-I/O harness:

- Both directions deny payload, but the real TLS/QUIC handshake succeeds.
- Queued STREAM and DATAGRAM data remain unserialized while explicit PINGs
  force packet construction; the simulated connection settles within a bounded
  number of steps rather than spinning on denied readiness.
- Explicit allow is a positive calibration: both payload frame types are sent
  and received in both directions.
- Unilateral denial does not prevent payload in the opposite direction.
- A small send window retains backpressure while denied data remains queued.
- The full upstream library test suite also runs with the default policy.

Compilation and every runtime test run **only in GitHub CI**. Local preparation
runs our source transformation as a data operation; it does not execute the
downloaded crate, its build scripts, tests or binaries. Local checks are limited
to Python AST parsing and Rust formatting/syntax checks.

## Confirmed simulated multipath scenario

A new real-harness scenario keeps the initial signaling-only path Available
and opens a permitted path with Backup status on both peers. It queues payload
before the permitted path exists, then checks delivery without requeueing;
fresh STREAM/DATAGRAM data must also flow while that path is Backup. After
explicit path abandonment, control-path PINGs must not carry queued payload;
a fresh permitted Backup path must release the queue. Per-path backend frame
counters distinguish these simulated paths. The address predicate is synthetic
fixture classification, not authenticated production transport identification.
This tests explicit close/reopen, not detection of physical network loss.

## Authored early-data follow-up (runtime pending)

Two additional tests each run allow and deny policies. A resumed client must
have cached 0-RTT keys; frame counters are inspected before server processing
and while the client is still handshaking. A fresh server queues payload after
its first handshake flight but before the client consumes it or sends Finished;
its counters are inspected while it is still handshaking. Both STREAM and
DATAGRAM must obey policy, and control handshakes must still complete. These
phase assertions and positive controls are required, not inferred from eventual
application non-delivery.

## Explicitly not proven

These tests are not physical-egress attribution. They do not prove
loss/retransmission onto another path, 0-RTT/server early data until the new
phase tests actually pass, DATAGRAM queue exhaustion, cancellation,
packet-loss-driven path recovery, Windows behavior, or QUIC NAT traversal. Those remain mandatory follow-up proofs before P03 acceptance.
The policy is not dynamically toggled to release already prepared packets.

The isolated backend uses its own published test dependency lock, separate from
the iroh baseline's lock. No project/dependency versions are bumped. CI uploads
that exact backend lock and the policy regression source for review.
