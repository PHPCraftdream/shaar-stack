# Real-carrier frame acceptance prerequisites

Current status: **source/graph/observer contracts authored; execution pending**.
This is not a successful real-carrier signaling-only proof. Task 203 still owns
real relay/Iroh scenarios, decoded-frame exclusion and positive sensitivity.
Task 204 public smoke is separately permission-blocked.

`probe.rs` is installed only in a disposable copy of shaar-p2p. Its hook runs in
`SignalingPump::receive_loop` after the production authenticated/current-link and
sealed-address membership checks. It captures complete received datagrams with
actual peer, connection, route/generation and custom instance/epoch. It does not
classify QUIC ciphertext. Scope slots are append-only, old scopes are never
rebound, each registered scope requires actual observations, and overflow fails.
Receive-progress waits bind the complete scope and wake only after unlocking.

`instrument.py` owns reversible fixture edits. The shared reviewed Noq finalized
packet-identity hook is reused, not installed by product preparation. Separate
fixture-only Iroh native-path helpers and SDK raw-handle/adversarial DATAGRAM
queues support future scenarios without expanding public product APIs. The
allow-all callback is an explicitly typed observation variant, never a fallback.

`graph.py` snapshots actual tracked/product path sources. It keeps registry
identities, source selection and normal/build edges checked. A future qlog/JSON
observation reference derives only already reviewed identities from the original
probe lock; its explicit lock/profile delta is not mislabeled as an unchanged
product graph. Both instrumented variants must match that reference exactly.
Production Cargo files and sources remain untouched.

The current `run.py` executes only the prerequisite:

1. snapshot the actual prepared product and immutable product lock;
2. install packet-identity/native helper/actual-receive observer edits in the copy;
3. require exact product normal/build identity, feature and edge equality;
4. compile the real copied shaar-p2p library, list its executable inventory and
   execute only `carrier_frame_probe::tests::` through the existing strict
   inventory/identity-scanning runner;
5. emit `passed-source-contracts-only` with inventories and reversible-source
   receipts, or a failure receipt; never claim wire acceptance.

Pure `checks.py` cases validate lock/reference parsing and edit constraints. Their
synthetic metadata is source-contract input, not real protocol evidence. All
compilation and test execution belongs to GitHub CI; do not run this package or
its preparation scripts locally. The CI diff owner is `carrier_frames`, isolated
from existing protocol-poll, SDK, resolver and dependency proof campaigns.

The complete acceptance criteria, provenance baseline and remaining scenarios are
in `docs/plans/p08-carrier-frame-acceptance.md`. No native/public smoke, host route,
NAT topology, Yggdrasil, release or full-workspace permission is added here.
