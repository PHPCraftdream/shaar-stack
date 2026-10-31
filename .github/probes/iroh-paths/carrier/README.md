# Real-carrier bootstrap frame fixture

Current status: **bootstrap candidate wired; execution and acceptance pending**.
The wire case is deliberately labeled bootstrap-only. Native path gain/loss,
re-punch, reconnect, public-network, NAT, Yggdrasil and TUN claims are out of
scope; the separate public smoke remains permission-gated.

`probe.rs` is installed only in a disposable copy of shaar-p2p. Its hook runs in
`SignalingPump::receive_loop` after production authenticated/current-link and
sealed-address membership checks. Captures retain complete ciphertext bytes and
the actual peer, connection, route generation, custom transport instance and
epoch. Unknown, retired, malformed, empty, or overflowed scopes fail closed.
Every registered scope must receive an observation before capture finalization.

`scenario.rs` uses the existing owned TCP/Noise/Yamux relay fixture and explicit
pinned relay bootstrap. It arms inbound capture before establishing the custom
Iroh connection, then sends bidi streams (including FIN) and DATAGRAM traffic in
both directions. Strict mode requires ongoing custom-control observations while
application receive APIs remain blocked. The disposable allow-all variant
requires positive application delivery and exact bytes in both directions.
The checked-in decoded-frame oracle remains byte-for-byte hash-pinned. A bounded
scenario-only qlog pass reads the documented finalized `fin` boolean from STREAM
frame metadata, binds it to the same finalized ciphertext packet identity and
captured datagram partition, and rejects duplicate captured packet identities.
It keeps the oracle's 16 MiB trace, 1024 packet-record, and 65535-byte packet
bounds. Negative controls reject absent/null/nonboolean FIN fields and duplicate
captured ciphertext. These checks supplement, but do not alter, the reviewed
oracle.

`instrument.py` copies the reviewed oracle and injects fixture-only endpoint
accessors into disposable product sources. The qlog observation graph is derived
from the prepared product lock and must add exactly n0-qlog 0.2.0 and serde_json
1.0.154; existing product identities, features, checksums and non-dev edges
remain checked. Product manifests, locks and sources are not edited.

`run.py --wire` creates separate strict and allow-all product copies, records
source-edit reversibility, packet helper/oracle hashes, graph validation,
selected test inventory and execution receipt, and restores its process
observation environment on exit. It labels successful runs
`passed-bootstrap-phase-only`; this label is not native-path acceptance. The
wire runner dynamically executes the selected fixture inventory (scenario,
wire-oracle controls and supplemental controls), rejects empty selections and
ignored cases, and checks that the mandatory scenario, oracle, and supplemental
control selectors each ran. Newly added controls matching those selectors are
included automatically; the complete suite's names and count are not frozen.
The normal `run.py` path remains source-contract-only. CI invokes both paths and
uploads their receipts. CI execution remains pending/unaccepted; no local build,
test, preparation, or project Python execution is permitted for this task.

Pure `checks.py` source-contract cases are not protocol evidence. Existing
product graph and CI ownership keep this fixture isolated under `carrier_frames`.
