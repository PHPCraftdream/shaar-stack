# iroh wrapper propagation calibration

Status: **CONSTANT, MIXED-PATH AND SAME-HOST WIRE REGRESSIONS PASSED; P03 NOT PASSED.**

[Run 39814987632](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39814987632)
at `843e396` passed on each of Ubuntu and Windows: three preparation rejection
controls, 16 unit tests, and the real iroh deny-all/allow-all calibration,
with no failures or ignored Rust tests. Actual logs were inspected.

This CI-only extension patches the published iroh 1.3.0 wrapper with one explicit
forwarder for the existing Noq application-payload callback. Both archive digests
must match the reviewed standalone lock. Preparation changes sources as data;
compilation and tests run only in GitHub CI. The production workspace and original
standalone probe remain unpatched.

The generated calibration uses two real iroh endpoints over the existing bounded
custom transport. A constant deny-all callback must allow handshake and subsequent
control traffic, retain STREAM backpressure, and produce zero decoded sent STREAM
and DATAGRAM frames in both directions. Constant allow-all positively calibrates
both frame types and exact application bytes. The callback does not classify any
address prefix and makes no claim about transport provenance.

The negative wait is a terminal behavioral observation: a datagram must not arrive
while keep-alive traffic continues. It is not a latency or performance benchmark.
Explicit reset ends the blocked stream; this is not arbitrary future-cancellation
proof. The full calibration has an absolute 120-second deadline.

Preparation rejection controls cover corrupt archives, mismatched lock checksums,
and preservation of an existing destination. The successful workflow preparation
is the positive source-transformation path. No downloaded code is executed by the
preparation script. The generated lock preserves every dependency version and
changes source identity only for the two same-version local path replacements.

## Authored mixed-path follow-up

The new test conservatively denies the entire internal synthetic address fabric,
including unknown subnets, and permits native IP tuples. This does not authorize
any custom transport by prefix or authenticate a transport generation. The fixture
starts with custom-only remote reachability while real loopback sockets are bound.
It queues STREAM/FIN and DATAGRAM once in each direction and checks non-delivery
while custom control continues. Only then does the client explicitly open a native
Backup path on the original Noq connection; the original queues must drain.
Qlog must attribute payload only to the exact peer loopback socket, with control
but no payload on the non-native tuples. Run `39825937164` at `fd54ba6` confirmed
this on each of Linux and Windows: three preparation checks, 16 unit tests, one
constant-policy test, and both mixed-path tests passed, with no failures/ignored.

Two generated fixture hooks make the phases explicit: disable Noq NAT address
exchange (the public iroh setter ignores zero), and call `open_path_ensure` on the
existing connection with Backup status. Neither hook changes the immutable payload
callback. These hooks are not production APIs. This controlled admission is not
autonomous discovery, hole punching, or physical path failure.

The first mixed-path run (`39818131770`) timed out on both OS. The qlog evidence
showed successful custom control traffic but no native tuple or payload frames.
The fixture had submitted an IP candidate to the remote actor while disabling NAT
traversal; candidate insertion was not an explicit path-opening operation. The
actor's connection checks rely on hole punching to discover/open an IP path
(`remote_state.rs:753-787`), whereas its actual explicit open operation is
`open_path_ensure` (`1051-1088`). The corrected hook uses that same Noq operation
without reconnecting; all queue, payload-exclusion and exact-delivery assertions
remain. The timeout was not increased; the corrected run passed as reported above.

## Authored exact-ciphertext wire oracle

The generated Noq source additionally puts each finalized encrypted packet into
`quic:packet_sent.data.raw.data`, alongside its decoded frame metadata. The source
boundary is `packet_builder.rs:353-368`, after encryption and before qlog emission;
`n0-qlog 0.2.0` defines `PacketSent.raw` and `RawInfo.data` (hex bytes). This logs
publicly transmitted ciphertext, not keys or application plaintext. No production
or original baseline dependency source is changed.

A bounded custom enqueue capture records only successful sends. An independently
owned loopback UDP forwarder records datagrams received through the OS socket API
before forwarding to the peer. The oracle matches complete ciphertext bytes, not
length, timing or PathId. Prefix-free packet identities allow every coalesced
packet to be consumed in order; unknown bytes, partial/trailing packets, duplicate
or ambiguous identities fail closed. Positive controls exercise corruption,
truncation, coalescing, repeat capture and bounded admission.

The real iroh test requires zero captured custom STREAM/DATAGRAM frames and
positive native captures for both types and both directions. Every captured byte
must correlate. Constructed-but-unobserved packets are reported separately, with
zero unobserved payload required. Capture buffers are capped at 256 datagrams per
direction/boundary; trace input at 16 MiB and the identity index at 1024 packets.
[Run 39829606362](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39829606362)
at `619fa79` passed on each of Windows and Ubuntu: three preparation checks,
18 unit tests, one constant-policy calibration, two mixed-path tests, and seven
wire tests, with no failures or ignored tests. Actual job logs were inspected.

| OS | Direction | Custom packets / STREAM / DATAGRAM | Native packets / STREAM / DATAGRAM | Constructed but unobserved packets |
|---|---|---|---|---|
| Windows | 0 | 27 / 0 / 0 | 5 / 1 / 1 | 0 |
| Windows | 1 | 23 / 0 / 0 | 6 / 1 / 1 | 0 |
| Ubuntu | 0 | 28 / 0 / 0 | 5 / 1 / 1 | 0 |
| Ubuntu | 1 | 23 / 0 / 0 | 5 / 1 / 1 | 0 |

These are observed packet counts, not fixed expected counts. Complete captured
ciphertext matched in both directions at both boundaries. The native forwarder
is a same-host OS UDP packet-observation fixture; the custom boundary is a bounded
in-memory sender. This does not prove real libp2p/Yggdrasil transport deployment,
controlled two-NAT traversal, autonomous discovery or selected-custom authority.

Still required before P03 acceptance: real QUIC traversal through the calibrated
NAT topology, required loss/recovery proofs, and authorization/lifetime binding
before permitting selected custom transports to carry payload. The wrapper
forwarder remains a spike API, not a production or published-library commitment.

## Authored cross-process control fixture (runtime unverified)

`support/nat/` supplies the next prerequisite: two Rust helper peers and one owned
UDP relay can run in separate processes/network namespaces. Tokio UDP readiness
backs the custom transport directly, without detached reader/writer tasks or an
extra reliability protocol. The real QUIC handshake handles ordinary UDP loss.
This is a disposable fixture, not a production relay or libp2p/Yggdrasil adapter.

The `SN54` envelope carries kind, side and a public 32-hex-byte case marker before
at most 1500 opaque QUIC bytes. The marker is not authentication; QUIC/TLS still
checks the configured peer EndpointId. The relay has exactly two address slots,
256 captured datagrams per side, a 4096-message limit and a 120-second lifetime.
Registration has a 10-second deadline. A bound endpoint retains its address
publisher; duplicate binds and sends after endpoint drop fail explicitly.

The generated `nat-peer` binary has relay/peer/stop/control-verifier roles. Peer
readiness requires real TLS completion, queued STREAM/FIN and DATAGRAM bytes,
non-delivery before native address publication, and continuing custom traffic.
Owned case-directory GO/STOP barriers prevent early peer shutdown from making
negative observations pass. File publication is atomic and occurs outside the
async runtime; metadata waits use the generated-only Tokio `fs` feature, at the
same dependency version. This JSON is helper input, not a Server/Client schema.

CI runs protocol limits/malformed input, real UDP round trips, publisher lifetime,
wrong-source/layout, incomplete registration and capture-overflow controls. It
also starts all three real processes, joins every child, and independently matches
relay ciphertext to both peer qlogs with zero application frames. A separate exact
after-readiness fault case verifies owned-child termination/reaping.
[Run 39841831803](https://github.com/PHPCraftdream/shaar-stack/actions/runs/39841831803)
at `baba50d` confirmed seven component tests and both real-process cases on
Windows and Ubuntu, alongside all earlier suites. Normal helper exits were all
zero, with no forced cleanup. Windows relay captures contained 24/21 packets and
Ubuntu 26/20, with zero STREAM/DATAGRAM or constructed-but-unobserved packets.
The exact after-readiness fault reaped all three owned children on both systems;
`cleanup_failed` was false. Initial compile errors required a mutable watcher
binding and a generated-only `Transmit::spike_new` constructor; ECN stays private,
and no assertions were removed.

Optional native bind/address fields are authored for the subsequent NAT scenario;
those branches are not accepted by the control-only process case. No two-NAT,
autonomous hole-punching or production transport claim follows from this fixture.
