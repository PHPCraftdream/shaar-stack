# iroh wrapper propagation calibration

Status: **AUTHORED; RUNTIME UNVERIFIED; P03 NOT PASSED.**

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

Not proven: selective transport authorization, transport-instance/generation
binding, real physical-egress correlation, multipath recovery, or QUIC traversal
through NAT. Those remain required before P03 acceptance. The wrapper forwarder
is a spike API, not a production or published-library commitment.
