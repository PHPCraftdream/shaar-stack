<!-- Copyright 2026 PHPCraftdream; SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Independent native signed-record reference

Acceptance: the existing publication CI step produces a fixed native-profile
record using the independent pinned implementation, retains source/lock/command
and output identities on both OS, and permits parent DATA inspection. This does
not establish SDK interoperability, P09 acceptance, legal clearance or release
permission. No product dependency, public network, new CI segment or general
proof framework is added.

## Fixed input and source

- Implementation: `https://github.com/pubky/pkarr`, revision
  `f6ae1eb8c41e53a583341cb790db71ab266b9383`, package declares 8.1.0.
- Features: `signed_packet` only, default features disabled. No client, relay or
  DHT feature may be active. This isolated workspace does not inherit product
  patches or modify the product lock. Its resolved transitive versions are not
  known until CI generates and retains its own lock and metadata.
- Seed/public key: public RFC 8032 test 1 material, also used by the existing SDK
  tests. This is intentionally public fixture input, never production identity.
- Timestamp: 1700000000000000 microseconds, TTL 30, `_iroh` TXT containing
  `addr=127.0.0.1:9000`. The reference implementation appends the signer's z32
  owner. No SDK encoder or hand-written DNS/signable encoding is used.
- Output: the upstream `SignedPacket::as_bytes()` envelope, bounded by 1104 bytes;
  32-byte public key, 64-byte signature, 8-byte big-endian timestamp and DNS.

The parent independently authenticated the source blobs against the commit's
explicit Git tree `819c3d42d4e6c6230fac4273fc9645e196a81dcb` before authoring.
CI checks the consumed manifest, key and signed-packet source hashes against
those reviewed bytes. This is Git-source identity, not registry-byte equivalence.
The authentic root MIT text was retained separately; no license text or holder
is synthesized here. The implementation's license is not a product release gate
waiver.

## Execution boundary

Only GitHub CI runs this fixture. Resolve once, retain the actual lock and
metadata, then test and run with `--locked`. Retain the fixed envelope, source
commitments, command logs and output SHA-256 under the existing publication
artifact. Re-running the generator must emit identical bytes. Negative controls
reject modified key, signature, timestamp, DNS and truncated/empty envelopes.

After CI, independently inspect the DATA and freeze the actual tuple for #261.
Only a test of the real SDK decoder against those frozen external bytes can
establish interoperability. A same-library verification is merely a generator
sanity check. No tuple is claimed before CI actually produces it.

## Frozen tuple and SDK regression contract

The parent verified feature CI `41769210931` and upstream CI `41769776477`, both at
source SHA `464071279795fcfbd331ab95179da4b5e6967dac`, on Linux and Windows.
All four runs produced the same 206-byte `native-record.bin`, SHA-256
`df80e08650a170f7da4c11a1ef1ab1e41eaa98dd6ec07f6776c1112dfeef4101`.
Consumed source, generator, lock, command-log and record commitments were checked
independently; this is not a registry-equivalence or legal-clearance claim.

The frozen literal in `crates/shaar/src/native_discovery/tests/codec/mod.rs` must be
copied from those authenticated artifact bytes, never reconstructed with the SDK
encoder. The existing decoder must accept its expected RFC 8032 public key,
sequence/timestamp 1700000000000000 and exact address `127.0.0.1:9000`, retain the
signed bytes, and pass the decoded observation into the real policy owner.
Controls must reject the wrong expected key, each byte mutation, every truncated
prefix and an appended suffix. The real policy owner must enforce the inclusive
300-second age and 30-second future boundaries and cap cache lifetime by the
remaining signed freshness. No new signer, DNS encoder or product dependency is
needed. Authored SDK regressions are not an executed interoperability result;
that claim requires their exact-SHA Linux/Windows CI and reviewed delivery.
