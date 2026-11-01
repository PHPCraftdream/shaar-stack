# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0

# Private native discovery leaf

This private SDK implementation verifies pkarr signed packets for the caller-supplied exact `EndpointId`, strictly validates a bounded native DNS/TXT profile, and transfers verified observations into the bounded in-memory `PolicyOwner`. It does not implement publication, DHT networking, dialing, actor ownership, cancellation, refresh, shutdown, or consumer integration; no P09/runtime-readiness claim is made.

## Pending actor boundary

The private address validator, signed decoder, and policy owner remain compiled in production but are not yet connected to the P09 actor. Production-only, item-scoped `dead_code` expectations mark the current pending boundary; `cfg(test)` profiles retain normal dead-code diagnostics. Keep expectations on diagnosed items only so newly unused items remain visible. Remove an item's expectation when actor wiring makes it live; do not treat these expectations as P09 integration or runtime-readiness evidence.

## Upstream APIs and strict profile

Pinned source receipts: simple-dns 0.12.0 archive SHA-256 `2b6f884fa9a8d48101774bfbd3aeb81e968dd22cffd19a372da69f183db22c1a`, matching root path-patched lock identity; upstream declares MIT and the prepared tree retains its original `LICENSE` (not relicensed). iroh-dns 1.3.0 archive SHA-256 `80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1`.

- `TXT::iter_raw` is used upstream to enumerate attributes, and iroh-dns concatenates the fragments of each TXT RR before splitting its first `=`. Following that source, the decoder requires an attribute delimiter somewhere in the fragments and validates UTF-8 only after concatenation; empty/malformed attributes and invalid or unsupported address values still fail atomically. `user-data` retains its existing 245-byte limit.

- `SignedPacket::from_bytes` verifies Ed25519 over original DNS bytes. Section counts are preflighted, answer records capped at 32 and DNS bytes capped at 1000. The prepared simple-dns source exposes `Packet::parse_exact`, which shares the parser body with the unchanged permissive `Packet::parse` entry point and rejects any remainder after declared sections; the production decoder uses the strict entry point. Canonical reserialization is not used because it rejects valid alternate wire encodings. TTL zero is accepted; DNS TTL does not govern policy freshness.
- Header/profile requires response, ID zero, standard opcode, no error/OPT, IN non-cache-flush TXT answers exclusively at exact `_iroh.<signing-key-z32>` labels. Each `addr` is parsed as one complete `SocketAddr` (no suffix/whitespace token acceptance), with at most four raw addresses before deduplication; mapped IPv6 canonicalizes to IPv4. Raw and canonical snapshots are retained during decoding; the policy owner stores canonical addresses. Relay/custom/other values fail. Bounded `user-data` metadata is retained in the private policy observation.

The parser repair is prepared from the exact SHA-256-pinned simple-dns archive by `.github/scripts/p2p/discovery/simple_dns/prepare.py`; its provenance records original and prepared file hashes, recipe hash and reverse-transformation proof. CI graph validation verifies that receipt and requires the Cargo lock and resolved metadata to identify the path-patched `simple-dns 0.12.0` source.


Policy retains at most 64 expected keys; greatest sequence, full signed winner bytes and conflict state survive cache expiry. Freshness/future limits are 300s/30s, and cache receipt is monotonic and at most 30s. Checked timestamp/deadline arithmetic and bounded record/address batch validation precede admission.

The checked-decoder metadata accessor is private; policy tests verify its admission lookup behavior through decoded observations only. No independent known-answer signed-record vector is present; RFC 8032 public-key derivation is not signed-record evidence.

No local Cargo/rustc/compiler, builds, tests, Python, network, source execution, project preparation or smoke run was performed. Publication/withdrawal/refresh/cancellation, actual network-work provenance, DHT ownership, operation caps/deadlines, shutdown/join, socket rebind, dial suppression and consumer integration remain deferred and unclaimed.
