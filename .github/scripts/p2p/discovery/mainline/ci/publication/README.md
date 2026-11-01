<!-- Copyright 2026 PHPCraftdream; SPDX-License-Identifier: MIT OR Apache-2.0 -->

## API

The transformed crate adds `EndpointInfo::to_pkarr_signed_packet_at(&self, secret_key: &SecretKey, ttl: u32, timestamp_micros: u64) -> Result<pkarr::SignedPacket, EncodingError>`. It checks endpoint/key binding first (`EncodingError::WrongSigningKey`), then rejects values above `i64::MAX` (`EncodingError::InvalidTimestamp`), then delegates TXT/DNS encoding and signing to the existing upstream implementation (`EncodingError::FailedBuildingPacket` for its errors). The internal `pub(crate)` helper takes `u64` and is not externally exported.

The old `to_pkarr_signed_packet` method remains byte-for-byte source unchanged, and continues taking its timestamp from upstream `Timestamp::now()`. No custom preimage, signer, or DNS encoding is added. The transformed library root adds `#![forbid(unsafe_code)]`. No extra public helper or attrs module export is added.

## Parent CI invocation

Invoke `runner.py` with `--archive <iroh-dns-1.3.0.crate> --source <exact-extracted-source> --original-lock <archive-Cargo.lock> --simple-dns-archive <simple-dns-0.12.0.crate> --destination <unused-outside-repo> --evidence <unused-outside-repo/receipt.json> --plan <parent-ci-plan.json> [--cargo <cargo-command>]`. The plan must use `scope` `targeted` or `full`, set `selection.mainline` true, and include full `head`, `base` (required for targeted; null or full ID for full), and `checkout` commit IDs; checkout must match the runner's read-only current-HEAD check. The runner registers the explicit `publication_tests` target for baseline and candidate metadata, stages baseline upstream bytes before applying edits, and keeps Cargo target outputs outside staged source. The only lock delta allowed is removal of the pinned simple-dns registry source/checksum; locked baseline and candidate resolved package graphs/features/edges are compared. This proves only an archive-based iroh-dns 1.3.0 graph, not compatibility with product dependency versions or lock.

The parent-supplied archive-baseline graph resolves iroh-base 1.2.0, tokio 1.53.1, serde 1.0.228, n0-error 1.0.1, and simple-dns 0.12.0; these are not asserted as product-resolved versions. Receipts include plan identity, source recipe, lock identities, both metadata graphs, toolchain versions, library and harness artifact hashes, and selected/observed test inventory. No test or build was executed for this authoring pass.


## Gaps

Parent-provided evidence identifies archive SHA-256 `80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1` and archive lock SHA-256 `e81d22b26b9e4ab1d68412b948b0e6447e594cf300ee064737796348b807204f`; not independently checked here. The exact n0-error 1.0.1 and macro source was unavailable, so macro-generated `EncodingError` structural match shapes remain unverified. Existing `SignedPacket::from_bytes` verification does not evidence strict rejection of trailing bytes; timestamp-only evidence makes no such verifier claim. Roundtrip verification is not an independent known-answer vector. `Timestamp::now` overflow remains out of scope.

No Python, Cargo, tests, formatting, metadata, or network commands were executed.

The exact registry archive declares `MIT OR Apache-2.0` in its manifest but does not include `LICENSE-MIT` or `LICENSE-APACHE`. The fixture preserves all original members and checks that declaration; it neither fabricates license texts nor establishes release/notices clearance. That remains a separate release gate.
