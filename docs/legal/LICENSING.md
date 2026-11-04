# Licensing

This workspace is offered under either of two licenses, at your option: the
MIT License (`docs/legal/LICENSE-MIT`) or the Apache License, Version 2.0
(`docs/legal/LICENSE-APACHE`). Selecting either license permits use under that license's
terms; the two licenses are alternatives, not combined terms. Cargo metadata
identifies this dual-license choice as `MIT OR Apache-2.0`.

## Attribution and third-party materials

The project copyright notice identifies PHPCraftdream and 2026. The Apache
appendix contains its canonical example notice, not a project-specific notice.
This project license does not replace the license notices or conditions of
third-party components. Review their applicable terms and retain required
notices when distributing the project. Contributor rights and any third-party
obligations require separate verification.

## Reviewed multibase 0.9.3 source modification

A prepared patch of `multibase` 0.9.3 removes the `base256emoji` dependency and the
Base256Emoji multibase encoding, because the exact license and notice provenance of the
base256emoji emoji alphabet table could not be established; the product must not depend on it.
This is a compatibility reduction: multibase strings with the emoji code point no longer
decode through this library, while every other multibase encoding the product uses
(base58btc, base64, base64url, base32, and the generic decode path used by multiaddr) is
unchanged. The upstream MIT license text of multibase is retained in the prepared tree, and
the modification is identified by the generated provenance receipt; the patched crate remains
upstream MIT and is not relicensed by this project. Upstream's own development `Cargo.lock`
inside the archive still lists the removed crates; Cargo never reads a dependency's lock
file, so it is kept byte-identical and is not part of the product graph. This removal does not itself certify
license compliance of the rest of the dependency graph: the dependency-license gate, notice
collection, and review of third-party terms remain separate obligations.
