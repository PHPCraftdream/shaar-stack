# Yggdrasil-ng pinned core preparation (leaf 53.1)

`prepare.py` downloads nothing itself; CI fetches the pinned archive (see
`.github/actions/prepare-sources/action.yml`), verifies the archive SHA-256,
then extracts only `LICENSE`, `crates/ironwood/`, and `crates/yggdrasil/` into
`target/ygg/Yggdrasil-ng-c9a54f1587bb133a06072596484c972a336db0d2/`. The
top-level `Cargo.toml` and `Cargo.lock` are hashed but never extracted or used.
A provenance receipt with original and prepared hashes is written next to the
prepared tree. No source patch is applied in this leaf.

The module lives under `.github/probes/` (mirroring the multi-archive
`native-graph` preparation) because `.github/scripts/` is already at the
seven-item directory limit.

## Content manifest

`ygg-manifest.json` (this directory) is the authoritative pin. Required schema:

    {
      "archive_url": "https://codeload.github.com/Revertron/Yggdrasil-ng/tar.gz/c9a54f1587bb133a06072596484c972a336db0d2",
      "archive_sha256": "4d978c1a8714e0569fd0a3782adab2f6b81b9c9e54d733dbeaa023aaebae96c1",
      "tree_digest": "b05902627173ccce95f88fc0a0e36f043646b7c129dc46e8e03d7512771ae2d0",
      "files": {"<path relative to the archive top directory>": "<lowercase sha256>"}
    }

Exactly 43 entries covering only the extracted scope (`LICENSE`, the two
crates) plus the two recorded manifests. `tree_digest` is the SHA-256 over the
sorted `path\0hash\n` lines. If the archive digest and the content manifest
disagree, the content manifest is authoritative and the archive hash is
recorded evidence. Until the coordinator provides this file, every
preparation run fails closed.

## Non-goals (leaf 53.1)

No lifecycle patch (leaf 53.2), no adapter API (53.3), no negative controls
(53.4), no TUN, root, routes or services, no unsafe code, no Go or FFI, no
version bumps. The upstream salsa20 SIMD fork is not adopted; stock crates.io
`salsa20` resolves transitively. The archive is untrusted data and is never
executed or built by this script.
