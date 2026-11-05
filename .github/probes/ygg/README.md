# Yggdrasil-ng pinned core preparation (leaf 53.1)

`prepare.py` downloads nothing itself; CI fetches the pinned archive (see
`.github/actions/prepare-sources/action.yml`), verifies the archive SHA-256,
then extracts only `LICENSE`, `crates/ironwood/`, and `crates/yggdrasil/` into
`target/ygg/Yggdrasil-ng-c9a54f1587bb133a06072596484c972a336db0d2/`. The
top-level `Cargo.toml` and `Cargo.lock` are hashed but never extracted or used.
A provenance receipt with original and prepared hashes is written next to the
prepared tree. Leaf 53.2 adds the reviewed lifecycle patch below.

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

## Lifecycle patch (leaf 53.2)

`lifecycle_patch.py` and `patches/{core,links,proto,ironwood_encrypted}.py` apply
the reviewed lifecycle corrections to `crates/yggdrasil/src/{core,links,proto}.rs`
and (leaf 53.2b) `crates/ironwood/src/encrypted/mod.rs` as exact
byte replacements ("old occurs exactly once") after the content manifest has
verified the original bytes. Per-file `ORIGINAL_SHA256` pins come from
`ygg-manifest.json`, which stays unchanged; `PATCHED_SHA256` pins the
patched bytes (computed from the literal hunks over the pinned data and
rechecked by `prepare`); a mismatch fails closed, and a placeholder value
`UNPINNED` prints the computed hash. `LICENSE`, the other `ironwood` files and
every unpatched file stay byte-exact. The 53.1 non-goals below described that leaf
only.

## Non-goals (leaf 53.1)

No lifecycle patch (leaf 53.2), no adapter API (53.3), no negative controls
(53.4), no TUN, root, routes or services, no unsafe code, no Go or FFI, no
version bumps. The upstream salsa20 SIMD fork is not adopted; stock crates.io
`salsa20` resolves transitively. The archive is untrusted data and is never
executed or built by this script.
