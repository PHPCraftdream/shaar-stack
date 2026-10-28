# CI-only Cargo notice-evidence collector

The collector is `.github/actions/dependency-license/notice_evidence.py`; its CI-only tests live in `.github/scripts/tests/test_notice_evidence.py` and are included in the existing `sdk-lock.yml` unittest discovery step:

```sh
python -I -X utf8 -m unittest discover -s .github/scripts/tests
```

At generation time, provide actual `cargo metadata --format-version 1` JSON and a JSON object whose keys are every resolved package's exact Cargo package ID and whose values are the corresponding prepared source-tree root. Each root must contain the exact `Cargo.toml` named by that package's metadata `manifest_path`. Example invocation:

```sh
python -I .github/actions/dependency-license/notice_evidence.py target/p2p/metadata.json target/notice-source-map.json target/notice-evidence.json
```

The source map is an explicit external input; this collector does not construct or verify archive-to-prepared-tree provenance. Workspace packages are explicitly excluded from third-party material collection and their package IDs are recorded in `excluded_workspace_package_ids`; they are not silently treated as third-party entries. Their project licensing remains outside this collector. Cargo may omit `license_file` for dependency packages; collection still requires a non-empty `license` declaration and discovered license material unless an explicit valid `license_file` is supplied. No fallback to `docs/legal` is performed.

Output records exact package IDs/source strings (which may contain host-specific path identities), declared expression, discovered legal-material names, content hashes, and exact bytes as hex. It rejects incomplete graph/package sets, malformed/dangling graph edges, mismatched source roots, missing/empty declarations without `license_file`, missing license materials, unsafe paths/reparse points, hard-linked legal evidence, unreadable traversal, and oversized inputs/material. Hard bounds (inclusive) are 32 MiB metadata JSON, 8 MiB source-map JSON, 4 MiB per material file, 100,000 files and 20,000 directories across all source trees, traversal depth 64 (root depth zero), 64 MiB total collected material across all packages and 128 MiB serialized manifest. Exceeding any bound fails; inputs/material are never truncated. These conservative limits also constrain traversal state and manifest memory. Stable ordering gives deterministic output only for identical metadata and mapped tree contents.

Output creation is atomic and no-clobber: the destination must not already exist, and the collector links a same-directory temporary file to the destination before removing the temporary name. This requires filesystem hard-link support in the output directory; unsupported operations fail closed. Path validation and alias checks are not race-proof against concurrent filesystem changes (TOCTOU); run against trusted, stable CI inputs and output directories.

This is evidence collection only: it does not establish archive provenance, artifact inclusion, completeness, legal correctness, or permission; it does not parse SPDX, choose OR alternatives, infer copyright, or determine compliance. Human review remains required.
