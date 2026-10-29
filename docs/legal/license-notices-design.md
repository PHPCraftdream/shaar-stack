# Design: third-party license notices for distributable artifacts

## Status and scope

This is a source-only design proposal. It does not change versions, license declarations, workflow/CI behavior, or project code. The implementation belongs in a future, separately reviewed change. CI may later generate and validate notice bundles; this document does not assert that an SPDX gate establishes notice completeness, legal compliance, or permission to distribute.

## Repository facts informing the design

The root workspace has six members and declares `MIT OR Apache-2.0`; the alternatives are also described in `docs/legal/LICENSING.md`, which identifies the project copyright attribution and explicitly warns that third-party terms remain separate. `.github/deny.toml` currently allows MIT and Apache-2.0 and includes dev/build dependencies. `.github/scripts/dependency_licenses.py` currently checks a locked graph and gathers Cargo metadata, a graph receipt, and six prepared-source provenance receipts. Its own documentation says receipts do not prove graph coverage or legal compliance.

The root `Cargo.toml` patches eight packages to prepared `target/` paths. CI prepares those trees from downloaded crate archives; the graph verifier checks resolved package identities and selected prepared paths. Thus registry lock entries alone cannot be treated as a complete description of the source being shipped or its notices. Current CI artifacts observed in workflow files are primarily test/proof artifacts, not a defined product release package. The implementation must first declare each actual distribution product and its inclusion rules rather than infer release contents from arbitrary CI uploads.

## Goals and non-goals

Generate a deterministic, reviewable third-party notice bundle for each explicitly named distribution artifact, and validate that bundle against the exact resolved dependency graph and source content represented in that artifact. Fail closed if attribution, source identity, license material, provenance, or artifact mapping is ambiguous or missing. Preserve the existing workspace and dependency versions and declared SPDX expressions.

This is evidence and packaging hygiene, not a legal determination. Cargo metadata, cargo-deny, and SPDX parsing can identify declared licenses and graph nodes; none proves that a license declaration is correct, notices are legally sufficient, or source modifications satisfy obligations. Human review remains necessary.

## Inputs and graph model

1. Establish a versioned manifest of distributable artifact profiles: artifact identifier, target/platform or package selection, build feature set, included workspace binaries/libraries, and packaging roots. No profile is implicitly “all CI artifacts.”
2. For every profile, capture complete resolved Cargo metadata and the lockfile from the same resolution, with toolchain, target triple, feature selection, and source/patch receipt identities. Require resolution nodes and edges; reject metadata without a resolved graph. Include build and runtime dependencies that can contribute material to the distributed artifact. Dev-only dependencies may be excluded only when demonstrably absent from that artifact; record the policy and verify it rather than relying on a generic allowlist.
3. Model nodes by package name, version, source identity, checksum where applicable, and resolved graph edges. A path-patched package has no registry source/checksum identity; bind it instead to its prepared tree digest, original archive digest, preparation receipt, and patch-set digest. Do not collapse a path package and registry package merely because name/version match.
4. Preserve the original crate archives in the evidence set, or retain them in a retrievable content-addressed store keyed by a verified digest. A digest alone is not sufficient: the exact original archive must remain retrievable and be inspected for its license, copyright, and NOTICE materials. Associate every prepared path package with that archive, deterministic patch manifest, preparation receipt, and prepared-tree digest. If any link or archive retrieval/inspection fails, fail closed. Inspect the prepared distributed source as well, recording retained, changed, added, or removed legal materials against the original archive; never silently substitute one source's materials for the other.

## Notice data and SPDX policy

For each graph identity, collect package metadata and candidate files such as `LICENSE*`, `COPYING*`, `NOTICE*`, copyright/author attribution records, plus explicit human-reviewed overrides. Preserve verbatim license and notice text where redistribution requires it; record source path, content digest, and origin. Do not manufacture copyright holders or infer a NOTICE document from a license identifier. Missing, conflicting, malformed, or unreadable metadata/material is a blocking error until reviewed and resolved explicitly.

Parse SPDX expressions as expressions, not strings. Keep the distinction between `OR` (alternatives) and `AND` (conjunctive terms); never “resolve” an expression by selecting a convenient allowed license without a documented, reviewed choice applicable to the package. Unknown SPDX identifiers, `LicenseRef` expressions without their referenced text, unsupported syntax, and absent license declarations require explicit review and fail the automated acceptance path. Keep the existing MIT/Apache policy unchanged unless separately approved. Record both the declared expression and the chosen treatment/material; a successful expression allowlist is not evidence that notices or legal obligations have been met.

The workspace's own dual-license files and attribution remain separate from third-party entries. Include their existing project license texts where the artifact format requires them, without rewriting versions, declarations, or attribution.

## Artifact-to-package mapping

Produce a machine-readable inventory per artifact containing the artifact digest, profile and target, build/features identity, resolved graph receipt digest, included package identities, source kind (registry/git/path/workspace), and notice-material digests. Link each executable/library artifact to the profile and graph that built it. For vendored/static-linked or copied sources, require explicit mapping to their upstream component and notice materials even if the component is not present as a normal final binary dependency. A Cargo graph or filename heuristic cannot enumerate all embedded material. For each artifact profile, require an explicit, complete source-file inventory generated from the exact packaging inputs before assembly, with normalized path, file type, digest, and inclusion/exclusion disposition for every file. Require reviewed coverage evidence that accounts for every included file and identifies third-party-derived or embedded content and its upstream identity; maintain this as a reviewable mapping tied to that inventory digest. Any omitted, unclassified, or unmapped file blocks acceptance. Keep excluded files and rationale in the inventory so scope is auditable. Detect duplicate package names with distinct versions/sources as distinct entries.

Package the generated notices and machine-readable inventory next to each distribution artifact, not merely as an unrelated CI report. Validate the packaged bytes after assembly and record their hashes. If no actual distribution artifact exists in a CI run, report “not applicable” rather than claim artifact validation succeeded.

## Safety and fail-closed behavior

Treat manifests, archives, source trees, and package metadata as inputs that may be malformed. Canonicalize paths beneath designated extraction/work roots; reject absolute paths, traversal components, drive/UNC escapes, duplicate normalized paths, and archive links that escape the root. Reject symlinks, hard links, and reparse points, including in-root links; do not follow them. If a real dependency requires one, block it for an explicit, separately reviewed policy rather than silently relaxing this rule. Bound archive size, expanded size, file count, path length, and individual notice size. Read regular files without traversing arbitrary external paths. Reject unreadable files and unsupported encodings rather than silently omitting them; preserve original bytes for notice materials and emit deterministic UTF-8 metadata.

Generation must be atomic: write to a fresh temporary output, validate, then publish; never leave a partial “successful” bundle. Any missing graph receipt, archive-to-prepared-source link, declared license, required text, artifact mapping, digest match, or validation step fails the job and prevents distribution upload. Always retain failure diagnostics and available evidence, but do not let an evidence-upload success mask the gate failure.

## Reproducibility and evidence

Sort package identities, paths, and notices by stable bytewise keys; normalize metadata encoding/newlines and timestamps; avoid host paths, current time, filesystem enumeration order, and platform-dependent separators in generated output. Preserve license text bytes where required, documenting any packaging normalization separately. Pin tool versions/checksums in the implementation and record generator version, policy version, graph/profile digest, source/archive/patch digests, and output hashes. Verify two clean generations from identical inputs produce byte-identical bundles. The report should distinguish declared metadata, collected source evidence, human decisions, and unresolved review findings.

## CI-only verification plan

No local runtime checks are requested or performed for this design. In a future implementation, CI-only tests should cover:

- complete graph and edge receipt requirements, target/feature profiles, changed or missing graph nodes, duplicate identities, and registry-versus-path identity;
- original archive retrieval and inspection (not only digest recording), archive-to-prepared-tree/patch receipt binding, including missing or mismatched provenance;
- license/NOTICE/copyright discovery, preservation and conflicts; missing declarations, unknown SPDX IDs, `LicenseRef`, and `AND`/`OR` semantics;
- embedded/copied source mapping and deliberate unmapped-material failures;
- archive traversal, absolute/drive/UNC paths, symlink/reparse escapes, cycles, duplicate normalized names, bounds, malformed files, and unreadable evidence;
- each artifact profile's graph-to-binary mapping and validation of the actual assembled package contents;
- determinism across clean repeated runs and failure atomicity;
- workflow wiring proving notice validation is a required gate before distribution upload and that report/upload errors propagate.

These tests verify software contracts and evidence wiring only. Human review of third-party licensing and notice obligations remains required; a green SPDX check or notice-generation test must never be described as proof of legal compliance.

## Implementation boundary

A later implementation should add a design-aligned generator/validator and CI-only tests in appropriate existing source directories, then separately wire it into CI and distribution packaging. That change must respect `CLAUDE.md`, retain the existing dependency versions and licenses, and avoid claiming coverage for artifact types not actually mapped and tested.
