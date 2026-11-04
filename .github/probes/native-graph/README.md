# Native SDK dependency graph contracts

**Status:** the base graph at `ab96feb` passed exact-SHA feature CI `41778932723` and upstream CI `41782801796` on both OS with independent DATA inspection. Earlier authoring-only notes below describe their original source passes, not the absence of later execution. The SDK dev-codec extension is currently authored and awaiting fresh CI; this document is not publisher or complete P09 acceptance proof.

## SDK dev-codec projection

The existing dev-edge proof admits only `n0-future` 0.3.2 and `serde_bencode` 0.2.4
registry declarations resolved to their approved prepared paths. It requires an
exact dev-only declaration and condition set, a snapshotted root patch, exact
package path/version, original archive identity, full prepared-source inventory
and the exact provenance receipt. A retained codec package reached normally by
Mainline does not permit retaining a direct SDK dev edge in the normal consumer.
No normal/build edge, arbitrary registry replacement or unbound archive is allowed.

`fixture/baseline/` separates baseline materialization from this projection check
without adding a CI segment or changing the historical BASE. The graph module
keeps its existing entry point and delegates the proof to `baseline.projection`.
Tests use isolated copies of the already prepared CI source, never alter the
product tree, and reject kind/condition/requirement/source/root-snapshot/archive/
prepared-source/receipt/retained-edge/patch-path mutations. Local execution is
not acceptance; fresh exact-SHA CI is required before adopting this extension.

## Independent approved-route lock

CI `41797750366` reached the same control-lock failure on both OS: the approved
route used the candidate lock, including its new SDK dev-codec edge, against the
unchanged control SDK manifest. Its product metadata correctly rejected this with
`--locked`. The baseline and normal projection fixtures passed before that failure;
the failed run is not acceptance of the complete comparison.

The control now reads raw `Cargo.lock` bytes only from accepted graph revision
`ab96feb3f3503f91936664257a338b5486dfba0e` through a retained `git show` command.
SHA-256 must equal
`c5b9de68e430b865378fc5d9adf3489ba87885dcfc6783d734df3365c893c030`.
No lock is synthesized, refreshed or copied from the evolving candidate into the
control. Historical BASE `67e10f3`, its independent manifest transformation, source
bindings and all locked checks remain unchanged. Baseline and candidate still use
their own raw locks. Regressions cover all three roles, candidate-lock changes,
unknown roles, wrong bytes/types and exact CRLF rejection without normalization.
This repair requires fresh CI; authored regressions are not passing test evidence.

## N0-future Tokio feature comparison

The n0-future 0.3.2 archive is pinned to SHA-256 e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe. Historical BASE retains the registry source; approved-route and candidate use the prepared source. Only Cargo.toml changes: native Tokio retains requirement 1.28 and normal rt/time/macros, while test-util is dev-only. All other archive bytes stay unchanged, with exact inventory and reversal provenance.

The N0future feature comparison is an isolated development proof using the unchanged archived `Cargo.lock`, including its Tokio 1.48.0 registry checksum, with `--locked` metadata, library tests, and documentation checks. This is separate from the product Tokio 1.54.1 pin; Tokio 1.28 is the manifest requirement, not the resolved version. CI must fail rather than refresh the lockfile if an adjustment is needed. Any lock adjustment must be generated separately and reviewed by the parent as an exact delta. No execution claims are made.


## Preparation contract

`.github/probes/native-graph/prepare.py` accepts five local archives (`--adapter-archive`, `--mainline-archive`, `--bencode-archive`, `--dns-archive`, `--future-archive`) and creates a new destination root. It imports only the fixed, read-only mainline preparation modules. The adapter tree preserves the upstream workspace and lint inheritance, with its selected manifest at `adapter/iroh-mainline-address-lookup/Cargo.toml`. Each source has a receipt outside its package tree containing exact original/prepared inventories, complete imported recipe hash maps (including this generator), and source identity. `verify_all` recomputes the expected trees and validates inventories and receipts before returning package roots. The adapter receipt records the honest Git repository and revision, not registry equivalence. Adapter extraction enforces the immutable archive SHA-256 `035d35f41362c79d43f44dc1d5cdaf9c8c718fa3781fd09cf458b7b47cb014ba` and bounded, safe regular-file/directory archive paths.

The three fixed repair modules are `.github/scripts/p2p/discovery/mainline/prepare.py`, `.github/scripts/p2p/discovery/mainline/ci/bencode/prepare.py`, and `.github/scripts/p2p/discovery/mainline/ci/publication/prepare.py`. Existing recipes and runtime sources remain read-only. No preparation or tests were executed.

`crates/shaar/Cargo.toml` declares adapter 0.6.1 by generated path and n0-mainline 0.7.0 as normal dependencies. Root `[patch.crates-io]` redirects n0-mainline, serde_bencode, and iroh-dns to their respective prepared trees while retaining all existing patches. Cargo.lock contains the byte-exact CI-generated candidate after independent package/source/checksum/edge review; locked-build and feature acceptance still require passing CI receipts.

## Graph and CI contract

`.github/probes/native-graph/graph.py` audits exact Cargo lock identities and the isolated normal-consumer metadata graph. `audit_consumer_lock` allows only the consumer root addition, requires the consumer's sole lock dependency to be `shaar`, preserves exact source/version/checksum for packages present in both locks, and reports the dev/test-only identities absent from the normal projection. Unknown transitive additions are rejected with their complete name/version/source identity except for these reviewed registry identities and dependency shapes:

| Registry package | Version | Checksum | Reviewed dependency shape |
| --- | --- | --- | --- |
| `crc` | `3.4.0` | `5eb8a2a1cd12ab0d987a5d5e825195d372001a4094a0376319d5a0ad71c1ba0d` | depends on `crc-catalog` |
| `crc-catalog` | `2.5.0` | `217698eaf96b4a3f0bc4f3662aaa55bdf913cd54d7204591faa790070c6d0853` | no dependencies |
| `dyn-clone` | `1.0.20` | `d0881ea181b1df73ff77ffaaf9c7544ecc11e82fba9b5f27b262a3c73a332555` | no dependencies |

The normal `n0-mainline` consumer route is specifically `n0-mainline -> crc` and `n0-mainline -> dyn-clone`, with `crc -> crc-catalog`. These are exact route checks, not approval of arbitrary direct edges from the consumer root. The exact entries were independently matched against the approved upstream lock and the CI-generated candidate before this audit expansion. A candidate lock is not locked-build, feature, runtime, or legal acceptance.

`.github/probes/native-graph/ci.py resolve` is a manual candidate operation, not acceptance: the composite preparation action prepares all existing patched sources in resolve-only mode, then Cargo metadata performs resolution. It audits the prepared source identity, product metadata, and exact lock delta, and persists a receipt with before/after lockfiles, command logs, statuses, and hashes; the receipt records `accepted: false` and `verification_status: deferred-to-verify-locked`. Resolve does not perform the three-proof comparison, build, or tests. Full `verify` remains mandatory: it must compare baseline, control, and candidate using actual artifact features and future-dev proof, and run the normal feature-gate after adopting the CI-generated raw lock. CI runs the verification job on Linux and Windows; manual resolution is Ubuntu-only. These requirements describe the workflow; no execution outcome is asserted.


The projection evidence binds both Cargo metadata JSON payloads to SHA-256 digests and retained command receipts: each receipt records the exact argv, resolved cwd, stdout hash, and exit status, which must be zero. Every direct edge removed by projection must be accounted for by source metadata as a dev-dependency declaration on the owning manifest; normal and build edges are rejected. The declared alias must match exactly (a genuine package rename is permitted only when the metadata proves that rename), and the exact registry identity and source/path must match the declaration. Target, optional, and other applicable condition requirements must also match exactly; no condition or identity may be inferred or relaxed. A retained transitive target is accepted only when its uniquely identified provenance is proved by that exclusively-dev edge, while removed projection identities are reported separately. `_binding` canonicalizes the consumer root and manifest path while retaining fixed-receipt and symlink checks. This is authoring-only documentation of the audit contract, not execution evidence: no actual hashes, argv, cwd, or exit statuses from a run are available here, and none are asserted.

## Source-bound three-proof contract

`fixture/baseline/__init__.py` extracts the baseline only from pinned commit `67e10f3d836b48b954e9f82cc9ffb1d12bb1d71f` via `git archive`, checks the resolved commit, and records archive and input hashes. `prepare_sources` invokes the fixed preparation scripts with supplied local archives. The baseline and approved-route roots are separate extractions; only the approved-route root receives the exact manifest edits in `apply_route`. The candidate is the committed checkout at its recorded `HEAD`; its generated sources are verified, not edited by the route step.

The comparison requires exactly three distinct normal-consumer proofs: `baseline` and `approved_route` at the pinned base, plus `candidate` at the recorded candidate revision. Each includes locked metadata, normal-feature cargo tree, and library build artifacts with command records and hashes. `expected_control` binds the route to the baseline root-manifest hash and exact route-receipt hash. Comparison checks the observed package and feature delta against the approved-route control and requires candidate features to match that route; it does not presume a successful result. Independent reference-263 and legal gates are not waived.

This is authored verification machinery, not completed evidence: no tests, builds, or CI were executed during authoring, and no actual receipts establish success. Verification retains product build/metadata, nonzero witness inventory, isolated normal-consumer lock projection, and locked metadata/tree/build before acceptance. Source/API or package-projection limitations must be reported if observed in executed receipts; none are asserted here. These graph proofs do not establish license compliance or runtime behavior. The parent CI owns execution and acceptance.

Keep existing product pins unchanged: Tokio 1.54.1, serde 1.0.229, iroh/base/dns/noq/noq-proto/noq-udp 1.3.0, libp2p 0.57.1, Rust 1.99.1, and edition 2024.

The adapter runtime source remains unchanged; its prepared manifest adds only `package.workspace = ".."` to retain the upstream workspace and lint inheritance under the product tree. This exact difference is recorded and reversed by source verification. Lifecycle/runtime hardening is a separate sibling responsibility and is not supplied by this graph witness.

A Cargo registry dependency declaration may resolve through an approved root patch; the only permitted identities are `n0-future` 0.3.2 and `serde_bencode` 0.2.4, each with its exact registry declaration and requirement, a binding root `Cargo.toml` hash and exact patch target, the pinned archive's original/prepared inventories and recipe hashes, receipt, and target-manifest identity. Record the proof hashes. The direct-path route remains distinct and requires exact metadata path evidence; plain-registry guards are unchanged, and the historical unpatched baseline remains registry-sourced. This is a projection contract only: no passing CI or local execution is claimed.


## Compiler capture (authored CI-only recipe)

The compiler-capture wrapper recipe is pinned to Rust 1.99.1 and is intended for CI only. It creates fresh capture and target outputs for each consumer; forwards native compiler argv, inherited environment and stdio, retains per-invocation exit/context receipts and parent-command logs. It retains raw receipts with hashes for the recipe, compiler, and executable. Build records bind those identities to commits. Probes remain separate from the optional package. These are documentation requirements, not evidence of executed captures: no real receipts are verified here. CI acceptance remains pending, including platform coverage and checks of cwd and output discovery. Signal handling and inherited-stdio behavior are not yet established by harness tests; those tests do not constitute full wrapper execution.

The controlled child-transport test is authored through `forward`: it checks piped stdin/stdout/stderr, Unicode and quoted arguments, and exit status 37. Launch failure is tested separately. These tests are unexecuted CI-only coverage; authoring is not evidence that they pass.

Production audit maps Cargo primary filenames to the subset of captured outputs, validates snapshots and extern ownership via `baseline.validate_externs` (whose source location has moved), then compares normalized compiler units. Normalized units are production audit evidence. Source-only/incomplete evidence is not accepted.

Baseline positive and wrong-checksum tests are authored but unexecuted. Proc-macro host-positive and mismatched-target-ownership negative cases are also authored but unexecuted, not missing authoring. Remaining CI acceptance includes platform coverage and cwd/output-discovery checks. Snapshot/hash memory across the three output roles is O(total real output bytes); raw/enriched indexing is linear in serialized receipt bytes, in addition to Cargo artifact-matching scans; this is not a claim that the entire audit is linear. No tests or captures are claimed to have run. Legacy `artifact_features` is rejected, not ignored.

## Nested build-script capabilities

CI run `41663231359` observed a Cargo baseline exit status of 0, while the nested probe exited 1. The exact approved set is four package versions, checksum-bound, with source, argv, out-dir, and context recorded for the owning custom-build artifact and `build-script-executed` status. A failed known capability is not a launch failure. Snapshots are authoritative: auxiliary outputs at the same paths may be overwritten or deleted while ordinary outputs remain unchanged. Compare normalized auxiliary source/status/context/owner digests exactly against the control and candidate.

Authored coverage includes positive pure-shape tests for all six known auxiliary probes. Production-fixture coverage includes all six auxiliary shapes across four owners, including status and actual collector-count coverage (11). The production comparison fixture includes all six shapes. New CI 511 coverage authors a four-route-pair mutation loop with route-bound checksums, owner, source, and filenames. Runtime and per-package mutation outcomes remain unverified. All tests remain unexecuted; no acceptance or passing result is claimed.

## Cargo output aliases

Raw compiler receipts retain salted direct outputs. Cargo custom-build artifacts have `executable: null`; their `filenames` identify `build-script-build` (or `build-script-build.exe`). These aliases and the root-promoted rlib are separately proved by exact owner/args/source/context mapping. The collector compares each alias and live direct output against the retained direct snapshot, then saves independent `cargo-aliases` blobs and provenance. Replay validates the exact inventory and hashes while leaving extern owners as actual compiler outputs. An auxiliary runtime `OUT_DIR` hash may differ from its compile-owner hash.

This is authoring/source review only; tests, syntax checks, and CI were not run. Integration and platform acceptance remain pending.

## Source-bound stdin capabilities

The bounded stdin capability route is pinned to `num-traits` 0.2.19 and `autocfg` 1.5.1, with exact registry source/checksum identities. The approved route must match those exact registry checksums; names and versions alone are insufficient. Its source probes include the `empty initial` case and the exact `total_cmp` expression, with semantic probe counters 0 and 1 respectively.

Capture a raw stdin snapshot separately from `.ll` output. Stdin capture is bounded to 4096 bytes and is enabled only for the exact `stdin compile` probe, so ordinary compiler invocations and version probes do not have their stdin consumed. Preserve the direct-output exception only for a classified deletion. Semantic normalization retains source, counter, context, status, and owner while excluding the random crate nonce; this normalization is not a substitute for the raw snapshot.

Prior or latest `.ll` DATA is not retroactive evidence of stdin. A new wrapper is required to capture and bind stdin evidence. This is authoring-only documentation: no execution, CI acceptance, or integrated-test success is claimed.

## Multi-crate-type compiler targets

One compiler invocation remains one unit and retains all direct outputs. Repeated, distinct `--crate-type` values are canonicalized solely as a complete sorted set, which must match both metadata and artifact types. Missing, duplicate, unknown, empty, malformed, or mismatched types are rejected; other unique flags, identity, context, and ownership remain unchanged. Direct products need no `extra-filename` when there is no alias; alias singleton restrictions remain in force. Regression tests are authored, not executed; parent CI owns acceptance.

## Accepted SDK test-only source transition

Historical BASE `67e10f3` and its independently transformed control remain unchanged.
Delivered `70b55f4` changes only `crates/shaar/src/native_discovery/tests/codec.rs`,
behind the existing `cfg(test)` module; its 43-case native SDK suite passed on both
OS in feature CI `41772815878`. The normal source files and dependency manifests are
unchanged by that vector commit.

Only the candidate `shaar` 0.1.0 workspace binding with baseline archive
`183956ce9ae1b99245953ce3e65b76e44ea64bba5de113fc193af462ea8d4712` and exact new
source tree `59987da7663e14b9d1c8441c051a8cdcbebd497327a021b1ea7f84fdf8fe1e41`
uses historical tree `cadc863f39329a43c91fbacd34f3e0f707c5fcbe0f3b85cf0a1cedff5daddd88`
for dependency-feature/unit equivalence. The actual binding remains unmodified
in the evidence and is included in the proof digest. This is not an arbitrary
workspace-source exemption: unlisted trees, archives, roles, packages and versions
retain the original strict comparison; prepared dependency identities are unchanged.
Regressions cover this exact transition, raw-provenance digest changes and rejection
of forged bindings. Their execution and combined-SHA acceptance remain pending CI.

Windows DATA from CI `41775391999` proves the same accepted transition in exact
CRLF bytes: archive `e2fe4d5ff2a65b45848bcc128af2ef474ad9c836374763353d532a9d15f042a5`,
new tree `c0fbceaea9b9df00f45dffd55bd2057c9e549a14c1e6e5c956ef1b1c88aefde6`,
historical tree `2743b2fc2a8cef9642799d090bd6bd75dc43f63c0edef0077e8391a60a811f8a`.
The parent verified the actual archive hash, all 45 SDK source members against
fixed Git BASE with exact LF-to-CRLF conversion, and both old/new tree digests.
The second tuple is accepted as a whole, not as interchangeable archive/tree
components. No runtime newline stripping or generic source normalization occurs;
raw bindings still distinguish platform bytes. Regressions cover both tuples,
cross-pair rejection, unlisted archives and wrong-role changes on every OS.

## Reviewed multibase removal (authored, pending CI)

The product removes `base256emoji` 1.0.2 (emoji-table license/notice provenance could not be
established) via a reviewed same-version prepared patch of `multibase` 0.9.3; multiaddr keeps
working with Base58Btc, Base64, Base32Lower, Base64Url and generic multibase decode. The
recipe module `.github/probes/native-graph-multibase/prepare.py` is loaded by `prepare.py`
through the fixed-module mechanism; it pins registry archive SHA-256
`7e0e4a371cbf1dfd666b658ba137763edb23c45beb43cfe369b5593cd6b437b6`, changes exactly six files
(`Cargo.toml`, `Cargo.toml.orig`, `src/base.rs`, `src/error.rs`, `src/impls.rs`,
`tests/lib.rs`), anchors emoji lines structurally with ASCII byte escapes, and proves
exactness through the reversal check and receipt hashes. The upstream MIT license text is
retained; the modification is identified by the provenance receipt; the prepared tree and
receipt live under ignored `target/native-graph/`. Root `Cargo.toml` gains the
`[patch.crates-io]` path entry like the other native-graph patches, and the preparation action
fetches the pinned archive. The expected lock transition (multibase registry -> path with the
`base256emoji` edge dropped; `base256emoji` 1.0.2, `const-str` 0.4.3, `match-lookup` 0.1.3
removed) is produced by CI resolution only; the CI-generated candidate lock bytes are pending
and must not be invented. The committed lock shows the emoji chain is reachable only through
multibase. The three-proof comparison admits exactly this one new control-to-candidate
transition; historical BASE `67e10f3` and the pinned control lock `ab96feb` stay untouched,
and the lock-delta audit requires the chain removal to be complete and exclusive. Product
regressions in `crates/shaar-p2p/tests/multibase_base58.rs` cover base58btc PeerId text,
`/p2p/` text and binary, z-prefixed multibase decode (empty, zero-prefixed, arbitrary,
malformed), the now-failing emoji prefix, and Base64/Base32Lower/Base64Url preservation; the
CI policy selects the new integration test by its owned name and accepts a `Cargo.lock`
change together with a root `Cargo.toml` change. All of this is authored only; no tests, builds, or
CI were executed, and no passing result is claimed.

## License

This documentation is available under either the MIT License or the Apache License, Version 2.0, at your option.
