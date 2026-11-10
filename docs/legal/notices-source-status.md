# Notices Source Status — Task13 (Authentic License DATA Acquisition)

Date: 2026-11-08
Task: Task13 — notices DATA acquisition (parallel-authorized), worktree branch `notices-evidence-1108`, HEAD `a5d1e4bf9c301296c331d99de3b4e3ca5810acd6`.

Correction note (2026-11-08, second revision): corrected after independent review. Reconciles pinned-path-package identities vs registry artifacts and receipt-recorded license-material coverage from already-acquired receipts and repository history. No new network requests, downloads, or archive extraction were performed; acquired LICENSE bytes are unchanged; the acceptance criterion and recorded batch plan below are preserved verbatim.

## Purpose

Support v1 scenario distribution-readiness by acquiring a bounded batch of authentic dependency license DATA. This is evidence for the separately-gated Task14 notice assembly; it does not itself assemble or publish any notices.

## Acceptance criterion

For the two narrowly-allowed MPL-2.0 registry crates `ironwood@0.2.1` and `yggdrasil@0.3.1`, and for the pinned Yggdrasil-ng core revision `c9a54f1587bb133a06072596484c972a336db0d2`, this repository contains verbatim authentic license bytes acquired by HTTP GET from named official origins, each with recorded origin URL, byte size, and SHA-256, stored in a fresh isolated acquisition directory and preserved under `docs/legal/notices-material/`. The report additionally inventories existing local authentic evidence, states the authoritative lock identities at HEAD, and lists honest finite named gaps, without any completeness or legal-clearance claim.

## Non-goals

- No changes to maintained legal policy docs.
- No code, CI, manifest, lock, dependency, config, or version changes.
- No collector execution (the collector stays CI-only).
- No license interpretation or synthesis.
- No completeness claim for the whole dependency graph.
- No publication, upload, peers, public network use beyond the authorized batch, or smoke.

## Identity reconciliation: pinned path packages and registry artifacts

- `ironwood 0.2.1` and `yggdrasil 0.3.1` are path dependencies of the excluded nested workspace `crates/shaar-ygg-core`, bound by manifest path into the pinned Yggdrasil-ng tree at revision `c9a54f1587bb133a06072596484c972a336db0d2`; the root lock records them without registry source or checksum.
- The pinned snapshot manifests declare `ironwood 0.2.1` MPL-2.0 and `yggdrasil 0.3.1` MPL-2.0 (recorded as observed declarations, not legal determinations); the snapshot contains a single root LICENSE (MPL-2.0) and no per-crate license file under `crates/ironwood` or `crates/yggdrasil`; whether the CI-prepared `target/ygg` tree retains identical per-crate material was not verified locally.
- No evidence in this worktree links hypothetical crates.io artifacts of the same name/version to these path sources; the lock's missing registry checksums are an observed lock property, not a requirement.
- R1 and R2 (HTTP 403) are recorded as historical attempts to fetch same-name/version registry artifacts; they neither evidence nor disprove license material for the actual pinned path identities.
- Acceptance status: the pinned-revision license-material clause of the criterion is met (verbatim MPL-2.0 bytes preserved under `docs/legal/notices-material/` and hash-bound to the fresh official R3 fetch); the criterion's registry-artifact clause for `ironwood@0.2.1`/`yggdrasil@0.3.1` is not met (both requests failed) and is not determinative of the path identities' notice obligations per the points above; overall Task13 collection remains incomplete because verbatim license text for most current root-lock registry-source identities is not collected.

## Authorized batch: locations and requests

One bounded batch; at most two named official locations and ten file requests; the actual plan is 3 of max 10 requests, 2 of max 2 locations. No substitution or retry with different locations; any failure is recorded honestly.

- Location A — official crates.io distribution CDN:
  - R1: `https://static.crates.io/crates/ironwood/ironwood-0.2.1.crate`
  - R2: `https://static.crates.io/crates/yggdrasil/yggdrasil-0.3.1.crate`
- Location B — official source hosting of the pinned revision:
  - R3: `https://raw.githubusercontent.com/Revertron/Yggdrasil-ng/c9a54f1587bb133a06072596484c972a336db0d2/LICENSE`
  (purpose: bind the locally-retained pinned-revision license bytes to a fresh official URL fetch; expected sha256 `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04`)

Acquisition directory (fresh, this worktree): `.rush/downloads/notices-task13-1108-01/` (created empty; it did not pre-exist).

## Prepared-package receipt coverage (14 packages)

Legend: URL = official archive URL recorded in a local receipt; LicHash = LICENSE member sha256 recorded in a local receipt. Files observed locally without a receipt do not satisfy either column and are noted.

| Package | Version | Receipt dir(s) inspected | URL | LicHash | Local LICENSE member observed (un-receipted) |
| --- | --- | --- | --- | --- | --- |
| hickory-resolver | 0.26.3 | `p08-dns-ownership-source-1/hickory-resolver`; b930 receipt `p2p-resolver-provenance.json` | no | yes (b930 receipt: original and prepared LICENSE-APACHE `6b9522191b8cb7126b2d214edd7f782d2ccd83c467e9c03b8af9e0bf903b49b4` and LICENSE-MIT `dc470946f0a127507a9e577a20da1eb19eae0abc383b2be1f786f6427944f06c`, identical in original_files and prepared_files) | LICENSE-APACHE, LICENSE-MIT; receipt also records archive sha256 `3f3da5255c95d5a716857d54b5b8f4e8d67c3484d3beaaaae2ce25063b3ba981` + VCS revision `bd37cafbdd86112a6da32878f8c9bab22e14377e` |
| libp2p-dns | 0.45.0 | `p08-amino-source-bundle-1/libp2p-dns`; b930 receipt `p2p-dns-provenance.json` | no | no (b930 receipt records archive sha256 `18694695e98ff9ce26ee245fdede7cd0b4186cb793b25da3258d9c053400a291` + VCS revision + MIT declaration with six original files, no license-named member); a reviewed embedded-license header pin (first 1124 bytes of src/lib.rs, sha256 `22375f95ada42f478cc29687320886b83f0d59971ac6968755c12f6d95e207ca`) is recorded at commit `b930b62` in repository history (not present in the current branch tree) | none observed |
| libp2p-kad | 0.49.0 | `discovery139-kad-0490`, `kad-owner-190-20261030-01`, `p08-amino-source-bundle-1/libp2p-kad`; b930 receipt `p2p-kad-provenance.json` | no | no (b930 receipt: archive sha256 `973caa45045e53f3cf1cf3d596888b82602b30640fd75485836c81aa66e7c38a` + VCS revision, original_files enumeration contains no license-named member) | none observed |
| simple-dns | 0.12.0 | `native-record-240-1101-simpledns-01` | no | yes | (receipt covers archive members) |
| libp2p-relay | 0.22.0 | `libp2p-relay-0.22.0-archive-1`, `p08-bounded-relay-source-data-3`; b930 receipt `p2p-relay-provenance.json` | no | no (b930 receipt: archive sha256 `e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a`, no license-material hash; same hash in `p08-bounded-relay-source-data-3/provenance.json`) | none observed in extracted tree |
| n0-mainline | 0.7.0 | `native-mainline-212-1101-n0-01` | yes | yes (LICENSE-APACHE, LICENSE-MIT) | — |
| n0-future | 0.3.2 | `n0-future-0.3.2-archive-1`, `n0-future-0.3.2-source-1`, `n0-future-source-0.3.2` | no | no | LICENSE-APACHE, LICENSE-MIT |
| serde_bencode | 0.2.4 | `native-mainline-parser-251-1101-source-01` | no | no | LICENSE.md |
| iroh-dns | 1.3.0 | `native-mainline-239-1101-codec-01` | yes (`requested_url` in codec receipt) | no (codec receipt records archive sha256 `80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1`, no license-named member hash) | — |
| multibase | 0.9.3 | `multibase-0.9.3-71-01` | no | no | LICENSE |
| libp2p-swarm | 0.48.0 | `libp2p-swarm-0.48.0-archive-1`, `libp2p-swarm-0.48.0-source-1`, `p08-amino-source-bundle-1/libp2p-swarm`; b930 receipt `p2p-swarm-provenance.json` | no | no (b930 receipt: archive sha256 `57ccbe1baeaef036ffde4b265871e11c64d29464036bba635378f356bcdca854`, no license-material hash) | none observed |
| noq-proto | 1.3.0 | `noq-proto-gate-1.3.0-archive`, `noq-proto-gate-1.3.0-source`; `target-backend-provenance.json` | no | no (target-backend receipt: archive sha256 `7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f`, no license-material hash) | LICENSE-APACHE, LICENSE-MIT |
| iroh | 1.3.0 | `iroh-source-1.3.0`, `iroh-source-extract-1.3.0`; `target-backend-provenance.json` | no | no (target-backend receipt: archive sha256 `885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833`, no license-material hash) | LICENSE-BSD3 |
| noq | 1.3.0 | `noq-stream-api-1.3.0-archive`, `noq-stream-api-1.3.0-source`; `target-backend-provenance.json` | no | no (target-backend receipt: archive sha256 `b78be567e796cfa74bb9bdc4117790af2d505eb887019cf8803244353eb09d89`, no license-material hash) | LICENSE-APACHE, LICENSE-MIT |

Summary (receipt audit this revision): 3 of 14 prepared packages have receipt-recorded license-named member hashes (n0-mainline, hickory-resolver, simple-dns); 1 has a reviewed embedded-license header pin recorded in repository history at commit `b930b62` (libp2p-dns, not present in the current branch tree); 7 identities have archive-level hashes only without recorded license-material hashes (iroh-dns, libp2p-kad, libp2p-relay, libp2p-swarm, noq-proto, iroh, noq); 3 have no b930/target receipt at all (n0-future, serde_bencode, multibase — locally present archives/extracted sources are un-receipted). Shortfalls are named gaps in the Finite named gaps section below.

## New acquisition actuals

Batch executed 2026-11-08. Actual request count: 3 (3 of max 10), 2 locations used (2 of max 2).

| Req | URL | Status | Size (bytes) | SHA-256 |
| --- | --- | --- | --- | --- |
| R1 | `https://static.crates.io/crates/ironwood/ironwood-0.2.1.crate` | **403 — FAILED** | — | — |
| R2 | `https://static.crates.io/crates/yggdrasil/yggdrasil-0.3.1.crate` | **403 — FAILED** | — | — |
| R3 | `https://raw.githubusercontent.com/Revertron/Yggdrasil-ng/c9a54f1587bb133a06072596484c972a336db0d2/LICENSE` | 200 OK | 16726 | `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04` |

R1 and R2 returned HTTP 403 from the official crates.io CDN and are recorded as historical attempts; per the batch rules no retry or substitute location was attempted. Per the identity reconciliation above, these failures are not proof (positive or negative) about license material of the pinned path packages `ironwood 0.2.1` and `yggdrasil 0.3.1`. No registry `.crate` archive was acquired; `docs/legal/notices-material/` therefore contains no registry-derived license files, and nothing was substituted for any missing bytes.

## Cross-checks

- R3 fresh fetch bytes vs locally-retained pinned-tree LICENSE `.rush/downloads/yggdrasil-ng-c9a54f1-src-1/Yggdrasil-ng-c9a54f1587bb133a06072596484c972a336db0d2/LICENSE` (sha256 `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04`): **hash EQUAL, `cmp` byte-identical**.
- Material copy `docs/legal/notices-material/ygg-pinned-revision-c9a54f1-LICENSE` vs R3 bytes: **`cmp` byte-identical**, sha256 equal.
- R1/R2 extracted LICENSE members vs anything: **not testable — the crates were not acquired (HTTP 403)**.

## Existing local evidence inventory

All paths repository-relative under `.rush/downloads/` (physically in the shared ignored directory at the repository root).

| Item | Contents | Provenance strength |
| --- | --- | --- |
| `notices-b930-linux-receipts/dependency-license-list.json` | 453 keys comprising 439 registry-source identities and 14 path identities (6 workspace members + 8 [patch.crates-io] path packages; sources observed in the saved key extraction) | CI receipt (recorded run b930b62); STALE vs HEAD (see below) |
| `notices-b930-linux-receipts/{Cargo.toml, graph-receipt.json, metadata.json, p2p-{dns,kad,relay,resolver,swarm}-provenance.json, target-backend-provenance.json}` (no provenance.json in this set); `license-report-linux-40738356646/` and `license-report-windows-40738356646/` each contain provenance.json, Cargo.lock, dependency-licenses.log, metadata.json, graph-receipt.json and the same per-package receipts (older run 40738356646, 501-identity era) | CI receipts (recorded runs) |
| `native-mainline-212-1101-n0-01/source-receipt.json` | n0-mainline 0.7.0: `requested_url https://static.crates.io/crates/n0-mainline/n0-mainline-0.7.0.crate`, archive sha256 `f64972176bd209d1ebe98310743614e19728a33a4b288ae8147cca9f0b8c7463`, per-member sha256+size incl. LICENSE-APACHE (`903131e2786f073a942fbf8fae122d9e576e4dad758c6da7f9f2ba58fd8611ab`), LICENSE-MIT (`b15c26badf54093f4ad05ad947983010d2a6a1ed2f5787aef42797d521e44ccb`) | Official URL recorded + member hashes |
| `native-mainline-239-1101-codec-01/codec-source-receipt.json` + `iroh-dns-1.3.0.crate` | iroh-dns 1.3.0: `requested_url https://static.crates.io/crates/iroh-dns/iroh-dns-1.3.0.crate`; no LICENSE member hash observed in receipt | Official URL recorded |
| `native-record-240-1101-simpledns-01/source-receipt.json` + `simple-dns-0.12.0.crate` | simple-dns 0.12.0: archive sha256 `2b6f884fa9a8d48101774bfbd3aeb81e968dd22cffd19a372da69f183db22c1a`, member hashes incl. `simple-dns-0.12.0/LICENSE` (`c6550232507f928b83ef50f4be1e64c434da5ac2f434cdf9a2d89344af33e8fd`); no URL recorded in this receipt | Hash only |
| `p08-dns-ownership-source-1/` | hickory-resolver / hickory-proto / hickory-net 0.26.3 extracted sources with LICENSE-APACHE + LICENSE-MIT members; no receipt file observed | No receipt |
| `p08-amino-source-bundle-1/` | libp2p, -dns, -identify, -kad, -relay, -swarm sources (`source.crate` + `source/`); no LICENSE member or receipt observed at the inspected depth | No receipt |
| `discovery139-kad-0490/` (`source.crate`, `behaviour.rs`), `kad-owner-190-20261030-01/libp2p-kad.crate` | libp2p-kad 0.49.0 archives | No receipt |
| `libp2p-relay-0.22.0-archive-1/relay.crate`; `p08-bounded-relay-source-data-3/` (extracted `libp2p-relay-0.22.0/` + `provenance.json` with archive sha256 `e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a`; extracted tree shows NO LICENSE member) | relay 0.22.0 | Hash only (no URL) |
| `libp2p-swarm-0.48.0-archive-1/swarm.crate`, `libp2p-swarm-0.48.0-source-1/` (extracted; no LICENSE member observed) | swarm 0.48.0 | No receipt |
| `n0-future-0.3.2-archive-1/n0-future.crate`; `n0-future-0.3.2-source-1/` and `n0-future-source-0.3.2/` (extracted with LICENSE-APACHE + LICENSE-MIT) | n0-future 0.3.2 | No receipt |
| `native-mainline-parser-251-1101-source-01/` (`serde_bencode-0.2.4.crate` + extracted source with `LICENSE.md`; also noq-udp 1.1.1 material) | serde_bencode 0.2.4 | No receipt |
| `multibase-0.9.3-71-01/` (`multibase-0.9.3.crate` + extracted source with `LICENSE`) | multibase 0.9.3 | No receipt |
| `noq-proto-gate-1.3.0-archive/noq-proto-1.3.0.crate`, `noq-proto-gate-1.3.0-source/` (LICENSE-APACHE + LICENSE-MIT) | noq-proto 1.3.0 | No receipt |
| `iroh-source-1.3.0/iroh-1.3.0.crate`, `iroh-source-extract-1.3.0/iroh-1.3.0/` (LICENSE-BSD3) | iroh 1.3.0 | No receipt |
| `noq-stream-api-1.3.0-archive/noq-1.3.0.crate`, `noq-stream-api-1.3.0-source/` (LICENSE-APACHE + LICENSE-MIT) | noq 1.3.0 | No receipt |
| `yggdrasil-ng-c9a54f1-archive-1/src.tar.gz` | archive of pinned rev c9a54f1, sha256 `4d978c1a8714e0569fd0a3782adab2f6b81b9c9e54d733dbeaa023aaebae96c1`; **no acquisition receipt, original URL unrecorded** | Hash only |
| `yggdrasil-ng-c9a54f1-src-1/…/LICENSE` | MPL-2.0 text, sha256 `3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04`, only license file in the pinned tree; now **cross-checked byte-identical to fresh official R3 fetch** | Hash + fresh official fetch |
| `apache-license-165-20261028/` | project's own dual-license texts (historical task) | Historical |
| `base256emoji-notices-223-1031-01/` | provenance for a dependency REMOVED from the graph | Out-of-graph history |

## Current graph identity (HEAD `a5d1e4bf9c301296c331d99de3b4e3ca5810acd6`)

- Root `Cargo.lock`: 537 `[[package]]` entries, including 6 workspace members and 14 prepared `[patch.crates-io]` path packages: hickory-resolver 0.26.3, libp2p-dns 0.45.0, libp2p-kad 0.49.0, simple-dns 0.12.0, libp2p-relay 0.22.0, n0-mainline 0.7.0, n0-future 0.3.2, serde_bencode 0.2.4, iroh-dns 1.3.0, multibase 0.9.3, libp2p-swarm 0.48.0, noq-proto 1.3.0, iroh 1.3.0, noq 1.3.0.
- `crates/shaar-ygg-core/Cargo.lock`: 218 entries (nested standalone workspace, path deps into the pinned Yggdrasil-ng tree).
- `.github/probes/iroh-paths/Cargo.lock` (367): CI-only probe, not part of shipped identities.
- `ironwood 0.2.1` and `yggdrasil 0.3.1` are pinned path dependencies with no registry source/checksum in the lock. R1/R2 acquired no registry artifacts (HTTP 403). Even successful same-name registry downloads would establish only those registry artifacts' provenance, not equivalence to the actual pinned path sources.

### b930 staleness delta (b930 receipts vs root lock registry-source packages)

Comparing the 453 keys of `notices-b930-linux-receipts/dependency-license-list.json` (normalized to name+version) against the 513 registry-source (name, version) pairs of the root lock at HEAD:

- Added: **81** — an observed set difference between b930 keys (normalized to name+version) and the 513 registry-source (name, version) pairs of the root lock at HEAD; its composition includes crypto primitives, QUIC/TLS and HTTP stack crates, libp2p companion crates, icu/url stack and other additions, but the set difference alone does not establish which change introduced each identity, nor that each is in an activated, selected product graph (the comparison is against registry pairs only, while the b930 list mixes registry and path identities).
- Removed: **21**, audited composition: 6 workspace members (path identities excluded from HEAD registry pairs by construction of the comparison); 8 identities already patched by path at b930 (the b930 Cargo.toml lists exactly these 8 [patch.crates-io] entries: hickory-resolver, libp2p-dns, libp2p-kad, libp2p-relay, libp2p-swarm, noq-proto, iroh, noq) and still path deps at HEAD; 4 identities registry-resolved at b930 and path-patched by HEAD (simple-dns 0.12.0, iroh-dns 1.3.0, multibase 0.9.3, n0-future 0.3.2); 3 identities removed from the graph since b930 (base256emoji 1.0.2, const-str 0.4.3, match-lookup 0.1.3). `n0-mainline 0.7.0` and `serde_bencode 0.2.4` are absent from the b930 keys entirely (not yet dependencies of the recorded graph).
- Version-changed: **0** names (both sides normalized to name+version).
- Conclusion: the b930 list is not a current-graph inventory and must not be treated as current; a fresh CI license report at the current SHA remains required (Task14/CI scope).

## Finite named gaps

- (a) Verbatim license text bytes for most current root-lock registry-source identities are not collected as DATA here and no completeness is claimed. The saved extraction lists 513 (name, version) pairs with registry sources in the root lock at HEAD; local receipt- or archive-backed license material covers only the subset inventoried above, and the exact count of registry identities lacking local license-text evidence was not established in this bounded pass. Task14's CI-only collector plus distribution packaging owns bundle generation.
- (b) The b930 declared-license list is stale vs HEAD — 81 added / 21 removed set-difference identities whose composition is decomposed above; not a causal activation or completeness proof. A fresh CI license report at the current SHA remains open — Task14/CI scope, not run here.
- (c) Receipt coverage of the 14 prepared packages, per the receipt audit of this revision (3/1/7/3): receipt-recorded license-named member hashes (3): n0-mainline 0.7.0 (`native-mainline-212-1101-n0-01/source-receipt.json`, LICENSE-APACHE + LICENSE-MIT), hickory-resolver 0.26.3 (`notices-b930-linux-receipts/p2p-resolver-provenance.json`, original and prepared LICENSE-APACHE + LICENSE-MIT identical), simple-dns 0.12.0 (`native-record-240-1101-simpledns-01/source-receipt.json`, LICENSE); reviewed embedded-license header pin in repository history at commit `b930b62` (1): libp2p-dns 0.45.0 (`notices-b930-linux-receipts/p2p-dns-provenance.json`; pin not present in the current branch tree); archive-level hash only, no license-material hash (7): iroh-dns 1.3.0 (`native-mainline-239-1101-codec-01/codec-source-receipt.json`), libp2p-kad 0.49.0, libp2p-relay 0.22.0, libp2p-swarm 0.48.0 (all `notices-b930-linux-receipts/p2p-*-provenance.json`), noq-proto 1.3.0, iroh 1.3.0, noq 1.3.0 (all `notices-b930-linux-receipts/target-backend-provenance.json`); no b930/target receipt at all (3): n0-future 0.3.2, serde_bencode 0.2.4, multibase 0.9.3 (archives/extracted sources locally present but un-receipted). Audited receipts this revision: `p2p-{resolver,dns,kad,relay,swarm}-provenance.json` and `target-backend-provenance.json` (b930 set), `codec-source-receipt.json` (iroh-dns), `source-receipt.json` (n0-mainline), `source-receipt.json` (simple-dns); other `.rush/downloads` directories were not exhaustively audited in this pass.
- (d) The pinned Yggdrasil-ng archive (`yggdrasil-ng-c9a54f1-archive-1/src.tar.gz`) lacks an acquisition receipt (original URL unrecorded); mitigated by the recorded revision + archive hash + the successful R3 fresh official fetch cross-check (byte-identical).
- (e) R1/R2 (HTTP 403) are historical attempts and do not, per the identity reconciliation, establish missing license material for the pinned path packages `ironwood 0.2.1` and `yggdrasil 0.3.1`, whose top-level MPL-2.0 material is preserved and hash-bound. Genuine remaining gaps: verbatim text for most registry identities (gap (a)); per-crate license material inside the CI-prepared `target/ygg` tree (not locally verifiable from the pinned snapshot, which has only the root LICENSE); a fresh CI license report at the current SHA (gap (b)).
- (f) Historical evidence is era-stale: license-report-*40738356646 reflects the attohttpc 0.30.1 era (501 identities); `base256emoji-notices-223-1031-01` concerns a dependency now removed from the graph.

## Provenance limits and honesty

- No machine-private absolute paths are used in this report; all evidence paths are repository-relative.
- This report makes NO claim of legal clearance and NO claim of complete dependency notices.
- Hashes and byte sizes were recorded by local non-executing tooling (`sha256sum`, `cmp`, `ls -l`).
- All downloaded material is untrusted DATA: it was only hashed, compared, and copied verbatim; nothing downloaded was executed or interpreted.
- No license interpretation, synthesis, or rights-holder contact occurred; only verbatim bytes and recorded facts appear here.

## Batch execution log (ordered, non-executing steps only)

1. Report skeleton written before any network request (this file's first sections).
2. Acquisition directories created fresh: `.rush/downloads/notices-task13-1108-01/crates-io/` (empty — never populated) and `.rush/downloads/notices-task13-1108-01/ygg-pin/`.
3. R1 (crates.io CDN, ironwood) → HTTP 403, no bytes. R2 (crates.io CDN, yggdrasil) → HTTP 403, no bytes. R3 (raw.githubusercontent.com, pinned-revision LICENSE) → HTTP 200, 16726 bytes, saved as `ygg-pin/LICENSE`.
4. Hashing (`sha256sum`) and byte comparison (`cmp`) of R3 vs pinned-tree LICENSE → identical.
5. Verbatim copy R3 → `docs/legal/notices-material/ygg-pinned-revision-c9a54f1-LICENSE`; `cmp` re-verified identical.
6. b930-vs-HEAD delta computed with `awk` + `jq` only (no interpreter run); inventory and gap sections appended.
7. No archive extraction occurred (no archives acquired); no file in `crates-io/` exists.

## Commands and evidence (key outputs, brief)

- `git rev-parse HEAD` → `a5d1e4bf9c301296c331d99de3b4e3ca5810acd6`.
- HTTP GET ×3 via the authorized download tool (crates.io CDN ×2 → 403; raw.githubusercontent.com LICENSE → 200, 16726 bytes).
- `sha256sum` on R3 bytes, pinned-tree LICENSE, and the material copy → all `3f3d9e00…b9d04`.
- `cmp` R3 vs pinned-tree LICENSE → identical; `cmp` material copy vs R3 → identical.
- Root lock registry pairs: `awk` over `Cargo.lock` `name`/`version`/`source = "registry` → 513 pairs; b930 keys via `jq -r 'keys[] | split(" ") | .[0]+" "+.[1]'` → 453; set differences via `awk` → added 81 / removed 21 / version-changed 0.
- `ls`/`grep` over `.rush/downloads/` receipt dirs for `*receipt*`, `provenance*`, LICENSE members (observations recorded in the inventory above).

## Current corpus pass — 2026-11-09

This bounded pass records its criterion before adding any findings. Scope is this repository/worktree only: branch `notices-corpus-1109`, HEAD `20b601c2d8187e63355dfd8e9c7fe7785d576867`. The preceding inventory is historical evidence for branch `notices-evidence-1108` at `a5d1e4bf9c301296c331d99de3b4e3ca5810acd6`; it is not relabeled as a current-HEAD audit.

### Observable criterion and boundary

For the exact committed root and nested locks at this HEAD, maintain a reproducible inventory keyed by source identity, package name, version, and checksum where Cargo records one. For every path/prepared package, distinguish the lock's path identity from its resolved source and require a traceable mapping to the original archive/source, preparation receipt and prepared tree before calling provenance covered. Classify evidence separately as (1) authentic complete license/notice text with a verified source/hash, (2) held source/archive DATA potentially reusable after receipt and byte-level review, or (3) a genuine current-corpus text or provenance gap. This supports notices readiness for distribution of the existing end-to-end scenario steps 1–6; it is not new product work. This entry is an inventory and gap record only: it does not claim acceptance or CI for this new pass.

### Current lock identity observations

A non-executing standard-library TOML reader read the committed lock bytes. Root `Cargo.lock` SHA-256 is `ae186edff0a2fad29ffc4d6f4590a79a975a5ef6112c34606c6d5361be9c0597` (537 entries: 513 registry entries, all with checksum, and 24 path entries). Nested `crates/shaar-ygg-core/Cargo.lock` SHA-256 is `da64aa9e56683f5856ed5440a597a7d600b2c3ee5262b98de4aef024f85b5fe4` (218 entries: 215 registry entries, all with checksum, and 3 path entries). Deduplicating by the exact recorded source/name/version/checksum tuple gives 557 identities across the two locks: 533 registry identities and 24 path identities; 198 identities occur in both locks. Thus the registry inventory is reproducible from these exact lock bytes, not from the older b930 report.

Cargo lock entries do not encode a source path or checksum for path packages. The root lock's 24 path entries comprise six root workspace members, standalone first-party `shaar-ygg-core`, and 17 third-party path identities: 14 patched packages, generated adapter `iroh-mainline-address-lookup@0.6.1`, and pinned `ironwood@0.2.1` / `yggdrasil@0.3.1`. The nested lock has standalone first-party `shaar-ygg-core` and the same two pinned Yggdrasil path identities. Registry and path identities remain distinct even where names and versions coincide.

### Verified inventory summary

The inventory JSON DATA preserve the exact finite identities, source kinds, registry checksum and root/nested lock membership, classification, archive/material hashes and receipt references. Paths inside the inventories are repository-relative for preserved material and relative to the primary `.rush` service DATA root for held archives/receipts. Do not treat inventory rows as a legal or artifact-inclusion determination.

| Corpus | Identities | Current evidence classification |
| --- | ---: | --- |
| Registry source, root and nested lock union | 533 (root 513; nested 215; shared 195; root-only 318; nested-only 20) | 15 with complete authentic original text; 2 with partial README license references only; 1 exact-checksum archive with no full license text; 515 with no matching archive in the bounded audited DATA |
| Third-party path source | 17 (14 patches, generated `iroh-mainline-address-lookup`, pinned `ironwood` and `yggdrasil`) | 15 have complete package-level authentic original text; `iroh@1.3.0` has only component-scoped LICENSE-BSD3 text for Tailscale-derived portions and lacks complete package-level MIT OR Apache-2.0 terms; `iroh-dns@1.3.0` has no full text and lacks complete package-level MIT OR Apache-2.0 terms |
| Third-party union | 550 | 30 identities with complete package-level authentic original text; 520 without complete package-level terms (515 registry identities with no matching archive in bounded audited DATA, 3 registry identities with partial/no full text, and path gaps `iroh@1.3.0` and `iroh-dns@1.3.0`) |

First-party exclusions are six root workspace members plus standalone `shaar-ygg-core`; the generated adapter is third-party prepared source, not first-party. The pinned Yggdrasil root LICENSE is one authentic shared text for both pinned path identities, not two copied material files. This table reports original-text classification only; it does not imply archive provenance or completeness of prepared trees.

The registry identity set represents 533 exact source/name/version/checksum tuples: 15 have complete authentic original text, 2 only partial README evidence, 1 has a checksum-matched archive but no full text, and 515 have no matching archive in the bounded audited DATA. These status counts do not claim global archive absence or graph/legal completeness. `registry/inventory.json` is 314,094 bytes, SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`; `prepared/inventory.json` is 61,861 bytes, SHA-256 `1ca625be945859b9607c5203fd1fa86685b3db41ebfebcbee63cf7cac79df090`. Prepared-source counts distinguish 16 material-bearing identity rows from 15 rows with complete package-level terms, 1 component-text-only row (`iroh@1.3.0`), and 1 row without verbatim text (`iroh-dns@1.3.0`); there are 2 path rows without complete package terms. The previous prepared inventory input to the prior DATA pass had SHA-256 `7738cf6f5e654645b2e323b39ef00f0a41e60d8ac01c27f125bdca1289e98fc6`; it is historical pre-correction metadata, not the current inventory digest. The full exact identity membership and current classifications remain in JSON rather than duplicating 533 registry rows here.

Preserved registry material totals 23 files / 83,839 bytes (16 whole license/notice members, 5 complete embedded MIT headers, 2 partial README references). The wrapper adds full-text identity `n0-watcher@1.0.0` and two preserved complete license members (10,831 + 1,048 bytes). The inventory records its outer wrapper as 34,029 bytes / SHA-256 `007a252b7101ce0f667eb0d4e05b16aa356dd9192eac4c631fdf5c9bf0f5717d`; the single-layer decoded 33,999-byte inner `.crate` has SHA-256 `bbc618745ad0b7414b149d0517ad8b5573b2fb4d4e2717add3d2446ce1fdd826`, equal to the Cargo lock checksum. The inner manifest name/version was checked before classification. The orchestrator independently verified the outer/inner bytes and all 43 new material assets against primary `.rush/downloads` archives and available receipts, and verified the pinned shared-license equality. The gzip wrapper is additional to the 54-file `.crate` extension scan and its outer hash is not a Cargo checksum. Prepared-source material adds 20 files / 82,613 bytes. Together, the two new material directories contain 43 files / 166,452 bytes, plus the two inventory JSON files; the pinned Yggdrasil root LICENSE remains unchanged and is referenced once by both pinned identities. Full current prepared-tree equality remains unproven for the specifically listed limits; these observations do not claim distribution completeness or legal clearance.

| Prepared-source evidence boundary | Identities / finding |
| --- | --- |
| Original authentic text retained and hash-matched to held source archive for material-bearing path identities; current prepared-file equality is separate | 16 of 17 have retained material; 15 have complete package-level terms, `iroh@1.3.0` has component-only LICENSE-BSD3 text scoped to Tailscale-derived portions, and `iroh-dns@1.3.0` has no full text |
| Current prepared-file equality remains specifically unresolved | `libp2p-dns` embedded header; `libp2p-relay` and `libp2p-swarm` embedded headers; `simple-dns` LICENSE; `iroh` LICENSE-BSD3; both `noq-proto` files; both `noq` files |
| Prior saved recipe evidence with original/prepared hash equality, but not current green-prepared-byte attestation | `n0-future`, `n0-mainline`, `serde_bencode`, `multibase` |
| Acquisition origin URL absent from most prepared-source receipts | Archive digest binding is recorded, but origin is not; this is distinct from byte equality/authentic original text |

The shared pinned root LICENSE is explicitly archive-member/original/prepared hash-equal for both `ironwood@0.2.1` and `yggdrasil@0.3.1`; no per-crate LICENSE copy is inferred or required by this evidence. Registry and prepared-source records preserve archive-hash binding separately from acquisition-origin evidence. Full authentic original text does not imply a complete current prepared-tree provenance chain.

### Finite gaps and gated next step

The bounded registry `.crate` scan inventories 54 files / 37 distinct payloads / 4,793,980 compressed bytes; its separate gzip-wrapper follow-up is not included in those extension-scoped totals. The proposed registry archive tranche is exactly 515 one-time crates.io GETs for identities with no checksum-matched archive in the bounded audited DATA, using exact lock-checksum verification and URL-encoded package components (including `+` as `%2B`), with no retries/substitutions and stop caps of 64 MiB per object / 1 GiB aggregate. These are caps, not an estimate or completion guarantee.

The following table lists four registry raw-source candidates, proposal-only and unverified at the exact paths; each would require separate authorization for one GET capped at 64 KiB, 256 KiB total, with no retry, fallback or crawl.

| Identity | Candidate revision and raw paths (unverified) |
| --- | --- |
| `iroh-base@1.3.0` | `https://raw.githubusercontent.com/n0-computer/iroh/0072d7d84b233f9e7185eb676f049beaf557ac03/iroh-base/LICENSE-APACHE`; `https://raw.githubusercontent.com/n0-computer/iroh/0072d7d84b233f9e7185eb676f049beaf557ac03/iroh-base/LICENSE-MIT` |
| `netwatch@0.19.3` | `https://raw.githubusercontent.com/n0-computer/net-tools/0030e57fc70981895bb86212ff0f059cc41c8a4e/netwatch/LICENSE-APACHE`; `https://raw.githubusercontent.com/n0-computer/net-tools/0030e57fc70981895bb86212ff0f059cc41c8a4e/netwatch/LICENSE-MIT` |

The path-source gap `iroh-dns@1.3.0` has README/VCS evidence naming candidate `LICENSE-APACHE` and `LICENSE-MIT` under `n0-computer/iroh`, revision `17c0612f80f78f5288e97b818b1360ae6ea0a51a`, path `iroh-dns`; the two candidate raw URLs are `https://raw.githubusercontent.com/n0-computer/iroh/17c0612f80f78f5288e97b818b1360ae6ea0a51a/iroh-dns/LICENSE-APACHE` and `https://raw.githubusercontent.com/n0-computer/iroh/17c0612f80f78f5288e97b818b1360ae6ea0a51a/iroh-dns/LICENSE-MIT`. Its package-level MIT OR Apache-2.0 terms are missing. Together, the four registry candidates and two `iroh-dns` path candidates are six proposal-only raw-file candidates, each capped at 64 KiB (384 KiB aggregate) if separately authorized; none was requested, and no retry, fallback, or crawl occurred. Separately, `iroh@1.3.0` lacks complete package-level MIT OR Apache-2.0 terms: the held LICENSE-BSD3 remains authentic component notice text scoped only to Tailscale-derived portions. No URL request or acquisition is proposed for this bounded correction.

`prost-codec@0.4.0` has a held exact-checksum archive but no license text; it is associated with pinned `libp2p/rust-libp2p` revision `7171dce2f90c05ba7892d4ba926abb1881db27c7`, yet its exact license path is unresolved, so no URL request is proposed. No other checksum-matching archive was found in the bounded audited DATA for the 515 `missing_archive` registry rows; this is not a global absence claim. Extracted source DATA for `iroh-base`, `netwatch`, and `prost-codec` were inventoried but yielded no additional complete text. The prepared-tree equality gaps above require source/preparation receipt review or authorized current CI evidence, not blanket reacquisition. Most prepared-source archive acquisition URLs are absent from retained receipts. No acquisition/network activity occurred in this pass; authorization for any proposed candidate requests remains separate.

### Historical acceptance and non-goals

The historical change `ebf429bff58e38a13973f6f89c0d0aa2debfd141` and CI run `42481654381` remain explicitly accepted and unchanged. The limitations in the preceding `a5d1e4b` pass are historical scope/evidence limits, not a retroactive invalidation of that acceptance. This pass records documentation and DATA verification only; it does not claim new Task13 acceptance or CI, legal clearance, complete dependency notices, artifact inclusion, or distribution authorization. No local tests/builds/Cargo/project Python, acquisition/network, generator or Task14 work, CI/product/lock/policy changes, or new top-level asset is part of this entry.

## Task13/N1 bounded registry handoff — 2026-11-10

This append records the later, finite registry DATA pass against input HEAD `79e36e2aa77b0aa669dc58d91318427edce5db71`. The preceding sections, including their dated criteria, historic counts and limitations, remain historical and are not rewritten or relabeled. The authoritative pre-pass registry inventory input was 314,094 bytes with SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`; the worker-handoff inventory was 2,348,869 bytes with SHA-256 `61fb571b9400015f52d9b0a5ffbf01b4f7373300b692da8e90e8b2c8fbc6ffc0`. The primary metadata correction below supersedes that inventory digest, not its authentic material bytes.

### Observable criterion and scope

For the exact root and nested lock identities at the stated input HEAD, retain and map authentic license/notice or contextual bytes actually present in the exact authorized archive tranche; bind each selected material to its recorded lock identity, receipt URL/checksum, archive member and exact byte range; preserve all pre-existing material; distinguish package-scope terms from component text, references and unresolved cases. The observable replay contract is that the read-only DATA reader validates these relationships and prints the current inventory's exact byte count and SHA-256 along with the finite corpus totals. This supports notices evidence for distribution-readiness of the existing north-star scenario steps 1–6 only. It is not runtime/Task14 work, a new acquisition or policy campaign, legal clearance, OR-expression election, complete product notice determination or distribution permission.

### Bounded archive and preserved-material result

The completed authorized input is the 243,217-byte receipt (`f88dd58897b88c2a964c6b6d00ba5e7ca6c2109c70680a98f7e76124f00b4ff1`) and 515 exact URLs / archives under `../../.rush/downloads/notices-registry-authorized-1109/`; its checksum-bound URL and archive-member map remains in `registry/inventory.json`, not duplicated here. The parent’s completed current replay reports 515 verified unique URLs, 82,340,789 compressed bytes, 693,829,632 decoded tar bytes and 27,435 members, with zero omitted legal-named archive members. The independent parent comparison reports all 892 new preserved material files (4,414,088 bytes) byte-equal to their exact archive members/slices. Code/tooling files that merely matched copying/license filename searches were excluded. Current material roles are 796 package-terms, 12 embedded, 18 component, 43 legal-context and 23 reference. Three `netlink-packet-route` rows were promoted from legal-context to terms; this is reflected in those current role totals.

The earlier 18 registry rows and 46 pre-existing tracked files (material assets, inventories, attributes and the pinned license) remain byte-equal to HEAD; the prepared inventory remains unchanged. The parent source-replayed the 892 new assets and separately verified the 43 pre-existing assets byte-identical to HEAD; prior-pass source verification is historical evidence, not a new replay of those old archives. The resulting registry material set is 915 files / 4,497,927 bytes (old plus new); combined with 20 prepared files, the 935 preserved assets total 4,580,540 bytes. The separate pinned Yggdrasil LICENSE (16,726 bytes) remains unchanged and is not included in those asset totals. New grouped supplements stay under the five existing registry alpha-prefix groups; no new top-level asset was introduced, and the checked maximum direct registry directory fanout is six. Exact source URLs, receipt indices, per-file digests and member/slice mappings are retained in the inventory rather than restated as 892 rows here.

### Current finite classifications

For the 515 newly matched registry archives, the current pass classifies 478 package-complete, 9 missing selected material, 24 reference-only, 2 component-only and 2 review-gap. Together with the 18 preserved earlier registry rows, the full registry inventory now classifies 493 of 533 identities as package-complete, 2 component-only, 26 reference-only, 2 review-gap and 10 with no selected full terms. Thus 40 registry identities remain incomplete under this evidence classification. The extra old rows are `iroh-base@1.3.0` and `netwatch@0.19.3` (reference-only), and `prost-codec@0.4.0` (held exact-checksum archive, no full license text). “Missing” means no selected text in this bounded pass, not that terms do not exist; README/context references are not operative terms; component-only does not establish package-scope terms; review-gap remains unresolved.

The nine newly missing-selected-material identities are `asn1-rs-impl@0.2.0`, `futures-bounded@0.3.0`, `iroh-metrics-derive@1.0.1`, `n0-error-macros@1.0.1`, `rustls-platform-verifier-android@0.2.0`, `rw-stream-sink@0.5.0`, `winapi-i686-pc-windows-gnu@0.4.0`, `winapi-x86_64-pc-windows-gnu@0.4.0` and `yamux@0.14.1`. The 24 new reference-only identities are `base45@3.2.0`, `block2@0.6.2`, `dispatch2@0.3.1`, `dlopen2@0.8.2`, `enum-assoc@1.4.1`, `gloo-timers@0.3.0`, `gloo-timers@0.4.0`, `if-watch@3.2.2`, `jni-macros@0.22.4`, `jni-sys-macros@0.4.1`, `jni@0.22.4`, `ndk-context@0.1.1`, `objc2-core-foundation@0.3.2`, `objc2-core-wlan@0.3.2`, `objc2-encode@4.1.0`, `objc2-foundation@0.3.2`, `objc2-security-foundation@0.3.2`, `objc2-security@0.3.2`, `objc2-system-configuration@0.3.2`, `objc2@0.6.5`, `pharos@0.5.3`, `uint@0.10.2`, `valuable@0.1.1` and `yasna@0.5.2`. The component-only registry rows are `iroh-relay@1.3.0` and `ring@0.17.14`; review gaps are `r-efi@5.3.0` and `r-efi@6.0.0`.

Across 17 third-party path identities, 15 remain package-complete and 2 do not: `iroh@1.3.0` has component-only BSD-3 text for Tailscale-derived portions, not complete package MIT OR Apache-2.0 terms; `iroh-dns@1.3.0` has no full terms. The combined 550 third-party identities therefore classify as 508 package-complete and 42 incomplete. Attohttpc MPL-2.0 text availability is recorded as evidence only, not new policy acceptance. Available alternatives remain individually evidenced; this corpus does not choose an OR alternative or clear any package legally.

### Reader, bounds and execution limits

The repeatable read-only command is:

```sh
python -I docs/legal/notices-material/registry/replay.py .
```

An optional second argument supplies the primary downloads root. The reader uses only committed inventory/lock/material DATA and the held receipt-bound 515 archives; it does not read scratch selections or report inputs. It uses only Python standard-library modules, reads archives and manifests as bounded DATA, writes no files, and imports no project/repository module. Its caps are 64 MiB compressed per archive / 1 GiB compressed aggregate, 256 MiB decoded per archive, 2 GiB decoded aggregate, 32 MiB per regular member, 4 MiB per selected evidence member, 128 MiB selected evidence aggregate, 20,000 members per archive and 250,000 total members. It rejects unsafe paths, links/special members and normalized duplicates; it does not use `extractall`. The parent reran the reader and standalone AST syntax check: both PASS; the reader is 421 lines. The current parent replay is `call_13adf808888d4c85b7a0403167c73f28` (batch `cd2ad350-f7c2-4e2f-9ec5-294023801ce9`); it reports the inventory size/hash stated above, 892 new source-equal rows and 23 old hash-preserved rows. This is not a claim that project tests/CI ran. No local build, test, Cargo command, project Python, network request, source execution/import, or git write is claimed here.

### Process-boundary caveat

This is not a claim that every worker action stayed inside its assigned worktree. The first survey included 322 stale matching-lockfile rows; the parent caught and excluded them, and lockfile membership was not derived from that survey. A prefix-tree review job `f5552f3c` did not terminate and was stopped; signature-based classifications from that review were not accepted, and the subsequent review used actual bytes. During integration a worker accidentally wrote the primary read-only registry (890 assets plus inventory), then used its clean-root DATA script to restore the HEAD inventory and remove created supplements before the proper worktree integration. The parent observed the primary clean at `20c385b`; this later cleanup does not undo or erase the earlier boundary violation. Cleanup used no git writes (read-only `git show` only), but the entire execution is not described as worktree-only. Parent preflight reports that recursive Rush session/lock inspection and `git worktree list` were blocked by available tools and made no state changes.

Associated records: review `431c900a-bf0f-4e0b-996a-749d5c1b0653$$call_9456e5f937144053a07048fd23a464d3`; integration `ae5e1639-9324-44c7-88bd-70b4217476d5$$call_36ba8adb70754f9bada81430906df5b8`; metadata `e4518bde-c1cd-4bd3-8e30-2b595d461606$$call_9ad3f700a33949bb97263be3b0289887`. The earlier accessible worker artifact `call_14682d5173f04345af07c3080d5b2c63` records worker `b75a4cac`’s prior replay, not the final parent replay. The current parent replay is `call_13adf808888d4c85b7a0403167c73f28` (batch `cd2ad350-f7c2-4e2f-9ec5-294023801ce9`). This handoff does not claim CI, full Task13 acceptance, legal clearance, or distribution permission; unresolved named cases and existing prepared-tree equality limits remain open.

### Identity and unchanged-input check

The root/nested registry identity tuple set remains exactly 533: root 513, nested 215, shared 195, root-only 318 and nested-only 20. All 533 registry identities now have a checksum-matched held archive (zero missing archive); the new tranche covers the 515 prior missing-archive identities. The earlier 18 registry rows retain equality and their old material hashes are preserved. The prepared inventory remains exactly 61,861 bytes with SHA-256 `1ca625be945859b9607c5203fd1fa86685b3db41ebfebcbee63cf7cac79df090`. The standalone reader is 421 lines, below the 700-line code-file ceiling. Its output computes and prints the current registry inventory size/hash at replay time; the completed parent replay reported the current inventory digest/size recorded above.


## Primary review correction — 2026-11-10

The preceding N1 replay statements describe the worker-handoff metadata, not execution against this correction. Primary independently read the retained `aws-lc-sys@0.46.0` root LICENSE: its s2n-bignum section explicitly names MIT-0 as an applicable alternative and its MIT No Attribution section contains the complete grant and disclaimer. The MIT-0 alternative now binds that exact existing material as available; no OR alternative is elected and no authentic bytes changed. `historical_pre_n1_metadata.material_search` was restored exactly from the accepted pre-pass inventory rather than retaining the current-pass description.

The corrected registry inventory is 2,349,163 bytes, SHA-256 `93cbbe75a0967172695898e0bbf5b0b67b70c7e2cb2f349a81b0e4fdf9f2ddb3`. Package classification totals remain unchanged: 493/533 registry and 508/550 combined identities classified package-complete, with 40 registry / 42 combined incomplete identities. These are source-text availability classifications, not legal clearance or distribution permission.

Primary independently inspected all 515 receipt-bound archives using a separate isolated standard-library DATA reader and compared all 892 new materials byte-for-byte with their exact members/slices: 4,414,088 preserved bytes, 693,829,632 decoded bytes and 27,435 members; directory limits passed. The first invocation of that independent reader stopped at a Python string-literal syntax error before inspecting inputs; the corrected invocation passed. Primary did not run or import the maintained replay reader or project tests. This correction is not yet CI-verified.

The primary-read-only breach and the worker's unauthorized restoration/deletion remain process violations. Primary subsequently verified a clean main checkout and exact equality of its legal tree with accepted `79e36e2`; registry inventory remained 314,094 bytes with SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`. No claim of fully compliant historical execution is made. No further notices worker was launched for this correction; primary owns the remaining dirty worktree and its disposition. Full Task13, prepared-tree provenance, legal clearance and release remain unaccepted.
