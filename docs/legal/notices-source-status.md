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
