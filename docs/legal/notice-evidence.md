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

## Bounded retained-source inventory (2026-11-09; DATA only)

The orchestrator independently verified all 43 new material assets against primary `.rush/downloads` source archives and available receipts, and verified the pinned shared-license equality. Current full prepared-tree equality remains unproven for the named limits below. No project tests, CI, or new Task13 acceptance are claimed.

### Reproducibility and bounded local DATA checks

The following `python -I` standard-library DATA reader snippets were executed in the prior pass; the transcript records exit status 0 for each of the four readers. They check lock identities, inventory digests/classifications, preserved-file size/hashes, and archive-to-material slices. They read DATA with bounded reads only; they do not import project Python, extract archives to disk, execute source, access the network or invoke Cargo. The inventory digest reported by that prior pass is the pre-correction input digest; this correction changes inventory metadata only, not preserved material bytes. The independent replay recipe below documents the prior-pass check against primary service DATA.

```sh
python -I -c 'import pathlib,tomllib,hashlib,stat; root=pathlib.Path(".")
def bounded(path,cap):
 st=path.lstat(); assert stat.S_ISREG(st.st_mode) and st.st_size<=cap,path
 with path.open("rb") as f:
  b=f.read(cap+1); assert len(b)<=cap and len(b)==st.st_size and f.read(1)==b"",path
 return b
locks=("Cargo.lock","crates/shaar-ygg-core/Cargo.lock"); rows=[]
for rel in locks:
 raw=bounded(root/rel,4*1024*1024); ps=tomllib.loads(raw.decode("utf-8"))["package"]; ids={(p.get("source","path"),p["name"],p["version"],p.get("checksum")) for p in ps}; print(rel,len(raw),hashlib.sha256(raw).hexdigest(),len(ps),len(ids),sum(p.get("source","").startswith("registry+") for p in ps),sum(p.get("source") is None for p in ps)); rows.append(ids)
reg=[{x for x in s if x[0].startswith("registry+")} for s in rows]; print("registry union/intersection/root-only/nested-only",len(reg[0]|reg[1]),len(reg[0]&reg[1]),len(reg[0]-reg[1]),len(reg[1]-reg[0]))'
```

Observed: root lock 537 entries, 24 path / 513 registry; SHA-256 `ae186edff0a2fad29ffc4d6f4590a79a975a5ef6112c34606c6d5361be9c0597`. Nested lock 218 entries, 3 path / 215 registry; SHA-256 `da64aa9e56683f5856ed5440a597a7d600b2c3ee5262b98de4aef024f85b5fe4`. Exact registry identity union is 533; intersection 195, root-only 318, nested-only 20. Combined lock identity union is 557, including 24 distinct path identities. The 17 third-party path identities are 14 patches, generated `iroh-mainline-address-lookup@0.6.1`, and pinned `ironwood@0.2.1` / `yggdrasil@0.3.1`; first-party exclusions are six root workspace members plus standalone `shaar-ygg-core`.

```sh
python -I -c 'import pathlib,json,hashlib,collections,stat; b=pathlib.Path("docs/legal/notices-material")
def bounded(path,cap):
 st=path.lstat(); assert stat.S_ISREG(st.st_mode) and st.st_size<=cap,path
 with path.open("rb") as f:
  raw=f.read(cap+1); assert len(raw)<=cap and len(raw)==st.st_size and f.read(1)==b"",path
 return raw
rraw=bounded(b/"registry/inventory.json",1024*1024); praw=bounded(b/"prepared/inventory.json",1024*1024); r=json.loads(rraw); p=json.loads(praw); print("registry inventory",len(rraw),hashlib.sha256(rraw).hexdigest()); print("registry classes",dict(collections.Counter(i["classification"] for i in r["identities"]))); print("registry counts",json.dumps(r["counts"],sort_keys=True)); print("prepared inventory",len(praw),hashlib.sha256(praw).hexdigest()); print("prepared material totals",json.dumps(p["scope"]["material_totals"],sort_keys=True)); print("wrapped archive",json.dumps(r["wrapped_archive_scan"],sort_keys=True))'
```

Observed registry inventory: 314,094 bytes, SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`; 15 `preserved_complete_text`, 2 `reusable_archive_missing_full_text_partial_evidence`, 1 `reusable_archive_missing_full_text`, 515 `missing_archive`. Root/nested membership: 513 / 215 / 195 shared / 318 root-only / 20 nested-only. Current prepared inventory: 61,861 bytes, SHA-256 `1ca625be945859b9607c5203fd1fa86685b3db41ebfebcbee63cf7cac79df090`; prior-pass input digest `7738cf6f5e654645b2e323b39ef00f0a41e60d8ac01c27f125bdca1289e98fc6` was historical pre-correction metadata. There are 17 path identities, 20 new files / 82,613 bytes, 16 material-bearing rows, 15 with complete package-level terms, 1 component-text-only `iroh@1.3.0` row (LICENSE-BSD3 scoped only to Tailscale-derived portions; package MIT OR Apache-2.0 terms missing), and 1 no-verbatim-text `iroh-dns@1.3.0` row; 2 path identities lack complete package terms. The inventory's wrapped-archive record distinguishes the outer wrapper from decoded `.crate` bytes for `n0-watcher@1.0.0`; the orchestrator independently verified wrapper/inner bytes. Do not compare the outer wrapper hash to Cargo's checksum. Prior-pass local readers inspected then-current inventory DATA only.

```sh
python -I -c 'import pathlib,json,hashlib,stat; root=pathlib.Path("."); b=root/"docs/legal/notices-material"
def bounded_rel(rel,cap):
 path=pathlib.PurePosixPath(rel); assert not path.is_absolute() and all(x not in ("",".","..") for x in path.parts),rel
 f=root
 for x in path.parts:
  f=f/x; st=f.lstat()
  if x==path.parts[-1]: assert stat.S_ISREG(st.st_mode) and st.st_size<=cap,rel
  else: assert stat.S_ISDIR(st.st_mode),rel
 with f.open("rb") as stream:
  raw=stream.read(cap+1); assert len(raw)<=cap and len(raw)==st.st_size and stream.read(1)==b"",rel
 return raw
def json_bounded(rel): return json.loads(bounded_rel(rel,1024*1024))
r=json_bounded("docs/legal/notices-material/registry/inventory.json"); p=json_bounded("docs/legal/notices-material/prepared/inventory.json"); refs=[]
for i in r["identities"]:
 for m in i.get("materials",[]): refs.append(("docs/legal/notices-material/registry/"+m["material_path"],m["material_bytes"],m["material_sha256"]))
for i in p["identities"]:
 for m in i.get("materials",[]): refs.append((m["preserved_path"],m.get("bytes",m.get("slice",{}).get("bytes")),m.get("sha256",m.get("slice",{}).get("sha256"))))
seen={}; total=0
for rel,n,h in refs:
 assert n<=4*1024*1024; raw=bounded_rel(rel,4*1024*1024); assert len(raw)==n and hashlib.sha256(raw).hexdigest()==h,rel; assert rel not in seen or seen[rel]==h; seen[rel]=h; total+=n
print("material records/files/bytes",len(refs),len(seen),total)'
```

The prior pass's successful bounded readers observed 43 preserved material files, 43 inventory material records, 166,452 bytes; each file matched recorded size and SHA-256. This correction did not modify material assets. The historical source-status prefix (first 164 lines) remains byte-identical (24,608 bytes; SHA-256 `14521245b305716280637fa7441e504b7b94b4c51ce18be6aa03adbd8282f8b1`); the notice-evidence prefix (first 21 lines) remains byte-identical (3,198 bytes; SHA-256 `aa99447439d8c94a2a979aff4760a1460ccf54ab852334faa843f7db68fc403d`). The orchestrator reports its independent source-archive/receipt verification. These are DATA checks, not project tests, CI, full current prepared-tree equality proof, or Task13 acceptance.

Current inventory totals are 30 of 550 third-party identities with complete package-level authentic original text and 520 without complete package-level terms: 515 registry identities with no matching archive in the bounded audited DATA, 3 registry identities with partial/no full text, and path gaps `iroh@1.3.0` (component-text-only: its LICENSE-BSD3 notice is scoped to Tailscale-derived portions) and `iroh-dns@1.3.0` (no verbatim license text). The 16 material-bearing path rows remain unchanged; only 15 of 17 have complete package terms. This is not a global archive-absence statement, complete dependency graph, legal determination, product-artifact inclusion proof, or distribution authorization. The historical `ebf429b` / CI `42481654381` acceptance remains unchanged. This correction is documentation and metadata DATA work only; it does not claim new Task13 acceptance or CI.

The four bounded reader snippets above were executed during the prior pass and each exited 0, as recorded in the immediately preceding session transcript. In particular, replay 1 reported lock totals (533 registry identities; combined 195 shared, 318 root-only, 20 nested-only), replay 2 read the inventories, replay 3 reported `material records/files/bytes 43 43 166452`, and replay 4 reported `archive-to-material slices verified 45`. Replay 4 used then-current metadata whose prepared-inventory input digest was `7738cf6f5e654645b2e323b39ef00f0a41e60d8ac01c27f125bdca1289e98fc6`; it is not a replay of the corrected metadata. The current metadata digest is recorded above. Assets were unchanged by this correction. The recipe reads source as DATA only; successful prior-pass checks establish only the listed byte equalities, not origin URLs absent from receipts, current prepared-tree equality where separately listed unresolved, graph completeness, legal sufficiency, or distribution permission. After the correction, primary independently verified the corrected inventory digest and classification totals. The preserved material hashes and exact lock identity set were independently rechecked; archive/member byte comparisons from the preceding primary pass remain applicable because the authentic asset bytes are unchanged.

```sh
python -I -c 'import pathlib,json,hashlib,gzip,io,tarfile,stat; repo=pathlib.Path("."); data=(repo/"../../.rush/downloads").resolve(); docs=repo/"docs/legal/notices-material"; MAX=64*1024*1024; JSON=1024*1024; FILE=4*1024*1024; COUNT=10000

def bounded_file(base,rel,cap):
 path=pathlib.PurePosixPath(rel); assert not path.is_absolute() and all(part not in ("",".","..") for part in path.parts),rel
 target=base
 for part in path.parts:
  target=target/part; st=target.lstat()
  if part==path.parts[-1]: assert stat.S_ISREG(st.st_mode) and st.st_size<=cap,rel
  else: assert stat.S_ISDIR(st.st_mode),rel
 with target.open("rb") as f:
  raw=f.read(cap+1); assert len(raw)<=cap and len(raw)==st.st_size and f.read(1)==b"",rel
 return raw

def bounded_json(path): return json.loads(bounded_file(repo,path,JSON))

def bounded_gzip(raw,label):
 assert len(raw)<=MAX,label
 with gzip.GzipFile(fileobj=io.BytesIO(raw),mode="rb") as z: out=z.read(MAX+1)
 assert len(out)<=MAX,label
 return out

def member_bytes(tarbytes,name):
 with tarfile.open(fileobj=io.BytesIO(tarbytes),mode="r:") as tf:
  found=[]
  for n,m in enumerate(tf):
   assert n<COUNT,"member-count bound"
   if m.name==name: found.append(m)
  assert len(found)==1 and found[0].isfile(),name
  m=found[0]; assert m.size<=FILE,name
  f=tf.extractfile(m); assert f is not None
  b=f.read(FILE+1); assert len(b)==m.size<=FILE
  return b

def verify_material(preserved,n,h,rawmember,start,end):
 f=repo/preserved; st=f.lstat(); assert stat.S_ISREG(st.st_mode) and st.st_size==n<=FILE,preserved
 with f.open("rb") as stream:
  saved=stream.read(FILE+1); assert len(saved)==n and stream.read(1)==b"",preserved
 assert hashlib.sha256(saved).hexdigest()==h,preserved
 assert 0<=start<=end<=len(rawmember) and rawmember[start:end]==saved,preserved

r=bounded_json("docs/legal/notices-material/registry/inventory.json"); checked=0
for ident in r["identities"]:
 for m in ident.get("materials",[]):
  ok=False
  for a in ident.get("archive_data",[]):
   path=a.get("wrapper_data_path",a["path"]); raw=bounded_file(data,path,MAX)
   if a.get("wrapper_data_path"):
    assert len(raw)==a["wrapper_bytes"] and hashlib.sha256(raw).hexdigest()==a["wrapper_sha256"]
    raw=bounded_gzip(raw,path); assert len(raw)==a["bytes"] and hashlib.sha256(raw).hexdigest()==a["sha256"]==ident["checksum"]
   else: assert len(raw)==a["bytes"] and hashlib.sha256(raw).hexdigest()==a["sha256"]==ident["checksum"]
   tarbytes=bounded_gzip(raw,path); member=member_bytes(tarbytes,m["archive_member"]); assert len(member)==m["member_bytes"] and hashlib.sha256(member).hexdigest()==m["member_sha256"],(ident["name"],m["archive_member"])
   lo,hi=m["byte_range"]; digest=hashlib.sha256(member[lo:hi]).hexdigest()
   expected=m.get("slice_sha256",m["material_sha256"])
   if digest==expected:
    verify_material("docs/legal/notices-material/registry/"+m["material_path"],m["material_bytes"],m["material_sha256"],member,lo,hi); ok=True; break
  assert ok,(ident["name"],ident["version"],m["archive_member"])
  checked+=1
p=bounded_json("docs/legal/notices-material/prepared/inventory.json")
for ident in p["identities"]:
 a=ident.get("upstream_archive")
 if not a: continue
 raw=bounded_file(data,a["path"],MAX); assert len(raw)==a["bytes"] and hashlib.sha256(raw).hexdigest()==a["sha256"]
 tarbytes=bounded_gzip(raw,a["path"])
 for m in ident.get("materials",[]):
  member=member_bytes(tarbytes,m["source_member"])
  if "member_bytes" in m: assert len(member)==m["member_bytes"] and hashlib.sha256(member).hexdigest()==m["member_sha256"],(ident["cargo_identity"]["name"],m["source_member"])
  sl=m.get("slice"); lo=sl["start"] if sl else 0; hi=sl["end_exclusive"] if sl else len(member); n=sl["bytes"] if sl else m["bytes"]; h=sl["sha256"] if sl else m["sha256"]
  verify_material(m["preserved_path"],n,h,member,lo,hi); checked+=1
 s=ident.get("shared_material_reference")
 if s:
  prep=ident["preparation_evidence"]; member=member_bytes(tarbytes,prep["member"]); h=s["sha256"]; n=s["bytes"]
  verify_material(s["preserved_path"],n,h,member,0,len(member)); checked+=1
print("archive-to-material slices verified",checked)'
```

The snippets above read source as DATA only. Any missing/mismatched file, archive digest, member, identity or bounded size should fail closed; a successful replay still establishes only the listed byte equalities, not origin URLs absent from receipts, current prepared-tree equality where separately listed unresolved, graph completeness, legal sufficiency, or distribution permission. For `iroh-dns@1.3.0`, the candidate raw-file URLs and exact path are recorded in `docs/legal/notices-source-status.md`; these candidate requests remain separately gated and are not executed by this replay.

## Task13/N1 registry evidence handoff (2026-11-10; bounded DATA)

This section supplements the historical evidence above; it does not revise its old-pass dates, counts, digests or execution claims. The current appended registry data pass uses input HEAD `79e36e2aa77b0aa669dc58d91318427edce5db71` and the exact 515-archive authorized tranche. Its observable criterion is a read-only replay that checks root/nested lock identity tuples, the receipt-bound exact archive set, archive and manifest identities, member/material hashes and byte slices, retained old material, and reports the current inventory's exact byte hash and size. This is limited to notices evidence for distribution-readiness of existing north-star steps 1–6. It is not runtime/product work, Task14 assembly, a new acquisition or policy campaign, a license choice, legal clearance or distribution permission.

### Current evidence and classifications

The completed receipt is 243,217 bytes, SHA-256 `f88dd58897b88c2a964c6b6d00ba5e7ca6c2109c70680a98f7e76124f00b4ff1`, for 515 exact URLs. The worker-handoff registry inventory was 2,348,869 bytes, SHA-256 `61fb571b9400015f52d9b0a5ffbf01b4f7373300b692da8e90e8b2c8fbc6ffc0`; the primary correction below records its replacement metadata digest. The completed parent replay reports 515 verified unique URLs, 82,340,789 compressed bytes, 693,829,632 decoded tar bytes and 27,435 members. Parent independently compared all 892 new preserved material files (4,414,088 bytes) byte-for-byte to their exact archive members/slices and found zero omitted legal-named archive members. The updated registry inventory contains the per-identity and per-material source URL, receipt index, archive, member, checksum, exact range and digest mapping; these rows are intentionally not duplicated in this report. All 18 earlier registry rows and 46 pre-existing tracked files (material assets, inventories, attributes and the pinned license) remain byte-equal to HEAD; the prepared inventory is unchanged. The parent source-replayed the 892 new assets and separately verified the 43 pre-existing assets byte-identical to HEAD; prior-pass source verification is historical evidence, not a new replay of those old archives. The resulting registry set is 915 files / 4,497,927 bytes, and together with 20 prepared-source files the preserved assets total 935 files / 4,580,540 bytes. The pinned root LICENSE is a separate unchanged 16,726-byte asset and is outside those totals.

Current full registry classification: 493/533 package-complete, 2 component-only, 26 reference-only, 2 review-gap and 10 with no selected full terms (40 incomplete). This combines the current-pass 478 package-complete, 2 component-only, 24 reference-only, 2 review-gap and 9 missing-selected-material rows with the preserved 18-row earlier corpus; the three other prior rows are `iroh-base@1.3.0` and `netwatch@0.19.3` (reference-only), and `prost-codec@0.4.0` (exact-checksum archive, no full license text). “Missing” describes the bounded selected material only, not term absence. Reference-only content is context, not operative terms; component-only is not package-scope evidence; review-gap remains unresolved. The newly component-only registry cases are `iroh-relay@1.3.0` and `ring@0.17.14`; the two review gaps are `r-efi@5.3.0` and `r-efi@6.0.0`.

Across all 550 third-party registry and path identities, 508 are classified package-complete and 42 incomplete. Of 17 third-party path identities, 15 have complete package-level terms; `iroh@1.3.0` has only a component-scoped BSD-3 notice for Tailscale-derived portions and lacks package-level MIT OR Apache-2.0 terms, while `iroh-dns@1.3.0` has no full terms. Prepared-source inventory remains the 15/17 complete, 2 gap set (`iroh@1.3.0`, `iroh-dns@1.3.0`). Attohttpc MPL-2.0 full-text availability is evidence only, not policy acceptance. Available OR alternatives are recorded individually; no alternative is selected here. None of these counts establishes artifact inclusion, whole-graph legal sufficiency, or permission to distribute.

Twelve libp2p root MIT header slices remain exact comment bytes. Current material roles are 796 package-terms, 12 embedded, 18 component, 43 legal-context and 23 reference; netlink-packet-route rows were reclassified from legal-context to terms. New supplements are grouped under the five existing alpha-prefix directories; the checked direct registry fanout maximum is six. Exact material digests and member/range mappings belong to the inventory rather than duplicated prose.

### Replay contract and limits

The documented read-only replay invocation is:

```sh
python -I docs/legal/notices-material/registry/replay.py .
```

An optional second argument selects the primary downloads root. The reader uses only committed inventory/lock/material DATA and the held receipt-bound 515 archives; it does not read scratch selections or report inputs. It is an isolated standard-library DATA reader: it imports no project module, does not execute downloaded material, does not extract archives to disk and writes no output files. Bounds are 64 MiB compressed/archive and 1 GiB compressed aggregate, 256 MiB decoded/archive, 2 GiB total decoded, 32 MiB/member, 4 MiB/selected evidence item, 128 MiB selected evidence aggregate, 20,000 members/archive and 250,000 total members. It rejects unsafe paths, links/special members and normalized duplicate paths; it does not use `extractall`. The parent reran the reader and standalone AST syntax check: both PASS; the reader is 421 lines. Current parent replay `call_13adf808888d4c85b7a0403167c73f28` (batch `cd2ad350-f7c2-4e2f-9ec5-294023801ce9`) reported the current inventory digest/size above, 892 new source-equal rows and 23 old hash-preserved rows. This is not a claim that project tests/CI ran. No local builds, tests, Cargo, project Python, network, source execution/import, or git writes are claimed.

### Process limits and handoff boundary

Historical execution caveats are retained rather than sanitized: the first survey had 322 stale matching-lockfile rows caught and excluded by parent review; a nonterminating prefix-tree job `f5552f3c` was stopped and its signature classifications were not accepted; and an integration worker accidentally wrote the primary read-only registry (890 assets plus inventory) before its clean-root DATA restoration and the later proper worktree integration. Parent subsequently observed the primary clean at `20c385b`, but that does not undo the earlier boundary violation. Cleanup used no git writes (`git show` only); do not characterize the whole run as worktree-only. Parent also reports recursive Rush session/lock inspection and `git worktree list` were blocked by available tools, with no state changes.

Review, integration and metadata records are `431c900a-bf0f-4e0b-996a-749d5c1b0653$$call_9456e5f937144053a07048fd23a464d3`, `ae5e1639-9324-44c7-88bd-70b4217476d5$$call_36ba8adb70754f9bada81430906df5b8` and `e4518bde-c1cd-4bd3-8e30-2b595d461606$$call_9ad3f700a33949bb97263be3b0289887`. The earlier accessible worker artifact `call_14682d5173f04345af07c3080d5b2c63` records worker `b75a4cac`’s prior replay, not the final parent replay; the current parent replay is `call_13adf808888d4c85b7a0403167c73f28` (batch `cd2ad350-f7c2-4e2f-9ec5-294023801ce9`). This handoff does not claim full Task13 acceptance, legal clearance, complete current prepared-tree equality, CI, or distribution permission. It stops at the bounded evidence contract and leaves finite named gaps for separate review.


## Primary review correction — 2026-11-10

The preceding N1 replay statements describe the worker-handoff metadata, not execution against this correction. Primary independently read the retained `aws-lc-sys@0.46.0` root LICENSE: its s2n-bignum section explicitly names MIT-0 as an applicable alternative and its MIT No Attribution section contains the complete grant and disclaimer. The MIT-0 alternative now binds that exact existing material as available; no OR alternative is elected and no authentic bytes changed. `historical_pre_n1_metadata.material_search` was restored exactly from the accepted pre-pass inventory rather than retaining the current-pass description.

The corrected registry inventory is 2,349,163 bytes, SHA-256 `93cbbe75a0967172695898e0bbf5b0b67b70c7e2cb2f349a81b0e4fdf9f2ddb3`. Package classification totals remain unchanged: 493/533 registry and 508/550 combined identities classified package-complete, with 40 registry / 42 combined incomplete identities. These are source-text availability classifications, not legal clearance or distribution permission.

Primary independently inspected all 515 receipt-bound archives using a separate isolated standard-library DATA reader and compared all 892 new materials byte-for-byte with their exact members/slices: 4,414,088 preserved bytes, 693,829,632 decoded bytes and 27,435 members; directory limits passed. The first invocation of that independent reader stopped at a Python string-literal syntax error before inspecting inputs; the corrected invocation passed. Primary did not run or import the maintained replay reader or project tests. This correction is not yet CI-verified.

The primary-read-only breach and the worker's unauthorized restoration/deletion remain process violations. Primary subsequently verified a clean main checkout and exact equality of its legal tree with accepted `79e36e2`; registry inventory remained 314,094 bytes with SHA-256 `1aaca36c30203ecb73eebc8c73f1299c52e8b6161c27e3ec94a8e7a8c2aa347b`. No claim of fully compliant historical execution is made. No further notices worker was launched for this correction; primary owns the remaining dirty worktree and its disposition. Full Task13, prepared-tree provenance, legal clearance and release remain unaccepted.

## Nine-source upstream DATA supplement — 2026-11-10

See `notices-source-status.md#nine-pinned-upstream-candidates--2026-11-10` and `notices-material/upstream-raw-nine/inventory.json` for the separately authorized nine-GET pass: eight HTTP 200, one HTTP 404, 19,570 response bytes; five deduplicated verbatim assets / 15,539 bytes. Full upstream terms for three identity candidates are distinct from the objc2 licensing-reference/Apple-platform context and the missing objc2-encode candidate. The supplement does not modify the canonical archive inventory or claim an all-source completeness recount. Primary used isolated own-stdlib DATA readers and inspected exact response bytes; no maintained replay/project Python, downloaded source, build or test was executed. This supplement is not yet CI-accepted, full Task13, legal clearance or distribution permission.

## Explicit AUTHORS evidence boundary — 2026-11-10

The two retained r-efi READMEs explicitly name AUTHORS. The later primary-owned recovery in `notices-source-status.md#explicit-authors-terms-recovery--2026-11-10` adds exact full AUTHORS files with operative MIT terms and copyright, not reconstructed text. Canonical inventory SHA-256 is now `623e6284892396da69eadea5706a283c91afe1282676a0fc0fd6dac31792de30` (2,354,190 bytes); prior SHA-256 values describe earlier inputs, including the separate raw-source supplement. New CI-only corpus regressions invoke the existing terms-evidence validator and reject reference-only or missing evidence. They were not run locally. The replay's source/member/lock checks and hard resource limits remain unchanged; only its exact-dataset material totals change to 917 registry rows / 4,505,353 bytes, of which 894 / 4,421,514 belong to the held 515 archives. No new network or legal-policy authority, OR election, full Task13 acceptance or distribution permission is claimed.


## Three pinned repository-root bindings (2026-11-11 historical candidate)

The registry inventory distinguishes four `raw_materials` from archive-member
`materials`: root LICENSE for `dlopen2@0.8.2` and `valuable@0.1.1`, and both
LICENSE-MIT and LICENSE-APACHE for `jni@0.22.4`. These 14,200 verbatim bytes were
already acquired by the separately approved nine-URL pass; no new GET was made.
The retained receipt is `registry/raw-sources/receipts/receipt.json` (moved from
`raw-sources/receipt.json` on 2026-11-12, bytes unchanged; 5,542 bytes,
SHA-256 `d4f45767bba3d21266670faa1ffeacc8076c9768a2da5f23d382aac2ebf8bfd5`).

Each exact locked archive checksum binds the archived `.cargo_vcs_info.json`
and `Cargo.toml.orig` bytes, package path, original README scope and pinned
repository revision to its separately fetched root material. The archived README
license references and original relative README paths were inspected in the
preceding offline review. Raw files are never represented as members of the
published `.crate`. The replay retains its previous 917 archive-material records
and 4,505,353 bytes; the four raw files and 14,200 bytes are counted separately.
It verifies the full pinned acquisition receipt and actual source archive metadata
before accepting these three exact raw bindings. The CI contracts check retained
bindings and mutation rejection; they do not replace an actual archive replay.

An independent stdlib DATA comparison found no changes in the other 530 registry
identities and matched all four raw files and six archived metadata payloads.
The candidate registry counts are 498 of 533 text-available identities; with the
unchanged 15 of 17 path identities this is 513 of 550, leaving 37 incomplete.
This three-package candidate was subsequently accepted and delivered as `00206f6`:
CI `43040958250` verified 34 notice-evidence tests per OS. The resulting accepted
baseline is 513 of 550; the macro supplement below is a separate later candidate.
Both JNI alternatives are retained and neither is elected. No applicability is
extended to other JNI versions, JNI macros, objc2 or any other package/revision.
This records authentic-text availability, not legal sufficiency, clearance,
product artifact inclusion, release permission or completion of Task13/N1.

## Two exact JNI macro root bindings (2026-11-11 candidate)

The user separately authorized four exact pinned candidate GETs in proposal
`dca3218e59f24108feedbc36fdb416c500792a35c5aee50b48ee1b3fadf457a7`.
All four returned HTTP 200: 24,380 bytes in 5.39 seconds, without redirects,
retries, fallback URLs, cloning, execution or imports. That request budget is
consumed. The original 5,646-byte CRLF receipt is retained verbatim as
`registry/raw-sources/receipts/jni-macro-receipt.json` (moved from `raw-sources/` on 2026-11-12; bytes unchanged), SHA-256
`1a9f927618e812d27bdd1d1850042b9efa21a9f1f42396add47a468eac1aa120`.

The new bindings are `jni-macros@0.22.4` at revision
`33045a124105c939d1e2cbdcb5a39e5d868ffa03`, path `crates/jni-macros`, and
`jni-sys-macros@0.4.1` at revision `64d77b7a5f119d7b55b4e2c169a4668067ff59e6`,
path `jni-sys-macros`. Their actual archived original manifests explicitly declare
MIT OR Apache-2.0 and the matching repositories. Their original README values
are respectively absent and `README.md`; no root-relative README is invented.
The retained archived VCS and original-manifest bytes bind exact checksums,
clean revisions and package paths to each newly acquired root text. The earlier
JNI package revision is not automatically reused. Both alternatives are retained.

All four new LICENSE files are separate raw materials, never fabricated `.crate`
members. Archive evidence remains 917 materials / 4,505,353 bytes; raw evidence
now has eight files / 38,580 bytes across five exact packages. Replay pins both
original receipts independently and validates the second acquisition format's
identity, HTTP outcomes, unique four-file set and time/byte/request budgets before
adapting its DATA records. The old three bindings keep their original checks.

Independent stdlib DATA comparison confirmed the other 531 registry identities
unchanged. Candidate inventory: 2,378,290 bytes, SHA-256
`4392fa5beb114ae9bb1f4797422c43a464b5387e1d4e0d8bc56d67df54d67b92`.
Text availability is 500/533 registry plus unchanged 15/17 path identities:
515/550, leaving 35 incomplete. CI verification and delivery are still pending;
local checks are syntax/DATA only, not project test execution or full archive
program replay. No broader revision applicability, OR election, legal clearance,
release authority or completion of N1 is asserted.

## Seventeen pinned root bindings closing gaps (2026-11-12 candidate)

Authorization: on 2026-11-12 the user granted all permissions for repository work
and downloads ("Все разрешения на работы с репами и скачиваниями - я выдаю"). Only
exact pinned `raw.githubusercontent.com` license-file URLs at each archive's
`.cargo_vcs_info.json` revision were requested: 27 GETs, one per URL, no
redirects/retries/fallbacks, 64 KiB/object, 30 s/request, all HTTP 200, 157,286
bytes in 42 s. Each body's git blob SHA-1 equals the blob SHA reported by the
repository contents listing at that revision, so the bytes are exactly the files in
the pinned commit. Nothing was executed or imported; no text was synthesized.
The retained receipt is `registry/raw-sources/receipts/n1-gap-receipt.json`
(27,525 bytes, SHA-256 `3f6f2c53fb29aebd923e9e60cd36671a86f9f988d916e0a69c2fb03fc677e0e3`);
the 27 verbatim bodies are stored per package (32 files, 182,118 bytes, because
`iroh-base`/`iroh-relay`/`iroh` and `prost-codec`/`rw-stream-sink` pin shared files).
The download-side receipt, directory listings and bodies are in the untracked
`.rush/downloads/notices-n1-gaps-1112/` and `.rush/downloads/n1-listings-1112/`.

New registry bindings (15): `asn1-rs-impl@0.2.0`, `gloo-timers@0.3.0`,
`gloo-timers@0.4.0`, `iroh-base@1.3.0`, `iroh-metrics-derive@1.0.1`,
`iroh-relay@1.3.0`, `n0-error-macros@1.0.1`, `ndk-context@0.1.1`,
`netwatch@0.19.3`, `prost-codec@0.4.0`, `rustls-platform-verifier-android@0.2.0`,
`rw-stream-sink@0.5.0`, `uint@0.10.2`, `yamux@0.14.1`, `yasna@0.5.2`. New path
bindings (2): `iroh@1.3.0` (revision `0072d7d84b233f9e7185eb676f049beaf557ac03`)
and `iroh-dns@1.3.0` (revision `17c0612f80f78f5288e97b818b1360ae6ea0a51a`), both
bound to the revision in the pinned upstream archive recorded in the prepared
inventory; their patches do not alter license files. Each binding records the
archived `.cargo_vcs_info.json` and packaged `Cargo.toml` bytes. Replay requires a
clean (not dirty) revision, the matching `path_in_vcs`, package name/version, a
declared expression whose alternatives are exactly covered by the bound files, and a
repository equal to the pinned URL's. Both alternatives are retained and neither is
elected. Package directories at the pinned revisions held no license files except the
`LICENSE-BSD3` component notice and `rustls-platform-verifier-android`, whose package-directory `LICENSE-*` entries are
git symlinks (blob SHA-1 equal to the targets `../LICENSE-APACHE`/`../LICENSE-MIT`);
the repository-root files they name are bound. `uint` names its Apache alternative
`LICENSE-APACHE2`. The `iroh-relay` and `iroh` component-scoped `LICENSE-BSD3` stay
component-only evidence. The earlier package-directory candidate URLs for
`iroh-dns` were never requested because the listing shows those files do not exist.

Layout: the raw tree is now `registry/raw-sources/{receipts,a-f,g-i,j-l,m-r,s-z}/`
(same alphabetical groups as `packages/`, each at most seven entries); the five
earlier packages and both earlier receipts moved without byte changes and the exact
path attributes in `notices-material/.gitattributes` follow them. The replay was split
by responsibility into `replay.py`, `raw_sources.py` (receipts and bindings) and
`data_io.py` (bounded readers), loaded by file path so isolated `python -I` runs work.

Result: registry text availability is 515 of 533 and path identities 17 of 17, so
532 of 550 third-party identities have authentic text available (previously 515 of
550); 18 registry identities remain incomplete. Registry classification counts are
500 package-complete, 15 preserved-complete, 14 reference-only, 3 missing and 1
component-only. Inventory: 2,487,465 bytes, SHA-256
`4ad6d77cbb2b138bc6991ef2fac0b3fc507c8ca0a4bf6c96437d17f10dbf1d30`; prepared
inventory 97,688 bytes, SHA-256
`ab03774b63930c9b5d32bb0124290f312cd71946be192dc975e3c7bbc98ab184`. Raw evidence
now totals 40 files / 220,698 bytes across 22 packages; archive evidence is
unchanged at 917 materials / 4,505,353 bytes. The local read-only replay
(`python -I docs/legal/notices-material/registry/replay.py .`, not a unit test)
reported PASS against the held archives; the CI notice tests add 5 gap test methods
(bindings, receipt mutations, binding mutations, swapped-text rejection, exact counts,
remaining gaps and raw-tree layout). Test execution evidence is CI only. This records
text availability, not legal sufficiency, clearance, election, artifact inclusion or
release permission, and does not complete N1.

Remaining 18 gaps, each documented rather than filled:

- `base45@3.2.0`, `enum-assoc@1.4.1`, `futures-bounded@0.3.0`, `if-watch@3.2.2`,
  `pharos@0.5.3`: the pinned repository revision contains no license file at the
  root or package path (declared MIT, MIT OR Apache-2.0, MIT, MIT OR Apache-2.0 and
  Unlicense respectively). `base45`'s archived VCS state is also dirty.
- `block2@0.6.2`, `dispatch2@0.3.1`, `objc2@0.6.5`, `objc2-core-foundation@0.3.2`,
  `objc2-core-wlan@0.3.2`, `objc2-encode@4.1.0`, `objc2-foundation@0.3.2`,
  `objc2-security@0.3.2`, `objc2-security-foundation@0.3.2`,
  `objc2-system-configuration@0.3.2`: the pinned repository root holds only
  `LICENSE.md`, a licensing statement with links and an Apple SDK caveat, not the
  operative license texts (already retained as context); crate directories hold none.
- `ring@0.17.14`: component-only. Its own `LICENSE` defers to `LICENSE-other-bits`
  (ISC) and `LICENSE-BoringSSL`, all already retained; the pinned revision is dirty
  and has no package-level Apache-2.0 text, so nothing new can be bound.
- `winapi-i686-pc-windows-gnu@0.4.0`, `winapi-x86_64-pc-windows-gnu@0.4.0`: the
  archives carry no VCS info, so there is no pinned revision to bind.

## Deterministic notices assembly and check (N2, 2026-11-12 candidate)

Acceptance criterion: for each supported release target, a stdlib-only generator
reproducibly assembles one `THIRD-PARTY-NOTICES-<target>.txt` for `shaar-server` and
`shaar-client` from the accepted corpus, and a CI check regenerates it, compares it to
the committed manifest and fails on any linked identity without authentic text that is
not in the reviewed gap list. Non-goals: legal clearance, OR-alternative election,
release permission, packaging of an actual artifact, and any new text acquisition.

Code lives in `.github/actions/dependency-license/notices/` (`notices.py` entry point;
`notice_cfg.py`, `notice_graph.py`, `notice_corpus.py`, `notice_render.py`), tests in
`.github/scripts/tests/test_notices.py`, and the reviewed record in
`docs/legal/notices-material/release/` (`policy.json`, `manifest-<target>.json`). The
existing `dependency-license` composite action runs the tests and the check
(`notices.py check`) on both CI runners and uploads the generated files as the
`third-party-notices-<OS>` artifact; no new workflow exists. `.github/ci/policy.py` already
mapped the generator and corpus paths to the `license` domain and now also maps
`test_notices*` there, because the action runs those tests directly.

### Supported targets and applicability rule

Supported release targets are the two CI hosts, `x86_64-unknown-linux-gnu` and
`x86_64-pc-windows-msvc` (`release/policy.json`; the Go/MinGW sketch in
`docs/architecture/contracts.md` is superseded). A package is linked when Cargo's own
`cargo tree --locked -p shaar-server -p shaar-client -e normal --target <host>` lists it:
normal edges only, so build-only and dev-only crates are excluded and proc-macro crates
are included. Each OS job produces the tree for its own host, so Cargo itself decides
feature and platform selection for both release targets. A pure cfg evaluation of the
unfiltered `cargo metadata` JSON that CI already produces (`target/p2p/metadata.json`) is
kept as a superset guard: the first CI run showed it over-approximates (it links 409 and
411 packages against Cargo's 378 and 379, because it cannot model feature selection, for
example `attohttpc`, `aws-lc-rs`, `libp2p-quic`), so the check fails if Cargo links anything
the evaluation excluded, and the evaluation alone is never used for a committed record.
Every linked identity must map to exactly one corpus identity (registry by name, version,
source and lock checksum; path by name and version; first-party packages are excluded by
name in the policy). A job verifies only the target whose tree it supplies and skips the
other with a message; at least one target must be verified.

### Applicable sets (550 third-party identities)

| Target | Cargo tree | Third-party | Registry | Path | Complete text | Distributed blockers | Reviewed gaps not distributed |
|---|---|---|---|---|---|---|---|
| `x86_64-unknown-linux-gnu` | 378 | 372 | 355 | 17 | 367 | 5 | 13 |
| `x86_64-pc-windows-msvc` | 379 | 372 | 355 | 17 | 367 | 5 | 13 |

The two third-party sets differ (20 identities are linux-only, such as `netlink-*`,
`rtnetlink` and `nix`; 20 are Windows-only, such as `windows-*`, `ipconfig` and `wmi`), so
392 identities are distributed on at least one target and 158 of 550 on neither: 20
registry identities appear only in the nested `shaar-ygg-core` lock; of the 530 root-graph
identities, 16 are reachable only through build edges (`autocfg`, `cc`, `cfg_aliases`, `cmake`, `dunce`,
`find-msvc-tools`, `fs_extra`, `jobserver`, `pkg-config`, `rustc_version`, `same-file`,
`semver`, `shlex`, `version_check`, `walkdir`, `winapi-util`; all hold authentic text and
none is a gap) and the rest are platform- or feature-gated away from the target. The
manifests were generated from the metadata and tree artifacts of CI run `43243902226`
(identical output from the Linux and the Windows metadata); the committed record is
re-verified by each CI job against its own host tree.

### Gaps not distributed (13), with evidence

Each manifest lists, per gap, every edge from a linked package into the unlinked region
above the gap (`not_distributed[].boundary`: parent, version, child, version, edge kind,
predicate, and a flag that is true only when the cfg allows the edge and feature selection
removed it). All 13 gaps are excluded by target predicates alone (the flag is false in
every row; a contract test pins this).

- Ten objc2-family crates (`block2`, `dispatch2`, `objc2`, `objc2-core-foundation`,
  `objc2-core-wlan`, `objc2-encode`, `objc2-foundation`, `objc2-security`,
  `objc2-security-foundation`, `objc2-system-configuration`): reached only through
  `netdev` 0.45.1/0.46.3 and `netwatch` 0.19.3 edges gated by
  `cfg(target_os = "ios")`, `cfg(target_os = "macos")` or
  `cfg(any(target_os = "macos", target_os = "ios"))`, or by the `netwatch` to `netdev`
  edge version that is itself platform-gated. They would become blockers if an Apple
  target were added (a local cfg evaluation, superset and not CI-verified, reports 7
  additional linked gaps for `aarch64-apple-darwin`).
- `pharos` 0.5.3: only `iroh-relay` 1.3.0 to `ws_stream_wasm` 0.7.5, gated by
  `cfg(all(target_family = "wasm", target_os = "unknown"))`.
- `winapi-i686-pc-windows-gnu`, `winapi-x86_64-pc-windows-gnu`: only through
  `dlopen2` 0.8.2, gated by `cfg(target_os = "android")` (and the gated `netdev`
  versions); the evaluation also excludes them on `x86_64-pc-windows-gnu`.

### Remaining distributed blockers (5, both targets; confirmed by Cargo's own tree)

Not filled; the generated bundle lists them under `RELEASE BLOCKERS` and
`notices.py check --release` fails while any remain.

| Package | Declared | Reason (reviewed in `release/policy.json`) |
|---|---|---|
| `base45` 3.2.0 | MIT | pinned revision holds no license file at root or package path; archived VCS state dirty |
| `enum-assoc` 1.4.1 | MIT OR Apache-2.0 | no license file at the pinned revision |
| `futures-bounded` 0.3.0 | MIT | no license file at the pinned revision |
| `if-watch` 3.2.2 | MIT OR Apache-2.0 | no license file at the pinned revision |
| `ring` 0.17.14 | Apache-2.0 AND ISC | component texts retained; no package-level Apache-2.0 text at the dirty pinned revision |

### Generated files

Notices are generated, not committed; the byte count and SHA-256 are pinned in the
committed manifest, which a CI regeneration must reproduce exactly:

| File | Bytes | SHA-256 |
|---|---|---|
| `THIRD-PARTY-NOTICES-x86_64-unknown-linux-gnu.txt` (279 distinct texts) | 927,944 | `897505d51b49a31099f3a501f4f3f66945178065d49d588fe0fd385dc3d22717` |
| `THIRD-PARTY-NOTICES-x86_64-pc-windows-msvc.txt` (282 distinct texts) | 972,734 | `bcb1e8e810fbd4e3397561e0c624da44db0bd96708cb92af943771933ddfa0bb` |

Manifests: `manifest-x86_64-unknown-linux-gnu.json` 129,773 bytes
(`cbbcb53678ec47928da40051e25f5cc31ee32771f73f1ee2429b4bb8428b3dd3`),
`manifest-x86_64-pc-windows-msvc.json` 131,297 bytes
(`c76a90dce60d7066b05a5a221232a7a12bfc6491eb2644ced79350741683a061`); policy 5,282 bytes
(`771a7af6daf7a2b49a2647ddb3626fd9f6509ccfbb0c5902a5dd89b4c43363e5`).

Each text is printed once, verbatim, framed by BEGIN/END lines carrying its byte count
and SHA-256; packages are sorted by name, version and source; all alternatives of an OR
expression are printed and none is elected; reference-only files (README mentions) are
not terms and are omitted. Reading verifies recorded size and SHA-256 and rejects links,
traversal, empty and oversized files. The check fails on: a linked identity without a
corpus record or with a different lock checksum, a reviewed gap list that differs from
the corpus (unreviewed or stale), a changed text or inventory byte, a differing committed
manifest, a Cargo tree outside the cfg superset or without the products, and no verified
target. Regenerate the record after a corpus or graph change with
`notices.py generate --manifest-only --out <dir> --tree <target>=<cargo tree file>` for
both targets, using the CI metadata and the `third-party-notices-<OS>` tree artifacts, and
copy the manifests into `release/`.

Status: written and CI-executed. Run `43243902226` (first design) executed the new test
module (39 tests, all passing) and its check step failed on both runners only on the
superset guard above, which led to the Cargo-tree-authoritative design recorded here.
Run `43245627450` is green on Ubuntu and Windows: `test_notices.py` executed 44 tests on
each runner, the structural guard discovery ran 181 tests including them, and each runner's
check verified its own host manifest against Cargo's tree (the other target skipped by
design) and reported the five blockers. Generation from the CI artifacts is local,
read-only and offline. This establishes packaging determinism and text availability, not
legal sufficiency, clearance, election or release permission.
