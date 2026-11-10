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
