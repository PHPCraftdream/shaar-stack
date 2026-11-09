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
