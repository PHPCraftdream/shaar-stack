# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure, fail-closed validation of normal Cargo consumer graph proofs."""
import hashlib
import json
from pathlib import Path
import re

_ROLES = ("baseline", "approved_route", "candidate")
_KINDS = ("metadata", "tree", "build")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SDK_TEST_SOURCE_TRANSITIONS = {
    ("183956ce9ae1b99245953ce3e65b76e44ea64bba5de113fc193af462ea8d4712",
     "59987da7663e14b9d1c8441c051a8cdcbebd497327a021b1ea7f84fdf8fe1e41"):
        "cadc863f39329a43c91fbacd34f3e0f707c5fcbe0f3b85cf0a1cedff5daddd88",
    ("e2fe4d5ff2a65b45848bcc128af2ef474ad9c836374763353d532a9d15f042a5",
     "c0fbceaea9b9df00f45dffd55bd2057c9e549a14c1e6e5c956ef1b1c88aefde6"):
        "2743b2fc2a8cef9642799d090bd6bd75dc43f63c0edef0077e8391a60a811f8a",
    # Unwired private native runtime added to shaar/src since the control; no dependency edge changes.
    ("a9ce98ea03cbf9a6dfa63a0676d97dd63a8feb75493b8e7be97a04d763416f09",
     "758a1ca5888acabea6a99ca3580b0405974fb0cd8fb4f81b1cfe2fa7d31c1abc"):
        "cadc863f39329a43c91fbacd34f3e0f707c5fcbe0f3b85cf0a1cedff5daddd88",
    # Same source delta on the Windows runner, whose control tree differs.
    ("bd0c1843a330d5b9b3255ae2abb5b89007363a49ee13c49b8a98e64c956b1971",
     "af2aa516670e451abf9eeaf7bf54b3c13b1f43f4ddf264ed840ab4dba33bd425"):
        "2743b2fc2a8cef9642799d090bd6bd75dc43f63c0edef0077e8391a60a811f8a",
}
_ADDED = {("iroh-mainline-address-lookup", "0.6.1"), ("iroh-dns", "1.3.0"), ("n0-mainline", "0.7.0"), ("serde_bencode", "0.2.4"), ("n0-future", "0.3.2")}
_REVIEWED_REGISTRY = {
    ("crc", "3.4.0"): "5eb8a2a1cd12ab0d987a5d5e825195d372001a4094a0376319d5a0ad71c1ba0d",
    ("crc-catalog", "2.5.0"): "217698eaf96b4a3f0bc4f3662aaa55bdf913cd54d7204591faa790070c6d0853",
    ("dyn-clone", "1.0.20"): "d0881ea181b1df73ff77ffaaf9c7544ecc11e82fba9b5f27b262a3c73a332555",
}
_REVIEWED_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
_APPROVED_ARCHIVES = {
    "iroh-dns": "80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1",
    "iroh-mainline-address-lookup": "035d35f41362c79d43f44dc1d5cdaf9c8c718fa3781fd09cf458b7b47cb014ba",
    "n0-mainline": "f64972176bd209d1ebe98310743614e19728a33a4b288ae8147cca9f0b8c7463",
    "serde_bencode": "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e",
    "n0-future": "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe",
    "tokio-1.54.1-test-util": "b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3",
    "multibase": "7e0e4a371cbf1dfd666b658ba137763edb23c45beb43cfe369b5593cd6b437b6",
}

_MULTIBASE_IDENTITY = ("multibase", "0.9.3")
_MULTIBASE_CHECKSUM = "7e0e4a371cbf1dfd666b658ba137763edb23c45beb43cfe369b5593cd6b437b6"
_EMOJI_DROPS = {
    "base256emoji": ("1.0.2", "b5e9430d9a245a77c92176e649af6e275f20839a48389859d1661e9a128d077c"),
    "const-str": ("0.4.3", "2f421161cb492475f1661ddc9815a745a1c894592070661180fdec3d4872e9c3"),
    "match-lookup": ("0.1.3", "549e39695cc0b640f3cb378053832db3d2133422d49e8dcae5c866a2aaf1f730"),
}
_DEPENDENCY_OWNER_FIELDS = ("package", "target", "kind", "crate_types", "context", "triple", "features")


def _validate_reviewed_graph(proof, parsed):
    raw, packages, nodes = parsed[0], parsed[1], parsed[2]
    reviewed = {name for name, _ in _REVIEWED_REGISTRY}
    present = [pid for pid in packages if packages[pid].get("name") in reviewed]
    if not present:
        return
    expected = {("crc", "3.4.0"), ("crc-catalog", "2.5.0"), ("dyn-clone", "1.0.20"), ("n0-mainline", "0.7.0")}
    ids = {}
    for name, version in expected:
        matches = [pid for pid, pkg in packages.items() if pkg.get("name") == name]
        _need(len(matches) == 1 and packages[matches[0]].get("version") == version, proof["role"] + ": reviewed package missing or duplicated: " + name)
        pid = matches[0]
        pkg = packages[pid]
        if (name, version) in _REVIEWED_REGISTRY:
            _need(pkg.get("source") == _REVIEWED_SOURCE and proof.get("lock_checksums", {}).get(pid) == _REVIEWED_REGISTRY[(name, version)], proof["role"] + ": reviewed registry identity mismatch: " + name)
        else:
            binding = parsed[6].get(pid, {})
            _need(pkg.get("source") is None and binding.get("identity") == "prepared" and binding.get("package") == name and binding.get("version") == version and binding.get("archive_sha256") == _APPROVED_ARCHIVES[name], proof["role"] + ": n0-mainline is not the pinned prepared archive")
        ids[name] = pid
    expected_edges = {(ids["n0-mainline"], ids["crc"]), (ids["n0-mainline"], ids["dyn-clone"]), (ids["crc"], ids["crc-catalog"])}
    actual_edges = set()
    registry_ids = {ids[name] for name, _ in _REVIEWED_REGISTRY}
    for source, node in nodes.items():
        for dep in node.get("deps", []):
            kinds = dep.get("dep_kinds", [])
            if any(k.get("kind") in (None, "normal") for k in kinds):
                target = dep["pkg"]
                if source in registry_ids or target in registry_ids:
                    actual_edges.add((source, target))
    _need(actual_edges == expected_edges, proof["role"] + ": reviewed normal dependency edges mismatch")


class AuditError(ValueError):
    """Evidence does not establish the required graph contract."""


def _need(ok, message):
    if not ok:
        raise AuditError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _json(data, label):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError, AttributeError) as exc:
        raise AuditError("invalid JSON artifact: " + label) from exc


def _record(proof, kind):
    matches = [r for r in proof["records"] if isinstance(r, dict) and r.get("kind") == kind]
    _need(len(matches) == 1, proof["role"] + ": expected one " + kind + " record")
    r = matches[0]
    manifest, cwd = proof["consumer_manifest"], proof["consumer_cwd"]
    commands = {
        "metadata": ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", manifest],
        "tree": ["cargo", "tree", "--locked", "--edges", "normal,features", "--manifest-path", manifest],
    }
    if kind == "build":
        capture = proof.get("compiler_capture")
        _need(isinstance(capture, dict) and isinstance(capture.get("wrapper"), dict),
              proof["role"] + ": missing compiler capture target")
        commands["build"] = ["cargo", "build", "--locked", "--lib", "--message-format=json", "--target", capture["wrapper"].get("target"), "--manifest-path", manifest]
    _need(r.get("argv") == commands[kind] and r.get("cwd") == cwd and r.get("exit_code") == 0,
          proof["role"] + ": invalid " + kind + " execution")
    artifacts = proof["artifacts"]
    for stream in ("stdout", "stderr"):
        name, digest = r.get(stream), r.get(stream + "_sha256")
        _need(isinstance(name, str) and isinstance(artifacts.get(name), bytes), proof["role"] + ": missing " + stream)
        _need(isinstance(digest, str) and _DIGEST.fullmatch(digest) and _sha(artifacts[name]) == digest,
              proof["role"] + ": invalid " + stream + " digest")
    return artifacts[r["stdout"]]


def _stable_source(pkg, bindings, pid, proof):
    source = pkg.get("source")
    if source is not None:
        _need(isinstance(source, str) and source.startswith(("registry+", "git+")), "unsupported registry source")
        if source.startswith("registry+"):
            checksums = proof.get("lock_checksums", {})
            _need(_DIGEST.fullmatch(str(checksums.get(pid, ""))),
                  "registry package lacks matching lock checksum")
            return source + ":" + checksums[pid]
        return source
    b = bindings.get(pid)
    _need(isinstance(b, dict), proof["role"] + ": path package lacks source binding")
    _need(b.get("package") == pkg["name"] and b.get("version") == pkg["version"], "binding identity mismatch")
    _need(b.get("identity") in ("workspace", "prepared"), "invalid binding identity")
    for key in ("tree_sha256", "archive_sha256"):
        _need(_DIGEST.fullmatch(str(b.get(key, ""))), "invalid source digest")
    if b["identity"] == "prepared":
        _need(_DIGEST.fullmatch(str(b.get("recipe_sha256", ""))), "prepared source lacks recipe digest")
    tree = b["tree_sha256"]
    # Upstream 70b55f4 changes only the cfg(test) codec fixture; retain raw bindings in the proof digest.
    if (proof["role"] == "candidate" and b["identity"] == "workspace"
            and (b["package"], b["version"]) == ("shaar", "0.1.0")):
        tree = _SDK_TEST_SOURCE_TRANSITIONS.get((b["archive_sha256"], tree), tree)
    return "path:" + b["identity"] + ":" + b["package"] + "@" + b["version"] + ":archive=" + b["archive_sha256"] + ":tree=" + tree + (":recipe=" + b["recipe_sha256"] if b["identity"] == "prepared" else "")


def _metadata(proof):
    raw = _json(_record(proof, "metadata"), "metadata")
    packages = raw.get("packages", [])
    ids = [p.get("id") for p in packages if isinstance(p, dict)]
    _need(len(ids) == len(packages) and all(isinstance(i, str) for i in ids) and len(set(ids)) == len(ids), "invalid package ids")
    by_id = {p["id"]: p for p in packages}
    nodes_list = (raw.get("resolve") or {}).get("nodes", [])
    nodes = {n.get("id"): n for n in nodes_list if isinstance(n, dict)}
    _need(len(nodes) == len(nodes_list), "duplicate resolve nodes")
    manifest, cwd = proof["consumer_manifest"], proof["consumer_cwd"]
    _need(manifest.endswith("Cargo.toml") and Path(manifest).is_absolute() and
          Path(cwd).is_absolute(), "consumer paths must be absolute")
    root_candidates = [p for p in packages if p.get("name") == "native-graph-normal-consumer" and p.get("manifest_path") == manifest]
    _need(len(root_candidates) == 1, "expected native-graph-normal-consumer workspace root")
    root = root_candidates[0]
    _need(raw.get("workspace_root") == cwd and raw.get("workspace_members") == [root["id"]], "consumer must be sole workspace member")
    _need(root["id"] in nodes, "consumer missing resolve node")
    bindings = proof.get("source_bindings")
    _need(isinstance(bindings, dict) and set(bindings) <= set(by_id), "invalid source bindings")
    closure, stack = set(), [root["id"]]
    while stack:
        pid = stack.pop()
        if pid in closure:
            continue
        _need(pid in nodes and pid in by_id, "unknown dependency target")
        closure.add(pid)
        for dep in nodes[pid].get("deps", []):
            target = dep.get("pkg")
            _need(target in nodes and target in by_id, "unknown dependency target")
            kinds = dep.get("dep_kinds")
            _need(isinstance(kinds, list) and kinds and all(isinstance(k, dict) for k in kinds), "missing or invalid dependency kinds")
            _need(all(k.get("kind") in (None, "normal", "dev", "build") for k in kinds), "invalid dependency kind")
            if any(k.get("kind") in (None, "normal") for k in kinds):
                stack.append(target)
    direct = [d for d in nodes[root["id"]].get("deps", []) if by_id[d["pkg"]].get("name") == "shaar" and any(k.get("kind") in (None, "normal") for k in d.get("dep_kinds", []))]
    _need(len(direct) == 1, "consumer must directly depend on shaar normally")
    features, identities, runtime = {}, {}, {}
    for pid in closure:
        pkg, node = by_id[pid], nodes[pid]
        if pkg['name'] == 'native-graph-normal-consumer':
            continue
        source = _stable_source(pkg, bindings, pid, proof)
        key = (pkg["name"], pkg["version"], source)
        _need(key not in identities, "duplicate stable package identity")
        identities[key] = pid
        enabled = node.get("features", [])
        _need(isinstance(enabled, list) and all(isinstance(x, str) for x in enabled), "invalid feature data")
        if any(x == "test-util" or x.startswith("test-util/") for x in enabled):
            _need(not any(x.startswith("test-util/") for x in enabled), "test-util feature enabled")
            _need(proof["role"] == "baseline" and pkg.get("name") == "tokio" and pkg.get("version") == "1.54.1" and pkg.get("source") == _REVIEWED_SOURCE and any(by_id[package_id].get("name") == "n0-future" for package_id in closure), "test-util feature enabled")
            _validate_n0future(proof, (raw, by_id, nodes, root, None, None, bindings))
        features[key] = tuple(sorted(set(enabled)))
        if pkg.get("name") == "shaar":
            runtime[key] = pkg.get("manifest_path")
    tree = _record(proof, "tree").decode("utf-8", "strict")
    _need(tree.strip() and "native-graph-normal-consumer" in tree and "shaar" in tree, "tree lacks consumer/shaar evidence")
    return raw, by_id, nodes, root, features, identities, bindings, _sha(tree.encode())


def _build(proof, packages, nodes):
    from evidence import audit_units

    _record(proof, "build")
    def stable_identity(pkg):
        if pkg.get("name") == "native-graph-normal-consumer":
            return ("consumer", "0.0.0", "workspace-root")
        pid = pkg["id"]
        return (pkg["name"], pkg["version"], _stable_source(pkg, proof.get("source_bindings", {}), pid, proof))

    def baseline_test_util_validator(pkg):
        pid = pkg.get("id")
        if not (proof.get("role") == "baseline" and pkg.get("name") == "tokio" and pkg.get("version") == "1.54.1" and pkg.get("source") == _REVIEWED_SOURCE and proof.get("lock_checksums", {}).get(pid) == _APPROVED_ARCHIVES["tokio-1.54.1-test-util"]):
            return False
        _validate_n0future(proof, (None, packages, nodes, None, None, None, proof.get("source_bindings", {})), require_route=True)
        return True

    try:
        emitted, normalized = audit_units(proof, list(packages.values()), nodes, stable_identity, baseline_test_util_validator)
    except ValueError as exc:
        raise AuditError(str(exc)) from exc
    _need(any(unit["package"][0] == "shaar" and "lib" in unit["kind"] for unit in normalized), "missing normal shaar library artifact")
    return emitted, normalized


def _validate_n0future(proof, parsed, require_route=False):
    raw, packages, nodes = parsed[:3]
    role = proof["role"]
    if len(parsed) > 5 and parsed[5] is not None:
        reachable = set(parsed[5].values())
    else:
        roots = [p["id"] for p in packages.values() if p.get("name") == "native-graph-normal-consumer"]
        _need(len(roots) == 1 and roots[0] in nodes, role + ": consumer root missing")
        reachable, stack = set(), roots[:]
        while stack:
            pid = stack.pop()
            if pid in reachable:
                continue
            _need(pid in nodes and pid in packages, role + ": unknown dependency target")
            reachable.add(pid)
            for dep in nodes[pid].get("deps", []):
                if any(k.get("kind") in (None, "normal") for k in dep.get("dep_kinds", [])):
                    stack.append(dep["pkg"])
    futures = [pid for pid, pkg in packages.items() if pid in reachable and pkg.get("name") == "n0-future"]
    if not futures:
        _need(not require_route, role + ": missing n0future route")
        return
    _need(len(futures) == 1 and packages[futures[0]].get("version") == "0.3.2", role + ": invalid n0future identity")
    future = futures[0]
    binding = parsed[6].get(future, {})
    if role == "baseline":
        _need(packages[future].get('source') == _REVIEWED_SOURCE and proof.get('lock_checksums', {}).get(future) == _APPROVED_ARCHIVES['n0-future'], role + ": n0future registry identity mismatch")
    else:
        _need(packages[future].get("source") is None and binding.get("identity") == "prepared" and binding.get("package") == "n0-future" and binding.get("version") == "0.3.2" and binding.get("archive_sha256") == _APPROVED_ARCHIVES["n0-future"], role + ": n0future is not the pinned prepared archive")
    toks = [pid for pid, pkg in packages.items() if pid in reachable and pkg.get("name") == "tokio" and pkg.get("version") == "1.54.1"]
    _need(len(toks) == 1, role + ": expected unique tokio 1.54.1")
    tokio = toks[0]
    def edges(source, target, kind="normal"):
        return sum(1 for dep in nodes[source].get("deps", []) if dep.get("pkg") == target and any(k.get("kind") in (None, kind) for k in dep.get("dep_kinds", [])))
    iroh = [pid for pid, pkg in packages.items() if pid in reachable and pkg.get("name") == "iroh" and pkg.get("version") == "1.3.0"]
    _need(len(iroh) == 1, role + ": expected unique iroh 1.3.0")
    iroh = iroh[0]
    shaar = [pid for pid, pkg in packages.items() if pid in reachable and pkg.get("name") == "shaar"]
    _need(len(shaar) == 1 and edges(shaar[0], iroh) == 1 and edges(iroh, future) == 1 and edges(future, tokio) == 1, role + ": invalid n0future normal route")
    target = "cfg(not(all(target_family = \"wasm\", target_os = \"unknown\")))"
    native_normal = [d for d in packages[future].get("dependencies", []) if d.get("name") == "tokio" and d.get("kind") in (None, "normal") and d.get("target") == target]
    _need(len(native_normal) == 1 and native_normal[0].get("req") == "^1.28" and set(native_normal[0].get("features", [])) == {"rt", "time", "macros"} | ({"test-util"} if role == "baseline" else set()), role + ": invalid n0future tokio declaration")
    for owner_id in reachable:
        for declaration in packages[owner_id].get('dependencies',[]):
            if declaration.get('kind') in (None,'normal') and declaration.get('name')=='tokio' and 'test-util' in declaration.get('features',[]):
                _need(role=='baseline' and owner_id==future and declaration.get('target')==target,'unapproved normal test-util requester')
    dev = [d for d in packages[future].get("dependencies", []) if d.get("name") == "tokio" and d.get("kind") == "dev" and d.get("target") == target]
    if role != "baseline":
        _need(len(dev) == 1 and dev[0].get("req") == "^1.28" and dev[0].get("features", []) == ["test-util"], role + ": invalid n0future tokio dev declaration")
    else:
        _need(not dev, "baseline original native dev declaration unexpectedly changed")
    enabled = set(nodes[tokio].get("features", []))
    _need({"rt", "time", "macros"} <= enabled and ((role == "baseline" and "test-util" in enabled) or (role != "baseline" and "test-util" not in enabled)), role + ": tokio feature role mismatch")
    _need(proof.get("lock_checksums", {}).get(tokio) and _DIGEST.fullmatch(str(proof["lock_checksums"][tokio])), role + ": tokio checksum missing")


def _candidate_matches_control(parsed, unitsets):
    """Admit only the exact approved control-to-candidate multibase transition."""
    cf, xf = parsed["approved_route"][4], parsed["candidate"][4]
    registry_key = next((k for k in cf if k[:2] == _MULTIBASE_IDENTITY
                         and k[2] == _REVIEWED_SOURCE + ":" + _MULTIBASE_CHECKSUM), None)
    chain_keys = {k for k in cf if k[0] in _EMOJI_DROPS
                  and k[1] == _EMOJI_DROPS[k[0]][0]
                  and k[2] == _REVIEWED_SOURCE + ":" + _EMOJI_DROPS[k[0]][1]}
    present = any(k[0] in _EMOJI_DROPS for k in cf)
    if registry_key is None and not present:
        _need(xf == cf, "candidate package features differ from approved route")
        _need(unitsets["approved_route"] == unitsets["candidate"],
              "candidate compiler units differ from approved route")
        return
    _need(registry_key is not None and present and len(chain_keys) == 3,
          "approved multibase transition control state mismatch")
    _need(set(cf) - set(xf) == chain_keys | {registry_key},
          "unapproved control-to-candidate package removal")
    _need(len(set(xf) - set(cf)) == 1, "unapproved control-to-candidate package addition")
    prepared_key = next(iter(set(xf) - set(cf)))
    _need(prepared_key[:2] == _MULTIBASE_IDENTITY and prepared_key[2].startswith(
        "path:prepared:multibase@0.9.3:archive=" + _APPROVED_ARCHIVES["multibase"] + ":"),
        "unapproved prepared multibase identity")
    _need(cf[registry_key] == xf[prepared_key],
          "multibase feature drift across the approved transition")
    candidate_packages, bindings = parsed["candidate"][1], parsed["candidate"][6]
    ids = [pid for pid, pkg in candidate_packages.items() if pkg.get("name") == "multibase"]
    _need(len(ids) == 1 and candidate_packages[ids[0]].get("version") == "0.9.3"
          and candidate_packages[ids[0]].get("source") is None,
          "candidate multibase metadata identity mismatch")
    binding = bindings.get(ids[0], {})
    _need(binding.get("identity") == "prepared" and binding.get("package") == "multibase"
          and binding.get("archive_sha256") == _APPROVED_ARCHIVES["multibase"],
          "candidate multibase is not the pinned prepared archive")
    _need(not any(u["package"][0] in _EMOJI_DROPS for u in unitsets["candidate"]),
          "removed emoji-chain package still compiles")
    for unit in unitsets["candidate"]:
        for dep in unit.get("dependencies", []):
            _need(dep["unit"]["package"][0] not in _EMOJI_DROPS,
                  "retained unit still depends on a removed emoji-chain package: " + unit["package"][0])

    def _unit_form(unit):
        # Compare units by identity, dependency edges and dependency-owner fields;
        # only the recursive sha256 digests are dropped, because the approved
        # transition legitimately cascades them through every dependent unit.
        form = {key: value for key, value in unit.items() if key not in ("sha256", "dependencies")}
        package = form["package"]
        if package[:2] == _MULTIBASE_IDENTITY:
            form["package"] = (package[0], package[1], "multibase-transition")
        edges = []
        for dep in unit.get("dependencies", []):
            target = dep["unit"]["package"]
            if target[0] in _EMOJI_DROPS:
                continue
            if target[:2] == _MULTIBASE_IDENTITY:
                target = (target[0], target[1], "multibase-transition")
            owner = {key: dep["unit"][key] for key in _DEPENDENCY_OWNER_FIELDS}
            owner["package"] = target
            edges.append({"alias": dep["alias"], "kind": dep["kind"], "unit": owner})
        form["dependencies"] = sorted(edges, key=lambda item: json.dumps(item, sort_keys=True))
        return form

    def _sorted_forms(units):
        return sorted((_unit_form(u) for u in units
                       if u["package"][0] not in _EMOJI_DROPS),
                      key=lambda item: json.dumps(item, sort_keys=True))
    _need(_sorted_forms(unitsets["approved_route"]) == _sorted_forms(unitsets["candidate"]),
          "candidate compiler units differ beyond the approved multibase transition")


def compare_proofs(proofs, expected_base, expected_candidate, expected_control=None):
    """Validate role-bound Cargo evidence and return canonical content digests."""
    _need(isinstance(proofs, list) and len(proofs) == 3 and all(isinstance(p, dict) for p in proofs), "exactly three proof objects required")
    _need({p.get("role") for p in proofs} == set(_ROLES), "roles must be unique baseline, approved_route, candidate")
    by_role = {p["role"]: p for p in proofs}
    parsed, emitted, unitsets, artifact_digests = {}, {}, {}, {}
    for role in _ROLES:
        p = by_role[role]
        _need(p.get("context") == "normal", role + ": context must be normal")
        _need(p.get("revision") == (expected_candidate if role == "candidate" else expected_base), role + ": revision mismatch")
        _need(isinstance(p.get("records"), list) and len(p["records"]) == 3 and {r.get("kind") for r in p["records"] if isinstance(r, dict)} == set(_KINDS), role + ": invalid record set")
        _need(isinstance(p.get("consumer_cwd"), str), role + ": missing consumer_cwd")
        _need(p.get("artifacts") is not None and isinstance(p.get("artifacts"), dict), role + ": missing artifacts")
        _need("artifact_features" not in p, role + ": legacy package artifact commitment is not unit evidence")
        result = _metadata(p)
        parsed[role] = result
        _validate_n0future(p, result)
        if role in ("approved_route", "candidate"):
            _validate_reviewed_graph(p, result)
        emitted[role], unitsets[role] = _build(p, result[1], result[2])
        artifact_digests[role] = {name: _sha(data) for name, data in sorted(p["artifacts"].items()) if isinstance(data, bytes)}
        _need(len(artifact_digests[role]) == len(p["artifacts"]), role + ": artifact values must be bytes")
    _need(len({by_role[r]["consumer_cwd"] for r in _ROLES}) == len(_ROLES), "consumer worktrees must be distinct")
    for role in _ROLES:
        _need(isinstance(by_role[role].get("consumer_manifest"), str), role + ": missing consumer_manifest")
    _need(isinstance(expected_control, dict), "expected control commitments required")
    control = by_role["approved_route"]
    _need(control.get("base_manifest_sha256") == expected_control.get("root_manifest_sha256") and control.get("route_recipe_id") == expected_control.get("route_recipe_id"), "approved route commitments mismatch")
    _need(_DIGEST.fullmatch(str(control.get("base_manifest_sha256", ""))) and isinstance(control.get("route_recipe_id"), str) and control["route_recipe_id"], "approved route commitments missing")
    base, ctrl, cand = (parsed[r] for r in _ROLES)
    bf, cf, xf = base[4], ctrl[4], cand[4]
    for key in bf:
        if key not in cf:
            _need((key[0] == "iroh-dns" and key[1] == "1.3.0" and key[2].startswith("registry+")) or (key[0] == "n0-future" and key[1] == "0.3.2" and key[2].startswith("registry+") and key[2].endswith(":" + _APPROVED_ARCHIVES["n0-future"])), "unapproved baseline package removal: " + key[0])
    removed = set(bf) - set(cf)
    _need(len(removed) <= 2, "only pinned iroh-dns and n0future removals are permitted")
    for old in removed:
        _need((old[0] == "iroh-dns" and old[1] == "1.3.0" and old[2].startswith("registry+")) or (old[0] == "n0-future" and old[1] == "0.3.2" and old[2].startswith("registry+") and old[2].endswith(":" + _APPROVED_ARCHIVES["n0-future"])), "unapproved baseline package removal: " + old[0])
        _need(any(k[0] == old[0] and k[1] == old[1] for k in cf), "removed package lacks prepared replacement")
        replacement = next(k for k in cf if k[0] == old[0] and k[1] == old[1])
        if old[0] == "n0-future":
            _need(bf[old] == cf[replacement], "n0-future package features drift")
        archive = _APPROVED_ARCHIVES[old[0]]
        ids = [pid for pid, pkg in ctrl[1].items() if pkg.get("name") == old[0] and pkg.get("version") == old[1]]
        _need(replacement[2].startswith("path:prepared:") and len(ids) == 1 and ctrl[6].get(ids[0], {}).get("archive_sha256") == archive, old[0] + " replacement is not the pinned prepared archive")
    tokio_keys = [k for k in set(bf) & set(cf) if k[0] == "tokio" and k[1] == "1.54.1"]
    if any(k[0] == "n0-future" for k in bf):
        _need(len(tokio_keys) == 1, "n0future route requires stable tokio identity")
        tk = tokio_keys[0]
        _need(cf[tk] == tuple(x for x in bf[tk] if x != "test-util") and "test-util" in bf[tk] and "test-util" not in cf[tk], "approved tokio features must remove only test-util")
    if any(k[0] == "iroh-dns" and k[1] == "1.3.0" for k in removed):
        _need(any(k[0] == "iroh-dns" and k[1] == "1.3.0" and k[2].startswith("path:prepared:") for k in cf), "iroh-dns replacement missing")
    additions = set(cf) - set(bf)
    if any(k[0] == "n0-future" for k in additions):
        _need(all(any(pid in parsed[r][1] and parsed[r][1][pid].get("name") == "n0-future" for pid in parsed[r][1]) for r in ("approved_route", "candidate")), "n0future must be present in control and candidate")
    _need(all((k[0], k[1]) in _ADDED or (k[0], k[1]) in _REVIEWED_REGISTRY for k in additions), "unapproved normal package addition")
    _need(all(not k[2].startswith("path:prepared:") or (k[0], k[1]) in _ADDED for k in additions), "unapproved prepared source")
    for key in additions:
        if key[:2] in _REVIEWED_REGISTRY:
            _need(key[2] == _REVIEWED_SOURCE + ":" + _REVIEWED_REGISTRY[key[:2]], "unapproved reviewed registry identity")
    for name, version in _ADDED:
        package_ids = [pid for pid, pkg in ctrl[1].items() if pkg.get("name") == name and pkg.get("version") == version]
        if any(k[0] == name and k[1] == version and k[2].startswith("path:prepared:") for k in additions):
            _need(len(package_ids) == 1 and ctrl[6].get(package_ids[0], {}).get("archive_sha256") == _APPROVED_ARCHIVES[name], "prepared addition is not the pinned archive: " + name)
    delta = [{"package": list(k), "baseline": list(bf.get(k, ())), "approved_route": list(cf.get(k, ()))} for k in sorted(set(bf) | set(cf)) if bf.get(k) != cf.get(k)]
    allowed = control.get("approved_feature_deltas")
    _need(isinstance(allowed, list) and allowed == delta, "approved feature delta commitment mismatch")
    _candidate_matches_control(parsed, unitsets)
    for role in ("baseline", "approved_route", "candidate"):
        _need(emitted[role] <= set(parsed[role][1]), role + ": invalid emitted artifacts")
    return {
        "roles": list(_ROLES),
        "added_packages": [list(key) for key in sorted(additions)],
        "removed_packages": [
            list(key) for key in sorted(set(bf) - set(cf))
        ],
        "feature_deltas": delta,
        "tree_sha256": {
            role: parsed[role][7]
            for role in _ROLES
        },
        "artifacts": artifact_digests,
        "proof_sha256": {
            role: _sha(
                _canonical(
                    {
                        "role": role,
                        "revision": by_role[role]["revision"],
                        "source_bindings": by_role[role]["source_bindings"],
                        "artifacts": artifact_digests[role],
                        "tree": parsed[role][7],
                        "units": unitsets[role],
                        "features": sorted(
                            (list(key), list(value))
                            for key, value in parsed[role][4].items()
                        ),
                    }
                )
            )
            for role in _ROLES
        },
    }




def collect_capture(capture_dir, target_dir, context):
    """Validate and materialize compiler-wrapper capture receipts."""
    capture_dir = Path(capture_dir)
    target_dir = Path(target_dir)
    if not target_dir.is_absolute() or target_dir != target_dir.resolve():
        raise ValueError(f"target directory must be absolute and normalized: {target_dir}")
    for label, directory in (("capture", capture_dir), ("target", target_dir)):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"{label} directory missing or linked: {directory}")
    env = context.get("env")
    if not isinstance(env, dict):
        raise ValueError("capture context env must be a mapping")
    expected_env = {key: env.get(key) for key in (
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR")}
    if any(not isinstance(value, str) for value in expected_env.values()):
        raise ValueError("capture context env is missing required wrapper values")
    if not expected_env["RUSTC_WRAPPER"] or not expected_env["CARGO_TARGET_DIR"]:
        raise ValueError("capture context env is missing required wrapper values")
    if expected_env["RUSTC_WORKSPACE_WRAPPER"] != "":
        raise ValueError("capture context env workspace wrapper must be empty")
    if expected_env["CARGO_TARGET_DIR"] != str(target_dir):
        raise ValueError("capture context target directory mismatch")
    if any(not isinstance(context.get(key), str) or not context.get(key)
           for key in ("role", "revision", "nonce", "recipe_sha256", "compiler")):
        raise ValueError("capture context is missing required values")
    prepare = None
    if all(key in context for key in ("host", "packages", "lock_checksums")):
        import prepare as prepare_module
        prepare = prepare_module

    entries = sorted(capture_dir.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise AuditError("capture directory contains symlink entries")
    files = [
        path
        for path in entries
        if path.is_file() and path.parent == capture_dir and path.suffix == ".json"
    ]
    if not files:
        raise ValueError("capture directory contains no receipts")
    receipts = []
    raw = {}
    owners = set()
    snapshot_owners = set()
    ordinary_compile = False
    for path in files:
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise ValueError(f"unknown or linked capture file: {path.name}")
        try:
            data = path.read_bytes()
            raw[path.name] = data
            value = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid UTF-8 JSON receipt {path.name}: {error}") from error
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ValueError(f"unsupported receipt schema: {path.name}")
        for key in ("role", "revision", "nonce", "recipe_sha256", "compiler"):
            if value.get(key) != context.get(key):
                raise ValueError(f"receipt {path.name} context mismatch: {key}")
        if value.get("env") != expected_env:
            raise ValueError(f"receipt {path.name} environment mismatch")
        stdin_shape = None
        if value.get("stdin") is not None:
            import stdin_probes
            item = value["stdin"]
            if (not isinstance(item, dict) or set(item) != {"snapshot", "size"} or
                    not isinstance(item["snapshot"], str) or type(item["size"]) is not int or
                    item["size"] > 4096):
                raise ValueError("invalid stdin capability probe")
            snapshot = Path(item["snapshot"])
            if (not snapshot.is_absolute() or snapshot != snapshot.resolve() or
                    ".." in snapshot.parts or not snapshot.is_relative_to(capture_dir.resolve()) or
                    snapshot.parent == capture_dir.resolve() or
                    any(parent.is_symlink() for parent in (snapshot, *snapshot.parents))):
                raise ValueError("invalid stdin capability probe")
            if not snapshot.is_file() or snapshot.stat().st_size > 4096:
                raise ValueError("invalid stdin capability probe")
            relative = snapshot.relative_to(capture_dir.resolve()).as_posix()
            if snapshot in snapshot_owners:
                raise ValueError("invalid stdin capability probe")
            snapshot_owners.add(snapshot)
            data = snapshot.read_bytes()
            raw[relative] = data
            stdin_shape = stdin_probes.classify(value, target_dir, context.get("host"), context.get("packages", []), context.get("lock_checksums", {}), data)
            if stdin_shape is None:
                raise ValueError("invalid stdin capability probe")
        auxiliary = None
        if prepare is not None and value.get("kind") == "compile":
            auxiliary = prepare.auxiliary_probe_shape(
                value, target_dir, context.get("host"),
                context.get("packages"), context.get("lock_checksums"))
        if value.get("launch_error") is not None or (value.get("exit_code") != 0 and auxiliary is None):
            raise ValueError(f"capture failed: {path.name}")
        args, cwd = value.get("args"), value.get("cwd")
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise ValueError(f"invalid args in receipt: {path.name}")
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            raise ValueError(f"invalid cwd in receipt: {path.name}")
        probe = any(arg in {"-V", "--version", "-vV", "--print"} or arg.startswith("--print=") for arg in args)
        if not probe and '-' in args and stdin_shape is None:
            raise ValueError('stdin compile lacks approved source evidence')
        if probe:
            if value.get("kind") != "probe" or value.get("outputs") != [] or value.get("snapshots") != []:
                raise ValueError(f"invalid probe kind, outputs, or snapshots: {path.name}")
        else:
            if value.get("kind") != "compile":
                raise ValueError(f"invalid compile kind: {path.name}")
            for key in ("package_name", "package_version", "manifest_dir"):
                if not isinstance(value.get(key), str) or not value[key]:
                    raise ValueError(f"missing {key} in compile receipt: {path.name}")
            out_dir_values = []
            for index, arg in enumerate(args):
                if arg == "--out-dir":
                    if index + 1 < len(args):
                        out_dir_values.append(args[index + 1])
                    else:
                        out_dir_values.append("")
                elif arg.startswith("--out-dir="):
                    out_dir_values.append(arg[len("--out-dir="):])
            if len(out_dir_values) != 1 or not out_dir_values[0] or out_dir_values[0].startswith("-"):
                raise ValueError(f"invalid --out-dir in compile receipt: {path.name}")
            out_dir = Path(out_dir_values[0])
            if (not out_dir.is_absolute() or ".." in out_dir.parts
                    or out_dir.resolve() != out_dir
                    or (out_dir != target_dir and target_dir not in out_dir.parents)):
                raise ValueError(f"invalid compile output directory: {path.name}")
            outputs = value.get("outputs")
            snapshots = value.get("snapshots")
            if auxiliary is None and (not isinstance(outputs, list) or not outputs):
                raise ValueError(f"compile receipt has no outputs: {path.name}")
            if auxiliary is not None:
                expected_outputs = [] if value.get("exit_code") != 0 else [
                    str(out_dir / f"lib{auxiliary['package'].replace('-', '_')}.rmeta"),
                    str(out_dir / f"{auxiliary['package'].replace('-', '_')}.d")]
                if outputs != expected_outputs:
                    raise ValueError(f"invalid auxiliary outputs: {path.name}")
                if value.get("exit_code") != 0 and (outputs != [] or snapshots != []):
                    raise ValueError(f"failed auxiliary receipt has outputs: {path.name}")
            if not isinstance(outputs, list) or (auxiliary is None and not outputs):
                raise ValueError(f"compile receipt has no outputs: {path.name}")
            if not isinstance(snapshots, list) or len(snapshots) != len(outputs):
                raise ValueError(f"invalid snapshots in compile receipt: {path.name}")
            snapshot_by_output = {}
            for item in snapshots:
                if not isinstance(item, dict) or not isinstance(item.get("output"), str) or item["output"] in snapshot_by_output:
                    raise ValueError(f"invalid snapshot entry in compile receipt: {path.name}")
                snapshot = Path(item.get("snapshot", ""))
                if not snapshot.is_absolute() or ".." in snapshot.parts or snapshot.resolve() != snapshot or snapshot == capture_dir or capture_dir not in snapshot.parents or snapshot.parent == capture_dir:
                    raise ValueError(f"snapshot escapes capture directory or is not nested: {path.name}")
                if snapshot in snapshot_owners:
                    raise ValueError(f"duplicate snapshot path: {snapshot}")
                snapshot_owners.add(snapshot)
                cursor = snapshot
                while cursor != capture_dir:
                    if cursor.is_symlink():
                        raise ValueError(f"linked snapshot path: {snapshot}")
                    cursor = cursor.parent
                if snapshot.is_symlink() or not snapshot.is_file():
                    raise ValueError(f"snapshot missing or not regular: {snapshot}")
                snapshot_by_output[item["output"]] = snapshot
            if set(snapshot_by_output) != set(outputs):
                raise ValueError(f"snapshots do not match outputs: {path.name}")
            if auxiliary is None and stdin_shape is None:
                ordinary_compile = True
            value["kind"] = "compile"
            enriched = []
            for output in outputs:
                if not isinstance(output, str) or not Path(output).is_absolute():
                    raise ValueError(f"output path is not absolute: {path.name}")
                out = Path(output)
                if ".." in out.parts:
                    raise ValueError(f"output path contains parent component: {output}")
                if out.resolve() != out:
                    raise ValueError(f"output path is not normalized: {output}")
                if out.parent != out_dir:
                    raise ValueError(f"output is not owned by invocation out-dir: {output}")
                if out != target_dir and target_dir not in out.parents:
                    raise ValueError(f"output escapes target directory: {output}")
                cursor = out
                if auxiliary is None and stdin_shape is None:
                    while cursor != target_dir:
                        if cursor.is_symlink():
                            raise ValueError(f"linked output path: {output}")
                        cursor = cursor.parent
                    if out.is_symlink() or not out.is_file():
                        raise ValueError(f"output missing or not regular: {output}")
                    if output in owners:
                        raise ValueError(f"duplicate output owner: {output}")
                    owners.add(output)
                data = snapshot_by_output[output].read_bytes()
                if auxiliary is None and stdin_shape is None:
                    out_data = out.read_bytes()
                    if data != out_data:
                        raise ValueError(f"snapshot bytes differ from output: {output}")
                snapshot = snapshot_by_output[output]
                snapshot_data = data
                snapshot_relative = snapshot.relative_to(capture_dir).as_posix()
                raw[snapshot_relative] = snapshot_data
                enriched.append({"path": output, "size": len(data), "sha256": _sha(data), "snapshot_path": snapshot_relative})
            value["outputs"] = enriched
        receipts.append((path.name, value))
    inventory = {path.relative_to(capture_dir).as_posix() for path in entries if path.is_file()}
    expected_dirs = {parent for snapshot in snapshot_owners for parent in snapshot.parents if capture_dir in parent.parents}
    actual_dirs = {path for path in entries if path.is_dir()}
    if actual_dirs != expected_dirs:
        raise ValueError("capture directories do not match snapshot paths")
    if inventory != set(raw):
        raise ValueError("capture inventory does not match receipt and snapshot files")
    if not ordinary_compile:
        raise ValueError("capture has no compile receipt")
    return {"raw": raw, "units": [value for _, value in receipts]}


def audit_auxiliary(probes, proof, packages, cargo, messages, normalized, unit_by_output, stable_identity):
    """Forward auxiliary audit to the prepare module."""
    import prepare
    return prepare.audit_auxiliary(
        probes, proof, packages, cargo, messages, normalized, unit_by_output, stable_identity)


def audit_compiler_units(proof, packages, buildbytes, recipebytes):
    """Forward compiler-unit auditing to the capability fixture module."""
    from capability_fixture import audit_compiler_units as _audit_compiler_units
    return _audit_compiler_units(proof, packages, buildbytes, recipebytes)
