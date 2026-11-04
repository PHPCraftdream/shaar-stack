# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validation and normalization for stdin-backed native graph probes."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

NUM_TRAITS_CHECKSUM = "071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841"
AUTOCFG_CHECKSUM = "f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
_SOURCES = {0: b"", 1: b"pub fn probe() { let _ = 1f64.total_cmp(&2f64); }"}


def validate_recipe(wrapper, context, source_path, source):
    def need(ok, message):
        if not ok:
            raise ValueError(message)

    recipe = wrapper.get("recipe")
    need(isinstance(recipe, list) and len(recipe) == 6 and recipe[1:3] == ["--edition=2024", "-Copt-level=0"] and
         recipe[3] == source_path and recipe[4] == "-o" and recipe[5] == wrapper.get("wrapper"), "wrapper recipe argv mismatch")
    version = wrapper.get("version", "")
    version_fields = dict(line.split(': ', 1) for line in version.splitlines() if ': ' in line)
    need(version_fields.get("release") == "1.99.1" and wrapper.get("target") == version_fields.get("host") and
         isinstance(wrapper.get("compiler"), str) and wrapper.get("compiler") == recipe[0], "wrapper compiler version/host mismatch")
    for digest in (wrapper.get("compiler_sha256"), wrapper.get("source_sha256"), wrapper.get("wrapper_sha256"), context.get("recipe_sha256")):
        need(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "invalid SHA-256 commitment")
    recipe_digest = hashlib.sha256(json.dumps({"argv": recipe, "source_sha256": hashlib.sha256(source).hexdigest(),
                                                "compiler_sha256": wrapper.get("compiler_sha256"), "version": version},
                                               sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    need(recipe_digest == context.get("recipe_sha256"), "wrapper recipe digest mismatch")


def classify(raw, target_dir, host, packages, checksums, data):
    if not isinstance(raw, dict) or not isinstance(data, bytes) or len(data) > 4096:
        return None
    if raw.get("kind") != "compile" or raw.get("exit_code") != 0 or raw.get("launch_error") is not None:
        return None
    if raw.get("package_name") != "num-traits" or raw.get("package_version") != "0.2.19":
        return None
    cwd_value, manifest_value = raw.get("cwd"), raw.get("manifest_dir")
    if not isinstance(cwd_value, str) or not isinstance(manifest_value, str):
        return None
    cwd, manifest_dir = Path(cwd_value), Path(manifest_value)
    target = Path(target_dir) if isinstance(target_dir, (str, Path)) else None
    if (not cwd.is_absolute() or not manifest_dir.is_absolute() or not target or not target.is_absolute()
            or ".." in cwd.parts or ".." in manifest_dir.parts or ".." in target.parts
            or cwd != manifest_dir):
        return None
    candidates = [p for p in packages if isinstance(p, dict) and p.get("name") == "num-traits"
                  and p.get("version") == "0.2.19" and p.get("source") == REGISTRY
                  and p.get("manifest_path") == str(cwd / "Cargo.toml")]
    if len(candidates) != 1:
        return None
    package = candidates[0]
    package_id = package.get("id")
    if checksums.get(package_id) != NUM_TRAITS_CHECKSUM:
        return None
    dependencies = package.get("dependencies")
    if not isinstance(dependencies, list):
        return None
    declarations = [d for d in dependencies if isinstance(d, dict) and d.get("name") == "autocfg"]
    if (len(declarations) != 1 or declarations[0].get("kind") != "build"
            or declarations[0].get("source") != REGISTRY or declarations[0].get("rename") is not None
            or declarations[0].get("target") is not None or declarations[0].get("optional") is not False):
        return None
    autocfg = [p for p in packages if isinstance(p, dict) and p.get("name") == "autocfg"
               and p.get("version") == "1.5.1" and p.get("source") == REGISTRY]
    if len(autocfg) != 1 or checksums.get(autocfg[0].get("id")) != AUTOCFG_CHECKSUM:
        return None
    targets = package.get("targets")
    build_targets = [t for t in targets if isinstance(t, dict) and "custom-build" in t.get("kind", [])] if isinstance(targets, list) else []
    if (len(build_targets) != 1 or build_targets[0].get("src_path") != str(cwd / "build.rs")
            or build_targets[0].get("name") != "build-script-build" or build_targets[0].get("crate_types") != ["bin"]):
        return None
    args = raw.get("args")
    if not isinstance(args, list) or len(args) != 9 or not all(isinstance(arg, str) for arg in args):
        return None
    match = re.fullmatch(r"autocfg_([0-9a-f]{16})_([01])", args[1])
    if (args[0] != "--crate-name" or args[2] != "--crate-type=lib" or args[3] != "--out-dir"
            or args[5:] != ["--emit=llvm-ir", "--target", host, "-"] or not isinstance(host, str)):
        return None
    if not match:
        return None
    nonce, counter = match.group(1), int(match.group(2))
    if data != _SOURCES[counter]:
        return None
    out = Path(args[4])
    expected_build = target / host / "debug" / "build"
    if (not out.is_absolute() or ".." in out.parts or out.name != "out" or out.parent.parent != expected_build
            or not re.fullmatch(r"num-traits-[0-9a-f]+", out.parent.name)):
        return None
    stdin = raw.get("stdin")
    if (not isinstance(stdin, dict) or set(stdin) != {"snapshot", "size"}
            or not isinstance(stdin.get("snapshot"), str)):
        return None
    snapshot = Path(stdin["snapshot"])
    if not snapshot.is_absolute() or ".." in snapshot.parts or type(stdin.get("size")) is not int or stdin.get("size") != len(data):
        return None
    expected_output = str(out / (args[1] + ".ll"))
    if raw.get("outputs") != [expected_output]:
        return None
    return {"counter": counter, "source": data.decode("utf-8"), "package_id": package_id,
            "autocfg_id": autocfg[0]["id"], "context": "target", "target": host,
            "out_dir": str(out), "nonce": nonce, "status": 0}


def validate_input_snapshot(raw, proof, snapshots, expected_names):
    """Validate and register a captured stdin snapshot without classifying it."""
    if not isinstance(raw, dict):
        return None
    stdin = raw.get("stdin")
    if stdin is None:
        return None
    if (not isinstance(stdin, dict) or set(stdin) != {"snapshot", "size"}
            or not isinstance(stdin.get("snapshot"), str)):
        raise ValueError("invalid stdin snapshot metadata")
    size = stdin.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 4096:
        raise ValueError("invalid stdin snapshot size")
    capture = proof.get("compiler_capture") if isinstance(proof, dict) else None
    context = capture.get("context") if isinstance(capture, dict) else None
    env = context.get("env") if isinstance(context, dict) else None
    capture_dir = env.get("SHAAR_CAPTURE_DIR") if isinstance(env, dict) else None
    path = Path(stdin["snapshot"])
    root = Path(capture_dir) if isinstance(capture_dir, str) else None
    if (root is None or not root.is_absolute() or not path.is_absolute()
            or ".." in root.parts or ".." in path.parts):
        raise ValueError("invalid stdin snapshot path")
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise ValueError("stdin snapshot is outside capture directory") from None
    if not relative.parts:
        raise ValueError("stdin snapshot cannot be capture directory")
    rel = relative.as_posix()
    if rel in expected_names:
        raise ValueError("duplicate stdin snapshot")
    data = snapshots.get(rel) if isinstance(snapshots, dict) else None
    if not isinstance(data, bytes) or len(data) != size:
        raise ValueError("stdin snapshot bytes or size mismatch")
    expected_names.add(rel)
    return rel


def classify_input(raw, proof, packages):
    """Classify stdin evidence using its captured artifact bytes."""
    if not isinstance(raw, dict) or raw.get("stdin") is None:
        return None
    stdin = raw.get("stdin")
    if not isinstance(stdin, dict) or not isinstance(stdin.get("snapshot"), str):
        raise ValueError("invalid stdin snapshot metadata")
    capture = proof.get("compiler_capture") if isinstance(proof, dict) else None
    context = capture.get("context") if isinstance(capture, dict) else None
    env = context.get("env") if isinstance(context, dict) else None
    target_dir = env.get("CARGO_TARGET_DIR") if isinstance(env, dict) else None
    host = capture.get("wrapper", {}).get("target") if isinstance(capture.get("wrapper"), dict) else None
    artifacts = proof.get("artifacts") if isinstance(proof, dict) else None
    try:
        relative = Path(stdin["snapshot"]).relative_to(Path(env["SHAAR_CAPTURE_DIR"])).as_posix()
    except (TypeError, KeyError, ValueError):
        raise ValueError("invalid stdin snapshot path") from None
    consumer = proof.get("consumer_cwd")
    prefix = Path(consumer).name + "/compiler-capture/" if isinstance(consumer, str) else None
    data = artifacts.get(prefix + relative) if isinstance(artifacts, dict) and prefix else None
    if not isinstance(data, bytes):
        raise ValueError("stdin snapshot is absent")
    shape = classify(raw, target_dir, host, packages, proof.get("lock_checksums", {}), data)
    if shape is None:
        raise ValueError("stdin evidence could not be classified")
    return shape


def audit(probes, proof, packages, cargo, messages, artifact_units, stable_identity, nodes):
    """Validate stdin probe evidence against the captured graph and artifacts."""
    import json

    def fail(message):
        raise ValueError("invalid stdin probe evidence: " + message)

    if not isinstance(probes, list) or not isinstance(proof, dict):
        fail("invalid probes or proof")
    if not isinstance(packages, list) or not isinstance(cargo, list) or not isinstance(messages, list):
        fail("invalid graph evidence")
    if not isinstance(artifact_units, dict) or not isinstance(nodes, dict):
        fail("invalid artifact ownership evidence")
    if not probes:
        return []
    artifacts = proof.get("artifacts")
    capture = proof.get("compiler_capture")
    if not isinstance(artifacts, dict) or not isinstance(capture, dict):
        fail("missing captured stdin artifacts")
    env = capture.get("context", {}).get("env", {})
    target_dir = env.get("CARGO_TARGET_DIR") if isinstance(env, dict) else None
    host = capture.get("wrapper", {}).get("target") if isinstance(capture.get("wrapper"), dict) else None
    if not isinstance(target_dir, str) or not isinstance(host, str):
        fail("missing target or host")
    checksums = proof.get("lock_checksums", {})
    pairs = {}
    normalized = []
    for item in probes:
        if not isinstance(item, tuple) or len(item) != 2:
            fail("probe must contain raw evidence and shape")
        raw, shape = item
        if not isinstance(raw, dict) or not isinstance(shape, dict):
            fail("invalid raw evidence or shape")
        snapshot = raw.get("stdin")
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("snapshot"), str):
            fail("missing stdin snapshot")
        relative = Path(snapshot["snapshot"]).relative_to(Path(env["SHAAR_CAPTURE_DIR"])).as_posix()
        data = artifacts.get(Path(proof["consumer_cwd"]).name + "/compiler-capture/" + relative)
        if not isinstance(data, bytes):
            fail("stdin snapshot is absent")
        checked = classify(raw, target_dir, host, packages, checksums, data)
        if checked != shape:
            fail("probe classification mismatch")
        pid, autoid, counter = shape.get("package_id"), shape.get("autocfg_id"), shape.get("counter")
        num = [p for p in packages if isinstance(p, dict) and p.get("id") == pid and p.get("name") == "num-traits"]
        auto = [p for p in packages if isinstance(p, dict) and p.get("id") == autoid and p.get("name") == "autocfg"]
        if len(num) != 1 or len(auto) != 1:
            fail("package identity is not unique")
        node = nodes.get(pid)
        deps = node.get("deps") if isinstance(node, dict) else None
        edges = [d for d in deps if isinstance(d, dict) and d.get("name") == "autocfg" and d.get("pkg") == autoid
                 and isinstance(d.get("dep_kinds"), list) and any(k.get("kind") == "build" and k.get("target") is None for k in d["dep_kinds"] if isinstance(k, dict))] if isinstance(deps, list) else []
        if len(edges) != 1:
            fail("autocfg build dependency is not unique")
        customs = [a for a in cargo if isinstance(a, dict) and a.get("package_id") in (pid, num[0].get("name") + " " + num[0].get("version"))
                   and isinstance(a.get("target"), dict) and "custom-build" in a["target"].get("kind", [])]
        if len(customs) != 1 or customs[0].get("executable") is not None:
            fail("num-traits custom-build artifact is not unique")
        owner = artifact_units.get(id(customs[0]))
        if not isinstance(owner, tuple) or len(owner) != 3 or owner[1] is not num[0]:
            fail("custom-build artifact ownership mismatch")
        unit, package, row = owner
        if not isinstance(unit, dict) or package is not num[0] or not isinstance(row, dict):
            fail("invalid custom-build owner")
        if unit.get('context') != 'host' or row.get('kind') != ['custom-build']:
            fail("invalid custom-build owner context")
        unit_deps = unit.get('dependencies')
        if not isinstance(unit_deps, list) or not any(
            isinstance(d, dict)
            and d.get('alias') == 'autocfg'
            and isinstance(d.get('kind'), list)
            and 'build' in d['kind']
            and isinstance(d.get('unit'), dict)
            and d['unit'].get('package') == stable_identity(auto[0])
            and d['unit'].get('context') == 'host'
            and 'lib' in d['unit'].get('kind', [])
            for d in unit_deps
        ):
            fail("normalized build dependency mismatch")
        owner_hash = unit['sha256']
        executions = [m for m in messages if isinstance(m, dict) and m.get("reason") == "build-script-executed" and m.get("package_id") in (pid, num[0].get("name") + " " + num[0].get("version")) and m.get("out_dir") == shape.get("out_dir")]
        if len(executions) != 1:
            fail("build-script execution is not unique")
        key = pid
        entry = pairs.setdefault(key, {"nonce": shape.get("nonce"), "out_dir": shape.get("out_dir"), "counters": set()})
        if entry["nonce"] != shape.get("nonce") or entry["out_dir"] != shape.get("out_dir") or counter in entry["counters"]:
            fail("duplicate or inconsistent probe")
        entry["counters"].add(counter)
        normalized.append({"package": stable_identity(num[0]), "kind": ["auxiliary-stdin-probe"],
                           "source": shape["source"], "counter": counter, "status": 0,
                           "context": "target", "triple": shape["target"], "features": [], "owner": owner_hash})
    if any(group["counters"] != {0, 1} for group in pairs.values()):
        fail("incomplete probe pair")
    return sorted(normalized, key=lambda unit: json.dumps(unit, sort_keys=True, separators=(",", ":")))
