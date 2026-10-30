"""CI-only product-derived fixture graph with explicit reviewed observability deltas."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

ROOTS = {"shaar", "shaar-p2p", "iroh", "noq", "noq-proto", "libp2p", "libp2p-relay", "tokio"}
PATCHED = {"iroh", "noq", "noq-proto"}
PROBE_LOCK_SHA = "122e16a01b4b2d76a4ace23b2a25caba8856b2996fe901b1300e4c686a706b16"


def shared(repo):
    path = repo / ".github/scripts/p2p/carrier-wire-proof/graph.py"
    spec = importlib.util.spec_from_file_location("carrier_frames_product_copy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def metadata(root):
    output = subprocess.check_output(["cargo", "metadata", "--locked", "--format-version=1"], cwd=root)
    return json.loads(output)


def identity(package):
    return package["name"], package["version"], package.get("source")


def lock_blocks(text):
    parts = text.split("[[package]]")
    result = {}
    for block in parts[1:]:
        data = tomllib.loads("[[package]]" + block)
        if set(data) != {"package"} or len(data["package"]) != 1:
            raise ValueError("unexpected lock section in fixture input")
        package = data["package"][0]
        key = identity(package)
        if key in result:
            raise ValueError("duplicate lock identity")
        result[key] = (package, block)
    return parts[0], result


def resolve(reference, packages):
    match = re.fullmatch(r"([A-Za-z0-9_-]+)(?: ([^ ()]+))?(?: \(([^)]+)\))?", reference)
    if not match:
        raise ValueError("unsupported lock dependency reference")
    name, version, source = match.groups()
    found = [key for key in packages if key[0] == name and (version is None or key[1] == version)
             and (source is None or key[2] == source)]
    if len(found) != 1:
        raise ValueError("missing or ambiguous lock dependency: " + reference)
    return found[0]


def derive_lock(product_text, reviewed_text):
    prefix, product = lock_blocks(product_text)
    _, reviewed = lock_blocks(reviewed_text)
    for key in set(product) & set(reviewed):
        if key[2] is not None and product[key][0].get("checksum") != reviewed[key][0].get("checksum"):
            raise ValueError("reviewed and product checksums disagree for one registry identity")
    selected = dict(product)
    edges = {key: {resolve(dependency, product) for dependency in package.get("dependencies", [])}
             for key, (package, _) in product.items()}
    overrides = {}
    for name in PATCHED:
        keys = [key for key in product if key[:2] == (name, "1.3.0") and key[2] is None]
        if len(keys) != 1:
            raise ValueError("prepared product path identity missing: " + name)
        overrides[name] = keys[0]

    def include(key):
        if key[0] in overrides and key[1] == "1.3.0":
            return overrides[key[0]]
        if key in selected:
            return key
        package, block = reviewed[key]
        if not key[2] or not key[2].startswith("registry+"):
            raise ValueError("observation graph cannot add an unreviewed path identity")
        selected[key] = (package, block)
        edges[key] = set()
        for dependency in package.get("dependencies", []):
            edges[key].add(include(resolve(dependency, reviewed)))
        return key

    for name, key in overrides.items():
        candidates = [entry for entry in reviewed if entry[:2] == (name, "1.3.0")]
        if len(candidates) != 1:
            raise ValueError("reviewed observability package missing")
        package = reviewed[candidates[0]][0]
        edges[key].update(include(resolve(dependency, reviewed)) for dependency in package.get("dependencies", []))
    sdk = [key for key in product if key[0] == "shaar" and key[2] is None]
    jsons = [key for key in reviewed if key[:2] == ("serde_json", "1.0.154")]
    if len(sdk) != 1 or len(jsons) != 1:
        raise ValueError("reviewed SDK JSON observation identity missing")
    edges[sdk[0]].add(include(jsons[0]))

    def reference(key):
        names = [other for other in selected if other[0] == key[0]]
        if len(names) == 1:
            return key[0]
        versions = [other for other in names if other[1] == key[1]]
        if len(versions) == 1:
            return key[0] + " " + key[1]
        if key[2] is None:
            raise ValueError("ambiguous path dependency identity")
        return key[0] + " " + key[1] + " (" + key[2] + ")"

    output = prefix
    pattern = re.compile(r"\ndependencies = \[\n.*?\n\]", re.S)
    for key in sorted(selected, key=lambda key: (key[0], key[1], key[2] or "")):
        package, block = selected[key]
        dependencies = sorted(reference(dependency) for dependency in edges[key])
        replacement = "\ndependencies = [\n" + "".join(" " + json.dumps(item) + ",\n" for item in dependencies) + "]"
        if "dependencies" in package:
            if len(pattern.findall(block)) != 1:
                raise ValueError("lock dependency array layout changed")
            block = pattern.sub(lambda _: replacement, block, count=1)
        elif dependencies:
            block = block.rstrip() + replacement + "\n\n"
        output += "[[package]]" + block
    parsed = tomllib.loads(output)
    actual = {identity(package): package for package in parsed["package"]}
    if set(actual) != set(selected):
        raise ValueError("derived lock identity serialization changed")
    for key in product:
        if actual[key].get("checksum") != product[key][0].get("checksum"):
            raise ValueError("fixture changed an existing product checksum")
    return output, {"added_registry_identities": [list(key) for key in sorted(set(selected) - set(product))],
                    "existing_versions_and_checksums_preserved": True}


def copy_product(repo, product, destination):
    helper = shared(repo)
    destination.resolve().relative_to((repo / "target").resolve())
    paths = helper.product_paths(repo, product)
    hashes = helper.selected_hashes(repo, paths)
    destination.mkdir(parents=True, exist_ok=False)
    for name in paths:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / name, target)
    rebased = helper.rebase_manifests(repo, destination)
    if hashes != helper.selected_hashes(repo, paths):
        raise ValueError("product changed while taking frame fixture snapshot")
    return {"product_source_sha256": hashes, "manifest_path_rebases": rebased}, paths


def observation_reference(repo, root):
    helper = shared(repo)
    reviewed = (repo / ".github/probes/iroh-paths/Cargo.lock").read_bytes()
    if helper.digest(reviewed) != PROBE_LOCK_SHA:
        raise ValueError("reviewed observation lock changed")
    lock = (root / "Cargo.lock").read_bytes()
    manifest = root / "crates/shaar/Cargo.toml"
    original = manifest.read_bytes()
    anchor = 'features = ["tls-ring", "unstable-custom-transports"]'
    if original.decode().count(anchor) != 1 or b"dev-dependencies.serde_json" in original:
        raise ValueError("SDK observation feature anchor changed")
    transformed = original.decode().replace(anchor, 'features = ["tls-ring", "unstable-custom-transports", "qlog"]', 1)
    transformed += '\n[dev-dependencies.serde_json]\nversion = "=1.0.154"\ndefault-features = false\nfeatures = ["std"]\n'
    manifest.write_bytes(transformed.encode())
    derived, receipt = derive_lock(lock.decode(), reviewed.decode())
    (root / "Cargo.lock").write_bytes(derived.encode())
    return {**receipt, "product_lock_sha256": helper.digest(lock), "fixture_lock_sha256": helper.digest(derived.encode()),
            "manifest_before": helper.digest(original), "manifest_after": helper.digest(transformed.encode()),
            "declared_delta": "iroh/qlog and reviewed serde_json test parser only"}


def closure(data):
    packages = {package["id"]: package for package in data["packages"]}
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
    roots = [key for key, package in packages.items() if package["name"] in ROOTS]
    if len(roots) != len(ROOTS):
        raise ValueError("frame runtime roots missing or ambiguous")
    pending, found = roots[:], set()
    while pending:
        key = pending.pop()
        if key in found:
            continue
        found.add(key)
        pending.extend(dependency["pkg"] for dependency in nodes[key]["deps"]
                       if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]))
    def key(identity_id):
        return identity(packages[identity_id])
    result = {key(package_id): (set(nodes[package_id]["features"]),
              {(dependency["name"], key(dependency["pkg"]), kind["kind"], kind["target"])
               for dependency in nodes[package_id]["deps"] for kind in dependency["dep_kinds"] if kind["kind"] != "dev"})
              for package_id in found}
    if len(result) != len(found):
        raise ValueError("normalized frame graph identities are ambiguous")
    return result


def verify_reference(repo, product, reference):
    original = {identity(package): package for package in product["packages"]}
    observed = {identity(package): package for package in reference["packages"]}
    reviewed = tomllib.loads((repo / ".github/probes/iroh-paths/Cargo.lock").read_text(encoding="utf-8"))
    allowed = {identity(package) for package in reviewed["package"]}
    if not set(original) <= set(observed):
        raise ValueError("observation reference removed or replaced a product identity")
    if not set(observed) - set(original) <= allowed:
        raise ValueError("observation reference added a package absent from reviewed lock")
    before, after = closure(product), closure(reference)
    for key, (features, edges) in before.items():
        new_features, new_edges = after[key]
        if not features <= new_features or not edges <= new_edges:
            raise ValueError("observation reference removed a product feature or non-dev edge")
        if key[0] not in PATCHED and new_features != features:
            raise ValueError("unrelated product feature changed by qlog reference: " + key[0])
        if key[0] in PATCHED and new_features - features != {"qlog"} - features:
            raise ValueError("unexpected patched dependency observation feature delta")
        if key[0] not in PATCHED and new_edges != edges:
            raise ValueError("unrelated non-dev edge changed by observation reference")
    return {"product_packages": len(original), "observation_packages": len(observed),
            "only_reviewed_observation_identities": True, "product_features_retained": True}


def verify_variant(reference, actual, root, expected_lock, expected_paths):
    if not {"shaar", "shaar-p2p", "iroh", "noq", "noq-proto", "libp2p-relay"} <= set(expected_paths):
        raise ValueError("frame copied-source selection witness is incomplete")
    packages = {identity(package): package for package in actual["packages"]}
    for name, expected in expected_paths.items():
        selected = [package for package in packages.values() if package["name"] == name]
        if len(selected) != 1 or Path(selected[0]["manifest_path"]).resolve() != expected.resolve() / "Cargo.toml":
            raise ValueError("frame variant did not select its copied source: " + name)
    if closure(reference) != closure(actual):
        raise ValueError("instrumented frame variant changed reference features or normal/build edges")
    if (root / "Cargo.lock").read_bytes() != expected_lock:
        raise ValueError("frame compilation changed the independently derived reference lock")
    return {"exact_reference_features_and_edges": True, "reference_lock_unchanged": True,
            "runtime_packages": len(closure(actual))}
