"""Mirror resolved production features over the driver's normal/build closure."""
import hashlib
import json
from pathlib import Path
import tomllib

SEEDS = ("noq", "tokio", "rustls", "rcgen")


def closure(metadata):
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    seeds = {}
    for name in SEEDS:
        matches = [key for key, package in packages.items() if package["name"] == name]
        if len(matches) != 1:
            raise ValueError(f"ambiguous driver closure seed: {name}")
        seeds[name] = matches[0]
    pending = list(seeds.values())
    reached = set()
    while pending:
        key = pending.pop()
        if key in reached:
            continue
        reached.add(key)
        pending.extend(dep["pkg"] for dep in nodes[key]["deps"]
                       if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
    return packages, nodes, seeds, reached


def identity(package):
    return package["name"], package["version"], package.get("source")


def manifest_dependencies(metadata):
    packages, nodes, seeds, reached = closure(metadata)
    names = {key: name for name, key in seeds.items()}
    lines = []
    for index, key in enumerate(sorted(reached)):
        package = packages[key]
        alias = names.get(key, f"proof_dependency_{index}")
        features = sorted(nodes[key]["features"])
        fields = f'package = {json.dumps(package["name"])}, version = "={package["version"]}"'
        if package.get("source") is None:
            fields += f', path = {json.dumps(Path(package["manifest_path"]).parent.resolve().as_posix())}'
        elif not package["source"].startswith("registry+"):
            raise ValueError("unreviewed non-registry closure source")
        lines.append(f'{alias} = {{ {fields}, default-features = false, features = {json.dumps(features)} }}')
    return "\n".join(lines) + "\n"


def verify(product_lock, fixture_lock, baseline_path):
    baseline_lock = tomllib.loads(product_lock.read_text(encoding="utf-8"))["package"]
    fixture_packages = tomllib.loads(fixture_lock.read_text(encoding="utf-8"))["package"]
    lock_identity = lambda p: tuple(p.get(key) for key in ("name", "version", "source", "checksum"))
    allowed = {lock_identity(package) for package in baseline_lock}
    for package in fixture_packages:
        if package["name"] != "noq-driver-product-proof" and lock_identity(package) not in allowed:
            raise ValueError(f"fixture changed product identity: {package['name']}")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    actual = json.loads(fixture_lock.with_name("metadata.json").read_text(encoding="utf-8"))
    expected_packages, expected_nodes, _, expected_closure = closure(baseline)
    actual_packages, actual_nodes, _, actual_closure = closure(actual)
    expected_by_identity = {identity(expected_packages[key]): key for key in expected_closure}
    actual_by_identity = {identity(actual_packages[key]): key for key in actual_closure}
    if expected_by_identity.keys() != actual_by_identity.keys():
        raise ValueError("driver dependency closure differs from production")
    receipt = []
    for package_identity, expected_id in sorted(expected_by_identity.items()):
        actual_id = actual_by_identity[package_identity]
        expected = expected_nodes[expected_id]
        resolved = actual_nodes[actual_id]
        if set(expected["features"]) != set(resolved["features"]):
            raise ValueError(f"driver feature mismatch: {package_identity}: {expected['features']} != {resolved['features']}")
        def edges(node, packages):
            return sorted((dep["name"], identity(packages[dep["pkg"]]),
                           sorted((kind["kind"] or "normal", kind["target"] or "")
                                  for kind in dep["dep_kinds"] if kind["kind"] != "dev"))
                          for dep in node["deps"]
                          if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
        if edges(expected, expected_packages) != edges(resolved, actual_packages):
            raise ValueError(f"driver dependency edges differ: {package_identity}")
        if package_identity[0] in ("noq", "noq-proto"):
            expected_path = Path(expected_packages[expected_id]["manifest_path"]).resolve()
            actual_path = Path(actual_packages[actual_id]["manifest_path"]).resolve()
            if expected_path != actual_path:
                raise ValueError("fixture does not use production prepared sources")
        receipt.append({"identity": package_identity, "features": sorted(expected["features"])})
    result = {"product_lock_sha256": hashlib.sha256(product_lock.read_bytes()).hexdigest(),
              "baseline_metadata_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
              "packages": receipt}
    fixture_lock.with_name("feature-receipt.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Verified identities, features and normal/build edges for {len(receipt)} driver-closure packages.")
