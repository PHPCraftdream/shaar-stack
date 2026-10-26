"""CI-only resolver fixture with exact host product identities and feature closure."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("resolver_fixture", HERE / "fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
prepare = fixture.prepare


def closure(metadata):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = [p for p in packages.values() if p["name"] == "hickory-resolver"]
    if len(roots) != 1 or roots[0]["version"] != prepare.VERSION or roots[0]["source"] is not None:
        raise ValueError("product must resolve the single prepared resolver")
    root = roots[0]["id"]
    pending, found = [root], set()
    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        found.add(identity)
        pending.extend(d["pkg"] for d in nodes[identity]["deps"]
                       if any(k["kind"] != "dev" for k in d["dep_kinds"]))
    return root, {identity: (packages[identity], nodes[identity]) for identity in found}


def key(package):
    return package["name"], package["version"], package["source"]


def create(source, baseline, lock, destination):
    metadata = json.loads(baseline.read_text(encoding="utf-8"))
    root, graph = closure(metadata)
    if Path(graph[root][0]["manifest_path"]).resolve() != (source / "Cargo.toml").resolve():
        raise ValueError("baseline resolver path differs from verified preparation")
    files, record = fixture.transformed(source)
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    active = sorted(graph[root][1]["features"])
    if "tokio" not in active or not set(active) <= manifest["features"].keys():
        raise ValueError("unsupported product resolver features")
    lines = ["[package]", 'name = "hickory-resolver"', f'version = "{prepare.VERSION}"',
             f'edition = {json.dumps(manifest["package"]["edition"])}', 'build = false',
             '[lib]', 'path = "src/lib.rs"', '[workspace]', 'resolver = "3"', '[features]']
    lines += [f'{json.dumps(name)} = []' for name in manifest["features"]]
    lines += ["[dependencies]"]
    aliases = {}
    for dependency in graph[root][1]["deps"]:
        if any(k["kind"] != "dev" for k in dependency["dep_kinds"]):
            aliases[dependency["name"]] = dependency["pkg"]
    # Closure anchors reproduce feature unification from other product consumers.
    direct = set(aliases.values())
    for index, identity in enumerate(sorted(graph)):
        if identity != root and identity not in direct:
            aliases[f"locking_pin_{index}"] = identity
    for alias, identity in sorted(aliases.items()):
        package, node = graph[identity]
        if package["source"] != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError("resolver fixture closure contains an unreviewed source")
        lines.append(f'{json.dumps(alias)} = {{ package = {json.dumps(package["name"])}, '
                     f'version = "={package["version"]}", default-features = false, '
                     f'features = {json.dumps(sorted(node["features"]))} }}')
    files["Cargo.toml"] = ("\n".join(lines) + "\n").encode()
    files["Cargo.lock"] = lock.read_bytes()
    record.update({"graph": "host-product", "baseline_sha256": prepare.digest(baseline.read_bytes()),
                   "product_lock_sha256": prepare.digest(lock.read_bytes()), "features": active,
                   "fixture_files": prepare.hashes(files), "recipe_sha256": prepare.digest(Path(__file__).read_bytes())})
    prepare.write_tree(files, destination)
    (destination / "fixture-provenance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def verify(baseline, lock, destination):
    record = json.loads((destination / "fixture-provenance.json").read_text(encoding="utf-8"))
    if (record["baseline_sha256"] != prepare.digest(baseline.read_bytes())
            or record["product_lock_sha256"] != prepare.digest(lock.read_bytes())
            or record["recipe_sha256"] != prepare.digest(Path(__file__).read_bytes())):
        raise ValueError("resolver product fixture provenance changed")
    for name, expected in record["fixture_files"].items():
        if name != "Cargo.lock" and prepare.digest((destination / name).read_bytes()) != expected:
            raise ValueError("resolver product fixture source changed")
    old_root, old = closure(json.loads(baseline.read_text(encoding="utf-8")))
    new_root, new = closure(json.loads((destination / "metadata.json").read_text(encoding="utf-8")))
    if Path(new[new_root][0]["manifest_path"]).resolve() != (destination / "Cargo.toml").resolve():
        raise ValueError("product fixture resolved the wrong root")
    expected = {key(p): (p, n) for p, n in old.values()}
    actual = {key(p): (p, n) for p, n in new.values()}
    if expected.keys() != actual.keys():
        raise ValueError("resolver fixture changed a product package identity")
    for identity, (_, node) in expected.items():
        actual_node = actual[identity][1]
        if set(node["features"]) != set(actual_node["features"]):
            raise ValueError(f"resolver fixture changed resolved features: {identity[:2]}")
        def edges(n, graph):
            return {(d["name"], key(graph[d["pkg"]][0]), k["kind"], k["target"])
                    for d in n["deps"] if not d["name"].startswith("locking_pin_")
                    for k in d["dep_kinds"] if k["kind"] != "dev"}
        expected_edges = edges(node, old)
        actual_edges = edges(actual_node, new)
        # The fixture root flattens already host-filtered dependency declarations only.
        if node["id"] == old_root:
            expected_edges = {(a, b) for a, b, _, _ in expected_edges}
            actual_edges = {(a, b) for a, b, _, _ in actual_edges}
        if expected_edges != actual_edges:
            raise ValueError("resolver fixture changed product dependency edges")
    product = tomllib.loads(lock.read_text(encoding="utf-8"))
    fixture_lock = tomllib.loads((destination / "Cargo.lock").read_text(encoding="utf-8"))
    identities = lambda data: {(p["name"], p["version"], p.get("source"), p.get("checksum")) for p in data["package"]}
    if not identities(fixture_lock) <= identities(product):
        raise ValueError("resolver fixture lock added or changed product identities")
    proof = {"packages": len(actual), "features": record["features"], "product_lock_sha256": record["product_lock_sha256"],
             "fixture_lock_sha256": prepare.digest((destination / "Cargo.lock").read_bytes())}
    (destination / "graph-receipt.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify", "features"))
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args()
    if args.mode == "create":
        create(args.source, args.baseline, args.lock, args.destination)
    elif args.mode == "verify":
        verify(args.baseline, args.lock, args.destination)
    else:
        record = json.loads((args.destination / "fixture-provenance.json").read_text(encoding="utf-8"))
        print(",".join(record["features"]))


if __name__ == "__main__":
    main()
