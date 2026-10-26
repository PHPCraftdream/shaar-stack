"""A wire harness restricted to the already resolved host product feature closure."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("relay_wire_prepare", HERE / "prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
ROOTS = {"libp2p", "libp2p-relay", "futures", "tokio"}


def key(package):
    return package["name"], package["version"], package["source"]


def closure(metadata):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = {p["name"]: p["id"] for p in packages.values() if p["name"] in ROOTS}
    if roots.keys() != ROOTS or any(sum(p["name"] == name for p in packages.values()) != 1 for name in ROOTS):
        raise ValueError("wire fixture requires one resolved identity for each root")
    pending, found = list(roots.values()), set()
    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        found.add(identity)
        pending.extend(d["pkg"] for d in nodes[identity]["deps"]
                       if any(k["kind"] != "dev" for k in d["dep_kinds"]))
    return roots, {identity: (packages[identity], nodes[identity]) for identity in found}


def create(source, baseline, lock, destination, units=False):
    metadata = json.loads(baseline.read_text(encoding="utf-8"))
    roots, graph = closure(metadata)
    relay = graph[roots["libp2p-relay"]][0]
    if relay["source"] is not None or Path(relay["manifest_path"]).resolve() != (source / "Cargo.toml").resolve():
        raise ValueError("product metadata did not select the prepared relay")
    package = next(p for p in metadata["packages"] if p["name"] == "shaar-p2p")
    if units:
        identity = [(p, n) for p, n in graph.values() if p["name"] == "libp2p-identity"]
        if len(identity) != 1 or "rand" not in identity[0][1]["features"]:
            raise ValueError("unchanged unit bodies require the existing host product identity rand feature")
        tree, receipt, unit_harness = prepare.unit_transform(source)
    else:
        tree, receipt = prepare.transform(source)
    target = "relay_operation_units" if units else "relay_operation_wire"
    test_path = "tests/units.rs" if units else "tests/wire.rs"
    output = {"relay/" + name: content for name, content in tree.items()}
    lines = ["[package]", 'name = "shaar-p2p"', f'version = {json.dumps(package["version"])}',
             f'edition = {json.dumps(package["edition"])}', "publish = false", "build = false",
             "[workspace]", 'resolver = "3"', 'exclude = ["relay"]', "[lib]", 'path = "src/lib.rs"',
             "[[test]]", f'name = "{target}"', f'path = "{test_path}"', "[dependencies]"]
    aliases = {name.replace("-", "_"): identity for name, identity in roots.items()}
    for index, identity in enumerate(sorted(graph)):
        if identity not in roots.values():
            aliases[f"relay_wire_pin_{index}"] = identity
    patches = []
    for alias, identity in sorted(aliases.items()):
        item, node = graph[identity]
        base = f'{json.dumps(alias)} = {{ package = {json.dumps(item["name"])}, version = "={item["version"]}", default-features = false, features = {json.dumps(sorted(node["features"]))}'
        if item["source"] is None:
            path = "relay" if item["name"] == "libp2p-relay" else Path(item["manifest_path"]).parent.resolve().as_posix()
            lines.append(base + f', path = {json.dumps(path)} }}')
            patches.append(f'{json.dumps(item["name"])} = {{ path = {json.dumps(path)} }}')
        elif item["source"] == "registry+https://github.com/rust-lang/crates.io-index":
            lines.append(base + " }")
        else:
            raise ValueError("wire fixture closure contains an unreviewed source")
    lines += ["[patch.crates-io]", *patches]
    output["Cargo.toml"] = ("\n".join(lines) + "\n").encode()
    output["Cargo.lock"] = lock.read_bytes()
    output["src/lib.rs"] = b"#![forbid(unsafe_code)]\n"
    if units:
        output[test_path] = unit_harness
    else:
        output[test_path] = (HERE / "test.rs").read_bytes()
        output["tests/support.rs"] = (HERE / "support.rs").read_bytes()
    receipt.update({"variant": "units" if units else "baseline", "host_product_closure": True,
                    "baseline_metadata_sha256": prepare.digest(baseline.read_bytes()),
                    "product_lock_sha256": prepare.digest(lock.read_bytes()),
                    "graph_recipe_sha256": prepare.digest(Path(__file__).read_bytes()),
                    "owned_fixture_sources": {p.name: prepare.digest(p.read_bytes()) for p in HERE.iterdir() if p.is_file()},
                    "fixture_files": prepare.hashes(output)})
    prepare.write(output, destination)
    (destination / "fixture-provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def verify(baseline, lock, destination, metadata_path):
    receipt = json.loads((destination / "fixture-provenance.json").read_text())
    if receipt["baseline_metadata_sha256"] != prepare.digest(baseline.read_bytes()) or receipt["product_lock_sha256"] != prepare.digest(lock.read_bytes()):
        raise ValueError("wire fixture baseline changed")
    if receipt["graph_recipe_sha256"] != prepare.digest(Path(__file__).read_bytes()):
        raise ValueError("wire graph recipe changed")
    if receipt["recipe_sha256"] != prepare.digest((HERE / "prepare.py").read_bytes()):
        raise ValueError("wire instrumentation recipe changed")
    owned = {p.name: prepare.digest(p.read_bytes()) for p in HERE.iterdir() if p.is_file()}
    if receipt["owned_fixture_sources"] != owned:
        raise ValueError("owned wire fixture sources changed")
    for name, expected in receipt["fixture_files"].items():
        if name != "Cargo.lock" and prepare.digest((destination / name).read_bytes()) != expected:
            raise ValueError("wire fixture source changed: " + name)
    _, old = closure(json.loads(baseline.read_text()))
    roots, new = closure(json.loads(metadata_path.read_text()))
    relay = new[roots["libp2p-relay"]][0]
    if Path(relay["manifest_path"]).resolve() != (destination / "relay/Cargo.toml").resolve():
        raise ValueError("wire fixture selected the wrong relay source")
    expected = {key(p): (p, n) for p, n in old.values()}
    actual = {key(p): (p, n) for p, n in new.values()}
    if expected.keys() != actual.keys():
        raise ValueError("wire fixture changed product package identities")
    for identity, (_, node) in expected.items():
        current = actual[identity][1]
        if set(node["features"]) != set(current["features"]):
            raise ValueError("wire fixture changed product features: " + str(identity[:2]))
        def edges(n, graph):
            return {(d["name"], key(graph[d["pkg"]][0]), k["kind"], k["target"])
                    for d in n["deps"] for k in d["dep_kinds"] if k["kind"] != "dev"}
        if edges(node, old) != edges(current, new):
            raise ValueError("wire fixture changed product dependency edges")
    identities = lambda data: {(p["name"], p["version"], p.get("source"), p.get("checksum")) for p in data["package"]}
    product_ids = identities(tomllib.loads(lock.read_text()))
    fixture_ids = identities(tomllib.loads((destination / "Cargo.lock").read_text()))
    if not fixture_ids <= product_ids:
        raise ValueError("wire fixture added a package identity")
    proof = {"packages": len(actual), "product_lock_sha256": receipt["product_lock_sha256"],
             "fixture_lock_sha256": prepare.digest((destination / "Cargo.lock").read_bytes()),
             "exact_features_and_edges": True, "runtime_verified": False}
    (destination / "graph-receipt.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    if args.mode == "create":
        create(args.source, args.baseline, args.lock, args.destination)
    else:
        verify(args.baseline, args.lock, args.destination, args.metadata)


if __name__ == "__main__":
    main()
