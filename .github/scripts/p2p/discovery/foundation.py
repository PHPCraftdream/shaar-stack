"""CI-only graph proof for the single explicit carrier-owned resolver edge."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib

BASELINE_LOCK = "cc48f78b6598afa20c5545073e0663b2cb822b1976bb731c34068246563af0db"
DEPENDENCY = 'hickory-resolver = { version = "=0.26.3", default-features = false, features = ["tokio"] }\n'
ANCHOR = 'name = "shaar-p2p"\nversion = "0.1.0"\ndependencies = [\n "asynchronous-codec",\n "futures",\n'
FORBIDDEN = {"__tls", "__https", "__quic", "__h3", "toml", "recursor"}


def original_lock(current):
    # Git checkout line endings are not a dependency-graph change.
    text = current.decode("utf-8").replace("\r\n", "\n")
    added = ANCHOR + ' "hickory-resolver",\n'
    if text.count(added) != 1:
        raise ValueError("owned DNS direct lock edge missing or ambiguous")
    original = text.replace(added, ANCHOR).encode("utf-8")
    if hashlib.sha256(original).hexdigest() != BASELINE_LOCK:
        raise ValueError("owned DNS changed lock bytes beyond its one direct edge")
    return original


def baseline(repository, destination):
    repository = repository.resolve()
    original = original_lock((repository / "Cargo.lock").read_bytes())
    manifest = (repository / "Cargo.toml").read_text(encoding="utf-8")
    patches = tomllib.loads(manifest)["patch"]["crates-io"]
    for patch in patches.values():
        relative = patch["path"]
        old = f'path = "{relative}"'
        if manifest.count(old) != 1:
            raise ValueError("baseline patch anchor changed")
        manifest = manifest.replace(old, f'path = {json.dumps((repository / relative).as_posix())}')
    p2p = (repository / "crates/shaar-p2p/Cargo.toml").read_text(encoding="utf-8")
    if p2p.count(DEPENDENCY) != 1:
        raise ValueError("owned DNS explicit manifest edge changed")
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(repository / "crates", destination / "crates", ignore=shutil.ignore_patterns("target", "__pycache__"))
    (destination / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")
    (destination / "Cargo.lock").write_bytes(original)
    (destination / "crates/shaar-p2p/Cargo.toml").write_text(p2p.replace(DEPENDENCY, ""), encoding="utf-8", newline="\n")


def graph(metadata):
    packages = metadata["packages"]
    identities = {p["id"]: (p["name"], p["version"], p.get("source")) for p in packages}
    if len(set(identities.values())) != len(identities):
        raise ValueError("ambiguous graph package identity")
    nodes = metadata.get("resolve", {}).get("nodes", [])
    if not nodes:
        raise ValueError("full resolved graph required")
    result = {}
    for node in nodes:
        edges = {
            (edge["name"], identities[edge["pkg"]], json.dumps(edge["dep_kinds"], sort_keys=True))
            for edge in node["deps"]
        }
        result[identities[node["id"]]] = (set(node["features"]), edges)
    return result


def compare(before, after):
    old, new = graph(before), graph(after)
    if old.keys() != new.keys():
        raise ValueError("owned DNS changed package identities")
    carrier = ("shaar-p2p", "0.1.0", None)
    resolver = ("hickory-resolver", "0.26.3", None)
    direct = ("hickory_resolver", resolver, json.dumps([{"kind": None, "target": None}], sort_keys=True))
    if carrier not in new or resolver not in new:
        raise ValueError("carrier/prepared resolver missing from graph")
    for package in old:
        previous_features, previous_edges = old[package]
        features, edges = new[package]
        if previous_features != features:
            raise ValueError(f"owned DNS changed feature union: {package[0]}")
        expected = previous_edges | {direct} if package == carrier else previous_edges
        if edges != expected or (package == carrier and direct in previous_edges):
            raise ValueError(f"owned DNS changed unexpected dependency edges: {package[0]}")
        if package[0] in {"hickory-net", "hickory-resolver"}:
            if "tokio" not in features or features & FORBIDDEN:
                raise ValueError(f"unsupported owned DNS runtime feature profile: {package[0]}")
    p2p = next(p for p in after["packages"] if p["name"] == "shaar-p2p")
    declared = [d for d in p2p["dependencies"] if d["name"] == "hickory-resolver"]
    if len(declared) != 1 or any((
        declared[0]["req"] != "=0.26.3", declared[0]["uses_default_features"],
        declared[0]["features"] != ["tokio"], declared[0]["kind"] is not None,
        declared[0]["target"] is not None,
    )):
        raise ValueError("owned DNS manifest edge or features changed")
    return {
        "added_direct_edge": "shaar-p2p -> hickory-resolver 0.26.3 (prepared)",
        "package_identities_unchanged": len(new),
        "all_other_edges_unchanged": True,
        "feature_unions_unchanged": True,
        "dns_features": {p[0]: sorted(features) for p, (features, _) in new.items()
                         if p[0] in {"hickory-net", "hickory-proto", "hickory-resolver", "libp2p-dns"}},
        "system_configuration_may_remain_enabled_transitively": True,
        "profile": "Explicit UDP/TCP only; no hosts/search loading; prepared cache_size=0",
    }


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    stage = sub.add_parser("baseline")
    stage.add_argument("--repository", type=Path, required=True)
    stage.add_argument("--destination", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--repository", type=Path, required=True)
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument("--product", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "baseline":
        baseline(args.repository, args.destination)
    else:
        current = (args.repository / "Cargo.lock").read_bytes()
        original_lock(current)
        receipt = compare(json.loads(args.baseline.read_text(encoding="utf-8")),
                          json.loads(args.product.read_text(encoding="utf-8")))
        receipt["original_lock_sha256"] = BASELINE_LOCK
        receipt["product_lock_sha256"] = hashlib.sha256(current).hexdigest()
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
