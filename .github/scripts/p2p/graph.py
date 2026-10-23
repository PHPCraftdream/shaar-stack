"""Stage/verify a P08 dependency graph in CI, without changing the product lock."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib

FAMILY = {
    "libp2p": "0.57.1",
    "libp2p-swarm": "0.48.0",
    "libp2p-relay": "0.22.0",
    "libp2p-request-response": "0.30.0",
}
DEPENDENCIES = '''[dependencies]
libp2p = { version = "=0.57.1", default-features = false, features = ["ed25519", "tokio", "tcp", "dns", "noise", "yamux", "kad", "identify", "relay", "request-response", "macros"] }
libp2p-swarm = "=0.48.0"
libp2p-relay = "=0.22.0"
libp2p-request-response = "=0.30.0"
iroh = { version = "=1.3.0", default-features = false, features = ["tls-ring", "unstable-custom-transports"] }
n0-watcher = "=1.0.0"
noq-udp = "=1.3.0"
futures = "=0.3.34"
tokio = { version = "=1.54.1", features = ["rt", "net", "sync", "time", "macros"] }
'''


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("candidate workspace source anchor changed")
    return text.replace(old, new)


def create(repository, destination, relay_source, swarm_source):
    repository = repository.resolve()
    relay_source = relay_source.resolve()
    swarm_source = swarm_source.resolve()
    swarm = tomllib.loads((swarm_source / "Cargo.toml").read_text(encoding="utf-8"))
    if swarm["target"]['cfg(target_family="wasm")']["dependencies"]["wasm-bindgen-futures"]["version"] != "=0.4.79":
        raise ValueError("reviewed swarm compatibility manifest is missing")
    if not (relay_source / "src/bounded_lease.rs").is_file():
        raise ValueError("reviewed bounded relay source is missing")
    manifest = (repository / "Cargo.toml").read_text(encoding="utf-8")
    for package in ("iroh", "noq-proto", "noq"):
        relative = f"target/backend/{package}/{package}-1.3.0"
        actual = (repository / relative).resolve()
        if not (actual / "Cargo.toml").is_file():
            raise ValueError("production backend must be prepared before candidate resolution")
        manifest = replace(manifest, f'path = "{relative}"', f"path = {json.dumps(actual.as_posix())}")
    root_patches = tomllib.loads(manifest)["patch"]["crates-io"]
    for name, path in (("libp2p-relay", relay_source), ("libp2p-swarm", swarm_source)):
        if name in root_patches:
            previous = root_patches[name]["path"]
            manifest = replace(manifest, f'path = "{previous}"', f"path = {json.dumps(path.as_posix())}")
        else:
            addition = f"{name} = {{ path = {json.dumps(path.as_posix())} }}"
            manifest = replace(manifest, "[patch.crates-io]", "[patch.crates-io]\n" + addition)
    sdk = repository / "crates/shaar-p2p/Cargo.toml"
    original = sdk.read_text(encoding="utf-8")
    dependencies = tomllib.loads(original).get("dependencies", {})
    if not dependencies:
        candidate = replace(original, "[dependencies]", DEPENDENCIES.rstrip())
    else:
        for name, version in FAMILY.items():
            dependency = dependencies.get(name)
            declared = dependency.get("version") if isinstance(dependency, dict) else dependency
            if declared != "=" + version:
                raise ValueError("product dependency family differs from reviewed candidate")
        candidate = original
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(repository / "crates", destination / "crates", ignore=shutil.ignore_patterns("target", "__pycache__"))
    (destination / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")
    original_lock = (repository / "Cargo.lock").read_bytes()
    (destination / "Cargo.lock").write_bytes(original_lock)
    (destination / "baseline.lock").write_bytes(original_lock)
    (destination / "crates/shaar-p2p/Cargo.toml").write_text(candidate, encoding="utf-8", newline="\n")


def identities(lock):
    return {(p["name"], p["version"], p.get("source"), p.get("checksum")) for p in lock["package"]}


def validate(old, new, metadata, relay_source, swarm_source):
    previous = identities(old)
    current = identities(new)
    if not previous.issubset(current):
        missing = sorted((name, version) for name, version, _, _ in previous - current)
        raise ValueError(f"candidate removed or changed an existing package identity: {missing}")
    nodes = metadata.get("resolve", {}).get("nodes") if metadata.get("resolve") else None
    if not nodes:
        raise ValueError("full resolved metadata is required; --no-deps is insufficient")
    resolved = {node["id"] for node in nodes}
    packages = metadata.get("packages", [])
    for name, version in FAMILY.items():
        locked = [p for p in new["package"] if p["name"] == name]
        if len(locked) != 1 or locked[0]["version"] != version:
            raise ValueError("candidate lock family differs from reviewed source APIs")
        matches = [p for p in packages if p["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != version or matches[0]["id"] not in resolved:
            raise ValueError("candidate dependency family differs from reviewed source APIs")
    for name, root in (("libp2p-relay", relay_source), ("libp2p-swarm", swarm_source)):
        package = next(p for p in packages if p["name"] == name)
        if package["source"] is not None or Path(package["manifest_path"]).resolve() != (root / "Cargo.toml").resolve():
            raise ValueError(f"candidate did not resolve the prepared source: {name}")
    added = sorted((name, version, source or "path", checksum or "") for name, version, source, checksum in current - previous)
    return {"retained_package_identities": len(previous), "added_package_identities": added, "family": FAMILY}


def verify(workspace, metadata_path, relay_source, swarm_source):
    old_bytes = (workspace / "baseline.lock").read_bytes()
    new_bytes = (workspace / "Cargo.lock").read_bytes()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    receipt = validate(tomllib.loads(old_bytes.decode()), tomllib.loads(new_bytes.decode()), metadata, relay_source, swarm_source)
    receipt["baseline_lock_sha256"] = hashlib.sha256(old_bytes).hexdigest()
    receipt["candidate_lock_sha256"] = hashlib.sha256(new_bytes).hexdigest()
    (workspace / "graph-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"retained": receipt["retained_package_identities"], "added": len(receipt["added_package_identities"])}))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    prepare = sub.add_parser("create")
    prepare.add_argument("--repository", type=Path, required=True)
    prepare.add_argument("--destination", type=Path, required=True)
    prepare.add_argument("--relay-source", type=Path, required=True)
    prepare.add_argument("--swarm-source", type=Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--workspace", type=Path, required=True)
    check.add_argument("--metadata", type=Path, required=True)
    check.add_argument("--relay-source", type=Path, required=True)
    check.add_argument("--swarm-source", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "create":
        create(args.repository, args.destination, args.relay_source, args.swarm_source)
    else:
        verify(args.workspace, args.metadata, args.relay_source, args.swarm_source)


if __name__ == "__main__":
    main()
