"""Prepare reviewed production dependency sources as data, before any Cargo build."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy  # noqa: E402
import runtime  # noqa: E402

PACKAGES = {
    "noq-proto": "7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f",
    "iroh": "885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833",
    "noq": "b78be567e796cfa74bb9bdc4117790af2d505eb887019cf8803244353eb09d89",
}
VERSION = "1.3.0"
MAX_ARCHIVE = 2 * 1024 * 1024


def validate_archive(path, package, lock):
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("backend archive exceeds the reviewed size bound")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    matches = [entry for entry in lock["package"] if entry["name"] == package and entry["version"] == VERSION]
    if len(matches) != 1 or matches[0].get("checksum") != PACKAGES[package] or digest != PACKAGES[package]:
        raise ValueError("backend archive does not match the reviewed lock checksum")


def prepare(archives, lock_path, destination):
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    # Validate every input before creating any output. Never overwrite a prepared tree.
    for package in PACKAGES:
        validate_archive(archives[package], package, lock)
    destination.mkdir(parents=True, exist_ok=False)
    roots = {}
    for package in PACKAGES:
        directory = destination / package
        directory.mkdir()
        with tarfile.open(archives[package]) as archive:
            archive.extractall(directory, filter="data")
        root = directory / f"{package}-{VERSION}"
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        if manifest["package"]["name"] != package or manifest["package"]["version"] != VERSION:
            raise ValueError("backend package identity mismatch")
        if manifest["package"].get("license") != "MIT OR Apache-2.0":
            raise ValueError("backend license changed")
        roots[package] = root
    runtime.apply(roots["noq"])
    policy.apply(roots["noq-proto"])
    policy.listener_limits(roots["iroh"])
    wrapper = roots["iroh"] / "src/endpoint/quic.rs"
    wrapper.write_text(policy.forwarder(wrapper.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
    for root in roots.values():
        manifest = root / "Cargo.toml"
        manifest.write_text(manifest.read_text(encoding="utf-8") + "\n[workspace]\n", encoding="utf-8", newline="\n")
    provenance = {"version": VERSION, "archives": PACKAGES,
                  "patch_sha256": hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest(),
                  "patch_sources": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                    for name in ("policy.py", "runtime.py", "ingress_budget.rs")},
                  "fixture_instrumentation": False}
    (destination / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return roots


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--noq-archive", type=Path, required=True)
    parser.add_argument("--iroh-archive", type=Path, required=True)
    parser.add_argument("--runtime-archive", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    roots = prepare({"noq-proto": args.noq_archive, "iroh": args.iroh_archive, "noq": args.runtime_archive}, args.lock, args.destination)
    print(json.dumps({name: str(path) for name, path in roots.items()}))


if __name__ == "__main__":
    main()
