"""Stage product Cargo wiring as data; only CI resolves and compiles the new graph."""
import argparse
from pathlib import Path
import shutil
import sys
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy import replace  # noqa: E402
from prepare import PACKAGES, VERSION  # noqa: E402


def seed_lock(original, probe):
    blocks = original.split("[[package]]")
    known = {(entry["name"], entry["version"], entry.get("source"))
             for entry in tomllib.loads(original)["package"]}
    found_sdk = False
    for index, block in enumerate(blocks[1:], 1):
        package = tomllib.loads("[[package]]" + block)["package"][0]
        if package["name"] == "shaar":
            blocks[index] = replace(block, "dependencies = [\n", 'dependencies = [\n "iroh",\n')
            found_sdk = True
    if not found_sdk:
        raise ValueError("SDK lock entry missing")
    for block in probe.split("[[package]]")[1:]:
        package = tomllib.loads("[[package]]" + block)["package"][0]
        if package["name"] == "iroh-paths-probe":
            continue
        key = (package["name"], package["version"], package.get("source"))
        if key in known:
            continue
        if package["name"] in PACKAGES:
            if package["version"] != VERSION or package.get("checksum") != PACKAGES[package["name"]]:
                raise ValueError("reviewed backend lock identity mismatch")
            block = "\n".join(line for line in block.split("\n")
                              if not line.startswith(("source =", "checksum =")))
        blocks.append(block)
        known.add(key)
    return "[[package]]".join(blocks)


def stage(repo, destination):
    root_manifest = (repo / "Cargo.toml").read_text(encoding="utf-8")
    if "[patch.crates-io]" in root_manifest:
        raise ValueError("staging expects the pre-adoption workspace")
    sdk = (repo / "crates/shaar/Cargo.toml").read_text(encoding="utf-8")
    sdk = replace(sdk, '[dependencies]\n', '[dependencies]\niroh = { version = "=1.3.0", default-features = false, features = ["tls-ring", "unstable-custom-transports"] }\n')
    sdk = replace(sdk, '["macros", "rt-multi-thread", "sync"]', '["macros", "rt-multi-thread", "sync", "time"]')
    root_manifest += '\n[patch.crates-io]\nnoq-proto = { path = "../noq-proto/noq-proto-1.3.0" }\niroh = { path = "../iroh/iroh-1.3.0" }\n'
    lock = seed_lock((repo / "Cargo.lock").read_text(encoding="utf-8"),
                     (repo / ".github/probes/iroh-paths/Cargo.lock").read_text(encoding="utf-8"))
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(repo / "crates", destination / "crates")
    (destination / "Cargo.toml").write_text(root_manifest, encoding="utf-8")
    (destination / "Cargo.lock").write_text(lock, encoding="utf-8")
    (destination / "crates/shaar/Cargo.toml").write_text(sdk, encoding="utf-8")
    shutil.copyfile(Path(__file__).with_name("dependency_gate.rs"), destination / "crates/shaar/tests/backend_gate.rs")


def validate_lock(repo, destination):
    original = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    actual = tomllib.loads((destination / "Cargo.lock").read_text(encoding="utf-8"))
    before = {(p["name"], p["version"], p["source"]): p.get("checksum")
              for p in original["package"] if "source" in p}
    after = {(p["name"], p["version"], p["source"]): p.get("checksum")
             for p in actual["package"] if "source" in p}
    if any(key not in after or after[key] != checksum for key, checksum in before.items()):
        raise ValueError("Cargo resolution changed an existing production package/version/checksum")
    for name in ("iroh", "noq", "noq-proto", "noq-udp"):
        matches = [p for p in actual["package"] if p["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != VERSION:
            raise ValueError("Cargo resolution changed the reviewed backend family")
        if name in PACKAGES and "source" in matches[0]:
            raise ValueError("Cargo did not select the prepared production path package")
    print("Product lock preserves every existing registry identity and the exact backend family")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--validate-lock", action="store_true")
    args = parser.parse_args()
    if args.validate_lock:
        validate_lock(args.repo, args.destination)
    else:
        stage(args.repo, args.destination)
