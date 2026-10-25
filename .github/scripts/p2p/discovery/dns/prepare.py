"""Prepare exact locked DNS source as data; never execute archive code."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import patch  # noqa: E402

VERSION = "0.45.0"
PACKAGE = f"libp2p-dns-{VERSION}"
DIGEST = "18694695e98ff9ce26ee245fdede7cd0b4186cb793b25da3258d9c053400a291"
LOCK_DIGEST = "c27554a61acfec08fa7ce6519b377fbcd19f7199b78eec5715769b53a9d3ee27"
LIB_DIGEST = "5f6291a1c453fc7c38c3992b4beacaa48741d9b390485ef2ffce186f2e3d7ca7"
MANIFEST_DIGEST = "6d08833df367d63ece317345c148ac45d7e456f8a46829394485a1b5e2460c72"
VCS = "7171dce2f90c05ba7892d4ba926abb1881db27c7"
MAX_ARCHIVE = 2 * 1024 * 1024
HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hashes(files):
    return {name: digest(data) for name, data in sorted(files.items())}


def recipe():
    return hashes({name: (HERE / name).read_bytes() for name in ("prepare.py", "patch.py", "bounds.rs")})


def archive_files(archive):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("DNS archive exceeds reviewed size bound")
    if digest(archive.read_bytes()) != DIGEST:
        raise ValueError("DNS archive checksum mismatch")
    files = {}
    total = 0
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if len(members) > 128:
            raise ValueError("DNS archive entry bound exceeded")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not path.parts or path.parts[0] != PACKAGE or len(path.parts) > 8
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unexpected DNS archive entry")
            if member.isdir():
                continue
            name = path.relative_to(PACKAGE).as_posix()
            total += member.size
            if total > 4 * MAX_ARCHIVE or name in files:
                raise ValueError("DNS archive expansion or duplicate entry")
            files[name] = source.extractfile(member).read()
    return files


def originals(files):
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    if (manifest["package"]["name"], manifest["package"]["version"]) != ("libp2p-dns", VERSION):
        raise ValueError("unexpected DNS package identity")
    notice = files["src/lib.rs"].decode().split("//!", 1)[0]
    if manifest["package"].get("license") != "MIT" or not all(marker in notice for marker in (
        "Copyright 2018 Parity Technologies", "Permission is hereby granted", 'THE SOFTWARE IS PROVIDED "AS IS"',
    )):
        raise ValueError("DNS license or embedded notice changed")
    if json.loads(files[".cargo_vcs_info.json"]) != {"git": {"sha1": VCS}, "path_in_vcs": "transports/dns"}:
        raise ValueError("DNS source provenance changed")
    for name, expected in (("Cargo.lock", LOCK_DIGEST), ("Cargo.toml", MANIFEST_DIGEST), ("src/lib.rs", LIB_DIGEST)):
        if digest(files[name]) != expected:
            raise ValueError(f"DNS original source bytes changed: {name}")


def transform(files):
    # Check anchors separately from the original-byte pins for useful drift diagnostics.
    library = patch.transform(files["src/lib.rs"].decode())
    originals(files)
    if "src/bounded_expansion.rs" in files:
        raise ValueError("unexpected existing DNS bounded module")
    if patch.reverse(library).encode() != files["src/lib.rs"]:
        raise ValueError("DNS original-byte reverse mismatch")
    return {
        "Cargo.toml": files["Cargo.toml"] + b"\n[workspace]\n",
        "src/lib.rs": library.encode(),
        "src/bounded_expansion.rs": (HERE / "bounds.rs").read_bytes(),
    }


def write_tree(files, destination):
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def prepare(archive, destination):
    files = archive_files(archive)
    changes = transform(files)
    receipt = {
        "package": "libp2p-dns", "version": VERSION, "archive_sha256": DIGEST,
        "archive_lock_sha256": LOCK_DIGEST, "vcs_revision": VCS, "license": "MIT",
        "recipe_files": recipe(), "original_files": hashes(files), "changed_files": sorted(changes),
        "dns_lookups": 32, "dial_attempts": 16, "accepted_txt_per_lookup": 16,
        "numeric_per_lookup": 4, "pending_candidates": 32, "retained_errors": 16,
        "encoded_address_bytes": 256, "txt_bytes": 1024,
        "fixture_instrumentation": False, "hickory_memory_or_joined_shutdown_proven": False,
    }
    files.update(changes)
    receipt["prepared_files"] = hashes(files)
    destination.mkdir(parents=True, exist_ok=False)
    root = destination / PACKAGE
    write_tree(files, root)
    (destination / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return root


def verify(root):
    receipt = json.loads((root.parent / "provenance.json").read_text(encoding="utf-8"))
    if (receipt["archive_sha256"] != DIGEST or receipt["recipe_files"] != recipe()
            or receipt["fixture_instrumentation"]):
        raise ValueError("DNS prepared provenance mismatch")
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("DNS prepared source link")
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in paths if p.is_file()}
    if hashes(files) != receipt["prepared_files"]:
        raise ValueError("DNS prepared source drift")
    restored = dict(files)
    if restored.pop("src/bounded_expansion.rs") != (HERE / "bounds.rs").read_bytes():
        raise ValueError("DNS owned expansion source drift")
    restored["src/lib.rs"] = patch.reverse(restored["src/lib.rs"].decode()).encode()
    if not restored["Cargo.toml"].endswith(b"\n[workspace]\n"):
        raise ValueError("DNS workspace boundary changed")
    restored["Cargo.toml"] = restored["Cargo.toml"].removesuffix(b"\n[workspace]\n")
    originals(restored)
    if hashes(restored) != receipt["original_files"]:
        raise ValueError("DNS original-byte reverse mismatch")
    return files


# CI-only observations surround real production admissions; no replacement algorithm.
OBSERVATIONS = {
    "        errors.push(error);": "        crate::retention_support::observe_error(errors.len() + 1);\n",
    "        pending.push(address);": "        crate::retention_support::observe_pending(pending.len() + 1);\n",
    "        Multiaddr::try_from(self.bytes().to_vec())": "        crate::retention_support::observe_allocation(self.len);\n",
    "    let text = str::from_utf8(text)": "    crate::retention_support::observe_parse();\n",
}


def instrument(text):
    for anchor, observation in OBSERVATIONS.items():
        expected = 2 if anchor == "        pending.push(address);" else 1
        if text.count(anchor) != expected:
            raise ValueError("DNS fixture observation anchor changed")
        text = text.replace(anchor, observation + anchor)
    return text


def fixture(source, destination):
    files = verify(source)
    before = hashes(files)
    files["src/bounded_expansion.rs"] = instrument(files["src/bounded_expansion.rs"].decode()).encode()
    files["src/lib.rs"] += b"\n#[cfg(test)]\nmod retention_support;\n#[cfg(test)]\nmod retention_tests;\n"
    for name in ("support", "tests"):
        files[f"src/retention_{name}.rs"] = (HERE / f"{name}.rs").read_bytes()
    if digest(files["Cargo.lock"]) != LOCK_DIGEST:
        raise ValueError("DNS fixture archive lock changed")
    write_tree(files, destination)
    receipt = {"archive_sha256": DIGEST, "archive_lock_sha256": LOCK_DIGEST,
               "production_files": before, "fixture_files": hashes(files),
               "owned_tests": hashes({name: (HERE / name).read_bytes() for name in ("support.rs", "tests.rs")}),
               "excluded_upstream_test_modules": []}
    (destination / "fixture-provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    build = modes.add_parser("prepare")
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--destination", type=Path, required=True)
    tests = modes.add_parser("fixture")
    tests.add_argument("--source", type=Path, required=True)
    tests.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        print(prepare(args.archive, args.destination))
    else:
        fixture(args.source, args.destination)


if __name__ == "__main__":
    main()
