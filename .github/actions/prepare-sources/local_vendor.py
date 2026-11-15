# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build an offline directory source for the crates.io packages of Cargo.lock from LOCAL archives.

Usage: python -I .github/actions/prepare-sources/local_vendor.py --search DIR [--search DIR ...]

Each `source = registry+crates.io` package of Cargo.lock is located by its locked SHA-256 checksum in
the given directories (searched recursively for `<name>-<version>.crate`; the hash is verified, the file
name is only a hint), extracted into the PRIMARY checkout's ignored `target/vendor/<name>-<version>/`
and given the `.cargo-checksum.json` that a cargo directory source requires. A package whose archive
is missing or whose digest differs is reported and makes the run fail; nothing is downloaded and no
network module is imported. Extracted material is DATA: nothing in it is executed here. A dependency's
build.rs runs only if the owner-permitted local clippy compiles that dependency.

It also writes `target/local-vendor.toml`, a cargo config that replaces crates.io by that directory:

    cargo clippy --config target/local-vendor.toml -p shaar --all-targets --locked --offline -- -D warnings

(`--config` goes AFTER `clippy`: the driver forwards only what follows the subcommand to its own cargo)

so no write is needed outside the repository (the config lives in the ignored `target/`, the cargo home
is untouched). In a linked worktree `target` is the junction to the primary `target/`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_FILE = 64 * 1024 * 1024
MAX_MEMBERS = 20000


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def locked_packages() -> dict[str, tuple[str, str]]:
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    found = {}
    for package in lock["package"]:
        if package.get("source") == REGISTRY and "checksum" in package:
            found[package["checksum"]] = (package["name"], package["version"])
    return found


def index_archives(search: list[Path], wanted: dict[str, tuple[str, str]]) -> dict[str, Path]:
    """Hash every candidate once; a candidate is a *.crate whose name matches a wanted package."""
    names = {f"{name}-{version}.crate": digest for digest, (name, version) in wanted.items()}
    found: dict[str, Path] = {}
    for base in search:
        for current, _dirs, files in os.walk(base):
            for file in files:
                digest = names.get(file)
                if digest is None or digest in found:
                    continue
                path = Path(current) / file
                if path.stat().st_size > MAX_FILE:
                    continue
                if sha256(path) == digest:
                    found[digest] = path
    return found


def extract(archive: Path, name: str, version: str, destination: Path, digest: str) -> None:
    prefix = f"{name}-{version}/"
    temporary = destination.with_name(destination.name + ".partial")
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError(f"{archive.name}: too many members")
        for member in members:
            if not member.name.startswith(prefix) or ".." in Path(member.name).parts:
                raise ValueError(f"{archive.name}: unexpected member {member.name!r}")
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"{archive.name}: non-regular member {member.name!r}")
            relative = member.name[len(prefix):]
            if not relative:
                continue
            target = temporary / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            assert source is not None
            with target.open("wb") as out:
                shutil.copyfileobj(source, out)
    (temporary / ".cargo-checksum.json").write_text(
        json.dumps({"files": {}, "package": digest}), encoding="utf-8")
    temporary.rename(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--search", action="append", required=True, type=Path,
                        help="directory searched recursively for <name>-<version>.crate (repeatable)")
    arguments = parser.parse_args()
    target = ROOT / "target"
    if not target.exists():
        print("target/ is missing: run local_prepare.py first (it creates the shared store link)")
        return 1
    wanted = locked_packages()
    found = index_archives([path for path in arguments.search if path.is_dir()], wanted)
    vendor = target.resolve() / "vendor"
    vendor.mkdir(exist_ok=True)
    missing = []
    prepared = reused = 0
    for digest, (name, version) in sorted(wanted.items(), key=lambda item: item[1]):
        destination = vendor / f"{name}-{version}"
        if destination.is_dir() and (destination / ".cargo-checksum.json").is_file():
            reused += 1
            continue
        archive = found.get(digest)
        if archive is None:
            missing.append(f"{name}-{version} sha256={digest}")
            continue
        extract(archive, name, version, destination, digest)
        prepared += 1
    print(f"vendor: {prepared} extracted, {reused} already present, {len(missing)} missing of {len(wanted)}")
    for line in missing:
        print("missing:", line)
    if missing:
        return 1
    config = target.resolve() / "local-vendor.toml"
    config.write_text(
        '[source.crates-io]\nreplace-with = "shaar-local-vendor"\n\n'
        '[source.shaar-local-vendor]\n'
        f'directory = "{vendor.as_posix()}"\n', encoding="utf-8")
    print("config:", config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
