# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare and verify the pinned, reviewed-patched Yggdrasil-ng core source tree.

The pinned archive is untrusted data: its members are only read and hashed,
never executed, and extraction is limited to the reviewed LICENSE and the two
workspace crates. The per-file content manifest (ygg-manifest.json) is the
authoritative pin; the archive digest is recorded evidence only. Leaf 53.2
applies the reviewed lifecycle hunks (lifecycle_patch.py) after manifest
verification; LICENSE and every unpatched file stay byte-exact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lifecycle_patch  # noqa: E402

REVISION = "c9a54f1587bb133a06072596484c972a336db0d2"
ARCHIVE_URL = "https://codeload.github.com/Revertron/Yggdrasil-ng/tar.gz/" + REVISION
ARCHIVE_SHA256 = "4d978c1a8714e0569fd0a3782adab2f6b81b9c9e54d733dbeaa023aaebae96c1"
ARCHIVE_TOP = "Yggdrasil-ng-" + REVISION
TREE_DIGEST = "b05902627173ccce95f88fc0a0e36f043646b7c129dc46e8e03d7512771ae2d0"
MANIFEST_COUNT = 43
MANIFEST_NAME = "ygg-manifest.json"
MANIFEST_RELATIVE = ".github/probes/ygg/" + MANIFEST_NAME
EXTRACT_FILE = "LICENSE"
EXTRACT_PREFIXES = ("crates/ironwood/", "crates/yggdrasil/")
RECORD_ONLY = ("Cargo.toml", "Cargo.lock")
REQUIRED_MANIFEST_KEYS = (EXTRACT_FILE, "crates/ironwood/Cargo.toml",
                          "crates/yggdrasil/Cargo.toml") + RECORD_ONLY
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_ENTRIES = 8192
MAX_MEMBER = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_DEPTH = 16
HEX = re.compile(r"[0-9a-f]{64}\Z")
SOURCE = {"kind": "git-archive", "repository": "https://github.com/Revertron/Yggdrasil-ng",
          "revision": REVISION}
RECIPE_FILES = ("prepare.py", "checks.py", MANIFEST_NAME, "lifecycle_patch.py",
                "patches/core.py", "patches/links.py", "patches/proto.py")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: digest(data) for name, data in sorted(files.items())}


def recipe() -> dict[str, str]:
    return {name: digest((HERE / name).read_bytes()) for name in RECIPE_FILES}


def _manifest_key_fault(name: str) -> str | None:
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or ".." in path.parts or "." in path.parts
            or "\\" in name or re.match(r"^[A-Za-z]:", name)
            or any(":" in part for part in path.parts) or not path.parts
            or len(path.parts) > MAX_DEPTH):
        return "unsafe content manifest path"
    return None


def scope(name: str) -> str | None:
    if name == EXTRACT_FILE:
        return "extract"
    if name in RECORD_ONLY:
        return "record"
    if any(name.startswith(prefix) for prefix in EXTRACT_PREFIXES):
        return "extract"
    return None


def load_manifest() -> dict[str, str]:
    path = HERE / MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"pinned content manifest missing: {MANIFEST_RELATIVE} "
                         "must be provided by the coordinator before preparation")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("pinned content manifest is invalid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("pinned content manifest must be a JSON object")
    for field, expected in (("archive_url", ARCHIVE_URL),
                            ("archive_sha256", ARCHIVE_SHA256),
                            ("tree_digest", TREE_DIGEST)):
        if document.get(field) != expected:
            raise ValueError(f"pinned content manifest {field} does not match the reviewed pin")
    files = document.get("files")
    if not isinstance(files, dict) or len(files) != MANIFEST_COUNT:
        raise ValueError(f"content manifest must list exactly {MANIFEST_COUNT} files")
    for name, checksum in files.items():
        if not isinstance(name, str) or not isinstance(checksum, str):
            raise ValueError("content manifest entries must be string pairs")
        if _manifest_key_fault(name) or scope(name) is None:
            raise ValueError(f"content manifest path is unsafe or outside the reviewed scope: {name}")
        if not HEX.fullmatch(checksum):
            raise ValueError(f"content manifest checksum is not a lowercase SHA-256: {name}")
    for required in REQUIRED_MANIFEST_KEYS:
        if required not in files:
            raise ValueError(f"content manifest is missing required path: {required}")
    lines = "".join(f"{name}\0{files[name]}\n" for name in sorted(files))
    if digest(lines.encode("utf-8")) != TREE_DIGEST:
        raise ValueError("content manifest does not match the pinned tree digest")
    return files


def _member_fault(member) -> str | None:
    path = PurePosixPath(member.name)
    if (path.is_absolute() or ".." in path.parts or "." in path.parts
            or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
            or any(":" in part for part in path.parts) or not path.parts
            or path.parts[0] != ARCHIVE_TOP or len(path.parts) > MAX_DEPTH
            or not (member.isfile() or member.isdir())):
        return "unsafe archive member"
    return None


def archive_files(archive: Path) -> tuple[dict[str, bytes], dict[str, str]]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive identity or size bound mismatch")
    if digest(archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("archive SHA-256 mismatch")
    files: dict[str, bytes] = {}
    recorded: dict[str, str] = {}
    seen: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        for index, member in enumerate(source, 1):
            fault = _member_fault(member)
            if fault:
                raise ValueError(fault)
            if index > MAX_ENTRIES:
                raise ValueError("archive entry bound exceeded")
            name = PurePosixPath(member.name).relative_to(ARCHIVE_TOP).as_posix()
            if name == ".":
                continue
            key = name.casefold()
            if key in seen:
                raise ValueError("duplicate archive path")
            seen.add(key)
            role = scope(name)
            if role is None or member.isdir():
                continue
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError("archive member size bound exceeded")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("archive expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size:
                raise ValueError("archive member length mismatch")
            if role == "record":
                recorded[name] = digest(data)
            else:
                files[name] = data
    return files, recorded


def verify_manifest(files: dict[str, bytes], recorded: dict[str, str],
                    manifest: dict[str, str]) -> None:
    extracted = set(files) | set(recorded)
    if extracted != set(manifest):
        raise ValueError("extracted file set differs from the pinned content manifest")
    for name, data in files.items():
        if digest(data) != manifest[name]:
            raise ValueError(f"extracted content hash differs from the pinned manifest: {name}")
    for name, checksum in recorded.items():
        if checksum != manifest[name]:
            raise ValueError(f"recorded-only hash differs from the pinned manifest: {name}")


def _package(manifest_bytes: bytes, label: str) -> dict:
    try:
        return tomllib.loads(manifest_bytes.decode("utf-8"))["package"]
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{label} package manifest invalid") from exc


def validate_originals(files: dict[str, bytes]) -> None:
    yggdrasil = _package(files["crates/yggdrasil/Cargo.toml"], "yggdrasil")
    ironwood = _package(files["crates/ironwood/Cargo.toml"], "ironwood")
    if (yggdrasil.get("name"), yggdrasil.get("version")) != ("yggdrasil", "0.3.1"):
        raise ValueError("yggdrasil package identity mismatch")
    if yggdrasil.get("license") != "MPL-2.0":
        raise ValueError("yggdrasil manifest license is not MPL-2.0")
    if ironwood.get("name") != "ironwood":
        raise ValueError("ironwood package identity mismatch")
    if "Mozilla Public License" not in files[EXTRACT_FILE].decode("utf-8", errors="replace"):
        raise ValueError("LICENSE text does not identify the Mozilla Public License")


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        path = root.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def inventory(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in prepared source tree")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return result


def build_receipt(files: dict[str, bytes], recorded: dict[str, str],
                  manifest: dict[str, str], patched: dict[str, bytes]) -> dict:
    prepared = hashes(patched)
    return {"package": "yggdrasil", "version": "0.3.1",
            "source": SOURCE,
            "archive_url": ARCHIVE_URL, "archive_sha256": ARCHIVE_SHA256,
            "content_manifest": {"path": MANIFEST_RELATIVE, "files": len(manifest),
                                 "tree_digest": TREE_DIGEST,
                                 "authority": "content-manifest"},
            "patch_applied": True, "changed_files": sorted(lifecycle_patch.changed_files()),
            "recipe_files": recipe(),
            "recorded_only_files": dict(sorted(recorded.items())),
            "original_files": {name: manifest[name] for name in sorted(files)},
            "prepared_files": prepared}


def prepare(archive: Path, destination: Path) -> Path:
    manifest = load_manifest()
    files, recorded = archive_files(archive)
    verify_manifest(files, recorded, manifest)
    validate_originals(files)
    patched = lifecycle_patch.apply(files)
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("output root must be new and its parent must exist")
    root = destination / ARCHIVE_TOP
    destination.mkdir()
    try:
        write_tree(root, patched)
        (destination / (ARCHIVE_TOP + ".provenance.json")).write_text(
            json.dumps(build_receipt(files, recorded, manifest, patched), sort_keys=True,
                       indent=2) + "\n", encoding="utf-8")
        verify(root, manifest)
        return root
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def verify(root: Path, manifest: dict[str, str] | None = None) -> dict[str, str]:
    manifest = manifest if manifest is not None else load_manifest()
    if root.name != ARCHIVE_TOP or root.is_symlink() or not root.is_dir():
        raise ValueError("unexpected prepared root")
    receipt_path = root.parent / (ARCHIVE_TOP + ".provenance.json")
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("prepared receipt missing or linked")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("prepared receipt invalid") from exc
    extracted_names = {name for name in manifest if scope(name) == "extract"}
    recorded_names = {name for name in manifest if scope(name) == "record"}
    expected_receipt = {"package": "yggdrasil", "version": "0.3.1", "source": SOURCE,
                        "archive_sha256": ARCHIVE_SHA256, "archive_url": ARCHIVE_URL,
                        "patch_applied": True,
                        "changed_files": sorted(lifecycle_patch.changed_files()),
                        "content_manifest": {"path": MANIFEST_RELATIVE,
                                             "files": MANIFEST_COUNT,
                                             "tree_digest": TREE_DIGEST,
                                             "authority": "content-manifest"},
                        "recipe_files": recipe(),
                        "recorded_only_files": {name: manifest[name]
                                                for name in sorted(recorded_names)},
                        "original_files": {name: manifest[name]
                                           for name in sorted(extracted_names)}}
    if {key: receipt.get(key) for key in expected_receipt} != expected_receipt:
        raise ValueError("prepared receipt mismatch")
    if set(receipt) != set(expected_receipt) | {"prepared_files"}:
        raise ValueError("prepared receipt has unexpected fields")
    files: dict[str, str] = {}
    for name, checksum in inventory(root).items():
        if scope(name) != "extract":
            raise ValueError(f"prepared tree contains an out-of-scope path: {name}")
        files[name] = checksum
    if sorted(files) != sorted(extracted_names):
        raise ValueError("prepared tree file set differs from the pinned manifest")
    changed = set(lifecycle_patch.changed_files())
    if any(files[name] != manifest[name] for name in files if name not in changed):
        raise ValueError("prepared source content hash differs from the pinned manifest")
    if files != receipt.get("prepared_files"):
        raise ValueError("prepared tree differs from its receipt")
    fault = lifecycle_patch.pin_fault({name: files[name] for name in sorted(changed)})
    if fault:
        raise ValueError(fault)
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--destination", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        print(prepare(args.archive, args.destination))
    else:
        verify(args.source)


if __name__ == "__main__":
    main()
