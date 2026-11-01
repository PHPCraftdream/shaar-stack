# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare and verify the pinned serde_bencode transitive repair source."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib

ARCHIVE_SHA256 = "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e"
PACKAGE = "serde_bencode-0.2.4"
VERSION = "0.2.4"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_MEMBER = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
HERE = Path(__file__).resolve().parent
SOURCE = "src/de.rs"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: digest(data) for name, data in sorted(files.items())}


def load_edits() -> dict[str, list[tuple[str, str]]]:
    """Load the one fixed repair module only when the CI runner calls preparation."""
    path = HERE / "edits.py"
    if path.resolve() != HERE / "edits.py" or not path.is_file() or path.is_symlink():
        raise ValueError("fixed serde_bencode edit module missing or unsafe")
    spec = importlib.util.spec_from_file_location("_serde_bencode_edits", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load fixed serde_bencode edit module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    edits = module.edits()
    if (not isinstance(edits, dict) or set(edits) != {SOURCE}
            or not isinstance(edits[SOURCE], list) or not edits[SOURCE]):
        raise ValueError("serde_bencode repair must edit only src/de.rs")
    return edits


def recipe() -> dict[str, str]:
    return {name: digest((HERE / name).read_bytes()) for name in ("prepare.py", "edits.py")}


def archive_files(archive: Path) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("serde_bencode archive identity/size mismatch")
    if digest(archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("serde_bencode archive checksum mismatch")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    file_paths: set[str] = set()
    directory_paths: set[str] = set()
    total = count = 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("serde_bencode archive entry bound exceeded")
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "." in path.parts
                    or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
                    or any(":" in part for part in path.parts) or not path.parts
                    or path.parts[0] != PACKAGE or len(path.parts) > 24
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unsafe serde_bencode archive member")
            name = path.relative_to(PACKAGE).as_posix()
            if name == ".":
                if not member.isdir() or "" in seen:
                    raise ValueError("serde_bencode package root must be a unique directory")
                seen.add("")
                continue
            normalized = name.casefold()
            if normalized in seen:
                raise ValueError("case-insensitive duplicate serde_bencode path")
            parents = [p.as_posix().casefold() for p in PurePosixPath(name).parents if str(p) != "."]
            if member.isdir():
                if normalized in file_paths or any(p in file_paths for p in parents):
                    raise ValueError("archive file/directory collision")
                directory_paths.add(normalized)
                seen.add(normalized)
                continue
            if (any(p in file_paths for p in parents)
                    or any(p.startswith(normalized + "/") for p in file_paths)
                    or normalized in directory_paths):
                raise ValueError("archive file/directory prefix collision")
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError("serde_bencode member size bound exceeded")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("serde_bencode archive expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("serde_bencode archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size or len(data) > MAX_MEMBER:
                raise ValueError("serde_bencode member length mismatch")
            seen.add(normalized)
            file_paths.add(normalized)
            files[name] = data
    return files


def validate_originals(files: dict[str, bytes]) -> None:
    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    package = manifest["package"]
    if (package.get("name"), package.get("version"), package.get("license")) != (
            "serde_bencode", VERSION, "MIT"):
        raise ValueError("unexpected serde_bencode package identity/license")
    license_text = files.get("LICENSE.md", b"").decode("utf-8")
    if not license_text or "MIT License" not in license_text:
        raise ValueError("upstream MIT license text missing")


def apply_edits(files: dict[str, bytes], edits: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    changed = dict(files)
    for name, pairs in edits.items():
        if name != SOURCE or name not in changed:
            raise ValueError("repair target missing or outside src/de.rs")
        text = changed[name].decode("utf-8")
        for old, new in pairs:
            if not old or old == new or text.count(old) != 1:
                raise ValueError("unique serde_bencode upstream edit anchor mismatch")
            text = text.replace(old, new, 1)
        changed[name] = text.encode("utf-8")
    return changed


def reverse(files: dict[str, bytes], edits: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    restored = dict(files)
    data = restored.get(SOURCE)
    if data is None:
        raise ValueError("serde_bencode repaired source missing")
    text = data.decode("utf-8")
    for old, new in reversed(edits[SOURCE]):
        if not new or text.count(new) != 1:
            raise ValueError("unique serde_bencode reverse anchor mismatch")
        text = text.replace(new, old, 1)
    restored[SOURCE] = text.encode("utf-8")
    return restored


def transform(files: dict[str, bytes]) -> dict[str, bytes]:
    validate_originals(files)
    edits = load_edits()
    changed = apply_edits(files, edits)
    if set(changed) != set(files) or hashes(reverse(changed, edits)) != hashes(files):
        raise ValueError("serde_bencode reverse transformation failed")
    return {name: data for name, data in changed.items() if files[name] != data}


def prepare(archive: Path, destination: Path) -> Path:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("destination must be new and its parent must exist")
    original = archive_files(archive)
    changes = transform(original)
    if set(changes) != {SOURCE}:
        raise ValueError("serde_bencode preparation must change only src/de.rs")
    prepared = dict(original)
    prepared.update(changes)
    destination.mkdir()
    try:
        root = destination / PACKAGE
        root.mkdir()
        for name, data in prepared.items():
            output = root.joinpath(*PurePosixPath(name).parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        receipt = {
            "package": "serde_bencode", "version": VERSION, "archive_sha256": ARCHIVE_SHA256,
            "license": "MIT (upstream; not relicensed)",
            "recipe_files": recipe(), "original_files": hashes(original),
            "prepared_files": hashes(prepared), "changed_files": [SOURCE],
        }
        (destination / "provenance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    except BaseException:
        import shutil
        shutil.rmtree(destination)
        raise
    return root


def verify(root: Path, archive: Path) -> dict[str, bytes]:
    if root.name != PACKAGE or root.is_symlink() or root.parent.is_symlink():
        raise ValueError("unexpected serde_bencode prepared root")
    receipt_path = root.parent / "provenance.json"
    if receipt_path.is_symlink():
        raise ValueError("serde_bencode receipt must not be a symlink")
    provenance = json.loads(receipt_path.read_text(encoding="utf-8"))
    original = archive_files(archive)
    changes = transform(original)
    if set(changes) != {SOURCE}:
        raise ValueError("serde_bencode preparation must change only src/de.rs")
    expected = dict(original)
    expected.update(changes)
    expected_receipt = {
        "package": "serde_bencode", "version": VERSION, "archive_sha256": ARCHIVE_SHA256,
        "license": "MIT (upstream; not relicensed)", "recipe_files": recipe(),
        "original_files": hashes(original), "prepared_files": hashes(expected),
        "changed_files": [SOURCE],
    }
    if provenance != expected_receipt:
        raise ValueError("serde_bencode provenance does not match archive and recipe")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    directories: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("link in prepared serde_bencode source")
        relative = path.relative_to(root).as_posix()
        normalized = relative.casefold()
        if normalized in seen:
            raise ValueError("prepared serde_bencode path collision")
        seen.add(normalized)
        if path.is_dir():
            directories.add(normalized)
        elif path.is_file():
            files[relative] = path.read_bytes()
    if any(name.casefold() in directories for name in files):
        raise ValueError("prepared serde_bencode file/directory collision")
    if files != expected or hashes(files) != hashes(expected):
        raise ValueError("prepared serde_bencode source differs from pinned transformation")
    restored = reverse(files, load_edits())
    validate_originals(restored)
    if restored != original:
        raise ValueError("serde_bencode prepared source does not reverse to archive")
    return files


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="mode", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--archive", type=Path, required=True)
    prepare_parser.add_argument("--destination", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--source", type=Path, required=True)
    verify_parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.archive, args.destination)
    else:
        verify(args.source, args.archive)


if __name__ == "__main__":
    main()
