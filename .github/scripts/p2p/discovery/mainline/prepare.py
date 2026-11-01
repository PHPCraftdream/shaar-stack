# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare and verify the pinned n0-mainline source repairs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tomllib

sys.dont_write_bytecode = True

ARCHIVE_SHA256 = "f64972176bd209d1ebe98310743614e19728a33a4b288ae8147cca9f0b8c7463"
PACKAGE = "n0-mainline-0.7.0"
VERSION = "0.7.0"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_MEMBER = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
HERE = Path(__file__).resolve().parent
TESTS = HERE / "tests"
SOURCE = "src/common/messages.rs"
INGRESS_TESTS = "src/common/messages/ingress_tests.rs"
SOCKET_INGRESS_TESTS = "src/actor/socket/ingress_tests.rs"
INGRESS_TEST_MODULE = '\n\n#[cfg(test)]\n#[path = "messages/ingress_tests.rs"]\nmod ingress_tests;\n'
SOCKET_INGRESS_TEST_MODULE = '\n\n#[cfg(test)]\n#[path = "socket/ingress_tests.rs"]\nmod ingress_tests;\n'
OLD_GUARD = "    if !bytes.len().is_multiple_of(104) {\n        return Err(DecodeMessageError::InvalidSignedPeersEncodingLength);\n    }"
NEW_GUARD = "    if bytes.len() != 104 {\n        return Err(DecodeMessageError::InvalidSignedPeersEncodingLength);\n    }"
TEST_MODULE = '\n\n#[cfg(test)]\n#[path = "messages/signed_peer_length_tests.rs"]\nmod signed_peer_length_tests;\n'
GENERATED = "src/common/messages/signed_peer_length_tests.rs"
OWNER = "src/owned.rs"
LIFECYCLE = "src/owned/lifecycle_tests.rs"
OWNER_SUFFIX = '\n#[cfg(test)]\n#[path = "owned/lifecycle_tests.rs"]\nmod tests;\n'
ACTOR_TESTS = "src/actor/owned_tests.rs"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: digest(data) for name, data in sorted(files.items())}


def load_edits(filename: str) -> dict[str, list[tuple[str, str]]]:
    path = (HERE / filename).resolve()
    if (filename not in ("numeric.py", "lifetime.py", "ci/ingress.py")
            or path != HERE / filename or not path.is_relative_to(HERE)):
        raise ValueError("invalid fixed edit-module path")
    name = "_mainline_" + filename.removesuffix(".py").replace("/", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load fixed edit module {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    edits = module.edits()
    if not isinstance(edits, dict):
        raise ValueError(f"invalid edits from {filename}")
    return edits


def edit_map() -> dict[str, list[tuple[str, str]]]:
    merged: dict[str, list[tuple[str, str]]] = {}
    for module in ("numeric.py", "lifetime.py", "ci/ingress.py"):
        for path, pairs in load_edits(module).items():
            merged.setdefault(path, []).extend(pairs)
    return merged


def recipe() -> dict[str, str]:
    names = ("prepare.py", "tests/regressions.rs", "numeric.py", "lifetime.py",
             "owner.rs", "tests/lifecycle_tests.rs", "tests/actor_tests.rs",
             "ci/ingress.py", "ci/bencode/prepare.py", "ci/bencode/edits.py",
             "tests/ingress_tests.rs", "tests/udp_ingress_tests.rs")
    return {name: digest((HERE / name).read_bytes()) for name in names}


def archive_files(archive: Path) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("n0-mainline archive identity/size mismatch")
    archive_data = archive.read_bytes()
    if digest(archive_data) != ARCHIVE_SHA256:
        raise ValueError("n0-mainline archive checksum mismatch")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    file_paths: set[str] = set()
    directory_paths: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as source:
        count = 0
        for member in source:
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("n0-mainline archive entry bound exceeded")
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "." in path.parts
                    or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
                    or any(":" in part for part in path.parts)
                    or not path.parts or path.parts[0] != PACKAGE or len(path.parts) > 24
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unsafe n0-mainline archive member")
            name = path.relative_to(PACKAGE).as_posix()
            if name == ".":
                if not member.isdir() or "" in seen:
                    raise ValueError("n0-mainline package root must be a unique directory")
                seen.add("")
                continue
            normalized = name.casefold()
            if normalized in seen:
                raise ValueError("case-insensitive duplicate archive path")
            parents = [p.as_posix().casefold() for p in PurePosixPath(name).parents if str(p) != "."]
            if member.isdir():
                if normalized in file_paths or any(parent in file_paths for parent in parents):
                    raise ValueError("archive file/directory collision")
                directory_paths.add(normalized)
                seen.add(normalized)
                continue
            if any(parent in file_paths for parent in parents):
                raise ValueError("archive file/directory prefix collision")
            if any(existing.startswith(normalized + "/") for existing in file_paths):
                raise ValueError("archive file/directory prefix collision")
            if normalized in directory_paths:
                raise ValueError("archive file/directory collision")
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError("archive member size bound exceeded")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("archive expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size or len(data) > MAX_MEMBER:
                raise ValueError("archive member length mismatch")
            seen.add(normalized)
            file_paths.add(normalized)
            files[name] = data
    return files


def validate_originals(files: dict[str, bytes]) -> None:
    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    package = manifest["package"]
    if (package.get("name"), package.get("version"), package.get("license")) != (
            "n0-mainline", VERSION, "MIT OR Apache-2.0"):
        raise ValueError("unexpected n0-mainline package identity/license")
    if not files.get("LICENSE-MIT") or not files.get("LICENSE-APACHE"):
        raise ValueError("upstream license files are missing")


def apply_edits(files: dict[str, bytes], edits: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    changed = dict(files)
    for path, pairs in edits.items():
        data = changed.get(path)
        if data is None:
            raise ValueError(f"required upstream source missing: {path}")
        text = data.decode("utf-8")
        for old, new in pairs:
            if not old or text.count(old) != 1 or old == new:
                raise ValueError(f"unique upstream edit anchor mismatch: {path}")
            text = text.replace(old, new, 1)
        changed[path] = text.encode("utf-8")
    return changed


def reverse(files: dict[str, bytes], edits: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    restored = dict(files)
    expected_generated = {
        GENERATED: (TESTS / "regressions.rs").read_bytes(),
        OWNER: (HERE / "owner.rs").read_bytes() + OWNER_SUFFIX.encode("utf-8"),
        LIFECYCLE: (TESTS / "lifecycle_tests.rs").read_bytes(),
        ACTOR_TESTS: (TESTS / "actor_tests.rs").read_bytes(),
        INGRESS_TESTS: (TESTS / "ingress_tests.rs").read_bytes(),
        SOCKET_INGRESS_TESTS: (TESTS / "udp_ingress_tests.rs").read_bytes(),
    }
    for path, expected in expected_generated.items():
        if restored.get(path) != expected:
            raise ValueError(f"generated source content mismatch: {path}")
    for path in expected_generated:
        del restored[path]
    data = restored.get(SOURCE)
    if data is None:
        raise ValueError("signed-peer source missing")
    text = data.decode("utf-8")
    if text.count(INGRESS_TEST_MODULE) != 1:
        raise ValueError("prepared ingress module shape mismatch")
    text = text.replace(INGRESS_TEST_MODULE, "", 1)
    restored[SOURCE] = text.encode("utf-8")
    data = restored.get("src/actor/socket.rs")
    if data is None:
        raise ValueError("prepared socket source missing")
    text = data.decode("utf-8")
    if text.count(SOCKET_INGRESS_TEST_MODULE) != 1:
        raise ValueError("prepared socket ingress module shape mismatch")
    restored["src/actor/socket.rs"] = text.replace(SOCKET_INGRESS_TEST_MODULE, "", 1).encode("utf-8")
    for path, pairs in reversed(list(edits.items())):
        data = restored.get(path)
        if data is None:
            raise ValueError(f"edited source missing during reverse: {path}")
        text = data.decode("utf-8")
        for old, new in reversed(pairs):
            if not new or text.count(new) != 1:
                raise ValueError(f"unique reverse edit anchor mismatch: {path}")
            text = text.replace(new, old, 1)
        restored[path] = text.encode("utf-8")
    data = restored.get(SOURCE)
    if data is None:
        raise ValueError("signed-peer source missing")
    text = data.decode("utf-8")
    if text.count(NEW_GUARD) != 1 or text.count(TEST_MODULE) != 1:
        raise ValueError("prepared signed-peer source shape mismatch")
    restored[SOURCE] = text.replace(TEST_MODULE, "", 1).replace(NEW_GUARD, OLD_GUARD, 1).encode("utf-8")
    return restored


def transform(files: dict[str, bytes]) -> dict[str, bytes]:
    validate_originals(files)
    if SOURCE not in files:
        raise ValueError(f"required signed-peer source missing: {SOURCE}")
    if OLD_GUARD not in files[SOURCE].decode("utf-8"):
        raise ValueError("signed-peer unique upstream guard anchor mismatch")
    edits = edit_map()
    if set(edits) & {OWNER, LIFECYCLE, ACTOR_TESTS, INGRESS_TESTS, SOCKET_INGRESS_TESTS}:
        raise ValueError("generated source collides with upstream edits")
    changed = apply_edits(files, edits)
    socket_text = changed["src/actor/socket.rs"].decode("utf-8")
    if SOCKET_INGRESS_TEST_MODULE in socket_text:
        raise ValueError("socket ingress module already exists")
    changed["src/actor/socket.rs"] = (socket_text + SOCKET_INGRESS_TEST_MODULE).encode("utf-8")
    text = changed[SOURCE].decode("utf-8")
    if text.count(OLD_GUARD) != 1 or NEW_GUARD in text or TEST_MODULE in text or INGRESS_TEST_MODULE in text:
        raise ValueError("signed-peer unique upstream guard anchor mismatch")
    text = text.replace(OLD_GUARD, NEW_GUARD, 1)
    changed[SOURCE] = (text + TEST_MODULE + INGRESS_TEST_MODULE).encode("utf-8")
    generated = {
        GENERATED: (TESTS / "regressions.rs").read_bytes(),
        OWNER: (HERE / "owner.rs").read_bytes() + OWNER_SUFFIX.encode("utf-8"),
        LIFECYCLE: (TESTS / "lifecycle_tests.rs").read_bytes(),
        ACTOR_TESTS: (TESTS / "actor_tests.rs").read_bytes(),
        INGRESS_TESTS: (TESTS / "ingress_tests.rs").read_bytes(),
        SOCKET_INGRESS_TESTS: (TESTS / "udp_ingress_tests.rs").read_bytes(),
    }
    original_names = {name.casefold() for name in files}
    generated_names = [name.casefold() for name in generated]
    edit_names = {name.casefold() for name in edits}
    if (len(set(generated_names)) != len(generated_names)
            or set(generated_names) & original_names
            or set(generated_names) & edit_names):
        raise ValueError("generated source collides with upstream files")
    for generated_name in generated_names:
        for existing in original_names | edit_names:
            if generated_name.startswith(existing + "/") or existing.startswith(generated_name + "/"):
                raise ValueError("generated source path-prefix collision")
    changed.update(generated)
    restored = reverse(changed, edits)
    if hashes(restored) != hashes(files):
        raise ValueError("reverse transformation failed")
    return {name: data for name, data in changed.items() if files.get(name) != data}


def prepare(archive: Path, destination: Path) -> Path:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("destination must be new and its parent must exist")
    original = archive_files(archive)
    changes = transform(original)
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
            "package": "n0-mainline", "version": VERSION, "archive_sha256": ARCHIVE_SHA256,
            "license": "MIT OR Apache-2.0 (upstream; not relicensed)",
            "recipe_files": recipe(), "original_files": hashes(original),
            "prepared_files": hashes(prepared), "changed_files": sorted(changes),
        }
        (destination / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    except BaseException:
        import shutil
        shutil.rmtree(destination)
        raise
    return root


def verify(root: Path, archive: Path) -> dict[str, bytes]:
    if root.name != PACKAGE or root.is_symlink() or root.parent.is_symlink():
        raise ValueError("unexpected n0-mainline prepared root")
    receipt_path = root.parent / "provenance.json"
    if receipt_path.is_symlink():
        raise ValueError("n0-mainline receipt must not be a symlink")
    provenance = json.loads(receipt_path.read_text(encoding="utf-8"))
    original = archive_files(archive)
    expected_changes = transform(original)
    expected_prepared = dict(original)
    expected_prepared.update(expected_changes)
    expected_receipt = {
        "package": "n0-mainline", "version": VERSION, "archive_sha256": ARCHIVE_SHA256,
        "license": "MIT OR Apache-2.0 (upstream; not relicensed)",
        "recipe_files": recipe(), "original_files": hashes(original),
        "prepared_files": hashes(expected_prepared), "changed_files": sorted(expected_changes),
    }
    if provenance != expected_receipt:
        raise ValueError("n0-mainline provenance does not match supplied archive and recipe")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    directories: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("link in prepared n0-mainline source")
        relative = path.relative_to(root).as_posix()
        normalized = relative.casefold()
        if normalized in seen:
            raise ValueError("prepared path collision")
        seen.add(normalized)
        if path.is_dir():
            directories.add(normalized)
        elif path.is_file():
            files[relative] = path.read_bytes()
    if any(name.casefold() in directories for name in files):
        raise ValueError("prepared file/directory collision")
    if hashes(files) != hashes(expected_prepared) or files != expected_prepared:
        raise ValueError("prepared source differs from supplied archive transformation")
    restored = reverse(files, edit_map())
    if restored != original:
        raise ValueError("prepared source does not reverse to supplied archive")
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
