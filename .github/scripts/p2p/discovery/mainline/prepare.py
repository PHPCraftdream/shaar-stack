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
INGRESS_TEST_MODULE = '\n\n#[cfg(test)]\n#[path = "messages/ingress_tests.rs"]\nmod ingress_tests;\n'
SOCKET_INGRESS_TEST_MODULE = '\n\n#[cfg(test)]\n#[path = "socket/ingress_tests.rs"]\nmod ingress_tests;\n'
SOCKET_RESOURCE_TEST_MODULE = '\n#[cfg(test)]\n#[path = "socket/resource_tests.rs"]\nmod resource_tests;\n'
OLD_GUARD = "    if !bytes.len().is_multiple_of(104) {\n        return Err(DecodeMessageError::InvalidSignedPeersEncodingLength);\n    }"
NEW_GUARD = "    if bytes.len() != 104 {\n        return Err(DecodeMessageError::InvalidSignedPeersEncodingLength);\n    }"
TEST_MODULE = '\n\n#[cfg(test)]\n#[path = "messages/signed_peer_length_tests.rs"]\nmod signed_peer_length_tests;\n'
GENERATED = "src/common/messages/signed_peer_length_tests.rs"
OWNER = "src/owned.rs"
LIFECYCLE = "src/owned/lifecycle_tests.rs"
ACTOR_TESTS = "src/actor/owned_tests.rs"
SOCKET_INGRESS_TESTS = "src/actor/socket/ingress_tests.rs"
RESOURCE_MODULE = "src/resource.rs"
SOCKET_RESOURCES = "src/actor/socket/resources.rs"
SOCKET_OWNED = "src/actor/socket/owned.rs"
STORE_OWNER = "src/store_owner.rs"
VISITED_STORE = "src/visited_store.rs"
SOCKET_RESOURCE_TESTS = "src/actor/socket/resource_tests.rs"
PUBLICATION_OBSERVER = "src/publication_observer.rs"
STORE_TESTS = "src/store_resource_tests.rs"
OWNED_ACTOR = "src/actor/owned_resources.rs"
OWNED_COMPLETION = "src/owned_completion.rs"
ACTOR_RESOURCE_TESTS = "src/actor/resource_tests.rs"
ACTOR_LIFECYCLE_TESTS = "src/actor/resource_tests/lifecycle_tests.rs"
HOSTILE_RESOURCE_TESTS = "src/actor/hostile_resource_tests.rs"
QUERY_RESOURCE_TESTS = "src/core/iterative_query/resource_tests.rs"
API_TESTS = "tests/owned_api.rs"
QUERY_RESOURCE_TEST_MODULE = '\n#[cfg(test)]\n#[path = "iterative_query/resource_tests.rs"]\nmod resource_tests;\n'
ACTOR_RESOURCE_MODULES = '\n#[cfg(test)]\n#[path = "actor/resource_tests.rs"]\nmod resource_tests;\n'
HOSTILE_RESOURCE_MODULE = '\n#[cfg(test)]\n#[path = "actor/hostile_resource_tests.rs"]\nmod hostile_resource_tests;\n'
OWNER_SUFFIX = '\n#[cfg(test)]\n#[path = "owned/lifecycle_tests.rs"]\nmod tests;\n'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: digest(data) for name, data in sorted(files.items())}


def load_edits(filename: str) -> dict[str, list[tuple[str, str]]]:
    path = (HERE / filename).resolve()
    allowed = (
        "numeric.py", "lifetime.py", "ci/ingress.py", "ci/resources/edits.py",
        "ci/resources/store_edits.py", "ci/ownership/actor.py", "ci/ownership/queries.py",
        "ci/ownership/completion.py",
    )
    if filename not in allowed or path != HERE / filename or not path.is_relative_to(HERE):
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
    for module in (
        "numeric.py", "lifetime.py", "ci/ingress.py", "ci/resources/edits.py",
        "ci/resources/store_edits.py", "ci/ownership/actor.py", "ci/ownership/queries.py",
        "ci/ownership/completion.py",
    ):
        for path, pairs in load_edits(module).items():
            merged.setdefault(path, []).extend(pairs)
    return merged


def recipe() -> dict[str, str]:
    names = (
        "prepare.py", "tests/regressions.rs", "numeric.py", "lifetime.py", "owner.rs",
        "tests/lifecycle_tests.rs", "tests/actor_tests.rs", "ci/ingress.py",
        "ci/bencode/prepare.py", "ci/bencode/edits.py", "ci/resources/edits.py",
        "ci/resources/store_edits.py", "ci/ownership/actor.py", "ci/ownership/queries.py",
        "ci/ownership/completion.py", "ci/resources/resource.rs", "ci/resources/stores/store_owner.rs",
        "ci/resources/socket/socket_resources.rs", "ci/resources/socket/socket_owned.rs", "ci/resources/socket/publication_observer.rs", "ci/resources/stores/visited_store.rs",
        "ci/resources/actor/mod.rs", "ci/resources/actor/owned_resources/admission.rs",
        "ci/resources/actor/owned_resources/maintenance.rs", "ci/resources/actor/owned_resources/tick.rs",
        "ci/resources/actor/owned_resources/failure.rs", "ci/resources/actor/owned_resources/queries.rs", "ci/resources/actor/owned_resources/put.rs", "ci/resources/tests/socket_resource_tests.rs",
        "ci/resources/tests/store_resource_tests.rs", "ci/resources/tests/lifecycle/mod.rs",
        "ci/ownership/tests/actor_resource_tests.rs", "ci/ownership/tests/actor_admission_tests.rs",
        "ci/ownership/tests/actor_put_tests.rs", "ci/ownership/query_resource_tests.rs", "ci/ownership/completion.rs",
        "ci/resources/tests/lifecycle/lifecycle_tests/put_start_tests.rs",
        "ci/resources/tests/lifecycle/lifecycle_tests/retry_tests.rs",
        "ci/ownership/tests/hostile_tests.rs", "ci/ownership/tests/hostile_resource_tests/completion_tests.rs",
        "ci/ownership/tests/hostile_resource_tests/provenance_tests.rs",
        "ci/ownership/tests/hostile_resource_tests/admission_wake_tests.rs",
        "ci/ownership/tests/hostile_resource_tests/terminal_put_tests.rs",
        "ci/ownership/tests/hostile_resource_tests/newoverload_put_tests.rs",
        "ci/ownership/tests/hostile_resource_tests/put_lifecycle_tests.rs",
        "ci/ownership/tests/hostile_resource_tests/public_put_tests.rs",
        "ci/ownership/tests/public_put/deadline.rs", "ci/ownership/tests/public_put/retirement.rs",
        "ci/ownership/tests/public_put/held_retirement.rs", "ci/ownership/tests/public_put/fatal_retirement.rs",
        "ci/resources/socket/test_controls.rs",
        "tests/ingress_tests.rs", "tests/udp_ingress_tests.rs", "tests/owned_api.rs",
    )
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
        "n0-mainline", VERSION, "MIT OR Apache-2.0"
    ):
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


def generated_sources() -> dict[str, bytes]:
    return {
        GENERATED: (TESTS / "regressions.rs").read_bytes(),
        OWNER: (HERE / "owner.rs").read_bytes() + OWNER_SUFFIX.encode("utf-8"),
        LIFECYCLE: (TESTS / "lifecycle_tests.rs").read_bytes(),
        ACTOR_TESTS: (TESTS / "actor_tests.rs").read_bytes(),
        INGRESS_TESTS: (TESTS / "ingress_tests.rs").read_bytes(),
        SOCKET_INGRESS_TESTS: (TESTS / "udp_ingress_tests.rs").read_bytes(),
        RESOURCE_MODULE: (HERE / "ci/resources/resource.rs").read_bytes(),
        SOCKET_RESOURCES: (HERE / "ci/resources/socket/socket_resources.rs").read_bytes(),
        STORE_OWNER: (HERE / "ci/resources/stores/store_owner.rs").read_bytes(),
        SOCKET_OWNED: (HERE / "ci/resources/socket/socket_owned.rs").read_bytes(),
        PUBLICATION_OBSERVER: (HERE / "ci/resources/socket/publication_observer.rs").read_bytes(),
        VISITED_STORE: (HERE / "ci/resources/stores/visited_store.rs").read_bytes(),
        SOCKET_RESOURCE_TESTS: (HERE / "ci/resources/tests/socket_resource_tests.rs").read_bytes(),
        STORE_TESTS: (HERE / "ci/resources/tests/store_resource_tests.rs").read_bytes(),
        OWNED_ACTOR: (HERE / "ci/resources/actor/mod.rs").read_bytes(),
        "src/actor/owned_resources/admission.rs": (HERE / "ci/resources/actor/owned_resources/admission.rs").read_bytes(),
        "src/actor/owned_resources/maintenance.rs": (HERE / "ci/resources/actor/owned_resources/maintenance.rs").read_bytes(),
        "src/actor/owned_resources/tick.rs": (HERE / "ci/resources/actor/owned_resources/tick.rs").read_bytes(),
        "src/actor/owned_resources/failure.rs": (HERE / "ci/resources/actor/owned_resources/failure.rs").read_bytes(),
        "src/actor/owned_resources/queries.rs": (HERE / "ci/resources/actor/owned_resources/queries.rs").read_bytes(),
        "src/actor/owned_resources/put.rs": (HERE / "ci/resources/actor/owned_resources/put.rs").read_bytes(),
        ACTOR_LIFECYCLE_TESTS: (HERE / "ci/resources/tests/lifecycle/mod.rs").read_bytes(),
        ACTOR_RESOURCE_TESTS: (HERE / "ci/ownership/tests/actor_resource_tests.rs").read_bytes(),
        "src/actor/resource_tests/admission_tests.rs": (HERE / "ci/ownership/tests/actor_admission_tests.rs").read_bytes(),
        "src/actor/resource_tests/put_tests.rs": (HERE / "ci/ownership/tests/actor_put_tests.rs").read_bytes(),
        "src/actor/resource_tests/lifecycle_tests/put_start_tests.rs": (HERE / "ci/resources/tests/lifecycle/lifecycle_tests/put_start_tests.rs").read_bytes(),
        "src/actor/resource_tests/lifecycle_tests/retry_tests.rs": (HERE / "ci/resources/tests/lifecycle/lifecycle_tests/retry_tests.rs").read_bytes(),
        QUERY_RESOURCE_TESTS: (HERE / "ci/ownership/query_resource_tests.rs").read_bytes(),
        HOSTILE_RESOURCE_TESTS: (HERE / "ci/ownership/tests/hostile_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/completion_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/completion_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/provenance_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/provenance_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/admission_wake_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/admission_wake_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/terminal_put_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/terminal_put_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/newoverload_put_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/newoverload_put_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/put_lifecycle_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/put_lifecycle_tests.rs").read_bytes(),
        "src/actor/hostile_resource_tests/public_put_tests.rs": (HERE / "ci/ownership/tests/hostile_resource_tests/public_put_tests.rs").read_bytes(),
        "src/actor/public_put/deadline.rs": (HERE / "ci/ownership/tests/public_put/deadline.rs").read_bytes(),
        "src/actor/public_put/retirement.rs": (HERE / "ci/ownership/tests/public_put/retirement.rs").read_bytes(),
        "src/actor/public_put/held_retirement.rs": (HERE / "ci/ownership/tests/public_put/held_retirement.rs").read_bytes(),
        "src/actor/public_put/fatal_retirement.rs": (HERE / "ci/ownership/tests/public_put/fatal_retirement.rs").read_bytes(),
        "src/actor/socket/test_controls.rs": (HERE / "ci/resources/socket/test_controls.rs").read_bytes(),
        OWNED_COMPLETION: (HERE / "ci/ownership/completion.rs").read_bytes(),
        API_TESTS: (TESTS / "owned_api.rs").read_bytes(),
    }


def reverse(files: dict[str, bytes], edits: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    restored = dict(files)
    generated = generated_sources()
    for path, expected in generated.items():
        if restored.get(path) != expected:
            raise ValueError(f"generated source content mismatch: {path}")
        del restored[path]
    actor_declarations = ACTOR_RESOURCE_MODULES
    actor_source = restored.get("src/actor.rs")
    if actor_source is None:
        raise ValueError("prepared owned actor source missing")
    text = actor_source.decode("utf-8")
    if text.count(actor_declarations) != 1:
        raise ValueError("prepared owned actor module declaration mismatch")
    if text.count(HOSTILE_RESOURCE_MODULE) != 1:
        raise ValueError("prepared hostile actor test module declaration mismatch")
    restored["src/actor.rs"] = text.replace(actor_declarations, "", 1).replace(HOSTILE_RESOURCE_MODULE, "", 1).encode("utf-8")
    query_source = restored.get("src/core/iterative_query.rs")
    if query_source is None:
        raise ValueError("prepared iterative query source missing")
    text = query_source.decode("utf-8")
    if text.count(QUERY_RESOURCE_TEST_MODULE) != 1:
        raise ValueError("prepared query test module declaration mismatch")
    restored["src/core/iterative_query.rs"] = text.replace(QUERY_RESOURCE_TEST_MODULE, "", 1).encode("utf-8")
    data = restored.get(SOURCE)
    if data is None:
        raise ValueError("signed-peer source missing")
    text = data.decode("utf-8")
    if text.count(INGRESS_TEST_MODULE) != 1:
        raise ValueError("prepared ingress module shape mismatch")
    restored[SOURCE] = text.replace(INGRESS_TEST_MODULE, "", 1).encode("utf-8")
    data = restored.get("src/actor/socket.rs")
    if data is None:
        raise ValueError("prepared socket source missing")
    text = data.decode("utf-8")
    for declaration in (SOCKET_INGRESS_TEST_MODULE, SOCKET_RESOURCE_TEST_MODULE):
        if text.count(declaration) != 1:
            raise ValueError("prepared socket test module shape mismatch")
        text = text.replace(declaration, "", 1)
    restored["src/actor/socket.rs"] = text.encode("utf-8")
    data = restored.get("src/lib.rs")
    if data is None or data.decode("utf-8").count("mod resource;\n") != 1:
        raise ValueError("prepared resource module declaration shape mismatch")
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
    if SOURCE not in files or OLD_GUARD not in files[SOURCE].decode("utf-8"):
        raise ValueError("signed-peer unique upstream guard anchor mismatch")
    edits = edit_map()
    generated = generated_sources()
    if set(edits) & set(generated):
        raise ValueError("generated source collides with upstream edits")
    changed = apply_edits(files, edits)
    socket_text = changed["src/actor/socket.rs"].decode("utf-8")
    if SOCKET_INGRESS_TEST_MODULE in socket_text or SOCKET_RESOURCE_TEST_MODULE in socket_text:
        raise ValueError("socket test module already exists")
    changed["src/actor/socket.rs"] = (socket_text + SOCKET_INGRESS_TEST_MODULE + SOCKET_RESOURCE_TEST_MODULE).encode("utf-8")
    lib_text = changed["src/lib.rs"].decode("utf-8")
    if lib_text.count("mod resource;\n") != 1:
        raise ValueError("resource declaration must be introduced exactly once by recipe edits")
    text = changed[SOURCE].decode("utf-8")
    if text.count(OLD_GUARD) != 1 or NEW_GUARD in text or TEST_MODULE in text or INGRESS_TEST_MODULE in text:
        raise ValueError("signed-peer unique upstream guard anchor mismatch")
    changed[SOURCE] = (text.replace(OLD_GUARD, NEW_GUARD, 1) + TEST_MODULE + INGRESS_TEST_MODULE).encode("utf-8")
    original_names = {name.casefold() for name in files}
    generated_names = [name.casefold() for name in generated]
    edit_names = {name.casefold() for name in edits}
    if len(set(generated_names)) != len(generated_names) or set(generated_names) & original_names or set(generated_names) & edit_names:
        raise ValueError("generated source collides with upstream files")
    for generated_name in generated_names:
        for existing in original_names | edit_names:
            if generated_name.startswith(existing + "/") or existing.startswith(generated_name + "/"):
                raise ValueError("generated source path-prefix collision")
    changed.update(generated)
    for path, suffix in (("src/actor.rs", ACTOR_RESOURCE_MODULES + HOSTILE_RESOURCE_MODULE), ("src/core/iterative_query.rs", QUERY_RESOURCE_TEST_MODULE)):
        text = changed[path].decode("utf-8")
        if suffix in text:
            raise ValueError(f"generated module declarations already exist: {path}")
        changed[path] = (text + suffix).encode("utf-8")
    if hashes(reverse(changed, edits)) != hashes(files):
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
            "package": "n0-mainline",
            "version": VERSION,
            "archive_sha256": ARCHIVE_SHA256,
            "license": "MIT OR Apache-2.0 (upstream; not relicensed)",
            "recipe_files": recipe(),
            "original_files": hashes(original),
            "prepared_files": hashes(prepared),
            "changed_files": sorted(changes),
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
        "package": "n0-mainline",
        "version": VERSION,
        "archive_sha256": ARCHIVE_SHA256,
        "license": "MIT OR Apache-2.0 (upstream; not relicensed)",
        "recipe_files": recipe(),
        "original_files": hashes(original),
        "prepared_files": hashes(expected_prepared),
        "changed_files": sorted(expected_changes),
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
    if reverse(files, edit_map()) != original:
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
