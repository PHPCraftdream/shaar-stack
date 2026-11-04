# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Prepare the pinned multibase 0.9.3 source without base256emoji."""

# The emoji doc/alphabet lines are anchored structurally (prefix/suffix/length
# bounds plus the archive and receipt hashes) rather than re-transcribed, to
# avoid byte drift against the vendored upstream source.

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib

ARCHIVE_SHA256 = "7e0e4a371cbf1dfd666b658ba137763edb23c45beb43cfe369b5593cd6b437b6"
PACKAGE = "multibase-0.9.3"
VERSION = "0.9.3"
RECIPE = ".github/probes/native-graph-multibase/prepare.py"
CHANGE_FILES = (
    "Cargo.toml",
    "Cargo.toml.orig",
    "src/base.rs",
    "src/error.rs",
    "src/impls.rs",
    "tests/lib.rs",
)
# The archive carries upstream's own development Cargo.lock. Cargo never reads a
# dependency's lock file, so it stays byte-identical and is exempt from the sweep.
INERT_FILES = ("Cargo.lock",)
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_ENTRIES = 512
MAX_MEMBER = 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
ROCKET = b"\xf0\x9f\x9a\x80"
EMOJI_DOC_PREFIX = b"/// Base256Emoji (alphabet: " + ROCKET
EMOJI_DOC_SUFFIX = b"\xf0\x9f\xa5\x82)\n"
DOC_MIN = 900
DOC_MAX = 1300


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {name: digest(data) for name, data in sorted(files.items())}


def recipe() -> dict[str, str]:
    return {RECIPE: digest(Path(__file__).resolve().read_bytes())}


def archive_files(archive: Path) -> dict[str, bytes]:
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("multibase archive identity/size mismatch")
    if digest(archive.read_bytes()) != ARCHIVE_SHA256:
        raise ValueError("multibase archive checksum mismatch")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    file_paths: set[str] = set()
    directory_paths: set[str] = set()
    total = count = 0
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("multibase archive entry bound exceeded")
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or "." in path.parts
                    or "\\" in member.name or re.match(r"^[A-Za-z]:", member.name)
                    or any(":" in part for part in path.parts) or not path.parts
                    or path.parts[0] != PACKAGE or len(path.parts) > 24
                    or not (member.isfile() or member.isdir())):
                raise ValueError("unsafe multibase archive member")
            name = path.relative_to(PACKAGE).as_posix()
            if name == ".":
                if not member.isdir() or "" in seen:
                    raise ValueError("multibase package root must be a unique directory")
                seen.add("")
                continue
            normalized = name.casefold()
            if normalized in seen:
                raise ValueError("case-insensitive duplicate multibase path")
            parents = [p.as_posix().casefold() for p in PurePosixPath(name).parents if str(p) != "."]
            if member.isdir():
                if normalized in file_paths or any(p in file_paths for p in parents):
                    raise ValueError("multibase archive file/directory collision")
                directory_paths.add(normalized)
                seen.add(normalized)
                continue
            if (any(p in file_paths for p in parents)
                    or any(p.startswith(normalized + "/") for p in file_paths)
                    or normalized in directory_paths):
                raise ValueError("multibase archive file/directory prefix collision")
            if member.size < 0 or member.size > MAX_MEMBER:
                raise ValueError("multibase member size bound exceeded")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("multibase archive expansion bound exceeded")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("multibase archive member unreadable")
            data = stream.read(MAX_MEMBER + 1)
            if len(data) != member.size or len(data) > MAX_MEMBER:
                raise ValueError("multibase member length mismatch")
            seen.add(normalized)
            file_paths.add(normalized)
            files[name] = data
    return files


def validate_originals(files: dict[str, bytes]) -> None:
    manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
    package = manifest["package"]
    if (package.get("name"), package.get("version"), package.get("license")) != (
            "multibase", VERSION, "MIT"):
        raise ValueError("unexpected multibase package identity/license")
    license_text = files.get("LICENSE", b"").decode("utf-8")
    if not license_text or "MIT License" not in license_text:
        raise ValueError("multibase upstream MIT license text missing")
    for name in CHANGE_FILES:
        if name not in files:
            raise ValueError("multibase recipe change target missing: " + name)


def _lines(name: str, data: bytes) -> list[bytes]:
    lines = data.splitlines(keepends=True)
    if b"".join(lines) != data:
        raise ValueError("multibase file lacks terminal newline: " + name)
    return lines


def _doc_shape(name: str, line: bytes) -> None:
    if (not line.startswith(EMOJI_DOC_PREFIX) or not line.endswith(EMOJI_DOC_SUFFIX)
            or not (DOC_MIN < len(line) < DOC_MAX)
            or line.count(b"Base256Emoji") != 1):
        raise ValueError("multibase emoji doc line shape mismatch in " + name)


def _unique(lines: list[bytes], name: str, needle: bytes) -> int:
    hits = [i for i, line in enumerate(lines) if line == needle]
    if len(hits) != 1:
        raise ValueError("unique multibase anchor mismatch in " + name)
    return hits[0]


def _removals(name: str, data: bytes) -> list[int]:
    """Return the sorted indices of the anchored base256emoji lines to delete."""
    lines = _lines(name, data)
    drop: list[int] = []
    if name == "Cargo.toml":
        block = [b"[dependencies.base256emoji]\n", b'version = "1.0.2"\n', b"\n"]
        start = _unique(lines, name, block[0])
        if lines[start:start + 3] != block:
            raise ValueError("multibase base256emoji dependency block mismatch")
        if lines[start + 3] != b"[dependencies.base45]\n":
            raise ValueError("multibase base256emoji block trailer mismatch")
        drop = [start, start + 1, start + 2]
    elif name == "Cargo.toml.orig":
        drop = [_unique(lines, name, b'base256emoji = "1.0.2"\n')]
    elif name == "src/error.rs":
        block = [
            b"impl From<base256emoji::DecodeError> for Error {\n",
            b"    fn from(_: base256emoji::DecodeError) -> Self {\n",
            b"        Self::InvalidBaseString\n",
            b"    }\n",
            b"}\n",
            b"\n",
        ]
        start = _unique(lines, name, block[0])
        if lines[start:start + 6] != block:
            raise ValueError("multibase base256emoji From impl block mismatch")
        drop = [start + i for i in range(6)]
    elif name == "src/base.rs":
        anchor = _unique(lines, name, b"    'U' => Base64UrlPad,\n")
        if not (anchor + 3 < len(lines)):
            raise ValueError("multibase base.rs emoji block out of range")
        _doc_shape(name, lines[anchor + 1])
        if lines[anchor + 2] != b"    '" + ROCKET + b"' => Base256Emoji,\n":
            raise ValueError("multibase base.rs emoji variant line mismatch")
        if lines[anchor + 3] != b"}\n":
            raise ValueError("multibase base.rs emoji block trailer mismatch")
        drop = [anchor + 1, anchor + 2]
    elif name == "src/impls.rs":
        drop.append(_unique(lines, name, b"use base256emoji::{Base, Emoji};\n"))
        docs = [i for i, line in enumerate(lines)
                if line.startswith(EMOJI_DOC_PREFIX) and line.endswith(EMOJI_DOC_SUFFIX)]
        if len(docs) != 1:
            raise ValueError("unique multibase emoji doc line mismatch in " + name)
        start = docs[0]
        tail = (
            b"#[derive(PartialEq, Eq, Clone, Copy, Debug)]\n",
            b"pub(crate) struct Base256Emoji;\n",
            b"\n",
            b"impl BaseCodec for Base256Emoji {\n",
            b"    fn encode<I: AsRef<[u8]>>(input: I) -> String {\n",
            b"        Emoji::encode(input.as_ref())\n",
            b"    }\n",
            b"\n",
            b"    fn decode<I: AsRef<str>>(input: I) -> Result<Vec<u8>> {\n",
            b"        Emoji::decode(input.as_ref()).map_err(|e| e.into())\n",
            b"    }\n",
            b"}\n",
            b"\n",
        )
        if start == 0 or lines[start - 1] != b"\n":
            raise ValueError("multibase impls.rs emoji doc predecessor mismatch")
        if start + 14 > len(lines) or tuple(lines[start + 1:start + 14]) != tail:
            raise ValueError("multibase impls.rs Base256Emoji block mismatch")
        if lines[start + 14] != b"derive_base_encoding! {\n":
            raise ValueError("multibase impls.rs emoji block trailer mismatch")
        drop.extend(range(start, start + 14))
    elif name == "tests/lib.rs":
        hits = [i for i, line in enumerate(lines)
                if line.startswith(b'        (Base256Emoji, "' + ROCKET)
                and line.endswith(b'"),\n')]
        if len(hits) != 3:
            raise ValueError("multibase tests/lib.rs emoji case count mismatch")
        drop = hits
    else:
        raise ValueError("multibase recipe has no anchor plan for " + name)
    return sorted(drop)


def _apply(original: dict[str, bytes]) -> dict[str, bytes]:
    """Deterministic anchored removal of every base256emoji reference."""
    changed = dict(original)
    for name in CHANGE_FILES:
        lines = _lines(name, original[name])
        drop = set(_removals(name, original[name]))
        changed[name] = b"".join(
            line for i, line in enumerate(lines) if i not in drop)
    manifest = tomllib.loads(changed["Cargo.toml"].decode("utf-8"))
    dependencies = manifest.get("dependencies", {})
    if "base256emoji" in dependencies:
        raise ValueError("multibase prepared Cargo.toml still lists base256emoji")
    for name in ("base-x", "base45", "data-encoding", "data-encoding-macro"):
        if name not in dependencies:
            raise ValueError("multibase prepared Cargo.toml lost dependency " + name)
    tree = dict(original)
    tree.update(changed)
    for name, data in tree.items():
        if name in INERT_FILES:
            continue
        if b"base256emoji" in data.lower():
            raise ValueError("multibase prepared tree still references base256emoji in " + name)
        if ROCKET in data:
            raise ValueError("multibase prepared tree still contains the emoji code char in " + name)
    return {name: data for name, data in changed.items() if original[name] != data}


def transform(files: dict[str, bytes]) -> dict[str, bytes]:
    validate_originals(files)
    changed = _apply(files)
    if reverse(files, changed) != files:
        raise ValueError("multibase reverse transformation failed")
    return changed


def reverse(original: dict[str, bytes], changed: dict[str, bytes]) -> dict[str, bytes]:
    """Rebuild the complete original tree from the prepared tree and compare."""
    if set(changed) != set(CHANGE_FILES):
        raise ValueError("multibase reverse requires exactly the recipe change files")
    expected = _apply(original)
    if changed != expected:
        raise ValueError("multibase prepared bytes differ beyond the exact transformation")
    recovered = dict(original)
    for name in CHANGE_FILES:
        original_lines = _lines(name, original[name])
        drop = sorted(_removals(name, original[name]))
        changed_lines = _lines(name, changed[name])
        keep = [line for i, line in enumerate(original_lines) if i not in set(drop)]
        if keep != changed_lines:
            raise ValueError("multibase changed content is not the anchored removal in " + name)
        rebuilt = list(changed_lines)
        for index in drop:
            rebuilt.insert(index, original_lines[index])
        recovered[name] = b"".join(rebuilt)
    if recovered != original:
        raise ValueError("multibase reverse reassembly does not match the originals")
    return recovered
