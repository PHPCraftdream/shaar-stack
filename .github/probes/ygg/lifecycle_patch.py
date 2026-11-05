# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reviewed lifecycle hunks for the pinned yggdrasil crate (leaf 53.2).

The pinned archive is untrusted data: hunks are exact byte replacements applied
only after the content manifest verified the original bytes. Each patch module
under patches/ pins its original per-file SHA-256 (from ygg-manifest.json) and
its patched SHA-256. Until the coordinator pins the patched hashes, the
placeholder value "UNPINNED" makes every preparation run fail closed with an
error that prints the computed patched hashes to pin.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNPINNED = "UNPINNED"

# (manifest path, patch module stem) in application order.
PATCH_MODULES = (
    ("crates/yggdrasil/src/core.rs", "core"),
    ("crates/yggdrasil/src/links.rs", "links"),
    ("crates/yggdrasil/src/proto.rs", "proto"),
    ("crates/ironwood/src/encrypted/mod.rs", "ironwood_encrypted"),
)


def _load(module_stem: str):
    path = HERE / "patches" / (module_stem + ".py")
    spec = importlib.util.spec_from_file_location("ygg_lifecycle_" + module_stem, path)
    if spec is None or spec.loader is None:
        raise ValueError("lifecycle patch module missing: " + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module_stem(name: str) -> str:
    for candidate, stem in PATCH_MODULES:
        if candidate == name:
            return stem
    raise ValueError("no lifecycle patch module for: " + name)


def changed_files() -> tuple[str, ...]:
    return tuple(name for name, _ in PATCH_MODULES)


def _as_bytes(block) -> bytes:
    if isinstance(block, bytes):
        return block
    return b"".join(block)


def hunks(name: str) -> tuple[tuple[bytes, bytes], ...]:
    normalized = []
    for hunk in _load(_module_stem(name)).HUNKS:
        old, new = (hunk["old"], hunk["new"]) if isinstance(hunk, dict) else hunk
        normalized.append((_as_bytes(old), _as_bytes(new)))
    return tuple(normalized)


def original_pins() -> dict[str, str]:
    return {name: _load(stem).ORIGINAL_SHA256 for name, stem in PATCH_MODULES}


def patched_pins() -> dict[str, str]:
    return {name: _load(stem).PATCHED_SHA256 for name, stem in PATCH_MODULES}


def apply(files: dict[str, bytes]) -> dict[str, bytes]:
    """Return a copy of `files` with the lifecycle hunks applied, failing closed."""
    patched = dict(files)
    for name in changed_files():
        data = patched[name]
        for index, (old, new) in enumerate(hunks(name)):
            found = data.count(old)
            if found == 0:
                raise ValueError(f"lifecycle hunk {index} old text not found in {name}")
            if found > 1:
                raise ValueError(f"lifecycle hunk {index} old text is ambiguous in {name}: "
                                 f"{found} occurrences")
            data = data.replace(old, new, 1)
        patched[name] = data
    return patched


def pin_fault(computed: dict[str, str]) -> str | None:
    """Fail closed unless every computed patched hash matches its pin."""
    pins = patched_pins()
    unpinned = [name for name in sorted(computed) if pins.get(name) == UNPINNED]
    if unpinned:
        listing = ", ".join(f"{name}={computed[name]}" for name in unpinned)
        return ("patched hashes are unpinned; pin them in .github/probes/ygg/patches/ "
                "after reviewing this controlled computation: " + listing)
    mismatched = [name for name in sorted(computed) if pins[name] != computed[name]]
    if mismatched:
        listing = ", ".join(f"{name} computed={computed[name]} pinned={pins[name]}"
                            for name in mismatched)
        return "patched content hash differs from the pinned hash: " + listing
    return None
