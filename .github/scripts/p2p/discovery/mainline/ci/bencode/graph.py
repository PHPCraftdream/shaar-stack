# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Audit an isolated lock/metadata substitution for serde_bencode."""
from __future__ import annotations

import copy
import json
import tomllib
from pathlib import Path

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e"
NAME = "serde_bencode"
VERSION = "0.2.4"


def _parsed(value):
    return tomllib.loads(bytes(value).decode("utf-8")) if isinstance(value, (bytes, bytearray)) else copy.deepcopy(value)


def _packages(lock):
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("lockfile packages missing")
    return packages


def _lock_expected(value):
    lock = _parsed(value)
    packages = _packages(lock)
    matches = [p for p in packages if p.get("name") == NAME]
    if len(matches) != 1:
        raise ValueError("lockfile serde_bencode package missing or duplicated")
    p = matches[0]
    if p.get("version") != VERSION or p.get("source") != REGISTRY or p.get("checksum") != CHECKSUM:
        raise ValueError("expected exact pinned serde_bencode package")
    p.pop("source")
    p.pop("checksum")
    return lock


def make_lock_overlay(original: bytes) -> bytes:
    """Remove only the pinned serde_bencode source and checksum fields."""
    old = _parsed(original)
    _lock_expected(old)
    text = bytes(original).decode("utf-8")
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == "[[package]]"]
    spans = []
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        if any(p.get("name") == NAME for p in tomllib.loads("".join(lines[start:end])).get("package", [])):
            spans.append((start, end))
    if len(spans) != 1:
        raise ValueError("serde_bencode stanza is not unique")
    start, end = spans[0]
    section = lines[start:end]
    kept = []
    removed = set()
    for line in section:
        stripped = line.strip()
        if stripped.startswith("source ="):
            if stripped != f'source = "{REGISTRY}"': raise ValueError("unexpected serde source")
            removed.add("source")
        elif stripped.startswith("checksum ="):
            if stripped != f'checksum = "{CHECKSUM}"': raise ValueError("unexpected serde checksum")
            removed.add("checksum")
        else: kept.append(line)
    if removed != {"source", "checksum"}: raise ValueError("expected exact source/checksum lines")
    result = "".join(lines[:start] + kept + lines[end:]).encode("utf-8")
    validate_lock(original, result)
    return result


def validate_lock(before, after):
    expected = _lock_expected(before)
    candidate = _parsed(after)
    if candidate != expected:
        raise ValueError("lock overlay changed fields beyond serde_bencode source/checksum")
    return {"source_identity": True, "version": True, "lock_edges": True}


def _metadata_packages(metadata):
    packages = metadata.get("packages")
    if not isinstance(packages, list): raise ValueError("metadata packages missing")
    return packages


def _unique(packages, key, label):
    result = {}
    for item in packages:
        value = item.get(key)
        if value in result: raise ValueError(f"duplicate {label}: {value}")
        result[value] = item
    return result


def _node_signature(metadata, mapping):
    nodes = (metadata.get("resolve") or {}).get("nodes")
    if not isinstance(nodes, list): raise ValueError("resolved metadata required")
    result = {}
    def norm(value): return mapping.get(value, value)
    for node in nodes:
        node_id = norm(node["id"])
        if node_id in result: raise ValueError(f"duplicate node ID: {node_id}")
        deps = [(dep.get("name"), norm(dep.get("pkg", "")), tuple(sorted(dep.get("dep_kinds", []), key=repr))) for dep in node.get("deps", [])]
        result[node_id] = (tuple(sorted(norm(x) for x in node.get("dependencies", []))), tuple(sorted(deps, key=repr)), tuple(sorted(node.get("features", []))) )
    return result


def validate_metadata(before, after, nroot: Path, broot: Path):
    nroot, broot = Path(nroot), Path(broot)
    oldp, newp = _metadata_packages(before), _metadata_packages(after)
    oldmap, newmap = _unique(oldp, "id", "package ID"), _unique(newp, "id", "package ID")
    old_targets = [p for p in oldp if p.get("name") == NAME and p.get("version") == VERSION]
    new_targets = [p for p in newp if p.get("name") == NAME and p.get("version") == VERSION]
    if len(old_targets) != 1 or old_targets[0].get("source") != REGISTRY or len(new_targets) != 1:
        raise ValueError("metadata serde_bencode identity missing or duplicated")
    a, b = old_targets[0], new_targets[0]
    if b.get("source") is not None or Path(b.get("manifest_path", "")).resolve() != (broot / "Cargo.toml").resolve():
        raise ValueError("overlay serde_bencode manifest must be exact broot Cargo.toml")
    if sum(p.get("name") == NAME for p in oldp) != 1 or sum(p.get("name") == NAME for p in newp) != 1:
        raise ValueError("metadata serde_bencode package duplicated")

    old_roots = [p for p in oldp if p.get("name") == "n0-mainline" and p.get("version") == "0.7.0"]
    new_roots = [p for p in newp if p.get("name") == "n0-mainline" and p.get("version") == "0.7.0"]
    if len(old_roots) != 1 or len(new_roots) != 1:
        raise ValueError("metadata n0-mainline root missing or duplicated")
    old_root, new_root = old_roots[0], new_roots[0]
    if (old_root.get("source") is not None or new_root.get("source") is not None
            or Path(old_root.get("manifest_path", "")).resolve() != (nroot / "Cargo.toml").resolve()
            or Path(new_root.get("manifest_path", "")).resolve() != (nroot / "Cargo.toml").resolve()
            or old_root.get("id") != new_root.get("id")
            or before.get("resolve", {}).get("root") != old_root.get("id")
            or after.get("resolve", {}).get("root") != new_root.get("id")):
        raise ValueError("metadata n0-mainline root identity changed")

    if before.get("resolve", {}).get("root") != after.get("resolve", {}).get("root"):
        raise ValueError("metadata root ID changed")
    mapping = {a["id"]: b["id"]}
    expected_ids = {mapping.get(i, i) for i in oldmap}
    if expected_ids != set(newmap):
        raise ValueError("metadata package IDs changed")
    fields = ("name", "version", "edition", "rust_version", "license", "features", "dependencies")
    def identity(package): return {field: package.get(field) for field in fields}
    for old_id, package in oldmap.items():
        new_id = mapping.get(old_id, old_id)
        candidate = newmap[new_id]
        if identity(package) != identity(candidate):
            raise ValueError("metadata package declarations changed")
        if old_id != a["id"] and (
                candidate.get("id") != old_id
                or candidate.get("source") != package.get("source")
                or candidate.get("manifest_path") != package.get("manifest_path")):
            raise ValueError("non-serde package identity changed")
    if len(oldp) != len(newp): raise ValueError("metadata package count changed")
    if _node_signature(before, mapping) != _node_signature(after, {}):
        raise ValueError("resolved dependency edges or features changed")
    return {"source_identity": True, "version": True, "edges": True, "features": True}


def validate_graph(lock_before, lock_after, metadata_before, metadata_after, nroot: Path, broot: Path):
    receipt = validate_lock(lock_before, lock_after)
    receipt.update(validate_metadata(metadata_before, metadata_after, nroot, broot))
    return receipt
