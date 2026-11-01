# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate the archive-locked publication graph baseline."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tomllib

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
SIMPLE_CHECKSUM = "2b6f884fa9a8d48101774bfbd3aeb81e968dd22cffd19a372da69f183db22c1a"


def lock_identities(lock: dict) -> dict[tuple[str, str], dict]:
    result = {}
    for package in lock.get("package", []):
        key = package["name"], package["version"]
        if key in result:
            raise ValueError("duplicate name/version package identity in archive lock")
        result[key] = package
    return result


def rewrite_lock(lock_bytes: bytes, simple_root: str) -> bytes:
    text = lock_bytes.decode("utf-8")
    lock = tomllib.loads(text)
    if "version" not in lock or not lock.get("package"):
        raise ValueError("archive lock top-level format metadata missing")
    matches = [p for p in lock["package"] if (p.get("name"), p.get("version")) == ("simple-dns", "0.12.0")]
    if len(matches) != 1 or matches[0].get("source") != REGISTRY or matches[0].get("checksum") != SIMPLE_CHECKSUM:
        raise ValueError("archive lock simple-dns identity/checksum differs from pinned source")
    for package in lock["package"]:
        if any(edge.startswith("simple-dns ") or edge.startswith("simple-dns@")
               for edge in package.get("dependencies", [])):
            raise ValueError("source-qualified simple-dns lock edges are unsupported")
    stanza = f'[[package]]\nname = "simple-dns"\nversion = "0.12.0"\nsource = "{REGISTRY}"\nchecksum = "{SIMPLE_CHECKSUM}"'
    if text.count(stanza) != 1:
        raise ValueError("simple-dns lock stanza shape unsupported; refusing rewrite")
    rewritten = text.replace(stanza, '[[package]]\nname = "simple-dns"\nversion = "0.12.0"', 1).encode("utf-8")
    validate_lock_rewrite(lock_bytes, rewritten, simple_root)
    return rewritten


def validate_lock_rewrite(before: bytes, after: bytes, simple_root: str) -> dict:
    old_lock, new_lock = tomllib.loads(before.decode("utf-8")), tomllib.loads(after.decode("utf-8"))
    if {k: v for k, v in old_lock.items() if k != "package"} != {k: v for k, v in new_lock.items() if k != "package"}:
        raise ValueError("lock rewrite changed top-level metadata")
    old, new = lock_identities(old_lock), lock_identities(new_lock)
    old_simple = old.get(("simple-dns", "0.12.0"), {})
    new_simple = new.get(("simple-dns", "0.12.0"), {})
    if (old_simple.get("source") != REGISTRY or old_simple.get("checksum") != SIMPLE_CHECKSUM
            or "source" in new_simple or "checksum" in new_simple):
        raise ValueError("only pinned simple-dns source/checksum may be removed")
    normalized_old = {}
    for key, package in old.items():
        if any(edge.startswith("simple-dns ") or edge.startswith("simple-dns@")
               for edge in package.get("dependencies", [])):
            raise ValueError("source-qualified simple-dns lock edges are unsupported")
        normalized_old[key] = {k: v for k, v in package.items()
                               if not (key == ("simple-dns", "0.12.0") and k in {"source", "checksum"})}
    if normalized_old != new:
        raise ValueError("lock rewrite changed package identity/version/edge/fields")
    return {"package_count": len(old),
            "dependency_edge_count": sum(len(p.get("dependencies", [])) for p in old_lock["package"]),
            "archive_lock_sha256": hashlib.sha256(before).hexdigest(),
            "candidate_lock_sha256": hashlib.sha256(after).hexdigest(),
            "simple_dns_source": simple_root}


def normalize_metadata(metadata: dict, simple_root: str) -> dict:
    nodes = metadata.get("resolve", {}).get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("full resolved Cargo metadata required")
    packages = metadata.get("packages", [])
    by_id = {package["id"]: package for package in packages}
    if len(by_id) != len(packages):
        raise ValueError("duplicate metadata package id")
    if len({(p["name"], p["version"]) for p in packages}) != len(packages):
        raise ValueError("duplicate package name/version in resolved metadata")
    simple = [p for p in packages if (p["name"], p["version"]) == ("simple-dns", "0.12.0")]
    if len(simple) != 1:
        raise ValueError("expected exactly one resolved simple-dns 0.12.0")
    simple = simple[0]
    if simple.get("source") not in (REGISTRY, None):
        raise ValueError("unexpected simple-dns source")
    if simple.get("source") is None and Path(simple["manifest_path"]).resolve() != (Path(simple_root) / "Cargo.toml").resolve():
        raise ValueError("candidate simple-dns manifest path mismatch")
    result = {}
    seen_ids = set()
    for node in nodes:
        node_id = node["id"]
        if node_id in seen_ids:
            raise ValueError("duplicate resolved node id")
        seen_ids.add(node_id)
        package = by_id.get(node_id)
        if package is None:
            raise ValueError("resolved node has no package metadata")
        key = package["name"], package["version"]
        if key in result:
            raise ValueError("multiple resolved package identities for name/version")
        name, version = key
        source = package.get("source")
        if key == ("simple-dns", "0.12.0"):
            source = "simple-dns-source-substitution"
        elif key == ("iroh-dns", "1.3.0"):
            if source is not None or Path(package["manifest_path"]).resolve() != Path(metadata["workspace_root"], "Cargo.toml").resolve():
                raise ValueError("iroh-dns root package identity/manifest mismatch")
        elif source is None:
            raise ValueError("unexpected path package identity: " + name)
        deps = []
        for dep in node.get("deps", []):
            target = by_id.get(dep["pkg"])
            if target is None:
                raise ValueError("dependency target missing")
            target_source = target.get("source")
            if (target["name"], target["version"]) == ("simple-dns", "0.12.0"):
                target_source = "simple-dns-source-substitution"
            kinds = tuple(sorted((item.get("kind") or "normal", item.get("target") or "")
                                 for item in dep.get("dep_kinds", [])))
            deps.append((dep.get("name"), target["name"], target["version"], target_source, kinds))
        result[key] = {"source": source, "features": sorted(node.get("features", [])),
                       "dependencies": sorted(deps, key=repr)}
    if seen_ids != set(by_id):
        raise ValueError("resolved metadata contains unrepresented packages")
    return result


def compare_metadata(baseline: dict, candidate: dict, simple_root: str) -> dict:
    baseline_simple = next((p for p in baseline.get("packages", [])
                            if (p.get("name"), p.get("version")) == ("simple-dns", "0.12.0")), {})
    candidate_simple = next((p for p in candidate.get("packages", [])
                             if (p.get("name"), p.get("version")) == ("simple-dns", "0.12.0")), {})
    if baseline_simple.get("source") != REGISTRY or candidate_simple.get("source") is not None:
        raise ValueError("metadata must show registry baseline and path candidate simple-dns")
    baseline_root = baseline.get("resolve", {}).get("root")
    candidate_root = candidate.get("resolve", {}).get("root")
    if baseline_root != candidate_root or not baseline_root:
        raise ValueError("baseline/candidate iroh-dns root identity differs")
    roots = [(metadata, next((p for p in metadata.get("packages", []) if p.get("id") == metadata["resolve"]["root"]), {}))
             for metadata in (baseline, candidate)]
    if any((package.get("name"), package.get("version"), package.get("source")) != ("iroh-dns", "1.3.0", None)
           for _, package in roots):
        raise ValueError("baseline/candidate root must be iroh-dns 1.3.0")
    if Path(roots[0][1].get("manifest_path", "")).resolve() != Path(roots[1][1].get("manifest_path", "")).resolve():
        raise ValueError("baseline/candidate iroh-dns root manifests differ")
    left = normalize_metadata(baseline, simple_root)
    right = normalize_metadata(candidate, simple_root)
    if left != right:
        raise ValueError("baseline/candidate graph, features, sources, or aliases differ")
    return {"resolved_package_count": len(left), "graph": [
        {"name": name, "version": version, **details}
        for (name, version), details in sorted(left.items())]}
