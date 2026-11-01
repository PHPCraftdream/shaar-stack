# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Static tests for the serde_bencode graph audit."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graph

REG = graph.REGISTRY
NROOT = Path("native-root").resolve()
BROOT = Path("prepared").resolve()
OLD_SERDE = "registry+https://github.com/rust-lang/crates.io-index#serde_bencode@0.2.4"
NEW_SERDE = "path+prepared#serde_bencode@0.2.4"
ROOT_ID = "path+native-root#n0-mainline@0.7.0"


def package(name, version, source=None, checksum=None, dependencies=None):
    p = {"name": name, "version": version, "dependencies": dependencies or []}
    if source is not None:
        p["source"] = source
    if checksum is not None:
        p["checksum"] = checksum
    return p


def metadata(path=False):
    serde_id = NEW_SERDE if path else OLD_SERDE
    serde_dep = {"name": "serde_bencode", "source": REG,
                 "req": "^0.2", "kind": None, "target": None,
                 "rename": None, "optional": False, "uses_default_features": True,
                 "features": []}
    base = {"edition": "2018", "rust_version": None, "license": "MIT",
            "features": {"default": []}, "dependencies": []}
    target = {**base, "id": serde_id, "name": "serde_bencode", "version": "0.2.4",
              "source": None if path else REG,
              "manifest_path": str((BROOT if path else Path("registry").resolve()) / "Cargo.toml")}
    root_package = {**base, "id": ROOT_ID, "name": "n0-mainline", "version": "0.7.0",
                    "source": None, "manifest_path": str(NROOT / "Cargo.toml"),
                    "dependencies": [serde_dep]}
    nodes = [
        {"id": serde_id, "dependencies": [], "deps": [], "features": ["default"]},
        {"id": ROOT_ID, "dependencies": [serde_id],
         "deps": [{"name": "serde_bencode", "pkg": serde_id,
                   "dep_kinds": [{"kind": None, "target": None}]}], "features": []},
    ]
    return {"packages": [target, root_package], "resolve": {"root": ROOT_ID, "nodes": nodes}}


OLD_LOCK = b'''version = 3\n\n[[package]]\nname = "serde_bencode"\nversion = "0.2.4"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e"\ndependencies = [\n "serde",\n]\n\n[[package]]\nname = "serde"\nversion = "1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "abc"\n'''


class GraphAuditTests(unittest.TestCase):
    def test_only_source_identity_substitution_passes(self):
        overlay = graph.make_lock_overlay(OLD_LOCK)
        self.assertTrue(graph.validate_lock(OLD_LOCK, overlay)["source_identity"])
        before, after = metadata(), metadata(True)
        result = graph.validate_metadata(before, after, NROOT, BROOT)
        self.assertTrue(result["source_identity"])
        self.assertNotEqual(before["packages"][0]["id"], after["packages"][0]["id"])

    def test_lock_overlay_rejects_wrong_checksum_or_path(self):
        wrong_checksum = OLD_LOCK.replace(graph.CHECKSUM.encode(), b"wrong")
        with self.assertRaises(ValueError):
            graph.make_lock_overlay(wrong_checksum)
        wrong_path = graph.make_lock_overlay(OLD_LOCK).replace(b'name = "serde"', b'name = "serdx"')
        with self.assertRaises(ValueError):
            graph.validate_lock(OLD_LOCK, wrong_path)

    def test_each_metadata_violation_is_rejected_independently(self):
        before = metadata()
        cases = (
            lambda x: x["packages"][0].update(manifest_path=str(NROOT / "Cargo.toml")),
            lambda x: x["packages"].remove(x["packages"][1]),
            lambda x: x["resolve"].update(root="wrong-root-id"),
            lambda x: x["resolve"]["nodes"][0].update(id="wrong-serde-id"),
            lambda x: x["packages"].append(copy.deepcopy(x["packages"][0])),
            lambda x: x["resolve"]["nodes"].append(copy.deepcopy(x["resolve"]["nodes"][0])),
            lambda x: x["resolve"]["nodes"][1]["deps"][0].update(name="different-name"),
            lambda x: x["packages"][1]["dependencies"][0].update(req="^0.3"),
            lambda x: x["packages"][0]["features"].update(extra=[]),
        )
        for mutate in cases:
            with self.subTest(mutate=mutate):
                changed = metadata(True)
                mutate(changed)
                with self.assertRaises(ValueError):
                    graph.validate_metadata(before, changed, NROOT, BROOT)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
