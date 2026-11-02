# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Static tests for the serde_bencode graph audit."""
from __future__ import annotations

import copy
import json
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
    def test_tokio_build_feature_artifacts_bind_both_builds(self):
        package_id = "registry+https://github.com/rust-lang/crates.io-index#tokio@1.53.1"
        metadata_after = {"packages": [{
            "id": package_id,
            "name": "tokio",
            "version": "1.53.1",
            "source": graph.REGISTRY,
            "targets": [{
                "name": "tokio",
                "kind": ["lib"],
                "src_path": str(Path("registry/tokio/src/lib.rs").resolve()),
            }],
        }], "resolve": {"nodes": [{"id": package_id}]}}
        normal = {
            "reason": "compiler-artifact",
            "package_id": package_id,
            "target": {"name": "tokio", "kind": ["lib"], "src_path": metadata_after["packages"][0]["targets"][0]["src_path"]},
            "profile": {"test": False, "opt_level": "0"},
            "features": ["rt", "sync", "time"],
        }
        test = copy.deepcopy(normal)
        test["features"].extend(["rt-multi-thread", "test-util"])

        receipt = graph.validate_tokio_build_features(
            json.dumps(normal), json.dumps(test), metadata_after
        )

        self.assertEqual(receipt["package_id"], package_id)
        self.assertEqual(receipt["version"], "1.53.1")
        self.assertEqual(receipt["source"], graph.REGISTRY)
        self.assertEqual(receipt["normal_features"], normal["features"])
        self.assertEqual(receipt["test_features"], test["features"])
        self.assertEqual(receipt["normal_profile"], normal["profile"])
        self.assertEqual(receipt["test_profile"], test["profile"])

        def verify(label, normal_case=None, test_case=None, metadata_case=None):
            changed_normal = copy.deepcopy(normal)
            changed_test = copy.deepcopy(test)
            changed_metadata = copy.deepcopy(metadata_after)
            if normal_case:
                normal_case(changed_normal)
            if test_case:
                test_case(changed_test)
            if metadata_case:
                metadata_case(changed_metadata)
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    graph.validate_tokio_build_features(
                        json.dumps(changed_normal), json.dumps(changed_test), changed_metadata
                    )

        verify("missing normal", lambda x: x.update(reason="build-finished"))
        verify("missing test", test_case=lambda x: x.update(reason="build-finished"))
        verify("empty normal", lambda x: x.update(features=[]))
        verify("empty test", test_case=lambda x: x.update(features=[]))
        with self.subTest(case="duplicate normal"):
            with self.assertRaises(ValueError):
                graph.validate_tokio_build_features(
                    json.dumps(normal) + "\n" + json.dumps(normal),
                    json.dumps(test),
                    metadata_after,
                )
        with self.subTest(case="duplicate test"):
            with self.assertRaises(ValueError):
                graph.validate_tokio_build_features(
                    json.dumps(normal),
                    json.dumps(test) + "\n" + json.dumps(test),
                    metadata_after,
                )
        with self.subTest(case="malformed JSON"):
            with self.assertRaises(ValueError):
                graph.validate_tokio_build_features("{", json.dumps(test), metadata_after)

        verify("wrong package ID", lambda x: x.update(package_id="wrong"))
        verify("wrong target source", lambda x: x["target"].update(src_path="wrong"))
        verify("wrong target kind", lambda x: x["target"].update(kind=["bin"]))
        verify("wrong target name", lambda x: x["target"].update(name="wrong"))
        verify("test profile true", test_case=lambda x: x["profile"].update(test=True))
        verify("features None", lambda x: x.update(features=None))
        verify("duplicate features", lambda x: x["features"].append(x["features"][0]))
        verify("normal includes test-util", lambda x: x["features"].append("test-util"))
        verify("test missing test-util", test_case=lambda x: x["features"].remove("test-util"))
        verify("test missing rt-multi-thread", test_case=lambda x: x["features"].remove("rt-multi-thread"))
        verify("test extra feature", test_case=lambda x: x["features"].append("extra"))
        verify("metadata wrong version", metadata_case=lambda x: x["packages"][0].update(version="1.0"))
        verify("metadata wrong source", metadata_case=lambda x: x["packages"][0].update(source="wrong"))
        verify("metadata duplicate tokio", metadata_case=lambda x: x["packages"].append(copy.deepcopy(x["packages"][0])))
        verify("metadata duplicate target", metadata_case=lambda x: x["packages"][0]["targets"].append(copy.deepcopy(x["packages"][0]["targets"][0])))
        verify("metadata missing resolve", metadata_case=lambda x: x.pop("resolve"))
        verify("metadata missing Tokio node", metadata_case=lambda x: x["resolve"].update(nodes=[]))
        verify("metadata duplicate Tokio node", metadata_case=lambda x: x["resolve"]["nodes"].append(copy.deepcopy(x["resolve"]["nodes"][0])))
        verify("metadata wrong Tokio node ID", metadata_case=lambda x: x["resolve"]["nodes"][0].update(id="wrong"))

    def test_mainline_tokio_test_util_is_the_only_prepared_change(self):
        original = {
            "dependencies": {
                "tokio": {
                    "version": "1.39",
                    "features": ["sync", "net", "time", "rt", "macros"],
                    "default-features": False,
                }
            },
            "dev-dependencies": {
                "tokio": {"version": "1", "features": ["rt-multi-thread"]}
            },
        }
        prepared = copy.deepcopy(original)
        prepared["dev-dependencies"]["tokio"]["features"].append("test-util")

        self.assertEqual(
            graph.validate_mainline_test_features(original, prepared),
            {"normal_tokio_features_unchanged": True, "dev_tokio_test_util_only": True},
        )

        cases = (
            ("normal test-util leak", lambda x: x["dependencies"]["tokio"]["features"].append("test-util")),
            ("missing dev feature", lambda x: x["dev-dependencies"]["tokio"].update(features=[])),
            ("extra dev feature", lambda x: x["dev-dependencies"]["tokio"]["features"].append("time")),
            ("duplicate dev feature", lambda x: x["dev-dependencies"]["tokio"]["features"].append("test-util")),
            ("normal version changed", lambda x: x["dependencies"]["tokio"].update(version="1.40")),
            ("new dependency", lambda x: x["dependencies"].update(serde="1")),
            ("dev version changed", lambda x: x["dev-dependencies"]["tokio"].update(version="2")),
            ("dev default-features disabled", lambda x: x["dev-dependencies"]["tokio"].update(**{"default-features": False})),
            ("dev tokio removed", lambda x: x["dev-dependencies"].pop("tokio")),
            ("normal tokio removed", lambda x: x["dependencies"].pop("tokio")),
            ("root feature aliases tokio test-util", lambda x: x.update(features={"leak": ["tokio/test-util"]})),
        )
        for label, mutate in cases:
            with self.subTest(case=label):
                changed = copy.deepcopy(prepared)
                mutate(changed)
                with self.assertRaises(ValueError):
                    graph.validate_mainline_test_features(original, changed)

        wrong_original = copy.deepcopy(original)
        wrong_original["dev-dependencies"]["tokio"]["features"] = ["rt"]
        with self.assertRaises(ValueError):
            graph.validate_mainline_test_features(wrong_original, prepared)

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
