# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare  # noqa: E402

ARCHIVE = Path(sys.argv[1])


class YggPreparationChecks(unittest.TestCase):
    def test_archive_identity_and_size_bounds(self):
        data = ARCHIVE.read_bytes()
        self.assertLessEqual(len(data), prepare.MAX_ARCHIVE)
        self.assertEqual(hashlib.sha256(data).hexdigest(), prepare.ARCHIVE_SHA256)

    def test_manifest_cross_checks_and_upstream_identity(self):
        manifest = prepare.load_manifest()
        self.assertEqual(len(manifest), prepare.MANIFEST_COUNT)
        files, recorded = prepare.archive_files(ARCHIVE)
        prepare.verify_manifest(files, recorded, manifest)
        prepare.validate_originals(files)
        self.assertIn("crates/yggdrasil/src/core.rs", files)
        self.assertIn("Cargo.toml", recorded)
        self.assertIn("Cargo.lock", recorded)
        self.assertNotIn("Cargo.toml", files)
        self.assertNotIn("Cargo.lock", files)

    def test_extraction_scope_is_license_and_two_crates_only(self):
        manifest = prepare.load_manifest()
        for name in manifest:
            self.assertIsNotNone(prepare.scope(name), name)
        top_names = {name for name in manifest if "/" not in name}
        self.assertEqual(top_names, {"LICENSE", "Cargo.toml", "Cargo.lock"})
        prefixes = {tuple(name.split("/")[:2]) for name in manifest if "/" in name}
        self.assertEqual(prefixes, {("crates", "ironwood"), ("crates", "yggdrasil")})

    def test_prepare_roundtrip_receipt_and_recorded_only_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "ygg"
            root = prepare.prepare(ARCHIVE, destination)
            self.assertEqual(root.name, prepare.ARCHIVE_TOP)
            self.assertFalse((destination / "Cargo.toml").exists())
            self.assertFalse((destination / "Cargo.lock").exists())
            self.assertFalse((root / "Cargo.toml").exists())
            self.assertTrue((root / "LICENSE").is_file())
            self.assertTrue((root / "crates/yggdrasil/Cargo.toml").is_file())
            self.assertTrue((root / "crates/ironwood/Cargo.toml").is_file())
            files = prepare.verify(root)
            self.assertEqual(sorted(files),
                             sorted(name for name in prepare.load_manifest()
                                    if prepare.scope(name) == "extract"))
            target = root / "crates/yggdrasil/src/core.rs"
            target.write_bytes(target.read_bytes() + b"drift")
            with self.assertRaisesRegex(ValueError, "prepared source content hash"):
                prepare.verify(root)

    def test_tampered_archive_is_rejected(self):
        data = ARCHIVE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "wrong.tar.gz"
            wrong.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))
            with self.assertRaisesRegex(ValueError, "archive SHA-256 mismatch"):
                prepare.archive_files(wrong)

    def test_unsafe_members_are_detected(self):
        class Member:
            def __init__(self, name, isfile=True, isdir=False):
                self.name = name
                self.isfile = lambda: isfile
                self.isdir = lambda: isdir
                self.size = 0

        deep = prepare.ARCHIVE_TOP + "/" + "/".join(["deep"] * 17)
        members = (Member("/abs/child"), Member("../escape"), Member("./dot"),
                   Member("back\\slash"), Member("C:/drive"), Member("colon:part"),
                   Member("wrong-top/child"), Member(deep),
                   Member(prepare.ARCHIVE_TOP + "/link", isfile=False, isdir=False))
        for member in members:
            with self.subTest(member=member.name):
                self.assertIsNotNone(prepare._member_fault(member))
        self.assertIsNone(prepare._member_fault(Member(prepare.ARCHIVE_TOP + "/LICENSE")))
        self.assertIsNone(prepare._member_fault(Member(prepare.ARCHIVE_TOP + "/crates")))

    def test_out_of_scope_names_have_no_scope(self):
        self.assertIsNone(prepare.scope("README.md"))
        self.assertIsNone(prepare.scope("crates/other/Cargo.toml"))
        self.assertIsNone(prepare.scope("src/main.rs"))
        self.assertEqual(prepare.scope("LICENSE"), "extract")
        self.assertEqual(prepare.scope("Cargo.toml"), "record")
        self.assertEqual(prepare.scope("crates/yggdrasil/src/lib.rs"), "extract")
        self.assertEqual(prepare.scope("crates/ironwood/Cargo.toml"), "extract")


class ProductWorkspaceContract(unittest.TestCase):
    """The native-graph workspace audit accepts the Yggdrasil exclusions only exactly."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "ygg_native_graph", Path(__file__).resolve().parents[1] / "native-graph/graph.py")
        self.graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.graph)
        self.adapter = self.graph.GENERATED_PATHS["iroh-mainline-address-lookup"]

    def manifest(self, exclusions):
        return {"workspace": {"exclude": exclusions, "members": ["crates/shaar"]}}

    def test_adapter_alone_or_with_the_exact_yggdrasil_paths_is_accepted(self):
        self.graph.audit_product_workspace(self.manifest([self.adapter]))
        self.graph.audit_product_workspace(self.manifest([self.adapter, *self.graph.YGG_EXCLUDES]))
        self.assertEqual(self.graph.YGG_EXCLUDES[1], "target/ygg/" + prepare.ARCHIVE_TOP)

    def test_partial_extra_reordered_or_unrelated_exclusions_are_rejected(self):
        ygg_core, ygg_source = self.graph.YGG_EXCLUDES
        for exclusions in ([ygg_core, ygg_source], [self.adapter, ygg_core],
                           [self.adapter, ygg_source, ygg_core],
                           [self.adapter, ygg_core, ygg_source, "crates/other"],
                           [self.adapter, ygg_core, "target/ygg"], []):
            with self.subTest(exclusions=exclusions), self.assertRaises(ValueError):
                self.graph.audit_product_workspace(self.manifest(exclusions))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
