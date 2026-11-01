# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Archive-bound source recipe integrity specifications."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from execution import ci as fixture_ci
import graph
import prepare
import runner


class RecipeIntegrity(unittest.TestCase):
    def test_ci_staging_failure_preserves_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "exported-evidence"
            arguments = ["ci.py", "--archive", str(root / "unread.crate"),
                         "--simple-dns-archive", str(root / "simple.crate"),
                         "--evidence", str(evidence)]
            with (
                patch.object(sys, "argv", arguments),
                patch.dict(os.environ, {"RUNNER_TEMP": str(root)}),
                patch.object(prepare, "archive_files", side_effect=ValueError("archive failure probe")),
            ):
                self.assertEqual(fixture_ci.main(), 1)
            receipt = json.loads((evidence / "receipt.json").read_text())
            self.assertEqual(receipt, {"status": "failed", "error": "archive failure probe"})

    def test_runner_path_resolution_and_output_path_guard(self):
        repo = runner.repository_root()
        self.assertTrue((repo / "CLAUDE.md").is_file())
        self.assertTrue((repo / "Cargo.toml").is_file())
        self.assertEqual(Path(runner.__file__).resolve(),
                         (repo / ".github/scripts/p2p/discovery/mainline/ci/publication/runner.py").resolve())
        helper = runner.simple_dns_helper().resolve()
        self.assertTrue(helper.is_file())
        self.assertEqual(helper, (repo / ".github/scripts/p2p/discovery/simple_dns/prepare.py").resolve())

        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory)
            self.assertFalse(external.resolve().is_relative_to(repo))
            accepted = runner.validate_output_paths(external / "stage", external / "receipt.json")
            self.assertEqual(accepted, ((external / "receipt.json").resolve(), (external / "stage").resolve()))
            prefix_sibling = repo.parent / (repo.name + "-publication-path-probe")
            runner.validate_output_paths(prefix_sibling / "stage", prefix_sibling / "receipt.json")
            for destination, receipt in (
                (repo / "target" / "stage", external / "receipt.json"),
                (external / "stage", repo / "target" / "receipt.json"),
                (repo, external / "receipt.json"),
                (external / "stage", repo),
                (external / "shared", external / "shared"),
                (external / "parent", external / "parent" / "receipt.json"),
                (external / "parent" / "stage", external / "parent"),
            ):
                with self.subTest(destination=destination, receipt=receipt):
                    with self.assertRaises(ValueError):
                        runner.validate_output_paths(destination, receipt)

    def test_graph_lock_and_metadata_mutations_are_rejected(self):
        raw = ("version = 3\n\n[[package]]\nname = \"simple-dns\"\nversion = \"0.12.0\"\n"
               f"source = \"{graph.REGISTRY}\"\nchecksum = \"{graph.SIMPLE_CHECKSUM}\"\ndependencies = [\"dep 1.0.0\"]\n\n"
               f"[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\nsource = \"{graph.REGISTRY}\"\nchecksum = \"{'a' * 64}\"\n")
        candidate = graph.rewrite_lock(raw.encode(), "simple")
        graph.validate_lock_rewrite(raw.encode(), candidate, "simple")
        mutations = (
            candidate.replace(b"dep 1.0.0", b"dep 2.0.0"),
            candidate.replace(b"version = 3", b"version = 4"),
            candidate.replace(b'checksum = "' + b"a" * 64, b'checksum = "' + b"b" * 64),
            candidate.replace(b'version = "1.0.0"', b'version = "1.0.1"'),
            candidate.replace(b'source = "' + graph.REGISTRY.encode(), b'source = "registry+altered'),
            candidate + b"\n[[package]]\nname = \"extra\"\nversion = \"1\"\n",
        )
        for bad in mutations:
            with self.assertRaises(ValueError):
                graph.validate_lock_rewrite(raw.encode(), bad, "simple")
        root_path = str(Path("workspace/Cargo.toml").resolve())
        simple_path = str(Path("simple/Cargo.toml").resolve())
        baseline = {"workspace_root": "workspace", "packages": [
            {"id": "root", "name": "iroh-dns", "version": "1.3.0", "source": None, "manifest_path": root_path},
            {"id": "dns", "name": "simple-dns", "version": "0.12.0", "source": graph.REGISTRY, "manifest_path": "registry/Cargo.toml"},
            {"id": "dep", "name": "dep", "version": "1.0.0", "source": graph.REGISTRY, "manifest_path": "registry/dep/Cargo.toml"}],
            "resolve": {"root": "root", "nodes": [
                {"id": "root", "features": [], "deps": [{"name": "alias", "pkg": "dns", "dep_kinds": [{"kind": None, "target": None}]}]},
                {"id": "dns", "features": ["std"], "deps": [{"name": "dep", "pkg": "dep", "dep_kinds": [{"kind": None, "target": None}]}]},
                {"id": "dep", "features": [], "deps": []}]}}
        good = json.loads(json.dumps(baseline))
        good["packages"][1]["source"] = None
        good["packages"][1]["manifest_path"] = simple_path
        graph.compare_metadata(baseline, good, "simple")
        checks = (
            lambda value: value["resolve"]["nodes"][0]["deps"][0].update(name="different-alias"),
            lambda value: value["resolve"]["nodes"][1].update(features=[]),
            lambda value: value["packages"][2].update(source="registry+other"),
            lambda value: value["packages"][1].update(manifest_path="wrong/Cargo.toml"),
            lambda value: value["packages"][1].update(version="0.12.1"),
            lambda value: value["packages"][1].update(source="registry+unexpected"),
            lambda value: value["packages"][0].update(manifest_path="wrong/Cargo.toml"),
        )
        for mutate in checks:
            changed = json.loads(json.dumps(good))
            mutate(changed)
            with self.assertRaises(ValueError):
                graph.compare_metadata(baseline, changed, "simple")
        duplicate = json.loads(json.dumps(good))
        duplicate["resolve"]["nodes"].append(dict(duplicate["resolve"]["nodes"][0]))
        with self.assertRaises(ValueError):
            graph.compare_metadata(baseline, duplicate, "simple")

    def test_archive_recipe_and_receipt_are_recomputed(self):
        archive_value = os.environ.get("IROH_DNS_ARCHIVE")
        if not archive_value:
            self.fail("IROH_DNS_ARCHIVE must name the pinned archive")
        archive = Path(archive_value)
        original = prepare.archive_files(archive)
        prepare.validate(original)
        self.assertNotIn("LICENSE-MIT", original)
        self.assertNotIn("LICENSE-APACHE", original)
        invalid_license = dict(original)
        invalid_license["Cargo.toml"] = original["Cargo.toml"].replace(
            b'license = "MIT OR Apache-2.0"', b'license = "unverified"', 1)
        self.assertNotEqual(invalid_license["Cargo.toml"], original["Cargo.toml"])
        with self.assertRaises(ValueError):
            prepare.validate(invalid_license)
        changed = prepare.transform(original)
        prepare.reverse(original, changed)
        receipt = {"archive_sha256": prepare.ARCHIVE_SHA256, "recipe": prepare.recipe(),
                   "source_sha256": {n: prepare.sha(b) for n, b in sorted(original.items())},
                   "prepared_sha256": {n: prepare.sha(b) for n, b in sorted({**original, **changed}.items())}}
        prepare.verify_prepared(original, changed, archive, receipt)
        forged_changed = dict(changed)
        key = next(iter(changed))
        forged_changed[key] += b"forged"
        forged_receipt = dict(receipt)
        forged_receipt["prepared_sha256"] = dict(receipt["prepared_sha256"], **{key: prepare.sha(forged_changed[key])})
        with self.assertRaises(ValueError):
            prepare.verify_prepared(original, forged_changed, archive, forged_receipt)
        altered = dict(original)
        key = next(iter(original))
        altered[key] += b"forged"
        forged_receipt = dict(receipt)
        forged_receipt["source_sha256"] = dict(receipt["source_sha256"], **{key: prepare.sha(altered[key])})
        with self.assertRaises(ValueError):
            prepare.verify_prepared(altered, changed, archive, forged_receipt)
        for bad_source in ({**original, "extra": b"x"}, {k: v for k, v in list(original.items())[1:]}):
            with self.assertRaises(ValueError):
                prepare.verify_prepared(bad_source, changed, archive, receipt)
        with tempfile.TemporaryDirectory() as directory:
            wrong_archive = Path(directory) / "wrong-iroh-dns.crate"
            wrong_archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaises(ValueError):
                prepare.verify_prepared(original, changed, wrong_archive, receipt)
        with self.assertRaises(ValueError):
            prepare.reverse(original, {})
        drifted = dict(original)
        drifted["src/pkarr.rs"] = drifted["src/pkarr.rs"].replace(b"Timestamp::now()", b"Timestamp::now_drifted()", 1)
        with self.assertRaises(ValueError):
            prepare.transform(drifted)

    def test_recipe_binds_owned_sources_and_policy(self):
        receipt = prepare.recipe()
        expected = {"prepare.py", "runner.py", "test_source.py", "graph.py", "execution/ci.py", "execution/verify.sh", "tests/publication_tests.rs"}
        self.assertEqual(set(receipt), expected)
        for name, value in receipt.items():
            self.assertEqual(value, hashlib.sha256((prepare.HERE / name).read_bytes()).hexdigest())
        rust = (prepare.HERE / "tests/publication_tests.rs").read_text(encoding="utf-8")
        self.assertIn("#![forbid(unsafe_code)]", rust)
        self.assertNotIn("unsafe {", rust)
        self.assertIn("Copyright 2026 PHPCraftdream", rust)
        self.assertIn("MIT OR Apache-2.0", rust)


if __name__ == "__main__":
    unittest.main()
