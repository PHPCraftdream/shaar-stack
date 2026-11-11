"""CI-only raw-source receipt and binding contracts, loaded by test_notice_evidence."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


class RegistryRawSourceTests(unittest.TestCase):
    def inputs(self):
        root = Path(__file__).resolve().parents[3]
        registry = root / "docs/legal/notices-material/registry"
        rows = json.loads((registry / "inventory.json").read_bytes())["identities"]
        spec = importlib.util.spec_from_file_location("raw_registry_replay", registry / "replay.py")
        replay = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(replay)
        selected = [r for r in rows if r.get("raw_source_binding") or r.get("raw_materials")]
        self.assertEqual({(r["name"], r["version"]) for r in selected}, set(replay.RAW_PACKAGES))
        return registry, replay, selected

    def members(self, row):
        # CI checks retained bindings; full archive replay compares these bytes to the .crate.
        return {m["archive_member"]: bytes.fromhex(m["bytes_hex"])
                for m in row["raw_source_binding"]["archive_metadata"].values()}

    def test_exact_raw_bindings_preserve_both_jni_alternatives_and_all_bytes(self):
        registry, replay, rows = self.inputs()
        receipt = replay.raw_receipt(registry)
        count = size = 0
        for row in rows:
            with self.subTest(package=row["name"]):
                n, length = replay.validate_raw_sources(row, registry, self.members(row), receipt)
                count += n
                size += length
                replay.validate_terms_evidence(row)
                self.assertEqual(row["classification"], "package-complete")
                alternatives = [a for g in row["terms_evidence"]["groups"] for a in g["alternatives"]]
                self.assertTrue(all(a["availability"] == "available" for a in alternatives))
                self.assertEqual({a["expression"] for a in alternatives},
                                 {"MIT", "Apache-2.0"} if row["name"].startswith("jni") else {"MIT"})
                for material in row["raw_materials"]:
                    self.assertNotIn("archive_member", material)
        self.assertEqual((count, size), (8, 38580))

    def test_raw_binding_rejects_wrong_identity_revision_metadata_scope_and_receipt(self):
        registry, replay, rows = self.inputs()
        receipt = replay.raw_receipt(registry)
        for original in rows:
            for mutation in ("version", "checksum", "revision", "path", "metadata", "role", "hash", "url", "missing"):
                row = copy.deepcopy(original)
                if mutation == "version":
                    row["version"] = "0.0.0"
                elif mutation == "checksum":
                    row["checksum"] = "0" * 64
                elif mutation == "revision":
                    row["raw_source_binding"]["revision"] = "0" * 40
                elif mutation == "path":
                    row["raw_source_binding"]["package_path_in_vcs"] = "other"
                elif mutation == "metadata":
                    row["raw_source_binding"]["archive_metadata"][".cargo_vcs_info.json"]["sha256"] = "0" * 64
                elif mutation == "role":
                    row["raw_materials"][0]["role"] = "reference_context"
                elif mutation == "hash":
                    row["raw_materials"][0]["material_sha256"] = "0" * 64
                elif mutation == "url":
                    row["raw_materials"][0]["url"] += "-other"
                else:
                    row["raw_materials"].pop()
                with self.subTest(package=original["name"], mutation=mutation), self.assertRaises(ValueError):
                    replay.validate_raw_sources(row, registry, self.members(original), receipt)
            bad_receipt = copy.deepcopy(receipt)
            record = next(r for r in bad_receipt["records"] if r["url"] == original["raw_materials"][0]["url"])
            record["identities"] = ["jni@0.21.1"]
            with self.assertRaises(ValueError):
                replay.validate_raw_sources(original, registry, self.members(original), bad_receipt)

    def test_changed_archived_vcs_or_retained_raw_bytes_are_rejected(self):
        registry, replay, rows = self.inputs()
        receipt = replay.raw_receipt(registry)
        original = rows[0]
        row = copy.deepcopy(original)
        item = row["raw_source_binding"]["archive_metadata"][".cargo_vcs_info.json"]
        vcs = json.loads(bytes.fromhex(item["bytes_hex"]))
        vcs["git"]["sha1"] = "0" * 40
        content = json.dumps(vcs).encode()
        item["bytes_hex"] = content.hex()
        item["sha256"] = hashlib.sha256(content).hexdigest()
        with self.assertRaises(ValueError):
            replay.validate_raw_sources(row, registry, self.members(row), receipt)
        read = replay.bounded_regular
        with mock.patch.object(replay, "bounded_regular", side_effect=lambda path, cap: read(path, cap) + b"changed"):
            with self.assertRaises(ValueError):
                replay.validate_raw_sources(original, registry, self.members(original), receipt)

    def test_macro_receipt_rejects_failed_requests_wrong_scope_and_budget_changes(self):
        registry, replay, _ = self.inputs()
        document = json.loads((registry / "raw-sources/jni-macro-receipt.json").read_bytes())
        self.assertEqual(len(replay.macro_records(document)), 4)
        for mutation in ("proposal", "status", "elapsed", "http", "curl", "identity", "revision",
                         "duplicate", "request", "object", "total", "unavailable"):
            changed = copy.deepcopy(document)
            attempt = changed["attempts"][0]
            if mutation == "proposal":
                changed["proposal_sha256"] = "0" * 64
            elif mutation == "status":
                changed["status"] = "stopped"
            elif mutation == "elapsed":
                changed["elapsed_seconds"] = 301
            elif mutation == "http":
                attempt["http_status_output"] = "302"
            elif mutation == "curl":
                attempt["curl_exit_code"] = 1
            elif mutation == "identity":
                attempt["candidate"]["package"]["checksum"] = "0" * 64
            elif mutation == "revision":
                attempt["candidate"]["revision"] = "0" * 40
            elif mutation == "duplicate":
                changed["attempts"][1] = copy.deepcopy(attempt)
            elif mutation == "request":
                attempt["request_seconds"] = 31
            elif mutation == "object":
                attempt["bytes"] = 65537
            elif mutation == "total":
                changed["body_bytes_total"] += 1
            else:
                attempt["text_available"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                replay.macro_records(changed)
        read = replay.bounded_regular
        with mock.patch.object(replay, "bounded_regular", side_effect=lambda path, cap:
                               read(path, cap) + (b"changed" if path.name == "jni-macro-receipt.json" else b"")):
            with self.assertRaises(ValueError):
                replay.raw_receipt(registry)

    def test_raw_terms_cannot_use_reference_material_or_a_missing_binding(self):
        _, replay, rows = self.inputs()
        for original in rows:
            for mutation in ("reference", "missing", "forged"):
                row = copy.deepcopy(original)
                if mutation == "reference":
                    for material in row["raw_materials"]:
                        material["role"] = "reference_context"
                elif mutation == "missing":
                    row["raw_materials"] = []
                else:
                    row["terms_evidence"]["groups"][0]["alternatives"][0]["evidence"][0]["sha256"] = "0" * 64
                with self.subTest(package=row["name"], mutation=mutation), self.assertRaises(ValueError):
                    replay.validate_terms_evidence(row)
