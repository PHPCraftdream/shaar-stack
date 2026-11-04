# SPDX-License-Identifier: MIT OR Apache-2.0
"""Read-only prepared-source fixtures for the exact patched SDK dev edge."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import graph

ROOT = Path(__file__).resolve().parents[5]


class PatchedCodecProjectionTests(unittest.TestCase):
    def check_case(self, mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            manifest = root / "Cargo.toml"
            manifest.write_bytes((ROOT / "Cargo.toml").read_bytes())
            sdk_manifest = root / "crates/shaar/Cargo.toml"
            sdk_manifest.parent.mkdir(parents=True)
            sdk_manifest.write_bytes((ROOT / "crates/shaar/Cargo.toml").read_bytes())
            relative = Path(graph.GENERATED_PATHS["serde_bencode"])
            prepared = root / relative
            shutil.copytree(ROOT / relative, prepared)
            receipt = prepared.parent / "serde_bencode-0.2.4.provenance.json"
            shutil.copyfile((ROOT / relative).parent / receipt.name, receipt)
            target = {"id": "codec", "name": "serde_bencode", "version": "0.2.4",
                      "source": None, "manifest_path": str(prepared / "Cargo.toml")}
            declaration = {"name": "serde_bencode", "rename": None, "req": "=0.2.4",
                           "kind": "dev", "source": graph.REGISTRY, "target": None}
            owner = {"id": "sdk", "name": "shaar", "version": "0.1.0", "source": None,
                     "manifest_path": str(sdk_manifest), "dependencies": [declaration]}
            edge = {"name": "serde_bencode", "pkg": "codec",
                    "dep_kinds": [{"kind": "dev", "target": None}]}
            product = {"workspace_root": str(root), "packages": [owner, target],
                       "resolve": {"nodes": [{"id": "sdk", "deps": [edge]}, {"id": "codec", "deps": []}]}}
            consumer = copy.deepcopy(product)
            consumer["resolve"]["nodes"][0]["deps"] = []
            context = {"product": product, "consumer": consumer,
                       "product_root_manifest": {"path": str(manifest),
                            "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()},
                       "bencode_archive": str(ROOT / "target/native-graph-archives/serde_bencode-0.2.4.crate")}
            if mutation == "normal":
                declaration["kind"] = None
                edge["dep_kinds"][0]["kind"] = None
            elif mutation == "condition":
                declaration["target"] = 'cfg(windows)'
            elif mutation == "requirement":
                declaration["req"] = "^0.2.4"
            elif mutation == "source":
                declaration["source"] = "git+https://invalid.example/codec"
            elif mutation == "root_snapshot":
                context["product_root_manifest"]["sha256"] = "0" * 64
            elif mutation == "missing_archive":
                del context["bencode_archive"]
            elif mutation == "archive":
                bad = root / "bad.crate"
                bad.write_bytes(b"not the approved archive")
                context["bencode_archive"] = str(bad)
            elif mutation == "prepared_source":
                with (prepared / "Cargo.toml").open("ab") as stream:
                    stream.write(b"\n# unreviewed source\n")
            elif mutation == "receipt":
                doc = json.loads(receipt.read_text())
                doc["package"] = "forged"
                receipt.write_text(json.dumps(doc))
            elif mutation == "consumer_edge":
                consumer["resolve"]["nodes"][0]["deps"] = [copy.deepcopy(edge)]
            elif mutation == "patch":
                text = manifest.read_text()
                old = 'serde_bencode = { path = "target/native-graph/serde_bencode-0.2.4" }'
                self.assertIn(old, text)
                manifest.write_text(text.replace(old, old.replace('serde_bencode-0.2.4', 'other-0.2.4'), 1))
                context["product_root_manifest"]["sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
            return graph._prove_dev_projection(("shaar", "0.1.0", "path"),
                       ("serde_bencode", "0.2.4", "path"), context, target_retained=True)

    def test_exact_patched_codec_edge_has_full_source_and_root_provenance(self):
        proof = self.check_case()
        self.assertEqual(proof["archive_sha256"], "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e")
        self.assertEqual(proof["alias"], "serde_bencode")
        self.assertEqual(proof["target_conditions"], [""])
        self.assertTrue(proof["prepared_manifest_sha256"])
        self.assertTrue(proof["prepared_receipt_sha256"])
        self.assertTrue(proof["root_manifest_sha256"])

    def test_projection_rejects_kind_condition_source_and_provenance_forgery(self):
        for mutation in ("normal", "condition", "requirement", "source", "root_snapshot",
                         "missing_archive", "archive", "prepared_source", "receipt", "consumer_edge", "patch"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check_case(mutation)
