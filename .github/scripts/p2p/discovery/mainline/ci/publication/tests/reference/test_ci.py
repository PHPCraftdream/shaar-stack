# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reference orchestration guards; mocks are not cryptographic evidence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci


class ReferenceRunnerTests(unittest.TestCase):
    def case(self, mutation=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source/pkarr"
            source.mkdir(parents=True)
            files = {"Cargo.toml": b"manifest", "src/types/keys.rs": b"keys",
                     "src/types/signed_packet.rs": b"signed packet"}
            expected = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
            for name, data in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            license_bytes = b"fixture license bytes, not a license grant"
            (source.parent / "LICENSE").write_bytes(license_bytes)
            metadata = {"packages": [{"id": "pkarr-id", "name": "pkarr", "version": "8.1.0",
                "source": ci.SOURCE, "manifest_path": str(source / "Cargo.toml")}],
                "resolve": {"nodes": [{"id": "pkarr-id", "features": ["signed_packet"]}]}}
            if mutation == "source":
                metadata["packages"][0]["source"] = ci.SOURCE.replace(ci.REVISION, "0" * 40)
            elif mutation == "feature":
                metadata["resolve"]["nodes"][0]["features"].append("dht")
            elif mutation == "bytes":
                (source / "src/types/keys.rs").write_bytes(b"unreviewed")
            elif mutation == "license":
                (source.parent / "LICENSE").write_bytes(b"changed license")
            calls = []
            def command(label, argv, cwd, logs, receipt, env):
                calls.append((label, list(argv)))
                receipt["commands"].append({"label": label, "argv": list(argv), "exit_code": 0})
                if label == "lock":
                    (cwd / "Cargo.lock").write_bytes(b"actual mock resolution")
                elif label == "metadata":
                    return json.dumps(copy.deepcopy(metadata))
                elif label == "tests" and mutation == "tests":
                    raise ValueError("tests failed")
                elif label.startswith("generate-"):
                    if mutation == "lock":
                        (cwd / "Cargo.lock").write_bytes(b"changed resolution")
                    data = b"a" * (1105 if mutation == "oversize" else 105)
                    if mutation == "nondeterministic" and label.endswith("1"):
                        data = b"b" * 105
                    Path(argv[-1]).write_bytes(data)
                return ""
            with (
                mock.patch.object(ci.runner, "repository_root", return_value=root),
                mock.patch.object(ci.runner, "command", side_effect=command),
                mock.patch.object(ci, "REVIEWED", expected),
                mock.patch.object(ci, "LICENSE_SHA256", hashlib.sha256(license_bytes).hexdigest()),
                mock.patch.dict(ci.os.environ, {"CI_PLAN_JSON": json.dumps({
                    "selection": {"publication": mutation != "selection"}})}),
            ):
                status = ci.main()
            receipt_path = root / "target/publication-evidence/reference/receipt.json"
            return status, json.loads(receipt_path.read_text()), calls

    def test_retains_actual_mock_lock_and_commands_before_execution(self):
        status, receipt, calls = self.case()
        self.assertEqual(status, 0)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["record_sha256"], hashlib.sha256(b"a" * 105).hexdigest())
        self.assertEqual(receipt["lock_sha256"], hashlib.sha256(b"actual mock resolution").hexdigest())
        self.assertEqual([label for label, _ in calls],
                         ["lock", "metadata", "tests", "generate-0", "generate-1"])
        self.assertTrue(all("--locked" in argv for label, argv in calls if label != "lock"))

    def test_unreviewed_inputs_fail_before_any_compilation(self):
        for mutation in ("selection", "source", "feature", "bytes", "license"):
            with self.subTest(mutation=mutation):
                status, receipt, calls = self.case(mutation)
                self.assertEqual(status, 1)
                self.assertEqual(receipt["status"], "failed")
                self.assertTrue(receipt["error"])
                self.assertFalse(any(label == "tests" or label.startswith("generate-")
                                     for label, _ in calls))

    def test_execution_output_and_lock_faults_preserve_failed_receipt(self):
        for mutation in ("tests", "oversize", "nondeterministic", "lock"):
            with self.subTest(mutation=mutation):
                status, receipt, _ = self.case(mutation)
                self.assertEqual(status, 1)
                self.assertEqual(receipt["status"], "failed")
                self.assertTrue(receipt["error"])


if __name__ == "__main__":
    unittest.main()
