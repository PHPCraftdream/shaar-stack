"""CI-only source controls; no archive code is executed by these checks."""
import hashlib
import json
from pathlib import Path
import unittest

from . import patch
from .handler_patch import replace


class OperationSourceChecks(unittest.TestCase):
    def source(self):
        return Path(__file__).resolve().parents[4] / "target/p2p/relay/libp2p-relay-0.22.0"

    def test_operation_sources_and_preparation_receipt_match_owned_bytes(self):
        root = self.source()
        receipt = json.loads((root.parent / "provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["relay_operation_gate"], "owner-captured-generation-v1")
        self.assertEqual(receipt["operation_gate_unit_tests"], 13)
        self.assertEqual(receipt["operation_handler_unit_tests"], 7)
        self.assertEqual(receipt["operation_client_unit_tests"], 5)
        owned = Path(__file__).parent
        for generated, source in (("operation_gate.rs", "gate.rs"),
                                  ("operation_tests.rs", "tests.rs"),
                                  ("priv_client/operation_handler_tests.rs", "fixtures/handler_tests.rs"),
                                  ("operation_client_tests.rs", "fixtures/client_tests.rs")):
            expected = (owned / source).read_bytes()
            actual = (root / "src" / generated).read_bytes()
            self.assertEqual(actual, expected)
            self.assertEqual(receipt["operation_source_sha256"][generated], hashlib.sha256(expected).hexdigest())
        self.assertFalse(receipt["operation_runtime_fixture_verified"])

    def test_operation_patch_rejects_reapplication_before_writing_sources(self):
        root = self.source() / "src"
        names = ("lib.rs", "priv_client.rs", "priv_client/handler.rs", "priv_client/transport.rs")
        before = {name: (root / name).read_bytes() for name in names}
        with self.assertRaisesRegex(ValueError, "anchor changed"):
            patch.patch(*(before[name].decode("utf-8") for name in names))
        self.assertEqual(before, {name: (root / name).read_bytes() for name in names})

    def test_operation_anchor_missing_or_duplicated_fails_closed(self):
        for source in ("missing", "anchor anchor"):
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                replace(source, "anchor", "replacement")
