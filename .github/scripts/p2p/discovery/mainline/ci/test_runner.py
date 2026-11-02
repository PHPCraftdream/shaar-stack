# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for the Mainline runner's inventory-selection contract."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
RUNNER_PATH = HERE / "run.py"
SPEC = importlib.util.spec_from_file_location("mainline_ci_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("fixed Mainline runner unavailable")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
VERIFY = RUNNER.load_verify()


def listing(*names: str) -> str:
    return "".join(name + ": test\n" for name in names)


class SelectionTests(unittest.TestCase):
    def test_external_api_inventory_is_required_and_strictly_scoped(self):
        names = ["owned_api_public_imports_are_type_checkable", "owned_api_handle_is_limited_and_reports_shutdown"]
        self.assertEqual(RUNNER.select_api_cases(listing(*names), "", VERIFY), sorted(names))
        for inventory, ignored in (("", ""), (listing(*names), listing(names[0])),
                                   (listing(*names, "foreign_case"), ""), (listing(names[0], names[0]), "")):
            with self.subTest(inventory=inventory, ignored=ignored):
                with self.assertRaises(ValueError):
                    RUNNER.select_api_cases(inventory, ignored, VERIFY)

    def test_selects_every_declared_owned_prefix_and_reports_ignored(self):
        cases = {prefix: prefix + "run" for prefix in RUNNER.PREFIXES}
        cases["actor::hostile_resource_tests::"] = "actor::hostile_resource_tests::hostile_case"
        ignored_name = RUNNER.PREFIXES[0] + "skipped"
        inventory = listing(*cases.values(), ignored_name, "dht::tests::upstream")
        selected, ignored = RUNNER.select_cases(inventory, listing(ignored_name), VERIFY)
        self.assertEqual(selected, list(cases.values()))
        self.assertEqual(ignored, [ignored_name])

    def test_rejects_empty_inventory(self):
        with self.assertRaises(ValueError):
            RUNNER.select_cases("", "", VERIFY)

    def test_rejects_missing_runnable_required_prefix(self):
        cases = [prefix + "run" for prefix in RUNNER.PREFIXES[1:]]
        with self.assertRaises(ValueError):
            RUNNER.select_cases(listing(*cases), "", VERIFY)

    def test_rejects_ignored_case_outside_inventory(self):
        with self.assertRaises(ValueError):
            RUNNER.select_cases(
                listing(*[prefix + "run" for prefix in RUNNER.PREFIXES]),
                listing("owned::tests::absent"), VERIFY,
            )

    def test_rejects_duplicate_inventory_entries(self):
        with self.assertRaises(ValueError):
            RUNNER.select_cases(
                listing(*([prefix + "run" for prefix in RUNNER.PREFIXES] + [RUNNER.PREFIXES[0] + "run"])), "", VERIFY
            )

    def test_rejects_prefix_with_only_ignored_cases(self):
        with self.assertRaises(ValueError):
            RUNNER.select_cases(
                listing(RUNNER.PREFIXES[0] + "skipped", *[prefix + "run" for prefix in RUNNER.PREFIXES[1:]]),
                listing(RUNNER.PREFIXES[0] + "skipped"), VERIFY,
            )


class VerificationTests(unittest.TestCase):
    def test_verifies_exact_successful_cargo_transcript(self):
        batch = ["owned::tests::case"]
        text = ("running 1 test\ntest owned::tests::case ... ok\n"
                "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n")
        RUNNER.verify_batch(batch, text, 0, VERIFY)

    def test_rejects_missing_extra_ignored_or_failed_case(self):
        cases = [
            ("running 1 test\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n", 0),
            ("running 1 test\ntest owned::tests::extra ... ok\ntest owned::tests::case ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", 0),
            ("running 1 test\ntest owned::tests::case ... ignored\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", 0),
            ("running 1 test\ntest owned::tests::case ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", 0),
            ("running 1 test\ntest owned::tests::case ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", 1),
        ]
        for output, status in cases:
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    RUNNER.verify_batch(["owned::tests::case"], output, status, VERIFY)

    def test_rejects_empty_execution_batch(self):
        with self.assertRaises(ValueError):
            RUNNER.verify_batch([], "", 0, VERIFY)

    def test_verifies_successful_batch_and_returns_result(self):
        batch = ["owned::tests::case"]
        text = ("running 1 test\ntest owned::tests::case ... ok\n"
                "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                "0 filtered out; finished in 0.00s\n")
        self.assertEqual(RUNNER.verify_batch(batch, text, 0, VERIFY), batch)


if __name__ == "__main__":
    unittest.main()
