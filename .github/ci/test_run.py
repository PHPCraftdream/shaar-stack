"""CI runner contracts; subprocess execution is mocked except the explicit workflow self-test."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("selected_runner", Path(__file__).with_name("run.py"))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class RunnerTests(unittest.TestCase):
    def test_failed_lint_retains_an_artifact_without_running_test_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def failed(arguments, log):
                self.assertEqual(arguments[:2], ["cargo", "clippy"])
                log.write_text("selected lint failure\n", encoding="utf-8")
                return "selected lint failure\n", 1
            with patch.object(RUN, "ROOT", root), patch.object(RUN, "capture", side_effect=failed):
                with self.assertRaisesRegex(ValueError, "lint failed: 1"):
                    RUN.lint([RUN.POLICY.target("shaar-p2p")])
            self.assertEqual((root / "target/ci-selected/0.lint.log").read_text(), "selected lint failure\n")

    def test_overlapping_filters_execute_each_selected_case_once(self):
        listing = "roles::a: test\nroles::b: test\nother::c: test\nroles::ignored: test\n"
        selected, ignored = RUN.selected_cases(listing, "roles::ignored: test\n", ["roles::", "roles::a"])
        self.assertEqual(selected, ["roles::a", "roles::b"])
        self.assertEqual(ignored, ["roles::ignored"])

    def test_no_matching_runnable_cases_is_not_success(self):
        for listing, ignored, filters in (("other: test\n", "", ["missing"]),
                                          ("ignored: test\n", "ignored: test\n", [""]),
                                          ("", "", [""])):
            with self.assertRaises(ValueError):
                RUN.selected_cases(listing, ignored, filters)

    def test_duplicate_malformed_or_inconsistent_inventory_fails(self):
        for listing, ignored in (("a: test\na: test\n", ""), ("broken", ""),
                                 ("a: test\n", "b: test\n")):
            with self.assertRaises(ValueError):
                RUN.selected_cases(listing, ignored, [""])

    def test_failed_unexpected_or_ignored_execution_is_rejected(self):
        expected = {"binary": "chosen: test\n"}
        for name, state, status in (("chosen", "FAILED", 1), ("other", "ok", 0), ("chosen", "ignored", 0)):
            output = f"running 1 test\ntest {name} ... {state}\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
            with self.assertRaises(ValueError):
                RUN.VERIFY.verify(expected, {"binary": (output, status)}, "")

    def test_command_batches_are_bounded_and_preserve_exact_inventory(self):
        names = [f"module::case_{index}" for index in range(20)]
        batches = list(RUN.batches(names, limit=50))
        self.assertEqual([name for batch in batches for name in batch], names)
        self.assertTrue(all(sum(len(name) + 1 for name in batch) <= 50 for batch in batches))
        with self.assertRaises(ValueError):
            list(RUN.batches(["x" * 51], limit=50))

    def test_only_fixed_package_target_and_filter_arguments_are_accepted(self):
        valid = RUN.POLICY.target("shaar-p2p", ("carrier::driver::protocols::",))
        RUN.validate([valid])
        for change in ({"package": "--help"}, {"name": "$(command)"},
                       {"filters": ["; command"]}, {"kind": "--all"}):
            with self.assertRaises(ValueError):
                RUN.validate([{**valid, **change}])
        with self.assertRaises(ValueError):
            RUN.validate([valid, valid])

    def test_identity_scanner_failure_redacts_artifact_before_reporting(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "run.log"
            log.write_text("unsafe fixture output", encoding="utf-8")
            with patch.object(RUN.SCANNER, "read_bounded", return_value=b"unsafe fixture output"), \
                 patch.object(RUN.SCANNER, "scan_bytes", return_value=True):
                with self.assertRaisesRegex(ValueError, "unsafe log redacted"):
                    RUN.safe_text(log)
            self.assertNotIn("unsafe fixture output", log.read_text(encoding="utf-8"))

    def test_build_artifact_is_from_exact_selected_target_and_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/shaar-p2p/src/lib.rs"
            binary = root / "target/debug/deps/shaar_p2p-unit"
            artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                        "target": {"kind": ["lib"], "name": "shaar_p2p", "src_path": str(source)},
                        "executable": str(binary)}
            spec = RUN.POLICY.target("shaar-p2p")
            with patch.object(RUN, "ROOT", root):
                self.assertEqual(RUN.executable(json.dumps(artifact), spec), binary.resolve())
                artifact["executable"] = str(root / "outside/binary")
                with self.assertRaises(ValueError):
                    RUN.executable(json.dumps(artifact), spec)
                with self.assertRaises(ValueError):
                    RUN.executable("", spec)


if __name__ == "__main__":
    unittest.main()
