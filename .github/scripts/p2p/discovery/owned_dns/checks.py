"""Regression tests for selected owned-DNS binary verification."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("owned_dns_verify", Path(__file__).with_name("verify.py"))
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class OwnedDnsVerifierChecks(unittest.TestCase):
    def setUp(self):
        self.names = "dns::tests::owned_dns_alpha: test\ndns::tests::owned_dns_beta: test\n"
        self.output = ("running 2 tests\n\ntest dns::tests::owned_dns_alpha ... ok\n"
                       "test dns::tests::owned_dns_beta ... ok\n\n"
                       "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 0.01s\n")

    def test_verifies_module_path_names(self):
        self.assertEqual(VERIFY.verify({"binary": self.names}, {"binary": (self.output, 0)}), 2)

    def test_accepts_distinct_actual_binaries(self):
        second = "test other::owned_dns_gamma ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        self.assertEqual(VERIFY.verify({"a": self.names, "b": "other::owned_dns_gamma: test\n"},
                                       {"a": (self.output, 0), "b": (second, 0)}), 3)

    def test_empty_inventory_allowed_per_binary_but_not_overall(self):
        empty = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 31 filtered out; finished in 0.00s\n"
        self.assertEqual(VERIFY.verify({"a": "", "b": self.names}, {"a": (empty, 0), "b": (self.output, 0)}), 2)
        with self.assertRaises(ValueError):
            VERIFY.verify({"a": ""}, {"a": (empty, 0)})

    def test_rejects_malformed_or_unfiltered_listing(self):
        for listing in ("broken listing\n", "other::test: test\n", "dns::owned_dns_a: test\ndns::owned_dns_a: test\n"):
            with self.assertRaises(ValueError):
                VERIFY.parse_listing(listing)

    def test_rejects_ignored_failed_missing_extra_duplicate_and_bad_results(self):
        bad_outputs = (
            self.output.replace(" ... ok", " ... ignored"),
            self.output.replace(" ... ok", " ... FAILED"),
            self.output.replace("owned_dns_beta ... ok", "owned_dns_missing ... ok"),
            self.output + "test dns::tests::owned_dns_extra ... ok\n",
            self.output.replace("owned_dns_alpha ... ok", "owned_dns_beta ... ok"),
            self.output.replace("test dns::tests::owned_dns_alpha ... ok", "test dns::tests::owned_dns_beta ... ok").replace("test dns::tests::owned_dns_beta ... ok", "test dns::tests::owned_dns_swap ... ok", 1),
            self.output.replace("2 passed", "1 passed"),
            self.output.replace("0 ignored", "1 ignored"),
            self.output + "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out; finished in 0.01s\n",
            self.output.replace("test result:", "unexpected result:"),
            self.output.replace("test dns::tests::owned_dns_alpha ... ok", "test dns::tests::owned_dns_alpha ... ok extra"),
        )
        for output in bad_outputs:
            with self.subTest(output=output), self.assertRaises(ValueError):
                VERIFY.verify({"binary": self.names}, {"binary": (output, 0)})
        with self.assertRaises(ValueError):
            VERIFY.verify({"binary": self.names}, {"binary": (self.output, 7)})

    def test_windows_line_endings(self):
        self.assertEqual(VERIFY.verify({"binary": self.names.replace("\n", "\r\n")},
                                       {"binary": (self.output.replace("\n", "\r\n"), 0)}), 2)

    def test_zero_inventory_counts(self):
        zero = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 31 filtered out; finished in 0.00s\n"
        self.assertEqual(VERIFY.verify({"a": "", "b": self.names}, {"a": (zero, 0), "b": (self.output, 0)}), 2)
        with self.assertRaises(ValueError):
            VERIFY.verify({"a": ""}, {"a": (zero, 0)})

    def test_accepts_inventory_additions_and_removals_per_binary(self):
        added_listing = self.names + "dns::tests::owned_dns_gamma: test\n"
        added_output = self.output.replace("running 2 tests", "running 3 tests").replace("test result: ok. 2 passed", "test dns::tests::owned_dns_gamma ... ok\ntest result: ok. 3 passed")
        removed_listing = "dns::tests::owned_dns_alpha: test\n"
        removed_output = self.output.replace("running 2 tests", "running 1 test").replace("test dns::tests::owned_dns_beta ... ok\n", "").replace("2 passed", "1 passed")
        self.assertEqual(VERIFY.verify({"a": added_listing, "b": removed_listing}, {"a": (added_output, 0), "b": (removed_output, 0)}), 4)

    def test_rejects_binary_set_mismatch(self):
        with self.assertRaises(ValueError):
            VERIFY.verify({"a": self.names}, {"b": (self.output, 0)})

    def test_rejects_swapped_per_binary_outputs(self):
        left = "dns::tests::owned_dns_alpha: test\n"
        right = "dns::tests::owned_dns_beta: test\n"
        alpha = "test dns::tests::owned_dns_alpha ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        beta = alpha.replace("owned_dns_alpha", "owned_dns_beta")
        with self.assertRaises(ValueError):
            VERIFY.verify({"a": left, "b": right}, {"a": (beta, 0), "b": (alpha, 0)})

    def test_artifact_selection_requires_exact_library_test_target(self):
        import json
        fixture = Path(__file__).resolve().parents[5] / "target" / "owned-dns-fixture"
        message = {"reason": "compiler-artifact", "package_id": "path+file:///repo#0.1.0",
                   "profile": {"test": True},
                   "target": {"name": "shaar_p2p", "src_path": str(Path(__file__).resolve().parents[5] / "crates" / "shaar-p2p" / "src" / "lib.rs"), "kind": ["lib"], "crate_types": ["lib"]},
                   "executable": str(fixture / "debug" / "deps" / "shaar_p2p-test")}
        self.assertEqual(len(VERIFY.artifacts(json.dumps(message), fixture)), 1)
        message["profile"]["test"] = False
        with self.assertRaises(ValueError):
            VERIFY.artifacts(json.dumps(message), fixture)


if __name__ == "__main__":
    unittest.main()
