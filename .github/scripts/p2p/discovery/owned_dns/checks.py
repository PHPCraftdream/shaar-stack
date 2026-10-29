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

    def test_other_selectors_use_the_same_inventory_contract(self):
        for selector in ("wire_dns_", "discovery_address_", "destination_roles_",
                         "destination_guard_", "carrier_destination_",
                         "discovery::roles::infrastructure::tests::",
                         "carrier_infrastructure_admission_", "carrier_infrastructure_network_"):
            name = selector + "alpha"
            listing = f"{name}: test\n"
            output = f"running 1 test\ntest {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
            with self.subTest(selector=selector):
                self.assertEqual(VERIFY.verify({"a": listing}, {"a": (output, 0)}, selector), 1)
                with self.assertRaises(ValueError):
                    VERIFY.verify({"a": listing}, {"a": (output.replace(" ... ok", " ... ignored"), 0)}, selector)
                with self.assertRaises(ValueError):
                    VERIFY.parse_listing("unrelated::test: test\n", selector)

    def test_cargo_output_extracts_harness_without_losing_captured_output(self):
        cargo = "   Compiling fixture\n     Running unittests src/lib.rs\n" + self.output
        self.assertEqual(VERIFY.cargo_execution(cargo), self.output)
        with self.assertRaises(ValueError):
            VERIFY.cargo_execution("compilation failed\n")
        for suffix in ("test dns::tests::owned_dns_extra ... ok\n", "running 1 test\n", self.output):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                execution = VERIFY.cargo_execution(cargo + suffix)
                VERIFY.verify({"binary": self.names}, {"binary": (execution, 0)})

    def test_cargo_wrapper_status_and_output(self):
        import os
        import subprocess
        import tempfile

        script = Path(__file__).with_name("cargo.sh").resolve()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            cargo.write_text('''#!/bin/bash
if [[ " $* " == *" --no-run "* ]]; then
  printf 'build stdout\\n'; printf 'build stderr\\n' >&2
  exit "$BUILD_STATUS"
fi
printf 'run stdout\\n'; printf 'run stderr\\n' >&2
exit "$RUN_STATUS"
''', encoding="utf-8", newline="\n")
            python = bin_dir / "python"
            python.write_text('''#!/bin/bash
script=""
for argument in "$@"; do
  if [[ "$argument" == *.py ]]; then script="$argument"; break; fi
done
case "$script" in
  *scan_identity_output.py*)
    if [[ "$SCAN_FAIL" == build && "$*" == *build.stderr* ]] ||
       [[ "$SCAN_FAIL" == run && "$*" == *combined.log* && -f "$RUNNER_TEMP/shaar-inventory-case/cargo-run.log" ]]; then
      exit 1
    fi ;;
  *checks.py*) exit 0 ;;
  *verify.py*) printf 'verified\\n'; exit "$VERIFY_STATUS" ;;
esac
exit 0
''', encoding="utf-8", newline="\n")
            cargo.chmod(0o755)
            python.chmod(0o755)
            cases = ((0, 0, "none", 0, 0), (0, 0, "none", 13, 13),
                     (7, 0, "none", 0, 7), (0, 9, "none", 0, 9),
                     (0, 0, "build", 0, 1), (7, 0, "build", 0, 7),
                     (0, 0, "run", 0, 1), (0, 9, "run", 0, 9))
            import shutil
            bash = shutil.which("bash")
            self.assertIsNotNone(bash, "Bash is required for cargo.sh regression coverage")
            for build, run, scan, verifier, expected in cases:
                with self.subTest(build=build, run=run, scan=scan, verifier=verifier):
                    shutil.rmtree(root / "shaar-inventory-case", ignore_errors=True)
                    log = root / "combined.log"
                    env = dict(os.environ, BUILD_STATUS=str(build), RUN_STATUS=str(run),
                               SCAN_FAIL=scan, VERIFY_STATUS=str(verifier))
                    # Convert native Windows paths inside Bash, then set its POSIX
                    # PATH there so extensionless shell mocks win over .exe tools.
                    launcher = r'''to_shell_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s' "$1"; fi
}
export PATH="$(to_shell_path "$1"):$PATH"
export RUNNER_TEMP="$(to_shell_path "$2")"
script="$(to_shell_path "$3")"
log="$(to_shell_path "$4")"
bash "$script" owned_dns_ case "$log" fixture source target normal --lib
'''
                    result = subprocess.run([bash, "-c", launcher, "fixture", str(bin_dir),
                                             str(root), str(script), str(log)],
                                            cwd=root, env=env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    build_output = "build stderr\nbuild stdout\n"
                    run_output = "run stdout\nrun stderr\n"
                    ran = build == 0 and scan != "build"
                    self.assertEqual(log.read_text(encoding="utf-8"), build_output + (run_output if ran else ""))
                    self.assertEqual(result.stdout, (build_output if scan != "build" else "") +
                                     (run_output if ran and scan != "run" else "") +
                                     ("verified\n" if ran and run == 0 and scan != "run" else ""))

    def test_unfiltered_and_captured_output_modes(self):
        listing = "module::alpha: test\n"
        output = ("running 1 test\ntest module::alpha ... ok\n\nsuccesses:\n\n"
                  "---- module::alpha stdout ----\nhello\ntest forged ... FAILED\n\n"
                  "successes:\n    module::alpha\n\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
        self.assertEqual(VERIFY.verify({"a": listing}, {"a": (output, 0)}, "", True), 1)
        forged = output.replace("hello\n", "hello\nrunning 1 test\ntest module::alpha ... ok\n"
                                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
        self.assertEqual(VERIFY.verify({"a": listing}, {"a": (forged, 0)}, "", True), 1)
        for duplicate in (output + output, output + self.output):
            with self.subTest(duplicate=duplicate), self.assertRaises(ValueError):
                VERIFY.verify({"a": listing}, {"a": (duplicate, 0)}, "", True)
        with self.assertRaises(ValueError):
            VERIFY.verify({"a": listing}, {"a": (output, 0)}, "", False)
        with self.assertRaises(ValueError):
            VERIFY.verify({"a": listing}, {"a": (output.replace("test module::alpha ... ok", "test module::other ... ok"), 0)}, "", True)

    def test_generalized_artifact_selection(self):
        import json
        root = Path(__file__).resolve().parents[5] / "target" / "fixture"
        source = root / "src/lib.rs"
        message = {"reason": "compiler-artifact", "package_id": "fixture",
                   "profile": {"test": True}, "target": {"name": "fixture_lib", "src_path": str(source), "kind": ["lib"], "crate_types": ["lib"]},
                   "executable": str(root / "build/test")}
        self.assertEqual(len(VERIFY.artifacts(json.dumps(message), root / "build", "fixture_lib", source)), 1)
        for target, path in (("wrong", source), ("fixture_lib", root / "other.rs")):
            with self.assertRaises(ValueError):
                VERIFY.artifacts(json.dumps(message), root / "build", target, path)
        message["executable"] = str(root / "outside")
        with self.assertRaises(ValueError):
            VERIFY.artifacts(json.dumps(message), root / "build", "fixture_lib", source)

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
