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
    def test_only_full_windows_receives_the_bounded_graph_capture_job_budget(self):
        workflow = (Path(__file__).resolve().parents[1] / "workflows/ci.yml").read_text(encoding="utf-8")
        job = workflow.split("  checks:\n", 1)[1].split("    steps:\n", 1)[0]
        timeouts = [line.strip() for line in job.splitlines() if line.strip().startswith("timeout-minutes:")]
        self.assertEqual(timeouts, ["timeout-minutes: ${{ fromJSON(needs.plan.outputs.selection).full && matrix.os == 'windows-latest' && 120 || 90 }}"])

    def test_nested_package_runs_by_manifest_path_and_workspace_members_by_name(self):
        nested = RUN.POLICY.target("shaar-ygg-core")
        self.assertEqual(RUN.package_arguments(nested), ["--manifest-path", "crates/shaar-ygg-core/Cargo.toml"])
        self.assertEqual(RUN.package_arguments(RUN.POLICY.target("shaar-p2p")), ["-p", "shaar-p2p"])
        with tempfile.TemporaryDirectory() as directory:
            seen = []
            def record(arguments, log):
                seen.append(arguments)
                log.write_text("ok\n", encoding="utf-8")
                return "ok\n", 0
            with patch.object(RUN, "ROOT", Path(directory)), patch.object(RUN, "capture", side_effect=record):
                RUN.lint([nested])
        self.assertEqual(seen, [["cargo", "clippy", "--locked", "--manifest-path",
                                 "crates/shaar-ygg-core/Cargo.toml", "--lib", "--", "-D", "warnings"]])

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

    def test_failed_cases_preserve_cargo_status_without_parsing_failure_prose(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = [("build", 0), ("chosen: test\n", 0), ("", 0), ("failure prose", 101)]
            with patch.object(RUN, "ROOT", root), \
                 patch.object(RUN, "capture", side_effect=outputs), \
                 patch.object(RUN, "executable", return_value=root / "target/binary"), \
                 patch.object(RUN.VERIFY, "cargo_execution", side_effect=AssertionError("failed output parsed")):
                with self.assertRaisesRegex(ValueError, "Cargo exit code: 101"):
                    RUN.tests([RUN.POLICY.target("shaar-p2p")])
            receipt = json.loads((root / "target/ci-selected/receipt.json").read_text())
            self.assertEqual(receipt[0]["exit_code"], 101)
            self.assertEqual(receipt[0]["unverified_batch"], ["chosen"])
            self.assertEqual(receipt[0]["verified_passed"], [])

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

    def test_slow_progress_requires_selected_unfinished_identity_and_terminal_success(self):
        listing = {"selected": "fast: test\nslow: test\n"}
        notice = "test slow has been running for over 60 seconds\n"
        prefix = "running 2 tests\ntest fast ... ok\n"
        terminal = "test slow ... ok\n"
        summary = "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 134.06s\n"
        output = prefix + notice + terminal + summary
        for text in (output, output.replace("\n", "\r\n"),
                     output.replace("test slow ... ok", "test slow - should panic ... ok")):
            execution = RUN.VERIFY.cargo_execution(text)
            self.assertEqual(RUN.VERIFY.verify(listing, {"selected": (execution, 0)}, ""), 2)
        invalid = (
            prefix + notice + summary,
            prefix + notice.replace("test slow ", "test other ") + terminal + summary,
            prefix + notice + notice + terminal + summary,
            prefix + terminal + notice + summary,
            prefix + terminal + summary + notice,
            prefix + notice.replace("over 60", "over 61") + terminal + summary,
            prefix + notice.replace("has been", "has  been") + terminal + summary,
            prefix + notice + terminal.replace("... ok", "... FAILED") + summary,
            prefix + notice + terminal.replace("... ok", "... ignored") + summary,
            output.replace("2 passed", "1 passed"),
            output + summary,
        )
        for text in invalid:
            with self.subTest(output=text), self.assertRaises(ValueError):
                RUN.VERIFY.verify(listing, {"selected": (text, 0)}, "")
        with self.assertRaises(ValueError):
            RUN.VERIFY.verify(listing, {"selected": (output, 101)}, "")

    def test_verifier_accepts_exact_should_panic_events_and_rejects_near_misses(self):
        ordinary = "network::admission::negotiation_frames::role_frame_oracle_accepts_control_only_stats"
        datagram = "network::admission::negotiation_frames::role_frame_oracle_rejects_relay_datagram_rx"
        stream = "network::admission::negotiation_frames::role_frame_oracle_rejects_relay_stream_tx"
        names = (ordinary, datagram, stream)
        listing = "".join(name + ": test\n" for name in names)
        events = (f"test {ordinary} ... ok", f"test {datagram} - should panic ... ok",
                  f"test {stream} - should panic ... ok")

        def transcript(lines):
            return ("running 3 tests\n\n" + "\n".join(lines) + "\n\n"
                    "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; "
                    "0 filtered out; finished in 0.01s\n")

        def verify_output(output, status=0):
            execution = RUN.VERIFY.cargo_execution("   Compiling fixture\n" + output)
            return RUN.VERIFY.verify({"selected": listing}, {"selected": (execution, status)}, "")

        for newline in ("\n", "\r\n"):
            output = transcript(events).replace("\n", newline)
            with self.subTest(newline=repr(newline)):
                self.assertEqual(verify_output(output), 3)

        # The owned-DNS CLI selector remains the default; empty selection is explicit.
        owned = "dns::tests::owned_dns_alpha: test\n"
        self.assertEqual(RUN.VERIFY.parse_listing(owned), ("dns::tests::owned_dns_alpha",))
        with self.assertRaises(ValueError):
            RUN.VERIFY.parse_listing(ordinary + ": test\n")
        # The verifier's legacy contract permits a missing harness header.
        headerless = "\n".join(transcript(events).splitlines()[2:])
        self.assertEqual(RUN.VERIFY.verify({"selected": listing}, {"selected": (headerless, 0)}, ""), 3)

        datagram_event = events[1]
        malformed_events = (
            ("marked failed", (events[0], datagram_event.replace(" ... ok", " ... FAILED"), events[2])),
            ("ordinary failed", (events[0].replace(" ... ok", " ... FAILED"), events[1], events[2])),
            ("marked ignored", (events[0], datagram_event.replace(" ... ok", " ... ignored"), events[2])),
            ("ordinary ignored", (events[0].replace(" ... ok", " ... ignored"), events[1], events[2])),
            ("missing event", (events[0], events[2])),
            ("duplicate event", (*events, datagram_event)),
            ("unexpected event", (events[0], events[1], events[2].replace(stream, "network::admission::unexpected"))),
            ("mixed-marker duplicate", (*events, f"test {datagram} ... ok")),
            ("double space before marker", (events[0], datagram_event.replace(" - should", "  - should"), events[2])),
            ("double space after marker", (events[0], datagram_event.replace("should panic", "should  panic"), events[2])),
            ("missing marker separator", (events[0], datagram_event.replace("panic ...", "panic..."), events[2])),
            ("wrong marker text", (events[0], datagram_event.replace("should panic", "should fail"), events[2])),
            ("repeated marker", (events[0], datagram_event.replace(" ... ok", " - should panic ... ok"), events[2])),
            ("tab marker spacing", (events[0], datagram_event.replace(" - should", "\t- should"), events[2])),
            ("extra event suffix", (events[0], datagram_event + " extra", events[2])),
            ("extra output", events + ("unexpected output",)),
        )
        for label, bad_events in malformed_events:
            with self.subTest(case=label), self.assertRaises(ValueError):
                verify_output(transcript(bad_events))

        for label, output in (
            ("wrong header count", transcript(events).replace("running 3 tests", "running 4 tests")),
            ("wrong passed count", transcript(events).replace("3 passed", "2 passed")),
            ("wrong failed count", transcript(events).replace("0 failed", "1 failed")),
            ("wrong ignored count", transcript(events).replace("0 ignored", "1 ignored")),
            ("wrong measured count", transcript(events).replace("0 measured", "1 measured")),
            ("duplicate header", transcript(events).replace("running 3 tests\n", "running 3 tests\nrunning 3 tests\n")),
            ("extra result", transcript(events) + "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"),
            ("suffix after result", transcript(events) + "extra output\n"),
        ):
            with self.subTest(case=label), self.assertRaises(ValueError):
                verify_output(output)
        with self.assertRaises(ValueError):
            verify_output(transcript(events), status=7)

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

    def test_external_native_witness_requires_exact_registered_source_and_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "crates/shaar/../../.github/probes/native-graph/fixture/witness.rs"
            binary = root / "target/debug/deps/native_graph_witness-unit"
            spec = RUN.POLICY.target("shaar", kind="test", name="native_graph_witness")
            artifact = {"reason": "compiler-artifact", "profile": {"test": True},
                        "target": {"kind": ["test"], "name": spec["name"], "src_path": str(source)},
                        "executable": str(binary)}
            with patch.object(RUN, "ROOT", root):
                self.assertEqual(RUN.executable(json.dumps(artifact), spec), binary)
                for wrong_source in (root / ".github/probes/other/fixture/witness.rs",
                                     root / "crates/shaar/tests/witness.rs",
                                     root / "outside/witness.rs"):
                    wrong = {**artifact, "target": {**artifact["target"], "src_path": str(wrong_source)}}
                    with self.subTest(source=wrong_source), self.assertRaises(ValueError):
                        RUN.executable(json.dumps(wrong), spec)
                for change in ({"package": "shaar-p2p"}, {"kind": "lib"}, {"name": "other"}):
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        RUN.executable(json.dumps(artifact), {**spec, **change})
                outside = {**artifact, "executable": str(root / "outside/binary")}
                with self.assertRaisesRegex(ValueError, "escaped"):
                    RUN.executable(json.dumps(outside), spec)
                second = {**artifact, "executable": str(root / "target/debug/deps/other")}
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    RUN.executable(json.dumps(artifact) + "\n" + json.dumps(second), spec)

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


class ProcessFeedbackTests(unittest.TestCase):
    def test_process_inventory_requires_exactly_the_reviewed_ignored_cases(self):
        listing = "".join(name + ": test\n" for name in RUN.PROCESS_CASES)
        self.assertEqual(len(RUN.PROCESS_CASES), 11)
        self.assertEqual(RUN.process_inventory(listing, listing), list(RUN.PROCESS_CASES))
        for ordinary, ignored in (("", ""), (listing, ""),
                                  (listing + "process_smoke::real_extra: test\n", listing),
                                  (listing + "process_smoke::composed::real_extra: test\n", listing),
                                  (listing, listing + "missing: test\n"),
                                  (listing + listing, listing)):
            with self.subTest(ordinary=ordinary, ignored=ignored), self.assertRaises(ValueError):
                RUN.process_inventory(ordinary, ignored)

    def test_product_binary_requires_exact_source_profile_and_target_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "target/debug/shaar-server"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"compiled fixture")
            artifact = {"reason": "compiler-artifact", "profile": {"test": False},
                        "target": {"kind": ["bin"], "name": "shaar-server",
                                   "src_path": str(root / "crates/shaar-server/src/main.rs")},
                        "executable": str(binary)}
            with patch.object(RUN, "ROOT", root):
                self.assertEqual(RUN.product_executable(json.dumps(artifact), "shaar-server"), binary)
                for changed in ({"profile": {"test": True}},
                                {"executable": str(root / "outside/server")},
                                {"executable": str(root / "target/missing")},
                                {"target": {**artifact["target"], "src_path": str(root / "other/main.rs")}}):
                    with self.subTest(changed=changed), self.assertRaises(ValueError):
                        RUN.product_executable(json.dumps({**artifact, **changed}), "shaar-server")
                with self.assertRaises(ValueError):
                    RUN.product_executable("", "shaar-client")
                with self.assertRaises(ValueError):
                    RUN.product_executable(json.dumps(artifact), "unknown")
                second = root / "target/other-server"
                second.write_bytes(b"second fixture")
                with self.assertRaises(ValueError):
                    RUN.product_executable(json.dumps(artifact) + "\n" +
                                           json.dumps({**artifact, "executable": str(second)}), "shaar-server")

    def test_process_receipt_preserves_exact_success_or_first_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                products = {name: root / ("target/" + name) for name in ("shaar-server", "shaar-client")}
                for name, path in products.items():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(name.encode())
                listing = "".join(name + ": test\n" for name in RUN.PROCESS_CASES)
                outputs = [("products", 0), ("tests", 0), (listing, 0), (listing, 0)]
                for case in RUN.PROCESS_CASES:
                    text = (f"running 1 test\ntest {case} ... ok\n"
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                            "0 filtered out; finished in 0.01s\n")
                    outputs.append(("failed batch" if fail else text, 101 if fail else 0))
                seen = []
                def capture(arguments, log, *, stderr=None, extra_env=None):
                    seen.append((arguments, extra_env))
                    text, code = outputs[len(seen) - 1]
                    log.write_text(text, encoding="utf-8")
                    if extra_env:
                        self.assertIsNotNone(stderr, "child stderr must not enter the harness transcript")
                    if stderr:
                        stderr.write_text("shaar-client: child diagnostic\n" if extra_env else "", encoding="utf-8")
                    return text, code
                with patch.object(RUN, "ROOT", root), \
                     patch.object(RUN, "capture", side_effect=capture), \
                     patch.object(RUN, "product_executable", side_effect=lambda _, name: products[name]), \
                     patch.object(RUN, "executable", return_value=root / "target/identity"), \
                     patch.object(RUN.subprocess, "check_output", return_value="a" * 40):
                    if fail:
                        with self.assertRaisesRegex(ValueError, "Cargo exit code: 101"):
                            RUN.process_feedback()
                    else:
                        RUN.process_feedback()
                receipt = json.loads((root / "target/ci-process/receipt.json").read_text(encoding="utf-8"))
                self.assertEqual(receipt["head"], "a" * 40)
                self.assertEqual(receipt["selected"], list(RUN.PROCESS_CASES))
                self.assertEqual(receipt["verified_passed"], [] if fail else list(RUN.PROCESS_CASES))
                self.assertEqual(receipt["status"], "failed" if fail else "passed")
                self.assertEqual(len(seen), 5 if fail else 4 + len(RUN.PROCESS_CASES))
                for arguments, environment in seen[4:]:
                    self.assertIn("--ignored", arguments)
                    self.assertIn("--exact", arguments)
                    self.assertEqual(environment, {"SHAAR_SERVER_EXE": str(products["shaar-server"]),
                                                   "SHAAR_CLIENT_EXE": str(products["shaar-client"])})
                if fail:
                    self.assertEqual(receipt["exit_code"], 101)
                    self.assertEqual(receipt["unverified_case"], RUN.PROCESS_CASES[0])

    def test_child_stderr_is_preserved_separately_without_weakening_the_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = root / "run.log"
            stderr = root / "run.stderr.log"
            case = RUN.PROCESS_CASES[0]
            transcript = (f"running 1 test\ntest {case} ... ok\n"
                          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                          "0 filtered out; finished in 0.01s\n")
            diagnostics = "shaar-client: child diagnostic\ntest forged ... FAILED\n"
            def command(arguments, **kwargs):
                self.assertIsNot(kwargs["stdout"], kwargs["stderr"])
                kwargs["stdout"].write(transcript.encode())
                kwargs["stderr"].write(diagnostics.encode())
                return RUN.subprocess.CompletedProcess(arguments, 0)
            with patch.object(RUN, "ROOT", root), patch.object(RUN.subprocess, "run", side_effect=command):
                text, status = RUN.capture(["fixture"], stdout, stderr=stderr)
            self.assertEqual(stderr.read_text(encoding="utf-8"), diagnostics)
            self.assertEqual(text, transcript)
            expected = {"process": case + ": test\n"}
            self.assertEqual(RUN.VERIFY.verify(expected, {"process": (RUN.VERIFY.cargo_execution(text), status)}, ""), 1)
            mixed = transcript.replace("running 1 test\n", "running 1 test\n" + diagnostics)
            with self.assertRaises(ValueError):
                RUN.VERIFY.verify(expected, {"process": (RUN.VERIFY.cargo_execution(mixed), 0)}, "")

    def test_nested_identity_fixture_changes_select_only_the_identity_integration_target(self):
        selected = RUN.POLICY.select(["crates/shaar/tests/identity/process_smoke/composed.rs"])
        self.assertEqual(selected["targets"], [RUN.POLICY.target("shaar", kind="test", name="identity")])
        self.assertFalse(selected["selection"]["full"])
        with self.assertRaises(ValueError):
            RUN.POLICY.select(["crates/shaar/tests/unknown/support.rs"])

    def test_existing_feedback_workflow_is_owned_narrow_and_never_resolves_locks(self):
        selected = RUN.POLICY.select([".github/workflows/sdk-lock.yml"])
        self.assertTrue(selected["selection"]["ci_policy"])
        self.assertFalse(selected["selection"]["rust"])
        workflow = (Path(__file__).resolve().parents[1] / "workflows/sdk-lock.yml").read_text(encoding="utf-8")
        resolve, feedback = workflow.split("  direct-feedback:\n", 1)
        self.assertIn("if: ${{ !inputs.direct_feedback }}", resolve)
        self.assertIn("cargo generate-lockfile", resolve)
        self.assertIn("if: ${{ inputs.direct_feedback }}", feedback)
        self.assertIn("uses: ./.github/actions/prepare-sources", feedback)
        self.assertIn('resolve_only: "false"', feedback)
        self.assertIn("cargo fmt --manifest-path crates/shaar-ygg-core/Cargo.toml -- --check", feedback)
        self.assertIn("python -I .github/ci/run.py process-feedback", feedback)
        self.assertNotIn("cargo generate-lockfile", feedback)
        self.assertNotIn("cargo fmt --all", feedback)
        self.assertNotIn("cargo test -p", feedback)


if __name__ == "__main__":
    unittest.main()
