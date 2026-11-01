"""CI-only regressions for fine-grained ownership, Git comparison and full triggers."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

RUN_SPEC = importlib.util.spec_from_file_location("ci_runner", Path(__file__).with_name("run.py"))
RUNNER = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(RUNNER)

SPEC = importlib.util.spec_from_file_location("ci_plan", Path(__file__).with_name("plan.py"))
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)
POLICY = PLAN.POLICY


class PolicyTests(unittest.TestCase):
    def test_native_discovery_sources_select_only_owned_module_cases(self):
        selector = "native_discovery::"
        for filename in ("address.rs", "codec.rs", "state.rs", "ordering_clock.rs", "unowned.rs"):
            with self.subTest(filename=filename):
                result = POLICY.select(["crates/shaar/src/native_discovery/tests/" + filename])
                self.assertEqual(result["targets"], [POLICY.target("shaar", (selector,))])
                self.assertEqual(result["suites"], ["native-discovery"])
                self.assertFalse(result["selection"]["full"])
                self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))

        for filename in ("prepare.py", "checks.py", "graph_checks.py"):
            result = POLICY.select([".github/scripts/p2p/discovery/simple_dns/" + filename])
            self.assertEqual(result["targets"], [POLICY.target("shaar", (selector,))])
            self.assertFalse(result["selection"]["full"])

        source = POLICY.select(["crates/shaar/src/native_discovery/record.rs"])
        source_target = source["targets"]
        RUNNER.validate(source_target)
        self.assertEqual(source_target, [POLICY.target("shaar", (selector,))])

        listing = ("native_discovery::tests::address::valid: test\n"
                   "native_discovery::tests::codec::roundtrip: test\n"
                   "native_discovery::tests::address::ignored: test\n"
                   "network::unrelated: test\n")
        ignored = "native_discovery::tests::address::ignored: test\n"
        selected, skipped = RUNNER.selected_cases(listing, ignored, [selector])
        self.assertEqual(selected, ["native_discovery::tests::address::valid", "native_discovery::tests::codec::roundtrip"])
        self.assertEqual(skipped, ["native_discovery::tests::address::ignored"])
        with self.assertRaisesRegex(ValueError, "matched no runnable cases"):
            RUNNER.selected_cases("network::unrelated: test\n", "", [selector])

    def test_native_discovery_wiring_and_manifest_lock_contracts_are_wide(self):
        module = POLICY.select(["crates/shaar/src/lib.rs", "crates/shaar/src/native_discovery/mod.rs"])
        self.assertEqual(module["targets"], [POLICY.target("shaar", ("", "native_discovery::"))])
        self.assertEqual(module["suites"], ["native-discovery", "package:shaar"])
        self.assertFalse(module["selection"]["full"])

        manifest = POLICY.select(["crates/shaar/Cargo.toml"])
        self.assertEqual(manifest["targets"], [POLICY.target("shaar")])
        self.assertTrue(manifest["selection"]["license"])
        self.assertEqual(POLICY.select(["crates/shaar-p2p/Cargo.toml", "Cargo.lock"])["targets"],
                         [POLICY.target("shaar-p2p")])
        for paths, expected_license, mixed in (
            (["crates/shaar/src/native_discovery/README.md", "crates/shaar/src/lib.rs"], False, False),
            (["crates/shaar/src/native_discovery/README.md", "crates/shaar/Cargo.toml"], True, False),
            (["crates/shaar/src/native_discovery/README.md", "crates/shaar/Cargo.toml", "Cargo.lock"], True, False),
            (["crates/shaar/src/native_discovery/record.rs", "crates/shaar/src/lib.rs"], False, True),
            (["crates/shaar/src/native_discovery/record.rs", "crates/shaar/Cargo.toml"], True, True),
            (["crates/shaar/src/native_discovery/record.rs", "crates/shaar/Cargo.toml", "Cargo.lock"], True, True),
        ):
            with self.subTest(paths=paths):
                result = POLICY.select(paths)
                expected = ["", "native_discovery::"] if mixed else [""]
                self.assertEqual(result["targets"], [POLICY.target("shaar", expected)])
                self.assertEqual(result["selection"]["license"], expected_license)
                self.assertFalse(result["selection"]["full"])
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select(["Cargo.lock"])

    def test_native_discovery_cumulative_repair_keeps_each_case_obligation(self):
        paths = ["crates/shaar/src/native_discovery/tests/address.rs",
                 "crates/shaar/src/native_discovery/tests/codec.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result["targets"], [POLICY.target("shaar", ("native_discovery::",))])
        self.assertEqual(result["suites"], ["native-discovery"])
        self.assertEqual(result, POLICY.select(list(reversed(paths))))

    def test_unrelated_shaar_shared_wiring_keeps_package_default(self):
        for path in ("crates/shaar/src/lib.rs", "crates/shaar/Cargo.toml"):
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertEqual(result["targets"], [POLICY.target("shaar")])
                self.assertEqual(result["suites"], ["package:shaar"])
                self.assertFalse(result["selection"]["full"])
                expected_domains = ["license"] if path.endswith("Cargo.toml") else []
                self.assertEqual([key for key in POLICY.DOMAINS if result["selection"][key]], expected_domains)

    def test_protocol_feature_selects_own_cases_and_small_wiring_contracts_only(self):
        paths = ["crates/shaar-p2p/src/carrier/driver/runtime/protocols/guard.rs",
                 "crates/shaar-p2p/src/carrier/driver/mod.rs",
                 "crates/shaar-p2p/src/carrier/driver/runtime/events/mod.rs",
                 "crates/shaar-p2p/src/carrier/driver/runtime/infrastructure_tests/identification.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result["suites"], ["carrier-core", "protocols"])
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(result["targets"][0]["package"], "shaar-p2p")
        self.assertIn("carrier::driver::protocols::", result["targets"][0]["filters"])
        self.assertIn("infrastructure::tests::identification::", result["targets"][0]["filters"])
        self.assertIn("carrier::driver::events::request_owner::tests::", result["targets"][0]["filters"])
        core = POLICY.select(["crates/shaar-p2p/src/carrier/driver/runtime/events/request_owner.rs"])
        self.assertEqual(core["suites"], ["carrier-core"])
        self.assertIn("carrier::driver::events::request_owner::tests::", core["targets"][0]["filters"])
        test_source = POLICY.select(["crates/shaar-p2p/src/carrier/driver/runtime/events/request_owner_tests.rs"])
        self.assertEqual(test_source["suites"], ["carrier-core"])
        self.assertIn("carrier::driver::events::request_owner::tests::", test_source["targets"][0]["filters"])
        self.assertNotIn("", result["targets"][0]["filters"])
        self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertTrue(result["selection"]["product"])
        self.assertFalse(result["selection"]["full"])

    def test_fault_test_source_and_driver_wiring_select_fault_cases(self):
        selector = "carrier::driver::fault_tests::"
        fault_source = POLICY.select(["crates/shaar-p2p/src/carrier/fault_tests.rs"])
        self.assertEqual(fault_source["suites"], ["carrier-core"])
        self.assertIn(selector, fault_source["targets"][0]["filters"])
        self.assertFalse(fault_source["selection"]["full"])

        driver_wiring = POLICY.select(["crates/shaar-p2p/src/carrier/driver/mod.rs"])
        self.assertEqual(driver_wiring["suites"], ["carrier-core"])
        self.assertIn(selector, driver_wiring["targets"][0]["filters"])
        self.assertFalse(driver_wiring["selection"]["full"])

        cumulative_repair = POLICY.select([
            "crates/shaar-p2p/src/carrier/fault_tests.rs",
            "crates/shaar-p2p/src/carrier/driver/mod.rs",
        ])
        self.assertIn(selector, cumulative_repair["targets"][0]["filters"])
        self.assertFalse(any(cumulative_repair["selection"][key] for key in POLICY.DOMAINS))
        self.assertFalse(cumulative_repair["selection"]["full"])

    def test_relay_gate_includes_provenance_and_handoff_contracts_without_broad_proofs(self):
        for suffix in ("gate.rs", "gate_factory.rs", "gate_test_support.rs"):
            with self.subTest(suffix=suffix):
                result = POLICY.select(["crates/shaar-p2p/src/carrier/relay/" + suffix])
                self.assertEqual(result["suites"], ["carrier-relay", "relay-gate"])
                self.assertEqual(len(result["targets"]), 1)
                target = result["targets"][0]
                self.assertEqual(target["package"], "shaar-p2p")
                self.assertIn("carrier::driver::roles_gate_tests::", target["filters"])
                self.assertIn("carrier::driver::roles_tests::", target["filters"])
                self.assertIn("infrastructure::tests::identification::handoff::", target["filters"])
                self.assertNotIn("", target["filters"])
                self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
                self.assertFalse(result["selection"]["full"])

    def test_carrier_frame_sources_select_only_their_owned_proof(self):
        paths = [".github/probes/iroh-paths/carrier/" + name
                 for name in ("probe.rs", "instrument.py", "graph.py", "run.py", "checks.py")]
        paths.append(".github/probes/iroh-paths/gate/bridge/support/packet_identity.py")
        for path in paths:
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertEqual([key for key in POLICY.DOMAINS if result["selection"][key]], ["carrier_frames"])
                self.assertEqual(result["suites"], ["carrier_frames"])
                self.assertFalse(result["targets"])
                self.assertTrue(result["selection"]["prepare"])
                self.assertFalse(result["selection"]["full"])
                self.assertFalse(result["selection"]["product"])

    def test_dependency_proofs_only_follow_changed_dependency_owner(self):
        cases = {".github/scripts/p2p/discovery/resolver/prepare.py": "resolver",
                 ".github/scripts/p2p/discovery/kad/kad.py": "kad",
                 ".github/scripts/p2p/relay/fixtures/wire/run.py": "relay",
                 ".github/scripts/tests/noq_driver/prepare.py": "backend"}
        for path, owner in cases.items():
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertEqual([k for k in POLICY.DOMAINS if result["selection"][k]], [owner])
                self.assertFalse(result["targets"])
                self.assertTrue(result["selection"]["prepare"])

    def test_docs_and_ci_policy_do_not_compile_rust(self):
        for paths in (["docs/plans/new.md", "CLAUDE.md"], [".github/ci/policy.py"]):
            result = POLICY.select(paths)
            self.assertFalse(result["selection"]["prepare"])
            self.assertFalse(result["selection"]["rust"])
        self.assertTrue(POLICY.select([".github/ci/policy.py"])["selection"]["ci_policy"])

    def test_unknown_paths_empty_comparison_and_shared_lock_fail_not_expand(self):
        for paths in ([], ["new-component/code.rs"], ["Cargo.lock"],
                      ["crates/shaar-p2p/src/new-unknown/module.rs"]):
            with self.subTest(paths=paths):
                with self.assertRaises(ValueError):
                    POLICY.select(paths)

    def test_unions_are_order_independent_and_targets_deduplicate(self):
        paths = ["crates/shaar-p2p/src/discovery/roles/mod.rs",
                 "crates/shaar-p2p/src/discovery/roles/infrastructure/tests/contacts.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result, POLICY.select(list(reversed(paths))))
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(result["targets"][0]["filters"],
                         ["discovery::roles::", "discovery::roles::infrastructure::tests::contacts::"])

    def test_full_is_all_explicit_proofs_without_targeted_double_execution(self):
        result = POLICY.select([], full=True)
        self.assertTrue(all(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertTrue(result["selection"]["full"])
        self.assertFalse(result["targets"])
        self.assertEqual(result["suites"], ["full"])

    def test_commit_values_cannot_be_git_options_or_shell(self):
        for value in ("--help", "$(command)", "a" * 39, "0" * 40, None):
            with self.assertRaises(ValueError):
                PLAN.commit(value)

    def test_marker_is_an_exact_separate_line(self):
        self.assertTrue(PLAN.FULL_MARKER.search("subject\n\n[ci:full]\n"))
        self.assertTrue(PLAN.FULL_MARKER.search("subject\r\n[ci:full]\r\n"))
        for message in ("subject [ci:full]", "> [ci:full]", " [ci:full]", "[ci:full ]", "[ci:FULL]"):
            self.assertFalse(PLAN.FULL_MARKER.search(message))


class GitTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(os.chdir, self.old)
        self.git("init", "-q")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "ci@example.invalid")

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.STDOUT).decode().strip()

    def commit_file(self, name, text, message="fixture"):
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.git("add", "--all")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def event(self, base, head, ref="refs/heads/develop"):
        return {"before": base, "after": head, "ref": ref}

    def test_rename_and_deletion_include_both_sides(self):
        base = self.commit_file("old.rs", "one")
        Path("old.rs").rename("new.rs")
        head = self.commit_file("docs/new.md", "two")
        paths, actual, _ = PLAN.changes("push", self.event(base, head), head)
        self.assertEqual(set(paths), {"old.rs", "new.rs", "docs/new.md"})
        self.assertEqual(actual, base)

    def test_feature_repair_preserves_original_own_test_selectors(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file("crates/shaar/src/network/mod.rs", "two")
        failed = self.commit_file("crates/shaar-p2p/src/carrier/fault_tests.rs", "fault obligation", "fault tests")
        head = self.commit_file("crates/shaar-p2p/src/carrier/driver/runtime/protocols/guard.rs", "three")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        self.assertEqual({t["package"] for t in result["targets"]}, {"shaar", "shaar-p2p"})
        p2p_target = next(t for t in result["targets"] if t["package"] == "shaar-p2p")
        self.assertIn("carrier::driver::fault_tests::", p2p_target["filters"])
        self.assertFalse(result["selection"]["backend"])

    def test_native_discovery_obligation_survives_policy_only_repair_push(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file("crates/shaar/src/native_discovery/tests/address.rs", "native test")
        head = self.commit_file(".github/ci/policy.py", "policy repair")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        self.assertEqual({(target["package"], tuple(target["filters"])) for target in result["targets"]},
                         {("shaar", ("native_discovery::",))})
        self.assertTrue(result["selection"]["ci_policy"])
        self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertFalse(result["selection"]["full"])

    def test_native_discovery_shared_obligation_survives_policy_only_repair_push(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file("crates/shaar/src/native_discovery/tests/address.rs", "native test")
        failed = self.commit_file("crates/shaar/src/lib.rs", "shared wiring")
        failed = self.commit_file("crates/shaar/Cargo.toml", "manifest")
        failed = self.commit_file("Cargo.lock", "lock")
        head = self.commit_file(".github/ci/policy.py", "policy repair")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        shaar = next(target for target in result["targets"] if target["package"] == "shaar")
        self.assertEqual(shaar["filters"], ["", "native_discovery::"])
        self.assertTrue(result["selection"]["license"])
        self.assertTrue(result["selection"]["ci_policy"])
        self.assertFalse(result["selection"]["full"])

    def test_missing_history_is_not_a_full_trigger(self):
        head = self.commit_file("docs/new.md", "one")
        with self.assertRaisesRegex(ValueError, "no automatic full fallback"):
            PLAN.plan("push", self.event("0" * 40, head), head)

    def test_current_commit_marker_triggers_full_even_without_a_base(self):
        head = self.commit_file("unknown.rs", "one", "sprint acceptance\n\n[ci:full]")
        result = PLAN.plan("push", self.event("0" * 40, head), head)
        self.assertEqual(result["trigger"], "commit-marker")
        self.assertTrue(result["selection"]["full"])

    def test_old_commit_marker_is_not_inherited(self):
        base = self.commit_file("docs/old.md", "one", "old sprint\n\n[ci:full]")
        head = self.commit_file("docs/new.md", "two")
        result = PLAN.plan("push", self.event(base, head), head)
        self.assertEqual(result["scope"], "targeted")
        self.assertFalse(result["selection"]["rust"])

    def test_pr_reads_real_head_message_not_checkout_merge_message(self):
        initial = self.commit_file("common.rs", "one")
        self.git("checkout", "-qb", "feature")
        head = self.commit_file("docs/new.md", "two")
        self.git("checkout", "-qb", "base", initial)
        base = self.commit_file("other.rs", "three", "merge text\n\n[ci:full]")
        event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
        result = PLAN.plan("pull_request", event, base)
        self.assertFalse(result["selection"]["full"])
        self.assertEqual(result["head"], head)
        self.assertEqual(result["base"], initial)

    def test_actions_manual_full_and_targeted_are_available(self):
        self.commit_file("docs/old.md", "one")
        head = self.commit_file("docs/new.md", "two")
        targeted = PLAN.plan("workflow_dispatch", {"inputs": {"scope": "targeted"}}, head, "refs/heads/develop")
        self.assertFalse(targeted["selection"]["rust"])
        full = PLAN.plan("workflow_dispatch", {"inputs": {"scope": "full"}}, head)
        self.assertEqual(full["trigger"], "manual-full")
        self.assertTrue(full["selection"]["full"])
        with self.assertRaises(ValueError):
            PLAN.plan("workflow_dispatch", {"inputs": {"scope": "typo"}}, head)


if __name__ == "__main__":
    unittest.main()
