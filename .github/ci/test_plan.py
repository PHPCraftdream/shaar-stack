"""CI-only regressions for fine-grained ownership, Git comparison and full triggers."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("ci_plan", Path(__file__).with_name("plan.py"))
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)
POLICY = PLAN.POLICY


class PolicyTests(unittest.TestCase):
    def test_protocol_feature_selects_own_cases_and_small_wiring_contracts_only(self):
        paths = ["crates/shaar-p2p/src/carrier/driver/runtime/protocols/guard.rs",
                 "crates/shaar-p2p/src/carrier/driver/mod.rs",
                 "crates/shaar-p2p/src/carrier/driver/runtime/events.rs",
                 "crates/shaar-p2p/src/carrier/driver/runtime/infrastructure_tests/identification.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result["suites"], ["carrier-core", "protocols"])
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(result["targets"][0]["package"], "shaar-p2p")
        self.assertIn("carrier::driver::protocols::", result["targets"][0]["filters"])
        self.assertIn("infrastructure::tests::identification::", result["targets"][0]["filters"])
        self.assertNotIn("", result["targets"][0]["filters"])
        self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertTrue(result["selection"]["product"])
        self.assertFalse(result["selection"]["full"])

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
        head = self.commit_file("crates/shaar-p2p/src/carrier/driver/runtime/protocols/guard.rs", "three")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        self.assertEqual({t["package"] for t in result["targets"]}, {"shaar", "shaar-p2p"})
        self.assertFalse(result["selection"]["backend"])

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
