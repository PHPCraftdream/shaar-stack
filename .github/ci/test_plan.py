"""CI policy regressions; run only in GitHub CI."""

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
    def test_dns_fixture_does_not_run_unrelated_dependency_campaigns(self):
        result = POLICY.select(["crates/shaar-p2p/src/dns/tests/support.rs"])["selection"]
        self.assertTrue(all(result[k] for k in ("dns", "discovery", "carrier", "p2p", "rust", "prepare")))
        self.assertFalse(any(result[k] for k in ("relay", "resolver", "kad", "backend", "sdk", "apps", "full")))

    def test_product_dns_and_discovery_include_consumers(self):
        for path in ("crates/shaar-p2p/src/dns/mod.rs", "crates/shaar-p2p/src/discovery/roles/mod.rs"):
            with self.subTest(path=path):
                result = POLICY.select([path])["selection"]
                self.assertTrue(all(result[k] for k in ("p2p", "sdk", "apps", "carrier", "discovery")))

    def test_docs_only_has_no_rust_build(self):
        result = POLICY.select(["docs/plans/new.md", "crates/shaar/src/network/README.md"])["selection"]
        self.assertFalse(any(result.values()))

    def test_unions_are_order_independent(self):
        paths = ["crates/shaar-p2p/src/dns/tests/support.rs", ".github/scripts/backend/policy.py"]
        forward = POLICY.select(paths)["selection"]
        self.assertEqual(forward, POLICY.select(list(reversed(paths)))["selection"])
        self.assertTrue(all(forward[k] for k in ("dns", "backend", "sdk", "apps")))

    def test_unknown_shared_empty_and_missing_base_are_broad_not_full(self):
        for paths, fallback in ((["Cargo.lock"], None), ([".github/ci/plan.py"], None),
                                (["new-component/code.rs"], None), ([], None),
                                (["docs/new.md"], "missing base")):
            with self.subTest(paths=paths, fallback=fallback):
                result = POLICY.select(paths, fallback=fallback)["selection"]
                self.assertTrue(all(result[k] for k in POLICY.DOMAINS))
                self.assertFalse(result["full"])

    def test_dependency_policies_keep_their_own_controls(self):
        cases = {".github/scripts/p2p/discovery/resolver/prepare.py": "resolver",
                 ".github/scripts/p2p/discovery/kad/kad.py": "kad",
                 ".github/scripts/p2p/relay/fixtures/wire/run.py": "relay",
                 ".github/scripts/tests/noq_driver/prepare.py": "backend"}
        for path, domain in cases.items():
            result = POLICY.select([path])["selection"]
            self.assertTrue(result[domain])
            self.assertTrue(result["sdk"])

    def test_license_only_prepares_graph_without_product_tests(self):
        result = POLICY.select([".github/actions/dependency-license/action.yml"])["selection"]
        self.assertTrue(result["license"])
        self.assertTrue(result["prepare"])
        self.assertFalse(result["rust"])

    def test_full_is_explicit_dispatch_only(self):
        with patch.object(PLAN, "changes", return_value=(["docs/new.md"], "a" * 40, "b" * 40)):
            for name in ("push", "pull_request", "workflow_dispatch"):
                result = PLAN.plan(name, {"inputs": {"scope": "full"}}, "b" * 40)
                self.assertEqual(result["selection"]["full"], name == "workflow_dispatch")
                if name == "workflow_dispatch":
                    self.assertTrue(all(result["selection"].values()))

    def test_bad_scope_fails_and_unavailable_history_is_conservative(self):
        with self.assertRaises(ValueError):
            PLAN.plan("workflow_dispatch", {"inputs": {"scope": "typo"}}, "a" * 40)
        with patch.object(PLAN, "changes", side_effect=ValueError("missing")):
            result = PLAN.plan("push", {"before": "0" * 40}, "a" * 40)
        self.assertTrue(result["fallback"])
        self.assertTrue(all(result["selection"][k] for k in POLICY.DOMAINS))
        self.assertFalse(result["selection"]["full"])

    def test_commit_values_cannot_be_git_options_or_shell(self):
        for value in ("--help", "$(command)", "a" * 39, "0" * 40, None):
            with self.assertRaises(ValueError):
                PLAN.commit(value)


class GitComparisonTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(os.chdir, self.old)
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "CI fixture")
        self.run_git("config", "user.email", "ci@example.invalid")

    def run_git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.STDOUT).decode().strip()

    def commit_file(self, name, text):
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.run_git("add", "--all")
        self.run_git("commit", "-qm", "fixture")
        return self.run_git("rev-parse", "HEAD")

    def test_push_rename_includes_both_paths_and_deleted_files(self):
        base = self.commit_file("old.rs", "one")
        Path("old.rs").rename("new.rs")
        end = self.commit_file("docs/new.md", "two")
        paths, actual_base, actual_end = PLAN.changes("push", {"before": base, "after": end}, end)
        self.assertEqual(set(paths), {"old.rs", "new.rs", "docs/new.md"})
        self.assertEqual((actual_base, actual_end), (base, end))

    def test_pr_uses_merge_base_not_base_branch_changes(self):
        initial = self.commit_file("common.rs", "one")
        self.run_git("checkout", "-qb", "feature")
        head = self.commit_file("feature.rs", "two")
        self.run_git("checkout", "-qb", "base", initial)
        base = self.commit_file("unrelated.rs", "three")
        event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
        paths, actual_base, actual_head = PLAN.changes("pull_request", event, base)
        self.assertEqual(paths, ["feature.rs"])
        self.assertEqual((actual_base, actual_head), (initial, head))

    def test_new_feature_branch_uses_develop_merge_base_when_available(self):
        base = self.commit_file("common.rs", "one")
        self.run_git("update-ref", "refs/remotes/origin/develop", base)
        head = self.commit_file("crates/shaar-p2p/src/dns/tests/support.rs", "two")
        event = {"before": "0" * 40, "after": head, "ref": "refs/heads/feature"}
        paths, actual_base, _ = PLAN.changes("push", event, head)
        self.assertEqual(paths, ["crates/shaar-p2p/src/dns/tests/support.rs"])
        self.assertEqual(actual_base, base)
        self.assertFalse(PLAN.plan("push", event, head)["selection"]["backend"])

    def test_fork_prefers_upstream_base_without_requiring_local_develop(self):
        older = self.commit_file("common.rs", "one")
        base = self.commit_file(".github/scripts/backend/policy.py", "two")
        self.run_git("update-ref", "refs/remotes/ci-upstream/develop", base)
        head = self.commit_file("crates/shaar-p2p/src/dns/tests/support.rs", "three")
        event = {"before": "0" * 40, "after": head, "ref": "refs/heads/feature"}
        for stale_origin in (False, True):
            if stale_origin:
                self.run_git("update-ref", "refs/remotes/origin/develop", older)
            result = PLAN.plan("push", event, head)
            self.assertIsNone(result["fallback"])
            self.assertEqual(result["base"], base)
            self.assertTrue(result["selection"]["dns"])
            self.assertFalse(result["selection"]["backend"])

    def test_new_branch_and_missing_history_do_not_false_pass_docs(self):
        head = self.commit_file("docs/new.md", "one")
        for base in ("0" * 40, "a" * 40):
            result = PLAN.plan("push", {"before": base, "after": head}, head)
            self.assertTrue(result["fallback"])
            self.assertTrue(result["selection"]["rust"])
            self.assertFalse(result["selection"]["full"])


if __name__ == "__main__":
    unittest.main()
