"""Workflow routing contracts for the repository's fixed layout, not a generic YAML parser."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def named_steps(text):
    starts = list(re.finditer(r"^      - name: (.+)$", text, re.MULTILINE))
    return {match[1]: text[match.end():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
            for index, match in enumerate(starts)}


class WorkflowTests(unittest.TestCase):
    def test_proof_groups_keep_explicit_owner_gates(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        expected = {
            "Verify relay operation units, wire cases and isolated counterfactuals": "relay",
            "Verify Carrier protocol barrier and isolated guard counterfactual": "carrier",
            "Verify resolver locking with archive features and genuine counterfactuals": "resolver",
            "Verify zero-capacity cache contracts and isolated counterfactuals": "resolver",
            "Verify resolver locking with product identities and host feature unions": "resolver",
            "Verify no-cache contracts with the unchanged product feature union": "resolver",
            "Verify owned DNS foundation and its single product graph edge": "dns",
            "Verify Kademlia internal retention with the unchanged archive lock": "kad",
            "Verify Noq fatal driver exit and cancellation": "backend",
            "Verify high-PTO shutdown negative control after production proofs": "backend",
            "cargo test": "full",
        }
        for name, owner in expected.items():
            with self.subTest(step=name):
                self.assertTrue(steps[name].startswith("\n        if: fromJSON(needs.plan.outputs.selection)." + owner + "\n"))

    def test_full_and_targeted_paths_do_not_both_execute(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        self.assertIn("cargo test --workspace --locked", steps["cargo test"])
        targeted = steps["Targeted project test cases"]
        self.assertIn("selection).product && !fromJSON(needs.plan.outputs.selection).full", targeted)
        self.assertIn("bash .github/ci/product.sh test", targeted)
        for name in ("Diagnose native-after-signaling path lifecycle (Windows only)",
                     "Diagnose unreachable native lifecycle under SDK parallelism (Windows only)"):
            self.assertIn("selection).full", steps[name])

    def test_feature_and_manual_comparisons_fetch_integration_base(self):
        fetch = named_steps(WORKFLOW.read_text(encoding="utf-8"))["Fetch upstream comparison base for feature revisions"]
        self.assertIn("github.event_name == 'workflow_dispatch'", fetch)
        self.assertIn("github.ref != 'refs/heads/develop'", fetch)
        self.assertIn("refs/heads/develop:refs/remotes/ci-upstream/develop", fetch)
        self.assertNotIn("github.event.before", fetch)

    def test_ci_control_tests_are_separate_from_product_dependency_proofs(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        steps = named_steps(text)
        self.assertIn("if: fromJSON(needs.plan.outputs.selection).ci_policy", steps["Verify selected-test runner with real libtest filters"])
        self.assertIn("run.py self-test", steps["Verify selected-test runner with real libtest filters"])
        self.assertIn("if: fromJSON(needs.plan.outputs.selection).ci_policy", steps["Structural guard tests"])
        self.assertNotIn("        if:", steps["Structural limits"])
        self.assertIn("CI_TARGETS: ${{ needs.plan.outputs.targets }}", text)
        self.assertNotIn("continue-on-error:", text)
        self.assertIn("target/ci-selected/", text)

    def test_preparation_does_not_unconditionally_run_dependency_tests(self):
        text = (ROOT / ".github/actions/prepare-sources/action.yml").read_text(encoding="utf-8")
        for owner, command in (("relay", "python -I .github/scripts/p2p/checks.py"),
                               ("dns", "python -I .github/scripts/p2p/discovery/dns/checks.py"),
                               ("resolver", 'rustfmt --edition 2021'),
                               ("kad", "python -I .github/scripts/p2p/discovery/kad/kad_checks.py")):
            start = "if ${{ fromJSON(inputs.selection)." + owner + " }}; then"
            self.assertIn(start + "\n          " + command, text)
        self.assertIn("> target/resolver-locking-baseline.json", text)
        self.assertIn("graph.py verify", text)

    def test_instructions_document_both_full_triggers_and_normal_actions(self):
        instructions = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn("[ci:full]", instructions)
        self.assertIn("CURRENT candidate commit", instructions)
        self.assertIn("scope: full", instructions)
        self.assertIn("scope: targeted", instructions)
        self.assertIn("ancestor commits do not trigger", instructions)
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("options: [targeted, full]", text)


if __name__ == "__main__":
    unittest.main()
