"""Check routing invariants in our fixed workflow layout, not general YAML parsing."""

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
    def test_expensive_proof_groups_have_explicit_owning_domains(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        expected = {
            "Verify relay operation units, wire cases and isolated counterfactuals": "relay",
            "Verify Carrier protocol barrier and isolated guard counterfactual": "carrier",
            "Verify resolver locking with archive features and genuine counterfactuals": "resolver",
            "Verify zero-capacity cache contracts and isolated counterfactuals": "resolver",
            "Verify resolver locking with product identities and host feature unions": "resolver",
            "Verify no-cache contracts with the unchanged product feature union": "resolver",
            "Verify owned DNS foundation and its single product graph edge": "dns",
            "Verify private DNS wire input envelopes": "dns",
            "Verify strict discovery address scope and complete grammar": "discovery",
            "Verify owned destination role ledger boundaries": "discovery",
            "Verify guarded DNS transport root pinning": "discovery",
            "Verify carrier role-integration wiring": "discovery",
            "Verify Kademlia internal retention with the unchanged archive lock": "kad",
            "Verify DNS expansion with the unchanged archive lock": "dns",
            "Verify ingress ownership and budget boundaries": "backend",
            "Verify Noq fatal driver exit and cancellation": "backend",
            "Verify identical driver fixture with product dependency identities": "backend",
            "Verify native path retention against the reviewed protocol archive lock": "backend",
            "Verify high-PTO shutdown negative control after production proofs": "backend",
            "Verify actor abort joins native resource destruction": "sdk",
            "cargo test": "full",
        }
        for name, domain in expected.items():
            with self.subTest(step=name):
                self.assertTrue(steps[name].startswith("\n        if: fromJSON(needs.plan.outputs.selection)." + domain + "\n"))

    def test_full_campaign_and_windows_repeats_are_not_automatic(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        for name in ("Diagnose native-after-signaling path lifecycle (Windows only)",
                     "Diagnose unreachable native lifecycle under SDK parallelism (Windows only)"):
            self.assertIn("matrix.os == 'windows-latest' && fromJSON(needs.plan.outputs.selection).full", steps[name])
        self.assertIn("cargo test --workspace --locked", steps["cargo test"])
        targeted = steps["Targeted product package tests"]
        self.assertIn("!fromJSON(needs.plan.outputs.selection).full", targeted)
        self.assertIn("bash .github/ci/product.sh test", targeted)
        self.assertIn("bash .github/ci/product.sh lint", steps["cargo clippy"])

    def test_product_graph_prerequisites_do_not_depend_on_resolver_tests(self):
        prep = (ROOT / ".github/actions/prepare-sources/action.yml").read_text(encoding="utf-8")
        self.assertIn('> target/resolver-locking-baseline.json', prep)
        for domain in ("resolver", "kad", "dns"):
            self.assertIn("if ${{ fromJSON(inputs.selection)." + domain + " }}; then", prep)
        for dependency in ("backend/prepare.py", "p2p/prepare.py", "discovery/dns/prepare.py",
                           '"$script/prepare.py"', "discovery/kad/kad.py prepare"):
            self.assertIn(dependency, prep)

    def test_upstream_base_is_fetched_for_every_feature_revision(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        fetch = steps["Fetch upstream comparison base for feature revisions"]
        self.assertTrue(fetch.startswith("\n        if: github.event_name == 'push' && github.ref != 'refs/heads/develop'\n"))
        self.assertIn("refs/heads/develop:refs/remotes/ci-upstream/develop", fetch)

    def test_workflow_always_runs_selection_and_structural_policy(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("    needs: plan\n", text)
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("python -I .github/ci/plan.py", text)
        self.assertIn("python -I -m unittest discover -s .github/ci", text)
        steps = named_steps(text)
        for name in ("Structural limits", "Structural guard tests"):
            self.assertNotIn("        if:", steps[name])
        self.assertNotIn("continue-on-error:", text)
        self.assertIn("ci-plan.json", text)


if __name__ == "__main__":
    unittest.main()
