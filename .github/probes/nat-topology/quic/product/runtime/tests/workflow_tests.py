"""CI-only text contracts for the explicit privileged-matrix dispatch; the workflow is never executed here."""

import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[7]
WORKFLOW = ROOT / ".github/workflows/sdk-lock.yml"
JOB = "controlled-network-matrix"
MATRIX_IF = "    if: ${{ inputs.controlled_network_matrix && !inputs.controlled_network_preflight && !inputs.direct_feedback }}\n"


def jobs(text):
    body = text.split("\njobs:\n", 1)[1]
    starts = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\s*$", body, re.MULTILINE))
    return {item[1]: body[item.end():starts[index + 1].start() if index + 1 < len(starts) else len(body)]
            for index, item in enumerate(starts)}


def steps(job):
    starts = list(re.finditer(r"^      - (?:name: (.+)|uses: (.+))$", job, re.MULTILINE))
    return [(item[1] or item[2], job[item.end():starts[index + 1].start() if index + 1 < len(starts) else len(job)])
            for index, item in enumerate(starts)]


def policy():
    spec = importlib.util.spec_from_file_location("matrix_policy", ROOT / ".github/ci/policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MatrixWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.job = jobs(self.text)[JOB]

    def test_dispatch_inputs_are_typed_default_off_and_exclusive(self):
        header = self.text.split("\njobs:\n", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", header.split("\non:\n", 1)[1].split("\npermissions:", 1)[0], re.MULTILINE),
                         ["workflow_dispatch"])
        block = re.search(r"^      controlled_network_matrix:\n((?:        [^\n]*\n)+)", header, re.MULTILINE)[1]
        self.assertIn("        type: boolean\n", block)
        self.assertIn("        default: false\n", block)
        self.assertIn("permissions:\n  contents: read\n", header)
        gate = next(line for line in self.job.splitlines() if line.startswith("    if:"))
        self.assertEqual(gate + "\n", MATRIX_IF)
        for other in ("resolve", "direct-feedback"):
            self.assertIn("!inputs.controlled_network_matrix", jobs(self.text)[other])

    def test_group_input_is_a_closed_choice_passed_only_to_the_phase_step(self):
        header = self.text.split("\njobs:\n", 1)[0]
        block = re.search(r"^      controlled_network_group:\n((?:        [^\n]*\n)+)", header, re.MULTILINE)[1]
        self.assertIn("        type: choice\n", block)
        self.assertEqual(re.findall(r"^          - (\w+)$", block, re.MULTILINE), ["base", "nat", "faults"])
        self.assertIn("        default: base\n", block)
        phase_step = dict(steps(self.job))["Run the bounded privileged phase (the only step using sudo)"]
        self.assertIn("MATRIX_GROUP: ${{ inputs.controlled_network_group }}", phase_step)
        self.assertIn('--group "$MATRIX_GROUP"', phase_step)
        self.assertEqual(self.job.count("controlled_network_group"), 1)
        phase = (ROOT / ".github/probes/nat-topology/quic/product/runtime/phase.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--group", choices=sorted(GROUPS), default="base")', phase)

    def test_job_is_fail_closed_bounded_and_privileged_only_in_one_step(self):
        self.assertIn("    runs-on: ubuntu-latest\n", self.job)
        self.assertIn("    timeout-minutes: 90\n", self.job)
        self.assertNotIn("continue-on-error", self.job)
        for forbidden in ("apt-get", "apt ", "pip install", "curl ", "wget", "dpkg", "modprobe", "sysctl", "iptables"):
            self.assertNotIn(forbidden, self.job)
        ordered = steps(self.job)
        names = [name for name, _ in ordered]
        expected = ["Validate exclusive controlled-network request and source", "Checkout the exact reviewed source",
                    "Verify checked-out source revision"]
        self.assertEqual(names[:3], expected)
        privileged = [name for name, body in ordered if "sudo" in body]
        self.assertEqual(privileged, ["Run the bounded privileged phase (the only step using sudo)"])
        self.assertEqual(names.index(privileged[0]), len(names) - 2)
        phase_step = dict(ordered)[privileged[0]]
        self.assertEqual(phase_step.count("sudo"), 2)
        self.assertIn("runtime/phase.py", phase_step)
        self.assertIn('--source "$SOURCE_REVISION"', phase_step)
        self.assertIn("timeout-minutes: 22", phase_step)
        for name, body in ordered[:3]:
            self.assertNotIn("sudo", body)
        checkout = dict(ordered)[expected[1]]
        self.assertIn("ref: ${{ inputs.source_revision }}", checkout)
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_REVISION"', dict(ordered)[expected[2]])
        upload = ordered[-1][1]
        self.assertIn("if: always()", upload)
        self.assertIn("if-no-files-found: error", upload)

    def test_source_and_mode_validation_runs_before_checkout_and_rejects_bad_requests(self):
        validation = dict(steps(self.job))["Validate exclusive controlled-network request and source"]
        body = validation.split("          python3 -I - <<'PYTHON'\n", 1)[1].split("          PYTHON\n", 1)[0]
        code = "\n".join(line[10:] for line in body.splitlines()) + "\n"
        run = lambda revision, direct="false", preflight="false": subprocess.run(
            [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=10,
            env={"SOURCE_REVISION": revision, "DIRECT_FEEDBACK": direct, "PREFLIGHT": preflight})
        self.assertEqual(run("a" * 40).returncode, 0)
        for revision in ("", "develop", "A" * 40, "a" * 39, "a" * 41, "a" * 40 + "\n", "a" * 40 + "; id"):
            with self.subTest(revision=repr(revision)):
                self.assertEqual(run(revision).returncode, 1)
        self.assertEqual(run("a" * 40, direct="true").returncode, 1)
        self.assertEqual(run("a" * 40, preflight="true").returncode, 1)
        self.assertEqual(run("a" * 40, direct="").returncode, 1)

    def test_owned_paths_map_to_the_ordinary_policy_job_without_unknown_ownership(self):
        module = policy()
        for path in (".github/probes/nat-topology/run.sh", ".github/probes/nat-topology/quic/product/runtime/phase.py",
                     ".github/probes/nat-topology/quic/product/runtime/tests/phase_tests.py",
                     ".github/workflows/sdk-lock.yml", ".github/ci/run.py"):
            with self.subTest(path=path):
                selected = module.select([path])
                self.assertEqual(selected["suites"], ["ci_policy"])
                self.assertEqual(selected["targets"], [])
                self.assertFalse(selected["selection"]["full"])


if __name__ == "__main__":
    unittest.main()
