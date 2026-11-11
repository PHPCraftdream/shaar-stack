"""Workflow routing contracts for the repository's fixed layout, not a generic YAML parser."""

import hashlib
import importlib.util
import os
import tomllib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def named_steps(text):
    starts = list(re.finditer(r"^      - name: (.+)$", text, re.MULTILINE))
    return {match[1]: text[match.end():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
            for index, match in enumerate(starts)}


def job_blocks(text):
    starts = list(re.finditer(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*$", text, re.MULTILINE))
    jobs_start = text.find("jobs:\n")
    return {match[1]: text[match.end():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
            for index, match in enumerate(starts) if match.start() > jobs_start}


def validate_capture_helper(text):
    required = (
        'local log_dir="target/native-graph-preparation-logs"',
        'mkdir -p "$log_dir"',
        'stdout_log="${log_dir}/${stem}.stdout.log"',
        'stderr_log="${log_dir}/${stem}.stderr.log"',
        'status_log="${log_dir}/${stem}.status"',
        "exec 3>&1 4>&2",
        "exec 1>&3 2>&4",
        'wait "$stdout_pid"',
        'wait "$stderr_pid"',
        "trap capture_finish EXIT",
        'printf \'%s\\n\' "$status" > "$status_log"',
        "if ((status == 0 && tee_status != 0)); then",
    )
    for fragment in required:
        if fragment not in text:
            raise AssertionError("capture helper is missing required contract: " + fragment)


def validate_native_graph_routing(text):
    jobs = job_blocks(text)
    manual = jobs.get("native_graph_resolve", "")
    checks = jobs.get("checks", "")
    manual_if = next((line for line in manual.splitlines() if line.startswith("    if:")), "")
    if manual_if != "    if: github.event_name == 'workflow_dispatch' && inputs.native_graph_resolve":
        raise AssertionError("manual resolver job must be dispatch-input gated")
    checks_if = next((line for line in checks.splitlines() if line.startswith("    if:")), "")
    if checks_if != "    if: ${{ !(github.event_name == 'workflow_dispatch' && inputs.native_graph_resolve) }}":
        raise AssertionError("ordinary checks must exclude manual resolver dispatch")
    prepare = re.search(r"^      - uses: \.\/.github/actions/prepare-sources\n(?P<body>.*?)(?=^      - |\Z)", checks, re.MULTILINE | re.DOTALL)
    owners = ("product", "dns", "discovery", "carrier", "carrier_frames", "relay", "resolver", "kad", "backend", "sdk", "apps", "license", "ygg")
    if not prepare:
        raise AssertionError("ordinary prepare-sources action is missing")
    body = prepare["body"]
    owner_if = next((line for line in body.splitlines() if line.startswith("        if:")), "")
    if ("fromJSON(needs.plan.outputs.selection).native_graph" not in owner_if
            or "native_graph_resolve" in owner_if
            or any("fromJSON(needs.plan.outputs.selection)." + owner not in owner_if for owner in owners)):
        raise AssertionError("ordinary prepare-sources owner gate is invalid")
    if 'resolve_only: "true"' not in manual or '"native_graph":true' not in manual:
        raise AssertionError("manual resolver must select native_graph with resolve_only")
    if not re.search(r"^      - name: Resolve native graph candidate\n        run: python -I \.github/probes/native-graph/ci.py resolve$", manual, re.MULTILINE):
        raise AssertionError("manual resolver command is missing")
    candidate = named_steps(text).get("Preserve native graph candidate evidence", "")
    verification = named_steps(text).get("Preserve native graph verification receipt", "")
    future_dev_files = ("target/native-graph-future-dev/Cargo.toml", "target/native-graph-future-dev/Cargo.lock")
    if any(path not in verification for path in future_dev_files):
        raise AssertionError("verification artifact must preserve exact future-dev manifest and lock paths")
    candidate_paths = ("Cargo.lock", "target/native-graph/Cargo.before.lock", "target/native-graph/Cargo.candidate.lock",
                       "target/native-graph/ci-receipt.json", "target/native-graph/logs/",
                       "target/native-graph/*.provenance.json")
    if any(path not in {line.strip() for line in candidate.splitlines()} for path in candidate_paths):
        raise AssertionError("candidate artifact must preserve exact lock, receipt, logs, and provenance paths")
    if "target/native-graph-future-dev/" in candidate or "target/native-graph-evidence/" in candidate:
        raise AssertionError("candidate artifact must not include future-dev or evidence directories")
    if "if: always()" not in candidate or "if-no-files-found: error" not in candidate:
        raise AssertionError("candidate artifact must preserve raw logs with fail-closed upload")
    preparation = named_steps(text).get("Preserve native graph preparation diagnostics", "")
    if ("if: always()" not in preparation or "target/native-graph-preparation-logs/" not in preparation
            or "if-no-files-found: error" not in preparation or "name: native-graph-preparation-diagnostics" not in preparation):
        raise AssertionError("preparation diagnostics require a distinct always-uploaded artifact")
    if "Cargo.lock" in preparation:
        raise AssertionError("preparation diagnostics must not fall back to Cargo.lock")


def validate_preparation_logs(action):
    starts = list(re.finditer(r"^    - name: (.+)$", action, re.MULTILINE))
    steps = {match[1]: action[match.end():starts[index + 1].start() if index + 1 < len(starts) else len(action)]
             for index, match in enumerate(starts)}
    expected = {
        "Prepare native graph source archives": "native-graph",
        "Prepare reviewed production backend sources": "backend",
        "Prepare reviewed strict DNS parser dependency": "simple-dns",
        "Prepare reviewed signaling dependencies and expiry controls": "relay",
        "Prepare reviewed DNS expansion boundary": "dns",
        "Prepare reviewed resolver locking boundary": "resolver",
        "Prepare reviewed Kademlia referral retention": "kad",
        "Prepare reviewed Yggdrasil-ng core sources": "ygg",
    }
    if set(steps) != set(expected):
        raise AssertionError("preparation action must contain the eight logged source preparation steps")
    for name, stem in expected.items():
        block = steps[name]
        if ("set -euo pipefail" not in block or ".github/actions/prepare-sources/capture.sh " + stem not in block):
            raise AssertionError("source preparation step must capture stdout, stderr, and exact status")


def validate_plan_control_transport(text):
    plan = job_blocks(text).get("plan", "")
    checks = job_blocks(text).get("checks", "")
    mainline = named_steps(text).get("Verify mainline lifecycle archive against planned revision", "")
    required = (
        ("control_metadata: ${{ steps.plan.outputs.control_metadata }}", plan),
        ("selection: ${{ steps.plan.outputs.selection }}", plan),
        ("targets: ${{ steps.plan.outputs.targets }}", plan),
        ("uses: actions/upload-artifact@", plan),
        ("name: ci-selection", plan),
        ("path: ci-plan.json", plan),
        ("if-no-files-found: error", plan),
        ("CI_PLAN_JSON: ${{ needs.plan.outputs.control_metadata }}", checks),
        ("CI_TARGETS: ${{ needs.plan.outputs.targets }}", checks),
        ("os: [ubuntu-latest, windows-latest]", checks),
        ('p=json.loads(os.environ["CI_PLAN_JSON"])', mainline),
        ('--plan-json "$CI_PLAN_JSON"', mainline),
    )
    for fragment, block in required:
        if fragment not in block:
            raise AssertionError("CI plan transport is missing required contract: " + fragment)
    if ("receipt: ${{" in plan or "steps.receipt.outputs" in plan or "- id: receipt" in plan
            or "json=json.dumps(data,separators=(',',':'))" in plan):
        raise AssertionError("full receipt output or compaction step must remain removed")
    if "CI_PLAN_CONTROL_JSON" in checks:
        raise AssertionError("checks must use only the established CI_PLAN_JSON name")
    if checks.index("CI_PLAN_JSON:") > checks.index("- uses: actions/checkout@"):
        raise AssertionError("bounded plan metadata must be available before checkout")


def validate_privileged_nat_routing(text, job_name):
    """Check the two fixed legacy workflow layouts, not arbitrary YAML."""
    header = text.split("\njobs:\n", 1)[0]
    if "on:\n  workflow_dispatch:\n    inputs:\n" not in header:
        raise AssertionError("privileged NAT workflows must declare typed dispatch inputs")
    events = header.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    if (re.findall(r"^  ([A-Za-z_][A-Za-z0-9_-]*):", events, re.MULTILINE) != ["workflow_dispatch"]
            or "permissions:\n  contents: read\n" not in header):
        raise AssertionError("privileged NAT workflows must be dispatch-only and read-only")
    revision = re.search(r"^      source_revision:\n((?:        [^\n]*\n)+)", header, re.MULTILINE)
    opt_in = re.search(r"^      allow_legacy_calibration:\n((?:        [^\n]*\n)+)", header, re.MULTILINE)
    if (not revision or "        type: string\n" not in revision[1]
            or "        required: true\n" not in revision[1] or "default:" in revision[1]
            or not opt_in or "        type: boolean\n" not in opt_in[1]
            or "        default: false\n" not in opt_in[1]):
        raise AssertionError("exact revision and default-off calibration inputs are required")
    job = job_blocks(text).get(job_name, "")
    if not re.search(r"^    runs-on: ubuntu-latest$", job, re.MULTILINE):
        raise AssertionError("privileged calibration must stay on a disposable Ubuntu runner")
    gate = next((line for line in job.splitlines() if line.startswith("    if:")), "")
    if gate != "    if: github.event_name == 'workflow_dispatch'" or "continue-on-error:" in job:
        raise AssertionError("manual preflight must run fail-closed, not skip to an empty green")
    steps = named_steps(job)
    names = ("Validate reviewed source revision", "Checkout", "Verify checked-out source revision")
    if any(name not in steps or job.count("- name: " + name) != 1 for name in names):
        raise AssertionError("source validation/checkout/verification steps must be unique")
    validation, checkout, verification = (steps[name] for name in names)
    source_env = "SOURCE_REVISION: ${{ inputs.source_revision }}"
    if (source_env not in validation or "python3 -I -" not in validation
            or "ALLOW_LEGACY_CALIBRATION: ${{ inputs.allow_legacy_calibration }}" not in validation
            or 'if os.environ["ALLOW_LEGACY_CALIBRATION"] != "true":' not in validation
            or 'revision = os.environ["SOURCE_REVISION"]' not in validation
            or 'if not re.fullmatch(r"[0-9a-f]{40}", revision):' not in validation
            or "raise SystemExit(" not in validation):
        raise AssertionError("revision validation must fail closed before checkout")
    if ("ref: ${{ inputs.source_revision }}" not in checkout
            or "persist-credentials: false" not in checkout):
        raise AssertionError("checkout must use the exact input without retained credentials")
    run = next((line.strip() for line in verification.splitlines() if line.startswith("        run:")), "")
    if source_env not in verification or run != 'run: test "$(git rev-parse HEAD)" = "$SOURCE_REVISION"':
        raise AssertionError("checked-out revision must equal the validated source input")
    positions = [job.index("- name: " + name) for name in names]
    privilege = job.find("sudo")
    if positions != sorted(positions) or privilege < positions[-1]:
        raise AssertionError("all source checks must precede every legacy privileged step")


class WorkflowTests(unittest.TestCase):
    def test_privileged_nat_workflows_are_manual_source_bound_and_owned(self):
        spec = importlib.util.spec_from_file_location("nat_workflow_policy", ROOT / ".github/ci/policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        for filename, job in (("nat-topology.yml", "fixture"), ("quic-nat.yml", "proof")):
            with self.subTest(workflow=filename):
                validate_privileged_nat_routing((ROOT / ".github/workflows" / filename).read_text(encoding="utf-8"), job)
                selected = policy.select([".github/workflows/" + filename])
                self.assertEqual(selected["suites"], ["ci_policy"])
                self.assertEqual(selected["targets"], [])
                self.assertTrue(selected["selection"]["ci_policy"])
                self.assertFalse(selected["selection"]["full"])
                self.assertFalse(selected["selection"]["rust"])

    def test_privileged_nat_routing_rejects_automatic_and_unreviewed_changes(self):
        gate = "    if: github.event_name == 'workflow_dispatch'"
        for filename, job in (("nat-topology.yml", "fixture"), ("quic-nat.yml", "proof")):
            text = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            mutations = (
                text.replace("on:\n  workflow_dispatch:", "on:\n  push:\n  workflow_dispatch:", 1),
                text.replace("default: false", "default: true", 1),
                text.replace(gate, "    if: true", 1),
                text.replace("ref: ${{ inputs.source_revision }}", "ref: develop", 1),
                text.replace("persist-credentials: false", "persist-credentials: true", 1),
                text.replace("python3 -I -", "python3 -", 1),
                text.replace("if not re.fullmatch", "if re.fullmatch", 1),
                text.replace('run: test "$(git rev-parse HEAD)" = "$SOURCE_REVISION"',
                             'run: test "$(git rev-parse HEAD)" = "$SOURCE_REVISION" || true', 1),
                text.replace("  contents: read", "  contents: write", 1),
                text.replace("runs-on: ubuntu-latest", "runs-on: self-hosted", 1),
                text.replace('if os.environ["ALLOW_LEGACY_CALIBRATION"] != "true":', 'if False:', 1),
                text.replace("- name: Validate reviewed source revision\n",
                             "- name: Validate reviewed source revision\n        continue-on-error: true\n", 1),
            )
            for index, changed in enumerate(mutations):
                with self.subTest(workflow=filename, mutation=index):
                    self.assertNotEqual(changed, text)
                    with self.assertRaises(AssertionError):
                        validate_privileged_nat_routing(changed, job)

    def test_privileged_nat_revision_preflight_executes_without_privilege(self):
        for filename in ("nat-topology.yml", "quic-nat.yml"):
            text = (ROOT / ".github/workflows" / filename).read_text(encoding="utf-8")
            validation = named_steps(text)["Validate reviewed source revision"]
            body = validation.split("          python3 -I - <<'PYTHON'\n", 1)[1].split("          PYTHON\n", 1)[0]
            code = "\n".join(line[10:] for line in body.splitlines()) + "\n"
            for revision in ("a" * 40, "", "develop", "A" * 40, "a" * 39, "a" * 41,
                             "a" * 39 + "g", "a" * 40 + "\n", "a" * 40 + "; printf injected"):
                with self.subTest(workflow=filename, revision=repr(revision)):
                    result = subprocess.run([sys.executable, "-I", "-c", code],
                                            env={**os.environ, "SOURCE_REVISION": revision,
                                                 "ALLOW_LEGACY_CALIBRATION": "true"},
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if revision == "a" * 40 else 1, result.stderr)
            for opt_in in ("false", "", "TRUE", "1"):
                with self.subTest(workflow=filename, opt_in=opt_in):
                    result = subprocess.run([sys.executable, "-I", "-c", code],
                                            env={**os.environ, "SOURCE_REVISION": "a" * 40,
                                                 "ALLOW_LEGACY_CALIBRATION": opt_in},
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("explicit separate authorization", result.stderr)

    def test_sdk_publisher_dev_codec_resolution_changes_only_one_existing_edge(self):
        sdk = tomllib.loads((ROOT / "crates/shaar/Cargo.toml").read_text(encoding="utf-8"))
        self.assertNotIn("serde_bencode", sdk["dependencies"])
        self.assertEqual(sdk["dev-dependencies"]["serde_bencode"], "=0.2.4")
        self.assertIn("test-util", sdk["dev-dependencies"]["tokio"]["features"])
        self.assertNotIn("test-util", sdk["dependencies"]["tokio"]["features"])
        spec = importlib.util.spec_from_file_location("publisher_lock_graph", ROOT / ".github/probes/native-graph/graph.py")
        graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(graph)
        text = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
        marker = '[[package]]\nname = "shaar"\n'
        prefix, rest = text.split(marker, 1)
        body, suffix = rest.split("\n[[package]]", 1)
        before_body = body.replace(' "serde_bencode",\n', '')
        after_body = before_body.replace('dependencies = [\n', 'dependencies = [\n "serde_bencode",\n', 1)
        def lock_bytes(value):
            return (prefix + marker + value + "\n[[package]]" + suffix).encode()
        before, after = lock_bytes(before_body), lock_bytes(after_body)
        result = graph.audit_lock_delta(before, after)
        self.assertEqual(result, {"added": [], "removed": [], "source_changed": []})
        for changed in (
            after_body.replace(' "n0-mainline",\n', ''),
            after_body.replace(' "serde_bencode",\n', ' "serde_bencode",\n "serde_bencode",\n'),
            after_body.replace(' "serde_bencode",\n', ' "serde_bencode",\n "unapproved",\n'),
            after_body.replace('dependencies = [\n', 'extra = "forged"\ndependencies = [\n', 1),
        ):
            with self.subTest(body=changed), self.assertRaises(ValueError):
                graph.audit_lock_delta(before, lock_bytes(changed))
        altered_dns = after.replace(b'name = "iroh-dns"\n', b'name = "iroh-dns"\nextra = "forged"\n', 1)
        altered_version = after.replace(b'name = "serde_bencode"\nversion = "0.2.4"',
                                        b'name = "serde_bencode"\nversion = "0.2.5"', 1)
        for changed in (altered_dns, altered_version):
            self.assertNotEqual(changed, after)
            with self.assertRaises(ValueError):
                graph.audit_lock_delta(before, changed)

    def test_workflow_extraction_preserves_exact_commands_and_structural_contract(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertLessEqual(len(text.splitlines()), 700)
        witness = ROOT / ".github/probes/native-graph/fixture/witness.rs"
        self.assertEqual(witness.read_text(encoding="utf-8").splitlines()[0], "#![forbid(unsafe_code)]")
        steps = named_steps(text)
        for name, script, digest in (
            ("Verify high-PTO shutdown negative control after production proofs", "protocol_close.sh",
             "3ab60d371da20ecac726b5989d7a017dcbc7c60bec2f01be5755c3443ac87af1"),
            ("Diagnose native-after-signaling path lifecycle (Windows only)", "windows_native_lifecycle.sh",
             "86ee241ef65937721ba083c7c5e7c1aa21c8caf053a77aecc9409595c2a4f257"),
        ):
            relative = ".github/probes/iroh-paths/ci/" + script
            self.assertIn("run: bash " + relative, steps[name])
            self.assertIn("shell: bash", steps[name])
            lines = (ROOT / relative).read_text(encoding="utf-8").splitlines(keepends=True)
            self.assertEqual(lines[0], "#!/usr/bin/env bash\n")
            self.assertEqual(hashlib.sha256("".join(lines[3:]).encode()).hexdigest(), digest)
            from test_plan import POLICY
            impact = POLICY.select([relative])
            self.assertTrue(impact["selection"]["ci_policy"])
            self.assertFalse(any(impact["selection"][owner] for owner in POLICY.DOMAINS))
            self.assertEqual(impact["targets"], [])
        self.assertIn("matrix.os == 'windows-latest' && fromJSON(needs.plan.outputs.selection).full",
                      steps["Diagnose native-after-signaling path lifecycle (Windows only)"])

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
            "Verify mainline lifecycle archive against planned revision": "mainline",
            "Verify supplied timestamp encoder against archive graph": "publication",
            "cargo test": "full",
        }
        for name, owner in expected.items():
            with self.subTest(step=name):
                self.assertTrue(steps[name].startswith("\n        if: fromJSON(needs.plan.outputs.selection)." + owner + "\n"))

    def test_publication_has_own_runner_archives_and_always_evidence(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        runner = steps["Verify supplied timestamp encoder against archive graph"]
        script = ".github/scripts/p2p/discovery/mainline/ci/publication/execution/verify.sh"
        self.assertIn("bash " + script, runner)
        execution = (ROOT / script).read_text(encoding="utf-8")
        self.assertIn("python -I .github/scripts/p2p/discovery/mainline/ci/publication/execution/ci.py", execution)
        self.assertIn("https://static.crates.io/crates/iroh-dns/iroh-dns-1.3.0.crate", execution)
        self.assertIn("https://static.crates.io/crates/simple-dns/simple-dns-0.12.0.crate", execution)
        self.assertNotIn("cargo test --workspace", runner)
        evidence = steps["Preserve supplied timestamp encoder evidence"]
        self.assertIn("always() && fromJSON(needs.plan.outputs.selection).publication", evidence)
        self.assertIn("if-no-files-found: error", evidence)
        self.assertIn("target/publication-evidence/", evidence)

    def test_plan_control_transport_is_bounded_and_published_before_checkout(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertLessEqual(len(text.splitlines()), 700)
        validate_plan_control_transport(text)
        plan = job_blocks(text)["plan"]
        checks = job_blocks(text)["checks"]
        self.assertNotIn("CI_PLAN_CONTROL_JSON", checks)

    def test_plan_control_transport_rejects_full_receipt_counterfactuals(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            text.replace("CI_PLAN_JSON: ${{ needs.plan.outputs.control_metadata }}",
                         "CI_PLAN_JSON: ${{ needs.plan.outputs.receipt }}", 1),
            text.replace("control_metadata: ${{ steps.plan.outputs.control_metadata }}",
                         "receipt: ${{ steps.receipt.outputs.json }}", 1),
            text.replace("      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        with:\n          name: ci-selection\n          path: ci-plan.json\n          if-no-files-found: error\n", "", 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation != text):
                self.assertNotEqual(mutation, text)
                with self.assertRaises(AssertionError):
                    validate_plan_control_transport(mutation)

    def test_mainline_archive_gate_and_prepare_sources_routing(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        steps = named_steps(text)
        mainline = steps["Verify mainline lifecycle archive against planned revision"]
        self.assertIn("python -I -m unittest discover -s .github/scripts/p2p/discovery/mainline/ci -p 'test_*.py'", mainline)
        self.assertIn('"CI_PLAN_JSON"', mainline)
        self.assertIn('p["head"]', mainline)
        self.assertIn('p["base"]', mainline)
        self.assertIn('p["scope"]', mainline)
        self.assertIn("https://static.crates.io/crates/n0-mainline/n0-mainline-0.7.0.crate", mainline)
        self.assertIn("--plan-json \"$CI_PLAN_JSON\"", mainline)
        self.assertIn("https://static.crates.io/crates/serde_bencode/serde_bencode-0.2.4.crate", mainline)
        self.assertIn("--bencode-archive target/mainline-archive/serde_bencode-0.2.4.crate", mainline)
        evidence = steps["Preserve mainline lifecycle evidence"]
        self.assertIn("always() && fromJSON(needs.plan.outputs.selection).mainline", evidence)
        self.assertIn("if-no-files-found: error", evidence)
        ordinary_checks = text.split("  checks:\n", 1)[1]
        prepare = next(step for step in ordinary_checks.split("      - ") if "./.github/actions/prepare-sources" in step)
        for owner in ("product", "dns", "discovery", "carrier", "carrier_frames", "relay", "resolver", "kad", "backend", "sdk", "apps", "license", "ygg"):
            self.assertIn("fromJSON(needs.plan.outputs.selection)." + owner, prepare)
        self.assertNotIn("selection).mainline", prepare)
        validate_native_graph_routing(text)
        validate_preparation_logs((ROOT / ".github/actions/prepare-sources/action.yml").read_text(encoding="utf-8"))

    def test_native_graph_routing_rejects_broken_dispatch_and_selection_gates(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        validate_native_graph_routing(text)
        mutations = (
            ("if: github.event_name == 'workflow_dispatch' && inputs.native_graph_resolve", "if: always()"),
            ("if: ${{ !(github.event_name == 'workflow_dispatch' && inputs.native_graph_resolve) }}", "if: always()"),
            ("selection).product", "selection).not_product"),
            ('resolve_only: "true"', 'resolve_only: "false"'),
            ('"native_graph":true', '"native_graph":false'),
            ("    if: github.event_name == 'workflow_dispatch' && inputs.native_graph_resolve\n", ""),
            ("    if: ${{ !(github.event_name == 'workflow_dispatch' && inputs.native_graph_resolve) }}\n", ""),
            ('          resolve_only: "true"\n', ""),
            ("target/native-graph-preparation-logs/", "target/native-graph/"),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, text)
                with self.assertRaises(AssertionError):
                    validate_native_graph_routing(text.replace(old, new, 1))

    def test_candidate_evidence_rejects_missing_logs_and_always_upload(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        candidate = named_steps(text)["Preserve native graph candidate evidence"]
        verification = named_steps(text)["Preserve native graph verification receipt"]
        self.assertTrue(all(path in verification for path in ("target/native-graph-future-dev/Cargo.toml", "target/native-graph-future-dev/Cargo.lock")))
        for old, new in (("            Cargo.lock\n", ""), ("target/native-graph/logs/", "target/native-graph/not-logs/"),
                         ("if: always()", "if: failure()"),
                         ("if-no-files-found: error", "if-no-files-found: warn"),
                         ("target/native-graph/Cargo.before.lock", "target/native-graph/*"),
                         ("target/native-graph/*.provenance.json", "target/native-graph/provenance.json")):
            with self.subTest(mutation=old):
                self.assertIn(old, candidate)
                with self.assertRaises(AssertionError):
                    validate_native_graph_routing(text.replace(candidate, candidate.replace(old, new, 1), 1))

        for path in ("target/native-graph-future-dev/Cargo.toml", "target/native-graph-evidence/"):
            with self.subTest(injected_path=path):
                with self.assertRaises(AssertionError):
                    validate_native_graph_routing(text.replace(candidate, candidate + "\n          - " + path, 1))

    def test_capture_helper_preserves_logs_on_initial_failure(self):
        helper = (ROOT / ".github/actions/prepare-sources/capture.sh").resolve().as_posix()
        with tempfile.TemporaryDirectory() as temporary:
            for status in (23, 0):
                with self.subTest(status=status):
                    script = (
                        "set -eu; source \"" + helper + "\" test-" + str(status) + "; "
                        "printf 'stdout message\\n'; printf 'stderr message\\n' >&2; exit " + str(status)
                    )
                    result = subprocess.run(["bash", "-c", script], cwd=temporary, capture_output=True, text=True)
                    log_dir = Path(temporary) / "target/native-graph-preparation-logs"
                    self.assertEqual(result.returncode, status)
                    self.assertEqual((log_dir / f"test-{status}.stdout.log").read_text(), "stdout message\n")
                    self.assertEqual((log_dir / f"test-{status}.stderr.log").read_text(), "stderr message\n")
                    self.assertEqual((log_dir / f"test-{status}.status").read_text(), f"{status}\n")

    def test_capture_helper_contract_rejects_missing_stderr_wait(self):
        helper = (ROOT / ".github/actions/prepare-sources/capture.sh").read_text(encoding="utf-8")
        validate_capture_helper(helper)
        old = '    wait "$stderr_pid" || tee_status=$?\n'
        self.assertIn(old, helper)
        with self.assertRaises(AssertionError):
            validate_capture_helper(helper.replace(old, "", 1))

    def test_product_source_preparation_diagnostics_contract(self):
        steps = named_steps(WORKFLOW.read_text(encoding="utf-8"))
        preparation = steps["Preserve source preparation diagnostics"]
        self.assertIn("if: always()", preparation)
        self.assertIn("steps.prepare_sources.outcome != 'skipped'", preparation)
        self.assertIn("''", preparation)
        self.assertIn("target/native-graph-preparation-logs/", preparation)
        self.assertIn("if-no-files-found: error", preparation)
        self.assertNotIn("Cargo.lock", preparation)

    def test_preparation_logs_reject_missing_capture_call(self):
        action = (ROOT / ".github/actions/prepare-sources/action.yml").read_text(encoding="utf-8")
        broken = action.replace("source .github/actions/prepare-sources/capture.sh native-graph\n", "", 1)
        with self.assertRaises(AssertionError):
            validate_preparation_logs(broken)

    def test_future_archive_arguments_are_present(self):
        action = (ROOT / ".github/actions/prepare-sources/action.yml").read_text(encoding="utf-8")
        self.assertIn("--future-archive target/native-graph-archives/n0-future-0.3.2.crate", action)
        self.assertIn("--output target/native-graph-archives/n0-future-0.3.2.crate", action)

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
