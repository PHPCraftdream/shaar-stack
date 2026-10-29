"""Focused regression tests for the dependency-license gate (CI only)."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "dependency_licenses.py"
spec = importlib.util.spec_from_file_location("dependency_licenses", SCRIPT)
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)
probe_path = SCRIPT.parents[1] / "actions" / "dependency-license" / "list_probe.py"
probe_spec = importlib.util.spec_from_file_location("license_list_probe", probe_path)
probe = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe)


class DependencyLicenseTests(unittest.TestCase):
    def test_bad_checksum_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp)
            with mock.patch.dict(os.environ, {"RUNNER_OS": "Linux", "RUNNER_TEMP": tmp}), \
                 mock.patch.object(licenses.tempfile, "TemporaryDirectory", return_value=mock.MagicMock(__enter__=lambda _: tmp, __exit__=lambda *args: None)), \
                 mock.patch.object(licenses.subprocess, "run") as run, \
                 mock.patch.object(licenses.tarfile, "open") as archive:
                def download(args, **kwargs):
                    Path(args[args.index("--output") + 1]).write_bytes(b"wrong archive")
                run.side_effect = download
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    licenses.install()
                archive.assert_not_called()

    def test_missing_and_malformed_receipts_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path.cwd()
            try:
                os.chdir(tmp)
                Path("Cargo.lock").write_text("lock")
                Path("Cargo.toml").write_text("manifest")
                Path(tmp, "dependency-licenses.log").write_text("ok")
                with mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
                    with self.assertRaisesRegex(FileNotFoundError, "missing required"):
                        licenses.report()
                    for rel in ("target/p2p/metadata.json", "target/p2p/graph-receipt.json", *licenses.RECEIPTS):
                        path = Path(rel)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("not-json" if rel == licenses.RECEIPTS[0] else "{}")
                    with self.assertRaises(json.JSONDecodeError):
                        licenses.report()
            finally:
                os.chdir(old)

    def test_check_returns_actual_tool_failure(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp, "RUNNER_OS": "Linux"}), \
             mock.patch.object(licenses.subprocess, "run", side_effect=lambda args, **kwargs: real_run([os.sys.executable, "-c", "import sys; print('denied'); sys.exit(17)"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=kwargs["timeout"])):
            self.assertEqual(licenses.check(), 17)
            self.assertEqual((Path(tmp) / "dependency-licenses.log").read_text().strip(), "denied")

    def test_check_preserves_unicode_report_with_cp1252_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
            result = subprocess.CompletedProcess([], 4, stdout="denied ├── package\n".encode("utf-8"))
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp, "RUNNER_OS": "Windows"}), \
                 mock.patch.object(licenses.subprocess, "run", return_value=result), \
                 mock.patch.object(licenses.sys, "stdout", output):
                self.assertEqual(licenses.check(), 4)
                self.assertIn("\\u251c\\u2500\\u2500", output.buffer.getvalue().decode("cp1252"))
                self.assertEqual((Path(tmp) / "dependency-licenses.log").read_text(encoding="utf-8"), "denied ├── package\n")
            output.close()

    def test_list_probe_checks_bounds_schema_duplicates_and_selection(self):
        iroh = "iroh 1.3.0 path+file:///work/target/backend/iroh/iroh-1.3.0"
        atto = "attohttpc 0.30.1 registry+https://example.invalid/index"
        prepared = [
            iroh,
            "noq 1.3.0 path+file:///work/target/backend/noq/noq-1.3.0",
            "noq-proto 1.3.0 path+file:///work/target/backend/noq-proto/noq-proto-1.3.0",
            "hickory-resolver 0.26.3 path+file:///work/target/p2p/resolver/hickory-resolver-0.26.3",
            "libp2p-dns 0.45.0 path+file:///work/target/p2p/dns/libp2p-dns-0.45.0",
            "libp2p-kad 0.49.0 path+file:///work/target/p2p/kad/libp2p-kad-0.49.0",
            "libp2p-relay 0.22.0 path+file:///work/target/p2p/relay/libp2p-relay-0.22.0",
            "libp2p-swarm 0.48.0 path+file:///work/target/p2p/swarm/libp2p-swarm-0.48.0",
        ]
        data = {item: {"licenses": ["MIT"]} for item in prepared}
        data[atto] = {"licenses": ["MPL-2.0"]}
        raw = json.dumps(data).encode()
        summary = probe.summarize(raw)
        self.assertEqual(summary["package_count"], 9)
        self.assertEqual(summary["selected"]["iroh"], [iroh])
        self.assertEqual(summary["selected"]["attohttpc"], [atto])
        with mock.patch.object(probe, "MAX_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds limit"):
                probe.summarize(raw)
        with mock.patch.object(probe, "MAX_PACKAGES", 1):
            with self.assertRaisesRegex(ValueError, "invalid license package list"):
                probe.summarize(raw)
        with mock.patch.object(probe, "MAX_ID_LENGTH", 1):
            with self.assertRaisesRegex(ValueError, "invalid package identifier"):
                probe.summarize(raw)
        with self.assertRaisesRegex(ValueError, "invalid license package list"):
            probe.summarize(b"[]")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            probe.summarize(b'{"x":{},"x":{}}')
        with self.assertRaisesRegex(ValueError, "invalid package license entry"):
            probe.summarize(json.dumps({iroh: {"licenses": None}}).encode())
        for item in prepared:
            missing = dict(data)
            del missing[item]
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                probe.summarize(json.dumps(missing).encode())
        wrong_path = dict(data)
        del wrong_path[iroh]
        wrong_path["iroh 1.3.0 path+file:///work/other/iroh-1.3.0"] = {"licenses": ["MIT"]}
        with self.assertRaisesRegex(ValueError, "unexpected source path"):
            probe.summarize(json.dumps(wrong_path).encode())
        ambiguous = dict(data)
        ambiguous["iroh 1.3.0 registry+https://example.invalid/index"] = {"licenses": ["MIT"]}
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            probe.summarize(json.dumps(ambiguous).encode())

    def test_list_probe_rejects_graph_policy_drift(self):
        policy = b'[graph]\nall-features = true\n[licenses]\ninclude-dev = true\ninclude-build = true\n'
        probe.validate_policy(policy)
        for before, after in [
            (b"all-features = true", b"all-features = false"),
            (b"include-dev = true", b"include-dev = false"),
            (b"include-build = true", b"include-build = false"),
        ]:
            with self.assertRaises(ValueError):
                probe.validate_policy(policy.replace(before, after))
        for option in [b"exclude-dev = true", b"exclude-unpublished = true", b"no-default-features = true", b'features = ["other"]']:
            with self.assertRaisesRegex(ValueError, "graph options diverge"):
                probe.validate_policy(policy.replace(b"[licenses]", option + b"\n[licenses]"))
        with mock.patch.object(probe, "MAX_POLICY_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "policy exceeds limit"):
                probe.validate_policy(policy)

    def test_action_keeps_check_and_report_upload_failures_gating(self):
        action = (SCRIPT.parents[1] / "actions" / "dependency-license" / "action.yml").read_text()
        import re
        steps = re.split(r"(?m)^    - name: ", action)[1:]
        by_name = {part.splitlines()[0]: part for part in steps}
        check = by_name["Check dependency licenses (locked graph)"]
        selected_graph = by_name["Inspect selected license graph"]
        report = by_name["Preserve dependency license report"]
        upload = by_name["Upload dependency license report"]
        enforce = by_name["Enforce dependency license gate result"]
        self.assertIn("continue-on-error: true", check)
        self.assertIn("--all-features list --format json --layout crate", selected_graph)
        self.assertNotIn("continue-on-error", selected_graph)
        self.assertNotIn("continue-on-error", report)
        self.assertNotIn("continue-on-error", upload)
        self.assertIn("if: always()", report)
        self.assertIn("if: always()", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn('test "${{ steps.check.outcome }}" = success', enforce)


if __name__ == "__main__":
    unittest.main()
