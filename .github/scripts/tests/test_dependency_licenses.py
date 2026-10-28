"""Focused regression tests for the dependency-license gate (CI only)."""
from __future__ import annotations

import hashlib
import importlib.util
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

    def test_action_keeps_check_and_report_upload_failures_gating(self):
        action = (SCRIPT.parents[1] / "actions" / "dependency-license" / "action.yml").read_text()
        import re
        steps = re.split(r"(?m)^    - name: ", action)[1:]
        by_name = {part.splitlines()[0]: part for part in steps}
        check = by_name["Check dependency licenses (locked graph)"]
        report = by_name["Preserve dependency license report"]
        upload = by_name["Upload dependency license report"]
        enforce = by_name["Enforce dependency license gate result"]
        self.assertIn("continue-on-error: true", check)
        self.assertNotIn("continue-on-error", report)
        self.assertNotIn("continue-on-error", upload)
        self.assertIn("if: always()", report)
        self.assertIn("if: always()", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn('test "${{ steps.check.outcome }}" = success', enforce)


if __name__ == "__main__":
    unittest.main()
