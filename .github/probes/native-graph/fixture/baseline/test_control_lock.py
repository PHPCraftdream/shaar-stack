# SPDX-License-Identifier: MIT OR Apache-2.0
"""Keep the three-role control independent of candidate dev-lock changes."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

import baseline

ROOT = Path(__file__).resolve().parents[5]


class ControlLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.argv = ["git", "show", baseline.APPROVED_LOCK_REVISION + ":Cargo.lock"]
        cls.accepted = subprocess.check_output(cls.argv, cwd=ROOT)

    def test_control_uses_exact_accepted_git_bytes_not_candidate_lock(self):
        calls = []

        def run(argv):
            calls.append(argv)
            return self.accepted

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, candidate = root / "baseline", root / "candidate"
            old.mkdir()
            candidate.mkdir()
            (old / "Cargo.lock").write_bytes(b"historical baseline lock")
            for changed in (b"candidate dev edge", b"unreviewed normal drift", b""):
                (candidate / "Cargo.lock").write_bytes(changed)
                control = baseline.projection_lock("approved_route", old, candidate, run)
                self.assertEqual(control, self.accepted)
                self.assertEqual(hashlib.sha256(control).hexdigest(), baseline.APPROVED_LOCK_SHA256)
                self.assertEqual((candidate / "Cargo.lock").read_bytes(), changed)
            self.assertEqual(calls, [self.argv] * 3)

    def test_baseline_and_candidate_keep_their_own_raw_lock_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, candidate = root / "baseline", root / "candidate"
            old.mkdir()
            candidate.mkdir()
            (old / "Cargo.lock").write_bytes(b"historical\r\n")
            (candidate / "Cargo.lock").write_bytes(b"candidate\n")

            def forbidden(argv):
                self.fail(f"non-control role must not read Git: {argv}")

            for role, expected in (("baseline", b"historical\r\n"), ("candidate", b"candidate\n")):
                self.assertEqual(baseline.projection_lock(role, old, candidate, forbidden), expected)
            with self.assertRaisesRegex(ValueError, "unknown projection lock role"):
                baseline.projection_lock("other", old, candidate, forbidden)

    def test_control_rejects_wrong_lock_bytes_without_normalizing_them(self):
        for raw in (b"", self.accepted + b"\n", self.accepted.replace(b"\n", b"\r\n"),
                    self.accepted.decode("utf-8"), None):
            with self.subTest(kind=type(raw).__name__), self.assertRaisesRegex(ValueError, "lock identity mismatch"):
                baseline.projection_lock("approved_route", ROOT, ROOT, lambda argv: raw)
