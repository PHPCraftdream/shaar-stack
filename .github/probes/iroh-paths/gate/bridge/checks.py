"""CI-only rejection controls for the owned source-data preparation script."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


class PreparationChecks(unittest.TestCase):
    def run_prepare(self, archive, probe, destination):
        return subprocess.run(
            [sys.executable, "-I", str(Path(__file__).with_name("prepare.py")),
             "--archive", str(archive), "--probe", str(probe),
             "--noq-source", str(self.args.noq_source),
             "--runtime-source", str(self.args.runtime_source),
             "--destination", str(destination)],
            text=True, capture_output=True, timeout=30,
        )

    def test_corrupt_archive_is_rejected_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "invalid.crate"
            archive.write_bytes(b"not the reviewed archive")
            destination = root / "destination"
            result = self.run_prepare(archive, self.args.probe, destination)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match reviewed lock checksum", result.stderr)
            self.assertFalse(destination.exists())

    def test_wrong_lock_checksum_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = (self.args.probe / "Cargo.lock").read_text(encoding="utf-8")
            entry = next(p for p in tomllib.loads(lock)["package"] if p["name"] == "iroh")
            (root / "Cargo.lock").write_text(lock.replace(entry["checksum"], "0" * 64), encoding="utf-8")
            destination = root / "destination"
            result = self.run_prepare(self.args.archive, root, destination)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match reviewed lock checksum", result.stderr)
            self.assertFalse(destination.exists())

    def test_existing_destination_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "destination"
            destination.mkdir()
            marker = destination / "owned-marker"
            marker.write_bytes(b"preserve")
            result = self.run_prepare(self.args.archive, self.args.probe, destination)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FileExistsError", result.stderr)
            self.assertEqual(marker.read_bytes(), b"preserve")
            self.assertEqual(list(destination.iterdir()), [marker])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--noq-source", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    PreparationChecks.args = parser.parse_args()
    unittest.main(argv=[sys.argv[0]])
