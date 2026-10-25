"""CI-only rejection controls for the owned source-data preparation script."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare import CID_PATH_DISPATCH, LEGACY_PATH_DISPATCH, pair_runtime_events  # noqa: E402


class PreparationChecks(unittest.TestCase):
    def test_path_timer_fixture_reversal_and_drift_guards(self):
        script = Path(__file__).resolve().parents[1] / "prepare.py"
        spec = importlib.util.spec_from_file_location("gate_prepare", script)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        path = self.args.noq_source / "src/tests/multipath.rs"
        before = path.read_bytes()
        patched = before.decode("utf-8")
        original = gate.path_timer_fixture(patched, reverse=True)
        self.assertEqual(hashlib.sha256(original.encode("utf-8")).hexdigest(), gate.MULTIPATH_DIGEST)
        self.assertEqual(gate.path_timer_fixture(original), patched)
        for text, reverse in ((patched, False), (original, True)):
            with self.subTest(reverse=reverse), self.assertRaises(ValueError):
                gate.path_timer_fixture(text, reverse=reverse)
        for old, new in gate.PATH_TEST_SWAPS:
            for text, anchor, reverse in ((original, old, False), (patched, new, True)):
                for replacement in ("changed fixture anchor", anchor + anchor):
                    with self.subTest(anchor=anchor, reverse=reverse), self.assertRaises(ValueError):
                        gate.path_timer_fixture(text.replace(anchor, replacement, 1), reverse=reverse)
        # No whole-file exemption: even unrelated upstream text must remain byte-exact.
        for text, reverse in ((original, False), (patched, True)):
            with self.subTest(reverse=reverse), self.assertRaisesRegex(ValueError, "reviewed archive"):
                gate.path_timer_fixture(text + "\n// unrelated mutation\n", reverse=reverse)
        self.assertEqual(path.read_bytes(), before)

    def run_prepare(self, archive, probe, destination):
        return subprocess.run(
            [sys.executable, "-I", str(Path(__file__).with_name("prepare.py")),
             "--archive", str(archive), "--probe", str(probe),
             "--noq-source", str(self.args.noq_source),
             "--runtime-source", str(self.args.runtime_source),
             "--destination", str(destination)],
            text=True, capture_output=True, timeout=30,
        )

    def test_runtime_event_pairing_preserves_other_source(self):
        for has_event, dispatch, expected in (
            (False, CID_PATH_DISPATCH, LEGACY_PATH_DISPATCH),
            (False, LEGACY_PATH_DISPATCH, LEGACY_PATH_DISPATCH),
            (True, CID_PATH_DISPATCH, CID_PATH_DISPATCH),
        ):
            with self.subTest(has_event=has_event, dispatch=dispatch):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    runtime, proto = root / "runtime", root / "proto"
                    (runtime / "src").mkdir(parents=True)
                    (proto / "src/connection").mkdir(parents=True)
                    connection = runtime / "src/connection.rs"
                    protocol = proto / "src/connection/paths.rs"
                    connection.write_text("before\n" + dispatch + "\nafter\n", encoding="utf-8")
                    protocol.write_text("RemoteCidsAvailable" if has_event else "RemoteStatus", encoding="utf-8")
                    original_protocol = protocol.read_bytes()
                    pair_runtime_events(runtime, proto)
                    self.assertEqual(connection.read_text(encoding="utf-8"), "before\n" + expected + "\nafter\n")
                    self.assertEqual(protocol.read_bytes(), original_protocol)
                    first = connection.read_bytes()
                    pair_runtime_events(runtime, proto)
                    self.assertEqual(connection.read_bytes(), first)

    def test_runtime_event_pairing_rejects_drift_without_overwrite(self):
        for protocol_text, runtime_text, message in (
            ("RemoteCidsAvailable", LEGACY_PATH_DISPATCH, "protocol/runtime event mismatch"),
            ("RemoteStatus", "changed dispatch", "dispatch anchor changed"),
            ("RemoteStatus", CID_PATH_DISPATCH * 2, "dispatch anchor changed"),
        ):
            with self.subTest(runtime=runtime_text):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    runtime, proto = root / "runtime", root / "proto"
                    (runtime / "src").mkdir(parents=True)
                    (proto / "src/connection").mkdir(parents=True)
                    connection = runtime / "src/connection.rs"
                    protocol = proto / "src/connection/paths.rs"
                    connection.write_text(runtime_text, encoding="utf-8")
                    protocol.write_text(protocol_text, encoding="utf-8")
                    before_runtime, before_proto = connection.read_bytes(), protocol.read_bytes()
                    with self.assertRaisesRegex(ValueError, message):
                        pair_runtime_events(runtime, proto)
                    self.assertEqual(connection.read_bytes(), before_runtime)
                    self.assertEqual(protocol.read_bytes(), before_proto)

    def test_prepared_pair_does_not_modify_input_sources(self):
        runtime_input = self.args.runtime_source / "src/connection.rs"
        proto_input = self.args.noq_source / "src/connection/paths.rs"
        before_runtime, before_proto = runtime_input.read_bytes(), proto_input.read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "destination"
            result = self.run_prepare(self.args.archive, self.args.probe, destination)
            self.assertEqual(result.returncode, 0, result.stderr)
            copied_runtime = (destination / "runtime-source/src/connection.rs").read_text(encoding="utf-8")
            copied_proto = (destination / "noq-source/src/connection/paths.rs").read_text(encoding="utf-8")
            expected = before_runtime.decode("utf-8")
            if "RemoteCidsAvailable" not in copied_proto:
                expected = expected.replace(CID_PATH_DISPATCH, LEGACY_PATH_DISPATCH)
                self.assertNotIn("RemoteCidsAvailable", copied_runtime)
            self.assertEqual(copied_runtime, expected)
        self.assertEqual(runtime_input.read_bytes(), before_runtime)
        self.assertEqual(proto_input.read_bytes(), before_proto)

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
