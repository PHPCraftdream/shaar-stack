"""Source-only CI controls for wire instrumentation and isolated defects."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("relay_wire_source_prepare", HERE / "prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class WireSourceChecks(unittest.TestCase):
    def source(self):
        return HERE.parents[5] / "target/p2p/relay/libp2p-relay-0.22.0"

    def test_wire_observations_are_reversible_and_other_files_unchanged(self):
        original = prepare.verified_product(self.source())
        changed, receipt = prepare.transform(self.source())
        self.assertEqual(receipt["production_files"], prepare.hashes(original))
        self.assertFalse(receipt["runtime_verified"])
        for name, edits in prepare.observations().items():
            text = changed[name].decode()
            for old, new in reversed(edits):
                text = prepare.replace(text, new, old)
            self.assertEqual(text.encode(), original[name], name)
        # The pinned archive ships its lockfile; instrumentation must not touch it.
        self.assertIn("Cargo.lock", original)
        self.assertEqual(changed["Cargo.lock"], original["Cargo.lock"])
        for name in original.keys() - prepare.observations().keys():
            self.assertEqual(changed[name], original[name], name)

    def test_each_counterfactual_reverses_exactly_one_gate(self):
        changed, _ = prepare.transform(self.source())
        for name, old, new in prepare.VARIANTS.values():
            defective = prepare.replace(changed[name].decode(), old, new)
            restored = prepare.replace(defective, new, old)
            self.assertEqual(restored.encode(), changed[name])
            self.assertNotEqual(defective.encode(), changed[name])

    def test_wire_instrumentation_rejects_anchor_drift_and_overwrite(self):
        for source in ("missing", "anchor anchor"):
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                prepare.replace(source, "anchor", "new")
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture"
            prepare.instrument(self.source(), destination)
            before = prepare.hashes(prepare.files(destination))
            with self.assertRaises(FileExistsError):
                prepare.instrument(self.source(), destination)
            self.assertEqual(prepare.hashes(prepare.files(destination)), before)

    def test_unit_bridge_preserves_all_bodies_and_exact_inventory(self):
        original = prepare.verified_product(self.source())
        tree, receipt, harness = prepare.unit_transform(self.source())
        self.assertEqual(len(receipt["unit_inventory"]), 25)
        self.assertEqual(len(set(receipt["unit_inventory"])), 25)
        self.assertEqual(harness.count(b"#[test]"), 25)
        self.assertEqual(harness.count(b"libp2p_relay::unit_bridge::run("), 25)
        self.assertTrue(receipt["unit_bodies_unchanged"])
        edits = receipt["unit_bridge_reversible_edits"]
        for name, changes in edits.items():
            restored = tree[name].decode()
            for old, new in reversed(changes):
                restored = prepare.replace(restored, new, old)
            self.assertEqual(restored.encode(), original[name], name)
        for name in original.keys() - edits.keys():
            self.assertEqual(tree[name], original[name], name)
        # The pinned archive ships its lockfile; the unit bridge must never rewrite it.
        self.assertIn("Cargo.lock", original)
        self.assertEqual(tree["Cargo.toml"], original["Cargo.toml"])
        self.assertEqual(tree["Cargo.lock"], original["Cargo.lock"])
        self.assertNotIn("src/unit_bridge.rs", original)

    def test_unit_bridge_never_enables_upstream_dev_tests_or_changes_inputs(self):
        tree, receipt, _ = prepare.unit_transform(self.source())
        self.assertEqual(len(prepare.UNIT_GROUPS), 3)
        for _, _, tests, _, _, _, count in prepare.UNIT_GROUPS:
            text = tree[tests].decode()
            self.assertEqual(text.count("pub(super) fn "), count)
            self.assertNotIn("#[test]", text)
        self.assertNotIn("src/wire_probe.rs", tree)
        self.assertFalse(receipt["runtime_verified"])

    def test_failed_compile_writes_full_evidence_before_raising(self):
        spec = importlib.util.spec_from_file_location("relay_wire_run", HERE / "run.py")
        run = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(run)
        script = "import sys; print('evidence-stdout'); print('evidence-stderr', file=sys.stderr); sys.exit(3)"
        with tempfile.TemporaryDirectory() as failed:
            log = Path(failed) / "compile-failure.log"
            with self.assertRaises(RuntimeError):
                run.command([sys.executable, "-I", "-c", script], Path(failed), failure_log=log)
            # Section markers prove each stream survived, not just the echoed command line.
            _, stdout_part, stderr_part = log.read_text(encoding="utf-8").split("\n--- ")
            self.assertTrue(stdout_part.startswith("stdout ---\n"))
            self.assertTrue(stderr_part.startswith("stderr ---\n"))
            self.assertIn("exit_code=3", log.read_text(encoding="utf-8"))
            self.assertIn("evidence-stdout", stdout_part)
            self.assertNotIn("evidence-stderr", stdout_part)
            self.assertIn("evidence-stderr", stderr_part)
            self.assertNotIn("evidence-stdout", stderr_part)
        with tempfile.TemporaryDirectory() as succeeded:
            log = Path(succeeded) / "compile-failure.log"
            run.command([sys.executable, "-I", "-c", "pass"], Path(succeeded), failure_log=log)
            self.assertFalse(log.exists(), "success must not create failure evidence")

    def test_wire_probe_is_not_added_to_product_public_api(self):
        original = prepare.verified_product(self.source())
        self.assertNotIn("src/wire_probe.rs", original)
        self.assertNotIn(b"pub mod wire_probe", original["src/lib.rs"])
        self.assertIn(b"new_with_operation_factory", original["src/lib.rs"])
        self.assertEqual(prepare.VARIANTS["protocol"][0], "src/operation_gate.rs")
        self.assertEqual(prepare.VARIANTS["renewal"][0], "src/priv_client/handler.rs")
        self.assertEqual(prepare.VARIANTS["reuse"][0], "src/priv_client.rs")
