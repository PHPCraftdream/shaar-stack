"""CI-only contract checks for fixture transformations; not protocol execution evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("carrier_check_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


graph = load("graph")
instrument = load("instrument")
runner = load("run")


def metadata(root):
    names = sorted(graph.ROOTS)
    packages = [{"id": name, "name": name, "version": "1.0.0", "source": None,
                 "manifest_path": str(root / name / "Cargo.toml")} for name in names]
    nodes = [{"id": name, "features": [], "deps": []} for name in names]
    next(node for node in nodes if node["id"] == "libp2p")["deps"] = [
        {"name": "relay", "pkg": "libp2p-relay", "dep_kinds": [{"kind": None, "target": None}]}]
    return {"packages": packages, "resolve": {"nodes": nodes}}


class FixtureContracts(unittest.TestCase):
    def setUp(self):
        target = Path.cwd() / "target"
        target.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="carrier-source-check-", dir=target)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.original = {
            instrument.GATE: ("prefix\n" + instrument.CAPABILITY + "\n"
                              + instrument.MARKER + "\nsuffix\n").encode(),
            instrument.LIBRARY: b"mod operation_gate;\n",
            instrument.HANDLER: ("prefix\n" + instrument.ERROR_SEND + "\nsuffix\n").encode(),
            instrument.LISTENER: ("prefix\n" + instrument.LISTENER_POLL + "\nsuffix\n").encode(),
            "Cargo.toml": b"[workspace]\n",
            "untouched.bin": bytes(range(256)),
        }
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "Cargo.lock").write_bytes(b"unchanged product lock\n")
        self.product = metadata(self.workspace)

    def transformed(self, variant):
        destination = self.root / variant
        with patch.object(instrument, "verified", return_value=self.original):
            record = instrument.instrument(self.root / "prepared", destination, variant)
        return destination, record

    def compile_inventory(self, names):
        directory = Path(tempfile.mkdtemp(prefix="inventory-", dir=self.root))
        workspace, relay = directory / "workspace", directory / "relay"
        unit_source = workspace / "crates/shaar-p2p/src/lib.rs"
        for source in (unit_source, relay / "src/lib.rs"):
            source.parent.mkdir(parents=True)
            source.write_bytes(b"fixture source\n")
        executable = directory / "compiled/unit-tests"

        def command(arguments, *args, **kwargs):
            if arguments[0] != "cargo":
                self.assertEqual(arguments[0], str(executable))
                return "".join(name + ": test\n" for name in names)
            executable.parent.mkdir()
            executable.write_bytes(b"fixture executable witness")
            artifacts = [
                {"reason": "compiler-artifact", "target": {"src_path": str(relay / "src/lib.rs")},
                 "fresh": False, "package_id": "fixture-relay"},
                {"reason": "compiler-artifact", "target": {"src_path": str(unit_source)},
                 "fresh": False, "package_id": "fixture-unit", "executable": str(executable)},
            ]
            return "\n".join(json.dumps(item) for item in artifacts)

        with patch.object(runner, "command", side_effect=command):
            return runner.compile_fixture(workspace, directory, relay, graph)

    def test_compiled_inventory_accepts_growing_and_shrinking_source_suites(self):
        fixtures = ["carrier_protocol_fixture::" + case["name"] for case in runner.CASES.values()]
        for size in (2, 19, 1):
            names = fixtures + [f"roles::destination_roles_case_{index}" for index in range(size)]
            _, selected, witness = self.compile_inventory(names)
            self.assertEqual(witness["unit_inventory"], names)
            self.assertEqual(set(selected), set(runner.CASES))
            runner.verify_inventories({variant: witness for variant in runner.VARIANTS})

    def test_inventory_equality_rejects_added_missing_or_replaced_counterfactual_tests(self):
        baseline = ["roles::destination_roles_one", "guard::destination_guard_two"]
        for changed in (baseline[:-1], baseline + ["new::case"], [baseline[0], "guard::other"]):
            results = {variant: {"unit_inventory": baseline} for variant in runner.VARIANTS}
            results["counterfactual"] = {"unit_inventory": changed}
            with self.assertRaisesRegex(ValueError, "changed the executable test inventory"):
                runner.verify_inventories(results)

    def test_inventory_requires_all_variants_and_nonempty_unique_well_formed_listings(self):
        with self.assertRaisesRegex(ValueError, "missing Carrier proof variant"):
            runner.verify_inventories({"baseline": {"unit_inventory": ["case"]}})
        with self.assertRaisesRegex(ValueError, "empty Carrier executable"):
            runner.verify_inventories({variant: {"unit_inventory": []} for variant in runner.VARIANTS})
        for listing in ("", "case: test\ncase: test\n", "case: benchmark\n", "malformed text\n"):
            with self.assertRaises(ValueError):
                runner.unit_inventory(listing)

    def test_compiled_inventory_keeps_exact_fixture_controls(self):
        fixtures = ["carrier_protocol_fixture::" + case["name"] for case in runner.CASES.values()]
        with self.assertRaisesRegex(ValueError, "included exactly once"):
            self.compile_inventory(fixtures[:-1])
        duplicated = "other::" + fixtures[0]
        with self.assertRaisesRegex(ValueError, "included exactly once"):
            self.compile_inventory(fixtures + [duplicated])

    def test_exact_anchor_is_required(self):
        for text in ("absent", "anchor anchor"):
            with self.assertRaises(ValueError):
                instrument.replace_once(text, "anchor", "replacement")

    def test_guard_counterfactual_changes_only_the_guard(self):
        baseline, _ = self.transformed("baseline")
        counterfactual, record = self.transformed("counterfactual")
        expected = (baseline / instrument.GATE).read_text().replace(instrument.GUARD, "if false {")
        self.assertEqual((counterfactual / instrument.GATE).read_text(), expected)
        self.assertTrue(record["guard_only_counterfactual"])
        self.assertFalse(record["runtime_verified"])

    def test_unrelated_bytes_are_preserved(self):
        destination, record = self.transformed("baseline")
        self.assertEqual((destination / "untouched.bin").read_bytes(), self.original["untouched.bin"])
        self.assertEqual(record["original_source_sha256"]["untouched.bin"],
                         graph.digest(self.original["untouched.bin"]))

    def test_observations_do_not_insert_an_extra_liveness_check(self):
        destination, _ = self.transformed("baseline")
        source = (destination / instrument.GATE).read_text()
        self.assertNotIn("bound_live", source)
        self.assertLess(source.index("before_protocol_poll"), source.index(instrument.GUARD))
        self.assertLess(source.index(instrument.GUARD), source.index("inner_poll_started"))
        self.assertLess(source.index("inner_poll_started"), source.index("future.as_mut().poll"))

    def test_crlf_gate_is_reversible(self):
        self.original[instrument.GATE] = self.original[instrument.GATE].replace(b"\n", b"\r\n")
        destination, record = self.transformed("baseline")
        self.assertIn(b"\r\n", (destination / instrument.GATE).read_bytes())
        self.assertEqual(record["original_source_sha256"][instrument.GATE],
                         graph.digest(self.original[instrument.GATE]))

    def test_listener_counterfactual_changes_only_premature_close(self):
        baseline, _ = self.transformed("baseline")
        counterfactual, record = self.transformed("counterfactual-listener")
        expected = (baseline / instrument.LISTENER).read_text().replace(
            instrument.LISTENER_HELD, instrument.LISTENER_BROKEN)
        self.assertEqual((counterfactual / instrument.LISTENER).read_text(), expected)
        for name in (instrument.GATE, instrument.LIBRARY, instrument.HANDLER):
            self.assertEqual((baseline / name).read_bytes(), (counterfactual / name).read_bytes())
        self.assertTrue(record["listener_only_counterfactual"])
        self.assertFalse(record["guard_only_counterfactual"])
        with patch.object(graph, "product_paths", side_effect=LookupError("variant accepted")):
            with self.assertRaisesRegex(LookupError, "variant accepted"):
                graph.create(self.root, self.product, self.root / "copied", self.root / "relay",
                             instrument, "counterfactual-listener", HERE / "scenario.rs")

    def test_listener_observer_is_before_reads_without_liveness_check(self):
        destination, _ = self.transformed("baseline")
        source = (destination / instrument.LISTENER).read_text()
        self.assertLess(source.index("before_listener_poll"), source.index("loop {"))
        self.assertNotIn(".live()", source)
        self.assertNotIn(".live()", instrument.IDENTITY)
        self.assertNotIn(".check(", instrument.IDENTITY)

    def test_error_observer_is_only_after_successful_channel_send(self):
        destination, _ = self.transformed("baseline")
        source = (destination / instrument.HANDLER).read_text()
        self.assertIn(instrument.ERROR_OBSERVED, source)
        self.assertEqual(source.count("typed_error_queued"), 1)
        self.assertIn("} else {\n                        crate::wire_probe::typed_error_queued", source)

    def test_all_observed_sources_preserve_crlf_bytes(self):
        for name in (instrument.GATE, instrument.LIBRARY, instrument.HANDLER, instrument.LISTENER):
            self.original[name] = self.original[name].replace(b"\n", b"\r\n")
        destination, _ = self.transformed("counterfactual-listener")
        for name in (instrument.GATE, instrument.LIBRARY, instrument.HANDLER, instrument.LISTENER):
            source = (destination / name).read_bytes()
            self.assertNotIn(b"\n", source.replace(b"\r\n", b""))

    def test_unknown_variant_is_rejected(self):
        with self.assertRaises(ValueError):
            instrument.instrument(self.root, self.root / "bad", "unreviewed")

    def test_existing_destination_is_not_overwritten(self):
        self.transformed("baseline")
        with self.assertRaises(FileExistsError):
            self.transformed("baseline")

    def test_matching_graph_and_lock_are_accepted(self):
        receipt = graph.verify(self.product, copy.deepcopy(self.product),
                               b"unchanged product lock\n", self.workspace,
                               self.workspace / "libp2p-relay")
        self.assertTrue(receipt["exact_features_and_edges"])
        self.assertEqual(receipt["packages"], len(graph.ROOTS))

    def test_changed_feature_union_is_rejected(self):
        fixture = copy.deepcopy(self.product)
        fixture["resolve"]["nodes"][0]["features"] = ["extra"]
        with self.assertRaises(ValueError):
            graph.verify(self.product, fixture, b"unchanged product lock\n",
                         self.workspace, self.workspace / "libp2p-relay")

    def test_changed_non_dev_edge_is_rejected(self):
        fixture = copy.deepcopy(self.product)
        next(node for node in fixture["resolve"]["nodes"] if node["id"] == "libp2p")["deps"] = []
        with self.assertRaises(ValueError):
            graph.verify(self.product, fixture, b"unchanged product lock\n",
                         self.workspace, self.workspace / "libp2p-relay")

    def test_changed_lock_is_rejected(self):
        with self.assertRaises(ValueError):
            graph.verify(self.product, self.product, b"different lock\n",
                         self.workspace, self.workspace / "libp2p-relay")

    def test_unselected_instrumented_relay_is_rejected(self):
        with self.assertRaises(ValueError):
            graph.verify(self.product, self.product, b"unchanged product lock\n",
                         self.workspace, self.workspace / "another-relay")

    def test_missing_graph_root_is_rejected(self):
        del self.product["packages"][0]
        with self.assertRaises(ValueError):
            graph.closure(self.product)

    def test_internal_manifest_paths_rebase_without_feature_change(self):
        origin = self.root / "origin"
        manifest = self.workspace / "Cargo.toml"
        manifest.write_text('[dependencies]\nrelay = { path = '
                            + json.dumps((origin / "relay").as_posix())
                            + ', features = ["client"] }\n', encoding="utf-8")
        records = graph.rebase_manifests(origin, self.workspace)
        parsed = tomllib.loads(manifest.read_text())
        self.assertEqual(parsed["dependencies"]["relay"]["features"], ["client"])
        self.assertEqual(parsed["dependencies"]["relay"]["path"],
                         (self.workspace / "relay").as_posix())
        self.assertEqual(set(records), {"Cargo.toml"})

    def test_external_manifest_paths_are_rejected(self):
        (self.workspace / "Cargo.toml").write_text(
            '[dependencies]\nrelay = { path = '
            + json.dumps((self.root / "outside-product").as_posix()) + ' }\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            graph.rebase_manifests(self.root / "origin", self.workspace)

    def test_deadline_counterfactual_removes_only_established_exemption(self):
        path = self.workspace / "crates/shaar-p2p/src/carrier/relay/gate_factory.rs"
        path.parent.mkdir(parents=True)
        guard = "if !matches!(record.state, RecordState::Established) && Instant::now() >= record.deadline {"
        original = ("unchanged prefix\n" + guard + "\nreturn false;\n}\nunchanged suffix\n").encode()
        path.write_bytes(original)
        record = graph.deadline_counterfactual(self.workspace, instrument)
        self.assertEqual(path.read_bytes(), original.replace(guard.encode(),
                         b"if Instant::now() >= record.deadline {"))
        self.assertEqual(record["original_sha256"], graph.digest(original))
        self.assertEqual(record["counterfactual_sha256"], graph.digest(path.read_bytes()))

    def test_deadline_counterfactual_rejects_anchor_drift(self):
        path = self.workspace / "crates/shaar-p2p/src/carrier/relay/gate_factory.rs"
        path.parent.mkdir(parents=True)
        path.write_text("no reviewed guard\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            graph.deadline_counterfactual(self.workspace, instrument)
        self.assertEqual(path.read_text(), "no reviewed guard\n")


if __name__ == "__main__":
    if os.environ.get("CI", "").lower() != "true":
        raise ValueError("Carrier fixture contract checks execute in CI only")
    unittest.main()
