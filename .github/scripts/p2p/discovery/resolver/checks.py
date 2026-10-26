"""CI-only source preparation, negative controls, and resolver graph assertions."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
import graph  # noqa: E402

spec = importlib.util.spec_from_file_location("resolver_fixture", HERE / "fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
resolver = fixture.prepare
REPOSITORY = HERE.parents[4]
ARCHIVE = REPOSITORY / "target/p2p/resolver-archive/resolver.crate"
SOURCE = REPOSITORY / "target/p2p/resolver" / resolver.PACKAGE


class PreparationChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_original_source_license_manifest_lock_and_exact_reversal(self):
        original = resolver.archive_files(ARCHIVE)
        prepared = resolver.verify(SOURCE)
        record = json.loads((SOURCE.parent / "provenance.json").read_text())
        self.assertEqual(record["original_files"], resolver.hashes(original))
        self.assertEqual(record["changed_files"], ["Cargo.toml", "src/lib.rs", "src/name_server.rs", "src/name_server_pool.rs"])
        reversed_files = resolver.patch.reverse(prepared)
        reversed_files["Cargo.toml"] = reversed_files["Cargo.toml"].removesuffix(b"\n[workspace]\n")
        reversed_files["src/lib.rs"] = reversed_files["src/lib.rs"].removeprefix(b"#![forbid(unsafe_code)]\n")
        self.assertEqual(reversed_files, original)
        self.assertFalse(record["resolver_lifecycle_acceptance"])

    def test_repeatability_and_existing_destination_never_overwritten(self):
        first = resolver.prepare(ARCHIVE, self.root / "one")
        second = resolver.prepare(ARCHIVE, self.root / "two")
        before = resolver.verify(first)
        self.assertEqual(before, resolver.verify(second))
        self.assertEqual((first.parent / "provenance.json").read_bytes(), (second.parent / "provenance.json").read_bytes())
        with self.assertRaises(FileExistsError):
            resolver.prepare(ARCHIVE, first.parent)
        self.assertEqual(before, resolver.verify(first))

    def test_invalid_archive_is_rejected_before_destination_creation(self):
        archive = self.root / "invalid.crate"
        for data, message in [(b"unreviewed", "checksum mismatch"), (bytes(resolver.MAX_ARCHIVE + 1), "size bound")]:
            archive.write_bytes(data)
            with self.assertRaisesRegex(ValueError, message):
                resolver.prepare(archive, self.root / "absent")
            self.assertFalse((self.root / "absent").exists())

    def test_unique_anchors_fail_closed(self):
        original = resolver.archive_files(ARCHIVE)
        for name, edits in resolver.patch.EDITS.items():
            for old, _ in edits:
                changed = dict(original)
                changed[name] = changed[name].replace(old.encode(), b"unreviewed", 1)
                with patch.object(resolver, "archive_files", return_value=changed):
                    with self.assertRaisesRegex(ValueError, "anchor changed"):
                        resolver.prepare(ARCHIVE, self.root / "absent")
                self.assertFalse((self.root / "absent").exists())
        for text in ("missing", "anchor anchor"):
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                resolver.patch.replace(text, "anchor", "new")

    def test_original_tree_including_unmodified_files_is_pinned(self):
        original = resolver.archive_files(ARCHIVE)
        for name in original:
            changed = dict(original)
            changed[name] += b" "
            with self.assertRaises((ValueError, KeyError)):
                resolver.originals(changed)
        changed = dict(original, unexpected=b"unreviewed")
        with self.assertRaisesRegex(ValueError, "source tree changed"):
            resolver.originals(changed)

    def test_prepared_source_recipe_and_receipt_drift_are_rejected(self):
        root = resolver.prepare(ARCHIVE, self.root / "prepared")
        path = root / "src/name_server.rs"
        before = path.read_bytes()
        path.write_bytes(before + b"\n")
        with self.assertRaisesRegex(ValueError, "source drift"):
            resolver.verify(root)
        path.write_bytes(before)
        with patch.object(resolver, "recipe", return_value={}):
            with self.assertRaisesRegex(ValueError, "provenance mismatch"):
                resolver.verify(root)
        receipt_path = root.parent / "provenance.json"
        record = json.loads(receipt_path.read_text())
        record["license"] = "unreviewed"
        receipt_path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "provenance mismatch"):
            resolver.verify(root)

    def test_fixture_changes_only_explicit_test_gates_and_owned_modules(self):
        production = resolver.verify(SOURCE)
        files, record = fixture.transformed(SOURCE)
        restored = dict(files)
        for parent, name in fixture.MODULES.items():
            suffix = f'\n#[cfg(all(test, feature = "tokio"))]\n#[path = "locking_{name}.rs"]\nmod locking_{name};\n'.encode()
            self.assertTrue(restored[parent].endswith(suffix))
            restored[parent] = restored[parent].removesuffix(suffix)
            self.assertEqual(restored.pop(f"src/locking_{name}.rs"), (HERE / f"{name}.rs").read_bytes())
        for name, anchors in fixture.EXCLUSIONS.items():
            for anchor in anchors:
                indent = anchor[:len(anchor) - len(anchor.lstrip())]
                restored[name] = restored[name].replace(("\n" + indent + "#[cfg(any())]\n" + anchor).encode(), ("\n" + anchor).encode())
        self.assertEqual(restored, production)
        self.assertEqual(record["archive_lock_sha256"], resolver.LOCK_DIGEST)
        destination = self.root / "fixture"
        fixture.fixture(SOURCE, destination)
        with self.assertRaises(FileExistsError):
            fixture.fixture(SOURCE, destination)

    def test_counterfactual_reverts_exactly_one_real_production_fix(self):
        production = resolver.verify(SOURCE)
        fixed, fixed_record = fixture.transformed(SOURCE)
        self.assertEqual(fixed_record["production_source_delta"], {})
        for selected, mechanism in fixture.MODULES.items():
            counterfactual, record = fixture.transformed(SOURCE, mechanism)
            self.assertEqual(record["counterfactual"], mechanism)
            self.assertEqual([name for name in fixed if fixed[name] != counterfactual[name]], [selected])
            expected = production[selected].decode()
            for old, new in reversed(resolver.patch.EDITS[selected]):
                expected = resolver.patch.replace(expected, new, old)
            self.assertEqual(record["production_source_delta"], {selected: {
                "prepared_sha256": resolver.digest(production[selected]),
                "counterfactual_sha256": resolver.digest(expected.encode()),
            }})
            for name, edits in resolver.patch.EDITS.items():
                for old, new in edits:
                    self.assertIn((old if name == selected else new).encode(), counterfactual[name])
            self.assertEqual(fixed["src/locking_connections.rs"], counterfactual["src/locking_connections.rs"])
            self.assertEqual(fixed["src/locking_cleanup.rs"], counterfactual["src/locking_cleanup.rs"])
        with self.assertRaisesRegex(ValueError, "unknown resolver counterfactual"):
            fixture.transformed(SOURCE, True)


class IdentityChecks(unittest.TestCase):
    def setUp(self):
        names = ("libp2p-relay", "libp2p-swarm", "libp2p-kad", "libp2p-dns", "hickory-resolver")
        self.roots = [Path(name) for name in ("relay", "swarm", "kad", "dns", "resolver")]
        paths = dict(zip(names, self.roots))
        self.old = {"package": [{"name": "unrelated", "version": "1", "source": "registry", "checksum": "keep", "dependencies": ["kept"]}]}
        self.new = copy.deepcopy(self.old)
        self.metadata = {"packages": [], "resolve": {"nodes": []}}
        for name, version in graph.FAMILY.items():
            source = None if name in paths else "registry"
            self.new["package"].append({"name": name, "version": version, "source": source})
            identity = f"{name}@{version}"
            self.metadata["packages"].append({"name": name, "version": version, "source": source,
                                              "id": identity, "manifest_path": str(paths.get(name, Path("registry")) / "Cargo.toml")})
            self.metadata["resolve"]["nodes"].append({"id": identity})
        self.old["package"].append({"name": "hickory-resolver", "version": resolver.VERSION,
                                    "source": "registry+https://github.com/rust-lang/crates.io-index", "checksum": resolver.DIGEST})

    def test_only_exact_resolver_registry_identity_is_replaced(self):
        result = graph.validate(self.old, self.new, self.metadata, *self.roots)
        self.assertTrue(result["reviewed_resolver_identity_replacement"])
        for field in ("version", "source", "checksum"):
            changed = copy.deepcopy(self.old)
            changed["package"][1][field] = "unreviewed"
            with self.assertRaisesRegex(ValueError, "existing package identity"):
                graph.validate(changed, self.new, self.metadata, *self.roots)

    def test_stock_duplicate_wrong_path_and_changed_edges_are_rejected(self):
        for duplicate in (False, True):
            changed = copy.deepcopy(self.new)
            stock = copy.deepcopy(self.old["package"][1])
            if duplicate:
                changed["package"].append(stock)
            else:
                changed["package"] = [p if p["name"] != "hickory-resolver" else stock for p in changed["package"]]
            with self.assertRaisesRegex(ValueError, "reviewed path identity"):
                graph.validate(self.old, changed, self.metadata, *self.roots)
        metadata = copy.deepcopy(self.metadata)
        next(p for p in metadata["packages"] if p["name"] == "hickory-resolver")["manifest_path"] = "other/Cargo.toml"
        with self.assertRaisesRegex(ValueError, "prepared source: hickory-resolver"):
            graph.validate(self.old, self.new, metadata, *self.roots)
        changed = copy.deepcopy(self.new)
        changed["package"][0]["dependencies"] = ["changed"]
        with self.assertRaisesRegex(ValueError, "dependency edge"):
            graph.validate(self.old, changed, self.metadata, *self.roots)


class ProductChecks(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("resolver_product", HERE / "product.py")
        self.product = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.product)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline = self.root / "baseline.json"
        self.lock = self.root / "Cargo.lock"
        self.destination = self.root / "fixture"
        self.registry = "registry+https://github.com/rust-lang/crates.io-index"
        def package(name, source, path):
            return {"id": name, "name": name, "version": "0.26.3", "source": source, "manifest_path": path}
        def dependency(name, package):
            return {"name": name, "pkg": package, "dep_kinds": [{"kind": None, "target": None}]}
        self.metadata = {
            "packages": [package("hickory-resolver", None, str(SOURCE / "Cargo.toml")),
                         package("hickory-net", self.registry, "registry/net/Cargo.toml"),
                         package("hickory-proto", self.registry, "registry/proto/Cargo.toml")],
            "resolve": {"nodes": [
                {"id": "hickory-resolver", "features": ["tokio"], "deps": [dependency("hickory_net", "hickory-net")]},
                {"id": "hickory-net", "features": ["tokio"], "deps": [dependency("hickory_proto", "hickory-proto")]},
                {"id": "hickory-proto", "features": ["std"], "deps": []},
            ]},
        }
        self.baseline.write_text(json.dumps(self.metadata))
        text = 'version = 4\n[[package]]\nname = "hickory-resolver"\nversion = "0.26.3"\n'
        for name in ("hickory-net", "hickory-proto"):
            text += f'[[package]]\nname = "{name}"\nversion = "0.26.3"\nsource = "{self.registry}"\nchecksum = "pinned-{name}"\n'
        self.lock.write_text(text)
        self.product.create(SOURCE, self.baseline, self.lock, self.destination)
        self.actual = copy.deepcopy(self.metadata)
        self.actual["packages"][0]["manifest_path"] = str(self.destination / "Cargo.toml")
        self.actual["resolve"]["nodes"][0]["deps"].append(dependency("locking_pin_fixture", "hickory-proto"))
        self.metadata_path = self.destination / "metadata.json"
        self.metadata_path.write_text(json.dumps(self.actual))

    def test_product_manifest_reuses_direct_aliases_and_pins_transitive_features(self):
        import tomllib
        manifest = tomllib.loads((self.destination / "Cargo.toml").read_text())
        dependencies = manifest["dependencies"]
        self.assertEqual(sum(d["package"] == "hickory-net" for d in dependencies.values()), 1)
        self.assertEqual(sum(d["package"] == "hickory-proto" for d in dependencies.values()), 1)
        self.assertNotIn("dev-dependencies", manifest)
        self.product.verify(self.baseline, self.lock, self.destination)

    def test_product_identity_feature_and_edge_drift_are_rejected(self):
        for mode in ("version", "features", "edge"):
            actual = copy.deepcopy(self.actual)
            if mode == "version":
                actual["packages"][1]["version"] = "0.26.2"
            elif mode == "features":
                actual["resolve"]["nodes"][1]["features"].append("unreviewed")
            else:
                actual["resolve"]["nodes"][1]["deps"] = []
            self.metadata_path.write_text(json.dumps(actual))
            with self.assertRaises(ValueError):
                self.product.verify(self.baseline, self.lock, self.destination)
        self.metadata_path.write_text(json.dumps(self.actual))
        changed_lock = self.lock.read_text().replace("pinned-hickory-net", "changed")
        (self.destination / "Cargo.lock").write_text(changed_lock)
        with self.assertRaisesRegex(ValueError, "lock added or changed"):
            self.product.verify(self.baseline, self.lock, self.destination)

    def test_product_registry_fallback_and_source_drift_are_rejected(self):
        actual = copy.deepcopy(self.actual)
        actual["packages"][0]["source"] = self.registry
        self.metadata_path.write_text(json.dumps(actual))
        with self.assertRaisesRegex(ValueError, "single prepared resolver"):
            self.product.verify(self.baseline, self.lock, self.destination)
        self.metadata_path.write_text(json.dumps(self.actual))
        source = self.destination / "src/name_server.rs"
        source.write_bytes(source.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.product.verify(self.baseline, self.lock, self.destination)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() and result.testsRun == 13 else 1)
