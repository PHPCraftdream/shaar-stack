"""CI-only controls for candidate graph verification and source preparation."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import graph  # noqa: E402
import prepare  # noqa: E402


class GraphChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.relay = Path(self.temporary.name) / "relay"
        self.swarm = Path(self.temporary.name) / "swarm"
        self.old = {"package": [{"name": "bytes", "version": "1.12.1", "source": "registry", "checksum": "old"}]}
        self.new = copy.deepcopy(self.old)
        self.metadata = {"packages": [], "resolve": {"nodes": []}}
        for name, version in graph.FAMILY.items():
            root = {"libp2p-relay": self.relay, "libp2p-swarm": self.swarm}.get(name)
            local = root is not None
            source = None if local else "registry"
            identity = f"{name}@{version}"
            self.new["package"].append({"name": name, "version": version, "source": source, "checksum": None if local else name})
            self.metadata["packages"].append({"name": name, "version": version, "source": source, "id": identity,
                                               "manifest_path": str(root / "Cargo.toml") if local else "registry"})
            self.metadata["resolve"]["nodes"].append({"id": identity})

    def test_complete_resolved_family_preserves_existing_identity(self):
        receipt = graph.validate(self.old, self.new, self.metadata, self.relay, self.swarm)
        self.assertEqual(receipt["retained_package_identities"], 1)
        self.assertEqual(len(receipt["added_package_identities"]), 4)

    def test_no_deps_or_empty_resolve_is_rejected(self):
        for resolve in [None, {"nodes": []}]:
            self.metadata["resolve"] = resolve
            with self.assertRaisesRegex(ValueError, "full resolved metadata"):
                graph.validate(self.old, self.new, self.metadata, self.relay, self.swarm)

    def test_existing_identity_removal_or_mutation_is_rejected(self):
        for field in ["name", "version", "source", "checksum"]:
            changed = copy.deepcopy(self.new)
            changed["package"][0][field] = "changed"
            with self.assertRaisesRegex(ValueError, "existing package identity"):
                graph.validate(self.old, changed, self.metadata, self.relay, self.swarm)
        changed = copy.deepcopy(self.new)
        changed["package"].pop(0)
        with self.assertRaisesRegex(ValueError, "existing package identity"):
            graph.validate(self.old, changed, self.metadata, self.relay, self.swarm)

    def test_wrong_unresolved_or_duplicate_family_is_rejected(self):
        for mode in ["version", "unresolved", "duplicate"]:
            metadata = copy.deepcopy(self.metadata)
            if mode == "version":
                metadata["packages"][0]["version"] = "0.0.0"
            elif mode == "unresolved":
                metadata["resolve"]["nodes"].pop(0)
            else:
                metadata["packages"].append(copy.deepcopy(metadata["packages"][0]))
            with self.assertRaisesRegex(ValueError, "reviewed source APIs"):
                graph.validate(self.old, self.new, metadata, self.relay, self.swarm)

    def test_candidate_lock_family_must_match_metadata(self):
        self.new["package"][1]["version"] = "0.0.0"
        with self.assertRaisesRegex(ValueError, "candidate lock family"):
            graph.validate(self.old, self.new, self.metadata, self.relay, self.swarm)

    def test_stock_or_wrong_path_prepared_sources_are_rejected(self):
        for name, root in (("libp2p-relay", self.relay), ("libp2p-swarm", self.swarm)):
            for field, value in (("source", "registry"), ("manifest_path", str(root.parent / "other/Cargo.toml"))):
                metadata = copy.deepcopy(self.metadata)
                package = next(p for p in metadata["packages"] if p["name"] == name)
                package[field] = value
                with self.assertRaisesRegex(ValueError, f"prepared source: {name}"):
                    graph.validate(self.old, self.new, metadata, self.relay, self.swarm)

    def test_source_anchor_drift_is_rejected(self):
        for replace in [graph.replace, prepare.replace]:
            for source in ["missing", "anchor anchor"]:
                with self.assertRaises(ValueError):
                    replace(source, "anchor", "new")

    def repository_fixture(self, adopted):
        repository = Path(self.temporary.name) / ("adopted" if adopted else "scaffold")
        sdk = repository / "crates/shaar-p2p"
        sdk.mkdir(parents=True)
        root = '[workspace]\nmembers = ["crates/shaar-p2p"]\n[patch.crates-io]\n'
        for name in ("iroh", "noq-proto", "noq"):
            relative = f"target/backend/{name}/{name}-1.3.0"
            source = repository / relative
            source.mkdir(parents=True)
            (source / "Cargo.toml").write_text("source fixture", encoding="utf-8")
            root += f'{name} = {{ path = "{relative}" }}\n'
        if adopted:
            root += 'libp2p-relay = { path = "target/p2p/relay/libp2p-relay-0.22.0" }\n'
            root += 'libp2p-swarm = { path = "target/p2p/swarm/libp2p-swarm-0.48.0" }\n'
        (repository / "Cargo.toml").write_text(root, encoding="utf-8")
        (repository / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        dependencies = graph.DEPENDENCIES if adopted else "[dependencies]\n"
        (sdk / "Cargo.toml").write_text('[package]\nname = "shaar-p2p"\nversion = "0.1.0"\n' + dependencies, encoding="utf-8")
        (self.relay / "src").mkdir(parents=True, exist_ok=True)
        (self.relay / "src/bounded_lease.rs").write_text("owned lease fixture", encoding="utf-8")
        self.swarm.mkdir(parents=True, exist_ok=True)
        (self.swarm / "Cargo.toml").write_text('''[target.'cfg(target_family="wasm")'.dependencies.wasm-bindgen-futures]
version = "=0.4.79"\n''', encoding="utf-8")
        return repository

    def test_staging_works_before_and_after_product_adoption_without_duplicate_patches(self):
        for adopted in (False, True):
            repository = self.repository_fixture(adopted)
            original = (repository / "Cargo.toml").read_bytes()
            destination = repository / "candidate"
            graph.create(repository, destination, self.relay, self.swarm)
            import tomllib
            staged = tomllib.loads((destination / "Cargo.toml").read_text())
            self.assertEqual(staged["patch"]["crates-io"]["libp2p-relay"]["path"], self.relay.resolve().as_posix())
            self.assertEqual(staged["patch"]["crates-io"]["libp2p-swarm"]["path"], self.swarm.resolve().as_posix())
            self.assertEqual((repository / "Cargo.toml").read_bytes(), original)
            self.assertEqual((destination / "baseline.lock").read_bytes(), (repository / "Cargo.lock").read_bytes())

    def test_wrong_product_family_is_rejected_before_candidate_is_created(self):
        repository = self.repository_fixture(True)
        manifest = repository / "crates/shaar-p2p/Cargo.toml"
        manifest.write_text(manifest.read_text().replace("=0.57.1", "=0.57.0"), encoding="utf-8")
        destination = repository / "candidate"
        with self.assertRaisesRegex(ValueError, "product dependency family"):
            graph.create(repository, destination, self.relay, self.swarm)
        self.assertFalse(destination.exists())

    def test_invalid_archive_never_creates_destination(self):
        archive = Path(self.temporary.name) / "wrong.crate"
        archive.write_bytes(b"not a reviewed archive")
        destination = Path(self.temporary.name) / "prepared"
        for build in (prepare.prepare, prepare.prepare_swarm):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                build(archive, destination)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
