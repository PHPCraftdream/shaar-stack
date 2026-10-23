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
