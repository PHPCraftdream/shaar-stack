"""CI-only Kademlia preparation and reviewed identity-replacement controls."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import graph  # noqa: E402
import kad  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[5]
ARCHIVE = REPOSITORY / "target/p2p/kad-archive/kad.crate"
SOURCE = REPOSITORY / "target/p2p/kad" / kad.PACKAGE


class PreparationChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_original_bytes_license_lock_and_provenance_are_preserved(self):
        original = kad.archive_files(ARCHIVE)
        prepared = kad.verify(SOURCE)
        receipt = json.loads((SOURCE.parent / "provenance.json").read_text())
        self.assertEqual(receipt["original_files"], kad.hashes(original))
        self.assertEqual(set(prepared), set(original))
        self.assertEqual(receipt["changed_files"], ["Cargo.toml", "src/behaviour.rs", "src/query/peers/closest.rs"])
        for name in original.keys() - set(receipt["changed_files"]):
            self.assertEqual(prepared[name], original[name], name)
        for name in ("src/behaviour.rs", "src/query/peers/closest.rs"):
            self.assertEqual(prepared[name].split(b"use std", 1)[0], original[name].split(b"use std", 1)[0])
        self.assertEqual(kad.digest(prepared["Cargo.lock"]), kad.LOCK_DIGEST)
        self.assertFalse(receipt["fixture_instrumentation"])
        self.assertFalse(receipt["global_operation_contact_bound"])

    def test_repeat_preparation_is_byte_identical_and_existing_tree_is_never_overwritten(self):
        first = kad.prepare(ARCHIVE, self.root / "first")
        second = kad.prepare(ARCHIVE, self.root / "second")
        self.assertEqual(kad.verify(first), kad.verify(second))
        self.assertEqual((first.parent / "provenance.json").read_bytes(), (second.parent / "provenance.json").read_bytes())
        before = kad.verify(first)
        with self.assertRaises(FileExistsError):
            kad.prepare(ARCHIVE, first.parent)
        self.assertEqual(kad.verify(first), before)

    def test_checksum_and_size_fail_before_destination_creation(self):
        archive = self.root / "wrong.crate"
        destination = self.root / "prepared"
        for data, message in ((b"unreviewed", "checksum mismatch"), (bytes(kad.MAX_ARCHIVE + 1), "size bound")):
            archive.write_bytes(data)
            with self.assertRaisesRegex(ValueError, message):
                kad.prepare(archive, destination)
            self.assertFalse(destination.exists())

    def test_anchor_drift_is_rejected_before_writes(self):
        original = kad.archive_files(ARCHIVE)
        for old, new in ((kad.DISCOVERED_OLD, "changed"), (kad.ADDRESS_OLD, "changed")):
            changed = dict(original)
            changed["src/behaviour.rs"] = changed["src/behaviour.rs"].replace(old.encode(), new.encode())
            with patch.object(kad, "archive_files", return_value=changed):
                with self.assertRaisesRegex(ValueError, "anchor changed"):
                    kad.prepare(ARCHIVE, self.root / "absent")
            self.assertFalse((self.root / "absent").exists())
        for source in ("missing", "anchor anchor"):
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                kad.replace(source, "anchor", "changed")

    def test_prepared_drift_and_unexpected_files_are_rejected(self):
        root = kad.prepare(ARCHIVE, self.root / "prepared")
        path = root / "src/behaviour.rs"
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "source drift"):
            kad.verify(root)
        path.write_bytes(original)
        (root / "unexpected.rs").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "source drift"):
            kad.verify(root)

    def test_caps_precede_clones_and_iterator_insertion(self):
        files = kad.verify(SOURCE)
        behaviour = files["src/behaviour.rs"].decode()
        discovery = behaviour.split("fn discovered<'a, I>", 1)[1].split("fn provider_peers", 1)[0]
        self.assertLess(discovery.index("addresses.len() >= 32"), discovery.index(".entry(peer.node_id)"))
        self.assertLess(discovery.index("address.as_ref().len() <= 256"), discovery.index(".cloned()"))
        self.assertLess(discovery.index("bounded.contains(&address)"), discovery.index(".cloned()"))
        self.assertIn("+ bounded.len() >= 4", discovery)
        self.assertIn("SmallVec::<[PeerId; 32]>", discovery)
        self.assertNotIn("others_iter.clone()", discovery)
        self.assertIn("    pub fn set_automatic_bootstrap_throttle(", behaviour)
        self.assertNotIn("#[cfg(test)]\n    pub fn set_automatic_bootstrap_throttle", behaviour)
        closest = files["src/query/peers/closest.rs"].decode().split("for peer in closer_peers {", 1)[1]
        self.assertLess(closest.index("self.closest_peers.len() >= 32"), closest.index("let key = peer.into()"))
        self.assertLess(closest.index("self.closest_peers.len() >= 32"), closest.index("entry.insert(peer)"))

    def test_fixture_changes_only_upstream_test_gates_and_owned_tests(self):
        destination = self.root / "fixture"
        before = kad.verify(SOURCE)
        kad.fixture(SOURCE, destination)
        receipt = json.loads((destination / "fixture-provenance.json").read_text())
        self.assertEqual(receipt["production_files"], kad.hashes(before))
        self.assertEqual((destination / "Cargo.lock").read_bytes(), before["Cargo.lock"])
        self.assertEqual((destination / "Cargo.toml").read_bytes(), before["Cargo.toml"])
        for name, data in before.items():
            actual = (destination / name).read_bytes()
            if name not in kad.UPSTREAM_TESTS:
                self.assertEqual(actual, data, name)
                continue
            text = actual.decode()
            if name == "src/behaviour.rs":
                text = text.split("\n#[cfg(test)]\nmod retention_behaviour", 1)[0].rstrip() + "\n"
                text = text.replace("#[cfg(any())]\nmod test;", "mod test;")
            else:
                if name == "src/query/peers/closest.rs":
                    text = text.split("// CLOSEST ITERATOR CONTRACT", 1)[0]
                    text = text.split("\n#[cfg(test)]\nmod retention_closest", 1)[0].rstrip() + "\n"
                text = text.replace("#[cfg(any())]\nmod test", "#[cfg(test)]\nmod test")
            self.assertEqual(text.rstrip(), data.decode().rstrip(), name)
        with self.assertRaises(FileExistsError):
            kad.fixture(SOURCE, destination)
        self.assertEqual(kad.verify(SOURCE), before)


class IdentityChecks(unittest.TestCase):
    def setUp(self):
        self.roots = [Path("relay"), Path("swarm"), Path("kad"), Path("dns")]
        self.old = {"package": [{"name": "unrelated", "version": "1", "source": "registry", "checksum": "keep"}]}
        self.new = copy.deepcopy(self.old)
        self.metadata = {"packages": [], "resolve": {"nodes": []}}
        paths = dict(zip(("libp2p-relay", "libp2p-swarm", "libp2p-kad", "libp2p-dns"), self.roots))
        for name, version in graph.FAMILY.items():
            source = None if name in paths else "registry"
            self.new["package"].append({"name": name, "version": version, "source": source})
            identity = f"{name}@{version}"
            self.metadata["packages"].append({"name": name, "version": version, "source": source,
                                              "id": identity, "manifest_path": str(paths.get(name, Path("registry")) / "Cargo.toml")})
            self.metadata["resolve"]["nodes"].append({"id": identity})
        self.old["package"].append({"name": "libp2p-kad", "version": kad.VERSION,
                                    "source": "registry+https://github.com/rust-lang/crates.io-index", "checksum": kad.DIGEST})

    def test_only_exact_reviewed_registry_identity_can_be_replaced(self):
        result = graph.validate(self.old, self.new, self.metadata, *self.roots)
        self.assertTrue(result["reviewed_kad_identity_replacement"])
        self.assertEqual(result["retained_package_identities"], 1)
        for field in ("version", "source", "checksum"):
            changed = copy.deepcopy(self.old)
            changed["package"][1][field] = "unreviewed"
            with self.assertRaisesRegex(ValueError, "existing package identity"):
                graph.validate(changed, self.new, self.metadata, *self.roots)

    def test_unrelated_changes_and_stock_or_duplicate_kad_are_rejected(self):
        changed = copy.deepcopy(self.new)
        changed["package"][0]["checksum"] = "changed"
        with self.assertRaisesRegex(ValueError, "existing package identity"):
            graph.validate(self.old, changed, self.metadata, *self.roots)
        for duplicate in (False, True):
            changed = copy.deepcopy(self.new)
            stock = copy.deepcopy(self.old["package"][1])
            if duplicate:
                changed["package"].append(stock)
            else:
                changed["package"] = [p if p["name"] != "libp2p-kad" else stock for p in changed["package"]]
            with self.assertRaisesRegex(ValueError, "reviewed path identity"):
                graph.validate(self.old, changed, self.metadata, *self.roots)


if __name__ == "__main__":
    unittest.main()
