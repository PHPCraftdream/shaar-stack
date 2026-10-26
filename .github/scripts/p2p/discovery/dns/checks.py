"""CI-only preparation, fixture and exact DNS identity replacement controls."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch as mock_patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
import graph  # noqa: E402

spec = importlib.util.spec_from_file_location("dns_prepare", HERE / "prepare.py")
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)
REPOSITORY = HERE.parents[4]
ARCHIVE = REPOSITORY / "target/p2p/dns-archive/dns.crate"
SOURCE = REPOSITORY / "target/p2p/dns" / dns.PACKAGE


class PreparationChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_original_bytes_and_reverse_license_lock_provenance(self):
        original = dns.archive_files(ARCHIVE)
        prepared = dns.verify(SOURCE)
        receipt = json.loads((SOURCE.parent / "provenance.json").read_text())
        self.assertEqual(receipt["original_files"], dns.hashes(original))
        self.assertEqual(receipt["changed_files"], ["Cargo.toml", "src/bounded_expansion.rs", "src/lib.rs"])
        self.assertEqual(set(prepared) - set(original), {"src/bounded_expansion.rs"})
        for name in original.keys() - {"Cargo.toml", "src/lib.rs"}:
            self.assertEqual(prepared[name], original[name], name)
        self.assertEqual(dns.patch.reverse(prepared["src/lib.rs"].decode()).encode(), original["src/lib.rs"])
        self.assertEqual(prepared["Cargo.toml"], original["Cargo.toml"] + b"\n[workspace]\n")
        self.assertEqual(prepared["src/lib.rs"].split(b"//!", 1)[0], original["src/lib.rs"].split(b"//!", 1)[0])
        self.assertFalse(receipt["fixture_instrumentation"])
        self.assertFalse(receipt["hickory_memory_or_joined_shutdown_proven"])

    def test_repeat_preparation_and_no_overwrite(self):
        first = dns.prepare(ARCHIVE, self.root / "first")
        second = dns.prepare(ARCHIVE, self.root / "second")
        before = dns.verify(first)
        self.assertEqual(before, dns.verify(second))
        self.assertEqual((first.parent / "provenance.json").read_bytes(), (second.parent / "provenance.json").read_bytes())
        with self.assertRaises(FileExistsError):
            dns.prepare(ARCHIVE, first.parent)
        self.assertEqual(dns.verify(first), before)

    def test_checksum_and_size_fail_before_writes(self):
        archive = self.root / "wrong.crate"
        for data, message in ((b"unreviewed", "checksum mismatch"), (bytes(dns.MAX_ARCHIVE + 1), "size bound")):
            archive.write_bytes(data)
            with self.assertRaisesRegex(ValueError, message):
                dns.prepare(archive, self.root / "absent")
            self.assertFalse((self.root / "absent").exists())

    def test_unique_anchors_and_all_original_source_pins_fail_closed(self):
        original = dns.archive_files(ARCHIVE)
        for old, _ in dns.patch.EDITS:
            changed = dict(original)
            changed["src/lib.rs"] = changed["src/lib.rs"].replace(old.encode(), b"changed", 1)
            with mock_patch.object(dns, "archive_files", return_value=changed):
                with self.assertRaises(ValueError):
                    dns.prepare(ARCHIVE, self.root / "absent")
            self.assertFalse((self.root / "absent").exists())
        for name in ("Cargo.lock", "Cargo.toml", ".cargo_vcs_info.json"):
            changed = dict(original)
            changed[name] += b"unreviewed"
            with self.assertRaises(ValueError):
                dns.transform(changed)
        for source in ("missing", "anchor anchor"):
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                dns.patch.replace(source, "anchor", "new")

    def test_prepared_source_and_recipe_drift_are_rejected(self):
        root = dns.prepare(ARCHIVE, self.root / "prepared")
        path = root / "src/bounded_expansion.rs"
        before = path.read_bytes()
        path.write_bytes(before + b"\n")
        with self.assertRaisesRegex(ValueError, "source drift"):
            dns.verify(root)
        path.write_bytes(before)
        with mock_patch.object(dns, "recipe", return_value={}):
            with self.assertRaisesRegex(ValueError, "provenance mismatch"):
                dns.verify(root)
        (root / "unexpected.rs").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "source drift"):
            dns.verify(root)

    def test_caps_precede_parsing_allocation_push_and_error_retention(self):
        files = dns.verify(SOURCE)
        library = files["src/lib.rs"].decode()
        bounded = files["src/bounded_expansion.rs"].decode()
        self.assertEqual(library.count(".take(bounded_expansion::MAX_NUMERIC)"), 3)
        self.assertNotIn("Vec<Protocol", library)
        self.assertNotIn("Addrs(Vec", library)
        self.assertNotIn("unresolved.push(addr.clone())", library)
        self.assertNotIn("dial_errors.push", library)
        self.assertIn("pub fn with_resolver(inner: T, resolver: R) -> Self", library)
        numeric = bounded.split("pub(crate) fn push_numeric", 1)[1].split("pub(crate) fn push_txt", 1)[0]
        self.assertLess(numeric.index("pending.len() >= MAX_PENDING"), numeric.index("Encoded::new()"))
        self.assertLess(numeric.index("encoded.push(protocol)"), numeric.index("encoded.address()"))
        txt = bounded.split("pub(crate) fn push_txt", 1)[1].split("pub(crate) fn parse_txt", 1)[0]
        self.assertLess(txt.index("accepted == MAX_TXT_RECORDS"), txt.index("parse_txt(text"))
        self.assertLess(txt.index("size.is_none()"), txt.index("parse_txt(text"))
        self.assertLess(txt.index(".ends_with(suffix.bytes())"), txt.index("encoded.0.address()"))
        parser = bounded.split("pub(crate) fn parse_txt", 1)[1]
        self.assertLess(parser.index("text.len() > MAX_TXT_BYTES"), parser.index("str::from_utf8"))
        self.assertIn("Protocol::from_str_parts", parser)
        self.assertNotIn("Multiaddr::try_from", parser)

    def test_fixture_only_adds_observations_and_owned_contracts(self):
        before = dns.verify(SOURCE)
        destination = self.root / "fixture"
        dns.fixture(SOURCE, destination)
        receipt = json.loads((destination / "fixture-provenance.json").read_text())
        self.assertEqual(receipt["production_files"], dns.hashes(before))
        self.assertEqual(receipt["excluded_upstream_test_modules"], [])
        for name, data in before.items():
            actual = (destination / name).read_bytes()
            if name == "src/bounded_expansion.rs":
                for observation in dns.OBSERVATIONS.values():
                    actual = actual.replace(observation.encode(), b"")
            elif name == "src/lib.rs":
                actual = actual.removesuffix(b"\n#[cfg(test)]\nmod retention_support;\n#[cfg(test)]\nmod retention_tests;\n")
            self.assertEqual(actual, data, name)
        self.assertEqual(dns.digest((destination / "Cargo.lock").read_bytes()), dns.LOCK_DIGEST)
        with self.assertRaises(FileExistsError):
            dns.fixture(SOURCE, destination)
        self.assertEqual(dns.verify(SOURCE), before)


class IdentityChecks(unittest.TestCase):
    def setUp(self):
        self.roots = [Path(name) for name in ("relay", "swarm", "kad", "dns", "resolver")]
        paths = dict(zip(("libp2p-relay", "libp2p-swarm", "libp2p-kad", "libp2p-dns", "hickory-resolver"), self.roots))
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
        self.old["package"].append({"name": "libp2p-dns", "version": dns.VERSION,
                                    "source": "registry+https://github.com/rust-lang/crates.io-index", "checksum": dns.DIGEST})

    def test_only_exact_registry_dns_identity_can_be_replaced(self):
        result = graph.validate(self.old, self.new, self.metadata, *self.roots)
        self.assertTrue(result["reviewed_dns_identity_replacement"])
        self.assertEqual(result["retained_package_identities"], 1)
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
                changed["package"] = [p if p["name"] != "libp2p-dns" else stock for p in changed["package"]]
            with self.assertRaisesRegex(ValueError, "reviewed path identity"):
                graph.validate(self.old, changed, self.metadata, *self.roots)
        metadata = copy.deepcopy(self.metadata)
        next(p for p in metadata["packages"] if p["name"] == "libp2p-dns")["manifest_path"] = "other/Cargo.toml"
        with self.assertRaisesRegex(ValueError, "prepared source: libp2p-dns"):
            graph.validate(self.old, self.new, metadata, *self.roots)
        changed = copy.deepcopy(self.new)
        changed["package"][0]["dependencies"] = ["changed"]
        with self.assertRaisesRegex(ValueError, "dependency edge"):
            graph.validate(self.old, changed, self.metadata, *self.roots)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() and result.testsRun == 9 else 1)
