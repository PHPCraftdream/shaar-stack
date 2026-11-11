"""CI-only negative controls for the owned-DNS product graph comparison."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import tomllib
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("foundation", Path(__file__).with_name("foundation.py"))
foundation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(foundation)


def fixture():
    packages = [{"id": name, "name": name, "version": version, "source": None, "dependencies": []}
                for name, version in [("shaar-p2p", "0.1.0"), ("hickory-resolver", "0.26.3"), ("hickory-net", "0.26.3")]]
    before = {"packages": packages, "resolve": {"nodes": [
        {"id": p["id"], "features": [] if p["name"] == "shaar-p2p" else ["tokio"], "deps": []}
        for p in packages]}}
    after = copy.deepcopy(before)
    after["resolve"]["nodes"][0]["deps"].append({"name": "hickory_resolver", "pkg": "hickory-resolver", "dep_kinds": [{"kind": None, "target": None}]})
    after["packages"][0]["dependencies"].append({"name": "hickory-resolver", "req": "=0.26.3", "uses_default_features": False, "features": ["tokio"], "kind": None, "target": None})
    return before, after


class FoundationGraphChecks(unittest.TestCase):
    def test_one_direct_edge_and_unchanged_feature_unions(self):
        before, after = fixture()
        result = foundation.compare(before, after)
        self.assertTrue(result["all_other_edges_unchanged"])
        self.assertTrue(result["feature_unions_unchanged"])
        self.assertEqual(result["package_identities_unchanged"], 3)

    def test_rejects_missing_or_extra_dependency_edges(self):
        before, after = fixture()
        after["resolve"]["nodes"][0]["deps"].clear()
        with self.assertRaisesRegex(ValueError, "dependency edges"):
            foundation.compare(before, after)
        before, after = fixture()
        after["resolve"]["nodes"][1]["deps"] = copy.deepcopy(after["resolve"]["nodes"][0]["deps"])
        with self.assertRaisesRegex(ValueError, "dependency edges"):
            foundation.compare(before, after)

    def test_rejects_feature_changes_and_encrypted_profile_even_if_preexisting(self):
        before, after = fixture()
        after["resolve"]["nodes"][1]["features"].append("system-config")
        with self.assertRaisesRegex(ValueError, "feature union"):
            foundation.compare(before, after)
        for feature in foundation.FORBIDDEN:
            before, after = fixture()
            for graph in (before, after):
                graph["resolve"]["nodes"][1]["features"].append(feature)
            with self.assertRaisesRegex(ValueError, "runtime feature profile"):
                foundation.compare(before, after)

    def test_rejects_version_identity_and_manifest_feature_drift(self):
        before, after = fixture()
        after["packages"][1]["version"] = "0.26.4"
        with self.assertRaisesRegex(ValueError, "package identities"):
            foundation.compare(before, after)
        before, after = fixture()
        after["packages"][0]["dependencies"][0]["uses_default_features"] = True
        with self.assertRaisesRegex(ValueError, "manifest edge"):
            foundation.compare(before, after)

    def test_fixture_paths_keep_copied_crates_and_rebase_prepared_sources_and_witness(self):
        target = Path(__file__).resolve().parents[5] / "target"
        target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="dns-paths-", dir=target) as temporary:
            repository = Path(temporary) / "caller"
            sdk, peer = repository / "crates/sdk", repository / "crates/peer"
            sdk.mkdir(parents=True)
            peer.mkdir()
            source = ('[dependencies]\npeer = { path = "../peer" }\n'
                      'prepared = { path = "../../target/prepared" }\n'
                      '[dev-dependencies]\nabsolute = { path = ' + json.dumps(peer.as_posix()) + ' }\n'
                      '[[test]]\nname = "witness"\npath = "../../.github/witness.rs"\n')
            (sdk / "Cargo.toml").write_text(source, encoding="utf-8")
            (peer / "Cargo.toml").write_text('[lib]\npath = "src/lib.rs"\n', encoding="utf-8")
            destination = repository / "target/baseline"
            shutil.copytree(repository / "crates", destination / "crates")
            records = foundation.rebase_fixture_paths(repository, destination)
            manifest = tomllib.loads((destination / "crates/sdk/Cargo.toml").read_text())
            self.assertEqual(manifest["dependencies"]["peer"]["path"], "../peer")
            self.assertEqual(Path(manifest["dependencies"]["prepared"]["path"]), repository / "target/prepared")
            self.assertEqual(Path(manifest["dev-dependencies"]["absolute"]["path"]), destination / "crates/peer")
            self.assertEqual(Path(manifest["test"][0]["path"]), repository / ".github/witness.rs")
            self.assertEqual(set(records), {"crates/sdk/Cargo.toml"})
            self.assertEqual((sdk / "Cargo.toml").read_text(), source)
            self.assertEqual((destination / "crates/peer/Cargo.toml").read_bytes(), (peer / "Cargo.toml").read_bytes())

    def test_fixture_path_rebase_rejects_escape_without_modifying_the_manifest(self):
        target = Path(__file__).resolve().parents[5] / "target"
        target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="dns-escape-", dir=target) as temporary:
            repository = Path(temporary) / "caller"
            destination = repository / "target/baseline"
            manifest = destination / "crates/sdk/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            for value in ("../../../outside", (Path(temporary) / "outside").as_posix()):
                content = ('[dependencies]\nescape = { path = ' + json.dumps(value) + ' }\n').encode()
                manifest.write_bytes(content)
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "escapes caller repository"):
                    foundation.rebase_fixture_paths(repository, destination)
                self.assertEqual(manifest.read_bytes(), content)

    def test_exact_product_lock_reverses_only_one_edge(self):
        repository = Path(__file__).resolve().parents[5]
        current = (repository / "Cargo.lock").read_bytes().replace(b"\r\n", b"\n")
        original = foundation.original_lock(current)
        self.assertEqual(foundation.original_lock(current.replace(b"\n", b"\r\n")), original)
        self.assertNotEqual(current, original)
        self.assertEqual(len(current) - len(original), len(b' "hickory-resolver",\n'))
        with self.assertRaisesRegex(ValueError, "lock bytes"):
            foundation.original_lock(current + b"\n")
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            foundation.original_lock(original)


if __name__ == "__main__":
    unittest.main()
