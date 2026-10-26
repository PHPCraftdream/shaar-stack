"""CI-only negative controls for the owned-DNS product graph comparison."""
import copy
import importlib.util
from pathlib import Path
import sys
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

    def test_exact_product_lock_reverses_only_one_edge(self):
        repository = Path(__file__).resolve().parents[4]
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
