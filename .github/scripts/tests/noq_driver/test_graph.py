"""CI-only contracts for the driver fixture's resolved dependency identities."""
import copy
import importlib.util
from pathlib import Path
import tomllib
import unittest

SPEC = importlib.util.spec_from_file_location("driver_graph", Path(__file__).with_name("graph.py"))
GRAPH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GRAPH)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def metadata():
    packages = []
    nodes = []
    for name, version in (("noq", "1.3.0"), ("tokio", "1.54.1"),
                          ("rustls", "0.23.46"), ("rcgen", "0.14.10"), ("rcgen", "0.13.2")):
        key = f"{name}@{version}"
        packages.append({"id": key, "name": name, "version": version,
                         "source": REGISTRY, "manifest_path": f"/fixture/{key}/Cargo.toml"})
        nodes.append({"id": key, "deps": [], "features": ["ring"] if name == "rcgen" else []})
    return {"packages": packages, "resolve": {"nodes": nodes}}


class DriverGraphTests(unittest.TestCase):
    def test_two_rcgen_versions_select_the_reviewed_suite_identity_independent_of_order(self):
        data = metadata()
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                data["packages"].sort(key=lambda package: package["id"], reverse=reverse)
                _, _, seeds, reached = GRAPH.closure(data)
                self.assertEqual(seeds["rcgen"], "rcgen@0.14.10")
                self.assertIn("rcgen@0.14.10", reached)
                self.assertNotIn("rcgen@0.13.2", reached)
                declarations = tomllib.loads(GRAPH.manifest_dependencies(data))
                self.assertEqual(declarations["rcgen"]["version"], "=0.14.10")
                self.assertEqual(declarations["rcgen"]["features"], ["ring"])
                self.assertFalse(declarations["rcgen"]["default-features"])

    def test_older_rcgen_is_not_removed_if_reachable_through_a_normal_driver_edge(self):
        data = metadata()
        data["resolve"]["nodes"][0]["deps"] = [
            {"name": "older_cert", "pkg": "rcgen@0.13.2",
             "dep_kinds": [{"kind": None, "target": None}]}]
        _, _, seeds, reached = GRAPH.closure(data)
        self.assertEqual(seeds["rcgen"], "rcgen@0.14.10")
        self.assertIn("rcgen@0.13.2", reached)
        declarations = tomllib.loads(GRAPH.manifest_dependencies(data))
        versions = {entry["version"] for entry in declarations.values() if entry["package"] == "rcgen"}
        self.assertEqual(versions, {"=0.13.2", "=0.14.10"})

    def test_missing_or_changed_reviewed_rcgen_never_falls_back_to_another_version(self):
        for replacement in (None, "0.14.11"):
            with self.subTest(replacement=replacement):
                data = metadata()
                if replacement is None:
                    data["packages"] = [p for p in data["packages"] if p["id"] != "rcgen@0.14.10"]
                else:
                    next(p for p in data["packages"] if p["id"] == "rcgen@0.14.10")["version"] = replacement
                with self.assertRaisesRegex(ValueError, "ambiguous driver closure seed: rcgen"):
                    GRAPH.closure(data)

    def test_duplicate_reviewed_identity_and_other_ambiguous_seeds_still_fail(self):
        for name in ("rcgen", "noq", "tokio", "rustls"):
            with self.subTest(name=name):
                data = metadata()
                duplicate = copy.deepcopy(next(p for p in data["packages"] if p["name"] == name))
                duplicate["id"] += "-other-source"
                duplicate["source"] = "registry+https://other.invalid/index"
                data["packages"].append(duplicate)
                with self.assertRaisesRegex(ValueError, f"ambiguous driver closure seed: {name}"):
                    GRAPH.closure(data)

    def test_unreviewed_non_registry_sources_remain_rejected(self):
        data = metadata()
        next(p for p in data["packages"] if p["id"] == "rcgen@0.14.10")["source"] = "git+https://invalid"
        with self.assertRaisesRegex(ValueError, "unreviewed non-registry closure source"):
            GRAPH.manifest_dependencies(data)


if __name__ == "__main__":
    unittest.main()
