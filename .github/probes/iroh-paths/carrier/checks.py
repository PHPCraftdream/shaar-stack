"""CI-only source/graph contracts; these checks are not real-carrier frame evidence."""

import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def load(name):
    spec = importlib.util.spec_from_file_location("carrier_frame_contract_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


graph = load("graph")
instrument = load("instrument")
REGISTRY = "registry+https://example.invalid/reviewed-index"


def entry(name, version, dependencies=(), checksum=None):
    text = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
    if checksum is not None:
        text += f'source = "{REGISTRY}"\nchecksum = "{checksum}"\n'
    if dependencies:
        text += 'dependencies = [\n' + ''.join(f' "{dependency}",\n' for dependency in dependencies) + ']\n'
    return text + '\n'


def locks():
    product = "version = 4\n\n" + ''.join([
        entry("shaar", "0.1.0", ("iroh",)),
        entry("iroh", "1.3.0", ("noq", "core")),
        entry("noq", "1.3.0", ("noq-proto",)),
        entry("noq-proto", "1.3.0", ("core",)),
        entry("core", "1.0.0", checksum="a" * 64),
    ])
    reviewed = "version = 4\n\n" + ''.join([
        entry("iroh", "1.3.0", ("noq", "core", "n0-qlog"), "b" * 64),
        entry("noq", "1.3.0", ("noq-proto",), "c" * 64),
        entry("noq-proto", "1.3.0", ("core", "n0-qlog"), "d" * 64),
        entry("core", "1.0.0", checksum="a" * 64),
        entry("n0-qlog", "0.2.0", ("serde_json",), "e" * 64),
        entry("serde_json", "1.0.154", ("core",), "f" * 64),
    ])
    return product, reviewed


class FrameContracts(unittest.TestCase):
    def test_lock_derivation_preserves_product_identities_versions_checksums_and_edges(self):
        product, reviewed = locks()
        derived, receipt = graph.derive_lock(product, reviewed)
        _, before = graph.lock_blocks(product)
        _, after = graph.lock_blocks(derived)
        self.assertTrue(set(before) <= set(after))
        for key, (package, _) in before.items():
            self.assertEqual(package.get("checksum"), after[key][0].get("checksum"))
            original = {graph.resolve(name, before) for name in package.get("dependencies", [])}
            current = {graph.resolve(name, after) for name in after[key][0].get("dependencies", [])}
            self.assertTrue(original <= current)
        self.assertEqual({key[0] for key in set(after) - set(before)}, {"n0-qlog", "serde_json"})
        for name in graph.PATCHED:
            selected = [key for key in after if key[0] == name]
            self.assertEqual(selected, [(name, "1.3.0", None)])
        self.assertTrue(receipt["existing_versions_and_checksums_preserved"])
        self.assertEqual(tomllib.loads(derived)["version"], 4)

    def test_lock_derivation_rejects_disagreeing_registry_checksum(self):
        product, reviewed = locks()
        reviewed = reviewed.replace('checksum = "' + "a" * 64 + '"', 'checksum = "' + "9" * 64 + '"')
        with self.assertRaisesRegex(ValueError, "checksums disagree"):
            graph.derive_lock(product, reviewed)

    def test_lock_resolver_rejects_ambiguous_or_missing_reference(self):
        text = "version = 4\n" + entry("core", "1.0.0", checksum="a" * 64) + entry("core", "2.0.0", checksum="b" * 64)
        _, packages = graph.lock_blocks(text)
        for value in ("core", "missing", "--flag", "core 3.0.0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    graph.resolve(value, packages)
        self.assertEqual(graph.resolve("core 1.0.0", packages), ("core", "1.0.0", REGISTRY))

    def test_variant_cannot_omit_copied_source_selection_witnesses(self):
        with self.assertRaisesRegex(ValueError, "witness is incomplete"):
            graph.verify_variant({}, {}, HERE, b"", {})

    def test_observation_variant_requires_real_boolean(self):
        for value in ("false", "true", None, 1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "explicit boolean"):
                    instrument.workspace(REPO, HERE, HERE / "scenario.rs", value)

    def test_fixture_edits_refuse_changed_or_repeated_anchor_and_reverse_exact_bytes(self):
        target = REPO / "target"
        target.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="frame-source-contract-", dir=target) as temporary:
            root = Path(temporary)
            source = root / "sample.rs"
            before = b"prefix\nexact anchor\nsuffix\n"
            source.write_bytes(before)
            receipt = []
            instrument.edit(root, "sample.rs", "exact anchor", "fixture anchor", receipt)
            self.assertTrue(receipt[0]["reverse_verified"])
            self.assertEqual(source.read_bytes().replace(b"fixture anchor", b"exact anchor"), before)
            changed = source.read_bytes()
            with self.assertRaises(ValueError):
                instrument.edit(root, "sample.rs", "exact anchor", "fixture anchor", [])
            self.assertEqual(source.read_bytes(), changed)
            source.write_text("exact anchor\nexact anchor\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                instrument.edit(root, "sample.rs", "exact anchor", "fixture anchor", [])

    def test_fixture_destination_cannot_escape_repository_target(self):
        with self.assertRaises(ValueError):
            instrument.owned(REPO / "crates", REPO)


if __name__ == "__main__":
    unittest.main()
