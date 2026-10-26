"""CI-only cache preparation, probe reversal, and one-fault provenance controls."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("resolver_fixture", ROOT / "fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
prepare = fixture.prepare
REPOSITORY = ROOT.parents[4]
SOURCE = REPOSITORY / "target/p2p/resolver" / prepare.PACKAGE
ARCHIVE = REPOSITORY / "target/p2p/resolver-archive/resolver.crate"


class CachePreparationChecks(unittest.TestCase):
    def test_cache_rollback_preserves_accepted_locking_bytes(self):
        original = prepare.archive_files(ARCHIVE)
        prepared = prepare.verify(SOURCE)
        restored = prepare.cache_patch.reverse(prepared, prepare.patch.replace)
        for name in prepare.cache_patch.EDITS:
            self.assertEqual(restored[name], original[name])
        for name, expected in prepare.patch.transform(original).items():
            self.assertEqual(restored[name], expected)
            self.assertEqual(prepared[name], expected)
        self.assertEqual(restored["Cargo.toml"], prepared["Cargo.toml"])
        self.assertEqual(restored["src/lib.rs"], prepared["src/lib.rs"])

    def test_each_cache_anchor_rejects_missing_or_duplicate_text(self):
        original = prepare.archive_files(ARCHIVE)
        for name, edits in prepare.cache_patch.EDITS.items():
            for old, _ in edits:
                for replacement in ("unreviewed", old + old):
                    files = dict(original)
                    files[name] = files[name].replace(old.encode(), replacement.encode(), 1)
                    with self.assertRaisesRegex(ValueError, "anchor changed"):
                        prepare.cache_patch.transform(files, prepare.patch.replace)

    def test_fixture_probes_reverse_without_replacing_production_bodies(self):
        fixed, _ = fixture.transformed(SOURCE)
        fixture.cache_fixture.uninstrument(fixed, prepare)
        production = prepare.verify(SOURCE)
        for name in ["src/cache.rs", "src/caching_client.rs", "src/lib.rs"]:
            text = fixed[name].decode()
            for anchor in fixture.EXCLUSIONS[name]:
                text = text.replace("\n#[cfg(any())]\n" + anchor, "\n" + anchor)
            self.assertEqual(text.encode(), production[name])

    def test_counterfactuals_change_only_the_selected_mechanism(self):
        production = prepare.verify(SOURCE)
        fixed, _ = fixture.transformed(SOURCE)
        for mechanism in fixture.cache_fixture.MECHANISMS:
            files, record = fixture.transformed(SOURCE, mechanism)
            expected = dict(production)
            changed = fixture.cache_fixture.counterfactual(expected, mechanism, prepare)
            self.assertEqual([name for name in fixed if files[name] != fixed[name]], [changed])
            self.assertEqual(record["production_source_delta"], {changed: {
                "prepared_sha256": prepare.digest(production[changed]),
                "counterfactual_sha256": prepare.digest(expected[changed]),
            }})
            for name in prepare.patch.EDITS:
                self.assertEqual(files[name], fixed[name])
            restored = dict(files)
            fixture.cache_fixture.uninstrument(restored, prepare)
            for name in ["src/cache.rs", "src/caching_client.rs"]:
                restored[name] = restored[name].replace(b"\n#[cfg(any())]\nmod tests {", b"\nmod tests {")
                self.assertEqual(restored[name], expected[name])

    def test_source_pins_and_recipe_cover_cache_transform(self):
        original = prepare.archive_files(ARCHIVE)
        record = json.loads((SOURCE.parent / "provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(record["recipe_files"]["cache_patch.py"], prepare.digest((ROOT / "cache_patch.py").read_bytes()))
        for name in prepare.cache_patch.EDITS:
            self.assertEqual(prepare.PINS[name], prepare.digest(original[name]))
            self.assertIn(name, record["changed_files"])
        self.assertFalse(record["resolver_lifecycle_acceptance"])

    def test_upstream_private_field_test_adaptation_is_exact_and_reversible(self):
        original = prepare.archive_files(ARCHIVE)["src/cache.rs"].decode()
        converted = prepare.cache_patch.test_access(original)
        self.assertEqual(prepare.cache_patch.test_access(converted, reverse=True), original)
        boundary = "#[cfg(test)]\nmod tests {"
        self.assertEqual(converted.split(boundary)[0], original.split(boundary)[0])
        self.assertEqual(converted.count("cache.cache.as_ref().unwrap().get("), 18)
        with self.assertRaisesRegex(ValueError, "private test access changed"):
            prepare.cache_patch.test_access(original.replace("cache.cache.get(", "changed(", 1))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() and result.testsRun == 6 else 1)
