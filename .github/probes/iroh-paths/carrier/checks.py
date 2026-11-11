"""CI-only source/graph contracts; these checks are not real-carrier frame evidence."""

import ast
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
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


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
        entry("n0-qlog", "0.2.0", ("serde_json", "serde_with"), "e" * 64),
        entry("serde_json", "1.0.154", ("core",), "f" * 64),
        entry("serde_with", "3.24.0", ("darling",), "1" * 64),
        entry("darling", "0.24.1", ("darling_core", "darling_macro"), "2" * 64),
        entry("darling_core", "0.24.1", ("ident_case", "strsim"), "3" * 64),
        entry("darling_macro", "0.24.1", ("darling_core",), "4" * 64),
        entry("ident_case", "1.0.1", checksum="5" * 64),
        entry("strsim", "0.11.1", checksum="6" * 64),
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
        self.assertEqual({tuple(key) for key in receipt["declared_observation_roots"]}, graph.OBSERVATION_ROOTS)
        self.assertEqual({key[0] for key in set(after) - set(before)},
                         {"n0-qlog", "serde_json", "serde_with", "darling", "darling_core", "darling_macro", "ident_case", "strsim"})
        for name in graph.PATCHED:
            selected = [key for key in after if key[0] == name]
            self.assertEqual(selected, [(name, "1.3.0", None)])
        self.assertTrue(receipt["existing_versions_and_checksums_preserved"])
        self.assertEqual(tomllib.loads(derived)["version"], 4)

    def shared_json_locks(self, dependencies_already_present=False):
        product, reviewed = locks()
        product += entry("serde_json", "1.0.154", ("core", "product-only"), "f" * 64)
        product += entry("product-only", "1.0.0", checksum="7" * 64)
        added = entry("foldhash", "0.2.0", checksum="8" * 64)
        added += entry("indexmap", "2.14.0", ("core",), "9" * 64)
        reviewed = reviewed.replace(entry("serde_json", "1.0.154", ("core",), "f" * 64),
            entry("serde_json", "1.0.154", ("core", "foldhash", "indexmap"), "f" * 64)) + added
        if dependencies_already_present:
            product += added
        return product, reviewed

    def test_existing_json_merges_reviewed_edges_without_replacing_product_edges(self):
        for present in (False, True):
            for newline in ("\n", "\r\n"):
                with self.subTest(present=present, newline=newline):
                    product, reviewed = self.shared_json_locks(present)
                    product, reviewed = product.replace("\n", newline), reviewed.replace("\n", newline)
                    derived, _ = graph.derive_lock(product, reviewed)
                    _, packages = graph.lock_blocks(derived)
                    package = packages[("serde_json", "1.0.154", REGISTRY)][0]
                    self.assertEqual({graph.resolve(dep, packages)[0] for dep in package["dependencies"]},
                                     {"core", "product-only", "foldhash", "indexmap"})
                    graph.validate_derived_lock(product, reviewed, derived)
                    blocks = derived.split("[[package]]")
                    index = next(i for i, block in enumerate(blocks) if 'name = "serde_json"' in block)
                    blocks[index] = blocks[index].replace(' "foldhash",' + newline, "")
                    with self.assertRaisesRegex(ValueError, "dependencies differ"):
                        graph.validate_derived_lock(product, reviewed, "[[package]]".join(blocks))

    def test_shared_json_observation_growth_is_exact_and_rejects_other_features_and_edges(self):
        _, reviewed = self.shared_json_locks()
        key = ("serde_json", "1.0.154", REGISTRY)
        core = ("core", ("core", "1.0.0", REGISTRY), None, None)
        extra = {(name, (name, version, REGISTRY), None, None)
                 for name, version in (("foldhash", "0.2.0"), ("indexmap", "2.14.0"))}
        before = ({"std"}, {core})
        after = ({"std", "alloc", "indexmap", "preserve_order"}, {core} | extra)
        self.assertTrue(graph.shared_observation_growth(key, before, after, reviewed))
        for features, edges in ((after[0] | {"unbounded_depth"}, after[1]),
                                (after[0] - {"preserve_order"}, after[1]),
                                (after[0], {core}),
                                (after[0], extra),
                                (after[0], after[1] | {("evil", ("core", "1.0.0", REGISTRY), None, None)}),
                                (after[0], {core} | {(name, target, "build", platform)
                                                    for name, target, _, platform in extra})):
            with self.subTest(features=features, edges=edges), self.assertRaisesRegex(
                    ValueError, "unreviewed shared serde_json"):
                graph.shared_observation_growth(key, before, (features, edges), reviewed)
        for other in (("serde_json", "1.0.155", REGISTRY), ("unrelated", "1.0.154", REGISTRY)):
            self.assertFalse(graph.shared_observation_growth(other, before, after, reviewed))

    def test_lock_derivation_normalizes_lf_and_crlf_inputs_without_changing_lock_semantics(self):
        product, reviewed = locks()
        outputs = []
        inputs = (("\n", "\n"), ("\r\n", "\r\n"), ("\r\n", "\n"), ("\n", "\r\n"))
        for product_newline, reviewed_newline in inputs:
            derived, _ = graph.derive_lock(product.replace("\n", product_newline), reviewed.replace("\n", reviewed_newline))
            parsed = tomllib.loads(derived)
            outputs.append({(item["name"], item["version"], item.get("source")): item for item in parsed["package"]})
        self.assertTrue(all(output == outputs[0] for output in outputs[1:]))
        _, source_packages = graph.lock_blocks(product)
        derived_packages = {key: (package, "") for key, package in outputs[0].items()}
        for key, (package, _) in source_packages.items():
            original_edges = {graph.resolve(dep, source_packages) for dep in package.get("dependencies", [])}
            derived_edges = {graph.resolve(dep, derived_packages) for dep in outputs[0][key].get("dependencies", [])}
            self.assertTrue(original_edges <= derived_edges)
            self.assertEqual(package.get("checksum"), outputs[0][key].get("checksum"))

    def test_lock_derivation_rejects_unreviewed_closure_and_root_version_or_checksum_drift(self):
        product, reviewed = locks()
        derived, receipt = graph.derive_lock(product, reviewed)
        self.assertEqual({key[0] for key in {tuple(item) for item in receipt["added_registry_identities"]}},
                         {"n0-qlog", "serde_json", "serde_with", "darling", "darling_core", "darling_macro", "ident_case", "strsim"})
        mutated_candidates = (
            derived.replace('checksum = "' + "1" * 64 + '"', 'checksum = "' + "8" * 64 + '"'),
            derived.replace('version = "3.24.0"', 'version = "3.24.1"'),
            derived.replace('checksum = "' + "2" * 64 + '"', 'checksum = "' + "8" * 64 + '"'),
            derived.replace('checksum = "' + "e" * 64 + '"', 'checksum = "' + "8" * 64 + '"'),
            derived + entry("unrelated", "1.0.0", checksum="7" * 64),
        )
        for mutated in mutated_candidates:
            with self.assertRaises(ValueError):
                graph.validate_derived_lock(product, reviewed, mutated)
        reviewed_blocks = reviewed.split("[[package]]")
        for index, block in enumerate(reviewed_blocks):
            if 'name = "iroh"' in block and 'version = "1.3.0"' in block:
                reviewed_blocks[index] = block.replace('"n0-qlog",', '"n0-qlog",\n "unrelated",', 1)
                break
        self.assertTrue(any('"unrelated"' in block for block in reviewed_blocks))
        extended_reviewed = "[[package]]".join(reviewed_blocks) + entry("unrelated", "1.0.0", checksum="7" * 64)
        with self.assertRaisesRegex(ValueError, "reviewed root closure"):
            graph.derive_lock(product, extended_reviewed)
        for changed in (
            reviewed.replace('name = "n0-qlog"\nversion = "0.2.0"', 'name = "n0-qlog"\nversion = "0.2.1"'),
            reviewed.replace('name = "n0-qlog"\nversion = "0.2.0"\nsource = "' + REGISTRY + '"', 'name = "n0-qlog"\nversion = "0.2.0"\nsource = "registry+https://example.invalid/index"'),
        ):
            with self.assertRaises(ValueError):
                graph.derive_lock(product, changed)

    def prepared_locks(self, name, version):
        product = "version = 4\n\n" + ''.join([
            entry("shaar", "0.1.0", ("iroh",)),
            entry("iroh", "1.3.0", ("noq", "core", name)),
            entry("noq", "1.3.0", ("noq-proto",)),
            entry("noq-proto", "1.3.0", ("core",)),
            entry("core", "1.0.0", checksum="a" * 64),
            entry(name, version),
        ])
        _, reviewed = locks()
        blocks = reviewed.split("[[package]]")
        index = next(i for i, block in enumerate(blocks) if 'name = "iroh"' in block)
        blocks[index] = blocks[index].replace('"n0-qlog",', '"n0-qlog",\n "' + name + '",', 1)
        return product, "[[package]]".join(blocks) + entry(name, version, checksum="7" * 64)

    def test_lock_derivation_maps_reviewed_registry_identities_to_prepared_product_paths(self):
        for name, version in sorted(graph.PATH_PREPARED):
            product, reviewed = self.prepared_locks(name, version)
            derived, receipt = graph.derive_lock(product, reviewed)
            _, after = graph.lock_blocks(derived)
            self.assertIn((name, version, None), after)
            self.assertNotIn((name, version, REGISTRY), after)
            self.assertNotIn(name, {item[0] for item in receipt["added_registry_identities"]})

    def test_lock_derivation_does_not_remap_unreviewed_prepared_paths(self):
        product, reviewed = self.prepared_locks("unreviewed-lib", "1.0.0")
        with self.assertRaisesRegex(ValueError, "reviewed root closure"):
            graph.derive_lock(product, reviewed)

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

    def test_shared_ciphertext_writer_keeps_lf_and_exact_reversal_on_every_host(self):
        target = REPO / "target"
        target.mkdir(exist_ok=True)
        helper = REPO / instrument.PACKET_HELPER
        tree = ast.parse(helper.read_bytes())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "apply")
        constants = {node.targets[0].id: ast.literal_eval(node.value) for node in function.body
                     if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id in {"call", "before"}}
        with tempfile.TemporaryDirectory(prefix="frame-lf-contract-", dir=target) as temporary:
            root = Path(temporary)
            (root / "src/connection").mkdir(parents=True)
            (root / "Cargo.toml").write_bytes(b'[package]\nname = "noq-proto"\nversion = "1.3.0"\n')
            files = {"src/connection/packet_builder.rs": constants["call"],
                     "src/connection/qlog.rs": constants["before"]}
            for name, anchor in files.items():
                (root / name).write_bytes(("prefix\n" + anchor + "\nsuffix\n").encode())
            receipt = instrument.packet_identity(REPO, root)
            self.assertEqual({record["path"] for record in receipt["files"]}, set(files))
            self.assertTrue(all(record["reverse_verified"] for record in receipt["files"]))
            for name in files:
                self.assertNotIn(b"\r\n", (root / name).read_bytes())

    def test_send_and_receive_diagnostics_remain_fixture_only_and_preserve_guards(self):
        (REPO / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="carrier-observer-", dir=REPO / "target") as temporary:
            root = Path(temporary)
            driver_path = root / "crates/shaar-p2p/src/bridge/driver.rs"
            driver_path.parent.mkdir(parents=True)
            driver_path.write_text(
                "        let _ = handle.send_on(frame.link, frame.packet).await;\n"
                "                if !handle.is_current(&received) { continue; }\n"
                "                let Ok(source) = source else { continue; };\n"
                "                if !shared.matches(&source, link) { continue; }\n"
                "                permit.send(Inbound { received, source });\n",
                encoding="utf-8")
            library = root / "crates/shaar-p2p/src/lib.rs"
            library.parent.mkdir(parents=True, exist_ok=True)
            library.write_text("#![forbid(unsafe_code)]\n", encoding="utf-8")
            receipt = instrument.observer(REPO, root)
            source = driver_path.read_text(encoding="utf-8")
            self.assertEqual(len(receipt["files"]), 6)
            self.assertTrue(all(item["reverse_verified"] for item in receipt["files"]))
            self.assertEqual(source.count("handle.send_on(frame.link, frame.packet).await"), 1)
            self.assertIn("packet_hex(&frame.packet)", source)
            self.assertIn("receive_rejected(handle.peer_id(), \"stale\", &received)", source)
            self.assertIn("let Ok(source) = source else { crate::carrier_frame_probe::receive_rejected(handle.peer_id(), \"no-source\", &received); continue; };", source)
            self.assertIn("receive_rejected(handle.peer_id(), \"route-mismatch\", &received)", source)
            self.assertIn("received(handle.peer_id(), &received, &source)", source)
            self.assertLess(source.index("is_current"), source.index("receive_rejected(handle.peer_id(), \"stale\""))
            self.assertLess(source.index("route-mismatch"), source.index("permit.send(Inbound"))

    def test_fixture_destination_cannot_escape_repository_target(self):
        with self.assertRaises(ValueError):
            instrument.owned(REPO / "crates", REPO)


if __name__ == "__main__":
    unittest.main()
