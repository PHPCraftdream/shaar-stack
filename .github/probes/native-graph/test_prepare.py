# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Filesystem-backed tests for native graph preparation and verification."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import tomllib

ROOT_MANIFEST = (
    b"[workspace]\nmembers=['iroh-mainline-address-lookup', 'iroh-mdns-address-lookup']\n"
    b"[workspace.lints.rust]\nmissing_debug_implementations = 'warn'\n"
    b"unexpected_cfgs = { level = 'warn', check-cfg = ['cfg(docsrs)'] }\n"
    b"[workspace.lints.clippy]\nunused-async = 'allow'\n"
)
SELECTED_MANIFEST = (
    b"[package]\nname='iroh-mainline-address-lookup'\nversion='0.6.1'\n\n[lints]\nworkspace=true\n"
)
MDNS_MANIFEST = b"[package]\nname='iroh-mdns-address-lookup'\nversion='0.1.0'\n\n[lints]\nworkspace=true\n"
INSERTED_MANIFEST = SELECTED_MANIFEST.replace(
    b"[package]\n", b'[package]\nworkspace = ".."\n', 1
)
SELECTED = "iroh-mainline-address-lookup/Cargo.toml"
FUTURE_TARGET = 'cfg(not(all(target_family = "wasm", target_os = "unknown")))'
FUTURE_MANIFEST = b'''[package]
name = "n0-future"
version = "0.3.2"

[dependencies]
tokio = { version = "1.28", features = [] }

[target.'cfg(not(all(target_family = "wasm", target_os = "unknown")))'.dependencies.tokio]
version = "1.28"
features = [
    "rt",
    "time",
    "macros",
    "test-util",
]

[target.'cfg(not(all(target_family = "wasm", target_os = "unknown")))'.dependencies.tokio-util]
version = "0.7.14"
features = ["rt"]
'''
FUTURE_ORIG = b'''[package]
name = "n0-future"
version = "0.3.2"

[dependencies]
tokio = { version = "1.28", features = [] }

[target.'cfg(not(all(target_family = "wasm", target_os = "unknown")))'.dependencies]
tokio = { version = "1.28", features = ["rt", "time", "macros", "test-util"] }
tokio-util = { version = "0.7.14", features = ["rt"] }
'''
FUTURE_CHANGED = b'''[package]
name = "n0-future"
version = "0.3.2"

[dependencies]
tokio = { version = "1.28", features = [] }

[target.'cfg(not(all(target_family = "wasm", target_os = "unknown")))'.dependencies.tokio]
version = "1.28"
features = [
    "rt",
    "time",
    "macros",
]

[target.'cfg(not(all(target_family = "wasm", target_os = "unknown")))'.dev-dependencies.tokio]
version = "1.28"
features = ["test-util"]

[target.'cfg(not(all(target_family = "wasm", target_os = "unknown")))'.dependencies.tokio-util]
version = "0.7.14"
features = ["rt"]
'''


sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare


class CandidateResolutionTests(unittest.TestCase):
    def test_candidate_preparation_failure_is_fail_closed(self):
        import ci

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "target/native-graph"
            destination.mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nexclude = ["target/native-graph/adapter/iroh-mainline-address-lookup"]\nmembers = []\n',
                encoding="utf-8",
            )
            lock_path = root / "Cargo.lock"
            lock_bytes = b'version = 4\n'
            lock_path.write_bytes(lock_bytes)
            receipt_path = destination / "ci-receipt.json"
            commands = []

            with (
                patch.multiple(ci, ROOT=root, DESTINATION=destination,
                               LOGS=destination / "logs", RECEIPT=receipt_path,
                               COMMANDS=commands),
                patch.object(ci, "ensure_sources", side_effect=ValueError("prepared inventory mismatch")),
                patch.object(ci.subprocess, "run", side_effect=AssertionError("resolution must not run")),
            ):
                with self.assertRaisesRegex(ValueError, "prepared inventory mismatch"):
                    ci.resolve_candidate()

            record = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertFalse(record["accepted"])
            self.assertEqual(record["mode"], "candidate-resolution-failed")
            self.assertEqual(record["commands"], [])
            self.assertEqual(lock_path.read_bytes(), lock_bytes)
            self.assertFalse((destination / "Cargo.candidate.lock").exists())

    def test_candidate_resolution_defers_full_comparison(self):
        self._candidate_case()

    def test_candidate_resolution_rejects_audit_drift(self):
        for mutation in ('checksum', 'source', 'edge', 'path', 'retained', 'adapter-source', 'duplicate', 'unknown-node', 'dev-edge'):
            with self.subTest(mutation=mutation):
                self._candidate_case(mutation)

    def _candidate_case(self, mutation=None):
        import ci
        import test_graph
        import graph

        fixtures = test_graph.GraphTests()
        before, after = fixtures.reviewed_lock_fixture()
        before['package'].append({
            'name': 'n0-future',
            'version': '0.3.2',
            'source': graph.REGISTRY,
            'checksum': 'e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe',
            'dependencies': [],
        })
        after['package'].append({
            'name': 'n0-future',
            'version': '0.3.2',
            'dependencies': [],
        })
        if mutation == 'checksum':
            before['package'][-1]['checksum'] = '0' * 64
        elif mutation == 'source':
            before['package'][-1]['source'] = 'registry+https://example.invalid/index'
        elif mutation == 'retained':
            next(p for p in after['package'] if p['name'] == 'serde')['checksum'] = 'changed'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "target/native-graph"
            destination.mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nexclude = ["target/native-graph/adapter/iroh-mainline-address-lookup"]\nmembers = []\n',
                encoding="utf-8",
            )
            lock_path = root / "Cargo.lock"
            lock_path.write_bytes(fixtures.toml(before))
            metadata = fixtures.reviewed_metadata()
            for package in metadata["packages"]:
                name = package["name"]
                if name in graph.GENERATED_PATHS:
                    package["manifest_path"] = str(root / graph.GENERATED_PATHS[name] / "Cargo.toml")
            if mutation == 'path':
                next(p for p in metadata['packages'] if p['name'] == 'n0-future')['manifest_path'] = str(
                    root / 'wrong/Cargo.toml'
                )
            elif mutation == 'edge':
                next(n for n in metadata['resolve']['nodes'] if n['id'] == 'iroh')['deps'] = []
            elif mutation == 'unknown-node':
                metadata['resolve']['nodes'].append({'id': 'unknown', 'deps': []})
            elif mutation == 'dev-edge':
                iroh_node = next(node for node in metadata['resolve']['nodes'] if node['id'] == 'iroh')
                future_edge = next(edge for edge in iroh_node['deps'] if edge['pkg'] == 'n0-future')
                future_edge['dep_kinds'] = [{'kind': 'dev', 'target': None}]
            elif mutation == 'adapter-source':
                adapterpackage = next(p for p in metadata['packages'] if p['name'] == 'iroh-mainline-address-lookup')
                adapterpackage['source'] = graph.REGISTRY
            elif mutation == 'duplicate':
                metadata['packages'].append({**next(p for p in metadata['packages'] if p['name'] == 'n0-future'), 'id': 'future-other', 'version': '0.3.3'})

            def runner(argv, *, cwd, **kwargs):
                self.assertEqual(argv, ["cargo", "metadata", "--format-version", "1"])
                self.assertEqual(cwd, root)
                lock_path.write_bytes(fixtures.toml(after))
                return types.SimpleNamespace(
                    stdout=json.dumps(metadata).encode(), stderr=b"", returncode=0
                )

            commands = [{'argv': ['stale']}]
            receipt_path = destination / "ci-receipt.json"
            with (
                patch.multiple(ci, ROOT=root, DESTINATION=destination,
                               LOGS=destination / "logs", RECEIPT=receipt_path,
                               COMMANDS=commands),
                patch.object(ci, "ensure_sources"),
                patch.object(ci.subprocess, "run", side_effect=runner),
                patch.object(ci, "feature_comparison", side_effect=AssertionError("full comparison ran")),
                patch.object(ci, "verify_future_dev", side_effect=AssertionError("future dev verification ran")),
            ):
                if mutation:
                    with self.assertRaises(ValueError):
                        ci.resolve_candidate()
                    record = json.loads(receipt_path.read_text(encoding='utf-8'))
                    self.assertFalse(record["accepted"])
                    self.assertEqual(record["mode"], "candidate-resolution-failed")
                    self.assertEqual(len(record["commands"]), 1)
                    self.assertEqual((destination / "Cargo.before.lock").read_bytes(), fixtures.toml(before))
                    self.assertEqual((destination / "Cargo.candidate.lock").read_bytes(), fixtures.toml(after))
                    command = record["commands"][0]
                    self.assertEqual(command["exit_code"], 0)
                    self.assertEqual(command["stdout_sha256"], hashlib.sha256(json.dumps(metadata).encode()).hexdigest())
                    self.assertEqual(command["stderr_sha256"], hashlib.sha256(b"").hexdigest())
                    self.assertEqual((destination / "logs" / command["stderr_log"]).read_bytes(), b"")
                    self.assertNotIn("normal_feature_comparison", record)
                    return
                receipt = ci.resolve_candidate()

            self.assertFalse(receipt["accepted"])
            self.assertEqual(receipt['verification_status'],'deferred-to-verify-locked')
            self.assertNotIn("normal_feature_comparison", receipt)
            self.assertEqual((destination / "Cargo.before.lock").read_bytes(), fixtures.toml(before))
            self.assertEqual((destination / "Cargo.candidate.lock").read_bytes(), fixtures.toml(after))
            record = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertFalse(record["accepted"])
            self.assertEqual(record["mode"], "candidate-resolution-not-acceptance")
            self.assertEqual(record["verification_status"], "deferred-to-verify-locked")
            self.assertEqual(len(record["commands"]), 1)
            command = record["commands"][0]
            raw_stdout = json.dumps(metadata).encode()
            self.assertEqual(command["cwd"], str(root))
            self.assertEqual(command["stdout_sha256"], hashlib.sha256(raw_stdout).hexdigest())
            self.assertEqual(command["stderr_sha256"], hashlib.sha256(b"").hexdigest())
            self.assertEqual((destination / "logs" / command["stdout_log"]).read_bytes(), raw_stdout)
            self.assertEqual((destination / "logs" / command["stderr_log"]).read_bytes(), b"")
            self.assertEqual(record["commands"][0]["argv"], ["cargo", "metadata", "--format-version", "1"])
            self.assertEqual(record["commands"][0]["exit_code"], 0)
            self.assertEqual(record["after_sha256"], hashlib.sha256(fixtures.toml(after)).hexdigest())


class PatchedProjectionTests(unittest.TestCase):
    def test_dev_projection_requires_real_manifest_and_preparation_evidence(self):
        import graph

        owner_identity = ("shaar", "0.1.0", "path")
        target_identity = ("n0-future", "0.3.2", "path")
        future_bytes = PreparationTests().future_archive()
        future_sha = hashlib.sha256(future_bytes).hexdigest()
        self.enterContext(patch.object(prepare, "FUTURE_SHA", future_sha))
        for mutation in (None, "missingpatch", "wrongpatch", "targetpath", "version", "source",
                         "archive", "manifest", "recipe", "mixedkind", "req", "alias", "target",
                         "missingcontext", "missingarchive", "missingreceipt", "rootdrift", "buildkind", "normalmanifest",
                         "consumerpath", "optional", "normaledge", "broadreq", "badarchive"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                future_archive = root / "future.crate"
                future_archive.write_bytes(future_bytes)
                generated = root / "target/native-graph/n0-future-0.3.2"
                generated.mkdir(parents=True)
                (generated / "Cargo.toml").write_bytes(FUTURE_CHANGED)
                (generated / "Cargo.toml.orig").write_bytes(FUTURE_ORIG)
                (generated / "src").mkdir()
                (generated / "src/lib.rs").write_bytes(b"runtime unchanged\n")
                (generated / "build.rs").write_bytes(b"build unchanged\n")
                owner_dir = root / "crates/shaar"
                owner_dir.mkdir(parents=True)
                (owner_dir / "Cargo.toml").write_text(
                    '[package]\nname="shaar"\nversion="0.1.0"\n'
                    '[dev-dependencies]\nn0-future = "=0.3.2"\n', encoding="utf-8")
                patch_line = 'n0-future = { path = "target/native-graph/n0-future-0.3.2" }'
                if mutation == "missingpatch":
                    patch_text = ""
                elif mutation == "wrongpatch":
                    patch_text = 'n0-future = { path = "wrong" }'
                else:
                    patch_text = patch_line
                root_manifest = root / "Cargo.toml"
                root_manifest.write_text(f"[patch.crates-io]\n{patch_text}\n", encoding="utf-8")
                original_files = {"Cargo.toml": FUTURE_MANIFEST, "Cargo.toml.orig": FUTURE_ORIG,
                                  "src/lib.rs": b"runtime unchanged\n", "build.rs": b"build unchanged\n"}
                prepared_files = {**original_files, "Cargo.toml": FUTURE_CHANGED}
                recipe = {".github/probes/native-graph/prepare.py": hashlib.sha256(
                    Path(prepare.__file__).read_bytes()).hexdigest()}
                receipt = {"package": "n0-future", "version": "0.3.2",
                           "archive_sha256": prepare.FUTURE_SHA,
                           "source": {"kind": "registry-archive", "archive_sha256": prepare.FUTURE_SHA},
                           "recipe_files": recipe, "original_files": prepare.hashes(original_files),
                           "prepared_files": prepare.hashes(prepared_files), "changed_files": ["Cargo.toml"]}
                (root / "target/native-graph/n0-future-0.3.2.provenance.json").write_text(json.dumps(receipt), encoding="utf-8")
                iroh = {"id": "iroh", "name": "iroh", "version": "1.3.0", "source": graph.REGISTRY,
                        "manifest_path": str(root / "iroh/Cargo.toml"),
                        "dependencies": [{"name": "n0-future", "rename": None, "req": "^0.3.2",
                                          "kind": None, "target": None, "features": [], "optional": False,
                                          "source": graph.REGISTRY}]}
                owner = {"id": "owner", "name": "shaar", "version": "0.1.0", "source": None,
                         "manifest_path": str(owner_dir / "Cargo.toml"),
                         "dependencies": [{"name": "iroh", "rename": None, "req": "*", "kind": None,
                                           "target": None, "features": [], "optional": False, "source": graph.REGISTRY},
                                          {"name": "n0-future", "rename": None, "req": "=0.3.2", "kind": "dev",
                                           "target": None, "features": [], "optional": False, "source": graph.REGISTRY}]}
                target = {"id": "future", "name": "n0-future", "version": "0.3.2", "source": None,
                          "manifest_path": str(generated / "Cargo.toml"), "dependencies": []}
                iroh_edge = {"pkg": "iroh", "name": "iroh", "dep_kinds": [{"kind": None, "target": None}]}
                edge = {"pkg": "future", "name": "n0_future", "dep_kinds": [{"kind": "dev", "target": None}]}
                consumer_owner = {**owner, "id": "consumer-owner"}
                product = {"workspace_root": str(root), "packages": [owner, iroh, target],
                           "resolve": {"nodes": [{"id": "owner", "deps": [iroh_edge, edge]},
                                                   {"id": "iroh", "deps": [{"pkg": "future", "name": "n0-future", "dep_kinds": [{"kind": None, "target": None}]}]},
                                                   {"id": "future", "deps": []}]}}
                consumer_target = {**target, "id": "consumer-future"}
                consumer_iroh = {**iroh, "id": "consumer-iroh"}
                consumer = {"packages": [consumer_owner, consumer_iroh, consumer_target], "resolve": {"nodes": [
                    {"id": "consumer-owner", "deps": [{**iroh_edge, "pkg": "consumer-iroh"}]},
                    {"id": "consumer-iroh", "deps": [{"pkg": "consumer-future", "name": "n0-future", "dep_kinds": [{"kind": None, "target": None}]}]},
                    {"id": "consumer-future", "deps": []}]}}
                if mutation == "targetpath":
                    target["manifest_path"] = str(root / "wrong/Cargo.toml")
                if mutation == "version":
                    target["version"] = "0.3.3"
                if mutation == "source":
                    target["source"] = graph.REGISTRY
                if mutation == "mixedkind":
                    edge["dep_kinds"].append({"kind": None, "target": None})
                if mutation == "buildkind":
                    edge["dep_kinds"][0]["kind"] = "build"
                if mutation == "req":
                    owner["dependencies"][1]["req"] = "=0.3.3"
                if mutation == "alias":
                    edge["name"] = "other"
                if mutation == "target":
                    edge["dep_kinds"][0]["target"] = "cfg(unix)"
                if mutation == "manifest":
                    (generated / "Cargo.toml").write_bytes(FUTURE_MANIFEST)
                if mutation == "archive":
                    receipt["archive_sha256"] = "0" * 64
                if mutation == "recipe":
                    receipt["recipe_files"] = {}
                if mutation in ("archive", "recipe"):
                    (root / "target/native-graph/n0-future-0.3.2.provenance.json").write_text(json.dumps(receipt), encoding="utf-8")
                if mutation == "normalmanifest":
                    with (owner_dir / "Cargo.toml").open("a", encoding="utf-8") as stream:
                        stream.write("\n[dependencies]\nn0-future = \"=0.3.2\"\n")
                if mutation == "consumerpath":
                    consumer_target["manifest_path"] = str(root / "wrong/Cargo.toml")
                if mutation == "optional":
                    owner["dependencies"][1]["optional"] = True
                if mutation == "normaledge":
                    edge["dep_kinds"][0]["kind"] = None
                if mutation == "broadreq":
                    owner["dependencies"][1]["req"] = "^0.3.2"
                    ownerfile = owner_dir / "Cargo.toml"
                    ownerfile.write_text(ownerfile.read_text(encoding="utf-8").replace("=0.3.2", "^0.3.2"), encoding="utf-8")
                if mutation == "badarchive":
                    future_archive.write_bytes(b"wrong")
                raw_product, raw_consumer = json.dumps(product).encode(), json.dumps(consumer).encode()
                argv = ["cargo", "metadata", "--format-version", "1"]
                context = graph.build_projection_context(raw_product, raw_consumer,
                    product_record={"exit_code": 0, "argv": argv, "cwd": str(root), "stdout_sha256": hashlib.sha256(raw_product).hexdigest()},
                    consumer_record={"exit_code": 0, "argv": argv, "cwd": str(root), "stdout_sha256": hashlib.sha256(raw_consumer).hexdigest()},
                    product_argv=argv, consumer_argv=argv, product_cwd=root, consumer_cwd=root,
                    product_root_manifest=root_manifest, future_archive=future_archive)
                if mutation == "missingcontext":
                    context.pop("product_root_manifest")
                if mutation == "missingarchive":
                    context.pop("future_archive")
                if mutation == "missingreceipt":
                    (root / "target/native-graph/n0-future-0.3.2.provenance.json").unlink()
                product_lock = (
                    b'version = 4\n[[package]]\nname="shaar"\nversion="0.1.0"\n'
                    b'dependencies=["iroh", "n0-future"]\n\n[[package]]\nname="iroh"\n'
                    b'version="1.3.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n'
                    b'dependencies=["n0-future"]\n\n[[package]]\nname="n0-future"\n'
                    b'version="0.3.2"\ndependencies=[]\n'
                )
                if mutation == "rootdrift":
                    with root_manifest.open("a", encoding="utf-8") as stream:
                        stream.write("\n")
                consumer_lock = (product_lock.replace(
                    b'dependencies=["iroh", "n0-future"]', b'dependencies=["iroh"]', 1
                ) + b'\n[[package]]\nname="native-graph-normal-consumer"\nversion="0.0.0"\ndependencies=["shaar"]\n')
                if mutation is None:
                    proof = graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context)
                    self.assertEqual(proof["proven_projection_edges"][0]["manifest_sha256"], hashlib.sha256((owner_dir / "Cargo.toml").read_bytes()).hexdigest())
                    self.assertEqual(proof["proven_projection_edges"][0]["prepared_receipt_sha256"], hashlib.sha256((root / "target/native-graph/n0-future-0.3.2.provenance.json").read_bytes()).hexdigest())
                    self.assertEqual(proof["proven_projection_edges"][0]["root_manifest_sha256"], hashlib.sha256(root_manifest.read_bytes()).hexdigest())
                    self.assertEqual(proof["proven_projection_edges"][0]["archive_sha256"], future_sha)
                    self.assertEqual(proof["proven_projection_edges"][0]["prepared_manifest_sha256"], hashlib.sha256(FUTURE_CHANGED).hexdigest())
                else:
                    with self.assertRaises(ValueError):
                        graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context)


class PreparationTests(unittest.TestCase):
    def adapter_archive(self) -> bytes:
        files = {
            "Cargo.toml": ROOT_MANIFEST,
            SELECTED: SELECTED_MANIFEST,
            "iroh-mainline-address-lookup/src/lib.rs": b"pub fn original() {}\n",
            "iroh-mdns-address-lookup/Cargo.toml": MDNS_MANIFEST,
            "iroh-mdns-address-lookup/src/lib.rs": b"pub fn mdns() {}\n",
        }
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(f"{prepare.ADAPTER_TOP}/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return output.getvalue()

    def write_archive(self, directory: Path, name: str, data: bytes) -> Path:
        path = directory / f"{name}.tar.gz"
        path.write_bytes(data)
        return path

    def fake_modules(self, archives: dict[str, Path]) -> dict[str, object]:
        modules: dict[str, object] = {}
        for name in ("mainline", "bencode", "dns", "multibase"):
            source = {"src/lib.rs": f"{name}-original".encode()}
            changed = {"src/lib.rs": f"{name}-prepared".encode()}
            modules[name] = types.SimpleNamespace(
                ARCHIVE_SHA256=hashlib.sha256(archives[name].read_bytes()).hexdigest(),
                archive_files=lambda _archive, content=source: content,
                transform=lambda _files, content=changed: content,
                reverse=lambda files, _changed: files,
                recipe=lambda n=name: {f"{n}/prepare.py": hashlib.sha256(n.encode()).hexdigest()},
            )
        return modules

    def modules_patch(self, modules: dict[str, object]):
        return patch.object(prepare, "fixed_module", side_effect=lambda name, _path: modules[name])

    def archives(self, base: Path) -> tuple[bytes, dict[str, Path]]:
        adapter_bytes = self.adapter_archive()
        archives = {"adapter": self.write_archive(base, "adapter", adapter_bytes)}
        future_bytes = self.future_archive()
        archives["future"] = self.write_archive(base, "future", future_bytes)
        for name in ("mainline", "bencode", "dns", "multibase"):
            archives[name] = self.write_archive(base, name, name.encode())
        return adapter_bytes, archives

    def future_archive(self) -> bytes:
        files = {
            "Cargo.toml": FUTURE_MANIFEST,
            "Cargo.toml.orig": FUTURE_ORIG,
            "src/lib.rs": b"runtime unchanged\n",
            "build.rs": b"build unchanged\n",
        }
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(f"{prepare.FUTURE_TOP}/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return output.getvalue()

    def test_future_transform_and_reverse_contract(self) -> None:
        files = {"Cargo.toml": FUTURE_MANIFEST, "Cargo.toml.orig": FUTURE_ORIG,
                 "src/lib.rs": b"runtime unchanged\n", "build.rs": b"build unchanged\n"}
        changed = {"Cargo.toml": FUTURE_CHANGED}
        self.assertEqual(prepare.future_transform(files), changed)
        self.assertEqual(prepare.future_reverse(files, changed), files)
        changed_manifest = tomllib.loads(changed["Cargo.toml"].decode())
        self.assertEqual(changed_manifest["dependencies"]["tokio"]["features"], [])
        self.assertEqual(changed_manifest["target"][FUTURE_TARGET]["dependencies"]["tokio"]["features"], ["rt", "time", "macros"])
        self.assertEqual(changed_manifest["target"][FUTURE_TARGET]["dev-dependencies"]["tokio"]["features"], ["test-util"])
        for invalid in (
            {}, {"Cargo.toml.orig": FUTURE_CHANGED}, {**changed, "src/lib.rs": b"bad"},
            {"Cargo.toml": FUTURE_CHANGED.replace(b'version = "1.28"', b'version = "1.29"', 1)},
            {"Cargo.toml": FUTURE_CHANGED.replace(b'features = ["test-util"]', b'features = []', 1)},
            {"Cargo.toml": FUTURE_CHANGED.replace(b'features = ["test-util"]', b'features = ["test-util", "macros"]', 1)},
        ):
            with self.assertRaises(ValueError):
                prepare.future_reverse(files, invalid)

    def test_future_archive_identity_and_safety(self) -> None:
        def archive(entries):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as stream:
                for name, data, kind in entries:
                    member = tarfile.TarInfo(name)
                    if kind == "link":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "target"
                        stream.addfile(member)
                    else:
                        member.size = len(data)
                        stream.addfile(member, io.BytesIO(data))
            return output.getvalue()
        good_files = {
            "Cargo.toml": FUTURE_MANIFEST,
            "Cargo.toml.orig": FUTURE_ORIG,
            "src/lib.rs": b"runtime unchanged\n",
            "build.rs": b"build unchanged\n",
        }
        good = archive([(f"{prepare.FUTURE_TOP}/{name}", data, "file") for name, data in good_files.items()])
        with tempfile.TemporaryDirectory() as temp:
            path = self.write_archive(Path(temp), "future", good)
            with patch.object(prepare, "FUTURE_SHA", hashlib.sha256(good).hexdigest()):
                self.assertEqual(prepare.future_archive(path)["Cargo.toml"], FUTURE_MANIFEST)
            bad_archives = [
                archive([(f"{prepare.FUTURE_TOP}/Cargo.toml", b"a", "file"), (f"{prepare.FUTURE_TOP}/Cargo.toml", b"b", "file")]),
                archive([(f"{prepare.FUTURE_TOP}/../escape", b"x", "file")]),
                archive([(f"{prepare.FUTURE_TOP}/link", b"", "link")]),
                archive([(f"{prepare.FUTURE_TOP}/large", b"x" * (prepare.MAX_MEMBER + 1), "file")]),
            ]
            for data in bad_archives:
                invalid = self.write_archive(Path(temp), "invalid", data)
                with patch.object(prepare, "FUTURE_SHA", hashlib.sha256(data).hexdigest()):
                    with self.assertRaises(ValueError):
                        prepare.future_archive(invalid)
            with patch.object(prepare, "FUTURE_SHA", "0" * 64):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    prepare.future_archive(path)

    def test_prepare_all_preserves_workspace_and_all_four_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            adapter_bytes, archives = self.archives(base)
            modules = self.fake_modules(archives)
            product = base / "product"
            product.mkdir()
            (product / "Cargo.toml").write_text("[workspace]\nmembers=[]\n", encoding="utf-8")
            (product / "target").mkdir()
            destination = product / "target/native-graph"
            self.assertFalse(destination.exists())
            with patch.object(prepare, "ADAPTER_SHA", hashlib.sha256(adapter_bytes).hexdigest()), patch.object(prepare, "FUTURE_SHA", hashlib.sha256(archives["future"].read_bytes()).hexdigest()), self.modules_patch(modules):
                original = prepare.adapter_archive(archives["adapter"])
                roots = prepare.prepare_all(archives, destination)
                verified = prepare.verify_all(archives, destination)
            self.assertEqual(roots, verified)
            expected = dict(original)
            expected[SELECTED] = INSERTED_MANIFEST
            adapter_root = destination / "adapter"
            for relative, content in expected.items():
                self.assertEqual((adapter_root / relative).read_bytes(), content)
            receipt = json.loads((destination / "adapter.provenance.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["original_files"], prepare.hashes(original))
            self.assertEqual(receipt["prepared_files"], prepare.hashes(expected))
            self.assertEqual(receipt["changed_files"], [SELECTED])
            self.assertEqual(receipt["archive_sha256"], hashlib.sha256(adapter_bytes).hexdigest())
            self.assertEqual(receipt["source"]["revision"], prepare.REVISION)
            self.assertEqual(receipt["recipe_files"], {".github/probes/native-graph/prepare.py": hashlib.sha256(Path(prepare.__file__).read_bytes()).hexdigest()})
            selected_path = adapter_root / SELECTED
            manifest = tomllib.loads(selected_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["package"]["workspace"], "..")
            self.assertEqual((selected_path.parent / manifest["package"]["workspace"]).resolve(), adapter_root.resolve())
            self.assertNotEqual(adapter_root.resolve(), product.resolve())
            self.assertEqual((adapter_root / "Cargo.toml").read_bytes(), ROOT_MANIFEST)
            self.assertEqual(prepare.adapter_reverse(original, {SELECTED: expected[SELECTED]}), original)
            future_root = destination / "n0-future-0.3.2"
            assert (future_root / "Cargo.toml.orig").read_bytes() == FUTURE_ORIG
            assert (future_root / "src/lib.rs").read_bytes() == b"runtime unchanged\n"
            assert (future_root / "build.rs").read_bytes() == b"build unchanged\n"
            future_receipt = json.loads((destination / "n0-future-0.3.2.provenance.json").read_text(encoding="utf-8"))
            future_original = {"Cargo.toml": FUTURE_MANIFEST, "Cargo.toml.orig": FUTURE_ORIG, "src/lib.rs": b"runtime unchanged\n", "build.rs": b"build unchanged\n"}
            future_prepared = {**future_original, "Cargo.toml": FUTURE_CHANGED}
            self.assertEqual(future_receipt["original_files"], prepare.hashes(future_original))
            self.assertEqual(future_receipt["prepared_files"], prepare.hashes(future_prepared))
            self.assertNotEqual(future_receipt["original_files"]["Cargo.toml"], future_receipt["prepared_files"]["Cargo.toml"])
            self.assertEqual(future_receipt["changed_files"], ["Cargo.toml"])
            self.assertEqual(future_receipt["archive_sha256"], hashlib.sha256(archives["future"].read_bytes()).hexdigest())
            self.assertEqual(future_receipt["recipe_files"], {".github/probes/native-graph/prepare.py": hashlib.sha256(Path(prepare.__file__).read_bytes()).hexdigest()})
            for tree in ("adapter", "n0-mainline-0.7.0", "serde_bencode-0.2.4", "iroh-dns-1.3.0", "n0-future-0.3.2", "multibase-0.9.3"):
                self.assertTrue((destination / f"{tree}.provenance.json").is_file())

    def test_adapter_transform_and_reverse_validation(self) -> None:
        files = {"Cargo.toml": ROOT_MANIFEST, SELECTED: SELECTED_MANIFEST,
                 "iroh-mdns-address-lookup/Cargo.toml": MDNS_MANIFEST, "runtime.rs": b"runtime\n"}
        changed = {SELECTED: INSERTED_MANIFEST}
        self.assertEqual(prepare.adapter_transform(files), changed)
        self.assertEqual(prepare.adapter_reverse(files, changed), files)
        bad_roots = [
            {k: v for k, v in files.items() if k != "Cargo.toml"},
            {**files, "Cargo.toml": b"[workspace]\nmembers=[]\n"},
            {**files, "Cargo.toml": b"[workspace]\nmembers=['iroh-mainline-address-lookup']\n"},
            {**files, "Cargo.toml": ROOT_MANIFEST.replace(b"members=", b"# no members\n")},
            {**files, "Cargo.toml": ROOT_MANIFEST.replace(b"members=[", b"members=[]\n# ")},
        ]
        bad_selected = [
            {k: v for k, v in files.items() if k != SELECTED},
            {**files, SELECTED: SELECTED_MANIFEST.replace(b"workspace=true", b"workspace=false")},
            {**files, SELECTED: SELECTED_MANIFEST.replace(b"workspace=true", b"")},
            {**files, SELECTED: SELECTED_MANIFEST.replace(b"[package]", b"[package]\nworkspace='wrong'")},
            {**files, SELECTED: b"[package]\n[package]\n"},
        ]
        for invalid in bad_roots + bad_selected:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    prepare.adapter_transform(invalid)
        for invalid in (
            {}, {"wrong/path": INSERTED_MANIFEST}, {**changed, "runtime.rs": b"runtime\n"},
            {SELECTED: INSERTED_MANIFEST.replace(b"workspace=true", b"workspace=false")},
            {SELECTED: INSERTED_MANIFEST.replace(b'workspace = ".."', b'workspace = "elsewhere"')},
            {SELECTED: INSERTED_MANIFEST.replace(b'workspace = ".."\n', b"")},
        ):
            with self.assertRaises(ValueError):
                prepare.adapter_reverse(files, invalid)

    def test_verify_all_rejects_source_and_receipt_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            adapter_bytes, archives = self.archives(base)
            modules = self.fake_modules(archives)
            destination = base / "native-graph"
            with patch.object(prepare, "ADAPTER_SHA", hashlib.sha256(adapter_bytes).hexdigest()), patch.object(prepare, "FUTURE_SHA", hashlib.sha256(archives["future"].read_bytes()).hexdigest()), self.modules_patch(modules):
                prepare.prepare_all(archives, destination)
                receipt_path = destination / "adapter.provenance.json"
                receipt_original = json.loads(receipt_path.read_text(encoding="utf-8"))
                tree = destination / "adapter"
                mutations = [
                    (SELECTED, SELECTED_MANIFEST),
                    (SELECTED, INSERTED_MANIFEST.replace(b'workspace = ".."', b'workspace = "wrong"')),
                    ("Cargo.toml", ROOT_MANIFEST.replace(b"missing_debug_implementations = 'warn'", b"missing_debug_implementations = 'deny'")),
                    ("iroh-mainline-address-lookup/src/lib.rs", b"corrupt\n"),
                ]
                for relative, content in mutations:
                    path = tree / relative
                    original = path.read_bytes()
                    path.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, "inventory mismatch: adapter"):
                        prepare.verify_all(archives, destination)
                    path.write_bytes(original)
                    prepare.verify_all(archives, destination)
                future_root = destination / "n0-future-0.3.2"
                future_manifest_path = future_root / "Cargo.toml"
                future_manifest = future_manifest_path.read_bytes()
                future_manifest_path.write_bytes(future_manifest.replace(b'features = [\n    "rt",\n    "time",\n    "macros",\n]', b'features = [\n    "rt",\n    "time",\n    "macros",\n    "test-util",\n]', 1))
                with self.assertRaises(ValueError):
                    prepare.verify_all(archives, destination)
                future_manifest_path.write_bytes(future_manifest)
                prepare.verify_all(archives, destination)
                future_receipt_path = destination / "n0-future-0.3.2.provenance.json"
                future_receipt_original = json.loads(future_receipt_path.read_text(encoding="utf-8"))
                future_receipt = dict(future_receipt_original)
                future_receipt["archive_sha256"] = "0" * 64
                future_receipt_path.write_text(json.dumps(future_receipt), encoding="utf-8")
                with self.assertRaises(ValueError):
                    prepare.verify_all(archives, destination)
                future_receipt_path.write_text(json.dumps(future_receipt_original), encoding="utf-8")
                prepare.verify_all(archives, destination)
                for field in ("original_files", "prepared_files", "changed_files"):
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    receipt[field] = {} if field != "changed_files" else []
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "receipt mismatch: adapter"):
                        prepare.verify_all(archives, destination)
                    receipt_path.write_text(json.dumps(receipt_original), encoding="utf-8")
                    prepare.verify_all(archives, destination)

    def test_adapter_rejects_path_collision_link_and_size_violations(self) -> None:
        cases = [
            [(f"{prepare.ADAPTER_TOP}/Cargo.toml", b"a", "file"), (f"{prepare.ADAPTER_TOP}/cargo.toml", b"b", "file")],
            [(f"{prepare.ADAPTER_TOP}/bad:name", b"x", "file")],
            [(f"{prepare.ADAPTER_TOP}/link", b"", "link")],
            [(f"{prepare.ADAPTER_TOP}/large", b"x" * (prepare.MAX_MEMBER + 1), "file")],
        ]
        for entries in cases:
            with self.subTest(entries=entries[:1]), tempfile.TemporaryDirectory() as temp:
                buffer = io.BytesIO()
                with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                    for name, data, kind in entries:
                        member = tarfile.TarInfo(name)
                        if kind == "link":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "target"
                            archive.addfile(member)
                        else:
                            member.size = len(data)
                            archive.addfile(member, io.BytesIO(data))
                path = Path(temp) / "invalid.tar.gz"
                path.write_bytes(buffer.getvalue())
                with patch.object(prepare, "ADAPTER_SHA", hashlib.sha256(buffer.getvalue()).hexdigest()):
                    with self.assertRaises(ValueError):
                        prepare.adapter_archive(path)

    def test_adapter_rejects_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data = self.adapter_archive()
            path = self.write_archive(Path(temp), "adapter", data)
            with patch.object(prepare, "ADAPTER_SHA", "0" * 64):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    prepare.adapter_archive(path)


if __name__ == "__main__":
    unittest.main()
