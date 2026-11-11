# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Cargo-semantic mutation tests for native graph audits."""
from __future__ import annotations

import copy
import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import graph


class GraphTests(unittest.TestCase):
    def test_kad_binding_retains_preparer_digest_and_rejects_missing_recipe(self):
        import hashlib
        import json
        import tempfile
        import ci

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target/p2p/kad/libp2p-kad-0.49.0"
            source.mkdir(parents=True)
            (source / "Cargo.toml").write_text('[package]\nname="libp2p-kad"\nversion="0.49.0"\n')
            receipt = source.parent / "provenance.json"
            data = {"archive_sha256": "a" * 64, "preparer_sha256": "b" * 64}
            receipt.write_text(json.dumps(data))
            package = {"name": "libp2p-kad", "version": "0.49.0"}
            binding = ci.evidence._binding(root, source, package, "baseline")
            recipe = json.dumps({"preparer_sha256": "b" * 64}, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(binding["recipe_sha256"], hashlib.sha256(recipe).hexdigest())
            self.assertEqual(binding["receipt_sha256"], hashlib.sha256(receipt.read_bytes()).hexdigest())
            del data["preparer_sha256"]
            receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "recipe digest missing"):
                ci.evidence._binding(root, source, package, "baseline")

    def test_verify_future_dev_preserves_source(self):
        import json
        import tempfile
        from unittest import mock
        import ci
        import prepare

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target/native-graph/n0-future-0.3.2"
            source.mkdir(parents=True)
            prepared = (
                b'[package]\nname = "n0-future"\nversion = "0.3.2"\n'
                + b"\n[target.'" + prepare.FUTURE_TARGET.encode() + b"'.dependencies.tokio]\n"
                + b'version = "1.28"\nfeatures = ["rt", "time", "macros"]\n'
                + b"\n[target.'" + prepare.FUTURE_TARGET.encode() + b"'.dev-dependencies.tokio]\n"
                + b'version = "1.28"\nfeatures = ["test-util"]\n'
            )
            (source / "Cargo.toml").write_bytes(prepared)
            (source / "src").mkdir()
            (source / "src/lib.rs").write_bytes(b"pub fn future() {}\n")
            lock = (
                b'version = 4\n\n[[package]]\nname = "n0-future"\nversion = "0.3.2"\n'
                b'dependencies = [\n "tokio",\n]\n\n[[package]]\nname = "tokio"\nversion = "1.48.0"\n'
                b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                b'checksum = "ff360e02eab121e0bc37a2d3b4d4dc622e6eda3a8e5253d5435ecf5bd4c68408"\n'
            )
            (source / "Cargo.lock").write_bytes(lock)
            logs = root / "logs"
            metadata = {
                "packages": [
                    {
                        "id": "future",
                        "name": "n0-future",
                        "version": "0.3.2",
                        "source": None,
                        "manifest_path": str(root / "target/native-graph-future-dev/Cargo.toml"),
                        "features": [],
                        "dependencies": [
                            {"name": "tokio", "source": graph.REGISTRY, "req": "^1.28", "kind": None, "rename": None, "target": prepare.FUTURE_TARGET, "features": ["rt", "time", "macros"]},
                            {"name": "tokio", "source": graph.REGISTRY, "req": "^1.28", "kind": "dev", "rename": None, "target": prepare.FUTURE_TARGET, "features": ["test-util"]},
                        ],
                    },
                    {
                        "id": "tokio",
                        "name": "tokio",
                        "version": "1.48.0",
                        "source": graph.REGISTRY,
                        "manifest_path": str(root / "tokio/Cargo.toml"),
                        "dependencies": [],
                    },
                ],
                "workspace_members": ["future"],
                "resolve": {
                    "root": "future",
                    "nodes": [
                        {"id": "future", "deps": [{"pkg": "tokio", "name": "tokio", "dep_kinds": [
                            {"kind": None, "target": prepare.FUTURE_TARGET},
                            {"kind": "dev", "target": prepare.FUTURE_TARGET},
                        ]}]},
                        {"id": "tokio", "features": ["rt", "time", "macros", "test-util"], "deps": []},
                    ],
                },
            }
            calls = []

            def subprocess_run(argv, cwd, **kwargs):
                calls.append(argv)
                if "metadata" in argv:
                    return type("Result", (), {"stdout": json.dumps(metadata).encode(), "stderr": b"", "returncode": 0})()
                return type("Result", (), {"stdout": b"ok", "stderr": b"", "returncode": 0})()

            with (mock.patch.multiple(ci, DESTINATION=source.parent, CONSUMER=root / "target/native-graph/normal-consumer",
                                     ROOT=root, LOGS=logs, COMMANDS=[]),
                  mock.patch.object(ci.subprocess, "run", side_effect=subprocess_run)):
                result = ci.verify_future_dev()
            self.assertEqual((source / "Cargo.toml").read_bytes(), prepared)
            self.assertEqual((source / "src/lib.rs").read_bytes(), b"pub fn future() {}\n")
            self.assertEqual(result["dev_lock_sha256_before"], result["dev_lock_sha256_after"])
            self.assertEqual([Path(argv[argv.index("--doc") if "--doc" in argv else argv.index("--lib")]).name
                              for argv in calls if "test" in argv], ["--lib", "--doc"])
            self.assertEqual([record["stdout_log"] for record in result["commands"]],
                             ["future-dev-metadata.json", "future-dev-test-lib.log", "future-dev-test-doc.log"])
            self.assertTrue((logs / "future-dev-metadata.json").read_bytes())

            mutations = (
                lambda data: next(p for p in data["packages"] if p["name"] == "tokio").update(version="1.54.1"),
                lambda data: next(p for p in data["packages"] if p["name"] == "tokio").update(source="registry+https://wrong.example/index"),
                lambda data: data["resolve"]["nodes"][0]["deps"].clear(),
                lambda data: data["resolve"].update(root="tokio"),
                lambda data: next(n for n in data["resolve"]["nodes"] if n["id"] == "tokio")["features"].remove("test-util"),
                lambda data: data["packages"].append({"id": "extra", "name": "unknown", "version": "1.0.0", "source": graph.REGISTRY, "manifest_path": str(root / "unknown/Cargo.toml"), "dependencies": []}),
                lambda data: data['resolve']['nodes'][1]['deps'].append({'pkg':'future','dep_kinds':[{'kind':None}]}),
            )
            for mutate in mutations:
                changed = copy.deepcopy(metadata)
                mutate(changed)

                def changed_subprocess_run(argv, cwd, **kwargs):
                    if "metadata" in argv:
                        return type("Result", (), {"stdout": json.dumps(changed).encode(), "stderr": b"", "returncode": 0})()
                    return type("Result", (), {"stdout": b"ok", "stderr": b"", "returncode": 0})()

                with (mock.patch.multiple(ci, DESTINATION=source.parent, CONSUMER=root / "target/native-graph/normal-consumer",
                                         ROOT=root, LOGS=logs, COMMANDS=[]),
                      mock.patch.object(ci.subprocess, "run", side_effect=changed_subprocess_run)):
                    with self.assertRaises(ValueError):
                        ci.verify_future_dev()
                self.assertEqual((source / "Cargo.toml").read_bytes(), prepared)
                self.assertEqual((source / "src/lib.rs").read_bytes(), b"pub fn future() {}\n")

            lock_path = source / "Cargo.lock"
            original_lock = lock_path.read_bytes()
            try:
                lock_path.write_bytes(original_lock.replace(
                    b"ff360e02eab121e0bc37a2d3b4d4dc622e6eda3a8e5253d5435ecf5bd4c68408",
                    b"0" * 64,
                ))
                with (mock.patch.multiple(ci, DESTINATION=source.parent, CONSUMER=root / "target/native-graph/normal-consumer",
                                         ROOT=root, LOGS=logs, COMMANDS=[]),
                      mock.patch.object(ci.subprocess, "run", side_effect=subprocess_run)):
                    with self.assertRaisesRegex(ValueError, "identity/checksum"):
                        ci.verify_future_dev()
            finally:
                lock_path.write_bytes(original_lock)
            self.assertEqual(lock_path.read_bytes(), original_lock)

    def test_ci_projection_validates_recorded_metadata_receipts(self):
        import hashlib
        import json
        import tempfile
        from unittest import mock
        import ci

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = root / "target/native-graph/normal-consumer"
            destination = root / "target/native-graph"
            logs = destination / "logs"
            shaar = root / "crates/shaar"
            shaar.mkdir(parents=True)
            logs.mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/shaar"]\n', encoding="utf-8")
            (shaar / "Cargo.toml").write_text('[package]\nname = "shaar"\nversion = "0.1.0"\n\n[dependencies]\nroute = "1"\n\n[dev-dependencies]\ntracing = "=0.1.44"\n', encoding="utf-8")
            product_packages = [
                {"name": "shaar", "version": "0.1.0", "dependencies": ["route", "tracing"]},
                {"name": "route", "version": "1.0.0", "source": graph.REGISTRY, "checksum": "route", "dependencies": ["tracing"]},
                {"name": "tracing", "version": "0.1.44", "source": graph.REGISTRY, "checksum": "trace", "dependencies": []},
            ]
            consumer_packages = [copy.deepcopy(package) for package in product_packages]
            consumer_packages[0]["dependencies"].remove("tracing")
            consumer_packages.insert(0, {"name": "native-graph-normal-consumer", "version": "0.0.0", "dependencies": ["shaar"]})

            def lock_bytes(packages):
                lines = ["version = 4"]
                for package in packages:
                    lines.extend(["", "[[package]]", f'name = "{package["name"]}"', f'version = "{package["version"]}"'])
                    for key in ("source", "checksum"):
                        if key in package:
                            lines.append(f'{key} = "{package[key]}"')
                    lines.append("dependencies = [" + ", ".join(json.dumps(dep) for dep in package.get("dependencies", [])) + "]")
                return ("\n".join(lines) + "\n").encode()

            product_metadata = {
                "packages": [
                    {"id": "shaar", "name": "shaar", "version": "0.1.0", "source": None, "manifest_path": str(shaar / "Cargo.toml"), "dependencies": [{"name": "tracing", "source": graph.REGISTRY, "req": "=0.1.44", "kind": "dev", "rename": None, "target": None}, {"name": "route", "source": graph.REGISTRY, "req": "*", "kind": None, "rename": None, "target": None}]},
                    {"id": "route", "name": "route", "version": "1.0.0", "source": graph.REGISTRY, "manifest_path": str(root / "route/Cargo.toml"), "dependencies": []},
                    {"id": "tracing", "name": "tracing", "version": "0.1.44", "source": graph.REGISTRY, "manifest_path": str(root / "tracing/Cargo.toml"), "dependencies": []},
                ],
                "workspace_root": str(root), "workspace_members": ["shaar"],
                "resolve": {"nodes": [
                    {"id": "shaar", "deps": [{"pkg": "tracing", "name": "tracing", "dep_kinds": [{"kind": "dev", "target": None}]}, {"pkg": "route", "dep_kinds": [{"kind": None, "target": None}]}]},
                    {"id": "route", "deps": [{"pkg": "tracing", "dep_kinds": [{"kind": None, "target": None}]}]},
                    {"id": "tracing", "deps": []},
                ]},
            }
            consumer_metadata = copy.deepcopy(product_metadata)
            consumer_metadata["packages"][0]["dependencies"] = [dependency for dependency in consumer_metadata["packages"][0]["dependencies"] if dependency["name"] != "tracing"]
            consumer_metadata["resolve"]["nodes"][0]["deps"] = [dependency for dependency in consumer_metadata["resolve"]["nodes"][0]["deps"] if dependency["pkg"] != "tracing"]
            product_bytes = json.dumps(product_metadata).encode()
            consumer_bytes = json.dumps(consumer_metadata).encode()
            product_lock = lock_bytes(product_packages)
            (root / "Cargo.lock").write_bytes(product_lock)
            (logs / "product-metadata.json").write_bytes(product_bytes)
            product_argv = ["cargo", "metadata", "--locked", "--format-version", "1"]
            product_record = {"argv": product_argv, "cwd": str(root), "exit_code": 0,
                              "stdout_sha256": hashlib.sha256(product_bytes).hexdigest(), "stdout_log": "product-metadata.json"}

            def cargo(argv, cwd, **kwargs):
                (Path(cwd) / "Cargo.lock").write_bytes(lock_bytes(consumer_packages))
                return type("Result", (), {"stdout": consumer_bytes, "stderr": b"", "returncode": 0})()

            with (mock.patch.multiple(ci, ROOT=root, CONSUMER=consumer, DESTINATION=destination, LOGS=logs, COMMANDS=[product_record]),
                  mock.patch.object(ci, "patches_from_root", return_value={}),
                  mock.patch.object(ci.subprocess, "run", side_effect=cargo)):
                _, report = ci.normal_projection_lock()
                record = ci.COMMANDS[-1]
                self.assertEqual(record["argv"], ["cargo", "metadata", "--manifest-path", str(consumer / "Cargo.toml"), "--format-version", "1"])
                self.assertEqual(record["cwd"], str(consumer))
                self.assertEqual(record["stdout_sha256"], hashlib.sha256(consumer_bytes).hexdigest())
                self.assertEqual(len(report["proven_projection_edges"]), 1)
                self.assertEqual(report["proven_projection_edges"][0]["manifest_sha256"], hashlib.sha256((shaar / "Cargo.toml").read_bytes()).hexdigest())
                self.assertEqual(report["metadata_sha256"], {"product": hashlib.sha256(product_bytes).hexdigest(), "consumer": hashlib.sha256(consumer_bytes).hexdigest()})
                report_path = destination / "normal-consumer.projection.json"
                self.assertEqual(json.loads(json.dumps(report)), json.loads(report_path.read_text(encoding="utf-8")))
                self.assertTrue(report_path.read_bytes())
                ci.COMMANDS[:] = [dict(product_record, stdout_sha256="bad")]
                with self.assertRaisesRegex(ValueError, "product metadata stdout digest mismatch"):
                    ci.normal_projection_lock()

    def test_evidence_run_preserves_and_audits_projection_receipts(self):
        import hashlib
        import json
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        sys.path.insert(0, str(Path(__file__).resolve().parent / "fixture"))
        import baseline as base
        import evidence
        import features
        import verify_once

        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "candidate"
            repo.mkdir()

            def setup(root):
                shaar = root / "crates/shaar"
                (shaar / "src").mkdir(parents=True)
                (root / "Cargo.toml").write_text(
                    '[workspace]\nexclude = ["target/native-graph/adapter/iroh-mainline-address-lookup"]\n'
                    'members = ["crates/shaar"]\n', encoding="utf-8")
                (shaar / "Cargo.toml").write_text(
                    '[package]\nname = "shaar"\nversion = "0.1.0"\n\n'
                    '[dependencies]\nroute = "1"\n\n[dev-dependencies]\ntracing = "=0.1.44"\n', encoding="utf-8")
                (shaar / "src/lib.rs").write_text("pub fn evidence() {}\n", encoding="utf-8")
                return shaar

            setup(repo)
            registry = "registry+https://github.com/rust-lang/crates.io-index"

            def metadata(root, consumer_root=None):
                consumer = consumer_root is not None
                shaar_path = str((root / "crates/shaar/Cargo.toml").resolve())
                route_path = str((root / "route/Cargo.toml").resolve())
                trace_path = "/registry/tracing/Cargo.toml"
                dependency = {"name": "tracing", "source": registry, "req": "=0.1.44", "kind": "dev", "rename": None, "target": None}
                if consumer:
                    root_path = str((consumer_root / "Cargo.toml").resolve())
                    packages = [
                        {"id": "consumer", "name": "native-graph-normal-consumer", "version": "0.0.0", "source": None, "manifest_path": root_path},
                        {"id": "shaar", "name": "shaar", "version": "0.1.0", "source": None, "manifest_path": shaar_path, "dependencies": [dependency]},
                        {"id": "route", "name": "route", "version": "1.0.0", "source": registry, "manifest_path": route_path},
                        {"id": "tracing", "name": "tracing", "version": "0.1.44", "source": registry, "manifest_path": trace_path}]
                    edges = {"consumer": ["shaar"], "shaar": ["route"], "route": ["tracing"], "tracing": []}
                    members, workspace_root = ["consumer"], str(consumer_root)
                else:
                    packages = [
                        {"id": "shaar", "name": "shaar", "version": "0.1.0", "source": None, "manifest_path": shaar_path, "dependencies": [dependency]},
                        {"id": "route", "name": "route", "version": "1.0.0", "source": registry, "manifest_path": route_path},
                        {"id": "tracing", "name": "tracing", "version": "0.1.44", "source": registry, "manifest_path": trace_path}]
                    edges = {"shaar": ["route", "tracing"], "route": ["tracing"], "tracing": []}
                    members, workspace_root = ["shaar"], str(root)
                nodes = []
                for p in packages:
                    deps = [{'name': d, 'pkg': d, 'dep_kinds': [{'kind': 'dev' if not consumer and p['id'] == 'shaar' and d == 'tracing' else None, 'target': None}]} for d in edges[p['id']]]
                    nodes.append({'id': p['id'], 'features': [], 'deps': deps})
                return {"packages": packages, "workspace_members": members, "workspace_root": workspace_root, "resolve": {"nodes": nodes}}

            def lock_bytes():
                return (b'version = 4\n\n[[package]]\nname = "shaar"\nversion = "0.1.0"\ndependencies = ["route", "tracing"]\n\n'
                        b'[[package]]\nname = "route"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + b'a' * 64 + b'"\ndependencies = ["tracing"]\n\n'
                        b'[[package]]\nname = "tracing"\nversion = "0.1.44"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + b'b' * 64 + b'"\n')

            (repo / "Cargo.lock").write_bytes(lock_bytes())

            runner = verify_once.make_capture_runner(repo, metadata, lock_bytes)

            def materialize(_repo, root, _command):
                setup(root)
                (root / "Cargo.lock").write_bytes(lock_bytes())
                return {"commit": "base", "archive_sha256": "a" * 64, "input_hashes": {"Cargo.toml": "c" * 64}}

            prepared = SimpleNamespace(prepare_all=lambda *_: {}, verify_all=lambda *_: {})
            expected = {"roles": ["baseline", "approved_route", "candidate"]}
            with mock.patch.object(base, "materialize", side_effect=materialize), \
                 mock.patch.object(base, "prepare_sources"), \
                 mock.patch.object(base, "collect_output_aliases", return_value=[]), \
                 mock.patch.object(base, "apply_route", return_value={"before": "d" * 64, "after": "e" * 64}), \
                 mock.patch.object(base, "projection_lock", return_value=lock_bytes()) as seeds, \
                 mock.patch.object(features, "compare_proofs", return_value=expected):
                result = evidence.run(repo, {}, prepared, graph, runner)
                self.assertEqual([call.args[0] for call in seeds.call_args_list], expected["roles"])

            report_path = Path(result["evidence"])
            self.assertTrue(report_path.is_file())
            self.assertTrue(report_path.stat().st_size)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual([proof["role"] for proof in report["proofs"]], expected["roles"])
            for proof in report["proofs"]:
                audit = proof["projection_audit"]
                self.assertEqual(len(audit["proven_projection_edges"]), 1)
                edge = audit["proven_projection_edges"][0]
                self.assertEqual(edge["manifest_sha256"], hashlib.sha256(Path(edge["manifest_path"]).read_bytes()).hexdigest())
                role = proof["role"]
                product_record = next(item for item in report["commands"] if role + "-product-metadata" in item["stdout"])
                consumer_record = next(item for item in report["commands"] if role + "-projection" in item["stdout"])
                self.assertEqual(audit["metadata_sha256"]["product"], product_record["stdout_sha256"])
                self.assertEqual(audit["metadata_sha256"]["consumer"], consumer_record["stdout_sha256"])
                self.assertEqual(product_record["argv"], ["cargo", "metadata", "--locked", "--format-version", "1"])
                self.assertEqual(consumer_record["argv"], ["cargo", "metadata", "--format-version", "1", "--manifest-path", proof["consumer_manifest"]])
                self.assertEqual(product_record["cwd"], str(Path(edge["manifest_path"]).parents[2].resolve()))
                self.assertEqual(consumer_record["cwd"], proof["consumer_cwd"])
                capture = proof["compiler_capture"]
                build_record = next(item for item in report["commands"] if item.get("compiler_capture") == capture)
                self.assertEqual(build_record["compiler_capture"], capture)
                self.assertEqual(capture["context"]["role"], proof["role"])
                self.assertEqual(capture["context"]["revision"], proof["revision"])
                self.assertEqual(build_record["environment"], capture["context"]["env"])
                self.assertEqual(capture["context"]["env"]["RUSTC_WORKSPACE_WRAPPER"], "")
                target_dir = Path(capture["context"]["env"]["CARGO_TARGET_DIR"])
                self.assertTrue(target_dir.is_relative_to(Path(proof["consumer_cwd"])))
                self.assertEqual(target_dir.name, "compiler-target")
                self.assertFalse(target_dir.exists())
                self.assertEqual(capture["receipts"]["compile.json"], hashlib.sha256((Path(proof["consumer_cwd"]) / "compiler-capture" / "compile.json").read_bytes()).hexdigest())
                for unit in capture["units"]:
                    for output in unit["outputs"]:
                        self.assertEqual(output["sha256"], hashlib.sha256((Path(proof["consumer_cwd"]) / "compiler-capture" / output["snapshot_path"]).read_bytes()).hexdigest())
                self.assertEqual(capture["build_stdout_sha256"], build_record["stdout_sha256"])
            self.assertEqual(sum("-Copt-level=0" in item["argv"] for item in report["commands"]), 1)
            self.assertEqual(sum("--test" in item["argv"] for item in report["commands"]), 1)
            self.assertEqual(sum(item["argv"][:2] == ["cargo", "build"] for item in report["commands"]), 3)
            self.assertEqual(len({proof["compiler_capture"]["context"]["env"]["CARGO_TARGET_DIR"] for proof in report["proofs"]}), 3)
            self.assertEqual(result["comparison"], expected)

    def product_manifest(self):
        return {"workspace": {"exclude": [graph.GENERATED_PATHS["iroh-mainline-address-lookup"]],
                               "members": ["crates/shaar"]}}

    def product_metadata(self):
        adapter_id = "path+file:///repo/target/native-graph/adapter/iroh-mainline-address-lookup#iroh-mainline-address-lookup@0.6.1"
        return {"packages": [{"id": adapter_id, "name": "iroh-mainline-address-lookup",
                              "version": "0.6.1", "source": None,
                              "manifest_path": str((Path("/repo") / graph.GENERATED_PATHS["iroh-mainline-address-lookup"] / "Cargo.toml").resolve())}],
                "workspace_members": ["shaar-id"]}

    def test_product_workspace_contract_exact_exclusion(self):
        manifest = self.product_manifest()
        graph.audit_product_workspace(manifest)
        changed = copy.deepcopy(manifest)
        del changed["workspace"]["exclude"]
        with self.assertRaises(ValueError):
            graph.audit_product_workspace(changed)
        for exclusions in ([], ["target/native-graph/adapter/other"],
                           [graph.GENERATED_PATHS["iroh-mainline-address-lookup"], "target/extra"],
                           ["target/native-graph"], ["target/*"]):
            changed = copy.deepcopy(manifest)
            changed["workspace"]["exclude"] = exclusions
            with self.subTest(exclusions=exclusions), self.assertRaises(ValueError):
                graph.audit_product_workspace(changed)
        changed = copy.deepcopy(manifest)
        changed["workspace"]["members"].append(graph.GENERATED_PATHS["iroh-mainline-address-lookup"])
        with self.assertRaisesRegex(ValueError, "explicit workspace member"):
            graph.audit_product_workspace(changed)

    def test_product_metadata_adapter_contract(self):
        metadata = self.product_metadata()
        graph.audit_product_metadata(metadata, Path("/repo"))
        mutations = (
            lambda data: data["packages"].clear(),
            lambda data: data["packages"][0].update(version="0.6.2"),
            lambda data: data["packages"][0].update(source=graph.REGISTRY),
            lambda data: data["packages"][0].update(manifest_path="/wrong/Cargo.toml"),
            lambda data: data["workspace_members"].append(data["packages"][0]["id"]),
        )
        for mutate in mutations:
            changed = copy.deepcopy(metadata)
            mutate(changed)
            with self.assertRaises(ValueError):
                graph.audit_product_metadata(changed, Path("/repo"))

    def test_real_root_workspace_members_and_patch_configuration(self):
        root = Path(__file__).resolve().parents[3]
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        graph.audit_product_workspace(manifest)
        self.assertEqual(manifest["workspace"]["members"], [
            "crates/shaar", "crates/shaar-ygg", "crates/shaar-p2p",
            "crates/shaar-server", "crates/shaar-client", "crates/shaar-platform"])
        self.assertIn("n0-mainline", manifest["patch"]["crates-io"])
        self.assertIn("iroh-dns", manifest["patch"]["crates-io"])

    def lock(self):
        return {"version": 4, "package": [
            {"name": "shaar", "version": "0.1.0", "dependencies": ["serde", "iroh-dns"]},
            {"name": "serde", "version": "1.0.229", "source": graph.REGISTRY,
             "checksum": "sum", "dependencies": []},
            {"name": "iroh-dns", "version": "1.3.0", "source": graph.REGISTRY,
             "checksum": "dns-sum", "dependencies": ["serde"]},
        ]}

    def toml(self, lock):
        output = ["version = 4\n"]
        for package in lock["package"]:
            output.extend(["[[package]]", f'name = "{package["name"]}"', f'version = "{package["version"]}"'])
            for key in ("source", "checksum"):
                if key in package:
                    output.append(f'{key} = "{package[key]}"')
            if "dependencies" in package:
                deps = ", ".join(f'"{dep}"' for dep in package["dependencies"])
                output.append(f"dependencies = [{deps}]")
            for key, value in package.items():
                if key not in {"name", "version", "source", "checksum", "dependencies"}:
                    if isinstance(value, bool):
                        output.append(f"{key} = {str(value).lower()}")
            output.append("")
        return "\n".join(output).encode()

    def test_lock_accepts_exact_edges_and_dns_switch(self):
        before = self.lock()
        after = copy.deepcopy(before)
        after["package"][0]["dependencies"] += ["iroh-mainline-address-lookup", "n0-mainline"]
        after["package"].remove(next(item for item in after["package"] if item["name"] == "iroh-dns"))
        after["package"].extend([
            {"name": "iroh-dns", "version": "1.3.0", "dependencies": ["serde"]},
            {"name": "iroh-mainline-address-lookup", "version": "0.6.1", "dependencies": []},
            {"name": "n0-mainline", "version": "0.7.0", "dependencies": []},
            {"name": "serde_bencode", "version": "0.2.4", "dependencies": []},
        ])
        self.assertEqual(len(graph.audit_lock_delta(self.toml(before), self.toml(after))["source_changed"]), 1)

    def reviewed_lock_fixture(self):
        before = self.lock()
        after = copy.deepcopy(before)
        after["package"][0]["dependencies"] += ["iroh-mainline-address-lookup", "n0-mainline"]
        after["package"].remove(next(item for item in after["package"] if item["name"] == "iroh-dns"))
        after["package"].extend([
            {"name": "iroh-dns", "version": "1.3.0", "dependencies": ["serde"]},
            {"name": "iroh-mainline-address-lookup", "version": "0.6.1", "dependencies": []},
            {"name": "n0-mainline", "version": "0.7.0", "dependencies": [
                "crc", "dyn-clone"]},
            {"name": "serde_bencode", "version": "0.2.4", "dependencies": []},
            {"name": "crc", "version": "3.4.0", "source": "registry+https://github.com/rust-lang/crates.io-index",
             "checksum": "5eb8a2a1cd12ab0d987a5d5e825195d372001a4094a0376319d5a0ad71c1ba0d",
             "dependencies": ["crc-catalog"]},
            {"name": "crc-catalog", "version": "2.5.0", "source": "registry+https://github.com/rust-lang/crates.io-index",
             "checksum": "217698eaf96b4a3f0bc4f3662aaa55bdf913cd54d7204591faa790070c6d0853"},
            {"name": "dyn-clone", "version": "1.0.20", "source": "registry+https://github.com/rust-lang/crates.io-index",
             "checksum": "d0881ea181b1df73ff77ffaaf9c7544ecc11e82fba9b5f27b262a3c73a332555"},
        ])
        return before, after

    def test_reviewed_lock_delta_fixture_and_mutations(self):
        before, after = self.reviewed_lock_fixture()
        report = graph.audit_lock_delta(self.toml(before), self.toml(after))
        self.assertTrue(report["added"])
        self.assertEqual(len(report["source_changed"]), 1)
        mutations = []
        for name in ("crc", "crc-catalog", "dyn-clone"):
            for field in ("checksum", "source", "version"):
                mutations.append((f"{name}-{field}", lambda data, n=name, f=field: next(p for p in data["package"] if p["name"] == n).__setitem__(f, "mutated")))
        mutations.extend([
            ("crc-dependency", lambda data: next(p for p in data["package"] if p["name"] == "crc")["dependencies"].append("dyn-clone")),
            ("extra-field", lambda data: next(p for p in data["package"] if p["name"] == "dyn-clone").update(extra=True)),
            ("extra-package", lambda data: data["package"].append({"name": "unrelated", "version": "1.0", "dependencies": []})),
            ("removed-package", lambda data: data["package"].remove(next(p for p in data["package"] if p["name"] == "serde"))),
            ("retained-checksum", lambda data: next(p for p in data["package"] if p["name"] == "serde").update(checksum="changed")),
            ("retained-dependency", lambda data: next(p for p in data["package"] if p["name"] == "serde")["dependencies"].append("crc")),
            ("shaar-shortcut", lambda data: next(p for p in data["package"] if p["name"] == "shaar")["dependencies"].append("crc")),
            ("missing-crc", lambda data: next(p for p in data["package"] if p["name"] == "n0-mainline")["dependencies"].remove("crc")),
            ("missing-dyn", lambda data: next(p for p in data["package"] if p["name"] == "n0-mainline")["dependencies"].remove("dyn-clone")),
            ("catalog-shortcut", lambda data: next(p for p in data["package"] if p["name"] == "n0-mainline")["dependencies"].append("crc-catalog")),
        ])
        for label, mutate in mutations:
            changed = copy.deepcopy(after)
            mutate(changed)
            with self.subTest(mutation=label), self.assertRaises(ValueError):
                graph.audit_lock_delta(self.toml(before), self.toml(changed))

        before = self.lock()
        after = copy.deepcopy(before)
        after["package"].append({"name": "unknown-transitive", "version": "2.3.4", "dependencies": []})
        with self.assertRaisesRegex(ValueError, "unknown-transitive.*2.3.4.*path"):
            graph.audit_lock_delta(self.toml(before), self.toml(after))

    def test_lock_rejects_unrelated_mutation(self):
        before = self.lock()
        after = copy.deepcopy(before)
        after["package"][1]["checksum"] = "changed"
        with self.assertRaisesRegex(ValueError, "unchanged lock identity"):
            graph.audit_lock_delta(self.toml(before), self.toml(after))

    def metadata(self):
        pins = {**graph.REQUIRED_NORMAL, "iroh": "1.3.0", "iroh-base": "1.3.0", "noq": "1.3.0",
                "noq-proto": "1.3.0", "noq-udp": "1.3.0"}
        names = ["shaar", *pins, "consumer"]
        versions = {"shaar": "0.1.0", **pins, "consumer": "0.0.0"}
        paths = {}
        for name, relative in graph.GENERATED_PATHS.items():
            paths[name] = str((Path("/generated") / relative / "Cargo.toml").resolve())
        paths.update({"shaar": "/repo/crates/shaar/Cargo.toml", "consumer": "/consumer/Cargo.toml"})

        packages = [{"id": name, "name": name, "version": versions[name],
                     "manifest_path": paths.get(name, f"/registry/{name}/Cargo.toml"),
                     "source": graph.REGISTRY if name not in paths else None} for name in names]
        target = 'cfg(not(all(target_family = "wasm", target_os = "unknown")))'
        next(p for p in packages if p["name"] == "n0-future")["dependencies"] = [
            {"name": "tokio", "kind": None, "target": target, "source": graph.REGISTRY,
             "req": "^1.28", "features": ["rt", "time", "macros"]},
            {"name": "tokio", "kind": "dev", "target": target, "source": graph.REGISTRY,
             "req": "^1.28", "features": ["test-util"]},
        ]
        nodes = [{"id": name, "features": [], "deps": []} for name in names]
        features_by_name = {"tokio": ["fs", "io-util", "rt", "sync", "time", "net", "macros"],
                            "iroh": ["tls-ring", "unstable-custom-transports"],
                            "iroh-base": ["key", "relay"]}
        for node in nodes:
            node["features"] = features_by_name.get(node["id"], [])
        by_id = {node["id"]: node for node in nodes}
        def edge(owner, dep):
            by_id[owner]["deps"].append({"pkg": dep, "dep_kinds": [{"kind": None}]})
        edge("consumer", "shaar")
        for dep in pins:
            edge("shaar", dep)
        for dep in ("iroh-base", "iroh-dns", "n0-mainline"):
            edge("iroh-mainline-address-lookup", dep)
        edge("n0-mainline", "serde_bencode")
        edge("iroh", "n0-future")
        edge("n0-future", "tokio")
        return {"packages": packages, "workspace_members": ["consumer"],
                "resolve": {"nodes": nodes, "root": "consumer"}}

    def reviewed_metadata(self):
        data = self.metadata()
        reviewed = [
            ("crc", "3.4.0", "registry+https://github.com/rust-lang/crates.io-index"),
            ("crc-catalog", "2.5.0", "registry+https://github.com/rust-lang/crates.io-index"),
            ("dyn-clone", "1.0.20", "registry+https://github.com/rust-lang/crates.io-index"),
        ]
        packages = data["packages"]
        nodes = data["resolve"]["nodes"]
        for name, version, source in reviewed:
            packages.append({"id": name, "name": name, "version": version, "source": source,
                             "manifest_path": f"/registry/{name}/Cargo.toml"})
            nodes.append({"id": name, "features": [], "deps": []})
        by_id = {node["id"]: node for node in nodes}
        by_id["n0-mainline"]["deps"].extend([
            {"pkg": "crc", "dep_kinds": [{"kind": None}]},
            {"pkg": "dyn-clone", "dep_kinds": [{"kind": None}]},
        ])
        by_id["crc"]["deps"].append({"pkg": "crc-catalog", "dep_kinds": [{"kind": None}]})
        return data

    def test_reviewed_normal_edges_exact_routes(self):
        data = self.reviewed_metadata()
        graph.audit_reviewed_normal_edges(data)
        nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
        self.assertFalse({"crc", "crc-catalog", "dyn-clone"} &
                         {edge["pkg"] for edge in nodes["shaar"]["deps"]})
        graph.audit_normal_metadata(data, Path("/generated"), normal_consumer=True)

    def test_reviewed_normal_edges_reject_mutations(self):
        mutations = [
            ("missing-crc-route", lambda data, nodes: nodes["n0-mainline"]["deps"].remove(next(e for e in nodes["n0-mainline"]["deps"] if e["pkg"] == "crc"))),
            ("missing-dyn-route", lambda data, nodes: nodes["n0-mainline"]["deps"].remove(next(e for e in nodes["n0-mainline"]["deps"] if e["pkg"] == "dyn-clone"))),
            ("missing-catalog-route", lambda data, nodes: nodes["crc"]["deps"].clear()),
            ("dev-edge-crc", lambda data, nodes: next(e for e in nodes["n0-mainline"]["deps"] if e["pkg"] == "crc").update(dep_kinds=[{"kind": "dev"}])),
            ("dev-edge-dyn", lambda data, nodes: next(e for e in nodes["n0-mainline"]["deps"] if e["pkg"] == "dyn-clone").update(dep_kinds=[{"kind": "dev"}])),
            ("dev-edge-catalog", lambda data, nodes: next(e for e in nodes["crc"]["deps"] if e["pkg"] == "crc-catalog").update(dep_kinds=[{"kind": "dev"}])),
            ("build-edge", lambda data, nodes: next(e for e in nodes["crc"]["deps"] if e["pkg"] == "crc-catalog").update(dep_kinds=[{"kind": "build"}])),
            ("extra-outgoing", lambda data, nodes: nodes["dyn-clone"]["deps"].append({"pkg": "crc", "dep_kinds": [{"kind": None}]})),
            ("wrong-source", lambda data, nodes: next(p for p in data["packages"] if p["name"] == "crc").update(source=None)),
            ("duplicate-identity", lambda data, nodes: data["packages"].append(copy.deepcopy(next(p for p in data["packages"] if p["name"] == "crc")))),
            ("other-version", lambda data, nodes: data["packages"].append({"id": "crc-other", "name": "crc", "version": "3.5.0", "source": "registry+https://github.com/rust-lang/crates.io-index"})),
        ]
        for label, mutate in mutations:
            data = self.reviewed_metadata()
            nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
            mutate(data, nodes)
            if label.startswith("missing-"):
                shortcut = "crc" if label == "missing-crc-route" else "dyn-clone" if label == "missing-dyn-route" else "crc-catalog"
                nodes["shaar"]["deps"].append({"pkg": shortcut, "dep_kinds": [{"kind": None}]})
            with self.subTest(mutation=label), self.assertRaises(ValueError):
                graph.audit_reviewed_normal_edges(data)

    def test_future_lock_source_replacement(self):
        before = self.lock()
        before["package"].append({
            "name": "n0-future", "version": "0.3.2", "source": graph.REGISTRY,
            "checksum": "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe",
            "dependencies": ["serde"],
        })
        after = copy.deepcopy(before)
        future = next(item for item in after["package"] if item["name"] == "n0-future")
        del future["source"]
        del future["checksum"]
        graph.audit_lock_delta(self.toml(before), self.toml(after))
        changed_before = copy.deepcopy(before)
        next(item for item in changed_before['package'] if item['name'] == 'n0-future')['checksum'] = '0' * 64
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(self.toml(changed_before), self.toml(after))

        mutations = (
            lambda data: next(item for item in data["package"] if item["name"] == "n0-future").update(checksum="wrong"),
            lambda data: next(item for item in data["package"] if item["name"] == "n0-future")["dependencies"].append("extra"),
            lambda data: next(item for item in data["package"] if item["name"] == "n0-future").update(checksum="e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe"),
        )
        for mutate in mutations:
            changed = copy.deepcopy(after)
            mutate(changed)
            with self.assertRaises(ValueError):
                graph.audit_lock_delta(self.toml(before), self.toml(changed))

    def test_future_native_declarations_reject_drift(self):
        mutations = (
            lambda data, nodes: next(item for item in data["packages"] if item["name"] == "n0-future")["dependencies"][0]["features"].append("test-util"),
            lambda data, nodes: next(item for item in data["packages"] if item["name"] == "n0-future")["dependencies"][1].update(features=[]),
            lambda data, nodes: next(item for item in data["packages"] if item["name"] == "n0-future")["dependencies"][0].update(target="cfg(target_os = \"windows\")"),
            lambda data, nodes: nodes["iroh"]["deps"].remove(next(edge for edge in nodes["iroh"]["deps"] if edge["pkg"] == "n0-future")),
        )
        for mutate in mutations:
            data = self.metadata()
            nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
            mutate(data, nodes)
            with self.assertRaises(ValueError):
                graph.audit_normal_metadata(data, Path("/generated"), normal_consumer=True)

    def test_normal_consumer_graph_accepts_isolated_root_and_package_paths(self):
        result = graph.audit_normal_metadata(self.metadata(), Path("/generated"), normal_consumer=True)
        self.assertTrue(set(graph.REQUIRED_NORMAL) <= result["normal_packages"])

    def test_graph_rejects_wrong_source_version_path_and_missing_edge(self):
        for mutation in ("source", "version", "path", "edge"):
            data = self.metadata()
            package = next(item for item in data["packages"] if item["name"] == "n0-mainline")
            if mutation == "source":
                package["source"] = graph.REGISTRY
            elif mutation == "version":
                package["version"] = "0.8.0"
            elif mutation == "path":
                package["manifest_path"] = "/wrong/Cargo.toml"
            else:
                by_id = {node["id"]: node for node in data["resolve"]["nodes"]}
                by_id["iroh-mainline-address-lookup"]["deps"] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                graph.audit_normal_metadata(data, Path("/generated"), normal_consumer=True)

    def test_graph_rejects_incorrect_consumer_and_test_util_feature(self):
        data = self.metadata()
        data["resolve"]["nodes"] = [node for node in data["resolve"]["nodes"] if node["id"] != "consumer"]
        with self.assertRaises(ValueError):
            graph.audit_normal_metadata(data, Path("/generated"), normal_consumer=True)
        for package, feature in (("tokio", "test-util"), ("iroh", "shaar-native-gate")):
            data = self.metadata()
            next(node for node in data["resolve"]["nodes"] if node["id"] == package)["features"].append(feature)
            with self.assertRaisesRegex(ValueError, feature):
                graph.audit_normal_metadata(data, Path("/generated"), normal_consumer=True)


if __name__ == "__main__":
    unittest.main()
