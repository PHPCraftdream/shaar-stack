# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Tests for product-to-consumer lock projection auditing."""
from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import graph
import ci
from ci import AuxiliaryProbeShapeTests
from test_aliases import CargoAliasTests
from test_alias_integration import AliasIntegrationTests
from test_stdin import StdinProbeTests


class ConsumerLockTests(unittest.TestCase):
    def lock_bytes(self, packages):
        pieces = ["version = 4\n"]
        for package in packages:
            pieces.extend(["[[package]]", f'name = "{package["name"]}"', f'version = "{package["version"]}"'])
            for key in ("source", "checksum"):
                if key in package:
                    pieces.append(f'{key} = "{package[key]}"')
            dependencies = ", ".join(f'"{item}"' for item in package.get("dependencies", []))
            pieces.extend([f"dependencies = [{dependencies}]", ""])
        return "\n".join(pieces).encode()

    def product(self):
        return [{"name": "shaar", "version": "0.1.0", "dependencies": ["serde", "unused-dev"]},
                {"name": "serde", "version": "1.0.229", "source": graph.REGISTRY,
                 "checksum": "abc", "dependencies": []},
                {"name": "unused-dev", "version": "0.2.0", "source": graph.REGISTRY,
                 "checksum": "def", "dependencies": []}]

    def consumer(self):
        return [{"name": "native-graph-normal-consumer", "version": "0.0.0", "dependencies": ["shaar"]},
                {"name": "shaar", "version": "0.1.0", "dependencies": ["serde"]},
                {"name": "serde", "version": "1.0.229", "source": graph.REGISTRY,
                 "checksum": "abc", "dependencies": []}]

    def test_exact_root_and_normal_projection_allow_dev_only_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product_lock, consumer_lock, _, _, _, context = self._projection_case(root, retained=False)
            result = graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
            self.assertEqual(result["removed_projection_packages"], [("tracing", "0.1.44", graph.REGISTRY)])

    def test_retained_dependency_edge_cannot_be_dropped(self):
        consumer = self.consumer()
        consumer[1]["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "uniquely identified|requires projection evidence"):
            graph.audit_consumer_lock(self.lock_bytes(self.product()), self.lock_bytes(consumer))

    def test_version_qualified_removed_edge_cannot_target_retained_package(self):
        product = self.product()
        product[0]["dependencies"] = ["serde 1.0.229", "unused-dev"]
        product.append({"name": "serde", "version": "2.0.0", "source": graph.REGISTRY,
                        "checksum": "new", "dependencies": []})
        consumer = self.consumer()
        consumer[1]["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "uniquely identified|requires projection evidence"):
            graph.audit_consumer_lock(self.lock_bytes(product), self.lock_bytes(consumer))

    def test_consumer_manifest_has_real_target_and_copies_patch_paths(self):
        with mock.patch.object(ci, "patches_from_root", return_value={"iroh": "/reviewed/iroh"}):
            manifest = ci.consumer_manifest()
        self.assertIn('[lib]\npath = "src/lib.rs"', manifest)
        self.assertIn('license = "MIT OR Apache-2.0"', manifest)
        self.assertIn('[patch.crates-io]', manifest)
        self.assertIn('iroh = { path = "/reviewed/iroh" }', manifest)

    def test_command_failure_records_status_and_raw_log_bytes(self):
        original_root = ci.LOGS
        with tempfile.TemporaryDirectory() as temporary:
            ci.LOGS = Path(temporary)
            self.addCleanup(setattr, ci, "LOGS", original_root)
            stderr_bytes = b"cargo failed\nraw byte: \xff\n" + b"z" * 20_000
            with (
                mock.patch.object(ci.subprocess, "run", return_value=type("Result", (), {
                    "stdout": b"out\n", "stderr": stderr_bytes, "returncode": 101})()),
                mock.patch.object(ci.sys, "stderr") as emitted,
            ):
                stdout, code = ci.run(["cargo", "metadata"], log_name="failure.log")
            self.assertEqual((stdout, code), ("out\n", 101))
            self.assertEqual((ci.LOGS / "failure.log").read_bytes(), b"out\n")
            self.assertEqual((ci.LOGS / "failure.log.stderr").read_bytes(), stderr_bytes)
            record = ci.COMMANDS[-1]
            self.assertEqual(record["exit_code"], 101)
            self.assertEqual(record["argv"], ["cargo", "metadata"])
            self.assertEqual(record["cwd"], str(ci.ROOT))
            self.assertEqual(record["stderr_sha256"], hashlib.sha256(stderr_bytes).hexdigest())
            diagnostic = "".join(call.args[0] for call in emitted.write.call_args_list)
            self.assertIn("cargo failed", diagnostic)
            self.assertIn("truncated", diagnostic)
            self.assertIn("failure.log.stderr", diagnostic)
            self.assertLessEqual(len(diagnostic), ci.MAX_FAILURE_DIAGNOSTIC + 512)

    def test_resolve_candidate_failure_saves_raw_receipt_and_stderr(self):
        import contextlib
        import io
        import json
        import tomllib

        stderr_bytes = b"cargo metadata failed\nraw byte: \xff\n"
        product_lock = (ci.ROOT / "Cargo.lock").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "target/native-graph"
            destination.mkdir(parents=True)
            (root / "crates/shaar").mkdir(parents=True)
            logs = destination / "logs"
            receipt = destination / "ci-receipt.json"
            emitted = io.StringIO()
            with (
                mock.patch.multiple(ci, ROOT=root, DESTINATION=destination, RECEIPT=receipt,
                                    LOGS=logs, COMMANDS=[]),
                mock.patch.object(ci, "ensure_sources", return_value=None),
                mock.patch.object(ci.subprocess, "run", return_value=type("Result", (), {
                    "stdout": b"", "stderr": stderr_bytes, "returncode": 101})()),
                contextlib.redirect_stderr(emitted),
            ):
                (root / "Cargo.toml").write_text('[workspace]\nexclude = ["target/native-graph/adapter/iroh-mainline-address-lookup"]\nmembers = ["crates/shaar", "crates/keep"]\n\n[workspace.package]\nversion = "1.2.3"\n\n[profile.dev]\ndebug = 1\n\n[patch.crates-io]\nexisting = { path = "existing" }\n')
                (root / "crates/shaar/Cargo.toml").write_text('[dependencies]\niroh-dns = "=1.3.0"\n')
                (root / 'Cargo.lock').write_bytes(product_lock)
                with self.assertRaisesRegex(RuntimeError, "cargo metadata resolution failed \\(101\\)"):
                    ci.resolve_candidate()

            record = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertFalse(record["accepted"])
            self.assertEqual(record["mode"], "candidate-resolution-failed")
            command = record["commands"][0]
            self.assertEqual(command["argv"], ["cargo", "metadata", "--format-version", "1"])
            self.assertEqual(command["cwd"], str(root))
            self.assertEqual(command["exit_code"], 101)
            self.assertEqual(command["stderr_sha256"], hashlib.sha256(stderr_bytes).hexdigest())
            self.assertEqual((logs / command["stderr_log"]).read_bytes(), stderr_bytes)
            self.assertIn("cargo metadata failed", emitted.getvalue())

    def test_short_byte_failure_diagnostic_preserves_raw_stderr(self):
        import contextlib
        import io

        stderr_bytes = b"error: recorded Cargo diagnostic\ninvalid byte: \xff\n"
        with tempfile.TemporaryDirectory() as temporary:
            logs = Path(temporary)
            emitted = io.StringIO()
            with (
                mock.patch.object(ci, "LOGS", logs),
                mock.patch.object(ci.subprocess, "run", return_value=type("Result", (), {
                    "stdout": b"", "stderr": stderr_bytes, "returncode": 101})()) as runner,
                contextlib.redirect_stderr(emitted),
            ):
                stdout, code = ci.run(["cargo", "metadata"], log_name="short-failure.log")
            self.assertEqual((stdout, code), ("", 101))
            self.assertIn("error: recorded Cargo diagnostic\ninvalid byte: �", emitted.getvalue())
            self.assertEqual((logs / "short-failure.log.stderr").read_bytes(), stderr_bytes)
            record = ci.COMMANDS[-1]
            self.assertEqual(record["stderr_sha256"], hashlib.sha256(stderr_bytes).hexdigest())
            self.assertEqual(record["exit_code"], 101)
            self.assertEqual(record["argv"], ["cargo", "metadata"])
            self.assertEqual(record["cwd"], str(ci.ROOT))
            self.assertEqual(runner.call_args.kwargs["cwd"], ci.ROOT)

    def test_success_has_no_failure_diagnostic(self):
        original_root = ci.LOGS
        with tempfile.TemporaryDirectory() as temporary:
            ci.LOGS = Path(temporary)
            self.addCleanup(setattr, ci, "LOGS", original_root)
            with (
                mock.patch.object(ci.subprocess, "run", return_value=type("Result", (), {
                    "stdout": b"ok", "stderr": b"", "returncode": 0})()),
                mock.patch.object(ci.sys, "stderr") as emitted,
            ):
                ci.run(["cargo", "metadata"], log_name="success.log")
            emitted.write.assert_not_called()

    def test_text_mock_failure_preserves_existing_contract(self):
        original_root = ci.LOGS
        with tempfile.TemporaryDirectory() as temporary:
            ci.LOGS = Path(temporary)
            self.addCleanup(setattr, ci, "LOGS", original_root)
            with mock.patch.object(ci.subprocess, "run", return_value=type("Result", (), {
                "stdout": "out\n", "stderr": "err\n", "returncode": 19})()):
                stdout, code = ci.run(["cargo", "metadata"], log_name="failure.log")
            self.assertEqual((stdout, code), ("out\n", 19))
            self.assertEqual((ci.LOGS / "failure.log").read_bytes(), b"out\n")
            self.assertEqual(ci.COMMANDS[-1]["exit_code"], 19)
            self.assertEqual(ci.COMMANDS[-1]["stderr_sha256"], hashlib.sha256(b"err\n").hexdigest())

    def test_process_launch_error_records_failure(self):
        original_root = ci.LOGS
        with tempfile.TemporaryDirectory() as temporary:
            ci.LOGS = Path(temporary)
            self.addCleanup(setattr, ci, "LOGS", original_root)
            with mock.patch.object(ci.subprocess, "run", side_effect=OSError("unavailable")):
                _, code = ci.run(["cargo", "metadata"], log_name="launch-error.log")
            self.assertEqual(code, -1)
            self.assertEqual(ci.COMMANDS[-1]["exit_code"], -1)
            self.assertIn("unavailable", (ci.LOGS / "launch-error.log.stderr").read_text(encoding="utf-8"))

    def test_consumer_lock_rejects_unknown_version_source_and_root_edge(self):
        for mutation in ("unknown", "version", "source", "root-edge"):
            consumer = copy.deepcopy(self.consumer())
            if mutation == "unknown":
                consumer.append({"name": "foreign", "version": "2.0.0"})
            elif mutation == "version":
                consumer[-1]["version"] = "1.0.230"
            elif mutation == "source":
                consumer[-1]["checksum"] = "forged"
            else:
                consumer[0]["dependencies"] = ["elsewhere"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                graph.audit_consumer_lock(self.lock_bytes(self.product()), self.lock_bytes(consumer))

    def test_baseline_materializes_pinned_inputs_and_rejects_unsafe_entries(self):
        import io
        import tarfile
        import baseline

        contents = {name: ("content:" + name).encode() for name in baseline.INPUTS}
        def archive(entries=None):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                for name, data, kind in entries or [(n, d, "file") for n, d in contents.items()]:
                    info = tarfile.TarInfo(name)
                    if kind == "dir":
                        info.type = tarfile.DIRTYPE
                        tar.addfile(info)
                    elif kind == "link":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "Cargo.toml"
                        tar.addfile(info)
                    else:
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
            return stream.getvalue()

        sdk_before = (Path(__file__).resolve().parents[4] / "Cargo.toml").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "baseline"
            payload = archive([("root", b"", "dir")] + [(n, d, "file") for n, d in contents.items()])
            calls = iter((baseline.BASE.encode(), payload))
            result = baseline.materialize(Path(temporary), root, lambda argv: next(calls))
            self.assertEqual(result["commit"], baseline.BASE)
            for name, data in contents.items():
                self.assertEqual((root / name).read_bytes(), data)
                self.assertEqual(result["input_hashes"][name], hashlib.sha256(data).hexdigest())
            self.assertEqual((Path(__file__).resolve().parents[4] / "Cargo.toml").read_bytes(), sdk_before)
            for entries in (( ("../escape", b"x", "file"),), (("escape", b"", "link"),)):
                with self.subTest(entries=entries), self.assertRaises(ValueError):
                    baseline.materialize(Path(temporary), Path(temporary) / ("bad" + str(len(list(Path(temporary).iterdir())))),
                                         lambda argv: baseline.BASE.encode() if argv[1] == "rev-parse" else archive(entries))
            with self.assertRaises(ValueError):
                baseline.materialize(Path(temporary), Path(temporary) / "wrong-rev", lambda argv: b"wrong" if argv[1] == "rev-parse" else payload)

    def test_baseline_route_and_source_commands_are_isolated(self):
        import baseline
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            (root / "crates/shaar").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/shaar", "crates/keep"]\n\n[workspace.package]\nversion = "1.2.3"\n\n[profile.dev]\ndebug = 1\n\n[patch.crates-io]\nexisting = { path = "existing" }\n')
            sdk = root / "crates/shaar/Cargo.toml"
            sdk.write_text('[dependencies]\niroh-dns = "=1.3.0"\n')
            sdk_before = sdk.read_bytes()
            original_root = root / "Cargo.toml"
            original_sdk = sdk
            original = __import__("tomllib").loads(original_root.read_text())
            original_bytes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in (original_root, original_sdk)}
            receipt = baseline.apply_route(root)
            routed_text = original_root.read_text()
            routed = __import__("tomllib").loads(routed_text)
            self.assertEqual(routed["workspace"]["members"], original["workspace"]["members"])
            self.assertEqual(routed["workspace"]["package"], original["workspace"]["package"])
            self.assertEqual(routed["profile"], original["profile"])
            self.assertEqual(routed["patch"]["crates-io"]["existing"], original["patch"]["crates-io"]["existing"])
            root_manifest = routed_text
            self.assertEqual(routed["workspace"]["exclude"], [graph.GENERATED_PATHS["iroh-mainline-address-lookup"]])
            graph.audit_product_workspace(routed)
            self.assertEqual(receipt["before"], original_bytes)
            self.assertEqual(receipt["after"], {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                                  for path in (original_root, original_sdk)})
            for bad in ([], ["wrong"], ["target/native-graph"]):
                changed = dict(routed)
                changed["workspace"] = dict(routed["workspace"], exclude=bad)
                with self.assertRaises(ValueError):
                    graph.audit_product_workspace(changed)
            for name, version in (("n0-mainline", "0.7.0"), ("serde_bencode", "0.2.4"), ("iroh-dns", "1.3.0")):
                self.assertEqual(root_manifest.count(f'{name} = {{ path = "target/native-graph/{name}-{version}", version = "={version}" }}'), 1)
            self.assertEqual(root_manifest.count("existing ="), 1)
            self.assertIn('iroh-dns = "=1.3.0"', sdk.read_text())
            self.assertIn('version = "=0.7.0"', sdk.read_text())
            self.assertNotEqual(sdk.read_bytes(), sdk_before)

            for exclusions in (
                ['target/native-graph/adapter/iroh-mainline-address-lookup'],
                ['wrong'], ['target/native-graph'],
            ):
                rejected = Path(temporary) / ("rejected-" + str(len(list(Path(temporary).iterdir()))))
                (rejected / "crates/shaar").mkdir(parents=True)
                rejected_manifest = rejected / "Cargo.toml"
                rejected_sdk = rejected / "crates/shaar/Cargo.toml"
                rejected_manifest.write_text(
                    '[workspace]\nexclude = ' + __import__("json").dumps(exclusions)
                    + '\nmembers = ["crates/shaar", "crates/keep"]\n\n[patch.crates-io]\nexisting = { path = "existing" }\n')
                rejected_sdk.write_text('[dependencies]\niroh-dns = "=1.3.0"\n')
                untouched = (rejected_manifest.read_bytes(), rejected_sdk.read_bytes())
                with self.subTest(exclusions=exclusions), self.assertRaisesRegex(ValueError, "already has exclusions"):
                    baseline.apply_route(rejected)
                self.assertEqual((rejected_manifest.read_bytes(), rejected_sdk.read_bytes()), untouched)

            commands = []
            baseline.prepare_sources(Path(temporary) / "candidate", root, commands.append)
            self.assertEqual(len(commands), 6)
            for command in commands:
                script = Path(command[2])
                self.assertTrue(script.is_relative_to(root / ".github" / "scripts"))
                self.assertFalse("nativegraph" in str(script))
            self.assertEqual(Path(commands[0][2]).resolve(), (root / ".github/scripts/backend/prepare.py").resolve())
            self.assertIn(str(root / ".github/probes/iroh-paths/Cargo.lock"), commands[0])
            self.assertIn("noq-proto.crate", " ".join(commands[0]))
            self.assertIn("iroh.crate", " ".join(commands[0]))
            self.assertIn("noq.crate", " ".join(commands[0]))

    def test_evidence_records_and_rejects_unexpected_baseline_revision(self):
        import json
        import evidence
        import baseline

        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            calls = []

            def runner(argv, cwd):
                calls.append(argv)
                return type("Result", (), {
                    "stdout": b"unexpected-revision\n", "stderr": b"", "returncode": 0,
                })()

            with self.assertRaisesRegex(ValueError, "baseline commit"):
                evidence.run(repo, {}, None, None, runner)

            record = json.loads((repo / "target/native-graph-evidence/evidence.json").read_text())
            self.assertEqual(calls, [["git", "rev-parse", baseline.BASE]])
            self.assertEqual(record["commands"][0]["argv"], calls[0])
            self.assertEqual(record["commands"][0]["exit_code"], 0)
            self.assertIn("baseline commit", record["error"])

    def test_evidence_failure_records_raw_stderr_artifact(self):
        import json
        import evidence

        stderr = b"git revision lookup failed: recorded failure\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def runner(argv, cwd):
                return type("Result", (), {"stdout": b"", "stderr": stderr, "returncode": 19})()
            with self.assertRaisesRegex(RuntimeError, "git revision lookup failed: recorded failure") as raised:
                evidence.run(root, {}, None, None, runner)
            artifact = root.resolve() / "target/native-graph-evidence/commands/000-baseline-materialize.stderr"
            self.assertIn(str(artifact), str(raised.exception))
            self.assertEqual(artifact.read_bytes(), stderr)
            record = json.loads((root / "target/native-graph-evidence/evidence.json").read_text())
            command = record["commands"][0]
            self.assertEqual(command["exit_code"], 19)
            self.assertEqual(command["stderr"], "commands/000-baseline-materialize.stderr")
            self.assertEqual(command["stderr_sha256"], hashlib.sha256(stderr).hexdigest())

    def test_evidence_binding_requires_prepared_receipt_and_binds_source_tree(self):
        import json
        import evidence

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target/native-graph/iroh-dns-1.3.0"
            source.mkdir(parents=True)
            (source / "Cargo.toml").write_text('[package]\nname="iroh-dns"\nversion="1.3.0"\n')
            (source / "src").mkdir()
            (source / "src/lib.rs").write_text("pub fn actual() {}\n")
            receipt = source.parent / "iroh-dns-1.3.0.provenance.json"
            receipt.write_text(json.dumps({"archive_sha256": "a" * 64, "recipe_files": {"prepare.py": "b" * 64}}))
            binding = evidence._binding(root, source, {"name": "iroh-dns", "version": "1.3.0"}, "baseline")
            self.assertEqual(binding["archive_sha256"], "a" * 64)
            self.assertEqual(binding["tree_sha256"], evidence._tree(source))
            receipt.unlink()
            with self.assertRaisesRegex(ValueError, "no fixed provenance receipt"):
                evidence._binding(root, source, {"name": "iroh-dns", "version": "1.3.0"}, "baseline")
            workspace = root / "crates/irohpkg"
            workspace.mkdir(parents=True)
            (workspace / "Cargo.toml").write_text("workspace")
            (workspace / "src").mkdir()
            (workspace / "src/lib.rs").write_text("native")
            native = evidence._binding(root, workspace, {"name": "irohpkg", "version": "0.1.0"}, "fixed-archive")
            self.assertEqual(native["identity"], "workspace")
            self.assertEqual(native["archive_sha256"], "fixed-archive")
            self.assertEqual(native["tree_sha256"], evidence._tree(workspace / "src"))
            alias = root / "alias"
            alias.mkdir()
            self.assertEqual(
                evidence._binding(root / "alias" / "..", root / "alias" / ".." / "crates/irohpkg",
                                  {"name": "irohpkg", "version": "0.1.0"}, "fixed-archive"),
                native,
            )


    def _projection_case(self, root, alias='tracing', retained=True, conditional=False, path_target=False):
        import json
        owner = root / "owner"
        owner.mkdir(exist_ok=True)
        manifest = owner / "Cargo.toml"
        dependency = f'{alias} = {{ package = "tracing", version = "=0.1.44" }}' if alias != "tracing" else 'tracing = "=0.1.44"'
        if path_target:
            dependency = 'tracing = { path = "../tracing", version = "=0.1.44" }'
        section = f'[target."cfg(unix)".dev-dependencies]\n{dependency}\n[target."cfg(windows)".dev-dependencies]\n{dependency}' if conditional else f'[dev-dependencies]\n{dependency}'
        manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n' + section + '\n')
        target_source = None if path_target else graph.REGISTRY
        target_manifest = root / "tracing/Cargo.toml"
        target_manifest.parent.mkdir(parents=True, exist_ok=True)
        target_manifest.write_text('[package]\nname="tracing"\nversion="0.1.44"\n')
        product = {"packages": [
            {"name":"shaar","version":"0.1.0","id":"owner","source":None,"manifest_path":str(manifest),"dependencies":[{"name":"tracing","kind":"dev","source":target_source,"req":"=0.1.44","rename":alias if alias != "tracing" else None,"target":None,"path":str(target_manifest.parent) if path_target else None}]},
            {"name":"tracing","version":"0.1.44","id":"tracing","source":target_source,"manifest_path":str(target_manifest),"dependencies":[]}],
            "resolve":{"nodes":[{"id":"owner","deps":[{"name":alias,"pkg":"tracing","dep_kinds":[{"kind":"dev","target":None}]}]}, {"id":"tracing","deps":[]}]},"workspace_root":str(root)}
        consumer = copy.deepcopy(product)
        if not retained:
            consumer["packages"] = [p for p in consumer["packages"] if p["id"] != "tracing"]
        consumer["resolve"]["nodes"][0]["deps"] = []
        product_lock = [{"name":"shaar","version":"0.1.0","dependencies":["tracing"]}, {"name":"tracing","version":"0.1.44","source":graph.REGISTRY if path_target else target_source,"checksum":"fixed","dependencies":[]}]
        if path_target:
            product_lock[1].pop('source', None)
            product_lock[1].pop('checksum', None)
        consumer_lock = [{"name":"native-graph-normal-consumer","version":"0.0.0","dependencies":["shaar"]},{"name":"shaar","version":"0.1.0","dependencies":[]}]
        if retained:
            consumer_lock.append(product_lock[1])
        product_bytes, consumer_bytes = json.dumps(product).encode(), json.dumps(consumer).encode()
        argv = ["cargo", "metadata", "--format-version", "1"]
        def build_context(product_data=product_bytes):
            record = lambda data: {"argv":argv,"cwd":str(root),"exit_code":0,"stdout_sha256":hashlib.sha256(data).hexdigest()}
            return graph.build_projection_context(product_data, consumer_bytes, product_record=record(product_data), consumer_record=record(consumer_bytes), product_argv=argv, consumer_argv=argv, product_cwd=root, consumer_cwd=root)
        return self.lock_bytes(product_lock), self.lock_bytes(consumer_lock), product, consumer, manifest, build_context

    def test_projection_receipt_contract_rejects_invalid_command_records(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product_data = json.dumps({"packages": [], "resolve": {"nodes": []}}).encode()
            consumer_data = product_data
            argv = ["cargo", "metadata", "--format-version", "1"]
            record = lambda data: {"argv": argv, "cwd": str(root), "exit_code": 0,
                                   "stdout_sha256": hashlib.sha256(data).hexdigest()}
            product_record, consumer_record = record(product_data), record(consumer_data)
            build = lambda: graph.build_projection_context(
                product_data, consumer_data, product_record=product_record,
                consumer_record=consumer_record, product_argv=argv, consumer_argv=argv,
                product_cwd=root, consumer_cwd=root)
            self.assertEqual(build()["product"], json.loads(product_data))
            for field, value, message in (
                ("stdout_sha256", "bad", "stdout digest mismatch"),
                ("argv", ["wrong"], "argv mismatch"),
                ("cwd", str(root / "other"), "cwd mismatch"),
                ("exit_code", 1, "did not succeed"),
            ):
                with self.subTest(field=field):
                    product_record[field] = value
                    with self.assertRaisesRegex(ValueError, message):
                        build()
                    product_record[field] = record(product_data)[field]

    def test_conditional_duplicate_dev_metadata_requires_matching_projection(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product_lock, consumer_lock, product, consumer, manifest, _ = self._projection_case(root, retained=False)
            manifest.write_text(
                '[package]\nname="shaar"\nversion="0.1.0"\n'
                '[target."cfg(unix)".dev-dependencies]\ntracing="=0.1.44"\n'
                '[target."cfg(windows)".dev-dependencies]\ntracing="^0.1.44"\n'
            )
            product['packages'][0]['dependencies'] = [
                {"name":"tracing","kind":"dev","source":graph.REGISTRY,"req":"=0.1.44","rename":None,"target":"cfg(unix)","path":None},
                {"name":"tracing","kind":"dev","source":graph.REGISTRY,"req":"^0.1.44","rename":None,"target":"cfg(windows)","path":None},
            ]
            product['resolve']['nodes'][0]['deps'][0]['dep_kinds'] = [
                {"kind":"dev","target":"cfg(unix)"}, {"kind":"dev","target":"cfg(windows)"}
            ]
            encoded = json.dumps(product).encode()
            record = lambda data: {"argv":["cargo","metadata","--format-version","1"],"cwd":str(root),"exit_code":0,"stdout_sha256":hashlib.sha256(data).hexdigest()}
            context = lambda: graph.build_projection_context(
                encoded, json.dumps(consumer).encode(), product_record=record(encoded),
                consumer_record=record(json.dumps(consumer).encode()),
                product_argv=["cargo","metadata","--format-version","1"],
                consumer_argv=["cargo","metadata","--format-version","1"], product_cwd=root, consumer_cwd=root)
            result = graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
            self.assertEqual(result["removed_projection_packages"], [("tracing", "0.1.44", graph.REGISTRY)])
            product['packages'][0]['dependencies'][1]['req'] = "=0.1.45"
            encoded = json.dumps(product).encode()
            with self.assertRaisesRegex(ValueError, "requirement"):
                graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())

    def test_retained_dev_edge_projection_evidence(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product_lock, consumer_lock, product, consumer, manifest, context = self._projection_case(root)
            result = graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
            self.assertEqual(len(result['proven_projection_edges']), 1)
            self.assertEqual(result['proven_projection_edges'][0]['target'], ['tracing', '0.1.44', graph.REGISTRY])
            self.assertEqual(result['proven_projection_edges'][0]['manifest_sha256'], hashlib.sha256(manifest.read_bytes()).hexdigest())
            for mutation in ('source', 'version', 'rename', 'target', 'duplicate'):
                mutated = copy.deepcopy(product)
                if mutation == 'source':
                    mutated['packages'][1]['source'] = 'registry+wrong'
                elif mutation == 'version':
                    mutated['packages'][1]['version'] = '9.9.9'
                elif mutation == 'rename':
                    mutated['packages'][0]['dependencies'][0]['rename'] = 'wrong'
                elif mutation == 'target':
                    mutated['resolve']['nodes'][0]['deps'][0]['dep_kinds'][0]['target'] = 'cfg(windows)'
                else:
                    duplicate = copy.deepcopy(mutated['packages'][1])
                    duplicate['id'] = 'duplicate'
                    mutated['packages'].append(duplicate)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context(json.dumps(mutated).encode()))
            manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n[dependencies]\ntracing="=0.1.44"\n')
            with self.assertRaises(ValueError): graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
            manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n[dev-dependencies]\ntracing="=0.1.44"\n')
            with self.assertRaisesRegex(ValueError, 'requires projection evidence'):
                graph.audit_consumer_lock(product_lock, consumer_lock)
            for alias, ok in (("trace_alias", True),):
                manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n[dev-dependencies]\ntrace_alias = { package="tracing", version="=0.1.44" }\n')
                renamed = copy.deepcopy(product)
                renamed['packages'][0]['dependencies'][0]['rename'] = alias
                renamed['resolve']['nodes'][0]['deps'][0]['name'] = alias
                encoded = json.dumps(renamed).encode()
                graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context(encoded))
                manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n[dev-dependencies]\ntracing="=0.1.44"\n')
                with self.assertRaisesRegex(ValueError, 'actual manifest alias'):
                    graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context(encoded))
            # Missing target is accepted only with matching source-manifest and metadata proof.
            product_lock, consumer_lock, product, consumer, manifest, context = self._projection_case(root, retained=False)
            graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
            for kind in (None, 'build'):
                mutated = copy.deepcopy(product)
                mutated['resolve']['nodes'][0]['deps'][0]['dep_kinds'] = [
                    {'kind': kind, 'target': None}
                ]
                mutated['packages'][0]['dependencies'][0]['kind'] = kind
                section = 'dependencies' if kind is None else 'build-dependencies'
                manifest.write_text(
                    '[package]\nname="shaar"\nversion="0.1.0"\n'
                    f'[{section}]\ntracing="=0.1.44"\n'
                )
                encoded = json.dumps(mutated).encode()
                with self.assertRaisesRegex(ValueError, 'not exclusively dev'):
                    graph.audit_consumer_lock(
                        product_lock, consumer_lock,
                        projection_context=context(encoded),
                    )
            manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n[dev-dependencies]\ntracing="=0.1.44"\n')
            with self.assertRaisesRegex(ValueError, 'requires projection evidence'):
                graph.audit_consumer_lock(product_lock, consumer_lock)
            product_lock, consumer_lock, product, consumer, manifest, context = self._projection_case(root, path_target=True)
            graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
            manifest.write_text('[package]\nname="shaar"\nversion="0.1.0"\n[dev-dependencies]\ntracing="=0.1.44"\n')
            with self.assertRaisesRegex(ValueError, 'registry projection dependency source mismatch'):
                graph.audit_consumer_lock(product_lock, consumer_lock, projection_context=context())
    def test_future_dev_verification_uses_disposable_copy_and_locked_tests(self):
        import json
        import ci
        import prepare
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "prepared"
            consumer = root / "consumer"
            source = destination / "n0-future-0.3.2"
            source.mkdir(parents=True)
            manifest = (
                '[package]\nname = "n0-future"\nversion = "0.3.2"\n'
                f'[target.{json.dumps(prepare.FUTURE_TARGET)}.dependencies]\n'
                'tokio = { version = "^1.28", features = ["macros", "rt", "time"] }\n'
                f'[target.{json.dumps(prepare.FUTURE_TARGET)}.dev-dependencies]\n'
                'tokio = { version = "^1.28", features = ["test-util"] }\n'
            ).encode()
            (source / "Cargo.toml").write_bytes(manifest)
            archived_lock = (
                'version = 4\n\n'
                '[[package]]\n'
                'name = "n0-future"\n'
                'version = "0.3.2"\n'
                'dependencies = ["tokio"]\n\n'
                '[[package]]\n'
                'name = "tokio"\n'
                'version = "1.48.0"\n'
                f'source = "{graph.REGISTRY}"\n'
                'checksum = "ff360e02eab121e0bc37a2d3b4d4dc622e6eda3a8e5253d5435ecf5bd4c68408"\n'
                '\n'
            ).encode()
            (source / "Cargo.lock").write_bytes(archived_lock)
            (source / "src.rs").write_bytes(b"pub fn fixture() {}\\n")
            metadata = {
                "packages": [
                    {
                        "id": "future",
                        "name": "n0-future",
                        "version": "0.3.2",
                        "source": None,
                        "manifest_path": str(root / "target/native-graph-future-dev/Cargo.toml"),
                        "dependencies": [
                            {"name": "tokio", "target": prepare.FUTURE_TARGET, "kind": None, "req": "^1.28", "source": graph.REGISTRY, "features": ["macros", "rt", "time"]},
                            {"name": "tokio", "target": prepare.FUTURE_TARGET, "kind": "dev", "req": "^1.28", "source": graph.REGISTRY, "features": ["test-util"]},
                        ],
                    },
                    {
                        "id": "tokio",
                        "name": "tokio",
                        "version": "1.48.0",
                        "source": graph.REGISTRY,
                    },
                ],
                "workspace_members": ["future"],
                "resolve": {
                    "root": "future",
                    "nodes": [
                        {"id": "future", "deps": [{"pkg": "tokio", "dep_kinds": [
                            {"kind": None, "target": prepare.FUTURE_TARGET},
                            {"kind": "dev", "target": prepare.FUTURE_TARGET},
                        ]}], "features": []},
                        {"id": "tokio", "deps": [], "features": ["rt", "time", "macros", "test-util"]},
                    ],
                },
            }
            calls = []
            def cargo(argv, cwd, **kwargs):
                calls.append((argv, Path(cwd)))
                if "metadata" in argv:
                    stdout = json.dumps(metadata).encode()
                else:
                    stdout = b"ok\\n"
                return type("Result", (), {"stdout": stdout, "stderr": b"", "returncode": 0})()
            before = ci.prepare.inventory(source)
            source_manifest = (source / "Cargo.toml").read_bytes()
            source_runtime = (source / "src.rs").read_bytes()
            with (mock.patch.multiple(ci, ROOT=root, DESTINATION=destination, CONSUMER=consumer,
                                      LOGS=root / "logs", COMMANDS=[]),
                  mock.patch.object(ci.subprocess, "run", side_effect=cargo)):
                result = ci.verify_future_dev()
                records = list(ci.COMMANDS)
            copied = Path(result["copy"]) / "Cargo.toml"
            self.assertTrue(records)
            self.assertEqual(records[0]["stdout_sha256"], hashlib.sha256(json.dumps(metadata).encode()).hexdigest())
            self.assertEqual([argv[:2] for argv, _ in calls[1:]], [["cargo", "test"], ["cargo", "test"]])
            self.assertEqual([argv[argv.index("--lib") if "--lib" in argv else argv.index("--doc")] for argv, _ in calls[1:]], ["--lib", "--doc"])
            self.assertTrue(all("--locked" in argv for argv, _ in calls))
            self.assertEqual((source / "Cargo.toml").read_bytes(), source_manifest)
            self.assertEqual((source / "Cargo.lock").read_bytes(), archived_lock)
            self.assertEqual((source / "src.rs").read_bytes(), source_runtime)
            self.assertEqual(ci.prepare.inventory(source), before)
            self.assertEqual(copied.read_bytes(), b'[workspace]\nresolver = "3"\n\n' + manifest)
            self.assertEqual((Path(result["copy"]) / "src.rs").read_bytes(), source_runtime)
            self.assertEqual(result["manifest_change"], "standalone workspace resolver=3 only")
            self.assertTrue(result["dev_lock_sha256_before"])
            self.assertEqual(result["dev_lock_sha256_before"], result["dev_lock_sha256_after"])
            self.assertEqual(result['dev_lock_sha256_before'], hashlib.sha256(archived_lock).hexdigest())
            self.assertEqual(records[0]["stdout_sha256"], hashlib.sha256(json.dumps(metadata).encode()).hexdigest())
            self.assertEqual(
                result["dev_tokio"],
                {"version": "1.48.0", "source": graph.REGISTRY,
                 "checksum": "ff360e02eab121e0bc37a2d3b4d4dc622e6eda3a8e5253d5435ecf5bd4c68408"},
            )
            self.assertTrue(all(record.get("stdout_sha256") for record in records))
            self.assertEqual((Path(result["copy"]) / "Cargo.lock").read_bytes(), archived_lock)
            self.assertTrue(all(cwd == Path(result["copy"]) for _, cwd in calls))
            for phase in ("metadata", "--lib", "--doc"):
                for filename in ("Cargo.toml", "Cargo.lock"):
                    def mutate(argv, cwd, **kwargs):
                        response = cargo(argv, cwd, **kwargs)
                        if phase in argv:
                            path = Path(cwd) / filename
                            path.write_bytes(path.read_bytes() + b"\nmutation")
                        return response
                    with self.subTest(phase=phase, filename=filename):
                        with (mock.patch.multiple(ci, ROOT=root, DESTINATION=destination, CONSUMER=consumer,
                                                  LOGS=root / "logs", COMMANDS=[]),
                              mock.patch.object(ci.subprocess, "run", side_effect=mutate)):
                            message = "manifest changed" if filename == "Cargo.toml" else "lock changed"
                            with self.assertRaisesRegex(ValueError, message):
                                ci.verify_future_dev()
                        self.assertEqual(ci.prepare.inventory(source), before)


if __name__ == "__main__":
    unittest.main()
