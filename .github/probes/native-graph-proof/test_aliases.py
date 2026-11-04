# SPDX-License-Identifier: MIT OR Apache-2.0
"""Regression tests for Cargo output alias attribution and byte capture."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from cargo_aliases import audit_output_aliases, cargo_output_aliases, collect_output_aliases


class CargoAliasTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.host = "x86_64-pc-windows-msvc" if sys.platform == "win32" else "x86_64-unknown-linux-gnu"
        self.target = self.root / "target"
        self.manifest = self.root / "Cargo.toml"
        self.manifest.write_text("[workspace]\n", encoding="utf-8")
        self.pkgroot = self.root / "reviewed-pkg"
        self.pkgroot.mkdir()
        self.pkgmanifest = self.pkgroot / "Cargo.toml"
        self.pkgmanifest.write_text("[package]\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def build_evidence(self):
        exe = ".exe" if "windows" in self.host else ""
        build_dir = self.target / "debug" / "build" / "reviewed-pkg-abc"
        build_dir.mkdir(parents=True, exist_ok=True)
        build_source = self.pkgroot / "build.rs"
        build_source.write_text("fn main() {}\n", encoding="utf-8")
        compiled_build = build_dir / ("build_script_build-abc" + exe)
        build_alias = build_dir / ("build-script-build" + exe)
        marker_build = b"captured custom-build output marker"
        compiled_build.write_bytes(marker_build)
        build_alias.write_bytes(marker_build)
        custom_target = {
            "src_path": str(build_source),
            "name": "build-script-build",
            "kind": ["custom-build"],
            "crate_types": ["bin"],
        }
        build_package = {
            "id": "reviewed-pkg 1.2.3 (path+file:///reviewed-pkg)",
            "name": "reviewed-pkg",
            "version": "1.2.3",
            "manifest_path": str(self.pkgmanifest),
            "targets": [custom_target],
        }
        build_unit = {
            "package_name": "reviewed-pkg",
            "package_version": "1.2.3",
            "cwd": str(self.pkgroot),
            "manifest_dir": str(self.pkgroot),
            "context": "host",
            "args": [
                "--crate-name", "build_script_build", "--crate-type", "bin",
                "-Cextra-filename=-abc", "--out-dir", str(build_dir), str(build_source),
            ],
            "outputs": [{
                "path": str(compiled_build),
                "size": len(marker_build),
                "sha256": hashlib.sha256(marker_build).hexdigest(),
                "snapshot_path": "raw/build.bin",
            }],
            "kind": "compile",
            "exit_code": 0,
            "launch_error": None,
        }
        build_artifact = {
            "reason": "compiler-artifact",
            "package_id": build_package["id"],
            "target": custom_target,
            "filenames": [str(build_alias)],
            "executable": None,
            "features": [],
            "profile": {"test": False},
            "fresh": False,
        }

        crate = "native_graph_normal_consumer"
        deps = self.target / self.host / "debug" / "deps"
        deps.mkdir(parents=True, exist_ok=True)
        root_source = self.root / "src" / "lib.rs"
        root_source.parent.mkdir(parents=True, exist_ok=True)
        root_source.write_text("pub fn marker() {}\n", encoding="utf-8")
        direct_rlib = deps / ("lib" + crate + "-abc.rlib")
        direct_meta = deps / ("lib" + crate + "-abc.rmeta")
        promoted_rlib = deps.parent / ("lib" + crate + ".rlib")
        marker_rlib = b"rlib evidence bytes"
        marker_meta = b"metadata evidence bytes"
        direct_rlib.write_bytes(marker_rlib)
        direct_meta.write_bytes(marker_meta)
        promoted_rlib.write_bytes(marker_rlib)
        lib_target = {
            "src_path": str(root_source),
            "name": crate,
            "kind": ["lib"],
            "crate_types": ["lib"],
        }
        root_package = {
            "id": "native-graph-normal-consumer 0.1.0 (path+file:///root)",
            "name": "native-graph-normal-consumer",
            "version": "0.1.0",
            "manifest_path": str(self.manifest),
            "targets": [lib_target],
        }
        lib_unit = {
            "package_name": root_package["name"],
            "package_version": root_package["version"],
            "cwd": str(self.root),
            "manifest_dir": str(self.root),
            "context": "target",
            "args": [
                "--crate-name", crate, "--crate-type", "lib", "-Cextra-filename=-abc",
                "--out-dir", str(deps), "--target", self.host, str(root_source),
            ],
            "outputs": [
                {
                    "path": str(direct_rlib), "size": len(marker_rlib),
                    "sha256": hashlib.sha256(marker_rlib).hexdigest(),
                    "snapshot_path": "raw/lib.rlib",
                },
                {
                    "path": str(direct_meta), "size": len(marker_meta),
                    "sha256": hashlib.sha256(marker_meta).hexdigest(),
                    "snapshot_path": "raw/lib.rmeta",
                },
            ],
            "kind": "compile",
            "exit_code": 0,
            "launch_error": None,
        }
        lib_artifact = {
            "reason": "compiler-artifact",
            "package_id": root_package["id"],
            "target": lib_target,
            "filenames": [str(promoted_rlib), str(direct_meta)],
            "executable": None,
            "features": [],
            "profile": {"test": False},
            "fresh": False,
        }
        direct_bytes = {
            str(compiled_build): marker_build,
            str(direct_rlib): marker_rlib,
            str(direct_meta): marker_meta,
        }
        alias_bytes = {str(build_alias): marker_build, str(promoted_rlib): marker_rlib}
        return (
            (build_unit, build_artifact, build_package),
            (lib_unit, lib_artifact, root_package),
            direct_bytes,
            alias_bytes,
        )

    def test_custom_build_alias_matches_host_suffix_and_evidence(self):
        (unit, artifact, package), _, _, _ = self.build_evidence()
        aliases = cargo_output_aliases(
            unit, artifact, package, str(self.target), self.host, str(self.manifest)
        )
        self.assertEqual(
            aliases,
            [{"alias": artifact["filenames"][0], "direct": unit["outputs"][0]["path"]}],
        )

    def test_alias_spellings_for_linux_and_windows(self):
        for host in ('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'):
            self.host = host
            build, lib, _, _ = self.build_evidence()
            for unit, artifact, package in (build, lib):
                aliases = cargo_output_aliases(
                    unit, artifact, package, str(self.target), self.host, str(self.manifest)
                )
                self.assertEqual(
                    aliases,
                    [{"alias": artifact["filenames"][0], "direct": unit["outputs"][0]["path"]}],
                )
            suffix = '.exe' if 'windows' in host else ''
            self.assertTrue(build[1]["filenames"][0].endswith('build-script-build' + suffix))

    def test_root_multi_crate_types_are_direct_products_only(self):
        import copy

        for crate_types in (('cdylib', 'lib'), ('lib', 'cdylib')):
            for suffix in ('', '-abc'):
                with self.subTest(crate_types=crate_types, suffix=suffix):
                    _, (unit, artifact, package), _, _ = self.build_evidence()
                    root = self.target / self.host / 'debug' / 'deps'
                    crate = 'native_graph_normal_consumer'
                    source = unit['args'][-1]
                    unit['args'] = [
                        '--crate-name', crate,
                        '--crate-type', crate_types[0], '--crate-type', crate_types[1],
                        '--out-dir', str(root), '--target', self.host,
                    ] + (['-Cextra-filename=' + suffix] if suffix else []) + [source]
                    artifact['target']['kind'] = ['cdylib', 'lib']
                    artifact['target']['crate_types'] = ['cdylib', 'lib']
                    rlib = root / ('lib' + crate + suffix + '.rlib')
                    shared = root / ('lib' + crate + suffix + '.so')
                    unit['outputs'] = [{'path': str(rlib)}, {'path': str(shared)}]
                    artifact['filenames'] = [str(rlib), str(shared)]
                    self.assertEqual(
                        cargo_output_aliases(unit, artifact, package, str(self.target), self.host, str(self.manifest)), []
                    )
                    invalid_values = (
                        ('--crate-type', 'dylib'),
                        ('--crate-type', 'lib', '--crate-type', 'lib'),
                        ('--crate-type', 'unknown'),
                        ('--crate-type', ''),
                        ('--crate-type',),
                    )
                    for value in invalid_values:
                        changed = copy.deepcopy(unit)
                        args = changed['args']
                        first = args.index('--crate-type')
                        if value == ('--crate-type',):
                            args[:] = [arg for arg in args if arg != '--crate-type' and arg not in crate_types]
                            args.extend(value)
                        elif value[1] == 'lib' and len(value) > 2:
                            args[first:first + 4] = list(value)
                        else:
                            args[first:first + 2] = list(value)
                        self.assertEqual(
                            cargo_output_aliases(unit, artifact, package, str(self.target), self.host, str(self.manifest)), []
                        )
                        self.assertIsNone(
                            cargo_output_aliases(changed, artifact, package, str(self.target), self.host, str(self.manifest))
                        )
                    promoted = copy.deepcopy(artifact)
                    promoted['filenames'] = [str(root.parent / ('lib' + crate + '.rlib'))]
                    self.assertIsNone(
                        cargo_output_aliases(unit, promoted, package, str(self.target), self.host, str(self.manifest))
                    )

    def test_root_consumer_promoted_rlib_alias(self):
        _, (unit, artifact, package), _, _ = self.build_evidence()
        aliases = cargo_output_aliases(
            unit, artifact, package, str(self.target), self.host, str(self.manifest)
        )
        self.assertEqual(
            aliases,
            [{"alias": artifact["filenames"][0], "direct": unit["outputs"][0]["path"]}],
        )

    def test_rejects_mismatched_attribution_and_compiler_arguments(self):
        for which in (0, 1):
            build, lib, _, _ = self.build_evidence()
            unit, artifact, package = build if which == 0 else lib
            self.assertIsNotNone(
                cargo_output_aliases(unit, artifact, package, str(self.target), self.host, str(self.manifest))
            )
            mutations = []
            bad_artifact = dict(artifact)
            bad_artifact["package_id"] = "other"
            mutations.append((unit, bad_artifact, package))
            bad_unit = dict(unit)
            bad_unit["cwd"] = str(self.root / "foreign")
            mutations.append((bad_unit, artifact, package))
            bad_unit = dict(unit)
            bad_unit["args"] = unit["args"] + ["-Cextra-filename=-def"]
            mutations.append((bad_unit, artifact, package))
            mutations.extend([
                (dict(unit, exit_code=1), artifact, package),
                (dict(unit, launch_error='failed'), artifact, package),
                (unit, dict(artifact, features=['forged']), package),
                (unit, dict(artifact, filenames=[str(self.root / 'wrong')]), package),
                (dict(unit, args=unit['args']+['--out-dir',str(self.target)]), artifact, package),
            ])
            for changed in mutations:
                self.assertIsNotNone(
                    cargo_output_aliases(unit, artifact, package, str(self.target), self.host, str(self.manifest))
                )
                self.assertIsNone(
                    cargo_output_aliases(*changed, str(self.target), self.host, str(self.manifest))
                )

    def test_collect_snapshots_live_alias_bytes_without_changing_raw_artifacts(self):
        build, lib, direct_bytes, alias_bytes = self.build_evidence()
        units = [build[0], lib[0]]
        original_raw = {
            record["snapshot_path"]: direct_bytes[record["path"]]
            for unit in units
            for record in unit["outputs"]
        }
        collected = {"units": units, "raw": dict(original_raw)}
        artifacts = [build[1], lib[1]]
        stdout = "\n".join(json.dumps(artifact) for artifact in artifacts)
        capture = self.root / "capture"
        context = {"env": {"CARGO_TARGET_DIR": str(self.target)}, "host": self.host}
        packages = [build[2], lib[2]]
        records = collect_output_aliases(
            collected, stdout, packages, context, str(self.manifest), str(capture)
        )
        self.assertEqual(len(records), 2)
        self.assertEqual({name: collected["raw"][name] for name in original_raw}, original_raw)
        self.assertEqual(len(collected["raw"]), len(original_raw) + 2)
        for record in records:
            data = (capture / record["snapshot_path"]).read_bytes()
            self.assertEqual(data, alias_bytes[record["alias"]])
            self.assertEqual(record["size"], len(data))
            self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())

        messages = [json.loads(line) for line in stdout.splitlines()]
        proof = {
            "compiler_capture": {
                "units": units, "aliases": records, "context": context,
                "wrapper": {"target": self.host},
            },
            "consumer_manifest": str(self.manifest),
            "consumer_cwd": str(self.root / "consumer"),
            "artifacts": {
                f"consumer/compiler-capture/{name}": data
                for name, data in collected["raw"].items()
            },
        }
        # Replay must use captured bytes, not the live direct or alias paths.
        for unit in units:
            for output in unit["outputs"]:
                Path(output["path"]).unlink()
        for alias in alias_bytes:
            Path(alias).unlink()
        mapped, owners = audit_output_aliases(proof, packages, messages)
        self.assertEqual(mapped, {0: {build[0]["outputs"][0]["path"]}, 1: {o["path"] for o in lib[0]["outputs"]}})
        self.assertEqual(owners, {0: 0, 1: 1})

    def test_replay_rejects_tampered_alias_evidence(self):
        build, lib, direct_bytes, alias_bytes = self.build_evidence()
        units = [build[0], lib[0]]
        collected = {"units": units, "raw": {
            output["snapshot_path"]: direct_bytes[output["path"]]
            for unit in units for output in unit["outputs"]
        }}
        artifacts = [build[1], lib[1]]
        messages = [json.loads(json.dumps(artifact)) for artifact in artifacts]
        stdout = "\n".join(json.dumps(artifact) for artifact in artifacts)
        context = {"env": {"CARGO_TARGET_DIR": str(self.target)}, "host": self.host}
        packages = [build[2], lib[2]]
        capture = self.root / "capture"
        records = collect_output_aliases(collected, stdout, packages, context, str(self.manifest), str(capture))
        proof = {
            "compiler_capture": {"units": units, "aliases": records, "context": context,
                                  "wrapper": {"target": self.host}},
            "consumer_manifest": str(self.manifest), "consumer_cwd": str(self.root / "consumer"),
            "artifacts": {f"consumer/compiler-capture/{name}": data for name, data in collected["raw"].items()},
        }
        mutations = []
        for key, value in (("sha256", "0" * 64), ("path", "wrong"), ("unit_index", 1)):
            changed = json.loads(json.dumps(records))
            changed[0][key] = value
            mutations.append(("aliases", changed))
        for key, value in (("features", ["tampered"]), ("filenames", ["wrong"])):
            changed = json.loads(json.dumps(messages))
            changed[0][key] = value
            mutations.append(("messages", changed))
        changed = json.loads(json.dumps(units))
        changed[0]["args"] += ["-Cextra-filename=-def"]
        mutations.append(("units", changed))
        changed_artifacts = dict(proof["artifacts"])
        alias_blob = "consumer/compiler-capture/" + records[0]["snapshot_path"]
        changed_artifacts[alias_blob] = b"tampered"
        mutations.append(("artifacts", changed_artifacts))
        changed = json.loads(json.dumps(records)) + [json.loads(json.dumps(records[0]))]
        mutations.append(("aliases", changed))
        mutations.append(("aliases", records[:1]))
        for field, value in mutations:
            audit_output_aliases(proof, packages, messages)
            candidate = __import__("copy").deepcopy(proof)
            if field == "aliases":
                candidate["compiler_capture"]["aliases"] = value
                args = messages
            elif field == "units":
                candidate["compiler_capture"]["units"] = value
                args = messages
            elif field == "messages":
                args = value
            else:
                candidate["artifacts"] = value
                args = messages
            with self.subTest(field=field, value=str(value)[:60]):
                with self.assertRaises(ValueError):
                    audit_output_aliases(candidate, packages, args)

    def test_alias_message_indexes_and_missing_or_duplicate_owner(self):
        import copy

        build, lib, direct_bytes, _ = self.build_evidence()
        units = [build[0], lib[0]]
        raw = {
            output["snapshot_path"]: direct_bytes[output["path"]]
            for unit in units
            for output in unit["outputs"]
        }
        collected = {"units": units, "raw": dict(raw)}
        messages = [
            {"reason": "compiler-message"},
            build[1],
            {"reason": "build-script-executed"},
            lib[1],
        ]
        stdout = "\n".join(json.dumps(message) for message in messages)
        context = {"env": {"CARGO_TARGET_DIR": str(self.target)}, "host": self.host}
        packages = [build[2], lib[2]]
        records = collect_output_aliases(
            collected, stdout, packages, context, str(self.manifest), str(self.root / "capture-positive")
        )
        self.assertEqual([record["artifact_index"] for record in records], [1, 3])
        self.assertEqual(collected["units"], units)
        self.assertEqual({name: collected["raw"][name] for name in raw}, raw)

        for mutation, expected in (("missing", "missing compiler unit"), ("duplicate", "ambiguous")):
            fresh = self.build_evidence()
            fresh_build, fresh_lib, fresh_bytes, _ = fresh
            fresh_units = [fresh_build[0], fresh_lib[0]]
            fresh_raw = {
                output["snapshot_path"]: fresh_bytes[output["path"]]
                for unit in fresh_units
                for output in unit["outputs"]
            }
            fresh_collected = {"units": fresh_units, "raw": dict(fresh_raw)}
            fresh_messages = [
                {"reason": "compiler-message"},
                fresh_build[1],
                {"reason": "build-script-executed"},
                fresh_lib[1],
            ]
            fresh_stdout = "\n".join(json.dumps(message) for message in fresh_messages)
            collect_output_aliases(
                fresh_collected, fresh_stdout, [fresh_build[2], fresh_lib[2]], context,
                str(self.manifest), str(self.root / ("capture-" + mutation + "-positive")),
            )
            changed_units = copy.deepcopy(fresh_units)
            if mutation == "missing":
                changed_units.remove(changed_units[0])
            else:
                changed_units.append(copy.deepcopy(changed_units[0]))
            changed = {"units": changed_units, "raw": dict(fresh_raw)}
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, expected):
                    collect_output_aliases(
                        changed, fresh_stdout, [fresh_build[2], fresh_lib[2]], context,
                        str(self.manifest), str(self.root / ("capture-" + mutation + "-changed")),
                    )

    def test_collect_rejects_alias_content_mismatch(self):
        build, lib, _, _ = self.build_evidence()
        units = [build[0], lib[0]]
        collected = {
            "units": units,
            "raw": {
                output["snapshot_path"]: Path(output["path"]).read_bytes()
                for unit in units
                for output in unit["outputs"]
            },
        }
        stdout = "\n".join(json.dumps(artifact) for artifact in (build[1], lib[1]))
        context = {"env": {"CARGO_TARGET_DIR": str(self.target)}, "host": self.host}
        packages = [build[2], lib[2]]
        messages = [json.loads(line) for line in stdout.splitlines()]
        proof = {
            "compiler_capture": {
                "units": units,
                "aliases": collect_output_aliases(
                    collected, stdout, packages, context, str(self.manifest), str(self.root / "capture")
                ),
                "context": context,
                "wrapper": {"target": self.host},
            },
            "consumer_manifest": str(self.manifest),
            "consumer_cwd": str(self.root / "consumer"),
            "artifacts": {
                f"consumer/compiler-capture/{name}": data
                for name, data in collected["raw"].items()
            },
        }
        audit_output_aliases(proof, packages, messages)
        Path(build[1]["filenames"][0]).write_bytes(b"wrong")
        collected["raw"] = {
            output["snapshot_path"]: Path(output["path"]).read_bytes()
            for unit in units
            for output in unit["outputs"]
        }
        with self.assertRaisesRegex(ValueError, "alias differs"):
            collect_output_aliases(
                collected, stdout, packages, context, str(self.manifest), str(self.root / "capture")
            )


    def test_collect_rejects_changed_direct_bytes(self):
        build, lib, direct_bytes, _ = self.build_evidence()
        units = [build[0], lib[0]]
        raw = {
            output["snapshot_path"]: direct_bytes[output["path"]]
            for unit in units
            for output in unit["outputs"]
        }
        collected = {"units": units, "raw": dict(raw)}
        stdout = "\n".join(json.dumps(artifact) for artifact in (build[1], lib[1]))
        context = {"env": {"CARGO_TARGET_DIR": str(self.target)}, "host": self.host}
        packages = [build[2], lib[2]]
        collect_output_aliases(
            collected, stdout, packages, context, str(self.manifest), str(self.root / "capture-positive")
        )
        Path(build[0]["outputs"][0]["path"]).write_bytes(b"changed direct")
        with self.assertRaisesRegex(ValueError, "alias differs"):
            collect_output_aliases(
                {"units": units, "raw": dict(raw)}, stdout, packages, context,
                str(self.manifest), str(self.root / "capture-changed-direct"),
            )

    def test_collector_rejects_reused_direct_unit(self):
        build, _, direct_bytes, _ = self.build_evidence()
        unit, artifact, package = build
        artifact = dict(artifact, filenames=[unit['outputs'][0]['path']])
        collected = {'units': [unit], 'raw': {o['snapshot_path']: direct_bytes[o['path']] for o in unit['outputs']}}
        context = {'env': {'CARGO_TARGET_DIR': str(self.target)}, 'host': self.host}
        line = json.dumps(artifact)
        self.assertEqual(collect_output_aliases(collected, line, [package], context, str(self.manifest), self.root/'direct-capture'), [])
        with self.assertRaisesRegex(ValueError, 'reused'):
            collect_output_aliases(collected, line+'\n'+line, [package], context, str(self.manifest), self.root/'direct-capture')

    def test_collector_rejects_non_object_message(self):
        build, _, direct_bytes, _ = self.build_evidence()
        unit, artifact, package = build
        context = {'env': {'CARGO_TARGET_DIR': str(self.target)}, 'host': self.host}
        packages = [package]
        raw = {output['snapshot_path']: direct_bytes[output['path']] for output in unit['outputs']}
        collected = {'units': [unit], 'raw': dict(raw)}
        collect_output_aliases(
            collected, json.dumps(artifact), packages, context, str(self.manifest),
            str(self.root / 'capture-positive-json'),
        )
        for stdout in ('[]', 'null'):
            fresh = {'units': [unit], 'raw': dict(raw)}
            with self.subTest(stdout=stdout):
                with self.assertRaisesRegex(ValueError, 'must be an object'):
                    collect_output_aliases(
                        fresh, stdout, packages, context, str(self.manifest),
                        str(self.root / 'capture-invalid-json'),
                    )

    def test_compiler_unit_crate_type_seam_regression(self):
        import copy
        from test_features import CompilerUnitEvidenceTests
        from capability_fixture import audit_compiler_units
        from features import AuditError

        for order in (("cdylib", "lib"), ("lib", "cdylib")):
            proof, packages, build, recipe = CompilerUnitEvidenceTests()._fixture()
            messages = [json.loads(line) for line in build.splitlines()]
            for package in packages:
                package["targets"][0]["kind"] = ["cdylib", "lib"]
                package["targets"][0]["crate_types"] = ["cdylib", "lib"]
            records = []
            for name in proof["invocations"]:
                record = json.loads(proof["artifacts"][name])
                args = record["args"]
                index = args.index("--crate-type")
                args[index:index + 2] = ["--crate-type", order[0], "--crate-type", order[1]]
                out = args[args.index("--out-dir") + 1]
                paths = [out + "/libunit_demo-u" + name[4] + ".so", out + "/libunit_demo-u" + name[4] + ".rlib"]
                record["outputs"] = paths
                proof["artifacts"][name] = json.dumps(record).encode()
                records.append(paths)
            for message, paths in zip(messages, records):
                message["target"]["kind"] = ["cdylib", "lib"]
                message["target"]["crate_types"] = ["cdylib", "lib"]
                message["filenames"] = paths
            build = b"".join((json.dumps(message) + "\n").encode() for message in messages)
            expected = ("cdylib", "lib")
            units = audit_compiler_units(proof, packages, build, recipe)
            self.assertEqual(len(units), 2)
            self.assertEqual([unit["context"] for unit in units], ["host", "target"])
            self.assertEqual([unit["crate_types"] for unit in units], [expected, expected])

            for label in (
                'missing', 'duplicate', 'subset', 'add', 'unknown', 'empty',
                'malformed', 'metadata-subset', 'artifact-subset',
            ):
                candidate = copy.deepcopy(proof)
                candidate_packages = copy.deepcopy(packages)
                candidate_messages = copy.deepcopy(messages)
                audit_compiler_units(
                    candidate, candidate_packages, build, recipe
                )
                name = candidate['invocations'][0]
                record = json.loads(candidate['artifacts'][name])
                args = record['args']
                index = args.index('--crate-type')

                if label == 'missing':
                    del args[index:index + 4]
                elif label == 'subset':
                    del args[index + 2:index + 4]
                elif label == 'duplicate':
                    args.extend(['--crate-type', 'lib'])
                elif label == 'add':
                    args.extend(['--crate-type', 'proc-macro'])
                elif label == 'unknown':
                    args.extend(['--crate-type', 'unknown'])
                elif label == 'empty':
                    args.extend(['--crate-type', ''])
                elif label == 'malformed':
                    args.append('--crate-type=lib,cdylib')
                elif label == 'metadata-subset':
                    candidate_packages[0]['targets'][0]['crate_types'] = ['lib']
                elif label == 'artifact-subset':
                    candidate_messages[0]['target']['crate_types'] = ['lib']

                candidate['artifacts'][name] = json.dumps(record).encode()
                candidate_build = b''.join(
                    (json.dumps(message) + '\n').encode()
                    for message in candidate_messages
                )
                with self.subTest(order=order, mutation=label), self.assertRaises(AuditError):
                    audit_compiler_units(
                        candidate, candidate_packages, candidate_build, recipe
                    )

    def test_crate_type_sets_are_complete_and_strict(self):
        from cargo_aliases import crate_types, target_crate_types

        for args in (
            ['--crate-type', 'cdylib', '--crate-type', 'lib'],
            ['--crate-type', 'lib', '--crate-type', 'cdylib'],
            ['--crate-type=cdylib', '--crate-type=lib'],
            ['--crate-type=lib', '--crate-type=cdylib'],
        ):
            with self.subTest(args=args):
                self.assertEqual(crate_types(args), ('cdylib', 'lib'))
        for kind in ('lib', 'bin', 'proc-macro'):
            with self.subTest(kind=kind):
                self.assertEqual(crate_types(['--crate-type', kind]), (kind,))

        self.assertEqual(target_crate_types({'crate_types': ['lib', 'cdylib']}), ('cdylib', 'lib'))
        for args in (
            [], ['--crate-type'], ['--crate-type', 'lib', '--crate-type', 'lib'],
            ['--crate-type', 'unknown'], ['--crate-type', ''], ['--crate-type='],
            ['--crate-type', '-lib'], ['--crate-type=--lib'], ['--crate-type', 'lib,cdylib'],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                crate_types(args)
        for row in (
            {}, {'crate_types': []}, {'crate_types': 'lib'},
            {'crate_types': ['lib', 'lib']}, {'crate_types': ['unknown']},
            {'crate_types': ['lib', 1]},
        ):
            with self.subTest(row=row), self.assertRaises(ValueError):
                target_crate_types(row)

if __name__ == "__main__":
    unittest.main()
