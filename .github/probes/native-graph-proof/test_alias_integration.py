# SPDX-License-Identifier: MIT OR Apache-2.0
"""Integration regression tests for captured Cargo output aliases."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "native-graph" / "fixture"
for path in (HERE, FIXTURE):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import features
import evidence
from cargo_aliases import collect_output_aliases, audit_output_aliases
from capability_fixture import attach_capability
from test_features import _proofs


class AliasIntegrationTests(unittest.TestCase):
    """Exercise the real capture collector, alias replay and unit audit."""

    def test_workspace_source_changes_retain_raw_provenance_and_malformed_bindings_fail(self):
        from test_features import _compare
        proofs = _proofs()
        original = _compare(copy.deepcopy(proofs))

        def shaar(items):
            return next(b for b in items["source_bindings"].values() if b["package"] == "shaar")

        for field, value in (("tree_sha256", "d" * 64), ("archive_sha256", "e" * 64)):
            changed = copy.deepcopy(proofs)
            shaar(changed[2])[field] = value
            result = _compare(changed)
            with self.subTest(field=field):
                self.assertNotEqual(original["proof_sha256"]["candidate"], result["proof_sha256"]["candidate"])
                self.assertEqual(original["feature_deltas"], result["feature_deltas"])
        for role in (0, 1, 2):
            for field, value in (("tree_sha256", "not-a-digest"), ("archive_sha256", "")):
                forged = copy.deepcopy(proofs)
                shaar(forged[role])[field] = value
                with self.subTest(role=role, field=field), self.assertRaises(features.AuditError):
                    _compare(forged)

    @staticmethod
    def _intrinsic_proofs(spelling=("--extern", "proc_macro")):
        from verify_once import add_dependency_unit
        proofs = _proofs()
        for proof in proofs:
            add_dependency_unit(proof, proc_macro=True)
            AliasIntegrationTests._append_extern(proof, spelling)
        return proofs

    @staticmethod
    def _append_extern(proof, spelling, receipt="dependency-unit.json"):
        capture = proof["compiler_capture"]
        prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
        raw = json.loads(proof["artifacts"][prefix + receipt])
        unit = next(u for u in capture["units"] if u["args"] == raw["args"])
        raw["args"].extend(spelling)
        data = json.dumps(raw).encode()
        proof["artifacts"][prefix + receipt] = data
        capture["receipts"][receipt] = hashlib.sha256(data).hexdigest()
        unit["args"] = raw["args"]

    @staticmethod
    def _audit_intrinsic(proof):
        packages, nodes = AliasIntegrationTests._metadata(proof)
        return evidence.audit_units(
            proof, packages, nodes,
            stable_identity=lambda p: (p["name"], p["version"]),
            baseline_test_util_validator=None,
        )[1]

    def test_host_proc_macro_intrinsic_replays_and_binds_unit_hash(self):
        from test_features import _compare
        from verify_once import add_dependency_unit
        hashes = []
        for spelling in (("--extern", "proc_macro"), ("--extern=proc_macro",)):
            proofs = self._intrinsic_proofs(spelling)
            _compare(proofs)
            units = self._audit_intrinsic(proofs[2])
            intrinsic = next(u for u in units if u["kind"] == ["proc-macro"])
            self.assertEqual(intrinsic["intrinsics"], ["proc_macro"])
            self.assertEqual(intrinsic["dependencies"], [])
            consumer = next(u for u in units if u["target"] == "shaar")
            self.assertEqual(len(consumer["dependencies"]), 1)
            hashes.append((intrinsic["sha256"], consumer["sha256"]))
        self.assertEqual(hashes[0], hashes[1])
        absent = _proofs()[2]
        add_dependency_unit(absent, proc_macro=True)
        units = self._audit_intrinsic(absent)
        intrinsic = next(u for u in units if u["kind"] == ["proc-macro"])
        consumer = next(u for u in units if u["target"] == "shaar")
        self.assertNotEqual(hashes[0][0], intrinsic["sha256"])
        self.assertNotEqual(hashes[0][1], consumer["sha256"])
        proofs = self._intrinsic_proofs()
        proofs[2] = absent
        with self.assertRaises(features.AuditError):
            _compare(proofs)

    def test_intrinsic_rejects_unknown_duplicate_shadowed_and_wrong_context(self):
        from test_features import _compare, _refresh_metadata
        for mutation in ("unknown", "empty", "duplicate", "path", "target", "context", "shadow", "resolved-shadow"):
            proofs = self._intrinsic_proofs()
            candidate = proofs[2]
            if mutation == "unknown":
                self._append_extern(candidate, ("--extern", "std"))
            elif mutation == "empty":
                self._append_extern(candidate, ("--extern=",))
            elif mutation == "duplicate":
                self._append_extern(candidate, ("--extern=proc_macro",))
            elif mutation == "path":
                self._append_extern(candidate, ("--extern", "proc_macro=/unknown/path"))
            elif mutation == "target":
                self._append_extern(candidate, ("--extern", "proc_macro"), "unit.json")
            elif mutation == "context":
                host = candidate["compiler_capture"]["wrapper"]["target"]
                self._append_extern(candidate, ("--target", host))
            else:
                def shadow(metadata):
                    package = next(p for p in metadata["packages"] if p["name"] == "iroh-base")
                    if mutation == "shadow":
                        package.setdefault("dependencies", []).append({
                            "name": "proc-macro", "rename": None, "kind": None})
                    else:
                        node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == package["id"])
                        node["deps"].append({"name": "proc_macro", "pkg": package["id"],
                                             "dep_kinds": [{"kind": "normal", "target": None}]})
                _refresh_metadata(candidate, shadow)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError) as failure:
                    self._audit_intrinsic(candidate)
                cause = str(failure.exception.__cause__)
                expected = ("shadows a Cargo dependency" if mutation in ("shadow", "resolved-shadow")
                            else "compiler output directory context mismatch" if mutation == "context"
                            else "alias is duplicate" if mutation == "path"
                            else "invalid --extern intrinsic")
                self.assertIn(expected, cause)
                with self.assertRaises(features.AuditError):
                    _compare(proofs)

    def test_collected_alias_capture_replays_and_audits(self):
        proof = self._root_alias(attach_capability(_proofs()[2]))
        self.collect_and_audit(proof)

    def test_shaar_multi_crate_alias_capture_and_type_guards(self):
        for suffix in ('', '-abc'):
            for crate_types in (("cdylib", "lib"), ("lib", "cdylib")):
                proof = self._shaar_multi_crate(
                    self._root_alias(attach_capability(_proofs()[2])), crate_types, suffix=suffix)
                self.collect_and_audit(proof, expected_aliases=5)

    @staticmethod
    def _shaar_multi_crate(proof, crate_types=("cdylib", "lib"), suffix=''):
        """Turn shaar's real ordinary unit into a Cargo multi-crate artifact."""
        capture = proof["compiler_capture"]
        prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
        metadata_record = next(r for r in proof["records"] if r["kind"] == "metadata")
        metadata = json.loads(proof["artifacts"][metadata_record["stdout"]])
        package = next(p for p in metadata["packages"] if p["name"] == "shaar")
        row = next(t for t in package["targets"] if t.get("kind") == ["lib"])
        build_record = next(r for r in proof["records"] if r["kind"] == "build")
        messages = [json.loads(line) for line in proof["artifacts"][build_record["stdout"]].splitlines() if line.strip()]
        artifact = next(m for m in messages if m.get("reason") == "compiler-artifact" and m.get("package_id") == package["id"])
        raw = json.loads(proof["artifacts"][prefix + "unit.json"])
        unit_index = next(i for i, u in enumerate(capture["units"])
                          if all(u.get(key) == value for key, value in raw.items() if key != "outputs"))
        unit = capture["units"][unit_index]
        args = raw["args"]
        at = args.index("--crate-type")
        args[at:at + 2] = sum((["--crate-type", kind] for kind in crate_types), [])
        row["kind"] = sorted(crate_types)
        row["crate_types"] = sorted(crate_types)
        host = capture["wrapper"]["target"]
        target_dir = Path(capture["context"]["env"]["CARGO_TARGET_DIR"])
        out_dir = target_dir / host / "debug" / "deps"
        crate = args[args.index("--crate-name") + 1]
        if suffix:
            args.extend(['-C', 'extra-filename=' + suffix])
        ext = ".dll" if "windows" in host.lower() else ".so"
        markers = {"lib": b"shaar rlib fixture marker", "cdylib": b"shaar cdylib fixture marker"}
        paths = {"lib": out_dir / ("lib" + crate + suffix + ".rlib"),
                 "cdylib": out_dir / ("lib" + crate + suffix + ext)}
        paths["rmeta"] = out_dir / ("lib" + crate + suffix + ".rmeta")
        markers["rmeta"] = b"shaar rmeta fixture marker"
        filenames, snapshots, outputs = [], [], []
        for old in unit["outputs"]:
            snapshot_name = old.get("snapshot_path")
            capture["receipts"].pop(snapshot_name, None)
            proof["artifacts"].pop(prefix + snapshot_name, None)
        for index, kind in enumerate(crate_types):
            path = paths[kind]
            data = markers[kind]
            filenames.append(str(path))
            snap = f"shaar-multi-outputs/{index}"
            digest = hashlib.sha256(data).hexdigest()
            snapshots.append({"output": str(path), "snapshot": str(Path(capture["context"]["env"]["SHAAR_CAPTURE_DIR"]) / snap)})
            outputs.append({"path": str(path), "size": len(data), "sha256": digest, "snapshot_path": snap})
            proof["artifacts"][prefix + snap] = data
            capture["receipts"][snap] = digest
        if "lib" in crate_types:
            path, data = paths["rmeta"], markers["rmeta"]
            snap = f"shaar-multi-outputs/{len(outputs)}"
            digest = hashlib.sha256(data).hexdigest()
            snapshots.append({"output": str(path), "snapshot": str(Path(capture["context"]["env"]["SHAAR_CAPTURE_DIR"]) / snap)})
            outputs.append({"path": str(path), "size": len(data), "sha256": digest, "snapshot_path": snap})
            proof["artifacts"][prefix + snap] = data
            capture["receipts"][snap] = digest
        raw.update(args=args, outputs=[o["path"] for o in outputs], snapshots=snapshots)
        unit.clear()
        unit.update(raw)
        unit["outputs"] = outputs
        artifact["target"] = copy.deepcopy(row)
        artifact["filenames"] = filenames
        encoded = json.dumps(raw).encode()
        proof["artifacts"][prefix + "unit.json"] = encoded
        capture["receipts"]["unit.json"] = hashlib.sha256(encoded).hexdigest()
        metadata_bytes = json.dumps(metadata).encode()
        build_bytes = b"\n".join(json.dumps(m).encode() for m in messages)
        for record, data in ((metadata_record, metadata_bytes), (build_record, build_bytes)):
            proof["artifacts"][record["stdout"]] = data
            record["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        capture["build_stdout_sha256"] = build_record["stdout_sha256"]
        return proof

    def collect_and_audit(self, proof, expected_aliases=5):
        old = proof["consumer_cwd"]
        packages, _ = self._metadata(proof)
        capture = proof["compiler_capture"]
        context = capture["context"]
        with tempfile.TemporaryDirectory() as temp:
            consumer = Path(temp).resolve() / "consumer"
            consumer.mkdir()
            new = str(consumer)
            prefix = Path(old).name + "/compiler-capture/"

            def relocate(value):
                if isinstance(value, str):
                    return value.replace(old, new).replace('/repo', str(consumer.parent / 'repo'))
                if isinstance(value, list):
                    return [relocate(item) for item in value]
                if isinstance(value, dict):
                    return {relocate(key): relocate(item) for key, item in value.items()}
                return value

            artifact_bytes = proof["artifacts"]
            structured = {key: value for key, value in proof.items() if key != "artifacts"}
            proof.update(relocate(structured))
            capture = proof['compiler_capture']
            context = capture['context']
            proof["consumer_cwd"] = new
            proof["consumer_manifest"] = str(consumer / "Cargo.toml")
            artifacts = {}
            for name, data in artifact_bytes.items():
                relocated_name = name.replace(old, new)
                if name.startswith(prefix):
                    continue
                artifacts[relocated_name] = data
            proof["artifacts"] = artifacts

            for record in proof["records"]:
                key = record["stdout"]
                data = artifacts[key]
                if record["kind"] == "metadata":
                    data = json.dumps(relocate(json.loads(data))).encode()
                    artifacts[key] = data
                    record["stdout_sha256"] = hashlib.sha256(data).hexdigest()
                elif record["kind"] == "build":
                    rows = [relocate(json.loads(line)) for line in data.splitlines() if line.strip()]
                    data = b"".join((json.dumps(row) + "\n").encode() for row in rows)
                    artifacts[key] = data
                    record["stdout_sha256"] = hashlib.sha256(data).hexdigest()
                    capture["build_stdout_sha256"] = record["stdout_sha256"]

            target = Path(context["env"]["CARGO_TARGET_DIR"])
            capture_dir = Path(context["env"]["SHAAR_CAPTURE_DIR"])
            target.mkdir(parents=True, exist_ok=True)
            capture_dir.mkdir(parents=True, exist_ok=True)
            raw_by_name = {}
            for name, digest in capture["receipts"].items():
                if name.startswith("cargo-aliases/"):
                    continue
                data = next((value for key, value in artifact_bytes.items()
                             if key.startswith(prefix) and key[len(prefix):] == name), None)
                if data is None:
                    continue
                if name.endswith('.json'):
                    data = json.dumps(relocate(json.loads(data))).encode()
                raw_by_name[name] = data
                path = capture_dir / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for unit in capture["units"]:
                if unit.get('stdin') is not None:
                    continue
                for output in unit["outputs"]:
                    snapshot = raw_by_name.get(output["snapshot_path"])
                    if snapshot is not None:
                        path = Path(output["path"])
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(snapshot)
            for alias in capture.get("aliases", []):
                snapshot = artifact_bytes.get(prefix + alias["snapshot_path"])
                if snapshot is not None:
                    path = Path(alias["alias"])
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(snapshot)
                    direct = Path(alias["direct"])
                    direct.parent.mkdir(parents=True, exist_ok=True)
                    if not direct.exists():
                        direct.write_bytes(snapshot)

            packages, _ = self._metadata(proof)
            collected = features.collect_capture(
                capture_dir, target,
                {**context, "host": capture["wrapper"]["target"],
                 "packages": packages, "lock_checksums": proof["lock_checksums"]},
            )
            build_record = next(r for r in proof["records"] if r["kind"] == "build")
            aliases = collect_output_aliases(
                collected, artifacts[build_record["stdout"]], packages,
                {**context, 'host': capture['wrapper']['target']}, proof["consumer_manifest"], capture_dir,
            )
            capture["units"] = collected["units"]
            capture["receipts"] = {name: hashlib.sha256(data).hexdigest()
                                   for name, data in collected["raw"].items()}
            capture["aliases"] = aliases
            capture["build_stdout_sha256"] = build_record["stdout_sha256"]
            messages = [json.loads(line) for line in artifacts[build_record["stdout"]].splitlines() if line.strip()]
            self.assertEqual(len(aliases), expected_aliases)
            self.assertTrue(any(alias["direct"].endswith("libnative_graph_normal_consumer-abc.rlib")
                                for alias in aliases))
            custom_artifacts = [message for message in messages
                                if message.get("reason") == "compiler-artifact"
                                and message.get("target", {}).get("kind") == ["custom-build"]]
            self.assertTrue(custom_artifacts)
            self.assertTrue(all(message.get("executable") is None for message in custom_artifacts))
            for name, data in collected["raw"].items():
                proof["artifacts"][consumer.name + '/compiler-capture/' + name] = data
            build_record["compiler_capture"] = capture
            for path in ({output["path"] for unit in capture["units"] for output in unit["outputs"]}
                         | {record["alias"] for record in aliases}):
                Path(path).unlink(missing_ok=True)
            emitted, normalized = evidence.audit_units(
                proof, packages, {n["id"]: n for n in self._metadata(proof)[1].values()},
                stable_identity=lambda p: (p["name"], p["version"]),
                baseline_test_util_validator=None,
            )
            self.assertTrue(emitted)
            self.assertTrue(normalized)

            multi = [u for u in capture['units']
                     if u.get('package_name') == 'shaar' and u['args'].count('--crate-type') == 2]
            if multi:
                self.assertEqual(len(multi), 1)
                self.assertEqual(len(multi[0]['outputs']), 3)
                audited = [u for u in normalized if u.get('package') == ('shaar', '0.1.0')]
                self.assertEqual(len(audited), 1)
                self.assertEqual(audited[0]['crate_types'], ['cdylib', 'lib'])
                mapped, owners = audit_output_aliases(proof, packages, messages)
                index = next(i for i, m in enumerate(messages)
                             if m.get('target', {}).get('name') == 'shaar')
                self.assertEqual(owners[index], capture['units'].index(multi[0]))
                self.assertEqual(mapped[index], set(messages[index]['filenames']))
                self.assertLessEqual(mapped[index], {o['path'] for o in multi[0]['outputs']})

            mutations = (
                lambda p: p["compiler_capture"]["context"].update(recipe_sha256="0" * 64),
                lambda p: p["compiler_capture"]["units"][0]["args"].append("-Cextra-filename=-dead"),
                lambda p: p["artifacts"].update({consumer.name + '/compiler-capture/unit.json': b"{}"}),
            )
            for mutate in mutations:
                evidence.audit_units(proof, packages, self._metadata(proof)[1],
                    stable_identity=lambda p: (p["name"], p["version"]),
                    baseline_test_util_validator=None)
                candidate = copy.deepcopy(proof)
                mutate(candidate)
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    evidence.audit_units(candidate, packages, self._metadata(candidate)[1],
                        stable_identity=lambda p: (p["name"], p["version"]),
                        baseline_test_util_validator=None)

    def test_three_proof_alias_comparison(self):
        from test_features import _compare

        for mutation in ('hash', 'path', 'missing', 'duplicate', 'package', 'source',
                         'features', 'context', 'extra', 'ordinary-failure'):
            proofs = [self._root_alias(attach_capability(p)) for p in _proofs()]
            _compare(proofs)
            candidate = proofs[2]
            capture = candidate["compiler_capture"]
            alias = capture["aliases"][0]
            if mutation == 'hash':
                alias["sha256"] = "0" * 64
            elif mutation == 'path':
                alias["alias"] += ".forged"
            elif mutation == 'missing':
                capture["aliases"].pop(0)
            elif mutation == 'duplicate':
                capture["aliases"].append(copy.deepcopy(alias))
            else:
                raw_name = "unit.json" if mutation == 'ordinary-failure' else "root.json"
                prefix = Path(candidate["consumer_cwd"]).name + "/compiler-capture/"
                raw = json.loads(candidate["artifacts"][prefix + raw_name])
                unit = next(u for u in capture["units"] if all(
                    u.get(key) == value for key, value in raw.items() if key != "outputs"))
                if mutation == 'package':
                    raw["package_name"] = "foreign"
                elif mutation == 'source':
                    raw["args"][0] = "foreign.rs"
                elif mutation == 'features':
                    raw["args"].append('--cfg=feature="forged"')
                elif mutation == 'context':
                    raw["cwd"] = "foreign"
                elif mutation == 'extra':
                    raw["args"].append("-Cextra-filename=-def")
                else:
                    raw["exit_code"] = 1
                outputs = unit["outputs"]
                unit.clear()
                unit.update(raw)
                unit["outputs"] = outputs
                encoded = json.dumps(raw).encode()
                candidate["artifacts"][prefix + raw_name] = encoded
                capture["receipts"][raw_name] = hashlib.sha256(encoded).hexdigest()
            with self.assertRaises(features.AuditError):
                _compare(proofs)

    def test_windows_custom_build_pdb_alias_is_content_bound(self):
        from test_aliases import CargoAliasTests
        from cargo_aliases import cargo_output_aliases

        helper = CargoAliasTests()
        helper.setUp()
        self.addCleanup(helper.tearDown)
        helper.host = 'x86_64-pc-windows-msvc'
        (unit, artifact, package), _, direct_bytes, _ = helper.build_evidence()
        direct = Path(unit['outputs'][0]['path']).with_suffix('.pdb')
        alias = direct.parent / 'build_script_build.pdb'
        data = b'captured build-script PDB'
        direct.write_bytes(data)
        alias.write_bytes(data)
        unit['outputs'].append({'path': str(direct), 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'snapshot_path': 'raw/build.pdb'})
        artifact['filenames'].append(str(alias))
        pairs = cargo_output_aliases(unit, artifact, package, str(helper.target), helper.host, str(helper.manifest))
        self.assertEqual(pairs[-1], {'alias': str(alias), 'direct': str(direct)})
        collected = {'units': [unit], 'raw': {
            output['snapshot_path']: data if output['path'] == str(direct) else direct_bytes[output['path']]
            for output in unit['outputs']}}
        context = {'env': {'CARGO_TARGET_DIR': str(helper.target)}, 'host': helper.host}
        records = collect_output_aliases(collected, json.dumps(artifact), [package], context,
            str(helper.manifest), helper.root / 'capture')
        self.assertEqual(len(records), 2)
        proof = {'compiler_capture': {'units': [unit], 'aliases': records, 'context': context,
                 'wrapper': {'target': helper.host}}, 'consumer_manifest': str(helper.manifest),
                 'consumer_cwd': str(helper.root / 'consumer'), 'artifacts': {
                     'consumer/compiler-capture/' + name: blob for name, blob in collected['raw'].items()}}
        mapped, owners = audit_output_aliases(proof, [package], [artifact])
        self.assertEqual(mapped[0], {output['path'] for output in unit['outputs']})
        self.assertEqual(owners, {0: 0})
        alias.write_bytes(b'forged PDB')
        with self.assertRaisesRegex(ValueError, 'alias differs'):
            collect_output_aliases(collected, json.dumps(artifact), [package], context,
                str(helper.manifest), helper.root / 'capture-forged')

    def test_recorded_version_query_matrix_and_injection_guards(self):
        from test_features import _compare

        def with_query(args):
            proofs = _proofs()
            for proof in proofs:
                capture = proof['compiler_capture']
                prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
                raw = json.loads(proof['artifacts'][prefix + 'unit.json'])
                raw.update(kind='probe', args=list(args), outputs=[], snapshots=[], stdin=None,
                           cwd=proof['consumer_cwd'], package_name='', package_version='', manifest_dir='')
                encoded = json.dumps(raw).encode()
                proof['artifacts'][prefix + 'version.json'] = encoded
                capture['receipts']['version.json'] = hashlib.sha256(encoded).hexdigest()
                capture['units'].append(raw)
            return proofs

        for args in (['-vV'], ['-V'], ['--version'], ['--version', '--verbose']):
            with self.subTest(args=args):
                _compare(with_query(args))
        for args in (['--version', '--verbose', 'source.rs'],
                     ['--version', '--verbose', '--cfg=feature="test-util"'],
                     ['--version', '--verbose', '--unexpected']):
            with self.subTest(args=args), self.assertRaises(features.AuditError):
                _compare(with_query(args))

    def test_repeated_version_observations_keep_distinct_receipts(self):
        from test_features import _compare

        proofs = _proofs()
        for proof in proofs:
            capture = proof['compiler_capture']
            prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
            raw = json.loads(proof['artifacts'][prefix + 'unit.json'])
            raw.update(kind='probe', args=['-vV'], outputs=[], snapshots=[], stdin=None,
                       cwd=proof['consumer_cwd'], package_name='', package_version='', manifest_dir='')
            encoded = json.dumps(raw).encode()
            for index in range(4):
                name = f'version-{index}.json'
                proof['artifacts'][prefix + name] = encoded
                capture['receipts'][name] = hashlib.sha256(encoded).hexdigest()
                capture['units'].append(copy.deepcopy(raw))
        _compare(proofs)
        proof = proofs[2]
        capture = proof['compiler_capture']
        prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
        raw = json.loads(proof['artifacts'][prefix + 'version-3.json'])
        raw['compiler'] = 'foreign'
        encoded = json.dumps(raw).encode()
        proof['artifacts'][prefix + 'version-3.json'] = encoded
        capture['receipts']['version-3.json'] = hashlib.sha256(encoded).hexdigest()
        capture['units'][-1]['compiler'] = 'foreign'
        with self.assertRaises(features.AuditError):
            _compare(proofs)

    def test_three_proof_multi_type_guards(self):
        from test_features import _compare

        mutations = ('drop-type', 'duplicate-type', 'unknown-type', 'empty-type', 'missing-value',
                     'add-type', 'malformed-type', 'metadata-subset', 'artifact-subset', 'missing-owner', 'duplicate-unit',
                     'wrong-context')
        for mutation in mutations:
            proofs = [self._shaar_multi_crate(
                self._root_alias(attach_capability(p)),
                ('cdylib', 'lib') if index == 0 else ('lib', 'cdylib'))
                for index, p in enumerate(_proofs())]
            _compare(proofs)
            candidate = proofs[2]
            capture = candidate['compiler_capture']
            prefix = Path(candidate['consumer_cwd']).name + '/compiler-capture/'
            raw = json.loads(candidate['artifacts'][prefix + 'unit.json'])
            unit = next(u for u in capture['units'] if all(u.get(k) == v for k, v in raw.items() if k != 'outputs'))
            if mutation == 'drop-type':
                del raw['args'][raw['args'].index('--crate-type'):raw['args'].index('--crate-type') + 2]
            elif mutation == 'duplicate-type':
                raw['args'] += ['--crate-type', 'cdylib']
            elif mutation == 'unknown-type':
                raw['args'] += ['--crate-type', 'unknown']
            elif mutation == 'empty-type':
                raw['args'] += ['--crate-type', '']
            elif mutation == 'missing-value':
                raw['args'].append('--crate-type')
            elif mutation == 'add-type':
                raw['args'] += ['--crate-type', 'rlib']
            elif mutation == 'malformed-type':
                raw['args'].append('--crate-type=lib,cdylib')
            elif mutation == 'metadata-subset':
                self._refresh_multi(candidate, lambda row: row.update(crate_types=['lib']))
            elif mutation == 'artifact-subset':
                self._refresh_multi(candidate, lambda row: row.update(crate_types=['lib']), build=True)
            elif mutation == 'missing-owner':
                raw['outputs'] = raw['outputs'][:1]
                raw['snapshots'] = raw['snapshots'][:1]
                removed = unit['outputs'][1:]
                unit['outputs'] = unit['outputs'][:1]
                for output in removed:
                    capture['receipts'].pop(output['snapshot_path'], None)
                    candidate['artifacts'].pop(prefix + output['snapshot_path'], None)
            elif mutation == 'duplicate-unit':
                capture['units'].append(copy.deepcopy(unit))
            else:
                raw['cwd'] = 'foreign'
            if mutation not in ('metadata-subset', 'artifact-subset', 'duplicate-unit'):
                unit.update({k: v for k, v in raw.items() if k != 'outputs'})
                encoded = json.dumps(raw).encode()
                candidate['artifacts'][prefix + 'unit.json'] = encoded
                capture['receipts']['unit.json'] = hashlib.sha256(encoded).hexdigest()
            with self.assertRaises(features.AuditError):
                _compare(proofs)

    @staticmethod
    def _refresh_multi(proof, change, build=False):
        if build:
            record = next(r for r in proof['records'] if r['kind'] == 'build')
            rows = [json.loads(line) for line in proof['artifacts'][record['stdout']].splitlines() if line.strip()]
            artifact = next(m for m in rows if m.get('reason') == 'compiler-artifact' and m.get('target', {}).get('name') == 'shaar')
            change(artifact['target'])
            data = b'\n'.join(json.dumps(row).encode() for row in rows)
            proof['artifacts'][record['stdout']] = data
            record['stdout_sha256'] = hashlib.sha256(data).hexdigest()
            proof['compiler_capture']['build_stdout_sha256'] = record['stdout_sha256']
            return
        record = next(r for r in proof['records'] if r['kind'] == 'metadata')
        metadata = json.loads(proof['artifacts'][record['stdout']])
        package = next(p for p in metadata['packages'] if p['name'] == 'shaar')
        change(next(t for t in package['targets'] if t['name'] == 'shaar'))
        data = json.dumps(metadata).encode()
        proof['artifacts'][record['stdout']] = data
        record['stdout_sha256'] = hashlib.sha256(data).hexdigest()

    @staticmethod
    def _root_alias(proof):
        capture = proof["compiler_capture"]
        artifacts = proof["artifacts"]
        prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
        template = json.loads(artifacts[prefix + "unit.json"])
        metadata_record = next(r for r in proof["records"] if r["kind"] == "metadata")
        metadata = json.loads(artifacts[metadata_record["stdout"]])
        build_record = next(r for r in proof["records"] if r["kind"] == "build")
        messages = [json.loads(line) for line in artifacts[build_record["stdout"]].splitlines() if line.strip()]

        package = next(p for p in metadata["packages"] if p["name"] == "native-graph-normal-consumer")
        target_row = {"name": "native_graph_normal_consumer", "kind": ["lib"],
                      "crate_types": ["lib"], "src_path": str(Path(proof["consumer_cwd"]) / "src" / "lib.rs")}
        package["targets"] = [target_row]
        root = Path(proof["consumer_cwd"])
        source = root / "src" / "lib.rs"
        host = capture["wrapper"]["target"]
        target_dir = Path(capture["context"]["env"]["CARGO_TARGET_DIR"])
        deps = target_dir / host / "debug" / "deps"
        crate = "native_graph_normal_consumer"
        direct = [deps / f"lib{crate}-abc.rlib", deps / f"lib{crate}-abc.rmeta"]
        promoted = deps.parent / f"lib{crate}.rlib"
        marker = [b"root consumer promoted rlib fixture marker", b"root consumer direct rmeta fixture marker"]
        raw = copy.deepcopy(template)
        raw.update(package_name=package["name"], package_version=package["version"],
                   cwd=str(root), manifest_dir=str(root))
        raw["args"] = [str(source), "--crate-name", crate, "--crate-type", "lib",
                       "--emit=dep-info,metadata,link", "--out-dir", str(deps),
                       "--target", host, "-C", "extra-filename=-abc"]
        raw["outputs"] = [str(path) for path in direct]
        raw["snapshots"] = []
        outputs = []
        for index, (path, data) in enumerate(zip(direct, marker)):
            snapshot = f"root-outputs/{index}"
            digest = hashlib.sha256(data).hexdigest()
            raw["snapshots"].append({"output": str(path), "snapshot": str(Path(capture["context"]["env"]["SHAAR_CAPTURE_DIR"]) / snapshot)})
            artifacts[prefix + snapshot] = data
            capture["receipts"][snapshot] = digest
            outputs.append({"path": str(path), "size": len(data), "sha256": digest, "snapshot_path": snapshot})
        encoded = json.dumps(raw).encode()
        raw_name = "root.json"
        artifacts[prefix + raw_name] = encoded
        capture["receipts"][raw_name] = hashlib.sha256(encoded).hexdigest()
        capture["units"].append(dict(raw, outputs=outputs))
        unit_index = len(capture["units"]) - 1
        target_row.update(name=crate, kind=["lib"], crate_types=["lib"], src_path=str(source))
        artifact = {"reason": "compiler-artifact", "package_id": package["id"], "target": target_row,
                    "features": [], "filenames": [str(promoted), str(direct[1])], "executable": None,
                    "profile": {"test": False}, "fresh": False}
        artifact_index = len(messages)
        alias_name = f"cargo-aliases/{artifact_index}-0.bin"
        alias_data = marker[0]
        artifacts[prefix + alias_name] = alias_data
        capture["receipts"][alias_name] = hashlib.sha256(alias_data).hexdigest()
        capture.setdefault("aliases", []).append({"artifact_index": artifact_index, "unit_index": unit_index,
            "alias": str(promoted), "direct": str(direct[0]), "snapshot_path": alias_name,
            "size": len(alias_data), "sha256": hashlib.sha256(alias_data).hexdigest()})
        messages.append(artifact)
        for record, data in ((metadata_record, json.dumps(metadata).encode()),
                             (build_record, b"\n".join(json.dumps(m).encode() for m in messages))):
            artifacts[record["stdout"]] = data
            record["stdout_sha256"] = hashlib.sha256(data).hexdigest()
        capture["build_stdout_sha256"] = build_record["stdout_sha256"]
        return proof

    @staticmethod
    def _metadata(proof):
        record = next(r for r in proof["records"] if r["kind"] == "metadata")
        metadata = json.loads(proof["artifacts"][record["stdout"]])
        return metadata["packages"], {node["id"]: node for node in metadata["resolve"]["nodes"]}



if __name__ == "__main__":
    unittest.main()
