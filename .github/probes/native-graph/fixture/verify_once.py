# SPDX-License-Identifier: MIT OR Apache-2.0
"""Regression guard for one three-proof normal-feature comparison."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
NATIVE_GRAPH = HERE.parent
sys.path.insert(0, str(NATIVE_GRAPH))
import ci
class ActualCompilerCaptureMutationTests(unittest.TestCase):
    def test_baseline_actual_test_util_requires_reviewed_checksum(self):
        from test_features import _n0future_proofs, _compare
        from features import AuditError

        proofs = _n0future_proofs()
        append_tokio_unit(proofs[0])
        _compare(proofs)
        metadata = json.loads(next(
            proofs[0]['artifacts'][record['stdout']]
            for record in proofs[0]['records'] if record['kind'] == 'metadata'
        ))
        tokio_id = next(package['id'] for package in metadata['packages'] if package['name'] == 'tokio')
        proofs[0]['lock_checksums'][tokio_id] = '0' * 64
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_duplicate_unit_rejected_without_new_raw_receipt(self):
        from test_features import _proofs, _compare
        from features import AuditError
        import copy

        proofs = _proofs()
        proof = attach_unit_proof(proofs[2])
        capture = proof["compiler_capture"]
        capunits0 = capture["units"]
        capture["units"].append(copy.deepcopy(capunits0[0]))
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_unknown_package_unit_rejected_with_refreshed_raw_hashes(self):
        from test_features import _proofs, _compare
        from features import AuditError
        import hashlib

        proofs = _proofs()
        proof = attach_unit_proof(proofs[2])
        capture = proof["compiler_capture"]
        prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
        raw = json.loads(proof["artifacts"][prefix + "unit.json"])
        raw["package_name"] = "unknown-package"
        encoded = json.dumps(raw).encode()
        proof["artifacts"][prefix + "unit.json"] = encoded
        capture["receipts"]["unit.json"] = hashlib.sha256(encoded).hexdigest()
        capture["units"][0]["package_name"] = "unknown-package"
        with self.assertRaises(AuditError):
            _compare(proofs)

    @staticmethod
    def set_unit_features(proof, features):
        import hashlib

        capture = proof['compiler_capture']
        prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
        raw = json.loads(proof['artifacts'][prefix + 'unit.json'])
        raw['args'] += [value for feature in features for value in ('--cfg', 'feature=' + json.dumps(feature))]
        encoded = json.dumps(raw).encode()
        proof['artifacts'][prefix + 'unit.json'] = encoded
        capture['receipts']['unit.json'] = hashlib.sha256(encoded).hexdigest()
        capture['units'][0]['args'] = raw['args']
        build = next(r for r in proof['records'] if r['kind'] == 'build')
        rows = [json.loads(line) for line in proof['artifacts'][build['stdout']].splitlines()]
        rows[0]['features'] = features
        data = b''.join((json.dumps(row) + '\n').encode() for row in rows)
        proof['artifacts'][build['stdout']] = data
        build['stdout_sha256'] = hashlib.sha256(data).hexdigest()
        capture['build_stdout_sha256'] = build['stdout_sha256']

    def test_wrapper_command_mutations_rejected(self):
        from test_features import _proofs, _compare
        from features import AuditError
        import hashlib

        _compare(_proofs())
        mutations = ('wrapper-command', 'wrapper-log', 'build-env',
                     'test-compile-source', 'build-cwd', 'build-status', 'build-stderr', 'unknown-cargo', 'raw-schema')
        for mutation in mutations:
            proofs = _proofs()
            proof = proofs[2]
            capture = proof['compiler_capture']
            build = next(r for r in proof['records'] if r['kind'] == 'build')
            if mutation == 'wrapper-command':
                capture['wrapper']['records'][2]['argv'] = list(capture['wrapper']['records'][2]['argv'])
                capture['wrapper']['records'][2]['argv'][0] = 'forged'
            elif mutation == 'wrapper-log':
                proof['artifacts'][capture['wrapper']['records'][1]['stdout']] += b'forged'
            elif mutation == 'build-env':
                build['environment'] = dict(build['environment'], RUSTC='forged')
            elif mutation == 'test-compile-source':
                wrapper = capture['wrapper']
                wrapper['test_argv'][3] = 'forged'
                wrapper['records'][3]['argv'][3] = 'forged'
            elif mutation == 'build-cwd':
                build['cwd'] = 'forged'
            elif mutation == 'build-status':
                build['exit_code'] = 1
            elif mutation == 'build-stderr':
                build['stderr_sha256'] = '0' * 64
            elif mutation == 'unknown-cargo':
                data = proof['artifacts'][build['stdout']] + b'{"reason":"forged"}\n'
                proof['artifacts'][build['stdout']] = data
                build['stdout_sha256'] = hashlib.sha256(data).hexdigest()
                capture['build_stdout_sha256'] = build['stdout_sha256']
            elif mutation == 'raw-schema':
                prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
                raw = json.loads(proof['artifacts'][prefix + 'unit.json'])
                raw['schema'] = 2
                encoded = json.dumps(raw).encode()
                proof['artifacts'][prefix + 'unit.json'] = encoded
                capture['receipts']['unit.json'] = hashlib.sha256(encoded).hexdigest()
                capture['units'][0]['schema'] = 2
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _compare(proofs)

    def test_capture_mutations_rejected(self):
        from test_features import _proofs, _compare
        from features import AuditError
        import hashlib
        from verify_once import attach_unit_proof

        mutations = ("missing-capture", "artifact-features", "raw-snapshot-hash", "recipe-source")
        for mutation in mutations:
            proofs = _proofs()
            proof = attach_unit_proof(proofs[2])
            capture = proof["compiler_capture"]
            build = next(r for r in proof["records"] if r["kind"] == "build")
            if mutation == "missing-capture":
                proof.pop("compiler_capture")
                build.pop("compiler_capture")
            elif mutation == "artifact-features":
                data = json.loads(proof["artifacts"][build["stdout"]])
                data = {**data, "features": ["forged"]}
                encoded = json.dumps(data).encode()
                proof["artifacts"][build["stdout"]] = encoded
                build["stdout_sha256"] = hashlib.sha256(encoded).hexdigest()
                capture['build_stdout_sha256'] = build['stdout_sha256']
            elif mutation == "raw-snapshot-hash":
                capture["receipts"]["unit-outputs/0"] = "0" * 64
            else:
                proof["artifacts"]["compiler-wrapper/wrapper.rs"] += b"\n// changed"
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _compare(proofs)

    def test_proc_macro_host_owner_context(self):
        from test_features import _proofs, _compare
        from features import AuditError

        proofs = _proofs()
        for proof in proofs:
            add_dependency_unit(proof, proc_macro=True)
        _compare(proofs)
        proofs = _proofs()
        add_dependency_unit(proofs[0], proc_macro=True)
        for proof in proofs[1:]:
            add_dependency_unit(proof, proc_macro='target')
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_matching_accepted_role_test_util_is_rejected(self):
        from test_features import _proofs, _compare
        from features import AuditError

        proofs = _proofs()
        for proof in proofs[1:]:
            self.set_unit_features(proof, ['wire'])
        _compare(proofs)

        proofs = _proofs()
        for proof in proofs[1:]:
            self.set_unit_features(proof, ['test-util'])
        with self.assertRaises(AuditError):
            _compare(proofs)


def attach_capture_snapshot(receipt, capture_dir):
    capture_dir = Path(capture_dir)
    snapshot_dir = capture_dir / f"snapshots-{len(list(capture_dir.iterdir()))}"
    snapshot_dir.mkdir()
    receipt = dict(receipt)
    receipt["snapshots"] = []
    for index, output in enumerate(receipt.get("outputs", [])):
        snapshot = snapshot_dir / f"{index:04d}.bin"
        snapshot.write_bytes(Path(output).read_bytes())
        receipt["snapshots"].append({"output": output, "snapshot": str(snapshot)})
    return receipt


def make_capture_runner(repo, metadata, lock_bytes):
    def runner(argv, cwd, env=None):
        cwd = Path(cwd)
        if Path(argv[0]).name in ('capture-tests','capture-tests.exe'):
            return b'fixture forwarding tests',0
        compiler = (repo / "fixture-rustc").resolve()
        if argv == ["rustup", "which", "rustc"]:
            compiler.write_bytes(b"compiler fixture")
            return str(compiler).encode(), 0
        if argv == [str(compiler), "-vV"]:
            return b'release: 1.99.1\nhost: fixture-host\n', 0
        if argv[0] == str(compiler) and "-o" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"wrapper fixture")
            return b"", 0
        if argv[:2] == ["git", "rev-parse"]:
            return b"candidate\n", 0
        if "metadata" in argv:
            consumer = "--manifest-path" in argv
            consumer_root = Path(argv[argv.index("--manifest-path") + 1]).parent if consumer else None
            role = consumer_root.name.removesuffix("-consumer") if consumer else None
            source_root = repo if role == "candidate" else repo / "target/native-graph-evidence" / role if consumer else cwd
            data = json.dumps(metadata(source_root, consumer_root)).encode()
            if not consumer and "--locked" not in argv:
                (cwd / "projected.lock").write_bytes(lock_bytes())
            if consumer and "--locked" not in argv:
                projected = lock_bytes().replace(b'dependencies = ["route", "tracing"]', b'dependencies = ["route"]', 1) + b'\n[[package]]\nname = "native-graph-normal-consumer"\nversion = "0.0.0"\ndependencies = ["shaar"]\n'
                (cwd / "Cargo.lock").write_bytes(projected)
            return data, 0
        if "tree" in argv:
            return "native-graph-normal-consumer\n\u2514\u2500\u2500 shaar\n".encode(), 0
        if "build" in argv:
            target_dir = Path(env["CARGO_TARGET_DIR"])
            capture_dir = Path(env["SHAAR_CAPTURE_DIR"])
            output = target_dir / "demo.rlib"
            output.write_bytes(b"compiler output fixture")
            receipt = {
                "schema": 1, "role": env["SHAAR_CAPTURE_ROLE"],
                "revision": env["SHAAR_CAPTURE_REVISION"], "nonce": env["SHAAR_CAPTURE_NONCE"],
                "recipe_sha256": env["SHAAR_CAPTURE_RECIPE_SHA256"],
                "compiler": str(compiler),
                "env": {key: env[key] for key in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR")},
                "kind": "compile", "args": ["--crate-name", "demo", "--out-dir", str(target_dir)],
                "cwd": str(cwd), "package_name": "demo", "package_version": "1",
                "manifest_dir": str(cwd), "exit_code": 0, "launch_error": None,
                "outputs": [str(output)],
            }
            receipt = attach_capture_snapshot(receipt, capture_dir)
            (capture_dir / "compile.json").write_text(json.dumps(receipt), encoding="utf-8")
            return (json.dumps({"reason": "compiler-artifact", "package_id": "shaar", "profile": {"test": False}, "target": {"kind": ["lib"]}, "features": []}) + "\n").encode(), 0
        raise AssertionError(argv)

    return runner


def attach_unit_proof(proof):
    import hashlib

    def sha(data):
        return hashlib.sha256(data).hexdigest()

    artifacts = proof["artifacts"]
    meta_record = next(r for r in proof["records"] if r["kind"] == "metadata")
    metadata = json.loads(artifacts[meta_record["stdout"]])
    package = next(p for p in metadata["packages"] if p["name"] == "shaar")
    cwd = Path(proof["consumer_cwd"])
    target = "fixture-host"
    source_path = str(Path(package["manifest_path"]).parent / "src/lib.rs")
    row = {"name": "shaar", "kind": ["lib"], "crate_types": ["lib"], "src_path": source_path}
    package["targets"] = [row]
    raw_meta = json.dumps(metadata).encode()
    artifacts[meta_record["stdout"]] = raw_meta
    meta_record["stdout_sha256"] = sha(raw_meta)
    root = Path(proof["consumer_cwd"]).parent
    compiler = str(root / "rustc")
    wrapper_root = root / "target/native-graph-evidence/compiler-wrapper"
    wrapper_path = str(wrapper_root / "wrapper")
    recipe_path = str(wrapper_root / "wrapper.rs")
    source = ci.evidence.native_wrapper_source().encode()
    version = "release: 1.99.1\nhost: fixture-host\n"
    recipe = [compiler, "--edition=2024", "-Copt-level=0", recipe_path, "-o", wrapper_path]
    compiler_sha = "a" * 64
    recipe_sha = sha(json.dumps({"argv": recipe, "source_sha256": sha(source), "compiler_sha256": compiler_sha, "version": version}, sort_keys=True, separators=(",", ":")).encode())
    env = ci.evidence.capture_environment(wrapper_path, cwd / "compiler-target", cwd / "compiler-capture", role=proof["role"], revision=proof["revision"], recipe_sha256=recipe_sha, nonce="fixture-nonce")
    env["RUSTC"] = compiler
    out_dir = Path(env["CARGO_TARGET_DIR"]) / target / "debug/deps"
    output = str(out_dir / "libshaar-fixture.rlib")
    snapshot = str(Path(env["SHAAR_CAPTURE_DIR"]) / "unit-outputs/0")
    data = b"fixture compiled shaar"
    receipt = {"schema": 1, "role": proof["role"], "revision": proof["revision"], "nonce": "fixture-nonce", "recipe_sha256": recipe_sha, "compiler": compiler, "env": {k: env[k] for k in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR")}, "kind": "compile", "args": [source_path, "--crate-name", "shaar", "--crate-type", "lib", "--out-dir", str(out_dir), "--target", target], "cwd": str(Path(package["manifest_path"]).parent), "package_name": "shaar", "package_version": package["version"], "manifest_dir": str(Path(package["manifest_path"]).parent), "exit_code": 0, "launch_error": None, "outputs": [output], "snapshots": [{"output": output, "snapshot": snapshot}]}
    raw = json.dumps(receipt).encode()
    unit = dict(receipt, outputs=[{"path": output, "size": len(data), "sha256": sha(data), "snapshot_path": "unit-outputs/0"}])
    wrapper = {"compiler": compiler, "target": target, "wrapper": wrapper_path, "source_path": recipe_path, "version": version, "recipe": recipe, "recipe_sha256": recipe_sha, "compiler_sha256": compiler_sha, "source_sha256": sha(source), "wrapper_sha256": "b" * 64}
    build = next(r for r in proof["records"] if r["kind"] == "build")
    build["argv"] = ["cargo", "build", "--locked", "--lib", "--message-format=json", "--target", target, "--manifest-path", proof["consumer_manifest"]]
    build_data = (json.dumps({"reason": "compiler-artifact", "package_id": package["id"], "target": row, "features": [], "filenames": [output], "profile": {"test": False}, "fresh": False}) + "\n").encode()
    artifacts[build["stdout"]] = build_data
    build["stdout_sha256"] = sha(build_data)
    build["environment"] = env
    capture = {"context": {"role": proof["role"], "revision": proof["revision"], "nonce": "fixture-nonce", "recipe_sha256": recipe_sha, "compiler": compiler, "env": env}, "wrapper": wrapper, "units": [unit], "receipts": {"unit.json": sha(raw), "unit-outputs/0": sha(data)}, "build_stdout_sha256": sha(build_data)}
    build["compiler_capture"] = capture
    proof["compiler_capture"] = capture
    artifacts[cwd.name + "/compiler-capture/unit.json"] = raw
    artifacts[cwd.name + "/compiler-capture/unit-outputs/0"] = data
    artifacts["compiler-wrapper/wrapper.rs"] = source
    # The unit fixture has no compiler-wrapper execution; attach deterministic
    # command receipts matching the validator's five-command schema.
    test_argv = [compiler, "--edition=2024", "--test", recipe_path, "-o", str(Path(wrapper_path).parent / "capture-tests")]
    wrapper["test_argv"] = test_argv
    wrapper["records"] = []
    commands = [["rustup", "which", "rustc"], [compiler, "-vV"], wrapper["recipe"], test_argv, [test_argv[-1], "--test-threads=1"]]
    outputs = [compiler.encode() + b"\n", version.encode(), b"", b"", b""]
    for index, (argv, stdout) in enumerate(zip(commands, outputs)):
        stderr = b""
        record = {"argv": argv, "cwd": str(root), "exit_code": 0,
                  "stdout": f"wrapper-fixture/{index}.stdout", "stderr": f"wrapper-fixture/{index}.stderr",
                  "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
        artifacts[record["stdout"]] = stdout
        artifacts[record["stderr"]] = stderr
        wrapper["records"].append(record)
    build["compiler_capture"]["wrapper"] = wrapper
    proof["compiler_capture"]["wrapper"] = wrapper
    return proof


def add_dependency_unit(proof, proc_macro=False):
    """Attach a captured registry iroh-base unit and link shaar to it."""
    import hashlib

    sha = lambda data: hashlib.sha256(data).hexdigest()
    capture = proof["compiler_capture"]
    prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
    artifacts = proof["artifacts"]
    raw = json.loads(artifacts[prefix + "unit.json"])
    metadata_record = next(r for r in proof["records"] if r["kind"] == "metadata")
    metadata = json.loads(artifacts[metadata_record["stdout"]])
    package = next(p for p in metadata["packages"] if p["name"] == "iroh-base")
    base_id = package["id"]
    package["manifest_path"] = "/registry/iroh-base/Cargo.toml"
    package["targets"] = [{"name": "iroh_base", "kind": ["lib"], "crate_types": ["lib"],
                           "src_path": "/registry/iroh-base/src/lib.rs"}]
    shaar = next(p for p in metadata["packages"] if p["name"] == "shaar")
    shaar.setdefault("dependencies", []).append({"name": "iroh-base", "rename": "iroh_base",
        "req": "^1.3.0", "kind": None, "target": None, "features": [], "source": shaar.get("source")})
    shaar_node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == shaar["id"])
    shaar_node["deps"].append({"name": "iroh_base", "pkg": base_id,
                                "dep_kinds": [{"kind": "normal", "target": None}]})
    if proc_macro:
        package["targets"][0]["kind"] = ["proc-macro"]
        package["targets"][0]["crate_types"] = ["proc-macro"]
    metadata_record_data = json.dumps(metadata).encode()
    artifacts[metadata_record["stdout"]] = metadata_record_data
    metadata_record["stdout_sha256"] = sha(metadata_record_data)

    args = list(raw["args"])
    args[0] = package["targets"][0]["src_path"]
    args[args.index("--crate-name") + 1] = "iroh_base"
    args[args.index("--out-dir") + 1] = str(Path(raw["outputs"][0]).parent)
    output = str(Path(raw["outputs"][0]).parent / "libiroh_base-dep.rlib")
    if proc_macro:
        args[args.index("--crate-type") + 1] = "proc-macro"
    if proc_macro is True:
        index = args.index("--target")
        del args[index:index + 2]
        host_dir = Path(capture["context"]["env"]["CARGO_TARGET_DIR"]) / "debug/deps"
        args[args.index("--out-dir") + 1] = str(host_dir)
        output = str(host_dir / "iroh_base-proc.dll")
    raw.update(args=args, outputs=[output], package_name="iroh-base", package_version=package["version"],
               manifest_dir="/registry/iroh-base", cwd="/registry/iroh-base")
    snapshot = "dependency-outputs/0"
    data = b""
    raw["snapshots"] = [{"output": output, "snapshot": str(Path(capture["context"]["env"]["SHAAR_CAPTURE_DIR"]) / snapshot)}]
    encoded = json.dumps(raw).encode()
    unit = dict(raw, outputs=[{"path": output, "size": 0, "sha256": sha(data), "snapshot_path": snapshot}])
    capture["units"].append(unit)
    capture["receipts"]["dependency-unit.json"] = sha(encoded)
    capture["receipts"][snapshot] = sha(data)
    artifacts[prefix + "dependency-unit.json"] = encoded
    artifacts[prefix + snapshot] = data

    original_raw = json.loads(artifacts[prefix + "unit.json"])
    original_raw["args"] += ["--extern", "iroh_base=" + output]
    original_encoded = json.dumps(original_raw).encode()
    artifacts[prefix + "unit.json"] = original_encoded
    capture["receipts"]["unit.json"] = sha(original_encoded)
    capture["units"][0]["args"] = original_raw["args"]
    build = next(r for r in proof["records"] if r["kind"] == "build")
    messages = [json.loads(line) for line in artifacts[build["stdout"]].splitlines()]
    messages.append(dict(messages[0], package_id=base_id,
                         target=package["targets"][0], features=[], filenames=[output]))
    build_data = b"".join((json.dumps(item) + "\n").encode() for item in messages)
    artifacts[build["stdout"]] = build_data
    build["stdout_sha256"] = sha(build_data)
    capture["build_stdout_sha256"] = sha(build_data)
    return proof


def append_tokio_unit(proof):
    """Attach a captured Tokio unit with the baseline-only test-util feature."""
    import hashlib
    sha = lambda data: hashlib.sha256(data).hexdigest()
    capture = proof["compiler_capture"]
    prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
    raw = json.loads(json.dumps(json.loads(proof["artifacts"][prefix + "unit.json"])))
    metadata_record = next(r for r in proof["records"] if r["kind"] == "metadata")
    metadata = json.loads(proof["artifacts"][metadata_record["stdout"]])
    package = next(p for p in metadata["packages"] if p["name"] == "tokio")
    package.update(manifest_path="/registry/tokio/Cargo.toml", targets=[
        {"name": "tokio", "kind": ["lib"], "crate_types": ["lib"], "src_path": "/registry/tokio/src/lib.rs"}])
    proof["lock_checksums"][package["id"]] = "b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3"
    data = json.dumps(metadata).encode()
    proof["artifacts"][metadata_record["stdout"]] = data
    metadata_record["stdout_sha256"] = sha(data)
    raw['args'][0] = '/registry/tokio/src/lib.rs'
    raw["args"][raw["args"].index("--crate-name") + 1] = "tokio"
    features = ["rt", "time", "macros", "test-util"]
    raw["args"] += [value for feature in features for value in ("--cfg", "feature=" + json.dumps(feature))]
    out_dir = str(Path(capture["context"]["env"]["CARGO_TARGET_DIR"]) / "fixture-host/debug/deps")
    raw["args"][raw["args"].index("--out-dir") + 1] = out_dir
    output = str(Path(out_dir) / "libtokio-unit.rlib")
    raw.update(outputs=[output], snapshots=[{"output": output,"snapshot":str(Path(capture["context"]["env"]["SHAAR_CAPTURE_DIR"])/"tokio-outputs/0")}],package_name="tokio",package_version="1.54.1",manifest_dir="/registry/tokio",cwd="/registry/tokio")
    snapshot = b"fixture compiled tokio unit"
    encoded = json.dumps(raw).encode()
    capture["units"].append(dict(raw, outputs=[{"path": output, "size": len(snapshot), "sha256": sha(snapshot), "snapshot_path": "tokio-outputs/0"}]))
    capture["receipts"]["tokio-unit.json"] = sha(encoded)
    capture["receipts"]["tokio-outputs/0"] = sha(snapshot)
    proof["artifacts"][prefix + "tokio-unit.json"] = encoded
    proof["artifacts"][prefix + "tokio-outputs/0"] = snapshot
    build = next(r for r in proof["records"] if r["kind"] == "build")
    rows = [json.loads(line) for line in proof["artifacts"][build["stdout"]].splitlines()]
    rows.append(dict(rows[0], package_id=package["id"], target=package["targets"][0], features=features, filenames=[output]))
    build_data = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    proof["artifacts"][build["stdout"]] = build_data
    build["stdout_sha256"] = sha(build_data)
    capture["build_stdout_sha256"] = build["stdout_sha256"]
    return proof


def add_host_unit(proof):
    import hashlib
    sha = lambda data: hashlib.sha256(data).hexdigest()
    capture = proof["compiler_capture"]
    prefix = Path(proof["consumer_cwd"]).name + "/compiler-capture/"
    raw = json.loads(proof["artifacts"][prefix + "unit.json"])
    raw = json.loads(json.dumps(raw))
    args = raw["args"]
    target_index = args.index("--target")
    del args[target_index:target_index + 2]
    out_dir = str(Path(capture["context"]["env"]["CARGO_TARGET_DIR"]) / "debug/deps")
    args[args.index("--out-dir") + 1] = out_dir
    args += ["--cfg", 'feature="std"']
    output = str(Path(out_dir) / "libshaar-host.rlib")
    snapshot_name = "host-outputs/0"
    snapshot_path = str(Path(capture["context"]["env"]["SHAAR_CAPTURE_DIR"]) / snapshot_name)
    raw["outputs"] = [output]
    raw["snapshots"] = [{"output": output, "snapshot": snapshot_path}]
    data = b"fixture host shaar"
    encoded = json.dumps(raw).encode()
    unit = dict(raw, outputs=[{"path": output, "size": len(data), "sha256": sha(data), "snapshot_path": snapshot_name}])
    capture["units"].append(unit)
    capture["receipts"]["host.json"] = sha(encoded)
    capture["receipts"][snapshot_name] = sha(data)
    proof["artifacts"][prefix + "host.json"] = encoded
    proof["artifacts"][prefix + snapshot_name] = data
    build = next(r for r in proof["records"] if r["kind"] == "build")
    rows = [json.loads(line) for line in proof["artifacts"][build["stdout"]].splitlines()]
    rows.append(dict(rows[0], features=["std"], filenames=[output]))
    build_data = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    proof["artifacts"][build["stdout"]] = build_data
    build["stdout_sha256"] = sha(build_data)
    capture["build_stdout_sha256"] = sha(build_data)
    return proof


class CaptureCollectorTests(unittest.TestCase):
    def test_native_wrapper_source_contract(self):
        source = ci.evidence.native_wrapper_source()
        self.assertGreater(source.count('.status()'), 1)
        self.assertIn('#![forbid(unsafe_code)]', source)
        self.assertIn('env::args_os()', source)
        self.assertIn('.args(args_os)', source)

    def test_capture_environment_resets_wrapper_keys(self):
        from evidence import capture_environment
        wrapper = Path('/tmp/wrapper').resolve()
        target = Path('/tmp/target').resolve()
        env = capture_environment(wrapper, target, '/tmp/capture',
                                  role='candidate', revision='rev', recipe_sha256='a' * 64, nonce='n')
        self.assertEqual(env['RUSTC_WRAPPER'], str(wrapper))
        self.assertEqual(env['RUSTC_WORKSPACE_WRAPPER'], '')
        self.assertEqual(env['CARGO_TARGET_DIR'], str(target))

    def test_actual_receipts_are_collected_and_hashed(self):
        from features import collect_capture
        with __import__('tempfile').TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            capture = root / 'capture'
            target = root / 'target'
            capture.mkdir()
            target.mkdir()
            output_dir = target / 'debug'
            output_dir.mkdir()
            output = output_dir / 'demo.rlib'
            output.write_bytes(b'compiled')
            env = {'RUSTC_WRAPPER': '/wrapper', 'RUSTC_WORKSPACE_WRAPPER': '', 'CARGO_TARGET_DIR': str(target)}
            receipt = {'schema': 1, 'role': 'candidate', 'revision': 'rev', 'nonce': 'n', 'recipe_sha256': 'a' * 64, 'compiler': '/rustc', 'env': env, 'kind': 'compile', 'args': ['--crate-name', 'demo', '--out-dir', str(output_dir)], 'cwd': str(root), 'package_name': 'demo', 'package_version': '1', 'manifest_dir': str(root), 'exit_code': 0, 'launch_error': None, 'outputs': [str(output)]}
            receipt = attach_capture_snapshot(receipt, capture)
            (capture / 'compile.json').write_text(json.dumps(receipt), encoding='utf-8')
            context = {**{key: receipt[key] for key in ('role', 'revision', 'nonce', 'recipe_sha256', 'compiler')}, 'env': env}
            result = collect_capture(capture, target, context)
            self.assertEqual(result['units'][0]['outputs'][0]['sha256'], __import__('hashlib').sha256(b'compiled').hexdigest())
            second_output = output_dir / 'second.rlib'
            second_output.write_bytes(b'second compiled')
            second = dict(receipt, outputs=[str(second_output)])
            second = attach_capture_snapshot(second, capture)
            second_path = capture / 'second.json'
            second_path.write_text(json.dumps(second), encoding='utf-8')
            result = collect_capture(capture, target, context)
            self.assertEqual(len(result['units']), 2)
            second['snapshots'][0]['snapshot'] = receipt['snapshots'][0]['snapshot']
            second_path.write_text(json.dumps(second), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'duplicate snapshot'):
                collect_capture(capture, target, context)

    def test_probe_only_receipt_without_compile_is_rejected(self):
        from features import collect_capture
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            capture = root / 'capture'
            target = root / 'target'
            capture.mkdir()
            target.mkdir()
            env = {'RUSTC_WRAPPER': '/wrapper', 'RUSTC_WORKSPACE_WRAPPER': '', 'CARGO_TARGET_DIR': str(target)}
            receipt = {'schema': 1, 'role': 'candidate', 'revision': 'rev', 'nonce': 'n',
                       'recipe_sha256': 'a' * 64, 'compiler': '/rustc', 'env': env,
                       'kind': 'probe', 'args': ['/rustc', '-vV'], 'cwd': str(root),
                       'exit_code': 0, 'launch_error': None, 'outputs': [], 'snapshots': []}
            (capture / 'probe.json').write_text(json.dumps(receipt), encoding='utf-8')
            context = {**{key: receipt[key] for key in ('role', 'revision', 'nonce', 'recipe_sha256', 'compiler')}, 'env': env}
            with self.assertRaisesRegex(ValueError, 'compile'):
                collect_capture(capture, target, context)

    def test_capture_inventory_io_error(self):
        from evidence import capture_inventory
        with mock.patch.object(Path, 'rglob', side_effect=OSError('unreadable')):
            result = capture_inventory(Path('/missing'))
        self.assertEqual(result, [{'error': 'unreadable'}])


class VerifyOnceTests(unittest.TestCase):
    def test_ci_uploads_compiler_capture_evidence_not_targets(self):
        workflow = (HERE.parents[3] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        lines = workflow.splitlines()
        upload_blocks = []
        for index, line in enumerate(lines):
            if "actions/upload-artifact@" not in line:
                continue
            block = []
            for candidate in lines[index:index + 16]:
                if block and candidate.startswith("      - "):
                    break
                block.append(candidate)
            upload_blocks.append("\\n".join(block))
        native_evidence = [block for block in upload_blocks if "native-graph-evidence" in block]
        self.assertTrue(native_evidence, "CI must upload native-graph-evidence")
        evidence = "\\n".join(native_evidence)
        self.assertIn("compiler-capture/", evidence)
        self.assertIn("compiler-wrapper/wrapper.rs", evidence)
        self.assertNotIn("compiler-target/", evidence)
        self.assertNotIn("compiler-wrapper/\\n", evidence)

    def test_verifier_materializes_one_three_proof_comparison(self):
        original_run = ci.subprocess.run
        calls = []

        def record_and_run(argv, *args, **kwargs):
            calls.append((list(argv), Path(kwargs.get("cwd", ci.ROOT)).resolve()))
            return original_run(argv, *args, **kwargs)

        with mock.patch.object(ci.subprocess, "run", side_effect=record_and_run), \
                mock.patch.object(ci, "resolve_candidate",
                                  side_effect=AssertionError(
                                      "candidate resolution must not run during verification")):
            receipt = ci.verify_locked()

        self.assertIs(receipt.get("accepted"), True, "locked verifier must accept")
        future_dev = receipt["future_dev"]
        self.assertIs(future_dev["source_inventory_unchanged"], True,
                      "future-dev verification must preserve the source inventory")
        future_calls = [(argv, cwd) for argv, cwd in calls
                        if argv and argv[0] == "cargo" and
                        "--manifest-path" in argv and
                        "future-dev" in str(cwd).lower()]
        metadata_calls = [argv for argv, _ in future_calls if argv[1:2] == ["metadata"]]
        lib_calls = [argv for argv, _ in future_calls if argv[1:2] == ["test"] and "--lib" in argv]
        doc_calls = [argv for argv, _ in future_calls if argv[1:2] == ["test"] and "--doc" in argv]
        self.assertEqual(len(metadata_calls), 1, "future-dev metadata must execute exactly once")
        self.assertEqual(len(lib_calls), 1, "future-dev library tests must execute exactly once")
        self.assertEqual(len(doc_calls), 1, "future-dev doc tests must execute exactly once")
        self.assertTrue(all("--locked" in argv for argv in metadata_calls + lib_calls + doc_calls),
                        "future-dev commands must use the lockfile")
        on_disk = json.loads(ci.RECEIPT.read_text(encoding="utf-8"))
        self.assertEqual(receipt["normal_feature_comparison"], on_disk["normal_feature_comparison"],
                         "returned and persisted comparison receipts must match")

        base_revision = ci.evidence.base.BASE
        archives = [argv for argv, _ in calls
                    if argv[:3] == ["git", "archive", "--format=tar"] and argv[3:] == [base_revision]]
        self.assertEqual(len(archives), 2, "comparison must materialize baseline and approved-route once")
        revisions = [argv for argv, _ in calls if argv == ["git", "rev-parse", base_revision]]
        self.assertEqual(len(revisions), 2, "comparison must resolve the base once per materialization")

        evidence_path = Path(receipt["normal_feature_comparison"]["evidence"])
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        roles = [proof.get("role") for proof in evidence.get("proofs", [])]
        self.assertCountEqual(roles, ["baseline", "approved_route", "candidate"],
                              "comparison must contain exactly the three proof roles")
        self.assertEqual(len(roles), 3, "proof roles must be unique")
        for proof in evidence["proofs"]:
            for kind in ("metadata", "tree", "build"):
                with self.subTest(role=proof["role"], kind=kind):
                    records = [record for record in proof["records"] if record.get("kind") == kind]
                    self.assertEqual(len(records), 1, "each proof needs exactly one recorded command per kind")
                    record = records[0]
                    self.assertEqual(record["exit_code"], 0)
                    self.assertEqual(Path(record["cwd"]).resolve(), Path(proof["consumer_cwd"]).resolve())
                    self.assertIn("--manifest-path", record["argv"])
                    self.assertEqual(str(Path(proof["consumer_manifest"]).resolve()),
                                     str(Path(record["argv"][record["argv"].index("--manifest-path") + 1]).resolve()))
                    for stream in ("stdout", "stderr"):
                        data = (evidence_path.parent / record[stream]).read_bytes()
                        import hashlib
                        self.assertEqual(hashlib.sha256(data).hexdigest(), record[stream + "_sha256"])


class PrepareCaptureWrapperTests(unittest.TestCase):
    def test_wrapper_recipe_and_validation(self):
        import hashlib
        import tempfile
        from evidence import prepare_capture_wrapper

        def exercise(mode="ok"):
            with tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary)
                (repo / "out").mkdir()
                compiler = repo / "rustc"
                compiler.write_bytes(b"fake compiler")
                calls = []

                def fakecommand(argv, cwd, label, env=None):
                    calls.append((list(argv), Path(cwd), label, env))
                    if label == "wrapper-compiler-path":
                        return str(compiler).encode()
                    if label == "wrapper-compiler-version":
                        return (b"release: wrong\nhost: test\n" if mode == "badrelease" else b"release: 1.99.1\nhost: test-host\n")
                    if label in ("wrapper-compile", "wrapper-transport-test-compile"):
                        Path(argv[argv.index("-o") + 1]).write_bytes(b"wrapper bytes")
                        return b""
                    if label == "wrapper-transport-tests":
                        if mode == "transport":
                            raise RuntimeError("transport failed")
                        return b""
                    raise AssertionError(label)

                if mode == "transport":
                    with self.assertRaisesRegex(RuntimeError, "transport failed"):
                        prepare_capture_wrapper(repo, repo / "out", fakecommand)
                    return
                if mode == "badrelease":
                    with self.assertRaises(ValueError):
                        prepare_capture_wrapper(repo, repo / "out", fakecommand)
                    return
                if mode == "missing":
                    def missing(argv, cwd, label, env=None):
                        if label == "wrapper-transport-test-compile":
                            calls.append((list(argv), Path(cwd), label, env))
                            return b""
                        return fakecommand(argv, cwd, label, env)
                    with self.assertRaises(ValueError):
                        prepare_capture_wrapper(repo, repo / "out", missing)
                    return
                receipt = prepare_capture_wrapper(repo, repo / "out", fakecommand)
                self.assertEqual(len(calls), 5)
                self.assertEqual(receipt["recipe"], calls[2][0])
                source = (repo / "out/compiler-wrapper/wrapper.rs").read_bytes()
                self.assertEqual(receipt["source_sha256"], hashlib.sha256(source).hexdigest())
                self.assertEqual(receipt["compiler_sha256"], hashlib.sha256(b"fake compiler").hexdigest())
                transport_call = next(call for call in calls if call[2] == "wrapper-transport-tests")
                self.assertEqual(transport_call[3], {"SHAAR_TRANSPORT_PYTHON": sys.executable,
                                                     "SHAAR_TRANSPORT_RUSTC": str(compiler.resolve()),
                                                     "SHAAR_TRANSPORT_HOST": "test-host"})

        for mode in ("ok", "badrelease", "missing", "transport"):
            with self.subTest(mode=mode):
                exercise(mode)

if __name__ == "__main__":
    unittest.main()
