# SPDX-License-Identifier: MIT OR Apache-2.0
"""Materialize isolated normal-consumer Cargo graph evidence for CI."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tomllib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import baseline as base
import features
import uuid
import graph as graph_module
import prepare
import stdin_probes
from cargo_aliases import audit_output_aliases, crate_types, target_crate_types

collect_capture = features.collect_capture


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture_environment(wrapper, target_dir, capture_dir, *, role, revision, recipe_sha256, nonce):
    return {
        "RUSTC_WRAPPER": str(Path(wrapper).resolve()),
        "RUSTC_WORKSPACE_WRAPPER": "",
        "CARGO_TARGET_DIR": str(Path(target_dir).resolve()),
        "SHAAR_CAPTURE_DIR": str(Path(capture_dir).resolve()),
        "SHAAR_CAPTURE_ROLE": role,
        "SHAAR_CAPTURE_REVISION": revision,
        "SHAAR_CAPTURE_RECIPE_SHA256": recipe_sha256,
        "SHAAR_CAPTURE_NONCE": nonce,
    }


capture_inventory = base.capture_inventory


native_wrapper_source = base.native_wrapper_source


def prepare_capture_wrapper(repo, out, runner):
    repo, out = Path(repo).resolve(), Path(out).resolve()
    directory = out / "compiler-wrapper"
    directory.mkdir()
    source_path = directory / "wrapper.rs"
    source = base.native_wrapper_source().encode("utf-8")
    source_path.write_bytes(source)
    compiler = Path(runner(["rustup", "which", "rustc"], cwd=repo, label="wrapper-compiler-path").decode("utf-8").strip())
    if not compiler.is_absolute() or not compiler.is_file() or not compiler.stat().st_mode:
        raise ValueError(f"invalid rustc path: {compiler}")
    compiler = compiler.resolve()
    version = runner([str(compiler), "-vV"], cwd=repo, label="wrapper-compiler-version").decode("utf-8")
    fields = dict(line.split(': ', 1) for line in version.splitlines() if ': ' in line)
    if fields.get('release') != '1.99.1' or not fields.get('host'):
        raise ValueError(f"unexpected pinned rustc version: {version!r}")
    wrapper = directory / ("capture-wrapper.exe" if os.name == "nt" else "capture-wrapper")
    test_exe = directory / ("capture-tests.exe" if os.name == "nt" else "capture-tests")
    argv = [str(compiler), "--edition=2024", "-Copt-level=0", str(source_path), "-o", str(wrapper)]
    runner(argv, cwd=repo, label="wrapper-compile")
    test_argv = [str(compiler), "--edition=2024", "--test", str(source_path), "-o", str(test_exe)]
    runner(test_argv, cwd=repo, label="wrapper-transport-test-compile")
    if wrapper.is_symlink() or test_exe.is_symlink() or not wrapper.is_file() or not test_exe.is_file():
        raise ValueError("wrapper or transport test executable missing or linked")
    runner([str(test_exe), "--test-threads=1"], cwd=repo, label="wrapper-transport-tests",
           env={"SHAAR_TRANSPORT_PYTHON": sys.executable,
                "SHAAR_TRANSPORT_RUSTC": str(compiler),
                "SHAAR_TRANSPORT_HOST": fields['host']})
    compiler_bytes = compiler.read_bytes()
    compiler_sha256, source_sha256 = _sha(compiler_bytes), _sha(source)
    wrapper_sha256, test_sha256 = _sha(wrapper.read_bytes()), _sha(test_exe.read_bytes())
    recipe = {"argv": argv, "source_sha256": source_sha256, "compiler_sha256": compiler_sha256, "version": version}
    recipe_sha256 = _sha(json.dumps(recipe, sort_keys=True, separators=(",", ":")).encode())
    return {"compiler": str(compiler), "target": fields['host'],
            "wrapper": str(wrapper), "source_path": str(source_path), "version": version,
            "recipe": argv, "recipe_sha256": recipe_sha256, "compiler_sha256": compiler_sha256,
            "source_sha256": source_sha256, "wrapper_sha256": wrapper_sha256,
            "transport_test_sha256": test_sha256, "test_argv": test_argv}


def _tree(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise ValueError('source inventory root missing or linked: '+str(root))
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in source tree: " + str(path))
        if path.is_file():
            files[path.relative_to(root).as_posix()] = _sha(path.read_bytes())
    return _sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def _binding(root, path, pkg, base_archive):
    raw_root = Path(root)
    raw_path = Path(path)
    if raw_root.is_symlink() or raw_path.is_symlink():
        raise ValueError(f"linked root or package path: {raw_root} -> {raw_path}")
    root = raw_root.resolve()
    path = raw_path.resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"package path escapes evidence root: {path} (root {root})")
    manifest = path / "Cargo.toml"
    if manifest.is_symlink():
        raise ValueError(f"linked package manifest: {manifest}")
    name = pkg["name"]
    version = pkg["version"]
    if path == (root / "crates" / "shaar").resolve() or (root / "crates").resolve() in path.parents:
        return {"package": name, "version": version, "identity": "workspace",
                "archive_sha256": base_archive, "tree_sha256": _tree(path / "src"),
                "manifest_sha256": _sha(manifest.read_bytes())}

    if name == 'iroh-mainline-address-lookup':
        receipt = root / "target" / "native-graph" / "adapter.provenance.json"
    elif name in {'n0-mainline','serde_bencode','iroh-dns','n0-future','multibase'}:
        receipt = root / "target" / "native-graph" / f'{name}-{version}.provenance.json'
    elif name in {'iroh','noq','noq-proto'}:
        receipt = root / "target" / "backend" / "provenance.json"
    elif name in {'ironwood','yggdrasil'}:
        receipt = root / "target" / "ygg" / "Yggdrasil-ng-c9a54f1587bb133a06072596484c972a336db0d2.provenance.json"
    elif name in {'libp2p-relay','libp2p-swarm','simple-dns','libp2p-dns','hickory-resolver','libp2p-kad'}:
        receipt = path.parent / "provenance.json"
    else:
        raise ValueError(f"no fixed provenance receipt mapping for {name} at {path}")
    if receipt.is_symlink():
        raise ValueError(f"prepared provenance receipt is linked: {receipt}")
    if not receipt.is_file():
        raise ValueError(f"prepared path package has no fixed provenance receipt: {receipt}")
    data = json.loads(receipt.read_text(encoding="utf-8"))
    archives = data.get("archives", {})
    archive_hash = data.get("archive_sha256") or data.get("sha256")
    if not archive_hash and isinstance(data.get("source"), dict):
        archive_hash = data["source"].get("archive_sha256")
    if not archive_hash and isinstance(archives, dict):
        archive_hash = archives.get(name)
    recipe = data.get("recipe_files")
    if not isinstance(recipe, dict) or not recipe:
        recipe = {}
        if isinstance(data.get("patch_sources"), dict):
            recipe.update(data["patch_sources"])
        for field in ("prepare_sha256", "preparer_sha256", "patch_sha256", "operation_patch_sha256"):
            if data.get(field):
                recipe[field] = data[field]
    if not recipe:
        raise ValueError(f"reviewed recipe digest missing from provenance receipt: {receipt}")
    if not archive_hash:
        raise ValueError(f"approved archive hash missing for {name}: {receipt}")
    return {"package": name, "version": version, "identity": "prepared",
            "tree_sha256": _tree(path), "archive_sha256": archive_hash,
            "recipe_sha256": _sha(json.dumps(recipe, sort_keys=True, separators=(",", ":")).encode()),
            "receipt_sha256": _sha(receipt.read_bytes()),
            "manifest_sha256": _sha(manifest.read_bytes())}


def run(repo, archives, prepare_module, graph_module, runner):
    """Build and audit baseline, approved-route, and current-checkout proofs."""
    repo = Path(repo).resolve()
    out = repo / "target" / "native-graph-evidence"
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "commands"
    logs.mkdir(exist_ok=True)
    records = []
    materializations = []
    capture_runs = []

    def command(argv, cwd, label, env=None):
        args = [os.fspath(value) for value in argv]
        try:
            result = runner(args, cwd=Path(cwd), **({'env': {**os.environ, **env}} if env is not None else {}))
            if isinstance(result, tuple):
                stdout, code = result
                stderr = b""
                code = int(code)
            else:
                stdout = result.stdout or b""
                stderr = result.stderr or b""
                code = result.returncode
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
        except BaseException as error:
            stdout, stderr, code = b"", (type(error).__name__ + ": " + str(error)).encode(), -1
            _record(args, cwd, label, stdout, stderr, code, env=env)
            raise
        _record(args, cwd, label, stdout, stderr, code, env=env)
        if code:
            diagnostic = stderr[:16384].decode("utf-8", errors="replace")
            raise RuntimeError(
                f"{label} failed ({code}); command={args!r}; cwd={Path(cwd).resolve()!s}; "
                f"stderr artifact={out / records[-1]['stderr']}\n{diagnostic}"
                + ("\n[stderr truncated; full stderr is in the artifact]" if len(stderr) > 16384 else "")
            )
        return stdout

    def _record(args, cwd, label, stdout, stderr, code, env=None):
        index = len(records)
        stdout_name, stderr_name = f"commands/{index:03d}-{label}.stdout", f"commands/{index:03d}-{label}.stderr"
        (out / stdout_name).write_bytes(stdout)
        (out / stderr_name).write_bytes(stderr)
        records.append({"argv": args, "cwd": str(Path(cwd).resolve()), "exit_code": code,
                        "stdout": stdout_name, "stderr": stderr_name,
                        "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr),
                        **({"environment": dict(env)} if env is not None else {})})

    def provenance(error=None, proofs=None, result=None):
        safe_proofs = [{**p, 'artifacts': {k:_sha(v) for k,v in p['artifacts'].items()}} for p in (proofs or [])]
        value = {"materializations": materializations, "commands": records,
                 "proofs": safe_proofs, "comparison": result,
                 "compiler_captures": capture_runs}
        if error is not None:
            value["error"] = f"{type(error).__name__}: {error}"
        (out / "evidence.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    try:
        base_roots = {}
        for role in ("baseline", "approved_route"):
            root = out / role
            info = base.materialize(repo, root, lambda argv: command(argv, repo, role + "-materialize"))
            base_roots[role] = (root, info)
            materializations.append({"role": role, "commit": info["commit"], "archive_sha256": info["archive_sha256"], "input_hashes": info["input_hashes"]})
        candidate = repo
        revision = command(["git", "rev-parse", "HEAD"], repo, "candidate-revision").decode("ascii").strip()
        wrapper = prepare_capture_wrapper(repo, out, lambda argv, **kw: command(argv, kw.get("cwd", repo), kw.get("label", "capture-wrapper"), kw.get("env")))
        wrapper['records']=[dict(r) for r in records[-5:]]
        roots = {"baseline": base_roots["baseline"][0], "approved_route": base_roots["approved_route"][0], "candidate": candidate}
        prepared = {"baseline": {}}
        for role in ("baseline", "approved_route"):
            root = roots[role]
            base.prepare_sources(repo, root, lambda argv: command(argv, repo, role + "-sources"))
            destination = root / "target" / "native-graph"
            if role == "approved_route":
                route = base.apply_route(root)
                graph_module.audit_product_workspace(tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8")))
                prepared[role] = prepare_module.prepare_all(archives, destination)
            else:
                prepared[role] = {}
        graph_module.audit_product_workspace(tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8")))
        prepared["candidate"] = prepare_module.verify_all(archives, repo / "target" / "native-graph")

        proofs, metadata_values = [], {}
        for role, root in roots.items():
            consumer = out / (role + '-consumer')
            consumer.mkdir()
            target_dir = consumer / 'compiler-target'
            capture_dir = consumer / 'compiler-capture'
            target_dir.mkdir()
            capture_dir.mkdir()
            role_revision = revision if role == 'candidate' else base_roots['baseline'][1]['commit']
            env = capture_environment(wrapper['wrapper'], target_dir, capture_dir, role=role,
                                      revision=role_revision, recipe_sha256=wrapper['recipe_sha256'],
                                      nonce=uuid.uuid4().hex)
            env['RUSTC'] = wrapper['compiler']
            (consumer / 'src').mkdir()
            (consumer / 'src' / 'lib.rs').write_text("#![forbid(unsafe_code)]\nuse shaar as _;\n", encoding="utf-8")
            manifest_data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
            patch_lines = []
            for name, config in sorted(manifest_data.get("patch", {}).get("crates-io", {}).items()):
                if "path" not in config:
                    raise ValueError(f"non-path root patch cannot be copied: {name}")
                patch_path = (root / config["path"]).resolve()
                if not patch_path.is_dir():
                    raise ValueError(f"root patch path missing: {name}: {patch_path}")
                patch_lines.append(f'{name} = {{ path = {json.dumps(patch_path.as_posix())} }}')
            cargo_manifest = ("[workspace]\nresolver = \"3\"\n\n[package]\n"
                'name = "native-graph-normal-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
                'license = "MIT OR Apache-2.0"\n\n[lib]\npath = "src/lib.rs"\n\n[dependencies]\n'
                f'shaar = {{ path = {json.dumps((root / "crates" / "shaar").resolve().as_posix())} }}\n\n'
                "[patch.crates-io]\n" + "\n".join(patch_lines) + "\n")
            manifest = consumer / "Cargo.toml"
            manifest.write_text(cargo_manifest, encoding="utf-8")
            seed = base.projection_lock(role, roots["baseline"], repo,
                                        lambda argv: command(argv, repo, "approved_route-lock"))
            product_args = ['cargo', 'metadata', '--locked', '--format-version', '1']
            if role == 'approved_route':
                (root / 'Cargo.lock').write_bytes(seed)
            product_output = command(product_args, root, role + '-product-metadata')
            product_record = dict(records[-1])
            (consumer / "Cargo.lock").write_bytes(seed)
            projection_args = ["cargo", "metadata", "--format-version", "1", "--manifest-path", str(manifest.resolve())]
            projection = command(projection_args, consumer, role + "-projection")
            consumer_record = dict(records[-1])
            projected = (consumer / "Cargo.lock").read_bytes()
            projection_context = graph_module.build_projection_context(
                product_output, projection, product_record=product_record,
                consumer_record=consumer_record, product_argv=product_args,
                consumer_argv=projection_args, product_cwd=root, consumer_cwd=consumer,
                product_root_manifest=root / "Cargo.toml", future_archive=archives.get("future"), bencode_archive=archives.get("bencode"))
            projection_audit = graph_module.audit_consumer_lock(seed, projected, projection_context=projection_context)

            proof_records, artifacts = [], {}
            for kind, args in (("metadata", ["metadata", "--locked", "--format-version", "1"]),
                               ("tree", ["tree", "--locked", "--edges", "normal,features"]),
                               ("build", ["build", "--locked", "--lib", "--message-format=json"])):
                argv = ["cargo", *args, "--manifest-path", str(manifest.resolve())]
                if kind == "build":
                    argv[5:5] = ["--target", wrapper["target"]]
                before = len(records)
                if kind == "build":
                    capture_context = {"role": role, "revision": role_revision, "nonce": env["SHAAR_CAPTURE_NONCE"],
                                       "recipe_sha256": wrapper["recipe_sha256"], "compiler": wrapper["compiler"],
                                       "env": env}
                    capture_run = {"role": role, "revision": role_revision,
                                   "nonce": env["SHAAR_CAPTURE_NONCE"],
                                   "recipe_sha256": wrapper["recipe_sha256"],
                                   "command_index": before,
                                   "capture_dir": str(capture_dir.resolve()),
                                   "inventory": []}
                    capture_runs.append(capture_run)
                    try:
                        output = command(argv, consumer, role + "-build", env=env)
                    finally:
                        capture_run["inventory"] = capture_inventory(capture_dir)
                    rec = dict(records[before])
                    rec["kind"] = kind
                    capture_context = {"role": role, "revision": role_revision, "nonce": env["SHAAR_CAPTURE_NONCE"],
                                       "recipe_sha256": wrapper["recipe_sha256"], "compiler": wrapper["compiler"],
                                       "env": env}
                    metadata = json.loads(artifacts[proof_records[0]["stdout"]])
                    lock = tomllib.loads(projected.decode("utf-8"))
                    package_checksums = {
                        (package["name"], package["version"], package.get("source")): package["checksum"]
                        for package in lock.get("package", []) if package.get("checksum")
                    }
                    lock_checksums = {
                        package["id"]: package_checksums[key]
                        for package in metadata["packages"]
                        if (key := (package["name"], package["version"], package.get("source"))) in package_checksums
                    }
                    collector_context = {**capture_context, "host": wrapper["target"],
                                         "packages": metadata["packages"], "lock_checksums": lock_checksums}
                    collected = collect_capture(capture_dir, target_dir, collector_context)
                    aliases = base.collect_output_aliases(collected, output, metadata['packages'], collector_context, str(manifest.resolve()), capture_dir)
                    capture_run["inventory"] = capture_inventory(capture_dir)
                    capture_artifacts = {f"{consumer.name}/compiler-capture/{name}": data
                                         for name, data in collected["raw"].items()}
                    capture_meta = {"context": capture_context, "wrapper": {**wrapper, "records": [dict(r) for r in wrapper["records"]]},
                                    "units": collected["units"],
                                    "aliases": aliases,
                                    "receipts": {name: _sha(data) for name, data in collected["raw"].items()},
                                    "build_stdout_sha256": rec["stdout_sha256"]}
                    rec["compiler_capture"] = capture_meta
                    records[before] = rec
                    artifacts.update(capture_artifacts)
                    artifacts[f'compiler-wrapper/wrapper.rs'] = Path(wrapper["source_path"]).read_bytes()
                else:
                    output = command(argv, consumer, role + "-" + kind)
                    rec = dict(records[before])
                    rec["kind"] = kind

                proof_records.append(rec)
                artifacts[rec["stdout"]] = output
                artifacts[rec["stderr"]] = (out / rec["stderr"]).read_bytes()
            for record in wrapper["records"]:
                for stream in ("stdout", "stderr"):
                    artifacts[record[stream]] = (out / record[stream]).read_bytes()
            metadata = json.loads(artifacts[proof_records[0]["stdout"]])
            metadata_values[role] = metadata
            bindings, checksums = {}, {}
            lock = tomllib.loads(projected.decode("utf-8"))
            for pkg in metadata["packages"]:
                if pkg.get("source") is not None:
                    continue
                manifest_path = Path(pkg["manifest_path"]).resolve()
                path = manifest_path.parent
                if path == (root / "crates" / "shaar").resolve() or (root / "crates").resolve() in path.parents:
                    bindings[pkg["id"]] = {"package": pkg["name"], "version": pkg["version"], "identity": "workspace",
                                            "archive_sha256": base_roots["baseline"][1]["archive_sha256"],
                                            "tree_sha256": _tree(path / "src"), "manifest_sha256": _sha(manifest_path.read_bytes())}
                    continue
                if path == consumer.resolve():
                    continue
                bindings[pkg["id"]] = _binding(root, path, pkg, base_roots["baseline"][1]["archive_sha256"])
            for package in lock.get("package", []):
                if package.get("checksum"):
                    key = (package["name"], package["version"], package.get("source"))
                    for pkg in metadata["packages"]:
                        if (pkg["name"], pkg["version"], pkg.get("source")) == key:
                            checksums[pkg["id"]] = package["checksum"]
            proof = {"role": role, "context": "normal", "revision": revision if role == "candidate" else base_roots["baseline"][1]["commit"],
                     "consumer_manifest": str(manifest.resolve()), "consumer_cwd": str(consumer.resolve()), "projection_json": projection.decode("utf-8"),
                     "projected_lock_sha256": _sha(projected), "seed_lock_sha256": _sha(seed), "records": proof_records,
                     "artifacts": artifacts, "source_bindings": bindings, "lock_checksums": checksums}
            proof["compiler_capture"] = capture_meta
            if projection_audit is not None:
                proof["projection_audit"] = projection_audit
            if role == "approved_route":
                proof["base_manifest_sha256"] = base_roots[role][1]["input_hashes"]["Cargo.toml"]
                proof["route_recipe_id"] = _sha(json.dumps(route, sort_keys=True, separators=(",", ":")).encode())
            proofs.append(proof)
            if target_dir.is_symlink():
                raise ValueError("compiler target became linked after capture")
            shutil.rmtree(target_dir)

        control = next(p for p in proofs if p["role"] == "approved_route")
        try:
            baseline_features = features._metadata(next(p for p in proofs if p["role"] == "baseline"))[4]
            control_features = features._metadata(control)[4]
            delta = [{"package": list(key), "baseline": list(baseline_features.get(key, ())), "approved_route": list(control_features.get(key, ()))}
                     for key in sorted(set(baseline_features) | set(control_features)) if baseline_features.get(key) != control_features.get(key)]
            control["approved_feature_deltas"] = delta
        except (AttributeError, KeyError, TypeError):
            raise ValueError("cannot derive approved feature deltas from control evidence")
        result = features.compare_proofs(
            proofs, base_roots["baseline"][1]["commit"], revision,
            expected_control={
                "root_manifest_sha256": base_roots["baseline"][1]["input_hashes"]["Cargo.toml"],
                "route_recipe_id": _sha(json.dumps(route, sort_keys=True, separators=(",", ":")).encode()),
            },
        )
        result["materialization"] = {"baseline_archive_sha256": base_roots["baseline"][1]["archive_sha256"],
                                     "approved_archive_sha256": base_roots["approved_route"][1]["archive_sha256"], "candidate_revision": revision}
        provenance(proofs=proofs, result=result)
        return {"comparison": result, "materializations": materializations, "commands": records, "evidence": str(out / "evidence.json")}
    except BaseException as error:
        provenance(error, locals().get("proofs"), locals().get("result"))
        raise


def audit_units(proof, packages, nodes, stable_identity, baseline_test_util_validator):
    """Audit captured rustc invocations against their Cargo build evidence."""
    def need(ok, message):
        if not ok:
            raise ValueError(message)

    try:
        need(isinstance(proof, dict), "invalid proof")
        role, revision = proof.get("role"), proof.get("revision")
        builds = [r for r in proof.get("records", []) if r.get("kind") == "build"]
        need(len(builds) == 1, "build record must be unique")
        build = builds[0]
        capture = proof.get("compiler_capture")
        need(isinstance(capture, dict) and build.get("compiler_capture") == capture,
             "compiler capture/build binding mismatch")
        context, wrapper = capture.get("context"), capture.get("wrapper")
        need(isinstance(context, dict) and isinstance(wrapper, dict), "missing compiler context or wrapper")
        base.validate_wrapper_records(proof, wrapper)
        env = context.get("env")
        need(build.get("environment") == env and build.get("compiler_capture", {}).get("context") == context,
             "build environment or context differs from capture")
        need(isinstance(build.get("argv"), list) and build["argv"] ==
             ["cargo", "build", "--locked", "--lib", "--message-format=json", "--target",
              wrapper["target"], "--manifest-path", proof["consumer_manifest"]] and
             "--target" in build["argv"] and build["argv"][build["argv"].index("--target") + 1] == wrapper.get("target"), "build argv must match capture context and target")
        for key, value in (("role", role), ("revision", revision)):
            need(context.get(key) == value, "compiler context mismatch: " + key)
        need(context.get("role") == proof.get("role") and context.get("revision") == proof.get("revision"), "build context role/revision mismatch")
        need(context.get("nonce") and context.get("recipe_sha256"), "missing nonce or recipe digest")
        env = context.get("env")
        need(isinstance(env, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()), "invalid context env")
        need(env.get("RUSTC") == wrapper.get("compiler") and env.get("RUSTC_WORKSPACE_WRAPPER") == "" and env.get("RUSTC_WRAPPER") == wrapper.get("wrapper"),
             "wrapper environment mismatch")
        for key in ("SHAAR_CAPTURE_ROLE", "SHAAR_CAPTURE_REVISION", "SHAAR_CAPTURE_RECIPE_SHA256", "SHAAR_CAPTURE_NONCE"):
            need(env.get(key) == context.get({"SHAAR_CAPTURE_ROLE": "role", "SHAAR_CAPTURE_REVISION": "revision", "SHAAR_CAPTURE_RECIPE_SHA256": "recipe_sha256", "SHAAR_CAPTURE_NONCE": "nonce"}[key]), "capture environment mismatch: " + key)
        source_path = wrapper.get("source_path")
        artifact_map = proof.get("artifacts")
        need(isinstance(artifact_map, dict) and isinstance(source_path, str), "missing proof artifacts or wrapper source")
        source_key = f"compiler-wrapper/wrapper.rs"
        need(source_key in artifact_map, "wrapper source artifact is missing")
        source = artifact_map[source_key]
        if isinstance(source, str):
            source = source.encode()
        expected_source = base.native_wrapper_source().encode("utf-8")
        need(source == expected_source and wrapper.get("source_sha256") == _sha(source), "wrapper source mismatch")
        stdin_probes.validate_recipe(wrapper, context, source_path, source)
        receipts = capture.get("receipts")
        need(isinstance(receipts, dict), "missing raw receipt commitment")
        artifact_map = proof.get("artifacts")
        need(isinstance(artifact_map, dict) and isinstance(proof.get("consumer_cwd"), str), "missing proof artifacts or consumer path")
        consumer_name = Path(proof["consumer_cwd"]).name
        need(env.get("CARGO_TARGET_DIR") == str(Path(proof["consumer_cwd"]) / "compiler-target") and
             env.get("SHAAR_CAPTURE_DIR") == str(Path(proof["consumer_cwd"]) / "compiler-capture"),
             "compiler output paths differ from consumer")
        need(context.get("compiler") == wrapper.get("compiler") and
             wrapper.get("recipe_sha256") == context.get("recipe_sha256"),
             "compiler or recipe differs from wrapper")
        capture_prefix = f"{consumer_name}/compiler-capture/"
        def artifact_bytes(name):
            key = f"{capture_prefix}{name}"
            value = artifact_map.get(key)
            if isinstance(value, str):
                value = value.encode()
            need(isinstance(value, bytes), "capture artifact missing: " + name)
            return value
        raw_names = {name for name in artifact_map if name.startswith(capture_prefix)}
        capture_commitments = {name[len(capture_prefix):]: _sha(artifact_map[name] if isinstance(artifact_map[name], bytes) else artifact_map[name].encode())
                               for name in raw_names}
        need(set(capture_commitments) == set(receipts) and capture_commitments == receipts,
             "capture artifact inventory or commitment mismatch")
        receipt_names = {name for name in raw_names
                         if Path(name).parent == Path(consumer_name) / "compiler-capture" and name.endswith(".json")}
        json_names = {Path(name).name for name in receipt_names}
        need(json_names <= set(receipts), "receipt inventory mismatch")
        raw_by_name = {}
        for name in json_names:
            raw_by_name[name] = json.loads(artifact_bytes(name).decode("utf-8"))
            need(isinstance(raw_by_name[name], dict) and raw_by_name[name].get("schema") == 1, "invalid raw receipt schema")
        units = capture.get("units")
        need(isinstance(units, list), "missing enriched compiler units")
        json_receipt_names = receipt_names
        need(len(units) == len(json_receipt_names), "compiler unit/JSON receipt count mismatch")
        snapshots = {Path(name).relative_to(Path(Path(proof["consumer_cwd"]).name) / "compiler-capture").as_posix(): artifact_map[name]
                     for name in raw_names if name not in json_receipt_names and not name.startswith(capture_prefix + 'cargo-aliases/')}
        need(all(isinstance(v, bytes) for v in snapshots.values()), "snapshot commitments must be raw bytes")
        expected_snapshot_names = set()
        enriched_by_receipt = {}
        enriched_index = {}
        matched_unit_ids = set()
        for unit in units:
            need(isinstance(unit, dict), "invalid enriched unit")
            key = json.dumps({k: v for k, v in unit.items() if k != 'outputs'}, sort_keys=True, separators=(',', ':'))
            enriched_index.setdefault(key, []).append(unit)
        for receipt_name, raw in raw_by_name.items():
            key = json.dumps({k: v for k, v in raw.items() if k != 'outputs'}, sort_keys=True, separators=(',', ':'))
            need(enriched_index.get(key), "enriched unit must match exactly one raw receipt")
            matches = [enriched_index[key].pop()]
            need(id(matches[0]) not in matched_unit_ids, "duplicate raw receipt identity")
            matched_unit_ids.add(id(matches[0]))
            enriched_by_receipt[receipt_name] = matches[0]
            raw_outputs = raw.get("outputs")
            stdin_probes.validate_input_snapshot(raw, proof, snapshots, expected_snapshot_names)
            need(isinstance(raw_outputs, list) and all(isinstance(x, str) for x in raw_outputs) and len(raw_outputs) == len(set(raw_outputs)), "invalid raw output list")
            raw_snaps = raw.get("snapshots", [])
            need(isinstance(raw_snaps, list), "invalid raw snapshots")
            need(len(raw_snaps) == len(raw_outputs) and
                 {s.get('output') for s in raw_snaps if isinstance(s, dict)} == set(raw_outputs),
                 'snapshot output inventory mismatch')
            for item in raw_snaps:
                need(isinstance(item, dict) and isinstance(item.get("output"), str) and isinstance(item.get("snapshot"), str), "invalid snapshot record")
                snapshot_name = Path(item["snapshot"]).relative_to(Path(env["SHAAR_CAPTURE_DIR"])).as_posix()
                need(snapshot_name not in expected_snapshot_names, "duplicate snapshot ownership")
                expected_snapshot_names.add(snapshot_name)
                snapshot_data = snapshots.get(snapshot_name)
                need(isinstance(snapshot_data, bytes), "raw snapshot missing")
                out = next((o for o in matches[0].get("outputs", []) if o.get("path") == item.get("output")), None)
                need(out is not None and out.get("sha256") == _sha(snapshot_data) and out.get("size") == len(snapshot_data), "snapshot output hash mismatch")
                need(out.get("snapshot_path") == snapshot_name, "snapshot relative path mismatch")
            need(len(matches[0].get("outputs", [])) == len(raw_outputs) and {o.get("path") for o in matches[0].get("outputs", [])} == set(raw_outputs), "enriched outputs differ from raw outputs")
        need(expected_snapshot_names == set(snapshots), "unowned raw snapshot artifact")
        raw_by_enriched_id = {id(unit): (name, raw_by_name[name]) for name, unit in enriched_by_receipt.items()}
        messages = [json.loads(line) for line in artifact_map[build["stdout"]].splitlines() if line.strip()]
        need(all(isinstance(m, dict) and m.get("reason") in {"compiler-artifact", "build-script-executed", "build-finished", "compiler-message", "future-incompat-report"} for m in messages), "unknown Cargo message reason")
        need(build.get("stdout_sha256") == _sha(artifact_map[build["stdout"]]) and capture.get("build_stdout_sha256") == build.get("stdout_sha256"), "build stdout commitment mismatch")
        cargo = [m for m in messages if m.get("reason") == "compiler-artifact"]
        mapped, artifact_owners = audit_output_aliases(proof, packages, messages)
        cargo_message_indices = [i for i, message in enumerate(messages) if message.get("reason") == "compiler-artifact"]
        package_index = {}
        for p in packages:
            package_index.setdefault((p.get("name"), p.get("version")), []).append(p)
        emitted, normalized, seen_outputs, seen_artifacts = set(), [], set(), set()
        normalized_keys = set()
        seen_cargo = set()
        unit_by_output, pending, auxiliary, artifact_units = {}, [], [], {}
        stdin_aux = []
        for enriched in units:
            need(isinstance(enriched, dict), "invalid enriched unit")
            # Raw receipt identity is bound by all fields other than enriched output hashes.
            candidate = raw_by_enriched_id.get(id(enriched))
            need(candidate is not None, "enriched unit differs from its raw receipt")
            name, raw = candidate
            need(name not in seen_artifacts, "duplicate enriched receipt")
            seen_artifacts.add(name)
            need(raw.get("role") == role and raw.get("revision") == revision and raw.get("nonce") == context["nonce"] and
                 raw.get("recipe_sha256") == context["recipe_sha256"] and raw.get("env") == {key: env[key] for key in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR")}, "receipt context mismatch")
            need(raw.get("compiler") == wrapper["compiler"], "compiler executable mismatch")
            args, cwd = raw.get("args"), raw.get("cwd")
            need(isinstance(args, list) and all(isinstance(a, str) for a in args) and isinstance(cwd, str), "invalid invocation")
            input_shape = stdin_probes.classify_input(raw, proof, packages)
            if input_shape is not None:
                stdin_aux.append((raw, input_shape))
                continue
            shape = prepare.auxiliary_probe_shape(raw, env["CARGO_TARGET_DIR"], wrapper["target"], packages, proof.get("lock_checksums", {}))
            if shape is not None:
                auxiliary.append((raw, shape))
                continue
            need(raw.get("exit_code") == 0 and raw.get("launch_error") is None, "failed compiler receipt")
            if any(a in ("-vV", "--version", "-V", "--print") or a.startswith("--print=") for a in args):
                crate_name_index = args.index("--crate-name") if "--crate-name" in args else -1
                version_probe = args in (["-vV"], ["-V"], ["--version"], ["--version", "--verbose"])
                target_info_probe = (
                    "--print=target-info" in args
                    or ("--print" in args and args.index("--print") + 1 < len(args)
                        and args[args.index("--print") + 1] == "target-info")
                )
                stdin_probe = (
                    crate_name_index >= 0
                    and crate_name_index + 1 < len(args)
                    and bool(args[crate_name_index + 1])
                    and "-" in args
                )
                need(raw.get("kind") == "probe" and raw.get("outputs") == [] and
                     raw.get("snapshots") == [] and (version_probe or target_info_probe or stdin_probe),
                     "invalid compiler probe")
                need(not any(a.endswith(".rs") for a in args),
                     "probe-shaped source compilation rejected")
                continue
            need(raw.get("kind") == "compile", "invalid compiler invocation kind")
            key = (raw.get("package_name"), raw.get("package_version"))
            normcwd = cwd.replace("\\", "/").rstrip("/")
            found = package_index.get(key, [])
            found = [p for p in found if p.get("manifest_path", "").replace("\\", "/").rsplit("/", 1)[0].rstrip("/") == normcwd]
            need(len(found) == 1, "compiler package is unknown or ambiguous")
            package = found[0]
            manifest = package["manifest_path"].replace("\\", "/").rsplit("/", 1)[0].rstrip("/")
            need(raw.get("manifest_dir", "").replace("\\", "/").rstrip("/") == manifest and normcwd == manifest, "compiler cwd/manifest mismatch")
            def opt(flag, required=True):
                vals = []
                for i, arg in enumerate(args):
                    if arg == flag:
                        vals.append(args[i + 1] if i + 1 < len(args) else None)
                    elif arg.startswith(flag + "="):
                        vals.append(arg[len(flag) + 1:])
                need(
                    len(vals) == (1 if required else min(1, len(vals)))
                    and all(isinstance(value, str) and value and not value.startswith("-")
                            for value in vals),
                    "invalid rustc option " + flag,
                )
                return vals[0] if vals else None
            crate, outdir = opt('--crate-name'), opt('--out-dir')
            types = crate_types(args)
            triple = opt("--target", False) or wrapper["target"]
            need(triple == wrapper["target"], "compiler target mismatch")
            context_kind = "target" if opt("--target", False) is not None else "host"
            target_root = env["CARGO_TARGET_DIR"].replace("\\", "/").rstrip("/")
            normalized_outdir = outdir.replace("\\", "/").rstrip("/")
            expected_context_prefix = target_root + ("/" + triple if context_kind == "target" else "") + "/"
            need(normalized_outdir.startswith(expected_context_prefix), "compiler output directory context mismatch")
            need(context_kind != "host" or not normalized_outdir.startswith(target_root + "/" + triple + "/"), "host output directory has target context")
            srcarg = next((a for a in args if a.endswith(".rs")), None)
            need(srcarg, "missing rust source")
            srcpath = Path(srcarg)
            src = str(srcpath if srcpath.is_absolute() else Path(normcwd) / srcpath)
            src = os.path.normpath(src).replace("\\", "/")
            targets = package.get("targets", [])
            rows = [t for t in targets if t.get("src_path", "").replace("\\", "/") == src and t.get("name", "").replace("-", "_") == crate.replace("-", "_") and types == target_crate_types(t)]
            need(len(rows) == 1, "rustc source/target does not match package")
            row = rows[0]
            cfgfeatures = []
            for i, arg in enumerate(args):
                if arg == "--cfg":
                    need(i + 1 < len(args), "missing --cfg value")
                    value = args[i + 1]
                elif arg.startswith("--cfg="):
                    value = arg[len("--cfg="):]
                else:
                    continue
                if value.startswith("feature="):
                    try:
                        feature = json.loads(value[len("feature="):])
                    except (json.JSONDecodeError, TypeError) as exc:
                        raise ValueError("invalid feature cfg") from exc
                    need(isinstance(feature, str) and bool(feature), "invalid feature cfg")
                    need(feature not in cfgfeatures, "duplicate feature cfg")
                    cfgfeatures.append(feature)
            cfgfeatures.sort()
            if any(value == "test-util" or value.startswith("test-util/") for value in cfgfeatures):
                need(role == "baseline" and key == ("tokio", "1.54.1") and callable(baseline_test_util_validator) and baseline_test_util_validator(package), "test-util compiler unit rejected")
            outputs = enriched.get("outputs")
            need(isinstance(outputs, list), "invalid captured outputs")
            need(all(Path(o["path"]).is_absolute() and ".." not in Path(o["path"]).parts and Path(o["path"]).parent == Path(outdir) for o in outputs), "captured output outside invocation directory")
            matching_indices = [i for i, a in enumerate(cargo) if a.get("package_id") in (package.get("id"), key[0]+" "+key[1]) and a.get("target", {}).get("src_path", "").replace("\\", "/") == src and a.get("target", {}).get("name") == row.get("name") and sorted(a.get("features", [])) == cfgfeatures and a.get("target", {}).get("kind") == row.get("kind") and target_crate_types(a.get('target',{}))==types and a.get("profile", {}).get("test") is False and a.get("fresh") is False and mapped[cargo_message_indices[i]] <= {o["path"] for o in outputs} and artifact_owners[cargo_message_indices[i]] == units.index(enriched)]
            need(len(matching_indices) == 1, "Cargo compiler artifact must match exactly once")
            cargo_index = matching_indices[0]
            need(cargo_index not in seen_cargo, "Cargo compiler artifact reused")
            seen_cargo.add(cargo_index)
            art = cargo[cargo_index]
            need(all(o["path"] not in seen_outputs for o in outputs), "duplicate output owner")
            seen_outputs.update(o["path"] for o in outputs)
            emitted.add(package.get("id"))
            ident = stable_identity(package)
            normalized_unit = {"package": ident, "target": row.get("name"), "kind": sorted(row.get("kind", [])), "crate_types": list(types), "context": context_kind, "triple": triple, "features": cfgfeatures}
            normalized.append(normalized_unit)
            artifact_units[id(cargo[cargo_index])] = (normalized_unit, package, row)
            for output in outputs:
                output_path = output.get("path")
                need(isinstance(output_path, str) and output_path not in unit_by_output, "invalid or duplicate output path")
                unit_by_output[output_path] = (normalized_unit, package, row)
            pending.append((raw, package, row, normalized_unit))
        base.validate_externs(pending, unit_by_output, packages, nodes)
        normalized.extend(features.audit_auxiliary(auxiliary, proof, packages, cargo, messages, normalized, artifact_units, stable_identity))
        normalized.extend(stdin_probes.audit(stdin_aux, proof, packages, cargo, messages, artifact_units, stable_identity, nodes))
        for unit in normalized:
            unit_key = json.dumps(unit, sort_keys=True, separators=(",", ":"))
            need(unit_key not in normalized_keys, "duplicate normalized compiler unit")
            normalized_keys.add(unit_key)
        need(len(seen_cargo) == len(cargo), "unmatched Cargo artifacts")
        need(seen_artifacts == json_names, "unmatched compiler receipts")
        return emitted, sorted(normalized, key=lambda x: json.dumps(x, sort_keys=True))
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
        raise ValueError("malformed compiler unit evidence") from exc
