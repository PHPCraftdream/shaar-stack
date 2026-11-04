# SPDX-License-Identifier: MIT OR Apache-2.0
"""Synthetic capability build fixtures for native graph proofs."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


def attach_capability(proof, case=None):
    if case is None:
        for extra in (('thiserror', '1.0.69', 'b6aaf5339b578ea85b50e080feb250a3e8ae8cfcdff9a461c9ec2904bc923f52'), ('thiserror', '2.0.21', '09e52cb86a36cede5cb101bf8908837b3e4c6e5e59fe7fd85c23fb56200d189e'), ('anyhow', '1.0.104', '330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470')):
            attach_capability(proof, extra)
    name, version, checksum = case or ('proc-macro2', '1.0.107', '985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9')
    label = '' if case is None else name + version + '.'
    capture = proof['compiler_capture']
    artifacts = proof['artifacts']
    prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
    template = json.loads(artifacts[prefix + 'unit.json'])
    meta = next(r for r in proof['records'] if r['kind'] == 'metadata')
    doc = json.loads(artifacts[meta['stdout']])
    build = next(r for r in proof['records'] if r['kind'] == 'build')
    messages = [json.loads(line) for line in artifacts[build['stdout']].splitlines()]
    registry = 'registry+https://github.com/rust-lang/crates.io-index'
    pid = registry + f'#{name}@{version}'
    root = (Path('/registry') / f'{name}-{version}').resolve()
    target = Path(capture['context']['env']['CARGO_TARGET_DIR'])
    owner_hash = ''.join(c for c in version.replace('.', '') if c.isdigit())
    owner_base = target / 'debug/build'
    runtime_parent = target / capture['wrapper']['target'] / 'debug/build' if name == 'thiserror' else owner_base
    owner_dir = owner_base / f'{name}-{owner_hash}'
    probe_dir = runtime_parent / f'{name}-{owner_hash}a/out/probe'
    owner_target = {'name': 'build-script-build', 'kind': ['custom-build'],
                    'crate_types': ['bin'], 'src_path': str(root / 'build.rs')}
    doc['packages'].append({'id': pid, 'name': name, 'version': version,
        'source': registry, 'manifest_path': str(root / 'Cargo.toml'),
        'targets': [owner_target], 'dependencies': []})
    doc['resolve']['nodes'].append({'id': pid, 'features': [], 'deps': []})
    shaar = next(p for p in doc['packages'] if p['name'] == 'shaar')
    node = next(n for n in doc['resolve']['nodes'] if n['id'] == shaar['id'])
    node['deps'].append({'name': name.replace('-', '_'), 'pkg': pid,
                         'dep_kinds': [{'kind': None, 'target': None}]})
    proof['lock_checksums'][pid] = checksum

    def publish(raw, artifact_name, blobs):
        raw['snapshots'] = []
        enriched = []
        for index, output in enumerate(raw['outputs']):
            snapshot = label + artifact_name + '-outputs/' + str(index)
            data = blobs[index]
            artifacts[prefix + snapshot] = data
            capture['receipts'][snapshot] = hashlib.sha256(data).hexdigest()
            raw['snapshots'].append({'output': output, 'snapshot': str(Path(capture['context']['env']['SHAAR_CAPTURE_DIR']) / snapshot)})
            enriched.append({'path': output, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'snapshot_path': snapshot})
        encoded = json.dumps(raw).encode()
        filename = label + artifact_name + '.json'
        artifacts[prefix + filename] = encoded
        capture['receipts'][filename] = hashlib.sha256(encoded).hexdigest()
        capture['units'].append(dict(raw, outputs=enriched))

    raw = copy.deepcopy(template)
    raw.update(package_name=name, package_version=version, cwd=str(root), manifest_dir=str(root))
    raw['args'] = [str(root / 'build.rs'), '--crate-name', 'build_script_build', '--crate-type', 'bin', '--out-dir', str(owner_dir), '-C', f'extra-filename=-{owner_hash}']
    executable = str(owner_dir / ('build-script-build.exe' if 'windows' in capture['wrapper']['target'] else 'build-script-build'))
    direct = str(owner_dir / (f'build_script_build-{owner_hash}' + ('.exe' if 'windows' in capture['wrapper']['target'] else '')))
    raw['outputs'] = [direct]
    publish(raw, 'owner', [b'owner0'])
    owner_index = len(capture['units']) - 1
    alias_data = b'owner0'
    alias_snapshot = 'cargo-aliases/' + str(len(messages)) + '-0.bin'
    artifacts[prefix + alias_snapshot] = alias_data
    capture['receipts'][alias_snapshot] = hashlib.sha256(alias_data).hexdigest()
    capture.setdefault('aliases', []).append({'artifact_index': len(messages), 'unit_index': owner_index,
        'alias': executable, 'direct': direct, 'snapshot_path': alias_snapshot, 'size': len(alias_data),
        'sha256': hashlib.sha256(alias_data).hexdigest()})
    messages.append({'reason': 'compiler-artifact', 'package_id': pid,
        'target': owner_target, 'features': [], 'filenames': [executable],
        'executable': None, 'profile': {'test': False}, 'fresh': False})
    messages.append({'reason': 'build-script-executed', 'package_id': pid,
                     'out_dir': str(probe_dir.parent)})
    proc = name == 'proc-macro2'
    sources = ('proc_macro_span.rs', 'proc_macro_span_location.rs', 'proc_macro_span_file.rs') if proc else (('build/probe.rs' if name == 'thiserror' else 'src/nightly.rs'),)
    cfg = '--cfg=procmacro2_build_probe' if proc else '--cfg=anyhow_build_probe' if name == 'anyhow' else None
    crate = 'proc_macro2' if proc else name
    for index, source in enumerate(sources):
        raw = copy.deepcopy(template)
        code = 1 if not proc or index == 0 else 0
        raw.update(package_name=name, package_version=version, cwd=str(root), manifest_dir=str(root), exit_code=code)
        raw['args'] = ([cfg] if cfg else []) + [f'--edition={"2021" if proc else "2018"}', f'--crate-name={crate}', '--crate-type=lib', '--cap-lints=allow', '--emit=dep-info,metadata', '--out-dir', str(probe_dir), ('src/probe/' + source if proc else source), '--target', capture['wrapper']['target']]
        raw['outputs'] = [] if code else [str(probe_dir / f'lib{crate}.rmeta'), str(probe_dir / f'{crate}.d')]
        publish(raw, 'capability-' + str(index), [(('capability-' + str(index) + str(i)).encode()) for i in range(len(raw['outputs']))])
    for record, data in ((meta, json.dumps(doc).encode()), (build, b''.join((json.dumps(m) + '\n').encode() for m in messages))):
        artifacts[record['stdout']] = data
        record['stdout_sha256'] = hashlib.sha256(data).hexdigest()
    capture['build_stdout_sha256'] = build['stdout_sha256']
    return proof


def audit_compiler_units(proof, packages, buildbytes, recipebytes):
    """Match captured rustc receipts to Cargo compiler-artifact records."""
    import re
    from features import AuditError, _need, _sha, _json, _ROLES
    from cargo_aliases import crate_types, target_crate_types

    def need(condition, message):
        _need(condition, message)

    try:
        need(isinstance(proof, dict), "invalid compiler capture")
        role, revision = proof.get("role"), proof.get("revision")
        cwd, target = proof.get("cwd"), proof.get("target")
        target_dir, wrapper = proof.get("target_dir"), proof.get("wrapper")
        need(role in _ROLES, "invalid compiler proof role")
        need(isinstance(revision, str) and revision, "incomplete compiler proof context")
        need(all(isinstance(value, str) and value for value in (cwd, target, target_dir, wrapper, proof.get("nonce"), proof.get("compiler"))),
             "incomplete compiler proof context")
        need(isinstance(recipebytes, bytes) and proof.get("recipe_sha256") == _sha(recipebytes),
             "compiler recipe digest mismatch")
        expected_argv = ["cargo", "build", "--locked", "--lib", "--message-format=json",
                         "--target", target, "--manifest-path", cwd.rstrip("/") + "/Cargo.toml"]
        need(proof.get("build_argv") == expected_argv, "compiler build argv mismatch")
        invocations, captures = proof.get("invocations"), proof.get("artifacts")
        need(isinstance(invocations, list) and invocations and isinstance(captures, dict) and
             len(invocations) == len(set(invocations)), "invalid compiler receipt set")
        package_index = {}
        for package in packages:
            package_index.setdefault((package["name"], package["version"]), []).append(package)
        messages = [json.loads(line) for line in buildbytes.splitlines() if line.strip()]
        artifacts = [item for item in messages if item.get("reason") == "compiler-artifact"]
        need(all(item.get("reason") in ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished") for item in messages),
             "unknown Cargo build message")
        units, matched, outputs_seen = [], set(), set()
        for receipt_name in invocations:
            need(isinstance(receipt_name, str) and isinstance(captures.get(receipt_name), bytes), "missing compiler receipt")
            receipt = _json(captures[receipt_name], "compiler receipt")
            need(receipt.get("schema") == 1 and receipt.get("role") == role and
                 receipt.get("revision") == revision and receipt.get("recipe_sha256") == proof["recipe_sha256"] and
                 receipt.get("nonce") == proof.get("nonce") and receipt.get("compiler") == proof.get("compiler") and receipt.get("exit_code") == 0,
                 "compiler receipt context mismatch")
            env = receipt.get("env")
            need(isinstance(env, dict) and env.get("RUSTC_WRAPPER") == wrapper and
                 env.get("RUSTC_WORKSPACE_WRAPPER") == "" and env.get("CARGO_TARGET_DIR") == target_dir and
                 set(env) <= {"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR"}, "compiler environment mismatch")
            key = (receipt.get("package_name"), receipt.get("package_version"))
            found = package_index.get(key, [])
            need(len(found) == 1, "unknown or ambiguous compiler package")
            package = found[0]
            manifest_dir = package["manifest_path"].rsplit("/", 1)[0]
            need(receipt.get("manifest_dir") == manifest_dir, "compiler manifest directory mismatch")
            need(isinstance(receipt.get("cwd"), str) and receipt["cwd"].replace("\\", "/").rstrip("/") == manifest_dir.replace("\\", "/").rstrip("/"),
                 "compiler receipt cwd mismatch")
            args = receipt.get("args")
            need(isinstance(args, list) and all(isinstance(arg, str) for arg in args), "invalid rustc arguments")

            def option(name, required=True):
                positions = [index for index, value in enumerate(args) if value == name]
                need((len(positions) == 1 if required else len(positions) <= 1) and (not required or positions[0] + 1 < len(args)), "invalid rustc option " + name)
                return args[positions[0] + 1] if positions else None

            crate, out_dir = option("--crate-name"), option("--out-dir")
            types = crate_types(args)
            triple = option("--target", False)
            need(triple is None or triple == target, "compiler target mismatch")
            context = "target" if triple is not None else "host"
            actual_triple = triple or "host"
            normalized_out = out_dir.replace("\\", "/").rstrip("/")
            normalized_target_dir = target_dir.replace("\\", "/").rstrip("/")
            expected_out_prefix = normalized_target_dir + "/" + target
            need(normalized_out.startswith(normalized_target_dir + "/"), "compiler output directory mismatch")
            need((context == "target" and normalized_out.startswith(expected_out_prefix + "/")) or
                 (context == "host" and not normalized_out.startswith(expected_out_prefix + "/")), "compiler output context mismatch")
            extra_values = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "-C"]
            extra_filename = next((value.split("=", 1)[1] for value in extra_values if value.startswith("extra-filename=")), "")
            metadata = next((value.split("=", 1)[1] for value in extra_values if value.startswith("metadata=")), "")
            features = tuple(sorted(args[index + 1][9:-1] for index, value in enumerate(args[:-1]) if value == "--cfg" and args[index + 1].startswith('feature="') and args[index + 1].endswith('"')))
            target_rows = package.get("targets", [])
            normalized_cwd = receipt["cwd"].replace("\\", "/").rstrip("/")
            source = next((arg for arg in args if arg.endswith(".rs") and any(
                row.get("src_path", "").replace("\\", "/") ==
                (arg if arg.startswith("/") or re.match(r"^[A-Za-z]:[/\\\\]", arg) else normalized_cwd + "/" + arg).replace("\\", "/") and
                row.get("name") == crate and set(row.get("kind", [])) & {"lib", "proc-macro", "custom-build"}
                for row in target_rows)), None)
            need(source is not None, "compiler source does not match package target")
            if not source.startswith("/") and not re.match(r"^[A-Za-z]:[/\\\\]", source):
                source = normalized_cwd + "/" + source
            source = source.replace("\\\\", "/")
            row = next(item for item in target_rows if item.get("src_path", "").replace("\\", "/") == source.replace("\\", "/") and item.get("name") == crate)
            need(target_crate_types(row) == types and not any(value == "test-util" or value.startswith("test-util/") for value in features),
                 "invalid compiler crate type or test-util feature")
            produced = receipt.get("outputs")
            need(isinstance(produced, list) and produced and all(isinstance(path, str) for path in produced), "compiler receipt has no outputs")
            need(all(path.replace("\\", "/").rsplit("/", 1)[0] == normalized_out and ".." not in path.replace("\\", "/").split("/") for path in produced), "compiler output path mismatch")
            matches = [item for item in artifacts if item.get("package_id") in (package.get("id"), package.get("name") + " " + package.get("version")) and
                       item.get("target", {}).get("src_path", "").replace("\\", "/") == source.replace("\\", "/") and item.get("target", {}).get("name") == crate and
                       tuple(sorted(item.get("features", []))) == features and set(item.get("filenames", [])) == set(produced) and
                       item.get("profile", {}).get("test") is False and item.get("fresh") is False and
                       item.get("target", {}).get("kind") == row.get("kind") and target_crate_types(item.get("target", {})) == types]
            need(len(matches) == 1, "compiler artifact mismatch")
            for path in produced:
                need(path not in outputs_seen, "compiler output ownership collision")
                outputs_seen.add(path)
            identity = (package.get("id", key), context, crate, tuple(row.get("kind", [])), source, features, actual_triple, metadata, extra_filename)
            need(identity not in matched, "duplicate compiler unit")
            matched.add(identity)
            units.append({"package_id": package.get("id", key), "context": context, "target": crate, "kind": tuple(row["kind"]), "source": source,
                          "features": features, "triple": actual_triple, "outputs": tuple(produced), "out_dir": out_dir, "metadata": metadata,
                          "crate_types": types, "extra_filename": extra_filename, "externs": [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--extern"]})
        need(matched and len(matched) == len(artifacts), "missing compiler receipt or artifact")
        return tuple(sorted(units, key=lambda unit: (unit["context"], unit["target"], unit["features"])))
    except AuditError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as exc:
        raise AuditError("malformed compiler unit evidence") from exc


def attach_stdin(proof, nonce='0123456789abcdef'):
    from stdin_probes import NUM_TRAITS_CHECKSUM, AUTOCFG_CHECKSUM, REGISTRY

    attach_capability(proof, ('num-traits', '0.2.19', NUM_TRAITS_CHECKSUM))
    capture = proof['compiler_capture']
    artifacts = proof['artifacts']
    prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
    label = 'num-traits0.2.19.'
    capture['units'].pop()
    capture['receipts'].pop(label + 'capability-0.json', None)
    artifacts.pop(prefix + label + 'capability-0.json', None)
    owner_raw = json.loads(artifacts[prefix + label + 'owner.json'])
    owner_unit = capture['units'][-1]
    meta = next(r for r in proof['records'] if r['kind'] == 'metadata')
    build = next(r for r in proof['records'] if r['kind'] == 'build')
    doc = json.loads(artifacts[meta['stdout']])
    messages = [json.loads(line) for line in artifacts[build['stdout']].splitlines()]
    registry = REGISTRY
    auto_id = registry + '#autocfg@1.5.1'
    auto_root = Path(owner_raw['manifest_dir']).parent / 'autocfg-1.5.1'
    target = Path(capture['context']['env']['CARGO_TARGET_DIR'])
    host_out = target / 'debug/deps/libautocfg-abc.rlib'
    runtime_out = target / capture['wrapper']['target'] / 'debug/build/num-traits-abca/out'
    auto_target = {'name': 'autocfg', 'kind': ['lib'], 'crate_types': ['lib'], 'src_path': str(auto_root / 'src/lib.rs')}
    doc['packages'].append({'id': auto_id, 'name': 'autocfg', 'version': '1.5.1', 'source': registry,
        'manifest_path': str(auto_root / 'Cargo.toml'), 'targets': [auto_target], 'dependencies': []})
    doc['resolve']['nodes'].append({'id': auto_id, 'features': [], 'deps': []})
    nt = next(p for p in doc['packages'] if p['name'] == 'num-traits')
    nt['dependencies'].append({'name': 'autocfg', 'source': registry, 'req': '^1', 'kind': 'build',
        'rename': None, 'optional': False, 'uses_default_features': True, 'features': [], 'target': None, 'registry': None})
    nt_node = next(n for n in doc['resolve']['nodes'] if n['id'] == nt['id'])
    nt_node['deps'].append({'name': 'autocfg', 'pkg': auto_id, 'dep_kinds': [{'kind': 'build', 'target': None}]})
    proof['lock_checksums'][auto_id] = AUTOCFG_CHECKSUM
    template = json.loads(artifacts[prefix + 'unit.json'])

    def publish(raw, name, data):
        raw['snapshots'] = []
        enriched = []
        for index, output in enumerate(raw['outputs']):
            snapshot = label + name + '-outputs/' + str(index)
            blob = data[index]
            artifacts[prefix + snapshot] = blob
            capture['receipts'][snapshot] = hashlib.sha256(blob).hexdigest()
            raw['snapshots'].append({'output': output, 'snapshot': str(Path(capture['context']['env']['SHAAR_CAPTURE_DIR']) / snapshot)})
            enriched.append({'path': output, 'size': len(blob), 'sha256': hashlib.sha256(blob).hexdigest(), 'snapshot_path': snapshot})
        encoded = json.dumps(raw).encode()
        filename = label + name + '.json'
        artifacts[prefix + filename] = encoded
        capture['receipts'][filename] = hashlib.sha256(encoded).hexdigest()
        capture['units'].append(dict(raw, outputs=enriched))

    raw = copy.deepcopy(template)
    raw.update(package_name='autocfg', package_version='1.5.1', cwd=str(auto_root), manifest_dir=str(auto_root),
        args=[str(auto_root / 'src/lib.rs'), '--crate-name', 'autocfg', '--crate-type', 'lib', '--out-dir', str(target / 'debug/deps')],
        outputs=[str(host_out)])
    publish(raw, 'autocfg', [b'autocfg'])
    messages.append({'reason': 'compiler-artifact', 'package_id': auto_id, 'target': auto_target,
        'features': [], 'filenames': [str(host_out)], 'executable': None, 'profile': {'test': False}, 'fresh': False})
    owner_args = owner_raw['args'] + ['--extern', 'autocfg=' + str(host_out)]
    owner_raw['args'] = owner_args
    owner_unit['args'] = owner_args
    owner_encoded = json.dumps(owner_raw).encode()
    artifacts[prefix + label + 'owner.json'] = owner_encoded
    capture['receipts'][label + 'owner.json'] = hashlib.sha256(owner_encoded).hexdigest()
    for index, data in enumerate((b'', b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }')):
        runtime_name = 'autocfg_' + nonce + '_' + str(index)
        stdin_blob = f'inputs-num-{index}/0'
        stdin_snapshot = str(Path(capture['context']['env']['SHAAR_CAPTURE_DIR']) / stdin_blob)
        raw = copy.deepcopy(template)
        raw.update(
            package_name='num-traits',
            package_version='0.2.19',
            cwd=owner_raw['cwd'],
            manifest_dir=owner_raw['manifest_dir'],
            args=[
                '--crate-name',
                runtime_name,
                '--crate-type=lib',
                '--out-dir',
                str(runtime_out),
                '--emit=llvm-ir',
                '--target',
                capture['wrapper']['target'],
                '-',
            ],
            outputs=[str(runtime_out / (runtime_name + '.ll'))],
            stdin={
                'snapshot': stdin_snapshot,
                'size': len(data),
            },
        )
        artifacts[prefix + stdin_blob] = data
        capture['receipts'][stdin_blob] = hashlib.sha256(data).hexdigest()
        publish(raw, 'stdin-' + str(index), [b'LL fixture ' + str(index).encode()])
    next(m for m in messages if m.get('reason') == 'build-script-executed' and m.get('package_id') == nt['id'])['out_dir'] = str(runtime_out)
    for record, data in ((meta, json.dumps(doc).encode()), (build, b''.join((json.dumps(m) + '\n').encode() for m in messages))):
        artifacts[record['stdout']] = data
        record['stdout_sha256'] = hashlib.sha256(data).hexdigest()
    capture['build_stdout_sha256'] = build['stdout_sha256']
    return proof
