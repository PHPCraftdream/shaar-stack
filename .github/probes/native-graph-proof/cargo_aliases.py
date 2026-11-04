# SPDX-License-Identifier: MIT OR Apache-2.0
"""Cargo compiler-artifact output aliases and replay snapshots."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


_CRATE_TYPES = frozenset(('bin', 'lib', 'rlib', 'dylib', 'cdylib', 'staticlib', 'proc-macro'))


def crate_types(args):
    """Parse rustc's repeated crate-type arguments into a canonical tuple."""
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise ValueError('arguments must be strings')
    found = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--crate-type':
            i += 1
            if i >= len(args):
                raise ValueError('missing value for --crate-type')
            value = args[i]
        elif arg.startswith('--crate-type='):
            value = arg[len('--crate-type='):]
        else:
            i += 1
            continue
        if not value or value.startswith('-') or ',' in value or value not in _CRATE_TYPES:
            raise ValueError('invalid --crate-type value')
        if value in found:
            raise ValueError('duplicate --crate-type value')
        found.append(value)
        i += 1
    if not found:
        raise ValueError('missing --crate-type')
    return tuple(sorted(found))


def target_crate_types(row):
    """Validate and canonicalize Cargo metadata crate types."""
    if not isinstance(row, dict):
        raise ValueError('target must be an object')
    values = row.get('crate_types')
    if (not isinstance(values, list) or not values or
            not all(isinstance(value, str) and value in _CRATE_TYPES for value in values) or
            len(set(values)) != len(values)):
        raise ValueError('invalid target crate_types')
    return tuple(sorted(values))


def cargo_output_aliases(unit, artifact, package, target_dir, host, root_manifest):
    """Return aliases only for exact promoted Cargo build-script/library outputs."""
    def reject():
        return None

    try:
        if not all(isinstance(value, dict) for value in (unit, artifact, package)):
            return reject()
        if unit.get('kind') != 'compile' or unit.get('exit_code') != 0 or unit.get('launch_error') is not None:
            return reject()
        raw_outputs = unit.get('outputs')
        if not isinstance(raw_outputs, list):
            return reject()
        outputs = {item['path'] if isinstance(item, dict) else item for item in raw_outputs}
        args = unit.get('args')
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            return reject()

        def flag(name, optional=False):
            found = []
            for i, arg in enumerate(args):
                if arg == name:
                    if i + 1 >= len(args):
                        raise ValueError(f'missing value for {name}')
                    value = args[i + 1]
                    if not value or value.startswith('-'):
                        raise ValueError(f'invalid value for {name}')
                    found.append(value)
                elif arg.startswith(name + '='):
                    value = arg[len(name) + 1:]
                    if not value or value.startswith('-'):
                        raise ValueError(f'invalid value for {name}')
                    found.append(value)
            if len(found) > 1:
                raise ValueError(f'duplicate flag {name}')
            if not found:
                if optional:
                    return None
                raise ValueError(f'missing flag {name}')
            return found[0]

        out_value = flag('--out-dir')
        output_root = Path(out_value)
        if not output_root.is_absolute() or '..' in output_root.parts:
            return reject()
        if any(not isinstance(path, str) or not Path(path).is_absolute() or '..' in Path(path).parts or Path(path).parent != output_root for path in outputs):
            return reject()
        filenames = artifact.get('filenames')
        if not isinstance(filenames, list) or not filenames or not all(isinstance(x, str) for x in filenames) or len(set(filenames)) != len(filenames):
            return reject()
        if artifact.get('package_id') != package.get('id'):
            return reject()
        if unit.get('package_name') != package.get('name') or unit.get('package_version') != package.get('version'):
            return reject()
        manifest_path = Path(package['manifest_path'])
        cwd = Path(unit['cwd'])
        if cwd != manifest_path.parent or Path(unit.get('manifest_dir', '')) != manifest_path.parent:
            return reject()
        row, targets = artifact.get('target'), package.get('targets')
        if not isinstance(row, dict) or not isinstance(targets, list):
            return reject()
        matching = [t for t in targets if isinstance(t, dict) and all(t.get(k) == row.get(k) for k in ('src_path', 'name', 'kind')) and target_crate_types(t) == target_crate_types(row)]
        if len(matching) != 1:
            return reject()
        sources = [arg for arg in args if arg.endswith('.rs')]
        if len(sources) != 1:
            return reject()
        source = Path(sources[0])
        source = source if source.is_absolute() else cwd / source
        if source != Path(row['src_path']):
            return reject()

        features = artifact.get('features')
        if not isinstance(features, list) or not all(isinstance(feature, str) for feature in features):
            return reject()
        cfg_features = []
        for i, arg in enumerate(args):
            value = None
            if arg == '--cfg' and i + 1 < len(args):
                value = args[i + 1]
            elif arg.startswith('--cfg='):
                value = arg[len('--cfg='):]
            if value is not None and value.startswith('feature='):
                feature = json.loads(value[len('feature='):])
                if not isinstance(feature, str) or not feature:
                    return reject()
                cfg_features.append(feature)
        if len(set(cfg_features)) != len(cfg_features) or set(cfg_features) != set(features):
            return reject()
        crate, types = flag('--crate-name'), crate_types(args)
        if crate.replace('-', '_') != row.get('name', '').replace('-', '_') or types != target_crate_types(row):
            return reject()
        target_value = flag('--target', optional=True)
        target_root, out = Path(target_dir), Path(out_value)
        if any(not p.is_absolute() or '..' in p.parts for p in (target_root, out)):
            return reject()
        extras = []
        for i, arg in enumerate(args):
            if arg == '-C' and i + 1 < len(args) and args[i + 1].startswith('extra-filename='):
                extras.append(args[i + 1][len('extra-filename='):])
            elif arg.startswith('-Cextra-filename='):
                extras.append(arg[len('-Cextra-filename='):])
        if len(extras) > 1:
            return reject()
        suffix = extras[0] if extras else None
        if suffix is not None and not re.fullmatch(r'-[0-9a-f]+', suffix):
            return reject()
        if set(filenames).issubset(outputs):
            return []
        if suffix is None:
            return reject()
        if row.get('kind') == ['custom-build'] and row.get('name') == 'build-script-build' and crate == 'build_script_build' and types == ('bin',) and target_value is None and artifact.get('executable') is None:
            base = package['name'] + suffix
            build_dir = target_root / 'debug/build' / base
            ext = '.exe' if 'windows' in host.lower() else ''
            compiled, alias = build_dir / ('build_script_build' + suffix + ext), build_dir / ('build-script-build' + ext)
            if out != build_dir or str(compiled) not in outputs:
                return reject()
            pairs = [{'alias': str(alias), 'direct': str(compiled)}]
            expected = [str(alias)]
            pdb = build_dir / ('build_script_build' + suffix + '.pdb')
            if ext and str(pdb) in outputs:
                pdb_alias = build_dir / 'build_script_build.pdb'
                expected.append(str(pdb_alias))
                pairs.append({'alias': str(pdb_alias), 'direct': str(pdb)})
            if filenames != expected:
                return reject()
            return pairs
        if package.get('name') == 'native-graph-normal-consumer' and Path(package.get('manifest_path', '')) == Path(root_manifest) and row.get('kind') == ['lib'] and row.get('crate_types') == ['lib'] and crate == 'native_graph_normal_consumer' and types == ('lib',) and target_value == host and artifact.get('executable') is None:
            deps = target_root / host / 'debug/deps'
            direct_rlib, direct_meta = deps / ('lib' + crate + suffix + '.rlib'), deps / ('lib' + crate + suffix + '.rmeta')
            alias, alias_meta = deps.parent / ('lib' + crate + '.rlib'), direct_meta
            if out != deps or not {str(direct_rlib), str(direct_meta)}.issubset(outputs) or set(filenames) != {str(alias), str(alias_meta)}:
                return reject()
            return [{'alias': str(alias), 'direct': str(direct_rlib)}]
    except (KeyError, TypeError, ValueError, OSError):
        return None
    return None


def collect_output_aliases(collected, build_stdout, packages, context, manifest, capture_dir):
    """Snapshot Cargo aliases omitted by compiler receipts; validate each artifact."""
    package_by_id = {p.get('id'): p for p in packages}
    records = []
    alias_paths, owned_units = set(), set()
    artifact_index = -1
    for line in build_stdout.splitlines():
        if not line.strip():
            continue
        artifact_index += 1
        artifact = json.loads(line)
        if not isinstance(artifact, dict):
            raise ValueError('Cargo message must be an object')
        if artifact.get('reason') != 'compiler-artifact':
            continue
        package = package_by_id.get(artifact.get('package_id'))
        if package is None:
            raise ValueError('Cargo artifact package is missing from metadata')
        matches = []
        for unit_index, unit in enumerate(collected['units']):
            if (unit.get('package_name') != package.get('name') or unit.get('package_version') != package.get('version') or
                    Path(unit.get('manifest_dir', '')) != Path(package.get('manifest_path', '')).parent):
                continue
            mapping = cargo_output_aliases(unit, artifact, package, context['env']['CARGO_TARGET_DIR'], context.get('host'), manifest)
            if mapping is not None:
                matches.append((unit_index, mapping))
        if len(matches) != 1:
            raise ValueError('Cargo artifact has ambiguous or missing compiler unit')
        unit_index, mapping = matches[0]
        if unit_index in owned_units:
            raise ValueError('Cargo compiler unit reused')
        owned_units.add(unit_index)
        for map_index, pair in enumerate(mapping):
            if pair['alias'] in alias_paths:
                raise ValueError('duplicate alias path')
            alias_paths.add(pair['alias'])
            direct_output = next(o for o in collected['units'][unit_index]['outputs'] if o['path'] == pair['direct'])
            direct_bytes = collected['raw'][direct_output['snapshot_path']]
            alias_path = Path(pair['alias'])
            if any(parent.is_symlink() for parent in alias_path.parents) or alias_path.is_symlink() or not alias_path.is_file() or alias_path.read_bytes() != direct_bytes or Path(pair['direct']).read_bytes() != direct_bytes:
                raise ValueError('Cargo output alias differs from captured direct output')
            snapshot_path = Path(capture_dir) / 'cargo-aliases' / f'{artifact_index}-{map_index}.bin'
            snapshot_path.parent.mkdir(parents=True, exist_ok=True)
            snapshot_path.write_bytes(direct_bytes)
            name = snapshot_path.relative_to(capture_dir).as_posix()
            collected['raw'][name] = direct_bytes
            records.append({'artifact_index': artifact_index, 'unit_index': unit_index, **pair,
                            'snapshot_path': name, 'size': len(direct_bytes), 'sha256': hashlib.sha256(direct_bytes).hexdigest()})
    return records


def audit_output_aliases(proof, packages, messages):
    """Replay alias attribution solely from captured proof data."""
    try:
        capture = proof['compiler_capture']
        units = capture['units']
        records = capture.get('aliases', [])
        if not isinstance(records, list) or not isinstance(units, list):
            raise ValueError('invalid alias capture')
        package_by_id = {p.get('id'): p for p in packages}
        expected, mapped, owners = [], {}, {}
        context = capture['context']
        target_dir = context['env']['CARGO_TARGET_DIR']
        host, manifest = capture['wrapper']['target'], proof['consumer_manifest']
        prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
        raw = {name[len(prefix):]: data for name, data in proof['artifacts'].items() if name.startswith(prefix)}
        alias_paths, owned_units = set(), set()
        for artifact_index, artifact in enumerate(messages):
            if not isinstance(artifact, dict):
                raise ValueError('Cargo message must be an object')
            if artifact.get('reason') != 'compiler-artifact':
                continue
            package = package_by_id.get(artifact.get('package_id'))
            if package is None:
                raise ValueError('unknown artifact package')
            matches = []
            for ui, unit in enumerate(units):
                if (unit.get('package_name') != package.get('name') or unit.get('package_version') != package.get('version') or
                        Path(unit.get('manifest_dir', '')) != Path(package.get('manifest_path', '')).parent):
                    continue
                pairs = cargo_output_aliases(unit, artifact, package, target_dir, host, manifest)
                if pairs is not None:
                    matches.append((ui, pairs))
            if len(matches) != 1:
                raise ValueError('ambiguous or missing artifact unit')
            ui, pairs = matches[0]
            if ui in owned_units:
                raise ValueError('Cargo compiler unit reused')
            owned_units.add(ui)
            filenames = set(artifact.get('filenames', []))
            for oi, pair in enumerate(pairs):
                if pair['alias'] in alias_paths:
                    raise ValueError('duplicate alias path')
                alias_paths.add(pair['alias'])
                direct = next(o for o in units[ui]['outputs'] if o['path'] == pair['direct'])
                snapshot_path = f'cargo-aliases/{artifact_index}-{oi}.bin'
                direct_bytes = raw[direct['snapshot_path']]
                expected.append({'artifact_index': artifact_index, 'unit_index': ui, **pair,
                                 'snapshot_path': snapshot_path, 'size': len(direct_bytes),
                                 'sha256': hashlib.sha256(direct_bytes).hexdigest()})
                filenames.discard(pair['alias'])
                filenames.add(pair['direct'])
            mapped[artifact_index] = filenames
            owners[artifact_index] = ui
        if records != expected:
            raise ValueError('alias records do not match Cargo replay')
        blobs = {name for name in raw if name.startswith('cargo-aliases/')}
        if blobs != {r['snapshot_path'] for r in expected}:
            raise ValueError('orphan or missing alias snapshots')
        for record in expected:
            data = raw[record['snapshot_path']]
            direct = next(o for o in units[record['unit_index']]['outputs'] if o['path'] == record['direct'])
            direct_sha = direct['sha256']
            if (not isinstance(data, bytes) or data != raw[direct['snapshot_path']] or
                    len(data) != record['size'] or hashlib.sha256(data).hexdigest() != record['sha256'] or
                    direct.get('size') != len(data) or direct_sha != record['sha256']):
                raise ValueError('alias snapshot differs from direct output')
        return mapped, owners
    except (KeyError, TypeError, ValueError, OSError, StopIteration) as exc:
        raise ValueError('invalid Cargo output alias evidence') from exc
