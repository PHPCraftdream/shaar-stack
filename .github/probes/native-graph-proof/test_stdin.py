# SPDX-License-Identifier: MIT OR Apache-2.0
"""Regression tests for stdin-backed native graph proofs."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
for directory in (HERE.parent / 'native-graph' / 'fixture', HERE):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import features
from stdin_probes import classify, audit

NUM = '071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841'
AUTO = 'f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53'
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'


class StdinProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='stdin-num-traits-')
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, data=b'', index=0):
        root = self.root
        target = root / 'target'
        host = 'x86_64-unknown-linux-gnu'
        out = target / host / 'debug/build/num-traits-abcd/out'
        out.mkdir(parents=True, exist_ok=True)
        manifest = root / 'Cargo.toml'
        package_id = f'{REGISTRY}#num-traits@0.2.19'
        autocfg_id = f'{REGISTRY}#autocfg@1.5.1'
        crate = 'autocfg_0123456789abcdef_' + str(index)
        output = out / (crate + '.ll')
        packages = [{
            'id': package_id, 'name': 'num-traits', 'version': '0.2.19',
            'source': REGISTRY, 'manifest_path': str(manifest),
            'dependencies': [{'name': 'autocfg', 'kind': 'build', 'source': REGISTRY,
                             'rename': None, 'target': None, 'optional': False}],
            'targets': [
                {'name': 'num_traits', 'kind': ['lib'], 'crate_types': ['lib'],
                 'src_path': str(root / 'src/lib.rs')},
                {'name': 'build-script-build', 'kind': ['custom-build'],
                 'crate_types': ['bin'], 'src_path': str(root / 'build.rs')},
            ],
        }, {
            'id': autocfg_id, 'name': 'autocfg', 'version': '1.5.1',
            'source': REGISTRY, 'manifest_path': str(root.parent / 'autocfg-1.5.1/Cargo.toml'),
            'dependencies': [],
            'targets': [{'name': 'autocfg', 'kind': ['lib'], 'crate_types': ['lib'],
                         'src_path': str(root.parent / 'autocfg-1.5.1/src/lib.rs')}],
        }]
        raw = {
            'args': ['--crate-name', crate, '--crate-type=lib', '--out-dir', str(out),
                     '--emit=llvm-ir', '--target', host, '-'],
            'outputs': [str(output)], 'kind': 'compile', 'exit_code': 0,
            'launch_error': None, 'package_name': 'num-traits',
            'package_version': '0.2.19', 'cwd': str(root), 'manifest_dir': str(root),
            'stdin': {'snapshot': str(root / 'capture/inputs/0'), 'size': len(data)},
        }
        checksums = {package_id: NUM, autocfg_id: AUTO}
        return raw, target, host, packages, checksums, data

    def test_empty_stdin_nonce_invariance(self):
        raw, target, host, packages, checksums, data = self.fixture(b'', 0)
        proof = classify(raw, target, host, packages, checksums, data)
        self.assertIsNotNone(proof)
        self.assertEqual((proof['counter'], proof['source']), (0, ''))
        second, *_ = self.fixture(b'', 0)
        second_crate = 'autocfg_fedcba9876543210_0'
        second['args'][1] = second_crate
        second['outputs'][0] = str(Path(second['outputs'][0]).with_name(second_crate + '.ll'))
        repeated = classify(second, target, host, packages, checksums, data)
        self.assertIsNotNone(repeated)
        self.assertEqual((proof['counter'], proof['source']),
                         (repeated['counter'], repeated['source']))

    def test_expression_stdin_nonce_invariance(self):
        data = b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }'
        raw, target, host, packages, checksums, _ = self.fixture(data, 1)
        proof = classify(raw, target, host, packages, checksums, data)
        self.assertIsNotNone(proof)
        self.assertEqual((proof['counter'], proof['source']), (1, data.decode()))
        second, *_ = self.fixture(data, 1)
        second_crate = 'autocfg_fedcba9876543210_1'
        second['args'][1] = second_crate
        second['outputs'][0] = str(Path(second['outputs'][0]).with_name(second_crate + '.ll'))
        repeated = classify(second, target, host, packages, checksums, data)
        self.assertIsNotNone(repeated)
        self.assertEqual((proof['counter'], proof['source']),
                         (repeated['counter'], repeated['source']))

    def test_mutated_evidence_is_rejected(self):
        data = b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }'
        raw, target, host, packages, checksums, _ = self.fixture(data, 1)
        self.assertIsNotNone(classify(raw, target, host, packages, checksums, data))
        mutations = []
        mutations.append((copy.deepcopy(raw), target, host, packages, checksums, b'wrong source'))
        changed = copy.deepcopy(raw)
        changed['stdin']['size'] += 1
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['args'][1] = 'autocfg_0123456789abcdef_2'
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['outputs'][0] = str(Path(changed['outputs'][0]).parent / 'wrong.ll')
        mutations.append((changed, target, host, packages, checksums, data))
        mutations.append((copy.deepcopy(raw), target, 'aarch64-unknown-linux-gnu', packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['args'].append('--cfg=unexpected')
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['args'].append('--cfg=feature=unexpected')
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['package_name'] = 'other'
        mutations.append((changed, target, host, packages, checksums, data))
        wrong_checksums = dict(checksums)
        wrong_checksums[next(iter(wrong_checksums))] = '0' * 64
        mutations.append((copy.deepcopy(raw), target, host, packages, wrong_checksums, data))
        wrong_packages = copy.deepcopy(packages)
        wrong_packages[0]['dependencies'] = []
        mutations.append((copy.deepcopy(raw), target, host, wrong_packages, checksums, data))
        auto_checksum = dict(checksums)
        auto_checksum[next(iter(auto_checksum.keys() - {next(k for k in checksums if '#num-traits@' in k)}))] = '0' * 64
        mutations.append((copy.deepcopy(raw), target, host, packages, auto_checksum, data))
        changed = copy.deepcopy(raw)
        changed['stdin'] = None
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['exit_code'] = 1
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['launch_error'] = 'compiler launch failed'
        mutations.append((changed, target, host, packages, checksums, data))
        changed = copy.deepcopy(raw)
        changed['args'][changed['args'].index('--out-dir') + 1] = str(target / 'wrong')
        mutations.append((changed, target, host, packages, checksums, data))
        other_source_packages = copy.deepcopy(packages)
        other_source_packages[0]['targets'][1]['src_path'] = str(self.root / 'other.rs')
        mutations.append((copy.deepcopy(raw), target, host, other_source_packages, checksums, data))
        old_auto = packages[1]['id']
        changed_auto_packages = copy.deepcopy(packages)
        changed_auto_packages[1]['version'] = '1.5.0'
        changed_auto_packages[1]['id'] = old_auto.replace('autocfg@1.5.1', 'autocfg@1.5.0')
        mutations.append((copy.deepcopy(raw), target, host, changed_auto_packages, checksums, data))
        for candidate in mutations:
            with self.subTest(candidate=candidate[0]):
                self.assertIsNotNone(classify(raw, target, host, packages, checksums, data))
                self.assertIsNone(classify(*candidate))

    def test_production_stdin_audit_owners_and_nonce(self):
        raws = []
        shapes = []
        data_by_counter = (b'', b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }')
        host = 'x86_64-unknown-linux-gnu'
        capture = self.root / 'capture'
        capture.mkdir()
        for counter, data in enumerate(data_by_counter):
            raw, target, _, packages, checksums, _ = self.fixture(data, counter)
            raw['nonce'] = 'nonce-one'
            raw['stdin']['snapshot'] = str(capture / f'inputs/{counter}')
            shape = classify(raw, target, host, packages, checksums, data)
            self.assertIsNotNone(shape)
            raws.append(raw)
            shapes.append(shape)
        package, auto = packages
        unit = {'context': 'host', 'sha256': 'a' * 64, 'dependencies': [
            {'alias': 'autocfg', 'kind': ['build'], 'unit': {
                'package': 'registry+https://github.com/rust-lang/crates.io-index#autocfg@1.5.1',
                'context': 'host', 'kind': ['lib']}}]}
        row = {'kind': ['custom-build']}
        artifacts = [{'package_id': package['id'], 'target': {'kind': ['custom-build']}, 'executable': None}]
        nodes = {package['id']: {'deps': [{'name': 'autocfg', 'pkg': auto['id'],
            'dep_kinds': [{'kind': 'build', 'target': None}]}]}}
        messages = [{'reason': 'build-script-executed', 'package_id': package['id'], 'out_dir': shapes[0]['out_dir']}]
        proof = {'artifacts': {'consumer/compiler-capture/inputs/0': data_by_counter[0],
                               'consumer/compiler-capture/inputs/1': data_by_counter[1]},
                 'compiler_capture': {'context': {'env': {'SHAAR_CAPTURE_DIR': str(capture),
                     'CARGO_TARGET_DIR': str(target)}}, 'wrapper': {'target': host}},
                 'consumer_cwd': str(self.root / 'consumer'), 'lock_checksums': checksums}
        def owners(cargo, owner=unit, owner_package=package):
            return {id(cargo[0]): (owner, owner_package, row)}
        cargo = copy.deepcopy(artifacts)
        args = (list(zip(raws, shapes)), proof, packages, cargo, messages,
                owners(cargo), lambda value:value['id'], nodes)
        result = audit(*args)
        self.assertEqual(len(result), 2)
        changed_raws = copy.deepcopy(raws)
        for raw in changed_raws:
            crate = 'autocfg_fedcba9876543210_' + raw['args'][1].rsplit('_', 1)[1]
            raw['args'][1] = crate
            raw['outputs'] = [str(Path(raw['outputs'][0]).with_name(crate + '.ll'))]
        changed_shapes = [classify(raw, target, host, packages, checksums, data)
                          for raw, data in zip(changed_raws, data_by_counter)]
        changed_cargo = copy.deepcopy(artifacts)
        changed_args = (list(zip(changed_raws, changed_shapes)), proof, packages, changed_cargo,
                        messages, owners(changed_cargo), lambda value:value['id'], nodes)
        self.assertEqual(result, audit(*changed_args))
        cases = []
        changed = copy.deepcopy(raws)
        changed[0]['stdin']['size'] += 1
        cases.append((changed, shapes, packages, artifacts, messages, unit, package, nodes))
        cases.append((copy.deepcopy(raws), shapes, packages, artifacts, messages, unit, package,
                      {package['id']: {'deps': []}}))
        cases.append((copy.deepcopy(raws), shapes, packages, artifacts, messages,
                      {'context': 'target', 'sha256': 'a' * 64, 'dependencies': unit['dependencies']}, package, nodes))
        cases.append((copy.deepcopy(raws), shapes, packages, artifacts, messages, unit, package, nodes, True))
        cases.append((copy.deepcopy(raws + [copy.deepcopy(raws[0])]), shapes + [shapes[0]], packages,
                      artifacts, messages, unit, package, nodes))
        for raws_case, shape_case, packages_case, cargo_case, messages_case, owner_case, owner_package_case, nodes_case, *missing in cases:
            audit(*args)
            with self.subTest(missing=missing):
                cargo_copy = copy.deepcopy(cargo_case)
                owned = {} if missing else owners(cargo_copy, owner_case, owner_package_case)
                probe_pairs = list(zip(raws_case, shape_case))
                if missing:
                    probe_pairs[0][0].pop('stdin')
                with self.assertRaises(ValueError):
                    audit(probe_pairs, proof, packages_case, cargo_copy, messages_case, owned,
                          lambda value:value['id'], nodes_case)

    def test_full_production_audit_path(self):
        from test_features import _proofs
        from test_alias_integration import AliasIntegrationTests
        from capability_fixture import attach_capability, attach_stdin

        helper = AliasIntegrationTests()
        proof = helper._root_alias(attach_capability(_proofs()[2]))
        proof = attach_stdin(proof)
        helper.collect_and_audit(proof, expected_aliases=6)

    def test_three_proof_stdin_comparison_and_mutations(self):
        from test_features import _proofs, _compare
        from test_alias_integration import AliasIntegrationTests
        from capability_fixture import attach_capability, attach_stdin

        helper = AliasIntegrationTests()

        def fresh():
            return [attach_stdin(helper._root_alias(attach_capability(proof)), nonce=(
                '0123456789abcdef' if proof['role'] == 'baseline' else
                '722b072ff7e63095' if proof['role'] == 'approved_route' else
                '8ad895b48a880bcb')) for proof in _proofs()]

        def refresh_raw(proof, raw_name, raw):
            prefix = Path(proof['consumer_cwd']).name + '/compiler-capture/'
            capture = proof['compiler_capture']
            old = json.loads(proof['artifacts'][prefix + raw_name])
            unit = next(u for u in capture['units'] if all(u.get(k) == v for k, v in old.items() if k != 'outputs'))
            if 'stdin' not in raw:
                unit.pop('stdin', None)
            unit.update({k: v for k, v in raw.items() if k != 'outputs'})
            encoded = json.dumps(raw).encode()
            proof['artifacts'][prefix + raw_name] = encoded
            capture['receipts'][raw_name] = hashlib.sha256(encoded).hexdigest()

        for mutation in ('source', 'checksum', 'route', 'args', 'context', 'missingstdin',
                         'snapshot', 'duplicate', 'owner', 'autocfg-checksum', 'feature', 'forgedunit'):
            proofs = fresh()
            _compare(proofs)
            candidate = proofs[2]
            capture = candidate['compiler_capture']
            prefix = Path(candidate['consumer_cwd']).name + '/compiler-capture/'
            raw_name = 'num-traits0.2.19.stdin-1.json'
            raw = json.loads(candidate['artifacts'][prefix + raw_name])
            unit = next(u for u in capture['units'] if u.get('package_name') == 'num-traits' and
                        u.get('args') == raw['args'])
            if mutation == 'source':
                data = b'pub fn probe() { let _ = 2f64.total_cmp(&2f64); }'
                blob_name = Path(raw['stdin']['snapshot']).relative_to(Path(capture['context']['env']['SHAAR_CAPTURE_DIR'])).as_posix()
                candidate['artifacts'][prefix + blob_name] = data
                capture['receipts'][blob_name] = hashlib.sha256(data).hexdigest()
                raw['stdin']['size'] = len(data)
            elif mutation == 'checksum':
                key = next(k for k in candidate['lock_checksums'] if '#num-traits@' in k)
                candidate['lock_checksums'][key] = '0' * 64
            elif mutation == 'autocfg-checksum':
                key = next(k for k in candidate['lock_checksums'] if '#autocfg@' in k)
                candidate['lock_checksums'][key] = '0' * 64
            elif mutation == 'feature':
                raw['args'].append('--cfg=feature=forged')
            elif mutation == 'forgedunit':
                raw['package_name'] = 'shaar'
                raw['package_version'] = '0.1.0'
                ordinary = next(u for u in capture['units'] if u.get('package_name') != 'num-traits')
                raw['cwd'] = ordinary['cwd']
                raw['manifest_dir'] = ordinary['manifest_dir']
            elif mutation == 'route':
                meta = next(r for r in candidate['records'] if r['kind'] == 'metadata')
                doc = json.loads(candidate['artifacts'][meta['stdout']])
                next(node for node in doc['resolve']['nodes'] if '#num-traits@0.2.19' in node['id'])['deps'] = []
                encoded = json.dumps(doc).encode()
                candidate['artifacts'][meta['stdout']] = encoded
                meta['stdout_sha256'] = hashlib.sha256(encoded).hexdigest()
            elif mutation == 'args':
                raw['args'].append('--cfg=unexpected')
            elif mutation == 'context':
                raw['cwd'] = '/foreign'
            elif mutation == 'missingstdin':
                blob_name = Path(raw['stdin']['snapshot']).relative_to(Path(capture['context']['env']['SHAAR_CAPTURE_DIR'])).as_posix()
                candidate['artifacts'].pop(prefix + blob_name)
                capture['receipts'].pop(blob_name)
                raw.pop('stdin')
            elif mutation == 'snapshot':
                blob_name = unit['outputs'][0]['snapshot_path']
                candidate['artifacts'][prefix + blob_name] += b'!'
                capture['receipts'][blob_name] = hashlib.sha256(candidate['artifacts'][prefix + blob_name]).hexdigest()
            elif mutation == 'duplicate':
                duplicate = copy.deepcopy(raw)
                duplicate_name = 'forged-stdin-duplicate.json'
                encoded = json.dumps(duplicate).encode()
                candidate['artifacts'][prefix + duplicate_name] = encoded
                capture['receipts'][duplicate_name] = hashlib.sha256(encoded).hexdigest()
                capture['units'].append(copy.deepcopy(unit))
            elif mutation == 'owner':
                build = next(r for r in candidate['records'] if r['kind'] == 'build')
                messages = [json.loads(line) for line in candidate['artifacts'][build['stdout']].splitlines()]
                messages = [m for m in messages if not (m.get('reason') == 'build-script-executed' and m.get('package_id', '').endswith('#num-traits@0.2.19'))]
                encoded = b'\n'.join(json.dumps(m).encode() for m in messages)
                candidate['artifacts'][build['stdout']] = encoded
                build['stdout_sha256'] = hashlib.sha256(encoded).hexdigest()
                capture['build_stdout_sha256'] = build['stdout_sha256']
            if mutation in ('source', 'args', 'context', 'missingstdin', 'feature', 'forgedunit'):
                refresh_raw(candidate, raw_name, raw)
            with self.subTest(mutation=mutation), self.assertRaises(features.AuditError):
                _compare(proofs)

    def test_collect_capture_preserves_stdin_evidence(self):
        root = self.root
        target, capture = root / 'target', root / 'capture'
        target.mkdir()
        capture.mkdir()
        host = 'x86_64-unknown-linux-gnu'
        wrapper, compiler = root / 'wrapper', root / 'rustc'
        wrapper.touch()
        compiler.touch()
        context = {'role': 'candidate', 'revision': 'fixture', 'nonce': 'fixture',
                   'recipe_sha256': 'a' * 64, 'compiler': str(compiler), 'host': host,
                   'packages': [], 'lock_checksums': {},
                   'env': {'RUSTC_WRAPPER': str(wrapper), 'RUSTC_WORKSPACE_WRAPPER': '',
                           'CARGO_TARGET_DIR': str(target)}}
        ordinary_dir = target / host / 'debug/deps'
        ordinary_dir.mkdir(parents=True)
        ordinary_output = ordinary_dir / 'libdemo.rlib'
        ordinary_output.write_bytes(b'ordinary output')

        def receipt(name, raw):
            raw.update(schema=1, role='candidate', revision='fixture', nonce='fixture',
                       recipe_sha256='a' * 64, compiler=str(compiler), env=context['env'])
            (capture / name).write_text(json.dumps(raw), encoding='utf-8')

        ordinary_snap = capture / 'outputs-normal/0'
        ordinary_snap.parent.mkdir()
        ordinary_snap.write_bytes(b'ordinary output')
        receipt('00-normal.json', {'kind': 'compile', 'exit_code': 0, 'launch_error': None,
            'package_name': 'demo', 'package_version': '1.0', 'cwd': str(root),
            'manifest_dir': str(root), 'args': ['--crate-name', 'demo', '--crate-type=lib',
            '--out-dir', str(ordinary_dir)], 'outputs': [str(ordinary_output)],
            'snapshots': [{'output': str(ordinary_output), 'snapshot': str(ordinary_snap)}]})
        for index, data in enumerate((b'', b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }')):
            raw, _, _, packages, checksums, _ = self.fixture(data, index)
            context['packages'] = packages
            context['lock_checksums'] = checksums
            raw.update(schema=1, role='candidate', revision='fixture', nonce='fixture',
                       recipe_sha256='a' * 64, compiler=str(compiler), env=context['env'])
            out_snap = capture / f'outputs-stdin-{index}/0'
            in_snap = capture / f'inputs-{index}/0'
            out_snap.parent.mkdir()
            in_snap.parent.mkdir()
            out_snap.write_bytes(b'stored ll bytes')
            in_snap.write_bytes(data)
            raw['snapshots'] = [{'output': raw['outputs'][0], 'snapshot': str(out_snap)}]
            raw['stdin']['snapshot'] = str(in_snap)
            (capture / f'{index + 1:02}-stdin.json').write_text(json.dumps(raw), encoding='utf-8')
        result = features.collect_capture(capture, target, context)
        self.assertEqual(len(result['units']), 3)
        self.assertEqual(ordinary_snap.read_bytes(), b'ordinary output')
        self.assertEqual((capture / 'outputs-stdin-0/0').read_bytes(), b'stored ll bytes')
        self.assertEqual((capture / 'outputs-stdin-1/0').read_bytes(), b'stored ll bytes')
        self.assertEqual((capture / 'inputs-0/0').read_bytes(), b'')
        self.assertEqual((capture / 'inputs-1/0').read_bytes(), b'pub fn probe() { let _ = 1f64.total_cmp(&2f64); }')
        changed = json.loads((capture / '02-stdin.json').read_text(encoding='utf-8'))
        changed['stdin']['size'] = 0
        (capture / '02-stdin.json').write_text(json.dumps(changed), encoding='utf-8')
        with self.assertRaises(ValueError):
            features.collect_capture(capture, target, context)


if __name__ == '__main__':
    unittest.main()
