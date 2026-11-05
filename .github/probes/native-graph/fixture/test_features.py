# SPDX-License-Identifier: MIT OR Apache-2.0
"""Synthetic proof-contract tests for compare_proofs; no Cargo or repository inputs."""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import AuditError, audit_compiler_units, compare_proofs, _metadata

_HEX = "a" * 64
_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
_CONTROL = {"root_manifest_sha256": _HEX, "route_recipe_id": "fixture-route-v1"}


def _compare(proofs):
    return compare_proofs(proofs, "base-revision", "candidate-revision", _CONTROL)


def _proof(role, revision, relay=False):
    cwd = str(Path('/tmp/native-graph-' + role).resolve())
    manifest = str(Path(cwd) / 'Cargo.toml')
    root_id = f"path+file://{cwd}#native-graph-{role}@0.0.0"
    shaar_id = "path+file:///repo#shaar@0.1.0"
    base_id = "registry+https://github.com/rust-lang/crates.io-index#iroh-base@1.3.0"
    packages = [
        {"id": root_id, "name": "native-graph-normal-consumer", "version": "0.0.0", "manifest_path": manifest},
        {"id": shaar_id, "name": "shaar", "version": "0.1.0", "manifest_path": str(Path('/repo/Cargo.toml').resolve())},
        {"id": base_id, "name": "iroh-base", "version": "1.3.0", "source": _REGISTRY},
    ]
    enabled = ["key", "relay"] if relay else ["key"]
    metadata = {"packages": packages, "workspace_root": cwd, "workspace_members": [root_id],
                "resolve": {"nodes": [
                    {"id": root_id, "deps": [{"pkg": shaar_id, "dep_kinds": [{"kind": "normal"}]}], "features": []},
                    {"id": shaar_id, "deps": [{"pkg": base_id, "dep_kinds": [{"kind": "normal"}]}], "features": []},
                    {"id": base_id, "deps": [], "features": enabled},
                ]}}
    tree = f"native-graph-normal-consumer v0.0.0 ({cwd})\n└── shaar v0.1.0 (/repo)\n    └── iroh-base v1.3.0\n".encode()
    build = (json.dumps({"reason": "compiler-artifact", "package_id": shaar_id,
                         "profile": {"test": False}, "target": {"kind": ["lib"]}, "features": []}) + "\n").encode()
    outputs = {"metadata": json.dumps(metadata).encode(), "tree": tree, "build": build}
    artifacts, records = {}, []
    commands = {
        "metadata": ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", manifest],
        "tree": ["cargo", "tree", "--locked", "--edges", "normal,features", "--manifest-path", manifest],
        "build": ["cargo", "build", "--locked", "--lib", "--message-format=json", "--manifest-path", manifest],
    }
    for kind, data in outputs.items():
        out, err = kind + ".stdout", kind + ".stderr"
        artifacts[out], artifacts[err] = data, b""
        records.append({"kind": kind, "argv": commands[kind], "cwd": cwd, "exit_code": 0,
                        "stdout": out, "stdout_sha256": hashlib.sha256(data).hexdigest(),
                        "stderr": err, "stderr_sha256": hashlib.sha256(b"").hexdigest()})
    proof = {"role": role, "context": "normal", "revision": revision,
             "consumer_manifest": manifest, "consumer_cwd": cwd,
             "records": records, "artifacts": artifacts,
             "lock_checksums": {base_id: _HEX},
             "source_bindings": {shaar_id: {"package": "shaar", "version": "0.1.0",
                                             "identity": "workspace", "archive_sha256": _HEX,
                                             "tree_sha256": _HEX}}}
    if role == "approved_route":
        proof.update(base_manifest_sha256=_HEX, route_recipe_id="fixture-route-v1",
                     approved_feature_deltas=[{"package": ["iroh-base", "1.3.0", _REGISTRY + ":" + _HEX],
                                               "baseline": ["key"], "approved_route": ["key", "relay"]}])
    import verify_once
    return verify_once.attach_unit_proof(proof)


def _proofs():
    return [_proof("baseline", "base-revision"),
            _proof("approved_route", "base-revision", relay=True),
            _proof("candidate", "candidate-revision", relay=True)]


def _refresh_metadata(proof, change):
    record = next(r for r in proof["records"] if r["kind"] == "metadata")
    data = json.loads(proof["artifacts"][record["stdout"]])
    change(data)
    encoded = json.dumps(data).encode()
    proof["artifacts"][record["stdout"]] = encoded
    record["stdout_sha256"] = hashlib.sha256(encoded).hexdigest()


def _add_serde_bencode(proof):
    package_id = "path+file:///prepared/serde_bencode-0.2.4#serde_bencode@0.2.4"
    package = {"id": package_id, "name": "serde_bencode", "version": "0.2.4",
               "manifest_path": "/prepared/serde_bencode-0.2.4/Cargo.toml"}
    binding = {"package": "serde_bencode", "version": "0.2.4", "identity": "prepared",
               "archive_sha256": "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e",
               "tree_sha256": "b" * 64, "recipe_sha256": "c" * 64}
    def add(doc):
        doc["packages"].append(package)
        shaar_id = next(p["id"] for p in doc["packages"] if p["name"] == "shaar")
        doc["resolve"]["nodes"].append({"id": package_id, "deps": [], "features": []})
        shaar = next(n for n in doc["resolve"]["nodes"] if n["id"] == shaar_id)
        shaar["deps"].append({"pkg": package_id, "dep_kinds": [{"kind": "normal"}]})
    _refresh_metadata(proof, add)
    proof["source_bindings"][package_id] = dict(binding)


def _add_route(proof):
    packages = [
        ("crc", "3.4.0", "5eb8a2a1cd12ab0d987a5d5e825195d372001a4094a0376319d5a0ad71c1ba0d"),
        ("crc-catalog", "2.5.0", "217698eaf96b4a3f0bc4f3662aaa55bdf913cd54d7204591faa790070c6d0853"),
        ("dyn-clone", "1.0.20", "d0881ea181b1df73ff77ffaaf9c7544ecc11e82fba9b5f27b262a3c73a332555"),
    ]
    n0_id = "path+file:///prepared/n0-mainline-0.7.0#n0-mainline@0.7.0"
    package_docs = [{"id": n0_id, "name": "n0-mainline", "version": "0.7.0",
                    "manifest_path": "/prepared/n0-mainline-0.7.0/Cargo.toml"}]
    registry_ids = {}
    for name, version, checksum in packages:
        package_id = f"{_REGISTRY}#{name}@{version}"
        registry_ids[name] = package_id
        package_docs.append({"id": package_id, "name": name, "version": version, "source": _REGISTRY})
    binding = {"package": "n0-mainline", "version": "0.7.0", "identity": "prepared",
               "archive_sha256": "f64972176bd209d1ebe98310743614e19728a33a4b288ae8147cca9f0b8c7463",
               "tree_sha256": "b" * 64, "recipe_sha256": "c" * 64}
    def add(doc):
        doc["packages"].extend(copy.deepcopy(package_docs))
        nodes = doc["resolve"]["nodes"]
        shaar_id = next(p["id"] for p in doc["packages"] if p["name"] == "shaar")
        base_id = next(p["id"] for p in doc["packages"] if p["name"] == "iroh-base")
        nodes.append({"id": n0_id, "deps": [{"pkg": registry_ids["crc"], "dep_kinds": [{"kind": "normal"}]},
                                                {"pkg": registry_ids["dyn-clone"], "dep_kinds": [{"kind": "normal"}]},
                                                {"pkg": base_id, "dep_kinds": [{"kind": "normal"}]}], "features": []})
        nodes.append({"id": registry_ids["crc"], "deps": [{"pkg": registry_ids["crc-catalog"], "dep_kinds": [{"kind": "normal"}]}], "features": []})
        nodes.append({"id": registry_ids["crc-catalog"], "deps": [], "features": []})
        nodes.append({"id": registry_ids["dyn-clone"], "deps": [], "features": []})
        next(n for n in nodes if n["id"] == shaar_id)["deps"].append({"pkg": n0_id, "dep_kinds": [{"kind": "normal"}]})
    _refresh_metadata(proof, add)
    proof["source_bindings"][n0_id] = binding
    proof["lock_checksums"].update({f"{_REGISTRY}#{name}@{version}": checksum for name, version, checksum in packages})


def _approve_actual_control_delta(proofs):
    baseline = _metadata(proofs[0])[4]
    control = _metadata(proofs[1])[4]
    proofs[1]["approved_feature_deltas"] = [
        {"package": list(key), "baseline": list(baseline.get(key, ())),
         "approved_route": list(control.get(key, ()))}
        for key in sorted(set(baseline) | set(control))
        if baseline.get(key) != control.get(key)
    ]


def _add_n0future(proof, baseline=False):
    exactnative = 'cfg(not(all(target_family = "wasm", target_os = "unknown")))'
    tokio = _REGISTRY + "#tokio@1.54.1"
    n0future = _REGISTRY + "#n0-future@0.3.2" if baseline else "path+file:///prepared/n0-future-0.3.2#n0-future@0.3.2"
    shaar = next(p["id"] for p in json.loads(proof["artifacts"][next(r for r in proof["records"] if r["kind"] == "metadata")["stdout"]])["packages"] if p["name"] == "shaar")
    iroh = _REGISTRY + "#iroh@1.3.0"
    def add(doc):
        for name, pid in (("iroh", iroh), ("n0-future", n0future), ("tokio", tokio)):
            package = {"id": pid, "name": name, "version": "1.3.0" if name == "iroh" else "0.3.2" if name == "n0-future" else "1.54.1"}
            if name != 'n0-future' or baseline:
                package['source'] = _REGISTRY
            else:
                package['manifest_path'] = '/prepared/n0-future-0.3.2/Cargo.toml'
            if name == "n0-future":
                package["dependencies"] = [{"name": "tokio", "req": "^1.28", "kind": None, "target": exactnative, "features": ["rt", "time", "macros"] + (["test-util"] if baseline else []), "source": _REGISTRY}]
                if not baseline:
                    package["dependencies"].append({"name": "tokio", "req": "^1.28", "kind": "dev", "target": exactnative, "features": ["test-util"], "source": _REGISTRY})
                package["dependencies"].append({"name": "tokio", "req": "^1.28", "kind": None, "target": None, "features": [], "source": _REGISTRY})
            elif name == "iroh":
                package["dependencies"] = [{"name": "n0-future", "req": "^0.3", "kind": None, "target": None, "features": [], "source": _REGISTRY if baseline else None}]
            doc["packages"].append(package)
            features = ["rt", "time", "macros"] + (["test-util"] if baseline else []) if name == "tokio" else []
            doc["resolve"]["nodes"].append({"id": pid, "deps": [], "features": features})
        nodes = {n["id"]: n for n in doc["resolve"]["nodes"]}
        nodes[shaar]["deps"].append({"pkg": iroh, "dep_kinds": [{"kind": "normal"}]})
        nodes[iroh]["deps"].append({"pkg": n0future, "dep_kinds": [{"kind": "normal"}]})
        nodes[n0future]["deps"].append({"pkg": tokio, "dep_kinds": [{"kind": "normal"}]})
    _refresh_metadata(proof, add)
    if baseline:
        proof["lock_checksums"][n0future] = "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe"
    else:
        proof["source_bindings"][n0future] = {"package": "n0-future", "version": "0.3.2", "identity": "prepared", "archive_sha256": "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe", "tree_sha256": "b" * 64, "recipe_sha256": "c" * 64}
    proof["lock_checksums"].update({tokio: "b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3", iroh: "d" * 64})


def _n0future_proofs():
    proofs = _proofs()
    _add_n0future(proofs[0], baseline=True)
    for proof in proofs[1:]:
        _add_n0future(proof)
    _approve_actual_control_delta(proofs)
    return proofs


class CompareProofsTests(unittest.TestCase):
    def test_n0future_three_role_tokio_feature_comparison(self):
        proofs = _n0future_proofs()
        from verify_once import append_tokio_unit
        append_tokio_unit(proofs[0])
        result = _compare(proofs)
        self.assertEqual(result["roles"], ["baseline", "approved_route", "candidate"])
        self.assertTrue(any(d["package"][0] == "tokio" and d["baseline"] == ["macros", "rt", "test-util", "time"] and d["approved_route"] == ["macros", "rt", "time"] for d in result["feature_deltas"]))

    def test_n0future_rejects_nonbaseline_testutil_and_graph_or_archive_drift(self):
        mutations = ("control-testutil", "candidate-testutil", "other-testutil", "source", "checksum", "native-target", "owner", "tokio-feature", "archive")
        for mutation in mutations:
            proofs = _n0future_proofs()
            target = proofs[1] if mutation == "control-testutil" else proofs[2]
            if mutation in ("control-testutil", "candidate-testutil", "other-testutil", "source", "native-target", "owner", "tokio-feature"):
                def change(doc):
                    packages = {p["name"]: p for p in doc["packages"]}
                    nodes = {n["id"]: n for n in doc["resolve"]["nodes"]}
                    if mutation in ("control-testutil", "candidate-testutil"):
                        nodes[packages["tokio"]["id"]]["features"].append("test-util")
                    elif mutation == "other-testutil":
                        nodes[packages["iroh-base"]["id"]]["features"].append("test-util")
                    elif mutation == "source":
                        packages["iroh"]["source"] = "registry+https://wrong.invalid/index"
                    elif mutation == "native-target":
                        nodes[packages["n0-future"]["id"]]["deps"][0]["dep_kinds"] = [{"kind": "dev"}]
                    elif mutation == "owner":
                        nodes[packages["shaar"]["id"]]["deps"].remove(next(d for d in nodes[packages["shaar"]["id"]]["deps"] if d["pkg"] == packages["iroh"]["id"]))
                    else:
                        nodes[packages["tokio"]["id"]]["features"].append("net")
                _refresh_metadata(target, change)
            elif mutation == "checksum":
                target["lock_checksums"][_REGISTRY + "#tokio@1.54.1"] = "0" * 64
            else:
                target["source_bindings"][next(k for k in target["source_bindings"] if "n0-future" in k)]["archive_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _approve_actual_control_delta(proofs)
                _compare(proofs)

    def test_refresh_metadata_updates_artifact_and_digest_without_losing_lock_binding(self):
        proofs = _proofs()
        _compare(copy.deepcopy(proofs))
        candidate = proofs[2]
        record = next(r for r in candidate["records"] if r["kind"] == "metadata")
        old_bytes = candidate["artifacts"][record["stdout"]]
        lock_checksums = copy.deepcopy(candidate["lock_checksums"])

        _refresh_metadata(candidate, lambda doc: doc.update(audit_marker="changed"))

        artifact_bytes = candidate["artifacts"][record["stdout"]]
        self.assertNotEqual(artifact_bytes, old_bytes)
        self.assertEqual(json.loads(artifact_bytes)["audit_marker"], "changed")
        self.assertEqual(record["stdout_sha256"], hashlib.sha256(artifact_bytes).hexdigest())
        self.assertEqual(candidate["lock_checksums"], lock_checksums)
        _compare(proofs)

    def test_three_role_positive_proof_commits_only_relay_delta(self):
        result = _compare(_proofs())
        self.assertEqual(result["roles"], ["baseline", "approved_route", "candidate"])
        self.assertEqual(len(result["feature_deltas"]), 1)
        self.assertEqual(result["feature_deltas"][0]["package"][:2], ["iroh-base", "1.3.0"])
        self.assertEqual(result["feature_deltas"][0]["baseline"], ["key"])
        self.assertEqual(result["feature_deltas"][0]["approved_route"], ["key", "relay"])

    def test_prepared_n0_reviewed_route_and_stable_identities(self):
        proofs = _proofs()
        for proof in proofs[1:]:
            _add_route(proof)
        _approve_actual_control_delta(proofs)
        result = _compare(proofs)
        self.assertEqual({tuple(item[:2]) for item in result["added_packages"]},
                         {("n0-mainline", "0.7.0"), ("crc", "3.4.0"),
                          ("crc-catalog", "2.5.0"), ("dyn-clone", "1.0.20")})
        self.assertTrue(all(len(item) == 3 for item in result["added_packages"]))

    def test_n0_route_rejects_reviewed_binding_and_graph_drift(self):
        mutations = ("archive", "n0-version", "crc-checksum", "catalog-checksum", "dyn-checksum",
                     "shortcut", "dev-only", "extra-incoming", "extra-outgoing", "unrelated")
        for mutation in mutations:
            proofs = _proofs()
            for proof in proofs[1:]:
                _add_route(proof)
            target = proofs[2]
            def change(doc):
                ids = {p["name"]: p["id"] for p in doc["packages"]}
                if mutation == "n0-version":
                    next(p for p in doc["packages"] if p["name"] == "n0-mainline")["version"] = "0.8.0"
                elif mutation in ("shortcut", "dev-only"):
                    if mutation == "shortcut":
                        shaar = next(n for n in doc["resolve"]["nodes"] if n["id"] == ids["shaar"])
                        shaar["deps"].remove(next(d for d in shaar["deps"] if d["pkg"] == ids["n0-mainline"]))
                        shaar["deps"].append({"pkg": ids["crc"], "dep_kinds": [{"kind": "normal"}]})
                    else:
                        n0 = next(n for n in doc["resolve"]["nodes"] if n["id"] == ids["n0-mainline"])
                        next(d for d in n0["deps"] if d["pkg"] == ids["crc"])["dep_kinds"] = [{"kind": "dev"}]
                elif mutation == "extra-incoming":
                    doc["resolve"]["nodes"][0]["deps"].append({"pkg": ids["crc"], "dep_kinds": [{"kind": "normal"}]})
                elif mutation == "extra-outgoing":
                    next(n for n in doc["resolve"]["nodes"] if n["id"] == ids["crc"])["deps"].append({"pkg": ids["dyn-clone"], "dep_kinds": [{"kind": "normal"}]})
                elif mutation == "unrelated":
                    next(n for n in doc["resolve"]["nodes"] if n["id"] == ids["shaar"])["deps"].append({"pkg": ids["dyn-clone"], "dep_kinds": [{"kind": "normal"}]})
            if mutation in ("archive",):
                target["source_bindings"][next(k for k in target["source_bindings"] if "n0-mainline" in k)]["archive_sha256"] = "e" * 64
            elif mutation in ("crc-checksum", "catalog-checksum", "dyn-checksum"):
                name = {"crc-checksum": "crc", "catalog-checksum": "crc-catalog", "dyn-checksum": "dyn-clone"}[mutation]
                target["lock_checksums"][next(k for k in target["lock_checksums"] if "#" + name + "@" in k)] = "e" * 64
            else:
                _refresh_metadata(target, change)
            _approve_actual_control_delta(proofs)
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _compare(proofs)

    def test_shared_control_candidate_registry_and_edge_drift_rejected(self):
        for name in ("crc", "crc-catalog", "dyn-clone"):
            for field in ("source", "version", "checksum"):
                proofs = _proofs()
                for proof in proofs[1:]:
                    _add_route(proof)
                _approve_actual_control_delta(proofs)
                _compare(copy.deepcopy(proofs))

                def mutate_registry(doc):
                    package = next(p for p in doc["packages"] if p["name"] == name)
                    if field == "source":
                        package["source"] = "registry+https://wrong.invalid/index"
                    elif field == "version":
                        package["version"] = "9.9.9"
                    else:
                        checksum_key = next(k for k in proof["lock_checksums"] if "#" + name + "@" in k)
                        proof["lock_checksums"][checksum_key] = "e" * 64

                if field == "checksum":
                    for proof in proofs[1:]:
                        checksum_key = next(k for k in proof["lock_checksums"] if "#" + name + "@" in k)
                        proof["lock_checksums"][checksum_key] = "e" * 64
                else:
                    for proof in proofs[1:]:
                        _refresh_metadata(proof, mutate_registry)
                _approve_actual_control_delta(proofs)
                with self.subTest(name=name, field=field), self.assertRaises(AuditError):
                    _compare(proofs)

        edges = (("n0-mainline", "crc"), ("n0-mainline", "dyn-clone"), ("crc", "crc-catalog"))
        for kind in ("dev", "build"):
            for source, target in edges:
                proofs = _proofs()
                for proof in proofs[1:]:
                    _add_route(proof)
                _approve_actual_control_delta(proofs)
                _compare(copy.deepcopy(proofs))
                for proof in proofs[1:]:
                    def mutate_edge(doc):
                        ids = {p["name"]: p["id"] for p in doc["packages"]}
                        node = next(n for n in doc["resolve"]["nodes"] if n["id"] == ids[source])
                        next(d for d in node["deps"] if d["pkg"] == ids[target])["dep_kinds"] = [{"kind": kind}]
                    _refresh_metadata(proof, mutate_edge)
                _approve_actual_control_delta(proofs)
                with self.subTest(kind=kind, edge=(source, target)), self.assertRaises(AuditError):
                    _compare(proofs)

        proofs = _proofs()
        unknown_id = _REGISTRY + "#unknown@1.0.0"
        for proof in proofs[1:]:
            def add_unknown(doc):
                doc["packages"].append({"id": unknown_id, "name": "unknown", "version": "1.0.0", "source": _REGISTRY})
                doc["resolve"]["nodes"].append({"id": unknown_id, "deps": [], "features": []})
                shaar = next(n for n in doc["resolve"]["nodes"] if "shaar" in n["id"])
                shaar["deps"].append({"pkg": unknown_id, "dep_kinds": [{"kind": "normal"}]})
            _refresh_metadata(proof, add_unknown)
            proof["lock_checksums"][unknown_id] = "e" * 64
        _approve_actual_control_delta(proofs)
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_candidate_only_route_expansion_rejected(self):
        proofs = _proofs()
        for proof in proofs[1:]:
            _add_route(proof)
        _refresh_metadata(proofs[2], lambda doc: doc["resolve"]["nodes"][-1].update(features=["expanded"]))
        _approve_actual_control_delta(proofs)
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_prepared_serde_bencode_normal_addition_is_approved_only_with_exact_delta(self):
        proofs = _proofs()
        _add_serde_bencode(proofs[1])
        _add_serde_bencode(proofs[2])
        _approve_actual_control_delta(proofs)
        result = _compare(proofs)
        self.assertEqual([p[:2] for p in result["added_packages"]], [["serde_bencode", "0.2.4"]])
        delta = next(d for d in result["feature_deltas"] if d["package"][0] == "serde_bencode")
        self.assertEqual(delta["baseline"], [])
        self.assertEqual(delta["approved_route"], [])

    def test_prepared_addition_binding_drift_is_rejected(self):
        for field in ("archive_sha256", "tree_sha256", "recipe_sha256"):
            proofs = _proofs()
            _add_serde_bencode(proofs[1])
            _add_serde_bencode(proofs[2])
            _approve_actual_control_delta(proofs)
            proofs[2]["source_bindings"][next(k for k in proofs[2]["source_bindings"] if "serde_bencode" in k)][field] = "d" * 64
            with self.subTest(field=field), self.assertRaises(AuditError):
                _compare(proofs)

    def test_unrelated_removal_missing_depkind_duplicate_node_and_control_commit_rejected(self):
        for mutation in ("remove", "depkind", "duplicate", "commit", "legacy-artifacts"):
            proofs = _proofs()
            if mutation == "remove":
                _refresh_metadata(proofs[1], lambda doc: (doc["packages"].remove(next(p for p in doc["packages"] if p["name"] == "iroh-base")), doc["resolve"]["nodes"].remove(next(n for n in doc["resolve"]["nodes"] if "iroh-base" in n["id"])), next(n for n in doc["resolve"]["nodes"] if "shaar" in n["id"])["deps"].clear()))
            elif mutation == "depkind":
                _refresh_metadata(proofs[2], lambda doc: doc["resolve"]["nodes"][0]["deps"][0].update(dep_kinds=[]))
            elif mutation == "duplicate":
                _refresh_metadata(proofs[2], lambda doc: doc["resolve"]["nodes"].append(copy.deepcopy(doc["resolve"]["nodes"][-1])))
            elif mutation == "legacy-artifacts":
                proofs[2]["artifact_features"] = {}
            else:
                proofs[1]["route_recipe_id"] = "altered-route"
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _compare(proofs)

    def test_normal_build_features_must_match_metadata_features_with_fresh_digest(self):
        proofs = _proofs()
        record = next(r for r in proofs[2]["records"] if r["kind"] == "build")
        message = json.loads(proofs[2]["artifacts"][record["stdout"]])
        message["features"] = ["unexpected"]
        encoded = (json.dumps(message) + "\n").encode()
        proofs[2]["artifacts"][record["stdout"]] = encoded
        record["stdout_sha256"] = hashlib.sha256(encoded).hexdigest()
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_candidate_extra_or_missing_feature_rejected_with_fresh_metadata_digest(self):
        for features in ([], ["relay", "metrics"]):
            proofs = _proofs()
            _refresh_metadata(proofs[2], lambda doc: doc["resolve"]["nodes"][-1].update(features=features))
            with self.subTest(features=features), self.assertRaises(AuditError):
                _compare(proofs)

    def test_wrong_identity_version_source_or_workspace_binding_rejected(self):
        mutations = [
            lambda doc: doc["packages"][-1].update(version="9.9.9"),
            lambda doc: doc["packages"][-1].update(source="git+https://example.invalid/repo"),
        ]
        for mutate in mutations:
            proofs = _proofs()
            _refresh_metadata(proofs[2], mutate)
            with self.assertRaises(AuditError):
                _compare(proofs)

    def test_workspace_source_digests_stay_in_the_proof_not_in_the_identity(self):
        proofs = _proofs()
        before = _compare(copy.deepcopy(proofs))
        binding = proofs[2]["source_bindings"]["path+file:///repo#shaar@0.1.0"]
        binding.update(tree_sha256="b" * 64, archive_sha256="c" * 64)
        after = _compare(proofs)
        self.assertNotEqual(before["proof_sha256"]["candidate"], after["proof_sha256"]["candidate"])

    def test_context_test_util_role_and_metadata_cardinality_fail_closed(self):
        mutations = [
            lambda p: p[2].update(context="dev"),
            lambda p: p[2]["records"].append(copy.deepcopy(p[2]["records"][0])),
            lambda p: p[2]["records"].remove(next(r for r in p[2]["records"] if r["kind"] == "metadata")),
            lambda p: p.pop(1),
            lambda p: p[2].update(role="baseline"),
        ]
        proofs = _proofs()
        _compare(copy.deepcopy(proofs))
        _refresh_metadata(proofs[2], lambda doc: doc["resolve"]["nodes"][1].update(features=["test-util"]))
        with self.assertRaisesRegex(AuditError, "test-util"):
            _compare(proofs)
        for mutate in mutations:
            proofs = _proofs()
            _compare(copy.deepcopy(proofs))
            mutate(proofs)
            with self.assertRaises(AuditError):
                _compare(proofs)

    def test_missing_or_test_build_artifact_and_execution_tampering_rejected(self):
        for mutation in ("build", "test-profile", "argv", "expanded-tree", "cwd", "digest"):
            proofs = _proofs()
            candidate = proofs[2]
            if mutation == "build":
                candidate["records"] = [r for r in candidate["records"] if r["kind"] != "build"]
            elif mutation == "test-profile":
                record = next(r for r in candidate["records"] if r["kind"] == "build")
                msg = json.loads(candidate["artifacts"][record["stdout"]])
                msg["profile"]["test"] = True
                data = (json.dumps(msg) + "\n").encode()
                candidate["artifacts"][record["stdout"]] = data
                record["stdout_sha256"] = hashlib.sha256(data).hexdigest()
            elif mutation in ("argv", "expanded-tree"):
                next(r for r in candidate["records"] if r["kind"] == "tree")["argv"].append("--all-features" if mutation == "argv" else "--no-dedupe")
            elif mutation == "cwd":
                next(r for r in candidate["records"] if r["kind"] == "metadata")["cwd"] = "relative"
            else:
                next(r for r in candidate["records"] if r["kind"] == "tree")["stdout_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _compare(proofs)

    def test_host_unit_feature_evidence(self):
        from verify_once import add_host_unit
        proofs = _proofs()
        add_host_unit(proofs[1])
        add_host_unit(proofs[2])
        _compare(proofs)
        proofs[2]["compiler_capture"]["units"][-1]["args"].append('--cfg=feature="forged"')
        with self.assertRaises(AuditError):
            _compare(proofs)

    def test_production_dependency_edge_capture(self):
        from verify_once import add_dependency_unit
        proofs = _proofs()
        for proof in proofs:
            add_dependency_unit(proof)
        _compare(proofs)
        for mutation in ("extern-path", "extern-alias", "duplicate-extern", "dependency-name", "dependency-kind", "host-target"):
            proofs = _proofs()
            for proof in proofs:
                add_dependency_unit(proof)
            candidate = proofs[2]
            capture = candidate["compiler_capture"]
            extern_mutation = mutation in ("extern-path", "extern-alias", "duplicate-extern")
            unit = capture["units"][0] if extern_mutation else capture["units"][-1]
            raw_suffix = ("/compiler-capture/unit.json" if extern_mutation
                          else "/compiler-capture/dependency-unit.json")
            raw_path = next(path for path in candidate["artifacts"]
                            if path.endswith(raw_suffix))
            raw = json.loads(candidate["artifacts"][raw_path])
            if mutation == "extern-path":
                index = raw["args"].index("--extern")
                raw["args"][index + 1] = "iroh_base=/unknown/path"
            elif mutation == "extern-alias":
                index = raw["args"].index("--extern")
                raw["args"][index + 1] = raw["args"][index + 1].replace("iroh_base=", "forged=")
            elif mutation == "duplicate-extern":
                index = raw["args"].index("--extern")
                raw["args"] += ["--extern", raw["args"][index + 1]]
            elif mutation == "dependency-name":
                def alter(doc):
                    package = next(p for p in doc["packages"] if p["name"] == "iroh-base")
                    package["name"] = "forged-base"
                _refresh_metadata(candidate, alter)
            elif mutation == "dependency-kind":
                def alter(doc):
                    package = next(p for p in doc["packages"] if p["name"] == "shaar")
                    dependency = next(d for d in package["dependencies"] if d["name"] == "iroh-base")
                    dependency["kind"] = "build"
                    node = next(n for n in doc["resolve"]["nodes"] if n["id"] == package["id"])
                    edge = next(d for d in node["deps"] if d.get("name", "").replace("-", "_") == "iroh_base")
                    edge["dep_kinds"] = [{"kind": "build"}]
                _refresh_metadata(candidate, alter)
            else:
                raw["args"].append("--target")
                raw["args"].append("forged-host")
            if mutation in ("extern-path", "extern-alias", "duplicate-extern", "host-target"):
                encoded = json.dumps(raw).encode()
                candidate["artifacts"][raw_path] = encoded
                capture["receipts"][Path(raw_path).name] = hashlib.sha256(encoded).hexdigest()
                unit["args"] = raw["args"]
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                _compare(proofs)

    def test_expected_control_missing_rejected(self):
        with self.assertRaises(AuditError):
            compare_proofs(_proofs(), "base-revision", "candidate-revision")


class CompilerUnitEvidenceTests(unittest.TestCase):
    def _fixture(self):
        cwd = "/tmp/compiler-units"
        target = "x86_64-unknown-linux-gnu"
        target_dir = cwd + "/unit-target"
        package_id = "path+file://" + cwd + "#unit-demo@1.0.0"
        packages = [{
            "id": package_id, "name": "unit-demo", "version": "1.0.0",
            "manifest_path": cwd + "/Cargo.toml",
            "targets": [{"name": "unit_demo", "kind": ["lib"], "crate_types": ["lib"],
                         "src_path": cwd + "/src/lib.rs"}],
        }]
        units = [
            ("host", ["std"], None),
            ("target", ["std", "wire"], target),
        ]
        recipe = b"reviewed rust wrapper"
        recipe_sha256 = hashlib.sha256(recipe).hexdigest()
        records, artifacts, messages, invocations = [], {}, [], []
        for i, (context, features, triple) in enumerate(units, 1):
            out = target_dir + ("/" + target if context == "target" else "") + "/debug/deps"
            args = [cwd + "/src/lib.rs", "--crate-name", "unit_demo", "--crate-type", "lib",
                    "-C", f"extra-filename=-u{i}", "--out-dir", out]
            for feature in features:
                args += ["--cfg", f'feature="{feature}"']
            if triple:
                args += ["--target", triple]
            outputs = [out + f"/libunit_demo-u{i}.rlib", out + f"/libunit_demo-u{i}.rmeta"]
            records.append({"schema": 1, "role": "candidate", "revision": "rev", "cwd": cwd,
                            "recipe_sha256": recipe_sha256, "nonce": "fixture-nonce",
                            "compiler": "/toolchain/rustc",
                            "env": {"RUSTC_WRAPPER": cwd + "/wrapper", "RUSTC_WORKSPACE_WRAPPER": "",
                                    "CARGO_TARGET_DIR": target_dir},
                            "args": args, "package_name": "unit-demo", "package_version": "1.0.0",
                            "manifest_dir": cwd, "exit_code": 0, "outputs": outputs})
            messages.append({"reason": "compiler-artifact", "package_id": package_id,
                             "target": {"name": "unit_demo", "kind": ["lib"],
                                        "crate_types": ["lib"], "src_path": cwd + "/src/lib.rs"},
                             "features": features, "filenames": outputs,
                             "profile": {"test": False}, "fresh": False})
            invocations.append(f"unit{i}.json")
        proof = {"role": "candidate", "revision": "rev", "cwd": cwd, "target": target,
                 "target_dir": target_dir, "wrapper": cwd + "/wrapper", "nonce": "fixture-nonce",
                 "compiler": "/toolchain/rustc", "recipe_sha256": recipe_sha256,
                 "build_argv": ["cargo", "build", "--locked", "--lib", "--message-format=json",
                                "--target", target, "--manifest-path", cwd + "/Cargo.toml"],
                 "invocations": invocations,
                 "artifacts": {name: json.dumps(record).encode()
                               for name, record in zip(invocations, records)}}
        build = b"".join((json.dumps(message) + "\n").encode() for message in messages)
        return proof, packages, build, recipe

    def test_two_compiler_units_are_audited_with_features_and_target_context(self):
        proof, packages, build, recipe = self._fixture()
        units = audit_compiler_units(proof, packages, build, recipe)
        self.assertEqual(len(units), 2)
        self.assertEqual([unit["context"] for unit in units], ["host", "target"])
        self.assertEqual([unit["features"] for unit in units], [("std",), ("std", "wire")])

    def test_compiler_unit_evidence_rejects_tampering_and_test_util(self):
        mutations = ("missing", "duplicate", "unknown-package", "role", "revision", "cwd",
                     "recipe", "argv", "target", "output", "extra-feature", "missing-feature",
                     "control-test-util", "candidate-test-util")
        for mutation in mutations:
            proof, packages, build, recipe = self._fixture()
            if mutation == "missing":
                proof["invocations"].pop()
            elif mutation == "duplicate":
                proof["invocations"].append(proof["invocations"][0])
            elif mutation == "unknown-package":
                record = json.loads(proof["artifacts"]["unit1.json"])
                record["package_name"] = "missing"
                proof["artifacts"]["unit1.json"] = json.dumps(record).encode()
            elif mutation in ("role", "revision", "cwd", "recipe", "argv", "target"):
                key = {"role": "role", "revision": "revision", "cwd": "cwd", "recipe": "recipe_sha256",
                       "argv": "build_argv", "target": "target"}[mutation]
                proof[key] = "tampered" if mutation != "argv" else ["cargo"]
            elif mutation == "output":
                record = json.loads(proof["artifacts"]["unit1.json"])
                record["outputs"][0] = "/forged.rlib"
                proof["artifacts"]["unit1.json"] = json.dumps(record).encode()
            elif mutation in ("extra-feature", "missing-feature", "control-test-util", "candidate-test-util"):
                messages = [json.loads(line) for line in build.splitlines()]
                if mutation == "extra-feature":
                    messages[1]["features"].append("extra")
                elif mutation == "missing-feature":
                    messages[1]["features"].remove("wire")
                elif mutation in ("control-test-util", "candidate-test-util"):
                    role = "approved_route" if mutation == "control-test-util" else "candidate"
                    proof["role"] = role
                    proof["target"] = "x86_64-unknown-linux-gnu"
                    for name in proof["invocations"]:
                        receipt = json.loads(proof["artifacts"][name])
                        receipt["role"] = role
                        receipt["args"] += ["--cfg", 'feature="test-util"']
                        proof["artifacts"][name] = json.dumps(receipt).encode()
                    for message in messages:
                        message["features"].append("test-util")
                build = b"".join((json.dumps(message) + "\n").encode() for message in messages)
            with self.subTest(mutation=mutation), self.assertRaises(AuditError):
                audit_compiler_units(proof, packages, build, recipe)


    def test_receipt_target_must_match_rustc_target_argument(self):
        proof, packages, build, recipe = self._fixture()
        receipt = json.loads(proof["artifacts"]["unit2.json"])
        target_index = receipt["args"].index("--target") + 1
        receipt["args"][target_index] = "aarch64-unknown-linux-gnu"
        proof["artifacts"]["unit2.json"] = json.dumps(receipt).encode()
        with self.assertRaises(AuditError):
            audit_compiler_units(proof, packages, build, recipe)

    def test_output_outside_isolated_target_dir_rejected_when_receipt_and_artifact_agree(self):
        proof, packages, build, recipe = self._fixture()
        receipt = json.loads(proof["artifacts"]["unit2.json"])
        out_index = receipt["args"].index("--out-dir") + 1
        receipt["args"][out_index] = "/tmp/foreign-target/debug/deps"
        receipt["outputs"] = [path.replace("/tmp/compiler-units/unit-target/x86_64-unknown-linux-gnu/debug/deps",
                                            "/tmp/foreign-target/debug/deps")
                              for path in receipt["outputs"]]
        proof["artifacts"]["unit2.json"] = json.dumps(receipt).encode()
        messages = [json.loads(line) for line in build.splitlines()]
        messages[1]["filenames"] = list(receipt["outputs"])
        build = b"".join((json.dumps(message) + "\n").encode() for message in messages)
        with self.assertRaises(AuditError):
            audit_compiler_units(proof, packages, build, recipe)

    def test_missing_compiler_identity_and_nonce_rejected_when_absent_everywhere(self):
        for identity in ("compiler", "nonce"):
            proof, packages, build, recipe = self._fixture()
            proof.pop(identity)
            for name in proof["invocations"]:
                receipt = json.loads(proof["artifacts"][name])
                receipt.pop(identity)
                proof["artifacts"][name] = json.dumps(receipt).encode()
            with self.subTest(identity=identity), self.assertRaises(AuditError):
                audit_compiler_units(proof, packages, build, recipe)

if __name__ == '__main__':
    unittest.main()
