# SPDX-License-Identifier: MIT OR Apache-2.0
"""Contract tests for the declared Yggdrasil closure; synthetic data only."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import features
from baseline import ygg_closure as y
from features import AuditError

_REG = "registry+https://github.com/rust-lang/crates.io-index"
_TOKIO = ("tokio", "1.54.1", _REG + ":" + "a" * 64)
_HEX = ("hex", "0.4.3", _REG + ":" + "b" * 64)
_SHAAR = ("shaar", "0.1.0", "path:workspace:shaar@0.1.0")


def _closure():
    keys = {(n, v, _REG + ":" + c): () for (n, v), c in y.REG.items()}
    for name, version in y.PREPARED.items():
        source = (f"path:prepared:{name}@{version}:archive={y.PREPARED_ARCHIVE}:tree={'t' * 64}"
                  f":recipe={y.PREPARED_RECIPE}")
        keys[(name, version, source)] = ("default",)
    keys[(*y.WORKSPACE, "path:workspace:shaar-ygg-core@0.1.0")] = ()
    return keys


def _control():
    return {_TOKIO: ("rt", "time"), _HEX: ("alloc", "std"), _SHAAR: ()}


def _candidate():
    keys = dict(_control())
    keys[_TOKIO] = ("full", "parking_lot", "rt", "time")
    keys[_HEX] = ("alloc", "default", "std")
    keys.update(_closure())
    return keys


class ReduceMetadataTests(unittest.TestCase):
    def test_absent_closure_is_returned_unchanged(self):
        control = _control()
        self.assertFalse(y.present(control))
        self.assertIs(y.reduce_metadata(control, control), control)

    def test_declared_closure_and_growth_reduce_to_the_control(self):
        candidate = _candidate()
        self.assertTrue(y.present(candidate))
        self.assertEqual(y.reduce_metadata(_control(), candidate), _control())

    def test_every_missing_closure_identity_is_rejected(self):
        for key in _closure():
            candidate = _candidate()
            del candidate[key]
            with self.subTest(package=key[0]), self.assertRaisesRegex(AuditError, "closure identities"):
                y.reduce_metadata(_control(), candidate)

    def test_forged_closure_sources_are_rejected(self):
        for key in _closure():
            candidate = _candidate()
            del candidate[key]
            forged = key[:2] + (key[2].replace(key[2][-8:], "0" * 8),)
            candidate[forged] = ()
            with self.subTest(package=key[0]), self.assertRaisesRegex(AuditError, "closure source"):
                y.reduce_metadata(_control(), candidate)

    def test_closure_already_in_the_control_is_rejected(self):
        control = _control()
        control[(*y.WORKSPACE, "path:workspace:shaar-ygg-core@0.1.0")] = ()
        with self.assertRaisesRegex(AuditError, "already present"):
            y.reduce_metadata(control, _candidate())

    def test_unlisted_package_stays_visible_to_the_strict_comparison(self):
        candidate = _candidate()
        candidate[("evil", "1.0.0", _REG + ":" + "c" * 64)] = ()
        self.assertNotEqual(y.reduce_metadata(_control(), candidate), _control())

    def test_undeclared_feature_changes_are_rejected(self):
        mutations = (
            (_TOKIO, ("full", "parking_lot", "rt", "test-util", "time")),
            (_TOKIO, ("rt",)),
            (_SHAAR, ("extra",)),
        )
        for key, features_ in mutations:
            candidate = _candidate()
            candidate[key] = features_
            with self.subTest(package=key[0], features=features_), self.assertRaisesRegex(
                    AuditError, "unapproved feature change"):
                y.reduce_metadata(_control(), candidate)


def _graph(edges):
    packages, nodes = {}, {}
    for source, target in edges:
        for name, version in (source, target):
            packages[name] = {"name": name, "version": version}
            nodes.setdefault(name, {"deps": []})
        nodes[source[0]]["deps"].append({"pkg": target[0], "dep_kinds": [{"kind": None}]})
    return packages, nodes


def _parsed(edges, feats):
    packages, nodes = _graph([(("root", "0.0.0"), ("shaar", "0.1.0"))] + list(edges))
    return (None, packages, nodes, {"id": "root"}, feats, {}, {}, "")


_BASE_EDGES = [(("shaar", "0.1.0"), ("tokio", "1.54.1")), (("shaar", "0.1.0"), ("hex", "0.4.3")),
               (("base256emoji", "1.0.2"), ("const-str", "0.4.3")), (("shaar", "0.1.0"), ("base256emoji", "1.0.2")),
               (("shaar", "0.1.0"), ("shaar-ygg", "0.1.0"))]


class CheckEdgesTests(unittest.TestCase):
    def check(self, added=(), removed=()):
        before = _parsed(_BASE_EDGES, {})
        kept = [edge for edge in _BASE_EDGES if edge not in removed]
        y.check_edges(before, _parsed(kept + list(added), {}))

    def test_closure_declared_and_emoji_changes_are_admitted(self):
        self.check(added=[(("shaar", "0.1.0"), ("shaar-ygg-core", "0.1.0")),
                          (("tokio", "1.54.1"), ("parking_lot", "0.12.5")),
                          (("shaar-ygg", "0.1.0"), ("tokio", "1.54.1"))],
                   removed=[(("base256emoji", "1.0.2"), ("const-str", "0.4.3"))])

    def test_undeclared_edge_between_existing_packages_is_rejected(self):
        with self.assertRaisesRegex(AuditError, "unapproved dependency edge: hex"):
            self.check(added=[(("hex", "0.4.3"), ("tokio", "1.54.1"))])

    def test_only_declared_shaar_ygg_direct_edges_are_admitted(self):
        declared = [(("shaar-ygg", "0.1.0"), (name, version)) for name, version in (
            ("iroh", "1.3.0"),
            ("iroh-base", "1.3.0"),
            ("n0-watcher", "1.0.0"),
            ("noq-udp", "1.3.0"),
        )]
        for edge in declared:
            with self.subTest(edge=edge):
                self.check(added=[edge])
        with self.assertRaisesRegex(AuditError, "unapproved dependency edge: shaar-ygg"):
            self.check(added=[(("shaar-ygg", "0.1.0"), ("evil", "1.0.0"))])

    def test_native_observer_admits_only_the_exact_existing_futures_edge(self):
        self.check(added=[(("shaar", "0.1.0"), ("futures", "0.3.34"))])
        for owner, version in (("shaar", "0.3.35"), ("hex", "0.3.34")):
            owner_version = "0.1.0" if owner == "shaar" else "0.4.3"
            with self.subTest(owner=owner, version=version), self.assertRaisesRegex(
                    AuditError, "unapproved dependency edge"):
                self.check(added=[((owner, owner_version), ("futures", version))])
        edge = (("shaar", "0.1.0"), ("futures", "0.3.34"))
        with self.assertRaisesRegex(AuditError, "edge removal"):
            y.check_edges(_parsed(_BASE_EDGES + [edge], {}), _parsed(_BASE_EDGES, {}))

    def test_removal_outside_the_emoji_chain_is_rejected(self):
        with self.assertRaisesRegex(AuditError, "edge removal"):
            self.check(removed=[(("shaar", "0.1.0"), ("hex", "0.4.3"))])


def _form(name, version="1.0.0", feats=(), deps=(), context="target", owner="o"):
    return {"package": (name, version, _REG + ":" + "0" * 64), "target": name, "kind": ["lib"],
            "crate_types": ["lib"], "context": context, "triple": "x86_64-unknown-linux-gnu",
            "features": list(feats), "dependencies": list(deps), "owner": owner}


def _dep(alias, form):
    fields = ("package", "target", "kind", "crate_types", "context", "triple", "features")
    return {"alias": alias, "kind": ["normal"], "unit": {key: form[key] for key in fields}}


class CheckUnitsTests(unittest.TestCase):
    def setUp(self):
        self.tokio = _form("tokio", "1.54.1", ("rt",))
        self.pool = _form("parking_lot", "0.12.5")
        self.hex = _form("hex", "0.4.3", ("std",))
        self.control = [self.tokio, self.pool, self.hex]

    def candidate(self):
        return copy.deepcopy(self.control)

    def test_identical_units_pass_and_owner_hashes_are_ignored(self):
        candidate = self.candidate()
        candidate[0]["owner"] = "other"
        y.check_units(self.control, candidate)

    def test_declared_growth_edges_and_new_units_pass(self):
        added = _form("rand_core", "0.6.4")
        candidate = self.candidate()
        candidate[0] = _form("tokio", "1.54.1", ("full", "parking_lot", "rt"),
                             (_dep("parking_lot", self.pool), _dep("rand_core", added)))
        candidate.append(added)
        candidate.append(_form("winnow", "1.0.4"))
        y.check_units(self.control, candidate)

    def test_declared_product_edge_to_tokio_passes(self):
        product = _form("shaar-ygg", "0.1.0")
        control = [product, self.tokio]
        candidate = copy.deepcopy(control)
        candidate[0]["dependencies"].append(_dep("tokio", self.tokio))
        y.check_units(control, candidate)

    def test_native_observer_unit_edge_preserves_version_owner_and_features(self):
        product = _form("shaar", "0.1.0")
        stream = _form("futures", "0.3.34", ("std",))
        control = [product, stream]
        candidate = copy.deepcopy(control)
        candidate[0]["dependencies"].append(_dep("futures", stream))
        y.check_units(control, candidate)
        changed = copy.deepcopy(candidate)
        changed[0]["dependencies"][0]["unit"]["package"] = ("futures", "0.3.35", stream["package"][2])
        with self.assertRaisesRegex(AuditError, "unapproved unit dependency"):
            y.check_units(control, changed)
        changed = copy.deepcopy(candidate)
        changed[1]["features"].append("thread-pool")
        with self.assertRaisesRegex(AuditError, "unapproved unit feature change"):
            y.check_units(control, changed)
        other = [_form("hex", "0.4.3"), stream]
        changed = copy.deepcopy(other)
        changed[0]["dependencies"].append(_dep("futures", stream))
        with self.assertRaisesRegex(AuditError, "unapproved unit dependency"):
            y.check_units(other, changed)

    def test_undeclared_units_edges_and_features_are_rejected(self):
        extra = {
            "unit": lambda c: c.append(_form("evil")),
            "host-unit-of-declared-shared-package": lambda c: c.append(_form("winnow", "1.0.4", context="host")),
            "feature": lambda c: c[2].update(features=["std", "serde"]),
            "feature-loss": lambda c: c[0].update(features=[]),
            "edge": lambda c: c[2]["dependencies"].append(_dep("tokio", self.tokio)),
            "missing-unit": lambda c: c.pop(),
            "duplicate": lambda c: c.append(copy.deepcopy(c[0])),
        }
        for label, mutate in extra.items():
            candidate = self.candidate()
            mutate(candidate)
            with self.subTest(label), self.assertRaises(AuditError):
                y.check_units(self.control, candidate)

    def test_missing_control_dependency_is_rejected(self):
        control = self.candidate()
        control[0]["dependencies"].append(_dep("parking_lot", self.pool))
        with self.assertRaisesRegex(AuditError, "dependency missing"):
            y.check_units(control, self.candidate())


class WiringTests(unittest.TestCase):
    def run_case(self, candidate_units, closure=True):
        control_feats = _control()
        candidate_feats = _candidate() if closure else _control()
        edges = [(("shaar", "0.1.0"), ("tokio", "1.54.1"))]
        extra = [(("shaar", "0.1.0"), ("shaar-ygg-core", "0.1.0"))] if closure else []
        parsed = {"approved_route": _parsed(edges, control_feats),
                  "candidate": _parsed(edges + extra, candidate_feats)}
        tokio = _form("tokio", "1.54.1", ("rt",))
        units = {"approved_route": [tokio], "candidate": candidate_units(tokio)}
        features._candidate_matches_control(parsed, units)

    def test_declared_closure_passes_through_the_control_comparison(self):
        self.run_case(lambda tokio: [_form("tokio", "1.54.1", ("full", "rt")), _form("rand_core", "0.6.4")])

    def test_absent_closure_keeps_the_strict_unit_equality(self):
        self.run_case(lambda tokio: [dict(tokio)], closure=False)
        with self.assertRaisesRegex(AuditError, "compiler units differ"):
            self.run_case(lambda tokio: [dict(tokio, features=["rt", "full"])], closure=False)

    def test_undeclared_unit_fails_with_the_closure_present(self):
        with self.assertRaisesRegex(AuditError, "unapproved candidate unit"):
            self.run_case(lambda tokio: [tokio, _form("evil")])


class BackendSourceTests(unittest.TestCase):
    def inputs(self):
        from baseline import backend_sources as b
        bindings = {}
        feats = {}
        units = {}
        for side, role in (("old", "approved_route"), ("new", "candidate")):
            bindings[role] = {}
            feats[role] = {}
            units[role] = []
            for name, source in b.SOURCES.items():
                key = b.key(name, side)
                feats[role][key] = ()
                bindings[role][name] = {
                    "package": name, "version": "1.3.0", "identity": "prepared",
                    "archive_sha256": source["archive"], "tree_sha256": source[side + "_tree"],
                    "manifest_sha256": source[side + "_manifest"],
                    "recipe_sha256": b.OLD_RECIPE if side == "old" else b.NEW_RECIPE,
                }
                unit = _form(name, "1.3.0")
                unit["package"] = key
                units[role].append(unit)
            units[role].append(_form("shaar", "0.1.0", deps=(_dep("iroh", units[role][0]),)))
        parsed = {}
        for role, values in feats.items():
            values.update(_control() if role == "approved_route" else _candidate())
            fields = list(_parsed([], values))
            fields[6] = bindings[role]
            parsed[role] = tuple(fields)
        return parsed, units

    def test_exact_transition_is_wired_into_metadata_and_unit_comparison_without_mutation(self):
        from baseline import backend_sources as b
        parsed, units = self.inputs()
        original = copy.deepcopy((parsed, units))
        normalized, normalized_units = b.comparison_inputs(parsed, units)
        self.assertEqual(normalized_units["candidate"], units["approved_route"])
        self.assertEqual((parsed, units), original)
        self.assertNotEqual(normalized["candidate"][4], parsed["candidate"][4])
        features._candidate_matches_control(parsed, units)

    def test_source_identity_drift_and_partial_transition_are_rejected(self):
        from baseline import backend_sources as b
        for name in b.SOURCES:
            for field in ("version", "source", "missing", "unchanged"):
                with self.subTest(name=name, field=field):
                    parsed, units = self.inputs()
                    values = parsed["candidate"][4]
                    key = b.key(name, "new")
                    value = values.pop(key)
                    if field == "version":
                        values[(name, "1.3.1", key[2])] = value
                    elif field == "source":
                        values[(name, key[1], key[2] + "-drift")] = value
                    elif field == "unchanged":
                        values[b.key(name, "old")] = value
                    with self.assertRaisesRegex(AuditError, "backend source transition"):
                        b.comparison_inputs(parsed, units)

    def test_every_frozen_binding_field_is_checked_on_both_sides(self):
        from baseline import backend_sources as b
        for role in ("approved_route", "candidate"):
            for name in b.SOURCES:
                for field in ("identity", "version", "archive_sha256", "tree_sha256",
                              "manifest_sha256", "recipe_sha256"):
                    with self.subTest(role=role, name=name, field=field):
                        parsed, units = self.inputs()
                        parsed[role][6][name][field] = "forged"
                        with self.assertRaisesRegex(AuditError, "backend source binding"):
                            b.comparison_inputs(parsed, units)

    def test_test_gate_and_other_feature_growth_are_not_normalized_away(self):
        from baseline import backend_sources as b
        for feature in ("shaar-native-gate", "unreviewed-feature"):
            with self.subTest(feature=feature):
                parsed, units = self.inputs()
                parsed["candidate"][4][b.key("iroh", "new")] = (feature,)
                with self.assertRaises(AuditError):
                    features._candidate_matches_control(parsed, units)

    def test_unit_source_and_feature_drift_are_not_normalized_away(self):
        for field in ("package", "dependency", "features"):
            with self.subTest(field=field):
                parsed, units = self.inputs()
                candidate = units["candidate"]
                if field == "package":
                    key = candidate[0]["package"]
                    candidate[0]["package"] = key[:2] + (key[2] + "-drift",)
                elif field == "dependency":
                    owner = candidate[-1]["dependencies"][0]["unit"]
                    key = owner["package"]
                    owner["package"] = key[:2] + (key[2] + "-drift",)
                else:
                    candidate[0]["features"].append("unreviewed-feature")
                with self.assertRaises(AuditError):
                    features._candidate_matches_control(parsed, units)

    def test_unchanged_graph_is_returned_without_copies(self):
        from baseline import backend_sources as b
        parsed, units = self.inputs()
        parsed["candidate"] = parsed["approved_route"]
        units["candidate"] = units["approved_route"]
        same_parsed, same_units = b.comparison_inputs(parsed, units)
        self.assertIs(same_parsed, parsed)
        self.assertIs(same_units, units)


if __name__ == "__main__":
    unittest.main()
