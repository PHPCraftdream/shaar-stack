# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Contract tests for the multibase recipe, lock delta, and comparison admission."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
NATIVE_GRAPH = HERE.parent / "native-graph"
sys.path.insert(0, str(NATIVE_GRAPH))
sys.path.insert(0, str(NATIVE_GRAPH / "fixture"))
import features
import graph

_SPEC = importlib.util.spec_from_file_location("_multibase_recipe", HERE / "prepare.py")
recipe = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(recipe)

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = recipe.ARCHIVE_SHA256
EMOJI_CHECKSUMS = {
    "base256emoji": ("1.0.2", "b5e9430d9a245a77c92176e649af6e275f20839a48389859d1661e9a128d077c"),
    "const-str": ("0.4.3", "2f421161cb492475f1661ddc9815a745a1c894592070661180fdec3d4872e9c3"),
    "match-lookup": ("0.1.3", "549e39695cc0b640f3cb378053832db3d2133422d49e8dcae5c866a2aaf1f730"),
}
DOC_LINE = b"/// Base256Emoji (alphabet: " + recipe.ROCKET * 250 + recipe.EMOJI_DOC_SUFFIX
PREPARED_SOURCE = ("path:prepared:multibase@0.9.3:archive=" + CHECKSUM
                   + ":tree=" + "b" * 64 + ":recipe=" + "c" * 64)


def manifest() -> bytes:
    return (b'[package]\nname = "multibase"\nversion = "0.9.3"\nlicense = "MIT"\n'
            b'\n[dependencies.base-x]\nversion = "0.2.7"\ndefault-features = false\n'
            b'\n[dependencies.base256emoji]\nversion = "1.0.2"\n'
            b'\n[dependencies.base45]\nversion = "3.2.0"\n'
            b'\n[dependencies.data-encoding]\nversion = "2.3.1"\n'
            b'\n[dependencies.data-encoding-macro]\nversion = "0.1.9"\n')


def original_files() -> dict[str, bytes]:
    error_rs = (
        b"use core::fmt;\n\n"
        b"impl From<base_x::DecodeError> for Error {\n    fn from(_: base_x::DecodeError) -> Self {\n"
        b"        Self::InvalidBaseString\n    }\n}\n\n"
        b"impl From<base256emoji::DecodeError> for Error {\n    fn from(_: base256emoji::DecodeError) -> Self {\n"
        b"        Self::InvalidBaseString\n    }\n}\n\n"
        b"impl From<data_encoding::DecodeError> for Error {\n    fn from(_: data_encoding::DecodeError) -> Self {\n"
        b"        Self::InvalidBaseString\n    }\n}\n"
    )
    base_rs = (
        b"build_base_enum! {\n"
        b"    'u' => Base64Url,\n"
        b"    'U' => Base64UrlPad,\n"
        + DOC_LINE
        + b"    '" + recipe.ROCKET + b"' => Base256Emoji,\n"
        + b"}\n"
    )
    impls_rs = (
        b"use crate::encoding;\n"
        b"use base256emoji::{Base, Emoji};\n"
        b"\n"
        + DOC_LINE
        + b"#[derive(PartialEq, Eq, Clone, Copy, Debug)]\n"
        b"pub(crate) struct Base256Emoji;\n"
        b"\n"
        b"impl BaseCodec for Base256Emoji {\n"
        b"    fn encode<I: AsRef<[u8]>>(input: I) -> String {\n"
        b"        Emoji::encode(input.as_ref())\n"
        b"    }\n"
        b"\n"
        b"    fn decode<I: AsRef<str>>(input: I) -> Result<Vec<u8>> {\n"
        b"        Emoji::decode(input.as_ref()).map_err(|e| e.into())\n"
        b"    }\n"
        b"}\n"
        b"\n"
        b"derive_base_encoding! {\n    Base2, encoding::BASE2;\n}\n"
    )
    tests_rs = (
        b"        (Base64UrlPad, \"UeWVzIG1hbmkgIQ==\"),\n"
        b'        (Base256Emoji, "' + recipe.ROCKET + b'"),\n'
        b'        (Base256Emoji, "' + recipe.ROCKET * 2 + b'"),\n'
        b'        (Base256Emoji, "' + recipe.ROCKET * 3 + b'"),\n'
        b"    ];\n"
    )
    return {
        "Cargo.toml": manifest(),
        "Cargo.toml.orig": b'[dependencies]\nbase-x = { version = "0.2.7", default-features = false }\n'
                           b'base256emoji = "1.0.2"\ndata-encoding = "2.3.1"\n',
        "src/base.rs": base_rs,
        "src/error.rs": error_rs,
        "src/impls.rs": impls_rs,
        "tests/lib.rs": tests_rs,
        "README.md": b"# multibase\n",
        "LICENSE": b"MIT License\n",
        # Faithful to the real archive: upstream's own dev lock names the chain.
        "Cargo.lock": b'[[package]]\nname = "base256emoji"\nversion = "1.0.2"\n'
                      b'dependencies = [\n "const-str",\n "match-lookup",\n]\n',
    }


class RecipeTransformTests(unittest.TestCase):
    def test_transform_changes_exactly_the_six_files_and_reverses(self):
        files = original_files()
        changed = recipe.transform(files)
        self.assertEqual(set(changed), set(recipe.CHANGE_FILES))
        prepared = {**files, **changed}
        self.assertEqual(prepared["README.md"], files["README.md"])
        self.assertEqual(prepared["LICENSE"], files["LICENSE"])
        for name, data in prepared.items():
            self.assertNotIn(b"base256emoji", data.lower(), name)
            self.assertNotIn(recipe.ROCKET, data, name)
        self.assertEqual(recipe.reverse(files, changed), files)
        self.assertIn(b"[dependencies.base45]", changed["Cargo.toml"])
        self.assertNotIn(b"Emoji::encode", changed["src/impls.rs"])
        self.assertNotIn(b"Base256Emoji", changed["src/base.rs"])
        self.assertNotIn(b"(Base256Emoji,", changed["tests/lib.rs"])

    def test_transform_rejects_anchor_drift(self):
        mutations = (
            lambda data: {**data, "src/base.rs": data["src/base.rs"].replace(
                DOC_LINE, b"/// Base256Emoji (alphabet: " + recipe.ROCKET * 4
                + recipe.EMOJI_DOC_SUFFIX)},
            lambda data: {**data, "src/base.rs": data["src/base.rs"].replace(
                b"    '" + recipe.ROCKET + b"' => Base256Emoji,\n",
                b"    '" + recipe.ROCKET + b"' => Base256Emoji2,\n")},
            lambda data: {**data, "src/impls.rs": data["src/impls.rs"].replace(
                b"pub(crate) struct Base256Emoji;\n", b"pub(crate) struct Base256Emoji2;\n")},
            lambda data: {**data, "tests/lib.rs": data["tests/lib.rs"]
                          + b'        (Base256Emoji, "' + recipe.ROCKET + b'"),\n'},
            lambda data: {**data, "Cargo.toml": data["Cargo.toml"].replace(
                b"\n[dependencies.base45]", b"\n[dependencies.base45x]")},
            lambda data: {**data, "src/error.rs": data["src/error.rs"].replace(
                b"impl From<base256emoji::DecodeError>", b"impl From<base256emoji::DecodeError2>")},
            lambda data: {**data, "Cargo.toml.orig": data["Cargo.toml.orig"].replace(
                b'base256emoji = "1.0.2"\n', b'base256emoji = "1.0.3"\n')},
            lambda data: {**data, "Cargo.toml": data["Cargo.toml"].replace(
                b'license = "MIT"', b'license = "Apache-2.0"')},
            lambda data: {key: value for key, value in data.items() if key != "src/base.rs"},
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(ValueError):
                    recipe.transform(mutate(original_files()))

    def test_inert_upstream_lock_is_retained_byte_identical(self):
        # Regression for the first CI run: the real archive carries a dev Cargo.lock that
        # still names base256emoji; Cargo ignores it, so it must neither fail the sweep nor change.
        files = original_files()
        self.assertIn(b"base256emoji", files["Cargo.lock"])
        changed = recipe.transform(files)
        self.assertNotIn("Cargo.lock", changed)
        self.assertEqual(recipe.reverse(files, changed), files)
        self.assertEqual(recipe.INERT_FILES, ("Cargo.lock",))

    def test_transform_rejects_leftover_references(self):
        mutated = {**original_files(), "README.md": b"see base256emoji docs\n"}
        with self.assertRaisesRegex(ValueError, "still references base256emoji"):
            recipe.transform(mutated)
        mutated = {**original_files(), "README.md": b"emoji " + recipe.ROCKET + b"\n"}
        with self.assertRaisesRegex(ValueError, "emoji code char"):
            recipe.transform(mutated)

    def test_reverse_rejects_partial_or_drifted_changes(self):
        files = original_files()
        changed = recipe.transform(files)
        with self.assertRaises(ValueError):
            recipe.reverse(files, {name: data for name, data in changed.items()
                                   if name != "Cargo.toml.orig"})
        with self.assertRaises(ValueError):
            recipe.reverse(files, {**changed, "README.md": b"drift\n"})
        with self.assertRaises(ValueError):
            recipe.reverse(files, {**changed,
                                   "Cargo.toml.orig": changed["Cargo.toml.orig"] + b"# extra\n"})


def archive_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for name, data in files.items():
            member = tarfile.TarInfo(f"{recipe.PACKAGE}/{name}")
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return output.getvalue()


class RecipeArchiveTests(unittest.TestCase):
    def test_archive_files_accepts_the_pinned_layout(self):
        data = archive_bytes(original_files())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "multibase-0.9.3.crate"
            path.write_bytes(data)
            with patch.object(recipe, "ARCHIVE_SHA256", hashlib.sha256(data).hexdigest()):
                loaded = recipe.archive_files(path)
        self.assertEqual(loaded["LICENSE"], b"MIT License\n")
        self.assertEqual(sorted(loaded), sorted(original_files()))

    def test_archive_files_reject_checksum_duplicates_links_and_traversal(self):
        good = archive_bytes(original_files())
        duplicated = io.BytesIO()
        with tarfile.open(fileobj=duplicated, mode="w:gz") as tar:
            for _ in range(2):
                member = tarfile.TarInfo(f"{recipe.PACKAGE}/LICENSE")
                member.size = 2
                tar.addfile(member, io.BytesIO(b"ok"))
        linked = io.BytesIO()
        with tarfile.open(fileobj=linked, mode="w:gz") as tar:
            member = tarfile.TarInfo(f"{recipe.PACKAGE}/LICENSE")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            tar.addfile(member)
        escaping = io.BytesIO()
        with tarfile.open(fileobj=escaping, mode="w:gz") as tar:
            member = tarfile.TarInfo(f"{recipe.PACKAGE}/../escape")
            member.size = 2
            tar.addfile(member, io.BytesIO(b"no"))
        cases = [duplicated.getvalue(), linked.getvalue(), escaping.getvalue()]
        with tempfile.TemporaryDirectory() as temporary:
            for index, data in enumerate(cases):
                path = Path(temporary) / f"case-{index}.crate"
                path.write_bytes(data)
                with patch.object(recipe, "ARCHIVE_SHA256", hashlib.sha256(data).hexdigest()):
                    with self.subTest(case=index), self.assertRaises(ValueError):
                        recipe.archive_files(path)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pinned.crate"
            path.write_bytes(good)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                recipe.archive_files(path)


def lock_entry(name, version, source=None, checksum=None, dependencies=()):
    entry = {"name": name, "version": version}
    if source:
        entry["source"] = source
    if checksum:
        entry["checksum"] = checksum
    if dependencies:
        entry["dependencies"] = list(dependencies)
    return entry


def lock_toml(packages) -> bytes:
    lines = ["version = 4"]
    for package in packages:
        lines.extend(["[[package]]", f'name = "{package["name"]}"',
                      f'version = "{package["version"]}"'])
        for key in ("source", "checksum"):
            if key in package:
                lines.append(f'{key} = "{package[key]}"')
        if "dependencies" in package:
            joined = ", ".join(f'"{dep}"' for dep in package["dependencies"])
            lines.append(f"dependencies = [{joined}]")
        lines.append("")
    return "\n".join(lines).encode()


def product_lock() -> list[dict]:
    return [
        lock_entry("shaar", "0.1.0", dependencies=["serde", "multiaddr"]),
        lock_entry("serde", "1.0.229", source=REGISTRY, checksum="sum"),
        lock_entry("multiaddr", "0.19.1", source=REGISTRY, checksum="addr",
                   dependencies=["multibase"]),
        lock_entry("multibase", "0.9.3", source=REGISTRY, checksum=CHECKSUM,
                   dependencies=["base-x", "base256emoji", "base45", "data-encoding",
                                 "data-encoding-macro"]),
        lock_entry("base256emoji", "1.0.2", source=REGISTRY,
                   checksum=EMOJI_CHECKSUMS["base256emoji"][1],
                   dependencies=["const-str", "match-lookup"]),
        lock_entry("const-str", "0.4.3", source=REGISTRY,
                   checksum=EMOJI_CHECKSUMS["const-str"][1]),
        lock_entry("match-lookup", "0.1.3", source=REGISTRY,
                   checksum=EMOJI_CHECKSUMS["match-lookup"][1]),
        lock_entry("base-x", "0.2.11", source=REGISTRY, checksum="basex"),
        lock_entry("base45", "3.2.0", source=REGISTRY, checksum="base45"),
        lock_entry("data-encoding", "2.6.0", source=REGISTRY, checksum="de"),
        lock_entry("data-encoding-macro", "0.1.17", source=REGISTRY, checksum="dem"),
    ]


def prepared_lock() -> list[dict]:
    dropped = {"base256emoji", "const-str", "match-lookup"}
    after = [entry for entry in copy.deepcopy(product_lock())
             if entry["name"] not in dropped]
    registry = next(entry for entry in after if entry["name"] == "multibase")
    registry.clear()
    registry.update(lock_entry("multibase", "0.9.3",
                               dependencies=["base-x", "base45", "data-encoding",
                                             "data-encoding-macro"]))
    return after


class LockDeltaTests(unittest.TestCase):
    def test_multibase_transition_is_the_only_newly_approved_delta(self):
        report = graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(prepared_lock()))
        removed = {tuple(entry) for entry in report["removed"]}
        self.assertIn(("multibase", "0.9.3", graph.REGISTRY), removed)
        for name, (version, _) in EMOJI_CHECKSUMS.items():
            self.assertIn((name, version, graph.REGISTRY), removed)
        self.assertIn((("multibase", "0.9.3", REGISTRY), ("multibase", "0.9.3", "path")),
                      [tuple(entry) for entry in report["source_changed"]])

    def test_multibase_transition_rejects_mutations(self):
        kept = copy.deepcopy(prepared_lock())
        next(entry for entry in kept if entry["name"] == "multibase")["checksum"] = "kept"
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(kept))
        wrong_before = copy.deepcopy(product_lock())
        next(entry for entry in wrong_before if entry["name"] == "multibase")["checksum"] = "0" * 64
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(wrong_before), lock_toml(prepared_lock()))
        edge = copy.deepcopy(prepared_lock())
        next(entry for entry in edge if entry["name"] == "multibase")["dependencies"].append("base256emoji")
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(edge))
        partial = copy.deepcopy(prepared_lock())
        partial.append(lock_entry("const-str", "0.4.3", source=REGISTRY,
                                  checksum=EMOJI_CHECKSUMS["const-str"][1]))
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(partial))
        retained = copy.deepcopy(prepared_lock())
        retained.append(lock_entry("multibase", "0.9.3", source=REGISTRY, checksum=CHECKSUM,
                                   dependencies=["base-x", "base256emoji", "base45",
                                                 "data-encoding", "data-encoding-macro"]))
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(retained))
        without_switch = [entry for entry in copy.deepcopy(product_lock())
                          if entry["name"] not in EMOJI_CHECKSUMS]
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(without_switch))
        foreign = prepared_lock() + [lock_entry("foreign", "1.0.0")]
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(foreign))
        pure_addition = prepared_lock()
        before_without_multibase = [entry for entry in copy.deepcopy(pure_addition)
                                    if entry["name"] != "multibase"]
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(before_without_multibase),
                                   lock_toml(pure_addition))
        drifted_helper = copy.deepcopy(product_lock())
        next(entry for entry in drifted_helper
             if entry["name"] == "const-str")["checksum"] = "drifted"
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(drifted_helper), lock_toml(prepared_lock()))
        retained_reference = copy.deepcopy(prepared_lock())
        retained_reference.append(lock_entry("serde_bencode", "0.2.4",
                                             dependencies=["const-str"]))
        with self.assertRaises(ValueError):
            graph.audit_lock_delta(lock_toml(product_lock()), lock_toml(retained_reference))


def feature_maps() -> tuple[dict, dict]:
    control = {
        ("multibase", "0.9.3", REGISTRY + ":" + CHECKSUM): ("std",),
        ("serde", "1.0.229", REGISTRY + ":abc"): (),
    }
    for name, (version, checksum) in EMOJI_CHECKSUMS.items():
        control[(name, version, REGISTRY + ":" + checksum)] = ()
    candidate = {
        ("multibase", "0.9.3", PREPARED_SOURCE): ("std",),
        ("serde", "1.0.229", REGISTRY + ":abc"): (),
    }
    return control, candidate


def parsed_for(control, candidate, binding=None):
    packages = {"mb": {"name": "multibase", "version": "0.9.3", "source": None}}
    if binding is None:
        binding = {"identity": "prepared", "package": "multibase",
                   "archive_sha256": CHECKSUM}
    bindings = {"mb": binding}
    return {
        "approved_route": [None, {}, {}, None, control, {}, {}, None],
        "candidate": [None, packages, {}, None, candidate, {}, bindings, None],
    }


_OWNER_FIELDS = ("package", "target", "kind", "crate_types", "context", "triple", "features")


def unit_sha256(unit):
    """Recompute the production recursive digest from baseline.validate_externs."""
    ordered = sorted(unit.get("dependencies", []),
                     key=lambda edge: (edge["alias"], json.dumps(edge["kind"], sort_keys=True)))
    canonical = {"unit": {key: value for key, value in unit.items()
                          if key not in ("dependencies", "sha256")},
                 "dependencies": [{"alias": edge["alias"], "kind": edge["kind"],
                                   "unit": edge["unit"]["sha256"]} for edge in ordered]}
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def dep_edge(alias, owner):
    # Production shape: the edge keeps the owner unit's identifying fields and
    # its recursive sha256 digest.
    edge = {"alias": alias, "kind": ["normal"],
            "unit": {key: owner[key] for key in _OWNER_FIELDS}}
    edge["unit"]["sha256"] = owner["sha256"]
    return edge


def ordinary_unit(package, target, context="target", kinds=("lib",), dependencies=()):
    unit = {"package": package, "target": target, "kind": list(kinds),
            "crate_types": list(kinds), "context": context, "triple": "host",
            "features": [], "intrinsics": [], "dependencies": list(dependencies)}
    unit["sha256"] = unit_sha256(unit)
    return unit


def real_units():
    """Control/candidate units in the production normalized representation.

    Digests are genuinely derived bottom-up, so the prepared multibase source
    change cascades through multiaddr and every dependent unit digest, exactly
    as production evidence does.
    """
    registry = ("multibase", "0.9.3", REGISTRY + ":" + CHECKSUM)
    prepared = ("multibase", "0.9.3", PREPARED_SOURCE)
    base256emoji = ("base256emoji", "1.0.2",
                    REGISTRY + ":" + EMOJI_CHECKSUMS["base256emoji"][1])
    const_str = ("const-str", "0.4.3", REGISTRY + ":" + EMOJI_CHECKSUMS["const-str"][1])
    match_lookup = ("match-lookup", "0.1.3",
                    REGISTRY + ":" + EMOJI_CHECKSUMS["match-lookup"][1])
    multiaddr = ("multiaddr", "0.19.1", REGISTRY + ":addr")
    shaar_p2p = ("shaar-p2p", "0.1.0", "path:workspace:shaar-p2p@0.1.0")
    shaar = ("shaar", "0.1.0", "path:workspace:shaar@0.1.0")

    # The helpers hang beneath base256emoji, as in the real manifest and lock.
    const_str_unit = ordinary_unit(const_str, "const-str")
    match_lookup_unit = ordinary_unit(match_lookup, "match-lookup", context="host",
                                      kinds=("proc-macro",))
    emoji_unit = ordinary_unit(base256emoji, "base256emoji", dependencies=(
        dep_edge("const_str", const_str_unit),
        dep_edge("match_lookup", match_lookup_unit),
    ))
    control_chain = [emoji_unit, const_str_unit, match_lookup_unit]
    control_multibase = ordinary_unit(registry, "multibase", dependencies=(
        dep_edge("base256emoji", emoji_unit),
    ))
    control_multiaddr = ordinary_unit(multiaddr, "multiaddr", dependencies=(
        dep_edge("multibase", control_multibase),
    ))
    control_p2p = ordinary_unit(shaar_p2p, "shaar_p2p", dependencies=(
        dep_edge("multiaddr", control_multiaddr),
    ))
    control_shaar = ordinary_unit(shaar, "shaar", dependencies=(
        dep_edge("shaar_p2p", control_p2p),
    ))
    candidate_multibase = ordinary_unit(prepared, "multibase")
    candidate_multiaddr = ordinary_unit(multiaddr, "multiaddr", dependencies=(
        dep_edge("multibase", candidate_multibase),
    ))
    candidate_p2p = ordinary_unit(shaar_p2p, "shaar_p2p", dependencies=(
        dep_edge("multiaddr", candidate_multiaddr),
    ))
    candidate_shaar = ordinary_unit(shaar, "shaar", dependencies=(
        dep_edge("shaar_p2p", candidate_p2p),
    ))
    control = [control_multibase, *control_chain, control_multiaddr,
               control_p2p, control_shaar]
    candidate = [candidate_multibase, candidate_multiaddr, candidate_p2p,
                 candidate_shaar]
    return control, candidate

class CandidateTransitionTests(unittest.TestCase):
    def test_recursive_digest_cascade_is_admitted(self):
        control, candidate = real_units()
        features._candidate_matches_control(parsed_for(*feature_maps()), {
            "approved_route": control, "candidate": candidate})

    def test_vacuous_graph_keeps_exact_equality(self):
        plain = {("serde", "1.0.229", REGISTRY + ":abc"): ()}
        features._candidate_matches_control(parsed_for(dict(plain), dict(plain)),
                                            {"approved_route": [], "candidate": []})
        with self.assertRaises(features.AuditError):
            drifted = {**plain, ("other", "1.0.0", "path:x"): ()}
            features._candidate_matches_control(parsed_for(plain, drifted),
                                                {"approved_route": [], "candidate": []})

    def test_candidate_transition_rejects_mutations(self):
        control, candidate = feature_maps()

        def expect_rejection(mutated_control=None, mutated_candidate=None,
                             units=None, binding=None):
            proofs = parsed_for(mutated_control or control, mutated_candidate or candidate,
                                binding)
            if units is None:
                control_units, candidate_units = real_units()
                units = (control_units, candidate_units)
            with self.assertRaises(features.AuditError):
                features._candidate_matches_control(proofs, {
                    "approved_route": units[0], "candidate": units[1]})

        baseline_control, baseline_candidate = real_units()
        features._candidate_matches_control(parsed_for(control, candidate), {
            "approved_route": baseline_control, "candidate": baseline_candidate})
        kept = dict(candidate)
        kept[("base256emoji", "1.0.2",
              REGISTRY + ":" + EMOJI_CHECKSUMS["base256emoji"][1])] = ()
        expect_rejection(mutated_candidate=kept)
        expect_rejection(mutated_candidate={**candidate,
                                            ("other", "1.0.0", "path:x"): ()})
        incomplete = {k: v for k, v in control.items()
                      if k[0] != "const-str"}
        expect_rejection(mutated_control=incomplete)
        drifted = {k: (("std2",) if k[0] == "multibase" else v) for k, v in candidate.items()}
        expect_rejection(mutated_candidate=drifted)
        unbound = {"identity": "prepared", "package": "multibase",
                   "archive_sha256": "0" * 64}
        expect_rejection(binding=unbound)
        expect_rejection(binding={})
        wrong_archive = dict(candidate)
        wrong_archive.pop(("multibase", "0.9.3", PREPARED_SOURCE))
        wrong_archive[("multibase", "0.9.3",
                       "path:prepared:multibase@0.9.3:archive=" + "0" * 64
                       + ":tree=" + "b" * 64 + ":recipe=" + "c" * 64)] = ("std",)
        expect_rejection(mutated_candidate=wrong_archive)

    def test_candidate_units_reject_real_shape_mutations(self):
        control_units, candidate_units = real_units()
        # The unmodified fixture must pass, so each rejection below is caused by its mutation.
        features._candidate_matches_control(parsed_for(*feature_maps()), {
            "approved_route": control_units, "candidate": candidate_units})

        def expect_rejection(mutated_candidate):
            with self.assertRaises(features.AuditError):
                features._candidate_matches_control(parsed_for(*feature_maps()), {
                    "approved_route": control_units, "candidate": mutated_candidate})

        retained_chain = copy.deepcopy(candidate_units)
        retained_chain[1]["dependencies"] = [dep_edge("base256emoji", control_units[1])]
        expect_rejection(retained_chain)
        top_level_chain = copy.deepcopy(candidate_units)
        top_level_chain.append(copy.deepcopy(control_units[2]))
        expect_rejection(top_level_chain)
        alias_drift = copy.deepcopy(candidate_units)
        alias_drift[1]["dependencies"][0]["alias"] = "mb"
        expect_rejection(alias_drift)
        owner_feature_drift = copy.deepcopy(candidate_units)
        owner_feature_drift[1]["dependencies"][0]["unit"]["features"] = ["std"]
        expect_rejection(owner_feature_drift)
        owner_context_drift = copy.deepcopy(candidate_units)
        owner_context_drift[2]["dependencies"][0]["unit"]["context"] = "host"
        expect_rejection(owner_context_drift)
        extra = copy.deepcopy(candidate_units)
        extra.append(ordinary_unit(("unexpected", "1.0.0", "path:x"), "unexpected"))
        expect_rejection(extra)
        missing = copy.deepcopy(candidate_units)
        missing.pop(3)
        expect_rejection(missing)
        triple_drift = copy.deepcopy(candidate_units)
        triple_drift[0]["triple"] = "other-host"
        expect_rejection(triple_drift)
        feature_drift = copy.deepcopy(candidate_units)
        feature_drift[0]["features"] = ["std"]
        expect_rejection(feature_drift)


if __name__ == "__main__":
    unittest.main()
