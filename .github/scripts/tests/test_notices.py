"""CI-only tests of the deterministic third-party notices generator and its check."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
NOTICES = REPO / ".github" / "actions" / "dependency-license" / "notices"
sys.path.insert(0, str(NOTICES))

import notice_cfg  # noqa: E402
import notice_corpus  # noqa: E402
import notice_graph  # noqa: E402
import notice_render  # noqa: E402
import notices  # noqa: E402

SRC = "registry+https://github.com/rust-lang/crates.io-index"
LINUX, WINDOWS = "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"
APACHE = b"Apache License\nVersion 2.0, January 2004\n"
MIT_A = b"MIT License\r\nCopyright (c) Alpha\r\n\r\nPermission is hereby granted"
MIT_B = b"MIT License\nCopyright (c) Beta\n"
MIT_P = b"MIT License\nCopyright (c) Path crate\n"
RELEASE = notice_corpus.BASE + "/release"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = notices.main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class Env:
    """A synthetic corpus, policy, metadata and lock exercising every classification."""

    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.root = self.tmp / "repo"
        self.base = self.root / notice_corpus.BASE
        self.registry, self.prepared = [], []
        self.edges = {
            "shaar-server": [("alpha", None, None), ("beta", None, "cfg(windows)"), ("gamma", "build", None),
                             ("delta", "dev", None), ("pathcrate", None, None), ("gapw", None, "cfg(windows)"),
                             ("gapmac", None, 'cfg(target_os = "macos")')],
            "shaar-client": [("alpha", None, None)],
        }
        self.sources = {n: SRC for n in ("alpha", "beta", "gamma", "delta", "gapw", "gapmac")}
        self.gaps = ["gapw", "gapmac"]
        both = [("LICENSE-APACHE", APACHE, "package_terms")]
        self.reg("alpha", "MIT OR Apache-2.0", both + [("LICENSE-MIT", MIT_A, "package_terms")])
        self.reg("beta", "MIT OR Apache-2.0", both + [("LICENSE-MIT", MIT_B, "package_terms")])
        self.reg("gamma", "MIT", [("LICENSE", MIT_A, "package_terms")])
        self.reg("delta", "MIT", [("LICENSE", MIT_B, "package_terms")])
        for gap in ("gapw", "gapmac"):
            self.reg(gap, "MIT", [("README.md", b"see the license", "reference_context")], "reference-only")
        self.path("pathcrate", "MIT", [("LICENSE", MIT_P)])

    def put(self, rel, data):
        target = self.base / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def reg(self, name, declared, files, classification="package-complete"):
        materials, texts = [], []
        for rel, data, role in files:
            path = "packages/%s/%s" % (name, rel)
            self.put("registry/" + path, data)
            materials.append({"archive_member": "%s-1.0.0/%s" % (name, rel), "material_path": path,
                              "material_bytes": len(data), "material_sha256": sha(data), "role": role,
                              "kind": role, "source_relative_path": rel})
            if role == "package_terms":
                texts.append(sha(data))
        row = {"name": name, "version": "1.0.0", "source": SRC, "checksum": sha(name.encode()),
               "classification": classification, "declared_license": declared, "materials": materials,
               "review_note": "synthetic"}
        if texts:
            alternatives = [{"availability": "available", "evidence": [{"sha256": t}]} for t in texts]
            row["terms_evidence"] = {"groups": [{"satisfied_by_available_text": True, "alternatives": alternatives}]}
        self.registry.append(row)
        return row

    def path(self, name, declared, files):
        materials = []
        for rel, data in files:
            path = "prepared/%s/%s" % (name, rel)
            self.put(path, data)
            materials.append({"preserved_path": notice_corpus.BASE + "/" + path, "bytes": len(data),
                              "sha256": sha(data), "source_member": "%s-2.0.0/%s" % (name, rel)})
        self.prepared.append({"cargo_identity": {"name": name, "version": "2.0.0"},
                              "package_manifest": {"declared_license": declared}, "materials": materials})
        self.sources[name] = None

    def version(self, name):
        return "2.0.0" if name == "pathcrate" else "0.1.0" if name.startswith("shaar-") else "1.0.0"

    def ident(self, name):
        source = self.sources.get(name)
        if source is None:
            return "path+file:///w/%s#%s" % (name, self.version(name))
        return "%s#%s@%s" % (source, name, self.version(name))

    def policy(self):
        cfgs = {LINUX: ["unix", 'target_os="linux"', 'target_family="unix"'],
                WINDOWS: ["windows", 'target_os="windows"', 'target_family="windows"']}
        return {"schema": 1, "products": ["shaar-client", "shaar-server"],
                "first_party": ["shaar-client 0.1.0", "shaar-server 0.1.0"],
                "targets": {t: {"cfg": c} for t, c in cfgs.items()},
                "gaps": [{"name": n, "version": "1.0.0", "reason": "reviewed: no license file"} for n in self.gaps]}

    def metadata(self):
        names = sorted({*self.edges, *(d for deps in self.edges.values() for d, _, _ in deps)})
        packages = [{"id": self.ident(n), "name": n, "version": self.version(n), "source": self.sources.get(n)}
                    for n in names]
        nodes = []
        for name in names:
            deps = [{"name": d, "pkg": self.ident(d), "dep_kinds": [{"kind": kind, "target": target}]}
                    for d, kind, target in self.edges.get(name, [])]
            nodes.append({"id": self.ident(name), "deps": deps})
        return {"packages": packages, "workspace_members": [self.ident(m) for m in self.edges],
                "resolve": {"nodes": nodes}}

    def lock(self):
        parts = []
        for name in sorted({*self.edges, *(d for deps in self.edges.values() for d, _, _ in deps)}):
            parts.append('[[package]]\nname = "%s"\nversion = "%s"\n' % (name, self.version(name)))
            if self.sources.get(name):
                parts.append('source = "%s"\nchecksum = "%s"\n' % (self.sources[name], sha(name.encode())))
        return "\n".join(parts)

    def write(self):
        (self.base / "registry").mkdir(parents=True, exist_ok=True)
        (self.base / "prepared").mkdir(parents=True, exist_ok=True)
        (self.base / "release").mkdir(parents=True, exist_ok=True)
        (self.base / "registry/inventory.json").write_text(json.dumps({"identities": self.registry}), "utf-8")
        (self.base / "prepared/inventory.json").write_text(json.dumps({"identities": self.prepared}), "utf-8")
        (self.base / "release/policy.json").write_text(json.dumps(self.policy()), "utf-8")
        (self.tmp / "metadata.json").write_text(json.dumps(self.metadata()), "utf-8")
        (self.tmp / "Cargo.lock").write_text(self.lock(), "utf-8")

    def args(self, command, out, *extra):
        return (command, "--root", self.root, "--metadata", self.tmp / "metadata.json", "--lock",
                self.tmp / "Cargo.lock", "--out", self.tmp / out, *extra)

    def record(self):
        self.write()
        code, _, err = run(*self.args("generate", "records", "--manifest-only"))
        assert code == 0, err
        for path in (self.tmp / "records").glob("manifest-*.json"):
            (self.base / "release" / path.name).write_bytes(path.read_bytes())

    def manifest(self, out, target):
        return json.loads((self.tmp / out / ("manifest-%s.json" % target)).read_text("utf-8"))


class CfgTests(unittest.TestCase):
    CFGS = notice_cfg.parse_rustc_cfg(["unix", 'target_os="linux"', 'panic="unwind"', "debug_assertions"])

    def test_predicates_evaluate_against_the_cfg_set(self):
        cases = {
            "cfg(unix)": True, "cfg(windows)": False, 'cfg(target_os = "linux")': True,
            'cfg(target_os = "macos")': False, "cfg(not(windows))": True, "cfg(any())": False, "cfg(all())": True,
            'cfg(all(unix, target_os = "linux"))': True, 'cfg(all(unix, target_os = "macos"))': False,
            'cfg(any(windows, target_os = "linux"))': True, "cfg(tokio_unstable)": False,
            'cfg(not(any(target_os = "macos", all(unix, not(target_os = "linux")))))': True,
            'cfg(all(not(windows), any(rustix_use_libc, miri, target_os = "linux")))': True,
        }
        for text, expected in cases.items():
            with self.subTest(text):
                self.assertIs(notice_cfg.matches(text, LINUX, self.CFGS), expected)

    def test_plain_triples_and_unconditional_edges(self):
        self.assertTrue(notice_cfg.matches(None, LINUX, self.CFGS))
        self.assertTrue(notice_cfg.matches(LINUX, LINUX, self.CFGS))
        self.assertFalse(notice_cfg.matches("x86_64-pc-windows-gnu", LINUX, self.CFGS))

    def test_malformed_expressions_are_rejected(self):
        deep = "cfg(" + "not(" * 70 + "unix" + ")" * 70 + ")"
        for text in ("cfg(all(unix)", "cfg(unix windows)", "cfg(not(unix, windows))", "cfg(target_os = linux)",
                     "cfg(unix $)", 'cfg(target_os = "a" "b")', "cfg()", deep):
            with self.subTest(text), self.assertRaises(notice_cfg.CfgError):
                notice_cfg.matches(text, LINUX, self.CFGS)

    def test_rustc_cfg_output_is_parsed_strictly(self):
        self.assertIn(("target_os", "linux"), self.CFGS)
        self.assertIn(("unix", None), self.CFGS)
        with self.assertRaises(notice_cfg.CfgError):
            notice_cfg.parse_rustc_cfg(["target_os=linux"])


class GraphTests(unittest.TestCase):
    PRODUCTS = ["shaar-server", "shaar-client"]

    def closure(self, env, triple):
        cfgs = notice_cfg.parse_rustc_cfg(env.policy()["targets"][triple]["cfg"])
        sets = notice_graph.closure(env.metadata(), self.PRODUCTS, triple, cfgs)
        return {root: {key[0] for key in keys} for root, keys in sets.items()}

    def test_target_filtering_and_edge_kinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Env(tmp)
            linux, windows = self.closure(env, LINUX), self.closure(env, WINDOWS)
        self.assertEqual(linux["shaar-server"], {"shaar-server", "alpha", "pathcrate"})
        self.assertEqual(windows["shaar-server"], {"shaar-server", "alpha", "pathcrate", "beta", "gapw"})
        for sets in (linux, windows):
            self.assertEqual(sets["shaar-client"], {"shaar-client", "alpha"})
            self.assertFalse({"gamma", "delta", "gapmac"} & sets["shaar-server"])

    def test_transitive_edges_follow_only_normal_kinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Env(tmp)
            env.edges["alpha"] = [("beta", None, None)]
            env.edges["beta"] = [("gamma", "build", None)]
            linux = self.closure(env, LINUX)
        self.assertEqual(linux["shaar-client"], {"shaar-client", "alpha", "beta"})

    def test_missing_graph_dangling_edge_and_duplicate_member_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Env(tmp)
            meta = env.metadata()
            cfgs = notice_cfg.parse_rustc_cfg([])
            with self.assertRaises(notice_graph.GraphError):
                notice_graph.closure({**meta, "resolve": None}, self.PRODUCTS, LINUX, cfgs)
            dangling = copy.deepcopy(meta)
            dangling["resolve"]["nodes"][0]["deps"].append({"name": "x", "pkg": "nope", "dep_kinds": []})
            with self.assertRaises(notice_graph.GraphError):
                notice_graph.closure(dangling, self.PRODUCTS, LINUX, cfgs)
            with self.assertRaises(notice_graph.GraphError):
                notice_graph.closure(meta, ["no-such-product"], LINUX, cfgs)

    def test_boundary_names_the_gating_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Env(tmp)
            cfgs = notice_cfg.parse_rustc_cfg(env.policy()["targets"][LINUX]["cfg"])
            sets = notice_graph.closure(env.metadata(), self.PRODUCTS, LINUX, cfgs)
            linked = set().union(*sets.values())
            rows = notice_graph.boundary(env.metadata(), ("gapmac", "1.0.0"), linked, LINUX, cfgs)
            self.assertEqual(rows, [("shaar-server", "0.1.0", "gapmac", "1.0.0", "normal",
                                     'cfg(target_os = "macos")', False)])
            # An edge the cfg allows but Cargo did not link is reported as feature-gated.
            narrowed = {key for key in linked if key[0] != "pathcrate"}
            rows = notice_graph.boundary(env.metadata(), ("pathcrate", "2.0.0"), narrowed, LINUX, cfgs)
            self.assertEqual(rows, [("shaar-server", "0.1.0", "pathcrate", "2.0.0", "normal", "", True)])

    def test_cargo_tree_output_is_parsed_and_rejects_garbage(self):
        text = ("shaar-server v0.1.0 (/w/crates/x)\nalpha v1.0.0\nmacro v2.0.0 (proc-macro) (*)\n"
                "patched v3.0.0 (/w/target/p) (*)\n" + r"winpath v1.0.0 (D:\a\x)" + "\n\n")
        self.assertEqual(notice_graph.tree_identities(text),
                         {("shaar-server", "0.1.0", True), ("alpha", "1.0.0", False), ("macro", "2.0.0", False),
                          ("patched", "3.0.0", True), ("winpath", "1.0.0", True)})
        for bad in ("garbage\n", "v1.0.0\n", "name v\n"):
            with self.subTest(bad), self.assertRaises(notice_graph.GraphError):
                notice_graph.tree_identities(bad)

    def test_tree_identities_map_to_unique_metadata_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta = Env(tmp).metadata()
        keys = notice_graph.tree_keys(meta, {("alpha", "1.0.0", False), ("pathcrate", "2.0.0", True)})
        self.assertEqual(keys, {("alpha", "1.0.0", SRC), ("pathcrate", "2.0.0", None)})
        for shape in (("alpha", "1.0.0", True), ("ghost", "1.0.0", False), ("alpha", "9.9.9", False)):
            with self.subTest(shape), self.assertRaises(notice_graph.GraphError):
                notice_graph.tree_keys(meta, {shape})

    def test_lock_requires_unique_identities(self):
        with self.assertRaises(notice_graph.GraphError):
            notice_graph.load_lock(b'[[package]]\nname = "a"\nversion = "1"\n[[package]]\nname = "a"\nversion = "1"\n')
        with self.assertRaises(notice_graph.GraphError):
            notice_graph.load_lock(b"")


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.env = Env(self.dir.name)

    def load(self):
        self.env.write()
        return notice_corpus.load(self.env.root)[0]

    def test_classification_and_reference_files(self):
        entries = self.load()
        alpha = entries[("alpha", "1.0.0", SRC)]
        self.assertTrue(alpha.complete)
        self.assertEqual([t.label for t in alpha.texts], ["LICENSE-APACHE", "LICENSE-MIT"])
        gap = entries[("gapw", "1.0.0", SRC)]
        self.assertFalse(gap.complete)
        self.assertEqual(gap.texts, ())
        self.assertTrue(entries[("pathcrate", "2.0.0", None)].complete)

    def test_component_only_text_is_not_package_terms(self):
        self.env.reg("comp", "Apache-2.0 AND ISC", [("LICENSE-ISC", b"ISC text", "component_terms")],
                     "component-only")
        row = self.env.registry[-1]
        row["classification"] = "package-complete"
        entry = self.load()[("comp", "1.0.0", SRC)]
        self.assertFalse(entry.complete)

    def test_unbacked_alternative_evidence_is_incomplete(self):
        row = self.env.registry[0]
        row["terms_evidence"]["groups"][0]["alternatives"][0]["evidence"] = [{"sha256": "0" * 64}]
        self.assertFalse(self.load()[("alpha", "1.0.0", SRC)].complete)

    def test_unsatisfied_group_is_incomplete(self):
        self.env.registry[0]["terms_evidence"]["groups"][0]["satisfied_by_available_text"] = False
        self.assertFalse(self.load()[("alpha", "1.0.0", SRC)].complete)

    def test_duplicate_identity_and_path_registry_collision_fail(self):
        self.env.registry.append(copy.deepcopy(self.env.registry[0]))
        with self.assertRaises(notice_corpus.CorpusError):
            self.load()
        self.env.registry.pop()
        self.env.registry.append({**self.env.registry[0], "name": "pathcrate", "version": "2.0.0", "source": None})
        with self.assertRaises(notice_corpus.CorpusError):
            self.load()

    def test_text_bytes_are_exact_and_tampering_is_detected(self):
        entries = self.load()
        text = entries[("alpha", "1.0.0", SRC)].texts[1]
        self.assertEqual(notice_corpus.read_text(self.env.root, text), MIT_A)
        path = self.env.base / text.path.removeprefix(notice_corpus.BASE + "/")
        path.write_bytes(MIT_A + b" ")
        with self.assertRaises(notice_corpus.CorpusError):
            notice_corpus.read_text(self.env.root, text)
        path.write_bytes(b"X" * len(MIT_A))
        with self.assertRaises(notice_corpus.CorpusError):
            notice_corpus.read_text(self.env.root, text)

    def test_empty_unsafe_and_oversized_paths_are_rejected(self):
        root = self.env.root
        self.env.write()
        (root / "empty").write_bytes(b"")
        empty = notice_corpus.Text("empty", sha(b""), 0, "x", "package_terms")
        with self.assertRaises(notice_corpus.CorpusError):
            notice_corpus.read_text(root, empty)
        for rel in ("../outside", "/abs", "a/../b", "a\\b", ""):
            with self.subTest(rel), self.assertRaises(notice_corpus.CorpusError):
                notice_corpus.read_bounded(root, rel, 10)
        (root / "big").write_bytes(b"0123456789A")
        with self.assertRaises(notice_corpus.CorpusError):
            notice_corpus.read_bounded(root, "big", 10)

    def test_links_are_not_followed(self):
        self.env.write()
        target = self.env.root / "real"
        target.write_bytes(b"data")
        try:
            os.symlink(target, self.env.root / "link")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(notice_corpus.CorpusError):
            notice_corpus.read_bounded(self.env.root, "link", 10)


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.env = Env(self.dir.name)
        self.env.write()

    def generate(self, out="out"):
        code, _, err = run(*self.env.args("generate", out))
        self.assertEqual(code, 0, err)
        return self.env.tmp / out

    def test_output_is_deterministic_and_independent_of_input_order(self):
        first = self.generate("one")
        meta = self.env.metadata()
        meta["packages"].reverse()
        meta["resolve"]["nodes"].reverse()
        for node in meta["resolve"]["nodes"]:
            node["deps"].reverse()
        (self.env.tmp / "metadata.json").write_text(json.dumps(meta), "utf-8")
        second = self.generate("two")
        names = sorted(p.name for p in first.iterdir())
        self.assertEqual(names, sorted(p.name for p in second.iterdir()))
        self.assertEqual(len(names), 4)
        for name in names:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)

    def test_texts_are_verbatim_deduplicated_and_framed(self):
        out = self.generate()
        linux = (out / ("THIRD-PARTY-NOTICES-%s.txt" % LINUX)).read_bytes()
        windows = (out / ("THIRD-PARTY-NOTICES-%s.txt" % WINDOWS)).read_bytes()
        self.assertEqual(linux.count(b"-----BEGIN TEXT"), 3)
        self.assertEqual(windows.count(b"-----BEGIN TEXT"), 4)
        for data in (APACHE, MIT_A, MIT_P):
            self.assertIn(data + b"\n-----END TEXT", linux)
        self.assertIn(("bytes=%d-----\n" % len(MIT_A)).encode() + MIT_A, linux)
        self.assertNotIn(MIT_B, linux)
        self.assertNotIn(b"see the license", linux + windows)

    def test_target_filtering_in_manifests(self):
        out = self.generate()
        linux, windows = self.env.manifest("out", LINUX), self.env.manifest("out", WINDOWS)
        names = lambda m: {i["name"] for i in m["identities"]}  # noqa: E731
        self.assertEqual(names(linux), {"alpha", "pathcrate"})
        self.assertEqual(names(windows), {"alpha", "pathcrate", "beta", "gapw"})
        self.assertEqual((linux["counts"]["third_party"], windows["counts"]["third_party"]), (2, 4))
        self.assertEqual(linux["counts"]["first_party_excluded"], 2)
        self.assertEqual(linux["linked_source"], "cfg-evaluation")
        self.assertEqual([i["kind"] for i in linux["identities"]], ["registry", "path"])
        self.assertTrue(linux["release_ready"])
        self.assertFalse(windows["release_ready"])
        self.assertEqual(linux["notices"]["sha256"], sha((out / linux["notices"]["file"]).read_bytes()))

    def test_blockers_and_not_distributed_evidence(self):
        self.generate()
        linux, windows = self.env.manifest("out", LINUX), self.env.manifest("out", WINDOWS)
        self.assertEqual([b["name"] for b in windows["blockers"]], ["gapw"])
        self.assertEqual(linux["blockers"], [])
        outside = {o["name"]: o for o in linux["not_distributed"]}
        self.assertEqual(set(outside), {"gapw", "gapmac"})
        self.assertEqual(outside["gapw"]["boundary"],
                         [["shaar-server", "0.1.0", "gapw", "1.0.0", "normal", "cfg(windows)", False]])
        self.assertEqual([o["name"] for o in windows["not_distributed"]], ["gapmac"])
        notice = (self.env.tmp / "out" / ("THIRD-PARTY-NOTICES-%s.txt" % WINDOWS)).read_text("utf-8")
        self.assertIn("RELEASE BLOCKERS", notice)
        self.assertIn("gapw 1.0.0 | MIT | registry INCOMPLETE | -", notice)

    def test_unlinked_identities_never_reach_the_output(self):
        out = self.generate()
        for target in (LINUX, WINDOWS):
            for name in ("gamma", "delta", "gapmac"):
                self.assertNotIn(name + " 1.0.0", (out / ("THIRD-PARTY-NOTICES-%s.txt" % target)).read_text("utf-8"))


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.env = Env(self.dir.name)
        self.env.record()

    def check(self, *extra):
        return run(*self.env.args("check", "checked", "--evaluator-only", *extra))

    def test_matching_record_passes_and_reports_blockers_without_failing(self):
        code, out, err = self.check()
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.count("RELEASE BLOCKER gapw 1.0.0"), 1)
        self.assertIn("%s: 2 third-party packages linked, 0 release blockers" % LINUX, out)

    def test_release_mode_fails_while_distributed_blockers_remain(self):
        code, out, _ = self.check("--release")
        self.assertEqual(code, 1)
        self.assertIn("RELEASE BLOCKER", out)

    def test_tampered_or_missing_committed_manifest_fails(self):
        path = self.env.base / "release" / ("manifest-%s.json" % LINUX)
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"name": "alpha"', b'"name": "alphx"'))
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("differs from the regenerated one", err)
        path.unlink()
        self.assertEqual(self.check()[0], 1)

    def test_changed_text_bytes_fail_closed(self):
        (self.env.base / "registry/packages/alpha/LICENSE-MIT").write_bytes(MIT_A + b"!")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("does not match its inventory record", err)

    def test_missing_text_file_fails_closed(self):
        (self.env.base / "registry/packages/alpha/LICENSE-MIT").unlink()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("notices: FAIL", err)

    def test_unreviewed_and_stale_gaps_fail(self):
        self.env.gaps = ["gapw"]
        self.env.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("unreviewed=[('gapmac', '1.0.0')]", err)
        self.env.gaps = ["gapw", "gapmac", "alpha"]
        self.env.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("stale=[('alpha', '1.0.0')]", err)

    def test_linked_identity_absent_from_corpus_fails(self):
        self.env.registry = [r for r in self.env.registry if r["name"] != "beta"]
        self.env.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("beta 1.0.0 has no corpus identity", err)

    def test_unmapped_path_package_fails(self):
        self.env.edges["shaar-server"].append(("rogue", None, None))
        self.env.sources["rogue"] = None
        self.env.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("rogue 1.0.0 has no corpus identity", err)

    def test_lock_checksum_mismatch_and_foreign_sources_fail(self):
        lock = self.env.tmp / "Cargo.lock"
        lock.write_text(lock.read_text("utf-8").replace(sha(b"alpha"), "0" * 64), "utf-8")
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("lock checksum differs", err)
        self.env.write()
        self.env.sources["alpha"] = "git+https://example.invalid/alpha"
        self.env.write()
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("unsupported package source", err)

    def test_stale_inventory_digest_invalidates_the_record(self):
        inventory = self.env.base / "registry/inventory.json"
        inventory.write_text(inventory.read_text("utf-8") + " ", "utf-8")
        self.assertEqual(self.check()[0], 1)


class TreeTests(unittest.TestCase):
    """Cargo's own tree is the authoritative linked set; the cfg evaluation is only its superset."""

    LINUX_TREE = ("shaar-server v0.1.0 (/w/s)\nalpha v1.0.0\npathcrate v2.0.0 (/w/p)\n"
                  "shaar-client v0.1.0 (/w/c)\nalpha v1.0.0 (*)\n")
    WINDOWS_TREE = LINUX_TREE + "beta v1.0.0\ngapw v1.0.0\n"

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.env = Env(self.dir.name)
        self.env.write()
        self.trees = {LINUX: self.tree("linux.txt", self.LINUX_TREE), WINDOWS: self.tree("windows.txt", self.WINDOWS_TREE)}

    def tree(self, name, text):
        path = self.env.tmp / name
        path.write_text(text, "utf-8")
        return path

    def flags(self, trees=None):
        return [arg for target, path in (self.trees if trees is None else trees).items() for arg in ("--tree", "%s=%s" % (target, path))]

    def record(self, trees=None):
        code, _, err = run(*self.env.args("generate", "records", "--manifest-only", *self.flags(trees)))
        self.assertEqual(code, 0, err)
        for path in (self.env.tmp / "records").glob("manifest-*.json"):
            (self.env.base / "release" / path.name).write_bytes(path.read_bytes())

    def check(self, trees=None, *extra):
        return run(*self.env.args("check", "checked", *self.flags(trees), *extra))

    def test_record_from_trees_verifies_and_is_marked_authoritative(self):
        self.record()
        code, out, err = self.check()
        self.assertEqual((code, err), (0, ""))
        self.assertNotIn("skipped", out)
        manifest = self.env.manifest("checked", LINUX)
        self.assertEqual(manifest["linked_source"], "cargo-tree")
        self.assertEqual({i["name"] for i in manifest["identities"]}, {"alpha", "pathcrate"})

    def test_tree_narrower_than_the_evaluation_defines_the_notices(self):
        narrow = self.tree("narrow.txt", self.LINUX_TREE.replace("pathcrate v2.0.0 (/w/p)\n", ""))
        self.record({LINUX: narrow, WINDOWS: self.trees[WINDOWS]})
        self.assertEqual({i["name"] for i in self.env.manifest("records", LINUX)["identities"]}, {"alpha"})
        code, _, err = self.check()
        self.assertEqual(code, 1)
        self.assertIn("differs from the regenerated one", err)

    def test_tree_linking_what_the_cfg_excludes_fails(self):
        wrong = self.tree("wrong.txt", self.LINUX_TREE + "beta v1.0.0\n")
        code, _, err = self.check({LINUX: wrong})
        self.assertEqual(code, 1)
        self.assertIn("excluded for %s: [('beta', '1.0.0')]" % LINUX, err)

    def test_tree_without_the_products_or_with_unknown_packages_fails(self):
        for name, text, message in (("empty.txt", "alpha v1.0.0\n", "every product"),
                                    ("ghost.txt", self.LINUX_TREE + "ghost v1.0.0\n", "not a unique metadata package")):
            with self.subTest(name):
                code, _, err = self.check({LINUX: self.tree(name, text)})
                self.assertEqual(code, 1)
                self.assertIn(message, err)

    def test_check_verifies_only_targets_with_a_tree_and_needs_at_least_one(self):
        self.record()
        code, out, _ = self.check({LINUX: self.trees[LINUX]})
        self.assertEqual(code, 0)
        self.assertIn("%s: skipped" % WINDOWS, out)
        code, _, err = self.check({})
        self.assertEqual(code, 1)
        self.assertIn("no target was verified", err)
        code, _, err = self.check({"aarch64-apple-darwin": self.trees[LINUX]})
        self.assertEqual(code, 1)
        self.assertIn("outside the policy", err)


class RepositoryContractTests(unittest.TestCase):
    """The committed corpus, policy and manifests agree with each other."""

    @classmethod
    def setUpClass(cls):
        cls.entries, cls.digests = notice_corpus.load(REPO)
        cls.policy = notices.load_policy(REPO)

    def manifest(self, target):
        raw = notice_corpus.read_bounded(REPO, "%s/manifest-%s.json" % (RELEASE, target), notice_corpus.MAX_JSON)
        return json.loads(raw)

    def test_corpus_counts_and_reviewed_gaps(self):
        self.assertEqual(len(self.entries), 550)
        self.assertEqual(sum(1 for e in self.entries.values() if e.complete), 532)
        notices.check_gap_policy(self.policy, self.entries)
        self.assertEqual(len(self.policy["gap_table"]), 18)
        self.assertEqual(sorted(self.policy["targets"]), [WINDOWS, LINUX])
        self.assertEqual(self.policy["products"], ["shaar-client", "shaar-server"])

    def test_committed_manifests_are_consistent_with_the_corpus(self):
        by_name = {}
        for entry in self.entries.values():
            by_name.setdefault((entry.name, entry.version, entry.kind), entry)
        for target in self.policy["targets"]:
            with self.subTest(target):
                manifest = self.manifest(target)
                self.assertEqual(manifest["inventories"], self.digests)
                counts = manifest["counts"]
                self.assertEqual(counts["third_party"], len(manifest["identities"]))
                self.assertEqual(counts["complete"], counts["third_party"] - counts["blockers"])
                self.assertEqual(counts["blockers"], len(manifest["blockers"]))
                self.assertEqual(manifest["release_ready"], not manifest["blockers"])
                for item in manifest["identities"]:
                    entry = by_name[(item["name"], item["version"], item["kind"])]
                    self.assertEqual(item["complete"], entry.complete)
                    self.assertEqual(item["checksum"], entry.checksum)
                    self.assertEqual(item["texts"], [t.sha256 for t in notice_render.ordered_texts(entry)])
                gaps = {(b["name"], b["version"]) for b in manifest["blockers"]}
                outside = {(o["name"], o["version"]) for o in manifest["not_distributed"]}
                self.assertEqual(gaps | outside, set(self.policy["gap_table"]))
                self.assertFalse(gaps & outside)
                self.assertEqual(manifest["linked_source"], "cargo-tree")
                for item in manifest["not_distributed"]:
                    self.assertTrue(item["boundary"], item["name"])
                    self.assertFalse(any(row[6] for row in item["boundary"]), item["name"])

    def test_committed_notices_hash_is_reproduced_from_the_manifest_identities(self):
        for target in self.policy["targets"]:
            with self.subTest(target):
                manifest = self.manifest(target)
                found = []
                for item in manifest["identities"]:
                    found.append(next(e for e in self.entries.values()
                                      if (e.name, e.version, e.kind) == (item["name"], item["version"], item["kind"])))
                text, order = notice_render.render_notices(
                    REPO, target, manifest["products"], found, manifest["inventories"], manifest["blockers"])
                self.assertEqual(len(text), manifest["notices"]["bytes"])
                self.assertEqual(sha(text), manifest["notices"]["sha256"])
                self.assertEqual(len(order), manifest["notices"]["texts"])


class WiringTests(unittest.TestCase):
    def test_license_action_runs_tests_and_the_check_before_enforcement(self):
        text = (REPO / ".github/actions/dependency-license/action.yml").read_text("utf-8")
        for needle in (".github/scripts/tests/test_notices.py", "notices/notices.py check", "--tree",
                       "target/third-party-notices"):
            self.assertIn(needle, text)
        self.assertLess(text.index("notices/notices.py check"), text.index("Enforce dependency license gate result"))

    def test_ci_selection_owns_the_notice_paths(self):
        spec = importlib.util.spec_from_file_location("ci_policy_for_notices", REPO / ".github/ci/policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        for path in (".github/actions/dependency-license/notices/notices.py",
                     ".github/scripts/tests/test_notices.py",
                     RELEASE + "/policy.json", RELEASE + "/manifest-%s.json" % LINUX):
            with self.subTest(path):
                selection = policy.select([path])["selection"]
                self.assertTrue(selection["license"])


if __name__ == "__main__":
    unittest.main()
