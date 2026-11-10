"""CI-only regressions for fine-grained ownership, Git comparison and full triggers."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUN_SPEC = importlib.util.spec_from_file_location("ci_runner", Path(__file__).with_name("run.py"))
RUNNER = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(RUNNER)

SPEC = importlib.util.spec_from_file_location("ci_plan", Path(__file__).with_name("plan.py"))
PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLAN)
POLICY = PLAN.POLICY


class PolicyTests(unittest.TestCase):
    def test_native_graph_ownership_is_narrow(self):
        result = POLICY.select([".github/probes/native-graph/graph.py"])
        self.assertEqual([key for key in POLICY.DOMAINS if result["selection"][key]], ["native_graph"])
        self.assertFalse(result["selection"]["full"])
        self.assertFalse(result["selection"]["sdk"])
        self.assertEqual(result["targets"], [POLICY.target("shaar", kind="test", name="native_graph_witness")])
        manifest = POLICY.select(["crates/shaar/Cargo.toml"])
        self.assertEqual(manifest["targets"], [POLICY.target("shaar")])
        bundled = POLICY.select([".github/probes/native-graph/graph.py", "Cargo.toml",
                                 "crates/shaar/Cargo.toml", "Cargo.lock"])
        self.assertEqual({(target["package"], target["kind"], target["name"]) for target in bundled["targets"]},
                         {("shaar", "test", "native_graph_witness"), ("shaar", "lib", "shaar"),
                          ("shaar-p2p", "lib", "shaar_p2p")})
        self.assertTrue(bundled["selection"]["native_graph"])
        mixed = POLICY.select([".github/probes/native-graph/README.md", "Cargo.toml",
                               "crates/shaar/Cargo.toml", "Cargo.lock"])
        self.assertEqual(mixed["targets"], [POLICY.target("shaar"), POLICY.target("shaar-p2p")])
        self.assertFalse(mixed["selection"]["native_graph"])
        code_manifest = POLICY.select([".github/probes/native-graph/graph.py", "crates/shaar/Cargo.toml"])
        self.assertEqual({(target["kind"], target["name"]) for target in code_manifest["targets"]},
                         {("test", "native_graph_witness"), ("lib", "shaar")})
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select([".github/probes/native-graph/graph.py", "crates/unknown/Cargo.toml"])
        generic = POLICY.select(["Cargo.toml", "crates/shaar-p2p/Cargo.toml", "Cargo.lock"])
        self.assertEqual({target["package"] for target in generic["targets"]}, {"shaar", "shaar-p2p"})

    def test_native_graph_proof_helpers_share_narrow_case_ownership(self):
        expected = [POLICY.target("shaar", kind="test", name="native_graph_witness")]
        for path in (".github/probes/native-graph-proof/cargo_aliases.py",
                     ".github/probes/native-graph-proof/test_aliases.py"):
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertTrue(result["selection"]["native_graph"])
                self.assertFalse(result["selection"]["sdk"])
                self.assertFalse(result["selection"]["full"])
                self.assertEqual(result["targets"], expected)
                self.assertEqual(result["suites"], ["native_graph"])

    def test_publication_fixture_has_narrow_independent_ownership(self):
        prefix = ".github/scripts/p2p/discovery/mainline/ci/publication/"
        for name in ("prepare.py", "execution/ci.py", "execution/verify.sh", "runner.py", "graph.py", "test_source.py", "tests/publication_tests.rs"):
            result = POLICY.select([prefix + name])
            self.assertTrue(result["selection"]["publication"])
            self.assertFalse(result["selection"]["mainline"])
            self.assertFalse(result["selection"]["product"])
            self.assertFalse(result["selection"]["full"])
            self.assertEqual(result["targets"], [])
        mixed = POLICY.select([prefix + "runner.py", ".github/scripts/p2p/discovery/mainline/prepare.py"])
        self.assertTrue(mixed["selection"]["publication"])
        self.assertTrue(mixed["selection"]["mainline"])
        full = POLICY.select([], full=True)
        self.assertTrue(full["selection"]["publication"])

    def test_yggdrasil_linking_manifests_select_the_graph_proof(self):
        witness = POLICY.target("shaar", kind="test", name="native_graph_witness")
        for path in ("crates/shaar-ygg/Cargo.toml", "crates/shaar-ygg-core/Cargo.toml"):
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertTrue(result["selection"]["native_graph"])
                self.assertIn(witness, result["targets"])
        for path in ("crates/shaar/src/path/mod.rs", "Cargo.lock", "crates/shaar/Cargo.toml"):
            with self.subTest(path=path):
                other = POLICY.select([path, "Cargo.toml"] if path == "Cargo.lock" else [path])
                self.assertFalse(other["selection"]["native_graph"])
                self.assertNotIn(witness, other["targets"])

    def test_path_policy_sources_select_only_owned_module_cases(self):
        for filename in ("mod.rs", "model.rs", "policy.rs", "tests/mod.rs", "tests/traces.rs"):
            with self.subTest(filename=filename):
                result = POLICY.select(["crates/shaar/src/path/" + filename])
                self.assertEqual(result["targets"], [POLICY.target("shaar", ("path::",))])
                self.assertEqual(result["suites"], ["sdk-path"])
                self.assertFalse(result["selection"]["full"])
                self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))

    def test_native_discovery_sources_select_only_owned_module_cases(self):
        selector = "native_discovery::"
        for filename in ("address.rs", "codec.rs", "state.rs", "ordering_clock.rs", "unowned.rs"):
            with self.subTest(filename=filename):
                result = POLICY.select(["crates/shaar/src/native_discovery/tests/" + filename])
                self.assertEqual(result["targets"], [POLICY.target("shaar", (selector,))])
                self.assertEqual(result["suites"], ["native-discovery"])
                self.assertFalse(result["selection"]["full"])
                self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))

        for filename in ("prepare.py", "checks.py", "graph_checks.py"):
            result = POLICY.select([".github/scripts/p2p/discovery/simple_dns/" + filename])
            self.assertEqual(result["targets"], [POLICY.target("shaar", (selector,))])
            self.assertFalse(result["selection"]["full"])

        source = POLICY.select(["crates/shaar/src/native_discovery/record.rs"])
        source_target = source["targets"]
        RUNNER.validate(source_target)
        self.assertEqual(source_target, [POLICY.target("shaar", (selector,))])

        listing = ("native_discovery::tests::address::valid: test\n"
                   "native_discovery::tests::codec::roundtrip: test\n"
                   "native_discovery::tests::address::ignored: test\n"
                   "network::unrelated: test\n")
        ignored = "native_discovery::tests::address::ignored: test\n"
        selected, skipped = RUNNER.selected_cases(listing, ignored, [selector])
        self.assertEqual(selected, ["native_discovery::tests::address::valid", "native_discovery::tests::codec::roundtrip"])
        self.assertEqual(skipped, ["native_discovery::tests::address::ignored"])
        with self.assertRaisesRegex(ValueError, "matched no runnable cases"):
            RUNNER.selected_cases("network::unrelated: test\n", "", [selector])

    def test_ygg_preparation_and_nested_core_select_only_owned_checks(self):
        probe = POLICY.select([".github/probes/ygg/prepare.py"])
        self.assertEqual([key for key in POLICY.DOMAINS if probe["selection"][key]], ["ygg"])
        self.assertEqual(probe["suites"], ["ygg"])
        self.assertEqual(probe["targets"], [])
        self.assertTrue(probe["selection"]["prepare"])
        self.assertFalse(probe["selection"]["rust"])
        self.assertFalse(probe["selection"]["full"])
        source = POLICY.select(["crates/shaar-ygg-core/src/lib.rs"])
        self.assertEqual(source["targets"], [POLICY.target("shaar-ygg-core")])
        self.assertEqual(source["suites"], ["package:shaar-ygg-core"])
        self.assertFalse(any(source["selection"][key] for key in POLICY.DOMAINS))
        self.assertTrue(source["selection"]["product"])
        lock = POLICY.select(["crates/shaar-ygg-core/Cargo.lock", "crates/shaar-ygg-core/Cargo.toml"])
        self.assertEqual(lock["targets"], [POLICY.target("shaar", kind="test", name="native_graph_witness"),
                                           POLICY.target("shaar-ygg-core")])
        self.assertTrue(lock["selection"]["native_graph"])
        self.assertEqual(lock["suites"], ["package:shaar-ygg-core"])
        lifecycle = POLICY.select(["crates/shaar-ygg-core/tests/lifecycle.rs"])
        self.assertEqual(lifecycle["targets"],
                         [POLICY.target("shaar-ygg-core", kind="test", name="lifecycle")])
        self.assertEqual(lifecycle["suites"], ["integration:lifecycle"])
        RUNNER.validate(lifecycle["targets"])
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select(["crates/shaar-p2p/Cargo.lock"])
        self.assertEqual(sorted(POLICY.NESTED), ["shaar-ygg-core"])
        self.assertEqual(sorted(RUNNER.NESTED), sorted(POLICY.NESTED))
        RUNNER.validate(source["targets"])

    def test_workspace_manifest_has_explicit_package_ownership_without_full_campaign(self):
        result = POLICY.select(["Cargo.toml"])
        self.assertEqual(result["targets"], sorted(
            (POLICY.target(package) for package in ("shaar", "shaar-p2p")),
            key=lambda target: (target["package"], target["kind"], target["name"])))
        self.assertEqual(result["suites"], ["workspace-manifest"])
        self.assertTrue(result["selection"]["license"])
        self.assertFalse(result["selection"]["full"])
        self.assertFalse(result["selection"]["backend"])

    def test_lock_with_root_manifest_selects_workspace_contract_cases(self):
        result = POLICY.select(["Cargo.lock", "Cargo.toml"])
        self.assertEqual(result["targets"], [POLICY.target("shaar"), POLICY.target("shaar-p2p")])
        self.assertEqual(result["suites"], ["workspace-manifest"])
        self.assertTrue(result["selection"]["license"])
        self.assertFalse(result["selection"]["full"])
        cumulative = POLICY.select(["Cargo.lock", "Cargo.toml",
                                   ".github/probes/native-graph-multibase/prepare.py"])
        self.assertTrue(cumulative["selection"]["native_graph"])
        self.assertEqual({(target["package"], target["kind"], target["name"])
                          for target in cumulative["targets"]},
                         {("shaar", "lib", "shaar"), ("shaar", "test", "native_graph_witness"),
                          ("shaar-p2p", "lib", "shaar_p2p")})
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select(["Cargo.lock"])

    def test_integration_test_source_selects_only_its_owned_target(self):
        result = POLICY.select(["crates/shaar-p2p/tests/multibase_base58.rs"])
        self.assertEqual(result["targets"],
                         [POLICY.target("shaar-p2p", kind="test", name="multibase_base58")])
        self.assertEqual(result["suites"], ["integration:multibase_base58"])
        self.assertTrue(result["selection"]["product"])
        self.assertTrue(result["selection"]["rust"])
        self.assertFalse(result["selection"]["full"])
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select(["crates/shaar-unknown/tests/new.rs"])

    def test_native_discovery_wiring_and_manifest_lock_contracts_are_wide(self):
        module = POLICY.select(["crates/shaar/src/lib.rs", "crates/shaar/src/native_discovery/mod.rs"])
        self.assertEqual(module["targets"], [POLICY.target("shaar", ("", "native_discovery::"))])
        self.assertEqual(module["suites"], ["native-discovery", "package:shaar"])
        self.assertFalse(module["selection"]["full"])
        manifest = POLICY.select(["crates/shaar/Cargo.toml"])
        self.assertEqual(manifest["targets"], [POLICY.target("shaar")])
        self.assertTrue(manifest["selection"]["license"])
        self.assertEqual(POLICY.select(["crates/shaar-p2p/Cargo.toml", "Cargo.lock"])["targets"],
                         [POLICY.target("shaar-p2p")])
        for paths, expected_license, mixed in (
            (["crates/shaar/src/native_discovery/README.md", "crates/shaar/src/lib.rs"], False, False),
            (["crates/shaar/src/native_discovery/README.md", "crates/shaar/Cargo.toml"], True, False),
            (["crates/shaar/src/native_discovery/README.md", "crates/shaar/Cargo.toml", "Cargo.lock"], True, False),
            (["crates/shaar/src/native_discovery/record.rs", "crates/shaar/src/lib.rs"], False, True),
            (["crates/shaar/src/native_discovery/record.rs", "crates/shaar/Cargo.toml"], True, True),
            (["crates/shaar/src/native_discovery/record.rs", "crates/shaar/Cargo.toml", "Cargo.lock"], True, True),
        ):
            with self.subTest(paths=paths):
                result = POLICY.select(paths)
                expected = ["", "native_discovery::"] if mixed else [""]
                self.assertEqual(result["targets"], [POLICY.target("shaar", expected)])
                self.assertEqual(result["selection"]["license"], expected_license)
                self.assertFalse(result["selection"]["full"])
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select(["Cargo.lock"])

    def test_workspace_manifest_selects_only_patch_consumers_with_runnable_cases(self):
        result = POLICY.select(["Cargo.toml"])
        self.assertEqual(result["targets"], [POLICY.target("shaar"), POLICY.target("shaar-p2p")])
        self.assertEqual(result["suites"], ["workspace-manifest"])
        self.assertTrue(result["selection"]["license"])
        self.assertFalse(result["selection"]["full"])
        RUNNER.validate(result["targets"])
        # A package-wide selector over a binary without runnable cases is a hard error.
        with self.assertRaisesRegex(ValueError, "matched no runnable cases"):
            RUNNER.selected_cases("", "", [""])

    def test_native_discovery_cumulative_repair_keeps_each_case_obligation(self):
        paths = ["crates/shaar/src/native_discovery/tests/address.rs",
                 "crates/shaar/src/native_discovery/tests/codec.rs",
                 "crates/shaar/src/native_discovery/tests/codec/mod.rs",
                 "crates/shaar/src/native_discovery/tests/codec/mutable.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result["targets"], [POLICY.target("shaar", ("native_discovery::",))])
        self.assertEqual(result["suites"], ["native-discovery"])
        self.assertEqual(result, POLICY.select(list(reversed(paths))))

    def test_unrelated_shaar_shared_wiring_keeps_package_default(self):
        for path in ("crates/shaar/src/lib.rs", "crates/shaar/Cargo.toml"):
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertEqual(result["targets"], [POLICY.target("shaar")])
                self.assertEqual(result["suites"], ["package:shaar"])
                self.assertFalse(result["selection"]["full"])
                expected_domains = ["license"] if path.endswith("Cargo.toml") else []
                self.assertEqual([key for key in POLICY.DOMAINS if result["selection"][key]], expected_domains)

    def test_protocol_feature_selects_own_cases_and_small_wiring_contracts_only(self):
        paths = ["crates/shaar-p2p/src/carrier/driver/runtime/protocols/guard.rs",
                 "crates/shaar-p2p/src/carrier/driver/mod.rs",
                 "crates/shaar-p2p/src/carrier/driver/runtime/events/mod.rs",
                 "crates/shaar-p2p/src/carrier/driver/runtime/infrastructure_tests/identification.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result["suites"], ["carrier-core", "protocols"])
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(result["targets"][0]["package"], "shaar-p2p")
        self.assertIn("carrier::driver::protocols::", result["targets"][0]["filters"])
        self.assertIn("infrastructure::tests::identification::", result["targets"][0]["filters"])
        self.assertIn("carrier::driver::events::request_owner::tests::", result["targets"][0]["filters"])
        core = POLICY.select(["crates/shaar-p2p/src/carrier/driver/runtime/events/request_owner.rs"])
        self.assertEqual(core["suites"], ["carrier-core"])
        self.assertIn("carrier::driver::events::request_owner::tests::", core["targets"][0]["filters"])
        test_source = POLICY.select(["crates/shaar-p2p/src/carrier/driver/runtime/events/request_owner_tests.rs"])
        self.assertEqual(test_source["suites"], ["carrier-core"])
        self.assertIn("carrier::driver::events::request_owner::tests::", test_source["targets"][0]["filters"])
        self.assertNotIn("", result["targets"][0]["filters"])
        self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertTrue(result["selection"]["product"])
        self.assertFalse(result["selection"]["full"])

    def test_fault_test_source_and_driver_wiring_select_fault_cases(self):
        selector = "carrier::driver::fault_tests::"
        fault_source = POLICY.select(["crates/shaar-p2p/src/carrier/fault_tests.rs"])
        self.assertEqual(fault_source["suites"], ["carrier-core"])
        self.assertIn(selector, fault_source["targets"][0]["filters"])
        self.assertFalse(fault_source["selection"]["full"])

        driver_wiring = POLICY.select(["crates/shaar-p2p/src/carrier/driver/mod.rs"])
        self.assertEqual(driver_wiring["suites"], ["carrier-core"])
        self.assertIn(selector, driver_wiring["targets"][0]["filters"])
        self.assertFalse(driver_wiring["selection"]["full"])

        cumulative_repair = POLICY.select([
            "crates/shaar-p2p/src/carrier/fault_tests.rs",
            "crates/shaar-p2p/src/carrier/driver/mod.rs",
        ])
        self.assertIn(selector, cumulative_repair["targets"][0]["filters"])
        self.assertFalse(any(cumulative_repair["selection"][key] for key in POLICY.DOMAINS))
        self.assertFalse(cumulative_repair["selection"]["full"])

    def test_relay_gate_includes_provenance_and_handoff_contracts_without_broad_proofs(self):
        for suffix in ("gate.rs", "gate_factory.rs", "gate_test_support.rs"):
            with self.subTest(suffix=suffix):
                result = POLICY.select(["crates/shaar-p2p/src/carrier/relay/" + suffix])
                self.assertEqual(result["suites"], ["carrier-relay", "relay-gate"])
                self.assertEqual(len(result["targets"]), 1)
                target = result["targets"][0]
                self.assertEqual(target["package"], "shaar-p2p")
                self.assertIn("carrier::driver::roles_gate_tests::", target["filters"])
                self.assertIn("carrier::driver::roles_tests::", target["filters"])
                self.assertIn("infrastructure::tests::identification::handoff::", target["filters"])
                self.assertNotIn("", target["filters"])
                self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
                self.assertFalse(result["selection"]["full"])

    def test_carrier_frame_sources_select_only_their_owned_proof(self):
        paths = [".github/probes/iroh-paths/carrier/" + name
                 for name in ("probe.rs", "instrument.py", "graph.py", "run.py", "checks.py")]
        paths.append(".github/probes/iroh-paths/gate/bridge/support/packet_identity.py")
        for path in paths:
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertEqual([key for key in POLICY.DOMAINS if result["selection"][key]], ["carrier_frames"])
                self.assertEqual(result["suites"], ["carrier_frames"])
                self.assertFalse(result["targets"])
                self.assertTrue(result["selection"]["prepare"])
                self.assertFalse(result["selection"]["full"])
                self.assertFalse(result["selection"]["product"])

    def test_mainline_proofs_select_only_their_owned_domain(self):
        result = POLICY.select([".github/scripts/p2p/discovery/mainline/checks.py"])
        self.assertEqual([key for key in POLICY.DOMAINS if result["selection"][key]], ["mainline"])
        self.assertTrue(result["selection"]["prepare"])
        self.assertFalse(result["selection"]["rust"])
        self.assertFalse(result["selection"]["product"])
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["suites"], ["mainline"])
        for other in ("dns", "relay", "sdk"):
            self.assertFalse(result["selection"][other])
        with self.assertRaisesRegex(ValueError, "No test impact rule"):
            POLICY.select([".github/scripts/unowned-mainline.py"])

    def test_dependency_proofs_only_follow_changed_dependency_owner(self):
        cases = {".github/scripts/p2p/discovery/resolver/prepare.py": "resolver",
                 ".github/scripts/p2p/discovery/kad/kad.py": "kad",
                 ".github/scripts/p2p/relay/fixtures/wire/run.py": "relay",
                 ".github/scripts/tests/noq_driver/prepare.py": "backend"}
        for path, owner in cases.items():
            with self.subTest(path=path):
                result = POLICY.select([path])
                self.assertEqual([k for k in POLICY.DOMAINS if result["selection"][k]], [owner])
                self.assertFalse(result["targets"])
                self.assertTrue(result["selection"]["prepare"])

    def test_docs_and_ci_policy_do_not_compile_rust(self):
        for paths in (["docs/plans/new.md", "CLAUDE.md"], [".github/ci/policy.py"]):
            result = POLICY.select(paths)
            self.assertFalse(result["selection"]["prepare"])
            self.assertFalse(result["selection"]["rust"])
        self.assertTrue(POLICY.select([".github/ci/policy.py"])["selection"]["ci_policy"])

    def test_legal_material_selects_license_domain_and_unknown_paths_fail_closed(self):
        material = POLICY.select(["docs/legal/notices-material/ygg-pinned-revision-c9a54f1-LICENSE"])
        self.assertEqual([key for key in POLICY.DOMAINS if material["selection"][key]], ["license"])
        self.assertFalse(material["selection"]["full"])
        self.assertFalse(material["selection"]["rust"])
        self.assertFalse(material["selection"]["sdk"])
        self.assertEqual(material["targets"], [])
        self.assertEqual(material["suites"], ["license"])
        self.assertEqual(material["reasons"],
                         [{"path": "docs/legal/notices-material/ygg-pinned-revision-c9a54f1-LICENSE",
                           "suites": ["license"]}])
        with self.assertRaisesRegex(ValueError, "No test impact rule for docs/legal/unowned-material"):
            POLICY.select(["docs/legal/unowned-material"])

    def test_unknown_paths_empty_comparison_and_shared_lock_fail_not_expand(self):
        for paths in ([], ["new-component/code.rs"], ["Cargo.lock"],
                      ["crates/shaar-p2p/src/new-unknown/module.rs"]):
            with self.subTest(paths=paths):
                with self.assertRaises(ValueError):
                    POLICY.select(paths)

    def test_unions_are_order_independent_and_targets_deduplicate(self):
        paths = ["crates/shaar-p2p/src/discovery/roles/mod.rs",
                 "crates/shaar-p2p/src/discovery/roles/infrastructure/tests/contacts.rs"]
        result = POLICY.select(paths)
        self.assertEqual(result, POLICY.select(list(reversed(paths))))
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(result["targets"][0]["filters"],
                         ["discovery::roles::", "discovery::roles::infrastructure::tests::contacts::"])

    def test_full_is_all_explicit_proofs_without_targeted_double_execution(self):
        result = POLICY.select([], full=True)
        self.assertTrue(all(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertTrue(result["selection"]["full"])
        self.assertFalse(result["targets"])
        self.assertEqual(result["suites"], ["full"])

    def test_commit_values_cannot_be_git_options_or_shell(self):
        for value in ("--help", "$(command)", "a" * 39, "0" * 40, None):
            with self.assertRaises(ValueError):
                PLAN.commit(value)

    def test_marker_is_an_exact_separate_line(self):
        self.assertTrue(PLAN.FULL_MARKER.search("subject\n\n[ci:full]\n"))
        self.assertTrue(PLAN.FULL_MARKER.search("subject\r\n[ci:full]\r\n"))
        for message in ("subject [ci:full]", "> [ci:full]", " [ci:full]", "[ci:full ]", "[ci:FULL]"):
            self.assertFalse(PLAN.FULL_MARKER.search(message))


class GitTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(os.chdir, self.old)
        self.git("init", "-q")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "ci@example.invalid")

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.STDOUT).decode().strip()

    def commit_file(self, name, text, message="fixture"):
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.git("add", "--all")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def event(self, base, head, ref="refs/heads/develop"):
        return {"before": base, "after": head, "ref": ref}

    def test_rename_and_deletion_include_both_sides(self):
        base = self.commit_file("old.rs", "one")
        Path("old.rs").rename("new.rs")
        head = self.commit_file("docs/new.md", "two")
        paths, actual, _ = PLAN.changes("push", self.event(base, head), head)
        self.assertEqual(set(paths), {"old.rs", "new.rs", "docs/new.md"})
        self.assertEqual(actual, base)

    def test_feature_repair_preserves_original_own_test_selectors(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file("crates/shaar/src/network/mod.rs", "two")
        failed = self.commit_file("crates/shaar-p2p/src/carrier/fault_tests.rs", "fault obligation", "fault tests")
        head = self.commit_file("crates/shaar-p2p/src/carrier/driver/runtime/protocols/guard.rs", "three")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        self.assertEqual({t["package"] for t in result["targets"]}, {"shaar", "shaar-p2p"})
        p2p_target = next(t for t in result["targets"] if t["package"] == "shaar-p2p")
        self.assertIn("carrier::driver::fault_tests::", p2p_target["filters"])
        self.assertFalse(result["selection"]["backend"])

    def test_native_discovery_obligation_survives_policy_only_repair_push(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file("crates/shaar/src/native_discovery/tests/address.rs", "native test")
        head = self.commit_file(".github/ci/policy.py", "policy repair")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        self.assertEqual({(target["package"], tuple(target["filters"])) for target in result["targets"]},
                         {("shaar", ("native_discovery::",))})
        self.assertTrue(result["selection"]["ci_policy"])
        self.assertFalse(any(result["selection"][key] for key in POLICY.DOMAINS))
        self.assertFalse(result["selection"]["full"])

    def test_native_discovery_shared_obligation_survives_policy_only_repair_push(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file("crates/shaar/src/native_discovery/tests/address.rs", "native test")
        failed = self.commit_file("crates/shaar/src/lib.rs", "shared wiring")
        failed = self.commit_file("crates/shaar/Cargo.toml", "manifest")
        failed = self.commit_file("Cargo.lock", "lock")
        head = self.commit_file(".github/ci/policy.py", "policy repair")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        shaar = next(target for target in result["targets"] if target["package"] == "shaar")
        self.assertEqual(shaar["filters"], ["", "native_discovery::"])
        self.assertTrue(result["selection"]["license"])
        self.assertTrue(result["selection"]["ci_policy"])
        self.assertFalse(result["selection"]["full"])

    def test_mainline_obligation_survives_policy_only_repair_push(self):
        base = self.commit_file("common.rs", "one")
        self.git("update-ref", "refs/remotes/ci-upstream/develop", base)
        failed = self.commit_file(".github/scripts/p2p/discovery/mainline/owner.rs", "mainline obligation")
        head = self.commit_file(".github/ci/policy.py", "policy repair")
        result = PLAN.plan("push", self.event(failed, head, "refs/heads/feature"), head)
        self.assertEqual(result["base"], base)
        self.assertTrue(result["selection"]["mainline"])
        self.assertEqual(result["targets"], [])
        self.assertFalse(result["selection"]["full"])
        self.assertIn(".github/scripts/p2p/discovery/mainline/owner.rs",
                      [reason["path"] for reason in result["reasons"]])

    def test_missing_history_is_not_a_full_trigger(self):
        head = self.commit_file("docs/new.md", "one")
        with self.assertRaisesRegex(ValueError, "no automatic full fallback"):
            PLAN.plan("push", self.event("0" * 40, head), head)

    def test_current_commit_marker_triggers_full_even_without_a_base(self):
        head = self.commit_file("unknown.rs", "one", "sprint acceptance\n\n[ci:full]")
        result = PLAN.plan("push", self.event("0" * 40, head), head)
        self.assertEqual(result["trigger"], "commit-marker")
        self.assertTrue(result["selection"]["full"])

    def test_old_commit_marker_is_not_inherited(self):
        base = self.commit_file("docs/old.md", "one", "old sprint\n\n[ci:full]")
        head = self.commit_file("docs/new.md", "two")
        result = PLAN.plan("push", self.event(base, head), head)
        self.assertEqual(result["scope"], "targeted")
        self.assertFalse(result["selection"]["rust"])

    def test_pr_reads_real_head_message_not_checkout_merge_message(self):
        initial = self.commit_file("common.rs", "one")
        self.git("checkout", "-qb", "feature")
        head = self.commit_file("docs/new.md", "two")
        self.git("checkout", "-qb", "base", initial)
        base = self.commit_file("other.rs", "three", "merge text\n\n[ci:full]")
        event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
        result = PLAN.plan("pull_request", event, base)
        self.assertFalse(result["selection"]["full"])
        self.assertEqual(result["head"], head)
        self.assertEqual(result["base"], initial)

    def test_actions_manual_full_and_targeted_are_available(self):
        self.commit_file("docs/old.md", "one")
        head = self.commit_file("docs/new.md", "two")
        targeted = PLAN.plan("workflow_dispatch", {"inputs": {"scope": "targeted"}}, head, "refs/heads/develop")
        self.assertFalse(targeted["selection"]["rust"])
        full = PLAN.plan("workflow_dispatch", {"inputs": {"scope": "full"}}, head)
        self.assertEqual(full["trigger"], "manual-full")
        self.assertTrue(full["selection"]["full"])
        with self.assertRaises(ValueError):
            PLAN.plan("workflow_dispatch", {"inputs": {"scope": "typo"}}, head)


class ControlTransportTests(unittest.TestCase):
    base = "79e36e2aa77b0aa669dc58d91318427edce5db71"
    head = "dd2da363b7d7552ceaf3c25076aac18132fd3cbe"

    root = Path(__file__).resolve().parents[2]

    def tranche(self):
        raw = subprocess.check_output(
            ["git", "diff", "--no-renames", "--name-only", "-z", self.base, self.head], cwd=self.root)
        paths = [path for path in raw.decode("utf-8").split("\0") if path]
        result = POLICY.select(paths)
        result.update(scope="targeted", event="push", base=self.base, head=self.head,
                      checkout=self.head, trigger="diff")
        return result

    def test_authentic_tranche_preserves_receipt_and_bounds_control_transport(self):
        result = self.tranche()
        self.assertEqual(len(result["reasons"]), 897)
        self.assertEqual(result["targets"], [])
        self.assertTrue(result["selection"]["license"])
        self.assertFalse(result["selection"]["mainline"])
        self.assertFalse(result["selection"]["full"])
        compact = json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        receipt = (json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        self.assertEqual(len(compact), 156718)
        self.assertEqual(len(receipt), 194579)
        self.assertEqual(hashlib.sha256(receipt).hexdigest(),
                         "a5ae366781fad60d86dddcbd66e6920c1bcdbb36fad3f859da0445b707659d01")

        _, _, _, control = PLAN.serialize_outputs(result, self.head)
        expanded = dict(result)
        expanded["reasons"] = result["reasons"] + [{"path": "extra-source", "suites": ["license"]}]
        self.assertEqual(PLAN.serialize_outputs(expanded, self.head)[3], control)

        old = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            os.chdir(directory)
            try:
                event_path = Path(directory) / "event.json"
                output_path = Path(directory) / "output"
                summary_path = Path(directory) / "summary"
                event_path.write_text("{}", encoding="utf-8")
                with patch.dict(os.environ, {
                        "GITHUB_EVENT_PATH": str(event_path), "GITHUB_EVENT_NAME": "push",
                        "GITHUB_SHA": self.head, "GITHUB_OUTPUT": str(output_path),
                        "GITHUB_STEP_SUMMARY": str(summary_path)}), \
                        patch.object(PLAN, "plan", return_value=result), patch("builtins.print"):
                    PLAN.main()
                receipt_path = Path(directory) / "ci-plan.json"
                self.assertEqual(receipt_path.read_bytes(), receipt)
                self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), result)
                output = dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())
            finally:
                os.chdir(old)

        self.assertEqual(json.loads(output["selection"]), result["selection"])
        self.assertEqual(json.loads(output["targets"]), result["targets"])
        control_raw = output[PLAN.CONTROL_OUTPUT].encode("utf-8")
        control_value = json.loads(control_raw)
        self.assertEqual(control_value, {key: result[key] for key in PLAN.CONTROL_KEYS})
        self.assertNotIn("reasons", control_value)
        self.assertLessEqual(len(control_raw), PLAN.CONTROL_LIMIT)
        child = subprocess.run(
            [sys.executable, "-I", "-c",
             "import json,os; c=json.loads(os.environ['CI_PLAN_JSON']); "
             "print(json.dumps([c[k] for k in ('scope','head','base','checkout')]))"],
            env=dict(os.environ, CI_PLAN_JSON=control_raw.decode("utf-8")),
            capture_output=True, text=True, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), ["targeted", self.head, self.base, self.head])

    def test_control_rejects_missing_malformed_mismatched_and_oversized_inputs(self):
        original = self.tranche()
        mutations = []
        missing = dict(original)
        del missing["base"]
        mutations.append(missing)
        missing_selection = dict(original)
        del missing_selection["selection"]
        mutations.append(missing_selection)
        malformed_boolean = dict(original, selection=dict(original["selection"]))
        malformed_boolean["selection"]["license"] = 1
        mutations.append(malformed_boolean)
        unknown_selection = dict(original, selection=dict(original["selection"]))
        unknown_selection["selection"]["unknown"] = False
        mutations.append(unknown_selection)
        mutations.append(None)
        malformed_selection = dict(original, selection=None)
        mutations.append(malformed_selection)
        scope_mismatch = dict(original, scope="full")
        mutations.append(scope_mismatch)
        malformed = dict(original, head="z" * 40)
        mutations.append(malformed)
        zero_head = dict(original, head="0" * 40)
        mutations.append(zero_head)
        bad_base = dict(original, base="z" * 40)
        mutations.append(bad_base)
        null_base = dict(original, base=None)
        mutations.append(null_base)
        checkout_mismatch = dict(original, checkout="a" * 40)
        mutations.append(checkout_mismatch)
        with tempfile.TemporaryDirectory() as directory:
            for index, result in enumerate(mutations):
                receipt = Path(directory) / (str(index) + ".json")
                output = Path(directory) / (str(index) + ".output")
                summary = Path(directory) / (str(index) + ".summary")
                with self.subTest(index=index), self.assertRaises(ValueError):
                    PLAN.write_outputs(result, self.head, receipt, output, summary)
                self.assertFalse(receipt.exists())
                self.assertFalse(output.exists())
                self.assertFalse(summary.exists())
        with patch.object(PLAN, "CONTROL_LIMIT", 1):
            with self.assertRaisesRegex(ValueError, "bounded transport"):
                PLAN.serialize_outputs(original, self.head)

    def test_full_control_accepts_null_base_and_distinct_pull_request_head(self):
        result = POLICY.select([], full=True)
        pr_head = "a" * 40
        result.update(scope="full", event="pull_request", base=None, head=pr_head,
                      checkout=self.head, trigger="commit-marker")
        _, selection, _, control = PLAN.serialize_outputs(result, self.head)
        self.assertTrue(json.loads(selection)["full"])
        value = json.loads(control)
        self.assertEqual(value, {key: result[key] for key in PLAN.CONTROL_KEYS})
        self.assertNotEqual(value["head"], value["checkout"])

    def test_mainline_and_publication_controls_preserve_policy_selection(self):
        for path, domain in (
                (".github/scripts/p2p/discovery/mainline/checks.py", "mainline"),
                (".github/scripts/p2p/discovery/mainline/ci/publication/prepare.py", "publication")):
            with self.subTest(domain=domain):
                result = POLICY.select([path])
                self.assertTrue(result["selection"][domain])
                result.update(scope="targeted", event="push", base=self.base, head=self.head,
                              checkout=self.head, trigger="diff")
                _, _, _, control = PLAN.serialize_outputs(result, self.head)
                value = json.loads(control)
                self.assertEqual(value["selection"], result["selection"])
                self.assertEqual((value["scope"], value["head"], value["base"], value["checkout"]),
                                 ("targeted", self.head, self.base, self.head))


if __name__ == "__main__":
    unittest.main()
