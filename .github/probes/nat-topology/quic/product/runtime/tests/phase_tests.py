"""CI-only phase-driver contracts: strict evidence conclusions, budgets and owned script lifetime."""

import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

RUNTIME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(RUNTIME.parent))
import contract  # noqa: E402
import network  # noqa: E402
import phase  # noqa: E402

NONCE, SOURCE, UID = "d" * 32, "a" * 40, 1001


def evidence(case):
    spec = contract.CASES[case]
    counters = {name: {"packets": 0, "bytes": 0} for name in network.COUNTERS}
    routers = {}
    for router in ("rtr_a", "rtr_b"):
        routers[router] = {"quota_used": 1000, "quota_limit": network.QUOTAS["product"], "counters": copy.deepcopy(counters)}
    if spec["udp_blocked"]:
        routers["rtr_a"]["counters"]["native_drop"]["packets"] = 3
    observations = {"target": {"accepts": spec["target_accepts"]}, "app": {"denied": False}}
    if not spec["udp_blocked"]:
        observations["native_nat_tuple"] = {"orig": {}, "reply": {}}
    identities = {name: {"uid": UID, "capabilities": 0} for name in ("wan", "target", "server", "client")}
    identities["app"] = {"unsampled": "exited before the receipt was read"}
    return {"status": "pass", "case": case, "purpose": "product", "source_revision": SOURCE,
            "config": {"nonce": NONCE, "helper_uid": UID}, "normal_native_gate_enabled": False,
            "case_result": {"quota_calibration": [{"passed": 8, "dropped": 16}, {"passed": 7, "dropped": 17}],
                            "kernel": routers, "observations": observations, "client_exit": spec["client_exit"],
                            "identities": identities, "forwarded_bytes": 2000, "active_seconds": 12.5}}


class EvidenceTests(unittest.TestCase):
    def test_each_case_has_an_accepting_synthetic_record_and_closed_mutations(self):
        # Metadata verifier tests only; no namespace, kernel or product behavior is claimed here.
        for case in contract.CASES:
            good = evidence(case)
            self.assertEqual(phase.verify_product_case(good, case, SOURCE, NONCE), {"forwarded_bytes": 2000, "active_seconds": 12.5})
            blocked = contract.CASES[case]["udp_blocked"]

            def mutate(name, value, good=good):
                changed = copy.deepcopy(good)
                result = changed["case_result"]
                if name == "status":
                    changed["status"] = value
                elif name == "case":
                    changed["case"] = "native-signal" if case != "native-signal" else "blocked-signal"
                elif name == "nonce":
                    changed["config"]["nonce"] = "e" * 32
                elif name == "source":
                    changed["source_revision"] = "b" * 40
                elif name == "purpose":
                    changed["purpose"] = "fault"
                elif name == "gate":
                    changed["normal_native_gate_enabled"] = True
                elif name == "calibration":
                    result["quota_calibration"][1]["dropped"] = 0
                elif name == "exhausted":
                    result["kernel"]["rtr_b"]["quota_used"] = network.QUOTAS["product"]
                elif name == "router":
                    del result["kernel"]["rtr_b"]
                elif name == "accepts":
                    result["observations"]["target"]["accepts"] = 1 - contract.CASES[case]["target_accepts"]
                elif name == "exit":
                    result["client_exit"] = 1 - contract.CASES[case]["client_exit"]
                elif name == "uid":
                    result["identities"]["server"]["uid"] = 0
                elif name == "caps":
                    result["identities"]["wan"]["capabilities"] = 1
                elif name == "identity":
                    del result["identities"]["client"]
                elif name == "native" and blocked:
                    result["kernel"]["rtr_a"]["counters"]["native_drop"]["packets"] = 0
                elif name == "native":
                    del result["observations"]["native_nat_tuple"]
                return changed

            for name in ("status", "case", "nonce", "source", "purpose", "gate", "calibration", "exhausted", "router",
                         "accepts", "exit", "uid", "caps", "identity", "native"):
                with self.subTest(case=case, mutation=name), self.assertRaises((ValueError, KeyError, TypeError)):
                    phase.verify_product_case(mutate(name, "fail"), case, SOURCE, NONCE)

    def test_validator_exits_become_recorded_problems_not_process_exits(self):
        self.assertIsNone(phase.guarded(lambda argv: argv == ["x"], "x"))
        def rejecting(_argv):
            raise SystemExit(2)
        self.assertIn("exit 2", phase.guarded(rejecting, "x"))


class PlanTests(unittest.TestCase):
    def test_plan_is_closed_sequential_and_within_the_privileged_budgets(self):
        self.assertEqual([entry[0] for entry in phase.PLAN],
                         ["setup-failure", "native-signal", "native-standby", "blocked-standby", "blocked-signal",
                          "live-failure", "interruption"])
        self.assertEqual({entry[1] for entry in phase.PLAN}, {"setup-fault", "product", "fixture-fault", "interrupt"})
        self.assertEqual([entry[2] for entry in phase.PLAN if entry[1] == "product"], list(contract.CASES))
        products = sum(1 for entry in phase.PLAN if entry[1] == "product")
        controls = len(phase.PLAN) - products
        self.assertEqual((products, controls), (4, 3))
        self.assertLessEqual(products * contract.CASE_SECONDS + controls * phase.CONTROL_SECONDS,
                             contract.PHASE_SECONDS - contract.CLEANUP_RESERVE)
        self.assertEqual(phase.ALLOCATED_BYTES, 64 * 1024 * 1024)
        self.assertEqual(phase.ARTIFACT_BYTES, 64 * 1024 * 1024)
        flags = {entry[0]: entry[3] for entry in phase.PLAN}
        self.assertEqual(flags["setup-failure"], ("--fault-inject-setup",))
        self.assertEqual(flags["live-failure"], ("--fault-inject-fixture",))

    def test_artifact_accounting_counts_regular_files_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "a/one").write_bytes(b"12345")
            (root / "two").write_bytes(b"678")
            self.assertEqual(phase.tree_bytes(root), 8)


@unittest.skipUnless(sys.platform == "linux", "owned run.sh lifetime uses POSIX signals")
class ScriptTests(unittest.TestCase):
    def script(self, text):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "run.sh"
        path.write_text("#!/bin/bash\n" + text + "\n", encoding="utf-8")
        return path

    def run_it(self, text, seconds):
        env = {"PATH": os.environ["PATH"]}
        return phase.run_script(self.script(text), ("--flag",), "/case", "nonce", env, seconds)

    def test_exit_status_is_returned_without_escalation(self):
        self.assertEqual(self.run_it('test "$1" = "--flag" && test "$2" = /case && test "$3" = nonce; exit $?', 10), (0, []))
        self.assertEqual(self.run_it("exit 3", 10), (3, []))

    def test_deadline_sends_term_then_kill_and_always_reaps(self):
        with mock.patch.object(phase.contract, "CLEANUP_RESERVE", 5):
            code, notes = self.run_it("exec sleep 30", 0.3)
        self.assertEqual((code, notes), (-15, ["case deadline: TERM", "timed out"]))
        with mock.patch.object(phase.contract, "CLEANUP_RESERVE", 0.5):
            code, notes = self.run_it("trap '' TERM\nexec sleep 30", 0.3)
        self.assertEqual(code, -9)
        self.assertEqual(notes, ["case deadline: TERM", "cleanup deadline: KILL", "timed out"])


if __name__ == "__main__":
    unittest.main()
