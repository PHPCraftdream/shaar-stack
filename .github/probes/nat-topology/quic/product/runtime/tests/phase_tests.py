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
# Every case x 2 routers x {product, fault}, 2 calibration tables, 2 NAT probes, the observation table and 3 dynamic blocks.
TOTAL_RULESETS = len(contract.CASES) * 2 * 2 + 2 + 2 + 1 + 3


def zero_counters():
    return {name: {"packets": 0, "bytes": 0} for name in network.COUNTERS}


def failover_record(spec):
    base = {"app1_native_snat_packets": 12, "block_native_snat_packets": 0, "block_ygg_tcp_packets": 9,
            "native_block_drops": {"rtr_a": {"packets": 5, "bytes": 500}, "rtr_b": {"packets": 0, "bytes": 0}}}
    if spec["mode"] == "signal":
        return {**base, "app2": {"denied": True, "reply_bytes": 0, "terminal": "reset"}}
    return {**base, "failover_seconds": 4.2, "recovery_seconds": 7.5, "recovery_native_snat_packets": 6,
            "app2": {"denied": False, "reply_bytes": 61}, "app3": {"denied": False, "reply_bytes": 61}}


def evidence(case):
    spec = contract.CASES[case]
    net = spec["net"]
    routers = {router: {"quota_used": 1000, "quota_limit": network.QUOTAS["product"], "counters": zero_counters()}
               for router in ("rtr_a", "rtr_b")}
    observations = {"target": {"accepts": spec["target_accepts"]}, "app": {"denied": False}}
    publication = {"native_addresses": [contract.ip_for(spec["server_ns"]) + ":40000"]}
    result_extra = {}
    if net == "dnat":
        kept, moved = (3, 0) if spec["nat"] == "cone" else (0, 3)
        result_extra["nat_calibration"] = [{"router": router, "flavor": spec["nat"], "kept": kept, "moved": moved} for router in routers]
        if spec["nat"] == "cone":
            result_extra["punch_control"] = {"status": "pass", "receipts": [
                {"host": "host_a", "sent": 20, "received": 18, "first": ["203.0.113.2", 40100]},
                {"host": "host_b", "sent": 20, "received": 19, "first": ["203.0.113.1", 40100]}]}
        if spec["direct"]:
            for router in routers:
                routers[router]["counters"]["peer_sent"]["packets"] = 5
                routers[router]["counters"]["peer_recv"]["packets"] = 6
        elif not spec["ygg_client_blocked"] and spec["mode"] == "standby":
            routers["rtr_a"]["counters"]["ygg_tcp"]["packets"] = 9
        if spec.get("relay_first"):
            routers["rtr_a"]["counters"]["dht_drop"]["packets"] = 3
            routers["rtr_a"]["counters"]["relay_tcp"]["packets"] = 40
    elif net == "relay":
        observations = {"target": {"accepts": 0}, "relay_full": {"server_exit": 1, "seconds": 31.0,
                                                                  "message": "shaar-server: composed startup: relay reservation failed at startup"}}
    elif net == "recover":
        observations["outage"] = {"client1_exit": 1, "app_outage": {"denied": True, "reply_bytes": 0, "terminal": "reset"},
                                  "recovery_seconds": 6.5, "app2": {"denied": False, "reply_bytes": 61}}
    elif net == "ipv6":
        for router in routers:
            routers[router]["quota_used"] = 0
            routers[router]["counters"]["lan6_native"]["packets"] = 7
            routers[router]["counters"]["lan6_sent"]["packets"] = 7
        publication = {"native_addresses": ["203.0.113.2:40000", "[2001:db8:13::2]:40001"]}
        observations["ipv6"] = {"hint": "[2001:db8:13::2]:40001",
                                "v4_block_drops": {"rtr_a": {"packets": 4, "bytes": 400}, "rtr_b": {"packets": 0, "bytes": 0}}}
    if net == "blocked":
        routers["rtr_a"]["counters"]["native_drop"]["packets"] = 3
    elif net in ("nat", "failover"):
        routers["rtr_a"]["counters"]["udp_nat"]["packets"] = 4
        routers["rtr_a"]["counters"]["native_snat"]["packets"] = 2
        if net == "nat":
            observations["native_nat_tuple"] = {"orig": {}, "reply": {}}
        else:
            observations["failover"] = failover_record(spec)
    elif net == "lan":
        for router in routers:
            routers[router]["quota_used"] = 0
            routers[router]["counters"]["lan_native"]["packets"] = 7
            routers[router]["counters"]["lan_sent"]["packets"] = 7
    elif net == "dht-drop":
        routers["rtr_a"]["counters"]["dht_drop"]["packets"] = 3
        routers["rtr_a"]["counters"]["udp_nat"]["packets"] = 4
        routers["rtr_a"]["counters"]["native_snat"]["packets"] = 2
    if spec.get("flow") in ("hole", "switch"):
        observations["perturb"] = {"kind": "nat-state-flush", "recovery_seconds": 8.0, "app2": {"denied": False, "reply_bytes": 61},
                                   "growth": {"native_new": 2, "native_snat": 5}}
    if spec.get("flow") == "denied-key":
        observations.update(client1_exit=0, denied_app={"denied": True, "reply_bytes": 0})
    identities = {name: {"uid": UID, "capabilities": 0} for name in contract.identity_roles(spec)}
    detector = {"outside_fwd": 3, "outside_out": 3, "udp53": 2, "tcp443": 2}
    return {"status": "pass", "case": case, "purpose": "product", "source_revision": SOURCE,
            "config": {"nonce": NONCE, "helper_uid": UID}, "normal_native_gate_enabled": False,
            "case_result": {"quota_calibration": [{"passed": 8, "dropped": 16}, {"passed": 7, "dropped": 17}],
                            "kernel": routers, "observations": observations, "publication": publication,
                            "client_exit": contract.final_client_exit(spec), "identities": identities, **result_extra,
                            "observe": {router: {name: 0 for name in detector} for router in routers},
                            "observe_calibration": [{"router": router, "detected": dict(detector)} for router in routers],
                            "forwarded_bytes": 2000, "active_seconds": 12.5}}


def mutate(case, name):
    spec = contract.CASES[case]
    changed = copy.deepcopy(evidence(case))
    result = changed["case_result"]
    counters = result["kernel"]
    if name == "status":
        changed["status"] = "fail"
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
        counters["rtr_b"]["quota_used"] = network.QUOTAS["product"]
    elif name == "router":
        del counters["rtr_b"]
    elif name == "accepts":
        result["observations"]["target"]["accepts"] = spec["target_accepts"] + 1
    elif name == "exit":
        result["client_exit"] = 1 - (contract.final_client_exit(spec) or 0)
    elif name == "uid":
        result["identities"]["server"]["uid"] = 0
    elif name == "caps":
        result["identities"]["wan"]["capabilities"] = 1
    elif name == "identity":
        del result["identities"]["server"]
    elif name == "outside":
        result["observe"]["rtr_a"]["outside_out"] = 1
    elif name == "outside-fwd":
        result["observe"]["rtr_b"]["udp53"] = 1
    elif name == "detector":
        result["observe_calibration"][0]["detected"]["outside_fwd"] = 0
    elif name == "native_drop":
        counters["rtr_a"]["counters"]["native_drop"]["packets"] = 0
    elif name == "escape":
        counters["rtr_b"]["counters"]["native_snat"]["packets"] = 1
    elif name == "native_snat":
        counters["rtr_a"]["counters"]["native_snat"]["packets"] = 0
    elif name == "udp_nat":
        counters["rtr_a"]["counters"]["udp_nat"]["packets"] = 0
    elif name == "tuple":
        del result["observations"]["native_nat_tuple"]
    elif name == "forwarded":
        counters["rtr_b"]["quota_used"] = 1
    elif name == "nat-hit":
        counters["rtr_a"]["counters"]["udp_nat"]["packets"] = 1
    elif name == "no-lan-traffic":
        counters["rtr_b"]["counters"]["lan_native"]["packets"] = 0
    elif name == "wrong-address":
        result["publication"]["native_addresses"] = ["198.51.100.1:40000"]
    elif name == "no-dht-drop":
        counters["rtr_a"]["counters"]["dht_drop"]["packets"] = 0
    elif name == "slow-failover":
        result["observations"]["failover"]["failover_seconds"] = contract.FAILOVER_SECONDS + 0.1
    elif name == "slow-recovery":
        result["observations"]["failover"]["recovery_seconds"] = contract.RECOVERY_SECONDS + 0.1
    elif name == "block-escape":
        result["observations"]["failover"]["block_native_snat_packets"] = 1
    elif name == "no-ygg":
        result["observations"]["failover"]["block_ygg_tcp_packets"] = 0
    elif name == "no-block-drop":
        result["observations"]["failover"]["native_block_drops"]["rtr_a"]["packets"] = 0
    elif name == "signal-reply":
        result["observations"]["failover"]["app2"]["reply_bytes"] = 5
    elif name == "denied-reply":
        result["observations"]["denied_app"]["reply_bytes"] = 5
    elif name == "control-exit":
        result["observations"]["client1_exit"] = 1
    elif name == "peer-recv":
        counters["rtr_b"]["counters"]["peer_recv"]["packets"] = 0
    elif name == "peer-sent":
        counters["rtr_a"]["counters"]["peer_sent"]["packets"] = 0
    elif name == "probe-flavor":
        result["nat_calibration"][0]["kept"] = 1
    elif name == "probe-missing":
        del result["nat_calibration"][1]
    elif name == "punch-missing":
        del result["punch_control"]
    elif name == "punch-garbled":
        result["punch_control"]["receipts"] = result["punch_control"]["receipts"][:1]
    elif name == "punch-unknown-status":
        result["punch_control"]["status"] = "skipped"
    elif name == "direct-path":
        counters["rtr_a"]["counters"]["peer_recv"]["packets"] = 1
    elif name == "no-relay-negotiation":
        counters["rtr_a"]["counters"]["relay_tcp"]["packets"] = 0
    elif name == "no-dht-drop-seen":
        counters["rtr_a"]["counters"]["dht_drop"]["packets"] = 0
    elif name == "ygg-used":
        counters["rtr_a"]["counters"]["ygg_tcp"]["packets"] = 1
    elif name == "ygg-missing":
        counters["rtr_a"]["counters"]["ygg_tcp"]["packets"] = 0
    elif name == "no-v6-traffic":
        counters["rtr_b"]["counters"]["lan6_native"]["packets"] = 0
    elif name == "no-v6-address":
        result["publication"]["native_addresses"] = ["203.0.113.2:40000"]
    elif name == "slow-perturb":
        result["observations"]["perturb"]["recovery_seconds"] = contract.RECOVERY_SECONDS + 0.1
    elif name == "no-new-mapping":
        result["observations"]["perturb"]["growth"]["native_new"] = 0
    elif name == "perturb-no-reply":
        result["observations"]["perturb"]["app2"]["reply_bytes"] = 0
    elif name == "ipv4-seen":
        counters["rtr_b"]["counters"]["lan_native"]["packets"] = 1
    elif name == "no-hint":
        result["observations"]["ipv6"]["hint"] = "203.0.113.2:40000"
    elif name == "no-block-receipt":
        del result["observations"]["ipv6"]["v4_block_drops"]
    elif name == "server-survived":
        result["observations"]["relay_full"]["server_exit"] = 0
    elif name == "untyped-failure":
        result["observations"]["relay_full"]["message"] = "shaar-server: some other error"
    elif name == "app-ran":
        result["observations"]["app"] = {"denied": False}
    elif name == "client-survived":
        result["observations"]["outage"]["client1_exit"] = 0
    elif name == "outage-reply":
        result["observations"]["outage"]["app_outage"]["reply_bytes"] = 5
    elif name == "slow-outage-recovery":
        result["observations"]["outage"]["recovery_seconds"] = contract.RECOVERY_SECONDS + 0.1
    elif name == "no-outage-recovery":
        result["observations"]["outage"]["app2"]["reply_bytes"] = 0
    return changed


MUTATIONS = {
    "common": ("status", "case", "nonce", "source", "purpose", "gate", "calibration", "exhausted", "router", "accepts",
               "exit", "uid", "caps", "identity", "outside", "outside-fwd", "detector"),
    "blocked": ("native_drop", "escape"),
    "nat": ("native_snat", "udp_nat", "tuple"),
    "lan": ("forwarded", "nat-hit", "no-lan-traffic", "wrong-address"),
    "dht-drop": ("no-dht-drop", "native_snat", "udp_nat"),
    "failover": ("native_snat", "udp_nat", "block-escape", "no-block-drop"),
    "dnat": ("probe-flavor", "probe-missing"),
    "ipv6": ("forwarded", "no-v6-traffic", "no-v6-address", "ipv4-seen", "no-hint", "no-block-receipt"),
    "relay": ("server-survived", "untyped-failure", "app-ran"),
    "recover": ("client-survived", "outage-reply", "slow-outage-recovery", "no-outage-recovery"),
    "flow:hole": ("slow-perturb", "no-new-mapping", "perturb-no-reply"),
}
MUTATIONS["flow:switch"] = MUTATIONS["flow:hole"]


class EvidenceTests(unittest.TestCase):
    def test_each_case_has_an_accepting_synthetic_record_and_closed_mutations(self):
        # Metadata verifier tests only; no namespace, kernel or product behavior is claimed here.
        for case, spec in contract.CASES.items():
            good = evidence(case)
            self.assertEqual(phase.verify_product_case(good, case, SOURCE, NONCE), {"forwarded_bytes": 2000, "active_seconds": 12.5})
            if spec["net"] == "nat":
                # An unavailable conntrack tuple is recorded, never silently dropped; counters stay mandatory.
                softer = copy.deepcopy(good)
                softer["case_result"]["observations"]["native_nat_tuple_unavailable"] = "procfs absent"
                del softer["case_result"]["observations"]["native_nat_tuple"]
                phase.verify_product_case(softer, case, SOURCE, NONCE)
            names = MUTATIONS["common"] + MUTATIONS[spec["net"]]
            if spec["net"] == "failover":
                names += ("block-escape",) if spec["mode"] == "signal" else ("slow-failover", "slow-recovery", "no-ygg")
                names += ("signal-reply",) if spec["mode"] == "signal" else ()
            if spec["net"] == "dnat":
                names += ("peer-recv", "peer-sent", "ygg-used") if spec["direct"] else ("direct-path",)
                names += ("ygg-missing",) if not spec["ygg_client_blocked"] and spec["mode"] == "standby" else ()
                names += ("ygg-used",) if spec["ygg_client_blocked"] and not spec["direct"] else ()
                names += ("punch-missing", "punch-garbled", "punch-unknown-status") if spec["nat"] == "cone" else ()
                names += ("no-relay-negotiation", "no-dht-drop-seen") if spec.get("relay_first") else ()
            names += MUTATIONS.get("flow:" + spec.get("flow", "single"), ())
            if spec.get("flow") == "denied-key":
                names += ("denied-reply", "control-exit")
            for name in names:
                with self.subTest(case=case, mutation=name), self.assertRaises((ValueError, KeyError, TypeError)):
                    phase.verify_product_case(mutate(case, name), case, SOURCE, NONCE)


    def test_validator_exits_become_recorded_problems_not_process_exits(self):
        self.assertIsNone(phase.guarded(lambda argv: argv == ["x"], "x"))
        def rejecting(_argv):
            raise SystemExit(2)
        self.assertIn("exit 2", phase.guarded(rejecting, "x"))


class PlanTests(unittest.TestCase):
    def test_plan_is_closed_sequential_and_within_the_privileged_budgets(self):
        self.assertEqual([entry[0] for entry in phase.PLAN],
                         ["setup-failure", "native-signal", "native-standby", "blocked-standby", "blocked-signal",
                          "lan-signal", "lan-standby", "relay-denied-signal", "failover-standby", "failover-signal",
                          "denied-blocked-standby", "dht-drop-signal", "outage-standby", "live-failure", "interruption"])
        self.assertEqual({entry[1] for entry in phase.PLAN}, {"setup-fault", "product", "fixture-fault", "interrupt"})
        self.assertEqual([entry[2] for entry in phase.PLAN if entry[1] == "product"], list(contract.CASES)[:12])
        products = sum(1 for entry in phase.PLAN if entry[1] == "product")
        controls = len(phase.PLAN) - products
        self.assertEqual((products, controls), (12, 3))
        self.assertEqual(len(contract.CASES), 28)
        # The worst case of every case at its ceiling does not fit 20 minutes; admission control refuses a case
        # that cannot finish, and the expected total (about 8 minutes) leaves the margin recorded in the contract.
        self.assertGreater(products * contract.CASE_SECONDS, contract.PHASE_SECONDS)
        self.assertGreaterEqual(contract.CASE_SECONDS, 150)
        self.assertEqual(phase.ALLOCATED_BYTES, 56 * 1024 * 1024)
        self.assertLessEqual(phase.ALLOCATED_BYTES, 64 * 1024 * 1024)
        self.assertEqual(phase.ARTIFACT_BYTES, 64 * 1024 * 1024)
        flags = {entry[0]: entry[3] for entry in phase.PLAN}
        self.assertEqual(flags["setup-failure"], ("--fault-inject-setup",))
        self.assertEqual(flags["live-failure"], ("--fault-inject-fixture",))

    def test_groups_cover_every_case_once_and_each_fits_the_privileged_budgets(self):
        self.assertEqual(set(phase.GROUPS), {"base", "nat", "faults"})
        self.assertIs(phase.GROUPS["base"], phase.PLAN)
        covered = []
        for group, plan in phase.GROUPS.items():
            with self.subTest(group=group):
                covered += [entry[2] for entry in plan if entry[1] == "product"]
                self.assertEqual((plan[0], plan[-2:]), (phase.PLAN[0], phase.PLAN[-2:]))
                self.assertEqual(len({entry[0] for entry in plan}), len(plan))
                self.assertLessEqual(phase.allocated(plan), 64 * 1024 * 1024)
                self.assertEqual({entry[1] for entry in plan} - {"product"}, {"setup-fault", "fixture-fault", "interrupt"})
        self.assertEqual(sorted(covered), sorted(contract.CASES))
        self.assertEqual(len(covered), len(contract.CASES))
        self.assertEqual(phase.allocated(phase.GROUPS["nat"]), 48 * 1024 * 1024)
        self.assertEqual(phase.allocated(phase.GROUPS["faults"]), 32 * 1024 * 1024)
        # The slowest-by-design cases (outage recovery, typed Server failures) run last in their group.
        self.assertEqual([entry[0] for entry in phase.GROUPS["faults"]][-5:-2], ["recover-standby", "relay-full-signal", "relay-full-standby"])

    def test_artifact_accounting_counts_regular_files_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "a/one").write_bytes(b"12345")
            (root / "two").write_bytes(b"678")
            self.assertEqual(phase.tree_bytes(root), 8)


class PrecheckTests(unittest.TestCase):
    TOOLS = {"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft"}

    def test_inventory_is_every_generated_ruleset(self):
        names = [name for name, _ in phase.precheck_rulesets("snaabbcc")]
        self.assertEqual(len(names), TOTAL_RULESETS)
        self.assertEqual(len(set(names)), TOTAL_RULESETS)
        self.assertEqual(sum(name.startswith("calibration/") for name in names), 2)
        self.assertIn("observation", names)
        self.assertEqual(sum(name.startswith("dynamic/") for name in names), 3)
        self.assertEqual(sorted(name for name in names if name.startswith("natprobe/")), ["natprobe/cone", "natprobe/random"])
        for case in contract.CASES:
            for router in ("rtr_a", "rtr_b"):
                for purpose in ("product", "fault"):
                    self.assertIn(f"{case}/{router}/{purpose}", names)

    def run_precheck(self, reject=None):
        calls = []

        def checked(argv, deadline, data=None, what="x"):
            calls.append(("checked", argv[1:], what))
            return b""

        def run_tool(argv, deadline, data=None):
            calls.append(("check", argv, data))
            label = phase.precheck_rulesets("snaabbcc")[sum(c[0] == "check" for c in calls) - 1][0]
            return (1, b"", b"syntax error") if label == reject else (0, b"", b"")

        with mock.patch.object(phase.kernel, "checked", checked), mock.patch.object(phase.kernel, "run_tool", run_tool),                 mock.patch.object(phase.secrets, "token_hex", lambda size: "aabbcc"):
            summary = {}
            return summary, phase.run_precheck(summary, self.TOOLS), calls

    def test_all_rulesets_run_in_one_owned_namespace_that_is_removed(self):
        summary, ok, calls = self.run_precheck()
        self.assertTrue(ok)
        result = summary["syntax_precheck"]
        self.assertEqual((result["status"], len(result["checks"]), result["namespace_removed"]), ("pass", TOTAL_RULESETS, True))
        self.assertEqual(calls[0][1:], (["netns", "add", "snaabbcc-chk"], "syntax pre-check namespace"))
        self.assertEqual(calls[-1][1:], (["netns", "del", "snaabbcc-chk"], "syntax pre-check namespace removal"))
        checks = [call for call in calls if call[0] == "check"]
        self.assertEqual(len(checks), TOTAL_RULESETS)
        for _, argv, data in checks:
            self.assertEqual(argv[:6], ["/usr/sbin/ip", "netns", "exec", "snaabbcc-chk", "/usr/sbin/nft", "--check"])
            self.assertIn(b"add table inet", data)

    def test_first_rejection_aborts_immediately_and_still_removes_the_namespace(self):
        target = phase.precheck_rulesets("snaabbcc")[5][0]
        summary, ok, calls = self.run_precheck(reject=target)
        self.assertFalse(ok)
        result = summary["syntax_precheck"]
        self.assertEqual((result["status"], result["aborted_at"], len(result["checks"])), ("fail", target, 6))
        self.assertEqual(result["checks"][-1]["error"], "syntax error")
        self.assertTrue(result["namespace_removed"])
        self.assertEqual(calls[-1][1][:2], ["netns", "del"])

    def test_setup_errors_fail_the_gate_without_running_cases(self):
        def broken(argv, deadline, data=None, what="x"):
            raise RuntimeError("cannot add namespace")

        with mock.patch.object(phase.kernel, "checked", broken):
            summary = {}
            self.assertFalse(phase.run_precheck(summary, self.TOOLS))
        self.assertEqual(summary["syntax_precheck"]["status"], "fail")
        self.assertIn("cannot add namespace", summary["syntax_precheck"]["error"])


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
