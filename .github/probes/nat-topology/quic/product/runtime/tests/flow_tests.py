"""CI-only pure contracts for observation, runtime blocks, controller flows and the extended workers."""

import asyncio
import copy
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock

RUNTIME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(RUNTIME.parent))
sys.path.insert(0, str(RUNTIME.parent / "flows"))
import verdicts as checks  # noqa: E402
import contract  # noqa: E402
import dynamic  # noqa: E402
import natprobe  # noqa: E402
import network  # noqa: E402
import observe  # noqa: E402
import perturb  # noqa: E402
import scenarios  # noqa: E402
import worker  # noqa: E402

PREFIX = "snaabbcc"
NONCE = "a" * 32
PORTS = {"dht": 42001, "relay": 42002, "transit": 42003}
CFG = {"prefix": PREFIX, "ns": {key: PREFIX + "-" + value for key, value in contract.SUFFIXES.items()}}
TOOLS = {"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft", "python": "/usr/bin/python3"}


def counter_document(table, values):
    return {"nftables": [{"metainfo": {}}] + [
        {"counter": {"family": "inet", "table": table, "name": name, "packets": value, "bytes": value * 10}}
        for name, value in values.items()]}


class ObserveTests(unittest.TestCase):
    def test_rules_only_count_destinations_outside_the_owned_set_and_never_decide(self):
        text = observe.rules(PREFIX)
        self.assertIn(f"add table inet {PREFIX}_obs\n", text)
        for name in observe.COUNTERS:
            self.assertIn(f"add counter inet {PREFIX}_obs {name}\n", text)
        self.assertEqual(text.count(f"ip daddr != {observe.OWNED}"), 6)
        for chain, hook in (("obsfwd", "forward"), ("obsout", "output")):
            self.assertIn(f"add chain inet {PREFIX}_obs {chain} {{ type filter hook {hook} priority -500; policy accept; }}", text)
        for word in (" drop", " reject", "masquerade", "flush"):
            self.assertNotIn(word, text)
        for owned in ("10.0.0.0/8", "127.0.0.0/8", "203.0.113.0/24", "224.0.0.0/3"):
            self.assertIn(owned, observe.OWNED)
        self.assertIn("udp dport 53 counter name udp53", text)
        self.assertIn("tcp dport 443 counter name tcp443", text)
        for prefix in ("", "../x", "sn12345", "sn12345g"):
            with self.assertRaises(ValueError):
                observe.rules(prefix)

    def test_counter_inventory_is_exact_and_nonzero_traffic_is_rejected(self):
        table = PREFIX + "_obs"
        good = counter_document(table, {name: 0 for name in observe.COUNTERS})
        self.assertEqual(observe.counts(good, PREFIX), {name: 0 for name in observe.COUNTERS})
        self.assertEqual(observe.verify_zero(observe.counts(good, PREFIX), "rtr_a"), {name: 0 for name in observe.COUNTERS})
        for mutation in ("missing", "foreign", "duplicate", "negative", "unknown"):
            document = copy.deepcopy(good)
            rows = document["nftables"]
            if mutation == "missing":
                del rows[-1]
            elif mutation == "foreign":
                rows[-1]["counter"]["table"] = "other"
            elif mutation == "duplicate":
                rows.append(copy.deepcopy(rows[-1]))
            elif mutation == "negative":
                rows[-1]["counter"]["packets"] = -1
            else:
                rows[-1]["counter"]["name"] = "outside"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                observe.counts(document, PREFIX)
        for name in observe.COUNTERS:
            found = {key: 0 for key in observe.COUNTERS}
            found[name] = 1
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "outside the owned address set"):
                observe.verify_zero(found, "rtr_b")

    def test_detector_must_see_known_outside_probes(self):
        seen = {"outside_fwd": 3, "outside_out": 3, "udp53": 2, "tcp443": 2}
        self.assertEqual(observe.check_detector(seen), seen)
        for name in seen:
            with self.subTest(name=name), self.assertRaises(ValueError):
                observe.check_detector({**seen, name: 1})

    def calibrate(self, detected):
        state, calls = {name: 0 for name in observe.COUNTERS}, []

        def checked(argv, deadline, data=None, what="x"):
            calls.append((what, argv[3], argv[4:]))
            if what == "observation probe" and argv[3] == CFG["ns"]["rtr_a"]:
                state.update(detected)
            elif what == "observation table removal":
                state.update({name: 0 for name in observe.COUNTERS})
            return json.dumps(counter_document(PREFIX + "_obs", state)).encode() if what == "observation snapshot" else b""

        with mock.patch.object(observe.kernel, "checked", checked):
            return calls, observe.calibrate(CFG, TOOLS, "rtr_a", "host_a", 0)

    def test_calibration_proves_the_installed_rules_then_restarts_from_zero(self):
        calls, result = self.calibrate({"outside_fwd": 3, "outside_out": 3, "udp53": 2, "tcp443": 2})
        self.assertEqual([item[0] for item in calls], [
            "observation rules install", "observation probe", "observation probe", "observation snapshot",
            "observation table removal", "observation rules install", "observation snapshot"])
        self.assertEqual([item[1] for item in calls[1:3]], [CFG["ns"]["host_a"], CFG["ns"]["rtr_a"]])
        self.assertEqual(result["detected"]["outside_fwd"], 3)
        self.assertTrue(all(item[1] == CFG["ns"]["rtr_a"] for index, item in enumerate(calls) if index != 1))
        with self.assertRaises(ValueError):
            self.calibrate({"outside_fwd": 3, "outside_out": 0, "udp53": 2, "tcp443": 2})


class DynamicTests(unittest.TestCase):
    def test_native_block_exempts_only_the_dht_socket_and_ygg_block_drops_only_transit(self):
        native = dynamic.rules(PREFIX, "native", PORTS)
        self.assertEqual(native.index("p13-dyn-dht-query") < native.index("p13-dyn-dht-reply") < native.index("p13-dyn-native-block"), True)
        self.assertIn("udp dport 42001 accept", native)
        self.assertIn("meta l4proto udp counter name dyn_drop drop", native)
        self.assertIn("priority -250", native)
        self.assertNotIn("tcp", native)
        ygg = dynamic.rules(PREFIX, "ygg", PORTS)
        self.assertIn("tcp dport 42003 counter name dyn_drop drop", ygg)
        self.assertIn("tcp sport 42003 counter name dyn_drop drop", ygg)
        self.assertNotIn("udp", ygg)
        self.assertNotEqual(dynamic.table_name(PREFIX, "native"), dynamic.table_name(PREFIX, "ygg"))
        for args in (("../x", "native", PORTS), (PREFIX, "relay", PORTS), (PREFIX, "ygg", {"dht": 80, "transit": 42003}),
                     (PREFIX, "ygg", {"dht": 42001})):
            with self.assertRaises(ValueError):
                dynamic.rules(*args)

    def test_drop_counter_inventory_is_exact(self):
        table = dynamic.table_name(PREFIX, "native")
        good = counter_document(table, {"dyn_drop": 4})
        self.assertEqual(dynamic.drops(good, PREFIX, "native"), {"packets": 4, "bytes": 40})
        for document in (counter_document(table, {"other": 1}), counter_document(table, {"dyn_drop": 1, "dyn_drop2": 1}),
                         counter_document("foreign", {"dyn_drop": 1}), {"nftables": []}):
            with self.assertRaises(ValueError):
                dynamic.drops(document, PREFIX, "native")

    def test_install_commits_both_routers_and_removal_reads_before_deleting(self):
        calls = []

        def checked(argv, deadline, data=None, what="x"):
            calls.append((argv[3], what))
            if what.endswith("snapshot"):
                return json.dumps(counter_document(dynamic.table_name(PREFIX, "ygg"), {"dyn_drop": 2})).encode()
            return b""

        with mock.patch.object(dynamic.kernel, "checked", checked):
            stamp = dynamic.install(CFG, TOOLS, "ygg", PORTS, 0)
            self.assertIsInstance(stamp, float)
            seen, later = dynamic.remove(CFG, TOOLS, "ygg", 0)
        self.assertGreaterEqual(later, stamp)
        self.assertEqual(seen["rtr_b"], {"packets": 2, "bytes": 20})
        a, b = CFG["ns"]["rtr_a"], CFG["ns"]["rtr_b"]
        self.assertEqual(calls, [(a, "dynamic ygg block install"), (b, "dynamic ygg block install"),
                                 (a, "dynamic ygg block snapshot"), (a, "dynamic ygg block removal"),
                                 (b, "dynamic ygg block snapshot"), (b, "dynamic ygg block removal")])


class FakeRun:
    """Records the controller calls a flow makes; no namespace, nft or product is involved."""

    def __init__(self, case, counters=(), times=()):
        self.spec, self.ev = contract.CASES[case], {"observations": {}}
        self.cfg, self.tools, self.ports = CFG, TOOLS, PORTS
        self.work, self.fillers = Path("/w"), [types.SimpleNamespace(name="filler1", exited=False)]
        self.active_start = time.monotonic()
        self.server, self.client = types.SimpleNamespace(name="server"), types.SimpleNamespace(name="client")
        self.active_end = time.monotonic() + 90
        self.case, self.server_key, self.relay, self.client_ns = case, "ab" * 32, "12D3KooWabc", "host_a"
        self.counter_values, self.times, self.apps, self.calls = list(counters), list(times), [], []
        self.sup = mock.Mock()
        self.sup.wait.return_value = 0

    def limit(self, seconds):
        return seconds

    def counters(self, router):
        return self.counter_values.pop(0)

    def app_once(self, name, deadline, guards, denied, attempts=None, pause=None):
        self.apps.append((name, deadline, tuple(guard.name for guard in guards), denied, attempts, pause))
        reply = 0 if denied else 61
        result = {"denied": denied, "reply_bytes": reply, **({"terminal": "reset"} if denied else {})}
        return {"admitted": True}, result, (self.times.pop(0) if self.times else 0.0)

    def other_key(self):
        return "/w/keys/other.key"

    def owned_file(self, name, text):
        self.calls.append(("file", name, text))
        return "/w/" + name

    def product(self, name, ns, config, binary=None):
        self.calls.append(("product", name, ns, config, binary))
        return types.SimpleNamespace(name=name)


def snap(native, nat, ygg):
    return {"native_snat": native, "udp_nat": nat, "ygg_tcp": ygg}


GOOD = [snap(0, 0, 0), snap(10, 3, 2), snap(10, 3, 2), snap(10, 3, 8), snap(10, 3, 8), snap(16, 3, 9)]
DROPS = ({"rtr_a": {"packets": 5, "bytes": 50}, "rtr_b": {"packets": 0, "bytes": 0}}, 120.0)


class ScenarioTests(unittest.TestCase):
    def failover(self, case, counters, times, drops=DROPS):
        run = FakeRun(case, counters, times)
        installs, removals = [], []
        with mock.patch.object(scenarios.dynamic, "install", lambda cfg, tools, kind, ports, deadline: installs.append(kind) or 100.0), \
                mock.patch.object(scenarios.dynamic, "remove", lambda cfg, tools, kind, deadline: removals.append(kind) or drops):
            try:
                scenarios.failover(run)
                error = None
            except ValueError as caught:
                error = caught
        return run, installs, removals, error

    def test_standby_failover_then_recovery_records_bounds_and_orders_the_blocks(self):
        run, installs, removals, error = self.failover("failover-standby", copy.deepcopy(GOOD), [50.0, 104.2, 127.5])
        self.assertIsNone(error)
        obs = run.ev["observations"]["failover"]
        self.assertEqual((obs["failover_seconds"], obs["recovery_seconds"]), (4.2, 7.5))
        self.assertEqual((obs["app1_native_snat_packets"], obs["block_native_snat_packets"], obs["block_ygg_tcp_packets"]), (10, 0, 6))
        self.assertEqual(obs["recovery_native_snat_packets"], 6)
        self.assertEqual(installs, ["native", "ygg"])
        self.assertEqual(removals, ["native", "ygg"])
        self.assertEqual([item[0] for item in run.apps], ["app", "app2", "app3"])
        self.assertEqual([item[3] for item in run.apps], [False, False, False])
        self.assertTrue(all(item[2] == ("server", "client") for item in run.apps))
        self.assertEqual(sum(item[4] for item in run.apps), 16)
        self.assertLessEqual(run.apps[1][1], 15)
        self.assertEqual(run.apps[2][1], int(contract.RECOVERY_SECONDS))

    def test_failover_bounds_and_counter_evidence_are_mandatory(self):
        base = copy.deepcopy(GOOD)
        slow = self.failover("failover-standby", copy.deepcopy(base), [50.0, 110.5, 127.5])[3]
        self.assertIn("above the 10.0 s bound", str(slow))
        late = self.failover("failover-standby", copy.deepcopy(base), [50.0, 104.0, 160.5])[3]
        self.assertIn("Native recovery took", str(late))
        escaped = copy.deepcopy(base)
        escaped[3] = snap(11, 3, 8)
        self.assertIn("escaped the runtime block", str(self.failover("failover-standby", escaped, [50.0, 104.0, 127.0])[3]))
        quiet = copy.deepcopy(base)
        quiet[3] = snap(10, 3, 2)
        self.assertIn("no Ygg TCP traffic", str(self.failover("failover-standby", quiet, [50.0, 104.0, 127.0])[3]))
        stalled = copy.deepcopy(base)
        stalled[5] = snap(10, 3, 9)
        self.assertIn("no translated Native UDP after", str(self.failover("failover-standby", stalled, [50.0, 104.0, 127.0])[3]))
        unused = copy.deepcopy(base)
        unused[1] = snap(0, 0, 2)
        self.assertIn("no translated Native UDP before", str(self.failover("failover-standby", unused, [50.0, 104.0, 127.0])[3]))
        idle = ({"rtr_a": {"packets": 0, "bytes": 0}, "rtr_b": {"packets": 0, "bytes": 0}}, 120.0)
        self.assertIn("never observed", str(self.failover("failover-standby", copy.deepcopy(base), [50.0, 104.0, 127.0], idle)[3]))

    def test_signal_failover_requires_fail_closed_without_a_recovery_phase(self):
        run, installs, removals, error = self.failover("failover-signal", copy.deepcopy(GOOD[:4]), [50.0, 133.0])
        self.assertIsNone(error)
        self.assertEqual((installs, removals), (["native"], ["native"]))
        self.assertEqual([item[0] for item in run.apps], ["app", "app2"])
        self.assertEqual([item[3] for item in run.apps], [False, True])
        self.assertEqual(run.apps[1][2], ("server",))
        obs = run.ev["observations"]["failover"]
        self.assertEqual(obs["fail_closed_seconds"], 33.0)
        self.assertEqual(obs["app2"]["reply_bytes"], 0)
        self.assertNotIn("recovery_seconds", obs)

    def test_single_flow_uses_the_case_expectation_and_guards(self):
        for case, denied, guards in (("native-signal", False, ("server", "client")), ("blocked-signal", True, ("server",)),
                                     ("lan-standby", False, ("server", "client")), ("outage-standby", True, ("server",))):
            run = FakeRun(case)
            scenarios.single(run)
            name, deadline, seen, was_denied, _, _ = run.apps[0]
            self.assertEqual((name, seen, was_denied), ("app", guards, denied), case)
            self.assertTrue(10 <= deadline <= worker.MAX_DEADLINE)
            self.assertEqual(set(run.ev["observations"]), {"app_ready", "app"})
        exhausted = FakeRun("native-signal")
        exhausted.active_end = time.monotonic() + 1
        with self.assertRaisesRegex(ValueError, "active budget exhausted"):
            scenarios.single(exhausted)

    def test_denied_key_runs_the_authorized_control_first_then_a_second_client(self):
        run = FakeRun("denied-blocked-standby")
        original = run.client
        scenarios.denied_key(run)
        self.assertEqual([(item[0], item[3]) for item in run.apps], [("app", False), ("app2", True)])
        self.assertEqual(run.apps[1][2], ("server",))
        run.sup.interrupt.assert_called_once_with(original)
        self.assertEqual(run.ev["observations"]["client1_exit"], 0)
        self.assertEqual(run.client.name, "client2")
        file_call = next(item for item in run.calls if item[0] == "file")
        self.assertEqual(file_call[1], "client2.ktav")
        self.assertIn("key_file:: /w/keys/other.key", file_call[2])
        self.assertIn("server: " + "ab" * 32, file_call[2])
        self.assertIn(("product", "client2", "host_a", "/w/client2.ktav", "client"), run.calls)

    def test_denied_key_fails_when_the_authorized_control_does_not_exit_cleanly(self):
        run = FakeRun("denied-blocked-standby")
        run.sup.wait.return_value = 1
        with self.assertRaisesRegex(ValueError, "authorized Client exit"):
            scenarios.denied_key(run)
        self.assertEqual([item[0] for item in run.apps], ["app"])

    def test_flow_registry_is_closed_and_every_case_flow_exists(self):
        self.assertEqual(set(scenarios.FLOWS), {"single", "failover", "denied-key", "hole", "switch", "ipv6", "outage-recovery", "relay-full"})
        for spec in contract.CASES.values():
            self.assertIn(spec.get("flow", "single"), scenarios.FLOWS)
        self.assertEqual(scenarios.APP1_ATTEMPTS + scenarios.APP2_ATTEMPTS + scenarios.APP3_ATTEMPTS, 16)


def full(**values):
    """A complete router counter snapshot (every named counter) with the given nonzero values."""
    return {**{name: 0 for name in network.COUNTERS}, **values}


class PerturbTests(unittest.TestCase):
    def run_flow(self, case, flow, counters, times, drops=DROPS, wait=0, **patches):
        run = FakeRun(case, counters, times)
        run.sup.wait.return_value = wait
        installs, removals = [], []
        with mock.patch.object(perturb.dynamic, "install", lambda cfg, tools, kind, ports, deadline: installs.append(kind) or patches.get("changed", 12.0)), \
                mock.patch.object(perturb.dynamic, "remove", lambda cfg, tools, kind, deadline: removals.append(kind) or drops), \
                mock.patch.object(perturb.kernel, "flap_wan", lambda cfg, tools, router, deadline: patches.get("changed", 12.0)), \
                mock.patch.object(perturb.kernel, "switch_client_address", lambda cfg, tools, deadline: patches.get("changed", 12.0)):
            try:
                flow(run)
                error = None
            except ValueError as caught:
                error = caught
        return run, installs, removals, error

    BEFORE = full(native_snat=10, native_new=2, udp_nat=3)

    def test_nat_state_flush_records_recovery_time_and_requires_a_new_mapping(self):
        after = full(native_snat=18, native_new=3, udp_nat=4, hole_in=2)
        run, _, _, error = self.run_flow("hole-standby", perturb.hole, [self.BEFORE, after], [10.0, 15.5])
        self.assertIsNone(error)
        obs = run.ev["observations"]["perturb"]
        self.assertEqual((obs["kind"], obs["recovery_seconds"]), ("nat-state-flush", 3.5))
        self.assertEqual((obs["growth"]["native_new"], obs["growth"]["native_snat"], obs["growth"]["hole_in"]), (1, 8, 2))
        self.assertEqual([(item[0], item[3]) for item in run.apps], [("app", False), ("app2", False)])
        self.assertEqual(run.apps[1][1], int(contract.RECOVERY_SECONDS))
        self.assertEqual(sum(item[4] for item in run.apps), 12)
        self.assertTrue(all(item[2] == ("server", "client") for item in run.apps))
        late = self.run_flow("hole-standby", perturb.hole, [self.BEFORE, after], [10.0, 52.5])[3]
        self.assertIn("above the 40.0 s bound", str(late))
        stale = self.run_flow("hole-standby", perturb.hole, [self.BEFORE, dict(after, native_new=2)], [10.0, 15.5])[3]
        self.assertIn("old mapping was not lost", str(stale))
        idle = self.run_flow("hole-standby", perturb.hole, [full(native_snat=0, native_new=2), after], [10.0, 15.5])[3]
        self.assertIn("before the NAT state flush", str(idle))

    def test_client_address_switch_requires_a_new_native_mapping_from_the_new_address(self):
        after = full(native_snat=15, native_new=4, udp_nat=6)
        run, _, _, error = self.run_flow("switch-signal", perturb.switch, [self.BEFORE, after], [10.0, 22.0], changed=14.0)
        self.assertIsNone(error)
        obs = run.ev["observations"]["perturb"]
        self.assertEqual((obs["kind"], obs["recovery_seconds"], obs["growth"]["native_new"]), ("client-address-switch", 8.0, 2))
        stale = self.run_flow("switch-signal", perturb.switch, [self.BEFORE, dict(after, native_new=2)], [10.0, 22.0])[3]
        self.assertIn("created no new Native NAT mapping", str(stale))

    def test_ipv6_only_case_runs_one_campaign_and_reads_the_block_that_was_active_the_whole_case(self):
        run = FakeRun("ipv6-signal")
        run.ev["observations"]["ipv6"] = {"hint": "[2001:db8:13::2]:40001"}
        removals = []
        with mock.patch.object(perturb.dynamic, "remove", lambda cfg, tools, kind, deadline: removals.append(kind) or DROPS):
            perturb.ipv6(run)
        self.assertEqual(removals, ["v4"])
        self.assertEqual([(item[0], item[3], item[2]) for item in run.apps], [("app", False, ("server", "client"))])
        self.assertTrue(10 <= run.apps[0][1] <= worker.MAX_DEADLINE)
        observed = run.ev["observations"]
        self.assertEqual(observed["ipv6"]["v4_block_drops"], DROPS[0])
        self.assertEqual(set(observed), {"ipv6", "app_ready", "app"})
        exhausted = FakeRun("ipv6-standby")
        exhausted.active_end = time.monotonic() + 1
        with self.assertRaisesRegex(ValueError, "active budget exhausted"):
            perturb.ipv6(exhausted)

    def test_outage_recovery_needs_a_failed_closed_client_then_a_fresh_client_after_both_blocks_lift(self):
        lifted = (DROPS[0], 55.0)
        run, installs, removals, error = self.run_flow("recover-standby", perturb.outage_recovery, [], [50.0, 63.0], drops=lifted, wait=1)
        self.assertIsNone(error)
        self.assertEqual((installs, removals), (["native", "ygg"], ["native", "ygg"]))
        self.assertEqual([(item[0], item[3]) for item in run.apps], [("app", True), ("app2", False)])
        self.assertEqual(run.apps[0][2], ("server",))
        self.assertEqual(run.apps[1][2], ("server", "client2"))
        self.assertIn(("product", "client2", "host_a", str(Path("/w") / "client.ktav"), "client"), run.calls)
        obs = run.ev["observations"]["outage"]
        self.assertEqual((obs["client1_exit"], obs["recovery_seconds"]), (1, 8.0))
        survived = self.run_flow("recover-standby", perturb.outage_recovery, [], [50.0, 63.0], drops=lifted, wait=0)[3]
        self.assertIn("not the typed failure status", str(survived))
        idle = ({"rtr_a": {"packets": 0, "bytes": 0}, "rtr_b": {"packets": 0, "bytes": 0}}, 120.0)
        self.assertIn("never observed", str(self.run_flow("recover-standby", perturb.outage_recovery, [], [50.0, 63.0], drops=idle, wait=1)[3]))
        slow = self.run_flow("recover-standby", perturb.outage_recovery, [], [50.0, 100.0], drops=lifted, wait=1)[3]
        self.assertIn("after the outage took", str(slow))

    def test_full_relay_requires_the_typed_exit_status_inside_the_bound_and_live_fillers(self):
        message = "shaar-server: composed startup: relay reservation failed at startup"
        run = FakeRun("relay-full-signal")
        run.sup.mark.return_value, run.sup.wait.return_value = message, 1
        perturb.relay_full(run)
        obs = run.ev["observations"]["relay_full"]
        self.assertEqual((obs["message"], obs["server_exit"]), (message, 1))
        run.sup.mark.assert_called_once_with(run.server, contract.RESERVE_FAIL, run.limit(perturb.RELAY_FULL_SECONDS))
        for wait, filler_exited, expect in ((0, False, "differs from the typed failure"), (1, True, "filler ended")):
            broken = FakeRun("relay-full-standby")
            broken.sup.mark.return_value, broken.sup.wait.return_value = message, wait
            broken.fillers[0].exited = filler_exited
            with self.assertRaisesRegex(ValueError, expect):
                perturb.relay_full(broken)
        late = FakeRun("relay-full-standby")
        late.sup.mark.return_value, late.sup.wait.return_value = message, 1
        late.active_start = time.monotonic() - perturb.RELAY_FULL_SECONDS - 5
        with self.assertRaisesRegex(ValueError, "typed Server failure took"):
            perturb.relay_full(late)


class NatProbeTests(unittest.TestCase):
    def test_rules_apply_the_exact_flavor_statement_and_count_kept_versus_moved_ports(self):
        cone = natprobe.rules(PREFIX, "cone", "10.0.1.2", "203.0.113.1")
        self.assertIn(f"add table inet {PREFIX}_nprobe\n", cone)
        self.assertIn("pnat ip saddr 10.0.1.2 ip protocol udp udp sport 40100 masquerade\n", cone)
        self.assertIn("udp dport 9001-9003 udp sport 40100 ct status snat counter name kept", cone)
        self.assertIn(f"add chain inet {PREFIX}_nprobe punchin {{ type filter hook input priority 0; policy accept; }}\n", cone)
        self.assertIn("punchin ip daddr 203.0.113.1 udp dport 40100 drop\n", cone)
        self.assertIn("udp dport 9001-9003 udp sport != 40100 ct status snat counter name moved", cone)
        self.assertIn("udp sport 40100 masquerade fully-random\n", natprobe.rules(PREFIX, "random", "10.0.2.2", "203.0.113.2"))
        self.assertEqual(natprobe.STATEMENTS["cone"], network.NAT_FLAVORS["cone"])
        self.assertEqual(natprobe.STATEMENTS["random"], network.NAT_FLAVORS["random"])
        for args in (("../x", "cone"), (PREFIX, "range"), (PREFIX, "symmetric")):
            with self.assertRaises(ValueError):
                natprobe.rules(args[0], args[1], "10.0.1.2", "203.0.113.1")

    def test_counter_inventory_and_flavor_oracles_are_exact(self):
        table = PREFIX + "_nprobe"
        good = counter_document(table, {"kept": 3, "moved": 0})
        self.assertEqual(natprobe.counts(good, PREFIX), {"kept": 3, "moved": 0})
        for document in (counter_document(table, {"kept": 3}), counter_document("foreign", {"kept": 3, "moved": 0}),
                         counter_document(table, {"kept": 3, "moved": 0, "extra": 1}), counter_document(table, {"kept": -1, "moved": 0})):
            with self.assertRaises(ValueError):
                natprobe.counts(document, PREFIX)
        self.assertEqual(natprobe.check({"kept": 3, "moved": 0}, "cone"), {"kept": 3, "moved": 0})
        self.assertEqual(natprobe.check({"kept": 0, "moved": 3}, "random"), {"kept": 0, "moved": 3})
        for found, flavor in (({"kept": 2, "moved": 1}, "cone"), ({"kept": 0, "moved": 3}, "cone"),
                              ({"kept": 3, "moved": 0}, "random"), ({"kept": 1, "moved": 2}, "random"), ({"kept": 3, "moved": 0}, "range")):
            with self.assertRaises(ValueError):
                natprobe.check(found, flavor)

    def test_calibration_sends_from_the_host_and_always_removes_its_table(self):
        cfg = dict(CFG, ip=contract.IPS)
        for kept, ok in ((3, True), (1, False)):
            calls = []
            document = counter_document(PREFIX + "_nprobe", {"kept": kept, "moved": 3 - kept})

            def checked(argv, deadline, data=None, what="x", calls=calls, document=document):
                calls.append((what, argv[3]))
                return json.dumps(document).encode() if what == "NAT probe snapshot" else b""

            with self.subTest(kept=kept), mock.patch.object(natprobe.kernel, "checked", checked):
                if ok:
                    result = natprobe.calibrate(cfg, TOOLS, "rtr_a", "host_a", "cone", 0)
                    self.assertEqual((result["flavor"], result["kept"], result["moved"]), ("cone", 3, 0))
                else:
                    with self.assertRaises(ValueError):
                        natprobe.calibrate(cfg, TOOLS, "rtr_a", "host_a", "cone", 0)
                self.assertEqual([item[0] for item in calls], ["NAT probe install", "NAT probe sender", "NAT probe snapshot", "NAT probe removal"])
                self.assertEqual([item[1] for item in calls], [CFG["ns"]["rtr_a"], CFG["ns"]["host_a"], CFG["ns"]["rtr_a"], CFG["ns"]["rtr_a"]])


class FakeProcess:
    def __init__(self, out, code=0):
        self.out, self.returncode = out, code

    def communicate(self, timeout=None):
        return self.out, b"boom"

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class PunchControlTests(unittest.TestCase):
    GOOD = [{"host": "host_a", "sent": 20, "received": 18, "first": ["203.0.113.2", 40100]},
            {"host": "host_b", "sent": 20, "received": 19, "first": ["203.0.113.1", 40100]}]

    def test_the_worker_sends_a_fixed_small_number_of_datagrams_and_never_echoes(self):
        code = natprobe.PUNCH % ("10.0.1.2", 40100, natprobe.PUNCH_SENDS, "203.0.113.2", 40100)
        self.assertEqual(natprobe.PUNCH_SENDS, 20)
        self.assertEqual(code.count("sendto"), 1)
        self.assertIn("for _ in range(20):", code)
        self.assertIn("s.settimeout(0.1)", code)
        self.assertNotIn("while time", code)
        compile(code, "punch-worker", "exec")

    def test_receipts_need_both_sockets_to_hear_the_peer_public_endpoint(self):
        self.assertEqual(natprobe.check_punch(copy.deepcopy(self.GOOD)), self.GOOD)
        for index, field, value in ((0, "received", 0), (1, "sent", 0), (1, "sent", 50000), (0, "received", 50000), (0, "first", None),
                                    (1, "first", ["203.0.113.2", 40100]), (0, "first", ["203.0.113.2", 41011]), (1, "host", "host_a")):
            changed = copy.deepcopy(self.GOOD)
            changed[index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                natprobe.check_punch(changed)
        with self.assertRaises(ValueError):
            natprobe.check_punch(self.GOOD[:1])

    def run_punch(self, codes, received=None):
        calls, spawned = [], []
        goods = copy.deepcopy(self.GOOD)
        for item in goods:
            item["received"] = item["received"] if received is None else received
        outputs = [json.dumps({key: value for key, value in item.items() if key != "host"}).encode() for item in goods]
        kwargs = {}

        def checked(argv, deadline, data=None, what="x"):
            calls.append((what, argv[3]))
            return b""

        def popen(argv, **kwargs):
            spawned.append(argv)
            return FakeProcess(outputs[len(spawned) - 1], codes[len(spawned) - 1])

        cfg = dict(CFG, ip=contract.IPS)
        with mock.patch.object(natprobe.kernel, "checked", checked), mock.patch.object(natprobe.subprocess, "Popen", popen):
            try:
                result, error = natprobe.punch(cfg, TOOLS, time.monotonic() + 10, **kwargs), None
            except ValueError as caught:
                result, error = None, caught
        return result, error, calls, spawned

    def test_punch_runs_one_socket_per_host_against_the_peer_router_and_always_removes_both_tables(self):
        result, error, calls, spawned = self.run_punch((0, 0))
        self.assertIsNone(error)
        self.assertEqual(result, {"status": "pass", "receipts": self.GOOD})
        a, b = CFG["ns"]["rtr_a"], CFG["ns"]["rtr_b"]
        self.assertEqual(calls, [("punch control NAT install", a), ("punch control NAT install", b),
                                 ("punch control NAT removal", a), ("punch control NAT removal", b)])
        self.assertEqual([argv[3] for argv in spawned], [CFG["ns"]["host_a"], CFG["ns"]["host_b"]])
        self.assertIn("'203.0.113.2', 40100", spawned[0][-1].replace('"', "'"))
        self.assertIn("'203.0.113.1', 40100", spawned[1][-1].replace('"', "'"))
        self.assertIn("'10.0.1.2', 40100", spawned[0][-1].replace('"', "'"))
        missed = self.run_punch((0, 0), received=0)
        self.assertIsNone(missed[1])
        self.assertEqual(missed[0]["status"], "fail")
        self.assertIn("did not receive from the peer's public endpoint", missed[0]["error"])
        self.assertEqual([item[0] for item in missed[2]][-2:], ["punch control NAT removal"] * 2)
        failed = self.run_punch((0, 1))
        self.assertIn("punch control worker failed", str(failed[1]))
        self.assertEqual([item[0] for item in failed[2]][-2:], ["punch control NAT removal"] * 2)


class NewVerdictTests(unittest.TestCase):
    def test_v4_dynamic_block_drops_only_segment_ipv4_udp_at_the_output_hook(self):
        text = dynamic.rules(PREFIX, "v4", PORTS)
        self.assertIn("type filter hook output priority -250", text)
        self.assertIn("ip daddr { 203.0.113.1, 203.0.113.2 } meta l4proto udp counter name dyn_drop drop", text)
        self.assertNotIn("tcp", text)
        self.assertNotIn("ip6", text)
        self.assertEqual(dynamic.table_name(PREFIX, "v4"), PREFIX + "_dv4")
        self.assertIn("hook forward", dynamic.rules(PREFIX, "native", PORTS))

    def test_unreviewed_net_classes_still_fail_and_new_ones_need_their_receipts(self):
        for net in ("dnat", "ipv6", "relay", "recover"):
            with self.subTest(net=net), self.assertRaises((ValueError, KeyError)):
                checks.verify_class({"net": net, "nat": "cone", "direct": True, "mode": "signal"}, receipts(), {})


def receipts():
    return {"observe": {router: {name: 0 for name in checks.OBSERVE_NAMES} for router in ("rtr_a", "rtr_b")},
            "observe_calibration": [{"detected": {"outside_fwd": 2, "outside_out": 2}}] * 2}


class ChecksTests(unittest.TestCase):
    def test_outside_contact_receipts_are_required_in_every_class(self):
        good = receipts()
        checks.no_outside_contact(good)
        for broken in ({}, {**good, "observe": {"rtr_a": good["observe"]["rtr_a"]}},
                       {**good, "observe_calibration": []},
                       {**good, "observe": {**good["observe"], "rtr_b": {**good["observe"]["rtr_b"], "tcp443": 2}}}):
            with self.assertRaises(ValueError):
                checks.no_outside_contact(broken)

    def test_unreviewed_classes_are_rejected(self):
        with self.assertRaises(ValueError):
            checks.verify_class({"net": "unknown"}, receipts(), {})


class ExtendedWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        patch = mock.patch.object(worker, "emit")
        patch.start()
        self.addCleanup(patch.stop)
        self.cleanup = []

    async def asyncTearDown(self):
        for item in self.cleanup:
            item.cancel()
        await asyncio.gather(*self.cleanup, return_exceptions=True)

    def start(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.cleanup.append(task)
        return task

    async def test_target_accepts_exactly_the_expected_number_of_streams_and_sums_receipts(self):
        bound, reader = worker.listener(0), asyncio.StreamReader(limit=64)
        port = bound.getsockname()[1]
        target = self.start(worker.target(NONCE, False, bound, reader, 3))
        for _ in range(3):
            result = await asyncio.wait_for(worker.app(NONCE, False, port), 5)
            self.assertFalse(result["denied"])
        reader.feed_data(("STOP " + NONCE + "\n").encode("ascii"))
        reader.feed_eof()
        request, reply = worker.payloads(NONCE)
        self.assertEqual(await asyncio.wait_for(target, 5),
                         {"accepts": 3, "request_bytes": 3 * len(request), "reply_bytes": 3 * len(reply)})

    async def test_an_extra_admission_or_early_stop_fails_the_target(self):
        bound, reader = worker.listener(0), asyncio.StreamReader(limit=64)
        port = bound.getsockname()[1]
        target = self.start(worker.target(NONCE, False, bound, reader, 1))
        await asyncio.wait_for(worker.app(NONCE, False, port), 5)
        extra = socket_connect(port)
        with self.assertRaisesRegex(ValueError, "unexpected fixed-target TCP admission"):
            await asyncio.wait_for(target, 5)
        extra.close()
        bound, reader = worker.listener(0), asyncio.StreamReader(limit=64)
        early = self.start(worker.target(NONCE, False, bound, reader, 2))
        await asyncio.sleep(0)
        reader.feed_data(("STOP " + NONCE + "\n").encode("ascii"))
        reader.feed_eof()
        with self.assertRaisesRegex(ValueError, "required APP outcome"):
            await asyncio.wait_for(early, 5)

    async def test_app_retries_typed_transient_failures_up_to_the_attempt_cap_with_a_fixed_pause(self):
        for attempts, passes in ((3, True), (2, False)):
            with self.subTest(attempts=attempts):
                bound = worker.listener(0)
                port = bound.getsockname()[1]

                async def serve(bound=bound):
                    loop = asyncio.get_running_loop()
                    for index in range(3):
                        stream, _ = await loop.sock_accept(bound)
                        try:
                            if index < 2:
                                continue
                            await worker.exact_eof(stream, worker.payloads(NONCE)[0])
                            await loop.sock_sendall(stream, worker.payloads(NONCE)[1])
                        finally:
                            stream.close()

                server = self.start(serve())
                try:
                    if passes:
                        result = await asyncio.wait_for(worker.app(NONCE, False, port, attempts=attempts, pause=0.05), 10)
                        self.assertEqual(result["attempts"], 3)
                    else:
                        with self.assertRaises(OSError) as caught:
                            await asyncio.wait_for(worker.app(NONCE, False, port, attempts=attempts, pause=0.05), 10)
                        self.assertIn(caught.exception.errno, worker.TRANSIENT)
                finally:
                    server.cancel()
                    bound.close()

    async def test_cli_bounds_attempts_pauses_and_accepts(self):
        def args(**values):
            return mock.Mock(**{"nonce": NONCE, "role": "app", "deny": False, "port": 0, "deadline": 10, "attempts": 4,
                                "pause": None, "accepts": 1, **values})

        with mock.patch.object(worker.os, "geteuid", return_value=1000):
            for bad in (args(attempts=0), args(attempts=worker.MAX_ATTEMPTS + 1), args(pause=0.01), args(pause=10.5),
                        args(role="target", accepts=-1), args(role="target", accepts=worker.MAX_ATTEMPTS + 1)):
                with self.subTest(role=bad.role, attempts=bad.attempts, pause=bad.pause, accepts=bad.accepts):
                    with self.assertRaises(ValueError):
                        await worker.main(bad)


def socket_connect(port):
    import socket
    stream = socket.create_connection(("127.0.0.1", port), 5)
    return stream


if __name__ == "__main__":
    unittest.main()
