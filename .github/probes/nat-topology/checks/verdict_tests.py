"""CI-only verdict contracts for the L4 punch cases: metadata only, no privileged network action."""

import copy
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
TOPOLOGY = HERE.parent
PRODUCT = TOPOLOGY / "quic" / "product"
RUNTIME = PRODUCT / "runtime"
for path in (TOPOLOGY, PRODUCT, RUNTIME, RUNTIME / "tests", PRODUCT / "flows"):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)
import contract  # noqa: E402
import phase  # noqa: E402  (import-safe: no privileged action at module level)
import phase_tests  # noqa: E402  (reuses the synthetic evidence/mutation factories)
import verdicts  # noqa: E402

NONCE, SOURCE = "d" * 32, "a" * 40
DIRECT_CONE = ("dnat-cone-norelay-signal", "dnat-cone-norelay-standby")
PUNCH_MUTATIONS = ("no-route-line", "no-punch-line", "punch-fallback", "punch-zero", "no-markers", "route-relay")


def peer_counters(sent=5, received=6, ygg=0, dht_drop=0, relay_tcp=0):
    """Minimal counter shape read by verdicts.packets: both routers, dnat-relevant names only."""
    base = {"peer_sent": {"packets": sent}, "peer_recv": {"packets": received},
            "ygg_tcp": {"packets": ygg}, "dht_drop": {"packets": dht_drop}, "relay_tcp": {"packets": relay_tcp}}
    return {router: copy.deepcopy(base) for router in ("rtr_a", "rtr_b")}


def punch_calibration(flavor="cone"):
    kept, moved = (3, 0) if flavor == "cone" else (0, 3)
    return [{"router": router, "flavor": flavor, "kept": kept, "moved": moved} for router in ("rtr_a", "rtr_b")]


def punch_control():
    return {"status": "pass", "receipts": [{"host": "host_a"}, {"host": "host_b"}]}


def direct_result(lines=True):
    """Minimal direct-cone verdict input; markers carry the punch trace and the native route line."""
    result = {"nat_calibration": punch_calibration(), "punch_control": punch_control(),
              "observe": {router: {name: 0 for name in verdicts.OBSERVE_NAMES} for router in ("rtr_a", "rtr_b")},
              "observe_calibration": [{"detected": {"outside_fwd": 2, "outside_out": 2}}] * 2}
    if lines:
        result["markers"] = {"client": "composed startup: server_address=none",
                             "client_lines": {contract.PUNCH_TRACE: contract.PUNCH_TRACE + "2 outcome=direct elapsed_ms=120",
                                              contract.ROUTE_LINE: contract.ROUTE_LINE + " via 203.0.113.10"}}
    return result


def fail_closed_result(spec):
    """Minimal fail-closed dnat verdict input (no direct path, no markers needed)."""
    ygg = 9 if not spec["ygg_client_blocked"] and spec["mode"] == "standby" else 0
    dht_drop = 3 if spec.get("relay_first") or spec.get("dht_denied") else 0
    relay_tcp = 40 if spec.get("relay_first") else 0
    counters = peer_counters(sent=0, received=0, ygg=ygg, dht_drop=dht_drop, relay_tcp=relay_tcp)
    return counters, {"nat_calibration": punch_calibration(spec["nat"]), "punch_control": punch_control(),
                      "observe": {router: {name: 0 for name in verdicts.OBSERVE_NAMES} for router in ("rtr_a", "rtr_b")},
                      "observe_calibration": [{"detected": {"outside_fwd": 2, "outside_out": 2}}] * 2}


class DirectConeVerdictTests(unittest.TestCase):
    def test_direct_cone_oracle_requires_route_and_punch_lines(self):
        for name in DIRECT_CONE:
            spec = contract.CASES[name]
            self.assertTrue(spec["direct"], name)
            verdicts.dnat(spec, peer_counters(ygg=9), direct_result())
            with self.subTest(case=name):
                self.assertEqual(phase.verify_product_case(phase_tests.evidence(name), name, SOURCE, NONCE),
                                 {"forwarded_bytes": 2000, "active_seconds": 12.5})
                for mutation in PUNCH_MUTATIONS:
                    with self.subTest(mutation=mutation), self.assertRaises((ValueError, KeyError)):
                        phase.verify_product_case(phase_tests.mutate(name, mutation), name, SOURCE, NONCE)
        base = direct_result()
        for mutation in ("markers-missing", "route-relay", "punch-fallback", "punch-zero"):
            counters, result = peer_counters(ygg=9), copy.deepcopy(base)
            if mutation == "markers-missing":
                del result["markers"]
            elif mutation == "route-relay":
                result["markers"]["client_lines"][contract.ROUTE_LINE] = contract.ROUTE_LINE.replace("native", "relay")
            elif mutation == "punch-fallback":
                result["markers"]["client_lines"][contract.PUNCH_TRACE] = contract.PUNCH_TRACE + "2 outcome=fallback"
            else:
                result["markers"]["client_lines"][contract.PUNCH_TRACE] = contract.PUNCH_TRACE + "0 outcome=direct"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verdicts.dnat(contract.CASES["dnat-cone-norelay-signal"], counters, result)

    def test_norelay_direct_cones_need_ygg_rendezvous_traffic(self):
        for name in ("dnat-cone-norelay-signal", "dnat-cone-norelay-standby"):
            spec = contract.CASES[name]
            with self.subTest(case=name):
                with self.assertRaises(ValueError):
                    verdicts.dnat(spec, peer_counters(ygg=0), direct_result())
                verdicts.dnat(spec, peer_counters(ygg=9), direct_result())


class FailClosedVerdictTests(unittest.TestCase):
    def test_relay_configured_cones_keep_todays_fail_closed_oracle(self):
        # All four A5 relay-configured cones stay unflipped until L4b (the merged punch needs a relay-less config).
        for name in ("dnat-cone-signal", "dnat-cone-standby", "dnat-cone-relay-signal", "dnat-cone-relay-standby"):
            spec = contract.CASES[name]
            self.assertFalse(spec["direct"], name)
            counters, result = fail_closed_result(spec)
            verdicts.dnat(spec, counters, result)
            self.assertEqual(phase.verify_product_case(phase_tests.evidence(name), name, SOURCE, NONCE),
                             {"forwarded_bytes": 2000, "active_seconds": 12.5})
            direct = copy.deepcopy(counters)
            for router in direct:
                direct[router]["peer_sent"]["packets"], direct[router]["peer_recv"]["packets"] = 5, 6
            with self.subTest(case=name), self.assertRaises(ValueError):
                verdicts.dnat(spec, direct, result)

    def test_sym_negative_controls_are_not_flipped(self):
        literal = [("dnat-sym-signal", "random", False, 0, 1), ("dnat-sym-standby", "random", False, 1, 0)]
        for name, flavor, direct, accepts, exit_code in literal:
            spec = contract.CASES[name]
            self.assertEqual((spec["nat"], spec["direct"], spec["target_accepts"], spec["client_exit"]),
                             (flavor, direct, accepts, exit_code), name)
            counters, result = fail_closed_result(spec)
            verdicts.dnat(spec, counters, result)
            # A flipped direct spec would contradict today's counter shape (no peer traffic, ygg allowed).
            with self.subTest(case=name), self.assertRaises(ValueError):
                verdicts.dnat({**spec, "direct": True}, counters, result)

    def test_fail_closed_guard_needs_observed_dht_drops(self):
        name = "dnat-cone-dhtdrop-signal"
        spec = contract.CASES[name]
        self.assertTrue(spec.get("dht_denied") and not spec["direct"], name)
        counters, result = fail_closed_result(spec)
        verdicts.dnat(spec, counters, result)
        self.assertEqual(phase.verify_product_case(phase_tests.evidence(name), name, SOURCE, NONCE),
                         {"forwarded_bytes": 2000, "active_seconds": 12.5})
        with self.assertRaises(ValueError):
            verdicts.dnat(spec, peer_counters(sent=0, received=0), result)
        with self.assertRaises(ValueError):
            phase.verify_product_case(phase_tests.mutate(name, "no-dht-drop-seen"), name, SOURCE, NONCE)


class PunchGroupTests(unittest.TestCase):
    def test_punch_group_membership(self):
        punch = [entry[2] for entry in phase.GROUPS["punch"] if entry[1] == "product"]
        self.assertEqual(punch, list(phase.PUNCH_CASES))
        self.assertEqual(set(punch), {"dnat-cone-norelay-signal", "dnat-cone-norelay-standby", "dnat-cone-dhtdrop-signal"})
        nat = [entry[2] for entry in phase.GROUPS["nat"] if entry[1] == "product"]
        self.assertIn("dnat-cone-signal", nat)
        self.assertIn("dnat-cone-standby", nat)
        self.assertEqual(set(nat) & set(punch), set())


if __name__ == "__main__":
    unittest.main()
