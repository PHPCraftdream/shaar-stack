"""CI-only pure product schema/ownership contracts; no privileged network operations."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("shaar_product_contract", Path(__file__).resolve().parents[2] / "contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
spec = importlib.util.spec_from_file_location("shaar_product_network", Path(__file__).resolve().parents[2] / "network.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class ProductContractTests(unittest.TestCase):
    def config(self, directory):
        prefix = "snaabbcc"
        return {"prefix": prefix, "nonce": "a" * 32, "out_dir": str(directory), "run_pid": 42,
                "helper_uid": 1001, "helper_gid": 1001, "ip": dict(contract.IPS),
                "translated_ports": [41010, 41020],
                "ns": {name: prefix + "-" + suffix for name, suffix in contract.SUFFIXES.items()}}

    def test_case_inventory_and_phase_budgets_remain_closed(self):
        self.assertEqual(list(contract.CASES), [
            "native-signal", "native-standby", "blocked-standby", "blocked-signal", "lan-signal", "lan-standby",
            "relay-denied-signal", "failover-standby", "failover-signal", "denied-blocked-standby", "dht-drop-signal",
            "outage-standby", "dnat-cone-signal", "dnat-cone-standby", "dnat-sym-signal", "dnat-sym-standby",
            "hole-signal", "hole-standby", "switch-signal", "switch-standby", "relay-full-signal", "relay-full-standby",
            "ipv6-signal", "ipv6-standby", "denied-native-signal", "recover-standby"])
        self.assertEqual(contract.PHASE_SECONDS, 1200)
        self.assertEqual(contract.CASE_SECONDS, 150)
        self.assertEqual(contract.MAX_CHILDREN, 16)
        self.assertEqual(contract.CLEANUP_RESERVE, 45)
        self.assertEqual(contract.FAILOVER_SECONDS, 10.0)
        # 12 product cases and 2 live controls, each with two per-router quotas, leave headroom under 64 MiB.
        self.assertEqual(12 * 2 * contract.PRODUCT_QUOTA + 2 * 2 * contract.FAULT_QUOTA, 56 * 1024 * 1024)
        for name, spec in contract.CASES.items():
            self.assertIn(spec["net"], contract.NETS, name)
            self.assertEqual(spec["udp_blocked"], spec["net"] == "blocked", name)
            self.assertIn(contract.client_ns(spec), ("host_a", "rtr_a"), name)
            self.assertIn(contract.ip_for(spec["server_ns"]), contract.IPS.values(), name)
        self.assertEqual(contract.ip_for("rtr_b"), "203.0.113.2")
        self.assertEqual(contract.final_client_exit(contract.CASES["denied-blocked-standby"]), 1)
        self.assertEqual(contract.final_client_exit(contract.CASES["native-signal"]), 0)
        self.assertEqual(contract.identity_roles(contract.CASES["denied-blocked-standby"])[-1], "client2")
        self.assertEqual(contract.identity_roles(contract.CASES["native-signal"]), contract.IDENTITY_ROLES)
        self.assertEqual(contract.CASES["blocked-signal"]["target_accepts"], 0)
        self.assertEqual(contract.CASES["blocked-signal"]["client_exit"], 1)
        self.assertFalse(contract.CASES["native-standby"]["udp_blocked"])
        self.assertTrue(contract.CASES["blocked-standby"]["udp_blocked"])

    def test_new_row_cases_declare_their_flows_exits_and_identities(self):
        cases = contract.CASES
        for name in ("dnat-cone-signal", "dnat-cone-standby"):
            self.assertEqual((cases[name]["nat"], cases[name]["direct"], cases[name]["target_accepts"]), ("cone", True, 1), name)
        for name in ("dnat-sym-signal", "dnat-sym-standby"):
            self.assertEqual((cases[name]["nat"], cases[name]["direct"]), ("random", False), name)
        self.assertEqual((cases["dnat-sym-signal"]["target_accepts"], cases["dnat-sym-signal"]["client_exit"]), (0, 1))
        self.assertEqual((cases["dnat-sym-standby"]["target_accepts"], cases["dnat-sym-standby"]["client_exit"]), (1, 0))
        for name in ("dnat-cone-signal", "dnat-sym-standby"):
            self.assertEqual(cases[name]["server_ns"], "host_b")
        for name in ("hole-signal", "hole-standby", "switch-signal", "switch-standby"):
            self.assertEqual((cases[name]["net"], cases[name]["target_accepts"], cases[name]["ygg_client_blocked"]), ("nat", 2, True), name)
        self.assertEqual(contract.client_bind(cases["switch-signal"]), "0.0.0.0")
        self.assertEqual(contract.client_bind(cases["native-signal"]), "10.0.1.2")
        self.assertEqual(contract.client_bind(cases["lan-signal"]), "203.0.113.1")
        full = cases["relay-full-standby"]
        self.assertTrue(contract.server_fails(full))
        self.assertFalse(contract.server_fails(cases["native-signal"]))
        self.assertEqual((full["fillers"], full["server_exit"], full["client_exit"], full["target_accepts"]), (2, 1, None, 0))
        self.assertEqual(contract.identity_roles(full), ("wan", "target", "server", "filler1", "filler2"))
        self.assertEqual(contract.identity_roles(cases["recover-standby"])[-1], "client2")
        self.assertEqual(contract.final_client_exit(cases["recover-standby"]), 0)
        self.assertEqual(contract.final_client_exit(full), None)
        for name in ("ipv6-signal", "ipv6-standby"):
            self.assertEqual((cases[name]["net"], cases[name]["client_ns"], cases[name]["server_ns"]), ("ipv6", "rtr_a", "rtr_b"), name)
        self.assertEqual(contract.SEGMENT_NETS, ("lan", "ipv6"))
        self.assertEqual(cases["denied-native-signal"]["net"], "nat")
        for spec in cases.values():
            self.assertIn(spec.get("flow", "single"), ("single", "failover", "denied-key", "hole", "switch", "ipv6", "outage-recovery", "relay-full"))

    def test_namespace_targets_cannot_escape_or_acquire_root_products(self):
        allowed = Path(contract.__file__).resolve().parents[2] / "out"
        allowed.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=allowed) as directory:
            original = self.config(Path(directory))
            self.assertEqual(contract.validate_config(original, "a" * 40, "native-signal"), Path(directory))
            for mutation in ("namespace", "address", "ports", "uid", "nonce", "path", "prefix"):
                changed = copy.deepcopy(original)
                if mutation == "namespace":
                    changed["ns"]["host_a"] = "default"
                elif mutation == "address":
                    changed["ip"]["wan"] = "192.0.2.10"
                elif mutation == "ports":
                    changed["translated_ports"] = [40001, 40002]
                elif mutation == "uid":
                    changed["helper_uid"] = 0
                elif mutation == "nonce":
                    changed["nonce"] += "0"
                elif mutation == "path":
                    changed["out_dir"] = str(allowed.parent)
                else:
                    changed["prefix"] = "../../foreign"
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    contract.validate_config(changed, "a" * 40, "native-signal")
            with self.assertRaises(ValueError):
                contract.validate_config(original, "develop", "native-signal")
            with self.assertRaises(ValueError):
                contract.validate_config(original, "a" * 40, "unreviewed")

    def test_ready_and_publication_records_bind_owned_pid_nonce_and_wire_sequence(self):
        nonce, key = "a" * 32, "b" * 64
        ready = {"role": "keys", "nonce": nonce, "pid": 42, "server_key": key, "client_key": "c" * 64}
        contract.validate_ready(ready, "keys", nonce, 42)
        for field, value in (("role", "wan"), ("nonce", "0" * 32), ("pid", 43), ("client_key", key)):
            changed = dict(ready)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.validate_ready(changed, "keys", nonce, 42)
        # This is metadata framing, not a cryptographic positive control.
        envelope = key + "0" * 128 + (7).to_bytes(8, "big").hex()
        publication = {"nonce": nonce, "sequence": 7, "signed_envelope_hex": envelope,
                       "native_addresses": ["203.0.113.10:40001"]}
        contract.validate_publication(publication, nonce, key)
        for field, value in (("nonce", "0" * 32), ("sequence", 8), ("signed_envelope_hex", "00"), ("native_addresses", [])):
            changed = dict(publication)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.validate_publication(changed, nonce, key)

    def test_normal_product_manifest_cannot_use_test_profiles_or_enable_the_packet_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"source_revision": "a" * 40, "normal_native_gate_enabled": False,
                        "products": {name: {"executable": str(root / name), "bytes": 1, "sha256": "b" * 64,
                                            "source_path": "/repo/crates/" + name + "/src/main.rs", "profile_test": False}
                                     for name in ("shaar-server", "shaar-client", "identity-helper")}}
            contract.validate_manifest(manifest, "a" * 40)
            for mutation in ("source", "gate", "profile", "path", "set"):
                changed = copy.deepcopy(manifest)
                if mutation == "source":
                    changed["source_revision"] = "c" * 40
                elif mutation == "gate":
                    changed["normal_native_gate_enabled"] = True
                elif mutation == "profile":
                    changed["products"]["shaar-server"]["profile_test"] = True
                elif mutation == "path":
                    changed["products"]["shaar-client"]["source_path"] = "/repo/fixture/main.rs"
                else:
                    changed["products"].pop("identity-helper")
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    contract.validate_manifest(changed, "a" * 40)

    @unittest.skipUnless(sys.platform == "linux", "namespace evidence uses Linux O_NOFOLLOW")
    def test_regular_evidence_reads_reject_symlinks_and_byte_overruns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real, link = root / "record.json", root / "link.json"
            real.write_text(json.dumps({"ok": True}), encoding="utf-8")
            self.assertEqual(contract.bounded_json(real), {"ok": True})
            link.symlink_to(real)
            with self.assertRaises(OSError):
                contract.bounded_json(link)
            with self.assertRaises(ValueError):
                contract.bounded_json(real, 1)
            with self.assertRaises(ValueError):
                contract.file_digest(real, 1)


class NetworkContractTests(unittest.TestCase):
    def evidence(self):
        # Synthetic metadata tests the verifier only, never kernel or NAT acceptance.
        table = "snaabbcc_product"
        base = {"family": "inet", "table": table}
        objects = [{"table": {"family": "inet", "name": table}}]
        for name, kind, hook, priority in (("budget", "filter", "forward", -300),
                                           ("paths", "filter", "forward", -200),
                                           ("natout", "nat", "postrouting", 100),
                                           ("seen", "filter", "postrouting", 200),
                                           ("lanin", "filter", "input", -200),
                                           ("lanout", "filter", "output", -200)):
            objects.append({"chain": {**base, "name": name, "type": kind, "hook": hook,
                                      "prio": priority, "policy": "accept"}})
        for name in sorted(network.COUNTERS):
            objects.append({"counter": {**base, "name": name, "packets": 0, "bytes": 0}})
        objects.append({"quota": {**base, "name": "phase_budget", "bytes": network.QUOTAS["product"], "used": 0, "inv": True}})
        for comment in ("budget", "no-ipv6", "other-tcp-block", "udp-nat", "tcp-nat",
                        "native-block", "dht-query", "dht-reply", "snat-seen"):
            chain = ("budget" if comment == "budget" else "natout" if comment.endswith("-nat")
                     else "seen" if comment == "snat-seen" else "paths")
            objects.append({"rule": {**base, "chain": chain, "expr": [{"counter": "test_metadata"}], "comment": "p13-" + comment}})
        return {"nftables": objects}

    def object(self, document, kind, name):
        return next(entry[kind] for entry in document["nftables"] if kind in entry and entry[kind].get("name") == name)

    def test_rule_compiler_keeps_native_and_ygg_exclusions_separate(self):
        import re
        self.assertEqual(network.CASES, set(contract.CASES))
        self.assertEqual(network.QUOTAS, {"product": contract.PRODUCT_QUOTA, "fault": contract.FAULT_QUOTA})
        ports = {"dht": 42001, "relay": 42002, "transit": 42003}
        for case in network.CASES:
            profile = network.PROFILES[case]
            for router in ("rtr_a", "rtr_b"):
                text = network.rules("snaabbcc", router, case, ports)
                self.assertIn(f"over {contract.PRODUCT_QUOTA} bytes", text)
                self.assertIn("quota name phase_budget counter name quota_drop drop", text)
                self.assertIn("meta nfproto ipv6 counter name ipv6_drop drop", text)
                flavor = network.NAT_FLAVORS[profile.get("nat", "range")]
                self.assertIn(flavor, text)
                # nft keywords such as snat/dnat/filter cannot be chain names (real nft rejected "snat").
                self.assertEqual(re.findall(r"add chain inet \S+ (\w+) ", text),
                                 ["budget", "paths", "lanin", "lanout", "natout", "seen"])
                self.assertIn("udp dport != 42001 ct status snat counter name native_snat", text)
                # Port-range NAT needs an explicit transport match in the rule.
                self.assertIn(f"ip protocol udp counter name udp_nat {flavor} comment", text)
                self.assertIn("meta l4proto tcp counter name tcp_nat masquerade", text)
                self.assertNotIn("ct state", text)
                self.assertNotIn("flush ruleset", text)
                self.assertNotIn("dnat", text)
                if profile["udp"] == "blocked":
                    self.assertIn("p13-native-block", text)
                    self.assertIn("udp dport 42001 accept", text)
                else:
                    self.assertNotIn("p13-native-block", text)
                self.assertEqual("p13-dht-block" in text, bool(profile.get("dht_drop")) and router == "rtr_a")
                self.assertEqual("p13-lan-native" in text, bool(profile.get("lan")))
                self.assertEqual("p13-lan-ygg-block" in text, bool(profile.get("lan")) and router == "rtr_a")
                if router == "rtr_a":
                    for service, port, counter in (("relay", 42002, "relay_tcp"), ("transit", 42003, "ygg_tcp")):
                        accept = f"tcp dport {port} counter name {counter} accept"
                        self.assertEqual(accept in text, service in profile["tcp_a"], (case, service))
                else:
                    self.assertIn("tcp dport 42002 counter name relay_tcp accept", text)
                    self.assertIn("tcp dport 42003 counter name ygg_tcp accept", text)
        self.assertIn("over 2097152 bytes", network.rules("snaabbcc", "rtr_a", "native-signal", ports, "fault"))

    def test_runtime_lan_and_outage_profiles_match_the_reviewed_path_policy(self):
        profiles = network.PROFILES
        self.assertEqual(profiles["failover-standby"]["udp"], "runtime")
        self.assertEqual(set(profiles["failover-standby"]["tcp_a"]), {"relay", "transit"})
        self.assertEqual(profiles["relay-denied-signal"]["tcp_a"], ("transit",))
        self.assertEqual(profiles["outage-standby"], {"udp": "blocked", "tcp_a": ()})
        ports = {"dht": 42001, "relay": 42002, "transit": 42003}
        outage = network.rules("snaabbcc", "rtr_a", "outage-standby", ports)
        self.assertNotIn("counter name relay_tcp accept", outage)
        self.assertNotIn("counter name ygg_tcp accept", outage)
        lan = network.rules("snaabbcc", "rtr_b", "lan-signal", ports)
        self.assertIn("lanin ip saddr 203.0.113.1 ip daddr 203.0.113.2 meta l4proto udp counter name lan_native", lan)
        lan = network.rules("snaabbcc", "rtr_a", "lan-standby", ports)
        self.assertIn("lanin ip saddr 203.0.113.2 ip daddr 203.0.113.1 meta l4proto udp counter name lan_native", lan)
        self.assertIn("lanout ip daddr 203.0.113.10 tcp dport 42003 counter name tcp_drop drop", lan)
        self.assertIn("lanout ip saddr 203.0.113.1 ip daddr 203.0.113.2 meta l4proto udp counter name lan_sent", lan)
        self.assertIn("lanout ip saddr 203.0.113.2 ip daddr 203.0.113.1 meta l4proto udp counter name lan_sent",
                      network.rules("snaabbcc", "rtr_b", "lan-signal", ports))

    def test_new_row_profiles_add_only_their_own_observations(self):
        ports = {"dht": 42001, "relay": 42002, "transit": 42003}
        rules = lambda router, case: network.rules("snaabbcc", router, case, ports)
        cone, sym_b = rules("rtr_a", "dnat-cone-signal"), rules("rtr_b", "dnat-sym-standby")
        self.assertIn("natout ip saddr 10.0.1.2 ip protocol udp counter name udp_nat masquerade comment", cone)
        self.assertIn("seen ip saddr 203.0.113.1 ip daddr 203.0.113.2 meta l4proto udp ct status snat counter name peer_sent", cone)
        self.assertIn("paths ip saddr 203.0.113.2 ip daddr 10.0.1.2 meta l4proto udp counter name peer_recv", cone)
        self.assertIn("seen ip saddr 203.0.113.1 meta l4proto udp udp dport != 42001 ct status snat counter name native_out", cone)
        self.assertIn("natout ip saddr 10.0.2.2 ip protocol udp counter name udp_nat masquerade fully-random comment", sym_b)
        self.assertIn("seen ip saddr 203.0.113.2 ip daddr 203.0.113.1 meta l4proto udp ct status snat counter name peer_sent", sym_b)
        self.assertNotIn("tcp dport 42003 counter name ygg_tcp accept", cone)
        self.assertIn("tcp dport 42003 counter name ygg_tcp accept", rules("rtr_a", "dnat-sym-signal"))
        self.assertNotIn("p13-native-block", cone)
        hole, switch = rules("rtr_a", "hole-signal"), rules("rtr_a", "switch-standby")
        self.assertIn("lanin ip daddr 203.0.113.1 meta l4proto udp counter name hole_in", hole)
        self.assertIn("natout ip saddr 10.0.1.2 ip protocol udp udp dport != 42001 counter name native_new", hole)
        self.assertLess(hole.index("counter name native_new"), hole.index("counter name udp_nat"))
        self.assertIn("natout ip saddr 10.0.1.0/24 ip protocol udp counter name udp_nat masquerade to :41010-41020 comment", switch)
        self.assertIn("natout ip saddr 10.0.1.0/24 meta l4proto tcp counter name tcp_nat masquerade comment", switch)
        self.assertNotIn("counter name hole_in", switch)
        v6a, v6b = rules("rtr_a", "ipv6-signal"), rules("rtr_b", "ipv6-standby")
        self.assertIn("lanin ip6 saddr 2001:db8:13::2 ip6 daddr 2001:db8:13::1 meta l4proto udp counter name lan6_native", v6a)
        self.assertIn("lanout ip6 saddr 2001:db8:13::1 ip6 daddr 2001:db8:13::2 meta l4proto udp counter name lan6_sent", v6a)
        self.assertIn("lanin ip6 saddr 2001:db8:13::1 ip6 daddr 2001:db8:13::2 meta l4proto udp counter name lan6_native", v6b)
        self.assertIn("meta nfproto ipv6 counter name ipv6_drop drop", v6a)
        self.assertEqual(network.V6, {"rtr_a": "2001:db8:13::1", "rtr_b": "2001:db8:13::2"})
        self.assertEqual(contract.V6, network.V6)
        for name in ("peer_sent", "peer_recv", "native_out", "native_new", "hole_in", "lan6_native", "lan6_sent"):
            self.assertIn(name, network.COUNTERS)
            self.assertNotIn(f"counter name {name}", rules("rtr_a", "native-signal"), name)
        for case in ("denied-native-signal", "relay-full-signal", "recover-standby"):
            self.assertIn(case, network.PROFILES)

    def test_network_commands_cannot_change_the_host_or_foreign_namespaces(self):
        cfg = {"prefix": "snaabbcc", "ns": {"rtr_a": "snaabbcc-rtr-a", "rtr_b": "snaabbcc-rtr-b"}}
        for router in ("rtr_a", "rtr_b"):
            plan = network.commands(cfg, router, "/usr/sbin/nft", "/usr/sbin/ip")
            for argv in plan.values():
                self.assertEqual(argv[:4], ["/usr/sbin/ip", "netns", "exec", cfg["ns"][router]])
            self.assertIn("--check", plan["check_rules"])
        for role in ("wan", "host_a", "default", ""):
            with self.assertRaises(ValueError):
                network.commands(cfg, role, "/usr/sbin/nft", "/usr/sbin/ip")
        for changed in ({**cfg, "prefix": "../../host"}, {**cfg, "ns": {"rtr_a": "default"}}):
            with self.assertRaises(ValueError):
                network.commands(changed, "rtr_a", "/usr/sbin/nft", "/usr/sbin/ip")
        ports = {"dht": 42001, "relay": 42002, "transit": 42003}
        for changed in ({**ports, "relay": 42003}, {**ports, "dht": True}, {**ports, "transit": 65536}, {**ports, "extra": 1}):
            with self.assertRaises(ValueError):
                network.rules("snaabbcc", "rtr_a", "blocked-signal", changed)
        with self.assertRaises(ValueError):
            network.rules("snaabbcc", "rtr_a", "native-signal", ports, "unbounded")

    def test_nft_metadata_requires_fresh_monotonic_budgets_and_real_drop_counters(self):
        before, after = self.evidence(), self.evidence()
        self.object(after, "counter", "native_drop").update(packets=2, bytes=200)
        self.object(after, "counter", "udp_nat").update(packets=1, bytes=100)
        self.object(after, "quota", "phase_budget")["used"] = 300
        result = network.verify(before, after, "snaabbcc", "product", blocked=True)
        self.assertEqual(result["quota_used"], 300)
        natted = copy.deepcopy(after)
        self.object(natted, "counter", "native_drop").update(packets=0, bytes=0)
        self.object(natted, "counter", "native_snat").update(packets=3, bytes=300)
        network.verify(before, natted, "snaabbcc", "product", require_nat=True)
        for counter in ("udp_nat", "native_snat"):
            lacking = copy.deepcopy(natted)
            self.object(lacking, "counter", counter)["packets"] = 0
            with self.subTest(lacking=counter), self.assertRaises(ValueError):
                network.verify(before, lacking, "snaabbcc", "product", require_nat=True)
        escaped = copy.deepcopy(after)
        self.object(escaped, "counter", "native_snat")["packets"] = 1
        with self.assertRaises(ValueError):
            network.verify(before, escaped, "snaabbcc", "product", blocked=True)
        with self.assertRaises(ValueError):
            network.verify(before, natted, "snaabbcc", "product", blocked=True, require_nat=True)
        for mutation in ("quota-hit", "drop-hit", "zero-native", "ipv6", "rollback", "changed-rule", "dirty-start"):
            initial, final = copy.deepcopy(before), copy.deepcopy(after)
            if mutation == "quota-hit":
                self.object(final, "quota", "phase_budget")["used"] = network.QUOTAS["product"]
            elif mutation == "drop-hit":
                self.object(final, "counter", "quota_drop")["packets"] = 1
            elif mutation == "zero-native":
                self.object(final, "counter", "native_drop")["packets"] = 0
            elif mutation == "ipv6":
                self.object(final, "counter", "ipv6_drop")["packets"] = 1
            elif mutation == "rollback":
                self.object(initial, "quota", "phase_budget")["used"] = 301
            elif mutation == "changed-rule":
                final["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
            else:
                self.object(initial, "counter", "tcp_nat")["packets"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                network.verify(initial, final, "snaabbcc", "product", blocked=True)

    def test_server_side_router_needs_no_drop_counter_but_keeps_rule_identity(self):
        before, after = self.evidence(), self.evidence()
        # Client side must observe drops; the Server-side router may legitimately see none.
        with self.assertRaises(ValueError):
            network.verify(before, after, "snaabbcc", "product", blocked=True)
        result = network.verify(before, after, "snaabbcc", "product", blocked=True, require_drop=False)
        self.assertEqual(result["quota_used"], 0)
        self.object(after, "counter", "native_drop").update(packets=1, bytes=10)
        network.verify(before, after, "snaabbcc", "product", blocked=True, require_drop=True)
        missing = self.evidence()
        missing["nftables"] = [row for row in missing["nftables"] if row.get("rule", {}).get("comment") != "p13-native-block"]
        with self.assertRaises(ValueError):
            network.verify(before, missing, "snaabbcc", "product", blocked=True, require_drop=False)

    def test_nft_inventory_rejects_missing_duplicate_or_foreign_objects(self):
        for mutation in ("missing-quota", "duplicate-counter", "foreign-table", "weak-quota", "missing-rule", "wrong-hook", "negative-counter"):
            document = self.evidence()
            if mutation == "missing-quota":
                document["nftables"] = [row for row in document["nftables"] if "quota" not in row]
            elif mutation == "duplicate-counter":
                document["nftables"].append({"counter": copy.deepcopy(self.object(document, "counter", "native_drop"))})
            elif mutation == "foreign-table":
                self.object(document, "counter", "tcp_drop")["table"] = "foreign"
            elif mutation == "weak-quota":
                self.object(document, "quota", "phase_budget")["inv"] = False
            elif mutation == "missing-rule":
                document["nftables"] = [row for row in document["nftables"] if row.get("rule", {}).get("comment") != "p13-budget"]
            elif mutation == "wrong-hook":
                self.object(document, "chain", "budget")["hook"] = "input"
            else:
                self.object(document, "counter", "tcp_drop")["packets"] = -1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                network.snapshot(document, "snaabbcc", "product")
