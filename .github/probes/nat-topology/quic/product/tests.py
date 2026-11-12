"""CI-only pure product schema/ownership contracts; no privileged network operations."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("shaar_product_contract", Path(__file__).with_name("contract.py"))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
spec = importlib.util.spec_from_file_location("shaar_product_network", Path(__file__).with_name("network.py"))
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
        self.assertEqual(set(contract.CASES), {"native-signal", "native-standby", "blocked-standby", "blocked-signal"})
        self.assertEqual(contract.PHASE_SECONDS, 1200)
        self.assertEqual(contract.MAX_CHILDREN, 16)
        self.assertEqual(contract.CLEANUP_RESERVE, 45)
        self.assertEqual(4 * 2 * contract.PRODUCT_QUOTA + 2 * 2 * contract.FAULT_QUOTA, 64 * 1024 * 1024)
        self.assertEqual(contract.CASES["blocked-signal"]["target_accepts"], 0)
        self.assertEqual(contract.CASES["blocked-signal"]["client_exit"], 1)
        self.assertFalse(contract.CASES["native-standby"]["udp_blocked"])
        self.assertTrue(contract.CASES["blocked-standby"]["udp_blocked"])

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
                                           ("snat", "nat", "postrouting", 100)):
            objects.append({"chain": {**base, "name": name, "type": kind, "hook": hook,
                                      "prio": priority, "policy": "accept"}})
        for name in sorted(network.COUNTERS):
            objects.append({"counter": {**base, "name": name, "packets": 0, "bytes": 0}})
        objects.append({"quota": {**base, "name": "phase_budget", "bytes": network.QUOTAS["product"], "used": 0, "inv": True}})
        for comment in ("budget", "no-ipv6", "other-tcp-block", "udp-nat", "tcp-nat",
                        "native-block", "dht-query", "dht-reply"):
            chain = "budget" if comment == "budget" else "snat" if comment.endswith("-nat") else "paths"
            objects.append({"rule": {**base, "chain": chain, "expr": [{"counter": "test_metadata"}], "comment": "p13-" + comment}})
        return {"nftables": objects}

    def object(self, document, kind, name):
        return next(entry[kind] for entry in document["nftables"] if kind in entry and entry[kind].get("name") == name)

    def test_rule_compiler_keeps_native_and_ygg_exclusions_separate(self):
        self.assertEqual(network.CASES, set(contract.CASES))
        self.assertEqual(network.QUOTAS, {"product": contract.PRODUCT_QUOTA, "fault": contract.FAULT_QUOTA})
        ports = {"dht": 42001, "relay": 42002, "transit": 42003}
        for case in network.CASES:
            for router in ("rtr_a", "rtr_b"):
                text = network.rules("snaabbcc", router, case, ports)
                self.assertIn("over 7340032 bytes", text)
                self.assertIn("quota name phase_budget counter name quota_drop drop", text)
                self.assertIn("meta nfproto ipv6 counter name ipv6_drop drop", text)
                self.assertIn("masquerade to :41010-41020", text)
                self.assertIn("meta l4proto tcp counter name tcp_nat masquerade", text)
                self.assertNotIn("ct state", text)
                self.assertNotIn("flush ruleset", text)
                self.assertNotIn("dnat", text)
                if case.startswith("blocked-"):
                    self.assertIn("p13-native-block", text)
                    self.assertIn("udp dport 42001 accept", text)
                else:
                    self.assertNotIn("p13-native-block", text)
                if router == "rtr_a":
                    allowed, denied = (42003, 42002) if case.startswith("blocked-") else (42002, 42003)
                    self.assertIn(f"tcp dport {allowed} accept", text)
                    self.assertNotIn(f"tcp dport {denied} accept", text)
        self.assertIn("over 2097152 bytes", network.rules("snaabbcc", "rtr_a", "native-signal", ports, "fault"))

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
        result = network.verify(before, after, "snaabbcc", "product", blocked=True, require_nat=True)
        self.assertEqual(result["quota_used"], 300)
        for mutation in ("quota-hit", "drop-hit", "zero-native", "zero-nat", "ipv6", "rollback", "changed-rule", "dirty-start"):
            initial, final = copy.deepcopy(before), copy.deepcopy(after)
            if mutation == "quota-hit":
                self.object(final, "quota", "phase_budget")["used"] = network.QUOTAS["product"]
            elif mutation == "drop-hit":
                self.object(final, "counter", "quota_drop")["packets"] = 1
            elif mutation in ("zero-native", "zero-nat"):
                self.object(final, "counter", "native_drop" if mutation == "zero-native" else "udp_nat")["packets"] = 0
            elif mutation == "ipv6":
                self.object(final, "counter", "ipv6_drop")["packets"] = 1
            elif mutation == "rollback":
                self.object(initial, "quota", "phase_budget")["used"] = 301
            elif mutation == "changed-rule":
                final["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
            else:
                self.object(initial, "counter", "tcp_nat")["packets"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                network.verify(initial, final, "snaabbcc", "product", blocked=True, require_nat=True)

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
