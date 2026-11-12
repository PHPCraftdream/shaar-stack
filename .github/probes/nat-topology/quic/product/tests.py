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
