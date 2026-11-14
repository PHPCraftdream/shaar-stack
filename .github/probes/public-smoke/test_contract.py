"""Pure CI-run tests: contract schema and ceilings, dispatch validation, keys, workflow routing."""

import copy
import importlib.util
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("smoke_run_for_contract_tests", HERE / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
CONTRACT, KEYS = RUN.CONTRACT, RUN.KEYS
RELAY = {"peer_id": "12D3KooWRhxsqdyvN1Cy4HDzPjKtdscPa9XUyqoqJwHSsGY8LQTQ", "address": "8.8.4.4:4001",
         "operator": "example operator", "basis": "published terms (test fixture)"}
APPROVAL = {"date": "2026-11-13", "quote": "test fixture", "decision_log": "docs/plans/north-star.md"}


def runnable():
    contract, digest = CONTRACT.load_contract()
    contract = copy.deepcopy(contract)
    contract["targets"]["libp2p_relay"] = dict(RELAY)
    contract["approval"] = dict(APPROVAL)
    return contract, digest


def env(digest, **changes):
    base = {"GITHUB_EVENT_NAME": "workflow_dispatch", "SOURCE_REVISION": "a" * 40, "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "123456789", "DIRECT_FEEDBACK": "false", "PREFLIGHT": "false", "MATRIX": "false",
            "PUBLIC_SMOKE": "true", "CONTRACT_SHA256": digest}
    base.update(changes)
    return {key: value for key, value in base.items() if value is not None}


class KeyTests(unittest.TestCase):
    def test_rfc8032_public_keys(self):
        vectors = (("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                   ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"))
        for seed, public in vectors:
            self.assertEqual(KEYS.public_key(bytes.fromhex(seed)).hex(), public)

    def test_seed_length_is_enforced(self):
        for bad in (b"", b"\0" * 31, b"\0" * 33, "a" * 32):
            with self.assertRaises(ValueError):
                KEYS.public_key(bad)

    def test_seeds_are_per_role_per_run_and_deterministic(self):
        one = KEYS.derive_seed("1", "1", "server")
        self.assertEqual(one, KEYS.derive_seed("1", "1", "server"))
        self.assertEqual(len(one), 32)
        others = {KEYS.derive_seed("1", "1", "client"), KEYS.derive_seed("2", "1", "server"),
                  KEYS.derive_seed("1", "2", "server")}
        self.assertNotIn(one, others)
        self.assertEqual(len(others), 3)
        with self.assertRaises(ValueError):
            KEYS.derive_seed("1", "1", "relay")

    def test_nonce_shape(self):
        self.assertRegex(KEYS.derive_nonce("1", "1"), r"^[0-9a-f]{16}$")
        self.assertNotEqual(KEYS.derive_nonce("1", "1"), KEYS.derive_nonce("2", "1"))

    @unittest.skipUnless(os.name == "posix", "mode bits are POSIX")
    def test_key_file_is_private_exclusive_and_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "server.key")
            seed = KEYS.derive_seed("1", "1", "server")
            KEYS.write_key_file(path, seed)
            self.assertEqual(path.read_bytes(), seed)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0)
            with self.assertRaises(FileExistsError):
                KEYS.write_key_file(path, seed)


class ContractTests(unittest.TestCase):
    def test_committed_contract_is_valid_and_exact(self):
        contract, digest = CONTRACT.load_contract()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        targets = contract["targets"]
        self.assertEqual([(row["host"], row["port"]) for row in targets["mainline_bootstrap"]],
                         [("dht.libtorrent.org", 25401), ("router.bittorrent.com", 6881)])
        self.assertEqual([row["uri"] for row in targets["ygg_peers"]],
                         ["tcp://ygg-pa.incognet.io:8883", "tcp://mo.us.ygg.triplebit.org:9000"])
        self.assertEqual(contract["budgets"]["retries"], 0)
        self.assertEqual(contract["budgets"]["runs_per_dispatch"], 1)

    def test_unapproved_contract_cannot_run(self):
        contract, _ = CONTRACT.load_contract()
        found = CONTRACT.blockers(contract)
        if found:
            with self.assertRaises(CONTRACT.Blocked):
                CONTRACT.require_runnable(contract)
        full, _ = runnable()
        self.assertEqual(CONTRACT.blockers(full), [])
        CONTRACT.require_runnable(full)

    def test_each_blocker_blocks_alone(self):
        full, _ = runnable()
        for field, value in (("approval", None),):
            changed = copy.deepcopy(full)
            changed[field] = value
            self.assertEqual(len(CONTRACT.blockers(CONTRACT.validate_contract(changed))), 1)
        changed = copy.deepcopy(full)
        changed["targets"]["libp2p_relay"] = None
        self.assertEqual(len(CONTRACT.blockers(CONTRACT.validate_contract(changed))), 1)

    def test_ceilings_cannot_be_widened(self):
        full, _ = runnable()
        mutations = [
            ("budgets", "retries", 1), ("budgets", "runs_per_dispatch", 2), ("budgets", "runners", 3),
            ("budgets", "job_seconds", 301), ("budgets", "sample_interval_ms", 5000),
        ]
        for section, key, value in mutations:
            changed = copy.deepcopy(full)
            changed[section][key] = value
            with self.subTest(key=key), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_contract(changed)
        for key, limit in CONTRACT.CEILINGS["per_job"].items():
            for value in (limit + 1, 0, -1, True, "1"):
                changed = copy.deepcopy(full)
                changed["budgets"]["per_job"][key] = value
                with self.subTest(per_job=key, value=value), self.assertRaises(CONTRACT.ContractError):
                    CONTRACT.validate_contract(changed)
        changed = copy.deepcopy(full)
        changed["budgets"]["app"]["exchanges"] = 2
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_contract(changed)
        tightened = copy.deepcopy(full)
        tightened["budgets"]["per_job"]["nic_bytes"] = 1024
        CONTRACT.validate_contract(tightened)

    def test_target_shapes_are_exact(self):
        full, _ = runnable()
        peers = full["targets"]["ygg_peers"]
        bad_targets = {
            "third peer": lambda c: peers.append({"uri": "tcp://a.example.org:1", "operator": "o", "basis": "b"}),
            "query string": lambda c: peers[0].update(uri="tcp://ygg-pa.incognet.io:8883?key=" + "a" * 64),
            "tls scheme": lambda c: peers[0].update(uri="tls://ygg-pa.incognet.io:8883"),
            "ip literal host": lambda c: peers[0].update(uri="tcp://203.0.113.9:8883"),
            "port zero": lambda c: peers[0].update(uri="tcp://ygg-pa.incognet.io:0"),
            "port too large": lambda c: peers[0].update(uri="tcp://ygg-pa.incognet.io:70000"),
            "empty basis": lambda c: peers[0].update(basis=" "),
            "no peers": lambda c: peers.clear(),
            "bad bootstrap host": lambda c: c["targets"]["mainline_bootstrap"][0].update(host="Bad_Host"),
            "bootstrap port": lambda c: c["targets"]["mainline_bootstrap"][0].update(port=0),
            "third bootstrap": lambda c: c["targets"]["mainline_bootstrap"].append(
                {"host": "x.example.org", "port": 1, "operator": "o", "basis": "b"}),
            "duplicate": lambda c: c["targets"]["mainline_bootstrap"].append(dict(c["targets"]["mainline_bootstrap"][0])),
            "extra field": lambda c: c["targets"].update(extra=1),
            "relay private": lambda c: c["targets"]["libp2p_relay"].update(address="10.0.0.1:4001"),
            "relay loopback": lambda c: c["targets"]["libp2p_relay"].update(address="127.0.0.1:4001"),
            "relay dns name": lambda c: c["targets"]["libp2p_relay"].update(address="relay.example.org:4001"),
            "relay bad peer id": lambda c: c["targets"]["libp2p_relay"].update(peer_id="QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
            "approval date": lambda c: c["approval"].update(date="13.11.2026"),
            "approval extra": lambda c: c["approval"].update(by="x"),
            "wrong scope": lambda c: c.update(scope="release"),
        }
        for name, mutate in bad_targets.items():
            changed = copy.deepcopy(full)
            peers = changed["targets"]["ygg_peers"]
            with self.subTest(name):
                mutate(changed)
                with self.assertRaises(CONTRACT.ContractError):
                    CONTRACT.validate_contract(changed)

    def test_timeline_is_consistent(self):
        full, _ = runnable()
        for key, value in (("server_launch_deadline_s", 20), ("server_end_offset_s", 99), ("server_end_offset_s", 106),
                           ("client_exchange_s", 80), ("client_exchange_s", 301), ("shutdown_grace_s", 16)):
            changed = copy.deepcopy(full)
            changed["budgets"]["timeline"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_contract(changed)
        line = CONTRACT.timeline(full, 1000)
        self.assertEqual(line, {"server_launch_by": 1010, "client_start_at": 1020, "server_end_at": 1105})

    def test_public_ipv4_rule(self):
        for good in ("8.8.8.8", "93.184.216.34"):
            self.assertTrue(CONTRACT.public_ipv4(good))
        for bad in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1",
                    "192.0.2.1", "0.0.0.0", "999.1.1.1", "::1", "name"):
            self.assertFalse(CONTRACT.public_ipv4(bad), bad)

    def test_oversized_or_malformed_contract_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, data in (("big.json", b" " * (64 * 1024 + 1)), ("bad.json", b"{")):
                path = Path(directory, name)
                path.write_bytes(data)
                with self.subTest(name), self.assertRaises(CONTRACT.ContractError):
                    CONTRACT.load_contract(path)


class DispatchTests(unittest.TestCase):
    def test_exact_dispatch_is_accepted(self):
        _, digest = runnable()
        result = CONTRACT.validate_dispatch(env(digest), digest)
        self.assertEqual(result["revision"], "a" * 40)
        self.assertEqual(result["attempt"], "1")

    def test_every_malformed_input_is_refused(self):
        _, digest = runnable()
        cases = {
            "push event": env(digest, GITHUB_EVENT_NAME="push"),
            "short sha": env(digest, SOURCE_REVISION="a" * 39),
            "long sha": env(digest, SOURCE_REVISION="a" * 41),
            "upper sha": env(digest, SOURCE_REVISION="A" * 40),
            "branch name": env(digest, SOURCE_REVISION="develop"),
            "trailing newline": env(digest, SOURCE_REVISION="a" * 40 + "\n"),
            "injection": env(digest, SOURCE_REVISION="a" * 40 + "; printf x"),
            "empty sha": env(digest, SOURCE_REVISION=""),
            "rerun attempt": env(digest, GITHUB_RUN_ATTEMPT="2"),
            "non decimal run id": env(digest, GITHUB_RUN_ID="12ab"),
            "feedback mode": env(digest, DIRECT_FEEDBACK="true"),
            "preflight mode": env(digest, PREFLIGHT="true"),
            "matrix mode": env(digest, MATRIX="true"),
            "smoke not requested": env(digest, PUBLIC_SMOKE="false"),
            "missing digest": env(digest, CONTRACT_SHA256=""),
            "upper digest": env(digest, CONTRACT_SHA256=digest.upper()),
            "wrong digest": env(digest, CONTRACT_SHA256="0" * 64),
            "missing variable": env(digest, MATRIX=None),
        }
        for name, request in cases.items():
            with self.subTest(name), self.assertRaises(CONTRACT.ContractError):
                CONTRACT.validate_dispatch(request, digest)

    def test_validation_refuses_before_reading_anything_else(self):
        with self.assertRaises(CONTRACT.ContractError):
            CONTRACT.validate_dispatch({}, "0" * 64)


class RenderTests(unittest.TestCase):
    def test_network_text_is_exact_and_secret_free(self):
        text = CONTRACT.render_network(["203.0.113.5:25401", "203.0.113.6:6881"], RELAY["peer_id"],
                                       RELAY["address"], ["tcp://a.example.org:1", "tcp://b.example.org:2"])
        self.assertEqual(text, (
            "network: {\n    mainline: {\n        bootstrap: [\n            203.0.113.5:25401\n"
            "            203.0.113.6:6881\n        ]\n    }\n    signaling: {\n        relay: " + RELAY["peer_id"] +
            "\n        relay_address: 8.8.4.4:4001\n    }\n    ygg: {\n        peers: [\n"
            "            tcp://a.example.org:1\n            tcp://b.example.org:2\n        ]\n    }\n}\n"))

    def test_role_configs(self):
        network = "network: {\n}\n"
        server = CONTRACT.render_server("127.0.0.1:9", network)
        client = CONTRACT.render_client("ab" * 32, "127.0.0.1:2222", network)
        self.assertIn("target: 127.0.0.1:9\n", server)
        self.assertIn("allowlist_path:: allowlist.txt\n", server)
        self.assertIn("fallback: standby\n", server)
        self.assertNotIn("server_address", client)
        self.assertTrue(client.startswith("server: " + "ab" * 32 + "\n"))
        self.assertIn("listen: 127.0.0.1:2222\n", client)

    def test_app_bytes_are_small_and_distinct(self):
        nonce = KEYS.derive_nonce("1", "1")
        request, reply = CONTRACT.app_request(nonce), CONTRACT.app_reply(nonce)
        self.assertNotEqual(request, reply)
        self.assertLessEqual(len(request), 128)
        self.assertTrue(request.endswith(b"\n") and reply.endswith(b"\n"))


class WorkflowTests(unittest.TestCase):
    text = (ROOT / ".github/workflows/sdk-lock.yml").read_text(encoding="utf-8")

    @classmethod
    def jobs(cls):
        starts = list(re.finditer(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*$", cls.text, re.MULTILINE))
        start = cls.text.find("jobs:\n")
        return {m[1]: cls.text[m.end():starts[i + 1].start() if i + 1 < len(starts) else len(cls.text)]
                for i, m in enumerate(starts) if m.start() > start}

    def test_input_is_default_off_and_exclusive(self):
        block = self.text.split("public_smoke:", 1)[1].split("permissions:", 1)[0]
        self.assertIn("default: false", block.split("public_smoke_contract_sha256", 1)[0])
        jobs = self.jobs()
        for name in ("resolve", "direct-feedback"):
            self.assertIn("!inputs.public_smoke", jobs[name], name)
        for name in ("public-smoke-plan", "public-smoke-build", "public-smoke-server", "public-smoke-client"):
            self.assertIn("inputs.public_smoke", jobs[name], name)

    def test_plan_validates_the_revision_before_checkout_and_everything_else(self):
        plan = self.jobs()["public-smoke-plan"]
        first = plan.index("Validate the exact dispatch inputs")
        self.assertLess(first, plan.index("actions/checkout"))
        self.assertLess(plan.index("actions/checkout"), plan.index("run.py validate"))
        self.assertIn('re.fullmatch(r"[0-9a-f]{40}"', plan)
        self.assertIn('GITHUB_RUN_ATTEMPT', plan)
        self.assertIn("python -I -m unittest", plan)

    def test_jobs_are_bounded_unprivileged_and_secret_free(self):
        jobs = self.jobs()
        for name in ("public-smoke-plan", "public-smoke-build", "public-smoke-server", "public-smoke-client"):
            block = jobs[name]
            self.assertIn("runs-on: ubuntu-latest", block)
            minutes = int(re.search(r"timeout-minutes: (\d+)", block)[1])
            self.assertLessEqual(minutes, 90 if name == "public-smoke-build" else 12, name)
            for forbidden in ("sudo", "apt-get", "secrets.", "continue-on-error", "retry", "ip netns"):
                self.assertNotIn(forbidden, block, name)
        self.assertNotIn("secrets.", self.text)
        for name in ("public-smoke-server", "public-smoke-client"):
            self.assertIn("needs: public-smoke-build", jobs[name])
            self.assertIn("if: always()", jobs[name])
        self.assertIn("permissions:\n  contents: read", self.text)

    def test_build_is_normal_and_artifacts_carry_no_keys(self):
        build = self.jobs()["public-smoke-build"]
        self.assertIn("python -I .github/ci/run.py product-manifest", build)
        self.assertNotIn("shaar-native-gate", build)
        self.assertIn("retention-days: 1", build)
        for name in ("public-smoke-server", "public-smoke-client"):
            block = self.jobs()[name]
            upload = block.split("upload-artifact", 1)[1]
            self.assertIn("-evidence/", upload)
            self.assertNotIn(".key", upload)
            self.assertNotIn("-work", upload)

    def test_probe_paths_have_explicit_policy_ownership(self):
        spec = importlib.util.spec_from_file_location("smoke_policy", ROOT / ".github/ci/policy.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ("run.py", "contract.py", "contract.json", "budget.py", "test_budget.py"):
            selected = module.select([".github/probes/public-smoke/" + name])
            self.assertEqual((selected["suites"], selected["targets"]), (["ci_policy"], []), name)

    def test_no_dispatch_runs_without_the_input(self):
        for name in ("public-smoke-plan", "public-smoke-build"):
            self.assertIn("if: ${{ inputs.public_smoke", self.jobs()[name])


if __name__ == "__main__":
    unittest.main()
