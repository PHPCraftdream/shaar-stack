"""CI-only pure contracts for the case controller; no namespace, nft, conntrack or product execution."""

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

RUNTIME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME))
sys.path.insert(0, str(RUNTIME.parent))
import case as runcase  # noqa: E402
import configs  # noqa: E402
import contract  # noqa: E402
import controller  # noqa: E402
import kernel  # noqa: E402

PORTS = {"dht": 42001, "relay": 42002, "transit": 42003}
RELAY = "12D3KooWabc"
KEY = "ab" * 32
NONCE = "c" * 32
GOOD_LINE = ("ipv4     2 udp      17 25 src=10.0.1.2 dst=203.0.113.10 sport=33000 dport=40123 "
             "src=203.0.113.10 dst=203.0.113.1 sport=40123 dport=41011 [ASSURED] mark=0 use=1")


class ConfigTests(unittest.TestCase):
    def test_server_and_client_texts_follow_each_case_and_name_only_the_server_key(self):
        for case, spec in contract.CASES.items():
            with self.subTest(case=case):
                server = configs.server_text(case, "/w/keys/server.key", "/w/allow.txt", PORTS, RELAY)
                client = configs.client_text(case, KEY, "/w/keys/client.key", PORTS, RELAY)
                self.assertIn(f"target: 127.0.0.1:{contract.TARGET_PORT}\n", server)
                self.assertIn(f"fallback: {spec['mode']}\n", server)
                self.assertIn(f"bind: {contract.ip_for(spec['server_ns'])}:0\n", server)
                self.assertIn("allowlist_path:: /w/allow.txt\n", server)
                self.assertIn(f"server: {KEY}\nlisten: 127.0.0.1:{contract.FRONT_PORT}\n", client)
                self.assertIn(f"fallback: {spec['mode']}\n", client)
                self.assertNotIn("server_address", client)
                self.assertNotIn("target", client)
                self.assertIn(f"bind: {contract.client_bind(spec)}:0\n", client)
                for text in (server, client):
                    self.assertIn(f"203.0.113.10:{PORTS['dht']}\n", text)
                    self.assertIn(f"relay: {RELAY}\nrelay_address: 203.0.113.10:{PORTS['relay']}\n", text)
                    self.assertIn(f"tcp://203.0.113.10:{PORTS['transit']}\n", text)
                    self.assertTrue(text.endswith("}\n"))

    def test_wildcard_client_bind_and_filler_namespace_follow_the_case_only(self):
        switch = configs.client_text("switch-standby", KEY, "/w/keys/client.key", PORTS, RELAY)
        self.assertEqual(switch.count("bind: 0.0.0.0:0\n"), 2)
        self.assertNotIn("bind: 10.0.1.2", switch)
        filler = configs.server_text("relay-full-signal", "/w/keys/filler1.key", "/w/allow.txt", PORTS, RELAY, ns="wan")
        self.assertEqual(filler.count("bind: 203.0.113.10:0\n"), 2)
        self.assertIn("fallback: signal\n", filler)
        self.assertIn("key_file:: /w/keys/filler1.key\n", filler)
        default = configs.server_text("dnat-cone-signal", "/w/keys/server.key", "/w/allow.txt", PORTS, RELAY)
        self.assertEqual(default.count("bind: 10.0.2.2:0\n"), 2)
        self.assertEqual(configs.client_text("lan-signal", KEY, "/w/keys/client.key", PORTS, RELAY).count("bind: 203.0.113.1:0\n"), 2)
        with self.assertRaises(ValueError):
            configs.network_text("198.51.100.7", PORTS, RELAY)

    def test_untrusted_paths_keys_peers_and_ports_cannot_reshape_the_config(self):
        for path in ("relative/key", "/w/key file", "/w/../key", "/w/key\nfallback: x", "", 7):
            with self.subTest(path=path), self.assertRaises(ValueError):
                configs.server_text("native-signal", path, "/w/allow.txt", PORTS, RELAY)
        for peer in ("", "a b", "a\nb", "x" * 101):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                configs.client_text("native-signal", KEY, "/w/c.key", PORTS, peer)
        for key in ("", "A" * 64, "a" * 63, KEY + "\n"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                configs.client_text("native-signal", key, "/w/c.key", PORTS, RELAY)
            with self.assertRaises(ValueError):
                configs.allowlist_text(key)
        for ports in ({**PORTS, "dht": 80}, {**PORTS, "relay": True}, {"dht": 42001}):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                configs.client_text("native-signal", KEY, "/w/c.key", ports, RELAY)
        with self.assertRaises(KeyError):
            configs.client_text("unreviewed", KEY, "/w/c.key", PORTS, RELAY)
        self.assertEqual(configs.allowlist_text(KEY), KEY + "\n")


class KernelTests(unittest.TestCase):
    def test_quota_probe_is_a_separate_tiny_table_and_requires_live_enforcement(self):
        table, text = kernel.probe_rules("snaabbcc", "10.0.1.2")
        self.assertEqual(table, "snaabbcc_qprobe")
        self.assertIn(f"over {kernel.PROBE_LIMIT} bytes", text)
        self.assertIn("ip saddr 10.0.1.2 udp dport 9 quota name probe_budget counter name probe_over drop", text)
        self.assertNotIn("flush", text)
        good = {"passed": 8, "dropped": 16, "used": 3072}
        self.assertEqual(kernel.check_probe(dict(good)), good)
        for field, value in (("passed", 0), ("dropped", 0), ("used", kernel.PROBE_LIMIT - 1), ("passed", 20)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                kernel.check_probe({**good, field: value})
        document = {"nftables": [
            {"counter": {"table": table, "name": "probe_pass", "packets": 8}},
            {"counter": {"table": table, "name": "probe_over", "packets": 16}},
            {"counter": {"table": "foreign", "name": "probe_over", "packets": 99}},
            {"quota": {"table": table, "name": "probe_budget", "used": 3072}}]}
        self.assertEqual(kernel.probe_counts(document, table), good)
        with self.assertRaises(ValueError):
            kernel.probe_counts({"nftables": document["nftables"][:1]}, table)

    def test_calibration_always_removes_its_owned_table_even_when_enforcement_fails(self):
        cfg = {"prefix": "snaabbcc", "ip": contract.IPS,
               "ns": {key: "snaabbcc-" + value for key, value in contract.SUFFIXES.items()}}
        tools = {name: "/usr/bin/" + name for name in ("ip", "nft", "python")}
        for dropped, expect_error in ((16, False), (0, True)):
            calls = []
            document = {"nftables": [
                {"counter": {"table": "snaabbcc_qprobe", "name": "probe_pass", "packets": 8}},
                {"counter": {"table": "snaabbcc_qprobe", "name": "probe_over", "packets": dropped}},
                {"quota": {"table": "snaabbcc_qprobe", "name": "probe_budget", "used": 3072}}]}

            def checked(argv, deadline, data=None, what="x", calls=calls, document=document):
                calls.append(what)
                return json.dumps(document).encode() if what == "quota probe snapshot" else b""

            with self.subTest(dropped=dropped), mock.patch.object(kernel, "checked", checked):
                if expect_error:
                    with self.assertRaises(ValueError):
                        kernel.calibrate_quota(cfg, tools, "rtr_a", "host_a", time.monotonic() + 5)
                else:
                    result = kernel.calibrate_quota(cfg, tools, "rtr_a", "host_a", time.monotonic() + 5)
                    self.assertEqual((result["passed"], result["dropped"]), (8, 16))
                self.assertEqual(calls, ["quota probe install", "quota probe sender", "quota probe snapshot", "quota probe removal"])

    def test_router_setup_uses_verified_tools_and_refuses_unexpected_forwarding_readback(self):
        cfg = {"prefix": "snaabbcc", "ip": contract.IPS,
               "ns": {key: "snaabbcc-" + value for key, value in contract.SUFFIXES.items()}}
        tools = {"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft", "sysctl": "/opt/verified/sysctl", "python": "/usr/bin/python3"}
        for answers, ok in ((("1", "0"), True), (("0", "0"), False), (("1", "1"), False)):
            calls, replies = [], list(answers)

            def checked(argv, deadline, data=None, what="x", calls=calls, replies=replies):
                calls.append((argv, what))
                return (replies.pop(0) + "\n").encode() if argv[4:5] == ["/opt/verified/sysctl"] and "-n" in argv else b""

            with self.subTest(answers=answers), mock.patch.object(kernel, "checked", checked):
                args = (cfg, tools, "rtr_a", "blocked-standby", {"dht": 42001, "relay": 42002, "transit": 42003},
                        "product", time.monotonic() + 5)
                if ok:
                    self.assertEqual(kernel.install_rules(*args)["forwarding"], {"ipv4": "1", "ipv6": "0"})
                    self.assertEqual(calls[-1][1], "nft rule install")
                    self.assertTrue(all(argv[:4] == ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-a"] for argv, _ in calls))
                    self.assertEqual([argv[5:] for argv, _ in calls[:2]],
                                     [["-q", "-w", "net.ipv4.ip_forward=1"], ["-q", "-w", "net.ipv6.conf.all.forwarding=0"]])
                else:
                    with self.assertRaises(ValueError):
                        kernel.install_rules(*args)
                    self.assertNotIn("nft rule install", [what for _, what in calls])

    def test_namespace_commands_only_enter_owned_namespaces_with_absolute_tools(self):
        cfg = {"prefix": "snaabbcc", "ns": {key: "snaabbcc-" + value for key, value in contract.SUFFIXES.items()}}
        tools = {"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft"}
        self.assertEqual(kernel.ns_argv(tools, cfg, "rtr_a", "/bin/true")[:4], ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-a"])
        with self.assertRaises(ValueError):
            kernel.ns_argv(tools, cfg, "default", "/bin/true")
        with self.assertRaises(ValueError):
            kernel.ns_argv({**tools, "nft": "nft"}, cfg, "rtr_a", "/bin/true")
        with self.assertRaises(ValueError):
            kernel.ns_argv(tools, {**cfg, "ns": {**cfg["ns"], "rtr_a": "default"}}, "rtr_a", "/bin/true")

    def test_lan_isolation_flushes_only_the_router_lan_side_interfaces(self):
        cfg = {"prefix": "snaabbcc", "ns": {key: "snaabbcc-" + value for key, value in contract.SUFFIXES.items()}}
        tools = {"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft"}
        calls = []
        with mock.patch.object(kernel, "checked", lambda argv, deadline, data=None, what="x": calls.append((argv, what)) or b""):
            kernel.isolate_segment(cfg, tools, 0)
        self.assertEqual([argv for argv, _ in calls], [
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-a", "/usr/sbin/ip", "addr", "flush", "dev", "snaabbccra1"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-b", "/usr/sbin/ip", "addr", "flush", "dev", "snaabbccrb1"]])

    def test_new_row_setup_commands_stay_inside_owned_namespaces_and_interfaces(self):
        cfg = {"prefix": "snaabbcc", "ip": contract.IPS, "ns": {key: "snaabbcc-" + value for key, value in contract.SUFFIXES.items()}}
        tools = {"ip": "/usr/sbin/ip", "nft": "/usr/sbin/nft"}
        calls = []
        stub = lambda argv, deadline, data=None, what="x": calls.append((argv, what)) or b""
        with mock.patch.object(kernel, "checked", stub):
            kernel.add_segment_v6(cfg, tools, 0)
            flushed_at = kernel.flap_wan(cfg, tools, "rtr_b", 0)
            switched_at = kernel.switch_client_address(cfg, tools, 0)
        self.assertGreater(switched_at, 0)
        self.assertLessEqual(flushed_at, switched_at)
        self.assertEqual([argv for argv, _ in calls], [
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-a", "/usr/sbin/ip", "-6", "addr", "add", "2001:db8:13::1/64", "dev", "snaabbccra0", "nodad"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-b", "/usr/sbin/ip", "-6", "addr", "add", "2001:db8:13::2/64", "dev", "snaabbccrb0", "nodad"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-b", "/usr/sbin/ip", "link", "set", "dev", "snaabbccrb0", "down"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-b", "/usr/sbin/ip", "link", "set", "dev", "snaabbccrb0", "up"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-rtr-b", "/usr/sbin/ip", "route", "replace", "default", "via", "203.0.113.10", "dev", "snaabbccrb0"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-host-a", "/usr/sbin/ip", "addr", "del", "10.0.1.2/24", "dev", "snaabbccha"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-host-a", "/usr/sbin/ip", "addr", "add", "10.0.1.3/24", "dev", "snaabbccha"],
            ["/usr/sbin/ip", "netns", "exec", "snaabbcc-host-a", "/usr/sbin/ip", "route", "replace", "default", "via", "10.0.1.1", "dev", "snaabbccha"]])
        with self.assertRaises(KeyError):
            kernel.flap_wan(cfg, tools, "wan", 0)

    def test_nat_observation_requires_a_replied_published_native_tuple_in_the_fixed_range(self):
        ports = kernel.native_candidates(["203.0.113.10:40123", "203.0.113.10:42001", "10.0.2.2:40123", "127.0.0.1:9", "bad"], 42001)
        self.assertEqual(ports, [40123])
        found = kernel.nat_observation([GOOD_LINE], "10.0.1.2", "203.0.113.1", ports)
        self.assertEqual((found["reply"]["dport"], found["assured"]), (41011, True))
        replaced = lambda old, new: GOOD_LINE.replace(old, new, 1)
        for name, line in (("unreplied", replaced("sport=33000 dport=40123 src=", "sport=33000 dport=40123 [UNREPLIED] src=")),
                           ("below-range", replaced("dport=41011", "dport=41009")),
                           ("above-range", replaced("dport=41011", "dport=41021")),
                           ("wrong-router", replaced("dst=203.0.113.1 ", "dst=203.0.113.2 ")),
                           ("wrong-source", replaced("src=10.0.1.2", "src=10.0.2.2")),
                           ("dht-port", replaced("dport=40123", "dport=42001").replace("sport=40123", "sport=42001")),
                           ("tcp", replaced("udp      17", "tcp      6")),
                           ("garbage", "not a conntrack line")):
            with self.subTest(name=name):
                self.assertIsNone(kernel.nat_observation([line], "10.0.1.2", "203.0.113.1", ports))
        self.assertIsNone(kernel.nat_observation([], "10.0.1.2", "203.0.113.1", ports))

    @unittest.skipUnless(sys.platform == "linux", "owned setup commands are Linux-only")
    def test_setup_commands_are_deadline_and_output_bounded_and_reaped(self):
        run = lambda code, **kw: kernel.run_tool([sys.executable, "-I", "-c", code], time.monotonic() + kw.get("seconds", 10))
        self.assertEqual(run("print('ok')")[:2], (0, b"ok\n"))
        self.assertEqual(kernel.run_tool([sys.executable, "-I", "-c", "import sys; print(sys.stdin.read())"],
                                         time.monotonic() + 10, b"in")[1], b"in\n")
        with self.assertRaises(TimeoutError):
            kernel.run_tool([sys.executable, "-I", "-c", "import time; time.sleep(30)"], time.monotonic() + 0.2)
        with self.assertRaises(TimeoutError):
            kernel.run_tool([sys.executable, "-I", "-c", "pass"], time.monotonic() - 1)
        with mock.patch.object(kernel, "MAX_OUTPUT", 10), self.assertRaises(ValueError):
            run("print('x' * 100)")
        with self.assertRaisesRegex(RuntimeError, "rc=3"):
            kernel.checked([sys.executable, "-I", "-c", "raise SystemExit(3)"], time.monotonic() + 10)


class CaseTests(unittest.TestCase):
    def test_app_and_target_receipts_match_exact_bytes_or_fail_closed(self):
        request, reply = runcase.worker.payloads(NONCE)
        ok = {"nonce": NONCE, "denied": False, "request_bytes": len(request), "reply_bytes": len(reply)}
        runcase.app_expectation(contract.CASES["native-signal"], ok)
        for field, value in (("denied", True), ("reply_bytes", 0), ("request_bytes", 1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runcase.app_expectation(contract.CASES["native-signal"], {**ok, field: value})
        closed = {"nonce": NONCE, "denied": True, "reply_bytes": 0, "terminal": "eof"}
        runcase.app_expectation(contract.CASES["blocked-signal"], closed)
        # The failover case accepts 1 stream in signal mode, yet its post-block APP must fail closed.
        runcase.app_expectation(contract.CASES["failover-signal"], closed, ok=False)
        runcase.app_expectation(contract.CASES["failover-signal"], ok, ok=True)
        with self.assertRaises(ValueError):
            runcase.app_expectation(contract.CASES["failover-signal"], ok, ok=False)
        for field, value in (("denied", False), ("reply_bytes", 1), ("terminal", "timeout")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runcase.app_expectation(contract.CASES["blocked-signal"], {**closed, field: value})
        receipt = {"accepts": 1, "request_bytes": len(request), "reply_bytes": len(reply)}
        runcase.target_expectation(contract.CASES["blocked-standby"], NONCE, receipt)
        runcase.target_expectation(contract.CASES["blocked-signal"], NONCE, {"accepts": 0, "request_bytes": 0, "reply_bytes": 0})
        triple = {"accepts": 3, "request_bytes": 3 * len(request), "reply_bytes": 3 * len(reply)}
        runcase.target_expectation(contract.CASES["failover-standby"], NONCE, triple)
        for changed in ({"accepts": 2}, {"request_bytes": len(request)}, {"reply_bytes": 0}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                runcase.target_expectation(contract.CASES["failover-standby"], NONCE, {**triple, **changed})
        for spec, changed in (("blocked-standby", {"accepts": 2}), ("blocked-standby", {"reply_bytes": 0}),
                              ("blocked-signal", {"accepts": 1}), ("blocked-signal", {"request_bytes": 1})):
            base = receipt if spec == "blocked-standby" else {"accepts": 0, "request_bytes": 0, "reply_bytes": 0}
            with self.subTest(spec=spec, changed=changed), self.assertRaises(ValueError):
                runcase.target_expectation(contract.CASES[spec], NONCE, {**base, **changed})

    def test_event_wait_fails_when_a_guarded_product_exits_before_the_event(self):
        run = object.__new__(runcase.Run)
        run.sup = mock.Mock()
        guard = types.SimpleNamespace(exited=True, name="server", returncode=1)
        child = types.SimpleNamespace(events=[], exited=False, open_streams=1)
        with self.assertRaisesRegex(RuntimeError, "exited unexpectedly: server rc=1"):
            run.await_event(child, "SHAAR_NAT_RESULT", time.monotonic() + 1, watch=(guard,))
        run.sup.step.assert_not_called()
        live = types.SimpleNamespace(exited=False, name="server", returncode=None)
        queued = types.SimpleNamespace(events=[("SHAAR_NAT_RESULT", {})], exited=False, open_streams=1)
        run.sup.event.return_value = {"ok": 1}
        self.assertEqual(run.await_event(queued, "SHAAR_NAT_RESULT", time.monotonic() + 1, watch=(live,)), {"ok": 1})
        steps = []
        waiting = types.SimpleNamespace(events=[], exited=False, open_streams=1)
        run.sup.step.side_effect = lambda deadline: (steps.append(deadline), waiting.events.append(("SHAAR_NAT_RESULT", {})))
        run.await_event(waiting, "SHAAR_NAT_RESULT", time.monotonic() + 1)
        self.assertEqual(len(steps), 1)

    def test_deadlines_never_exceed_the_supervisor_budget(self):
        run = object.__new__(runcase.Run)
        run.hard = time.monotonic() + 5
        self.assertLessEqual(run.limit(1000), run.hard)
        self.assertLess(run.limit(1), run.hard)


class ControllerTests(unittest.TestCase):
    def children(self, *items):
        return types.SimpleNamespace(children=[types.SimpleNamespace(name=n, returncode=r, signals=s) for n, r, s in items])

    def test_child_report_requires_graceful_exits_and_never_converts_failures_to_passes(self):
        spec = contract.CASES["blocked-signal"]
        ok = self.children(("wan", 0, []), ("client", 1, []), ("server", 0, []))
        entries, errors = controller.child_report(ok, spec, True)
        self.assertEqual((len(entries), errors), (3, []))
        self.assertTrue(all(item["error"] is None for item in entries))
        second = contract.CASES["denied-blocked-standby"]
        fine = self.children(("client", 0, []), ("client2", 1, []), ("app2", 0, []), ("server", 0, []))
        self.assertEqual(controller.child_report(fine, second, True)[1], [])
        for name, code in (("client", 1), ("client2", 0)):
            changed = self.children(("client", 0, []), ("client2", 1, []))
            changed.children[0 if name == "client" else 1].returncode = code
            self.assertEqual(len(controller.child_report(changed, second, True)[1]), 1, name)
        for bad in (("client", 0, []), ("server", 1, []), ("wan", 0, ["TERM"]), ("wan", -15, ["TERM"])):
            changed = self.children(("client", 1, []), bad)
            _, errors = controller.child_report(changed, spec, True)
            self.assertEqual(len(errors), 1, bad)
        _, errors = controller.child_report(self.children(("server", -15, ["TERM"])), spec, False)
        self.assertEqual(errors, [])

    def test_child_report_expects_the_typed_server_failure_and_the_recovery_client_pair(self):
        spec = contract.CASES["relay-full-signal"]
        ok = self.children(("wan", 0, []), ("filler1", 0, []), ("filler2", 0, []), ("server", 1, []))
        self.assertEqual(controller.child_report(ok, spec, True)[1], [])
        self.assertEqual(len(controller.child_report(self.children(("server", 0, [])), spec, True)[1]), 1)
        self.assertEqual(len(controller.child_report(self.children(("filler1", 1, [])), spec, True)[1]), 1)
        recover = contract.CASES["recover-standby"]
        fine = self.children(("client", 1, []), ("client2", 0, []), ("server", 0, []))
        self.assertEqual(controller.child_report(fine, recover, True)[1], [])
        swapped = self.children(("client", 0, []), ("client2", 1, []))
        self.assertEqual(len(controller.child_report(swapped, recover, True)[1]), 2)

    def test_fault_and_hold_hooks_are_inert_unless_requested(self):
        controller.make_hook(False, False)()
        with self.assertRaisesRegex(RuntimeError, "injected fixture failure"):
            controller.make_hook(True, False)()

    @unittest.skipUnless(sys.platform == "linux", "Linux tool and ownership model")
    def test_tool_and_product_provenance_fail_closed(self):
        with mock.patch.object(controller.preflight, "trusted_tool", lambda name: None if name == "nft" else Path("/usr/bin/" + name)):
            with self.assertRaisesRegex(ValueError, "nft"):
                controller.find_tools()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "product"
            binary.write_bytes(b"binary")
            binary.chmod(0o755)
            digest = contract.file_digest(binary)
            products = {name: {"executable": str(binary), "sha256": digest, "bytes": 6, "profile_test": False,
                               "source_path": "/repo/crates/" + name + "/src/main.rs"} for name in ("shaar-server", "shaar-client")}
            products["identity-helper"] = {"executable": str(binary), "sha256": digest, "bytes": 6}
            manifest = {"source_revision": "a" * 40, "normal_native_gate_enabled": False, "products": products}
            self.assertEqual(set(controller.verify_products(manifest, "a" * 40)), set(products))
            for mutation in ("digest", "size", "missing", "gate"):
                changed = copy.deepcopy(manifest)
                if mutation == "digest":
                    changed["products"]["shaar-server"]["sha256"] = "0" * 64
                elif mutation == "size":
                    changed["products"]["shaar-client"]["bytes"] = 7
                elif mutation == "missing":
                    changed["products"]["identity-helper"]["executable"] = str(root / "absent")
                else:
                    changed["normal_native_gate_enabled"] = True
                with self.subTest(mutation=mutation), self.assertRaises((ValueError, OSError)):
                    controller.verify_products(changed, "a" * 40)

    @unittest.skipUnless(sys.platform == "linux", "directory ownership uses POSIX chown")
    def test_case_directories_are_private_and_logs_stay_outside_helper_control(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = controller.prepare(root, os.getuid(), os.getgid())
            self.assertEqual(logs, root / "logs")
            self.assertEqual(oct((root / "work").stat().st_mode & 0o777), "0o700")
            self.assertEqual(oct((root / "work/keys").stat().st_mode & 0o777), "0o700")
            with self.assertRaises(FileExistsError):
                controller.prepare(root, os.getuid(), os.getgid())

    def test_interruption_handler_exits_with_the_sigterm_status(self):
        with self.assertRaises(SystemExit) as caught:
            controller.interrupted(15, None)
        self.assertEqual(caught.exception.code, 143)


if __name__ == "__main__":
    unittest.main()
