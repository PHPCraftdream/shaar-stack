"""Pure CI-run tests: /proc and ss parsing, budget enforcement, target fixture, process ownership."""

import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import sys
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("smoke_run_for_budget_tests", HERE / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
CONTRACT, KEYS, BUDGET = RUN.CONTRACT, RUN.KEYS, RUN.BUDGET

NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 5000 50 0 0 0 0 0 0 7000 40 0 0 0 0 0 0
  eth1: 1 1 0 0 0 0 0 0 2 1 0 0 0 0 0 0
"""
SS = """ESTAB 0      0         10.1.0.4:43210  203.0.113.9:8883  ino:123456 sk:1 cgroup:/x <->
\t cubic wscale:7,7 rto:204 bytes_sent:100 bytes_acked:101 bytes_received:500 segs_out:5
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* ino:99 sk:2 <->
ESTAB 0 0 [::ffff:10.1.0.4]:5 [::ffff:198.51.100.7]:4001 ino:77 sk:3 <->
\t bytes_acked:10 bytes_received:20
ESTAB 0 0 127.0.0.1:5 127.0.0.1:6 ino:55 sk:4 <->
\t bytes_acked:9000 bytes_received:9000
garbage line without fields
"""
YGG, RELAY = ipaddress.ip_address("203.0.113.9"), ipaddress.ip_address("198.51.100.7")
LIMITS = {"nic_bytes": 1000, "ygg_tcp_bytes": 700, "relay_tcp_bytes": 100, "dht_udp_bytes": 500,
          "ygg_connections": 2, "relay_connections": 2}


def entry(ip, port, size, state="ESTAB"):
    return {"state": state, "remote": (ipaddress.ip_address(ip), port), "bytes": size}


def meter(baseline=0):
    return BUDGET.Meter(dict(LIMITS), {"ygg": {YGG}, "relay": {RELAY}}, baseline)


class ParsingTests(unittest.TestCase):
    def test_net_dev_sums_every_non_loopback_interface(self):
        self.assertEqual(BUDGET.parse_net_dev(NET_DEV), (5001, 7002))
        self.assertEqual(BUDGET.parse_net_dev(""), (0, 0))
        self.assertEqual(BUDGET.parse_net_dev("eth0: x y z"), (0, 0))

    def test_ss_entries_are_keyed_by_inode(self):
        parsed = BUDGET.parse_ss(SS)
        self.assertEqual(set(parsed), {123456, 77, 55})
        self.assertEqual(parsed[123456]["bytes"], 601)
        self.assertEqual(str(parsed[123456]["remote"][0]), "203.0.113.9")
        self.assertEqual(parsed[123456]["remote"][1], 8883)
        self.assertEqual(parsed[77]["bytes"], 30)

    def test_owned_inodes_ignore_non_socket_links_and_errors(self):
        links = {"3": "socket:[10]", "4": "/dev/null", "5": "socket:[11]", "6": "anon_inode:[eventpoll]"}

        def readlink(path):
            name = path.rsplit("/", 1)[1]
            if name == "7":
                raise OSError("gone")
            return links[name]

        found = BUDGET.owned_inodes(42, listdir=lambda base: ["3", "4", "5", "6", "7"], readlink=readlink)
        self.assertEqual(found, {10, 11})
        self.assertEqual(BUDGET.owned_inodes(42, listdir=mock.Mock(side_effect=OSError)), set())

    def test_preflight_fails_closed_when_counters_or_ss_are_unavailable(self):
        BUDGET.preflight(read=lambda path: NET_DEV, ss=lambda: SS)
        with self.assertRaises(OSError):
            BUDGET.preflight(read=mock.Mock(side_effect=OSError), ss=lambda: SS)
        with self.assertRaises(RuntimeError):
            BUDGET.preflight(read=lambda path: NET_DEV, ss=mock.Mock(side_effect=RuntimeError))


class MeterTests(unittest.TestCase):
    def test_within_limits_reports_nothing_and_loopback_is_ignored(self):
        m = meter(baseline=100)
        fresh = m.observe(100 + 300, {1: entry("203.0.113.9", 8883, 200), 2: entry("198.51.100.7", 4001, 50),
                                      3: entry("127.0.0.1", 9, 10 ** 9)}, 1.0)
        self.assertEqual(fresh, [])
        totals = m.totals()
        self.assertEqual((totals["nic_bytes"], totals["ygg_tcp_bytes"], totals["relay_tcp_bytes"]), (300, 200, 50))
        self.assertEqual(totals["dht_udp_bytes"], 50)
        self.assertEqual((totals["ygg_connections"], totals["relay_connections"]), (1, 1))

    def test_each_cap_trips_once(self):
        cases = {
            "nic_bytes": (1001, {}),
            "ygg_tcp_bytes": (800, {1: entry("203.0.113.9", 1, 701)}),
            "relay_tcp_bytes": (700, {1: entry("198.51.100.7", 1, 101)}),
            "dht_udp_bytes": (600, {}),
            "ygg_connections": (10, {i: entry("203.0.113.9", 1, 1) for i in (1, 2, 3)}),
            "relay_connections": (10, {i: entry("198.51.100.7", 1, 1) for i in (1, 2, 3)}),
        }
        for name, (nic, sockets) in cases.items():
            m = meter()
            with self.subTest(name):
                self.assertIn(name, m.observe(nic, sockets, 1.0))
                self.assertEqual(m.observe(nic, sockets, 2.0), [])
                self.assertEqual(m.violations.count(name), 1)

    def test_unexpected_tcp_peer_is_a_violation(self):
        m = meter()
        self.assertEqual(m.observe(10, {1: entry("93.184.216.34", 443, 1)}, 0.5), ["unexpected_tcp_peer"])
        self.assertEqual(m.totals()["unexpected_connections"], 1)

    def test_ipv4_mapped_addresses_classify_as_their_ipv4(self):
        m = meter()
        self.assertEqual(m.classify(ipaddress.ip_address("::ffff:203.0.113.9")), "ygg")
        self.assertEqual(m.classify(ipaddress.ip_address("::ffff:127.0.0.1")), "loopback")
        self.assertEqual(m.classify(ipaddress.ip_address("2001:db8::1")), "unexpected")

    def test_high_water_survives_a_closed_socket_and_reuse_of_one_inode_counts_once(self):
        m = meter()
        m.observe(10, {1: entry("203.0.113.9", 1, 400)}, 1.0)
        m.observe(20, {}, 2.0)
        m.observe(30, {1: entry("203.0.113.9", 1, 300)}, 3.0)
        self.assertEqual(m.totals()["ygg_tcp_bytes"], 400)
        self.assertEqual(m.totals()["ygg_connections"], 1)

    def test_sample_uses_only_product_owned_sockets(self):
        m = meter(baseline=12000)
        reading = BUDGET.sample(7, m, 1.0, read=lambda path: NET_DEV, ss=lambda: SS,
                                listdir=lambda base: ["3"], readlink=lambda path: "socket:[123456]")
        self.assertEqual(reading, [])
        self.assertEqual(m.totals()["ygg_connections"], 1)
        self.assertEqual(m.totals()["relay_connections"], 0)
        self.assertEqual(m.peers(), [{"class": "ygg", "remote": "203.0.113.9:8883", "first_seen_s": 1.0}])


class NetworkHelperTests(unittest.TestCase):
    def test_interface_addresses_and_native_block_precondition(self):
        text = ("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 10.1.0.4/16 brd 10.1.255.255 scope global eth0\n"
                "2: eth0    inet6 fe80::6245:bdff:fe12:3456/64 scope link\n")
        found = RUN.interface_addresses(text)
        self.assertEqual(found, ["127.0.0.1", "10.1.0.4", "fe80::6245:bdff:fe12:3456"])
        self.assertEqual(RUN.require_native_unreachable(found), sorted(found))
        for bad in ("8.8.8.8", "2606:4700::1111"):
            with self.assertRaises(RUN.Abort):
                RUN.require_native_unreachable(found + [bad])

    def test_local_addresses_fail_closed_when_ip_fails(self):
        failed = mock.Mock(return_value=mock.Mock(returncode=1, stdout=""))
        with self.assertRaises(RUN.Abort):
            RUN.local_addresses(run=failed)

    def test_listening_checks_state_without_connecting(self):
        table = ("  sl  local_address rem_address   st tx_queue rx_queue\n"
                 "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000\n"
                 "   1: 0100007F:1F91 0100007F:1F90 01 00000000:00000000\n")
        self.assertTrue(RUN.listening(8080, read=lambda path: table))
        self.assertFalse(RUN.listening(8081, read=lambda path: table))
        self.assertFalse(RUN.listening(9999, read=lambda path: table))

    def test_resolution_requires_public_addresses(self):
        contract, _ = CONTRACT.load_contract()
        contract = copy.deepcopy(contract)
        contract["targets"]["libp2p_relay"] = {"peer_id": "12D3KooWRhxsqdyvN1Cy4HDzPjKtdscPa9XUyqoqJwHSsGY8LQTQ",
                                               "address": "8.8.4.4:4001", "operator": "o", "basis": "b"}

        def resolver(ip):
            return lambda host, port, family, kind: [(family, kind, 6, "", (ip, port))]

        result = RUN.resolve_targets(contract, resolver("8.8.8.8"))
        self.assertEqual([row["used"] for row in result["bootstrap"]], ["8.8.8.8:25401", "8.8.8.8:6881"])
        self.assertEqual(result["ygg_allowed"], {ipaddress.ip_address("8.8.8.8")})
        self.assertEqual(result["relay_allowed"], {ipaddress.ip_address("8.8.4.4")})
        for private in ("10.0.0.1", "127.0.0.1", "169.254.0.1"):
            with self.subTest(private), self.assertRaises(RUN.Abort):
                RUN.resolve_targets(contract, resolver(private))
        with self.assertRaises(RUN.Abort):
            RUN.resolve_targets(contract, lambda *args: [])


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.nonce = KEYS.derive_nonce("1", "1")
        self.target = RUN.Target(self.nonce, 128, 128)
        self.target.start()
        self.addCleanup(self.target.close)

    def talk(self, payload):
        with socket.create_connection(self.target.address, timeout=5) as connection:
            try:
                connection.sendall(payload)
                connection.settimeout(5)
                return connection.recv(256)
            except OSError:
                return b""

    def test_exactly_one_valid_exchange(self):
        reply = self.talk(CONTRACT.app_request(self.nonce))
        self.assertEqual(reply, CONTRACT.app_reply(self.nonce))
        self.assertTrue(self.target.done.wait(5))
        self.assertEqual((self.target.accepts, self.target.request_ok, self.target.errors), (1, True, []))
        self.assertEqual(self.talk(CONTRACT.app_request(self.nonce)), b"")
        deadline = time.monotonic() + 5
        while self.target.accepts < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.target.errors, ["extra target connection"])

    def test_wrong_request_is_not_answered(self):
        self.assertEqual(self.talk(b"shaar-public-smoke/v1 req ffffffffffffffff\n"), b"")
        self.assertTrue(self.target.done.wait(5))
        self.assertFalse(self.target.request_ok)
        self.assertEqual(self.target.errors, ["unexpected request bytes"])

    def test_byte_budget_is_enforced_at_construction(self):
        with self.assertRaises(RUN.Abort):
            RUN.Target(self.nonce, 10, 128)
        with self.assertRaises(RUN.Abort):
            RUN.Target(self.nonce, 128, 10)

    def serve_once(self, reply, hold=0.0):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)

        def run():
            connection, _ = listener.accept()
            with connection:
                connection.recv(256)
                time.sleep(hold)
                if reply:
                    connection.sendall(reply)

        threading.Thread(target=run, daemon=True).start()
        return listener.getsockname()[1]

    def test_client_exchange_checks_the_reply_once(self):
        port = self.serve_once(CONTRACT.app_reply(self.nonce))
        result = RUN.exchange(port, self.nonce, 5, 128)
        self.assertTrue(result["match"])
        self.assertEqual(result["reply_bytes"], len(CONTRACT.app_reply(self.nonce)))
        port = self.serve_once(b"wrong\n")
        self.assertFalse(RUN.exchange(port, self.nonce, 5, 128)["match"])
        port = self.serve_once(b"")
        self.assertEqual(RUN.exchange(port, self.nonce, 5, 128)["reply_bytes"], 0)

    def test_client_exchange_deadline_and_refusal(self):
        port = self.serve_once(b"late\n", hold=3)
        with self.assertRaises(OSError):
            RUN.exchange(port, self.nonce, 0.3, 128)
        closed = RUN.free_port()
        with self.assertRaises(OSError):
            RUN.exchange(closed, self.nonce, 1, 128)


@unittest.skipUnless(os.name == "posix", "owned child processes use POSIX signals")
class ProductTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.directory, ignore_errors=True))
        self.addCleanup(signal.signal, signal.SIGINT, signal.default_int_handler)

    def script(self, body):
        path = self.directory / "fake-product"
        path.write_text(f"#!{sys.executable}\nimport signal, sys, time\n{body}\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def start(self, body, sample):
        exe = self.script(body)
        patcher = mock.patch.object(BUDGET, "sample", sample)
        patcher.start()
        self.addCleanup(patcher.stop)
        product = RUN.Product(str(exe), self.directory / "cfg", self.directory, meter(), 0.05)
        time.sleep(0.4)
        return product

    def test_sigint_stops_the_owned_child_normally(self):
        product = self.start("signal.signal(signal.SIGINT, lambda *a: sys.exit(0))\nprint('up', flush=True)\ntime.sleep(60)",
                             lambda *args: [])
        self.assertTrue(product.alive())
        self.assertEqual(product.stop(5), 0)
        self.assertEqual((self.directory / "product.stdout.log").read_text(), "up\n")

    def test_a_child_that_ignores_sigint_is_killed_by_pid_after_the_grace(self):
        product = self.start("signal.signal(signal.SIGINT, signal.SIG_IGN)\ntime.sleep(60)", lambda *args: [])
        started = time.monotonic()
        self.assertEqual(product.stop(0.5), -signal.SIGKILL)
        self.assertLess(time.monotonic() - started, 10)

    def test_a_budget_violation_kills_the_product(self):
        product = self.start("time.sleep(60)", lambda *args: ["nic_bytes"])
        self.assertTrue(product.violated.wait(5))
        self.assertEqual(product.stop(1), -signal.SIGKILL)
        self.assertFalse(product.alive())

    def test_a_meter_failure_is_fail_closed(self):
        product = self.start("time.sleep(60)", mock.Mock(side_effect=RuntimeError("ss failed")))
        self.assertTrue(product.violated.wait(5))
        self.assertEqual(product.failure, "meter failure: RuntimeError")
        product.stop(1)

    def test_wait_until_stops_early_on_dead_product_or_condition(self):
        ticks = iter(range(1000))
        alive = mock.Mock(alive=mock.Mock(return_value=True), violated=threading.Event())
        slept = []
        RUN.wait_until(10, alive, clock=lambda: next(ticks), sleep=slept.append, extra=lambda: len(slept) == 3)
        self.assertEqual(len(slept), 3)
        dead = mock.Mock(alive=mock.Mock(return_value=False), violated=threading.Event())
        slept.clear()
        RUN.wait_until(10 ** 9, dead, clock=lambda: 0, sleep=slept.append)
        self.assertEqual(slept, [])
        alive.violated.set()
        RUN.wait_until(10 ** 9, alive, clock=lambda: 0, sleep=slept.append)
        self.assertEqual(slept, [])


class EvidenceTests(unittest.TestCase):
    def test_binary_must_match_the_gate_off_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory, "shaar-server")
            binary.write_bytes(b"binary")
            digest = hashlib.sha256(b"binary").hexdigest()
            manifest = {"source_revision": "a" * 40, "normal_native_gate_enabled": False,
                        "products": {"shaar-server": {"sha256": digest}}}
            self.assertEqual(RUN.verify_binary(binary, manifest, "shaar-server", "a" * 40), digest)
            for changed in ({**manifest, "source_revision": "b" * 40}, {**manifest, "normal_native_gate_enabled": True},
                            {**manifest, "products": {"shaar-server": {"sha256": "0" * 64}}},
                            {**manifest, "products": {}}):
                with self.assertRaises(RUN.Abort):
                    RUN.verify_binary(binary, changed, "shaar-server", "a" * 40)

    def test_evidence_never_carries_key_material(self):
        seed = KEYS.derive_seed("1", "1", "server")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RUN.Abort):
                RUN.write_evidence(directory, {"leak": seed.hex()}, [seed])
            RUN.write_evidence(directory, {"public_key": KEYS.public_key(seed).hex()}, [seed])
            self.assertTrue(Path(directory, "evidence.json").is_file())
            log = Path(directory, "log")
            log.write_bytes(b"ok " + seed)
            self.assertEqual(RUN.sanitized_tail(log, [seed]), "[redacted: key material pattern]")
            log.write_text("fine", encoding="utf-8")
            self.assertEqual(RUN.sanitized_tail(log, [seed]), "fine")

    def test_finish_writes_a_failing_verdict_for_violations_and_nonzero_exit(self):
        seed = KEYS.derive_seed("1", "1", "client")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory, "client-work")
            work.mkdir()
            (work / "product.stderr.log").write_text("shaar-client: x\n", encoding="utf-8")
            m = meter()
            m.observe(5000, {}, 1.0)
            evidence = {"failures": []}
            code = RUN.finish("client", {"workdir": work}, evidence, None, m, -9, [seed])
            self.assertEqual(code, 1)
            written = json.loads(Path(directory, "client-evidence", "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(written["status"], "fail")
            self.assertIn("budget violation: nic_bytes", written["failures"])
            clean = {"failures": []}
            self.assertEqual(RUN.finish("client", {"workdir": work}, clean, None, meter(), 0, [seed]), 0)

    def test_committed_contract_blocks_the_entrypoint_until_approved(self):
        contract, digest = CONTRACT.load_contract()
        request = {"GITHUB_EVENT_NAME": "workflow_dispatch", "SOURCE_REVISION": "a" * 40, "GITHUB_RUN_ATTEMPT": "1",
                   "GITHUB_RUN_ID": "1", "DIRECT_FEEDBACK": "false", "PREFLIGHT": "false", "MATRIX": "false",
                   "PUBLIC_SMOKE": "true", "CONTRACT_SHA256": digest}
        if CONTRACT.blockers(contract):
            with self.assertRaises(CONTRACT.Blocked):
                RUN.run_validate(env=request)

    def test_main_refuses_missing_arguments_and_bad_environment(self):
        self.assertEqual(RUN.main(["server"]), 2)
        self.assertEqual(RUN.main(["client", "--manifest", "m", "--bin", "b", "--workdir", "w", "--t0", "x1"]), 2)
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "push"}, clear=True):
            self.assertEqual(RUN.main(["validate"]), 2)


if __name__ == "__main__":
    unittest.main()
