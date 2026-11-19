"""CI-only contracts of the PCP gateway of the mapped-port cases (leaf DIRECT-T): the wire layout the product's codec reads, the
state machine, the nft text and the serve loop with a fake socket and a fake nft. No namespace, kernel or product runs here."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "quic/product/gateway.py"
spec = importlib.util.spec_from_file_location("product_gateway", PATH)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)

CLIENT, WAN, NONCE = "10.0.2.2", "203.0.113.2", bytes([9] * 12)
PREFIX_ARGS = ["--nonce", "a" * 32, "--prefix", "snaabbcc", "--nft", "/usr/sbin/nft", "--listen", "10.0.2.1", "--wan", WAN,
               "--client", CLIENT, "--mode", "grant"]


def request(client=CLIENT, internal=48896, lifetime=7200, protocol=17, nonce=NONCE):
    """A MAP request laid out like the product's `map_request` (crates/shaar pcp.rs)."""
    data = bytearray(60)
    data[0], data[1] = 2, 1
    data[4:8] = lifetime.to_bytes(4, "big")
    data[8:24] = gateway.mapped(client)
    data[24:36] = nonce
    data[36] = protocol
    data[40:42] = internal.to_bytes(2, "big")
    data[42:44] = internal.to_bytes(2, "big")
    return bytes(data)


class CodecTests(unittest.TestCase):
    def test_the_request_layout_is_the_one_the_product_writes(self):
        # The byte vector of `the_request_matches_the_layout_of_the_rfc` in pcp.rs, for the client 192.168.0.20.
        data = request("192.168.0.20")
        self.assertEqual(list(data[:8]), [2, 1, 0, 0, 0, 0, 0x1C, 0x20])
        self.assertEqual(list(data[8:24]), [0] * 10 + [0xFF, 0xFF, 192, 168, 0, 20])
        self.assertEqual(list(data[36:44]), [17, 0, 0, 0, 0xBF, 0x00, 0xBF, 0x00])
        self.assertEqual(gateway.parse(data, "192.168.0.20"), (NONCE, 48896, 7200))

    def test_anything_but_a_udp_map_request_of_the_client_is_not_parsed(self):
        self.assertIsNone(gateway.parse(request()[:59], CLIENT))
        self.assertIsNone(gateway.parse(request() + b"\0", CLIENT))
        self.assertIsNone(gateway.parse(request(client="10.0.2.3"), CLIENT), "another host's request")
        self.assertIsNone(gateway.parse(request(protocol=6), CLIENT))
        self.assertIsNone(gateway.parse(request(internal=1023), CLIENT))
        for index, value in ((0, 1), (1, 2), (1, 0x81)):
            changed = bytearray(request())
            changed[index] = value
            self.assertIsNone(gateway.parse(bytes(changed), CLIENT), (index, value))

    def test_the_answer_is_what_the_product_decodes_as_a_grant_or_a_refusal(self):
        grant = gateway.answer(NONCE, 48896, 48896, gateway.OK, 7200, WAN, 5)
        self.assertEqual(len(grant), 60)
        self.assertEqual((grant[0], grant[1], grant[3]), (2, 0x81, 0))
        self.assertEqual(int.from_bytes(grant[4:8], "big"), 7200)
        self.assertEqual(int.from_bytes(grant[8:12], "big"), 5)
        self.assertEqual((grant[24:36], grant[36], grant[40:42], grant[42:44]), (NONCE, 17, b"\xbf\x00", b"\xbf\x00"))
        self.assertEqual(list(grant[44:60]), [0] * 10 + [0xFF, 0xFF, 203, 0, 113, 2])
        refusal = gateway.answer(NONCE, 48896, 0, gateway.NOT_AUTHORIZED, 0, WAN, 5)
        self.assertEqual((refusal[1], refusal[3], refusal[42:44]), (0x81, 2, b"\0\0"))


class StateTests(unittest.TestCase):
    def machine(self, mode="grant"):
        applied = []
        return gateway.Gateway(mode, WAN, CLIENT, lambda ports: applied.append(set(ports))), applied

    def test_a_grant_installs_the_rule_once_a_renewal_keeps_it_and_a_deletion_removes_it(self):
        machine, applied = self.machine()
        reply = machine.handle(request(), CLIENT)
        self.assertEqual((reply[3], reply[42:44]), (0, b"\xbf\x00"))
        machine.handle(request(), CLIENT)
        reply = machine.handle(request(lifetime=0), CLIENT)
        self.assertEqual((reply[3], int.from_bytes(reply[4:8], "big")), (0, 0))
        self.assertEqual(applied, [{48896}, set()])
        self.assertEqual([item["op"] for item in machine.events], ["map", "renew", "delete"])
        self.assertEqual(machine.ports, set())

    def test_the_lifetime_is_capped_and_requests_of_others_are_ignored(self):
        machine, applied = self.machine()
        reply = machine.handle(request(lifetime=10 ** 6), CLIENT)
        self.assertEqual(int.from_bytes(reply[4:8], "big"), gateway.MAX_LIFETIME)
        self.assertIsNone(machine.handle(request(), "10.0.2.9"))
        self.assertIsNone(machine.handle(b"not pcp", CLIENT))
        self.assertEqual((machine.ignored, applied), (2, [{48896}]))

    def test_a_refusing_gateway_answers_not_authorized_and_installs_nothing(self):
        machine, applied = self.machine("refuse")
        reply = machine.handle(request(), CLIENT)
        self.assertEqual(reply[3], gateway.NOT_AUTHORIZED)
        self.assertEqual((applied, machine.ports, machine.events), ([], set(), [{"op": "refused", "port": 48896, "lifetime": 7200}]))

    def test_the_mapping_table_and_the_event_receipt_are_bounded(self):
        machine, applied = self.machine()
        for index in range(gateway.MAX_MAPPINGS):
            machine.handle(request(internal=40000 + index), CLIENT)
        reply = machine.handle(request(internal=41000), CLIENT)
        self.assertEqual(reply[3], gateway.NO_RESOURCES)
        self.assertEqual(len(machine.ports), gateway.MAX_MAPPINGS)
        self.assertEqual(machine.events[-1]["op"], "refused")
        for _ in range(gateway.MAX_EVENTS):
            machine.handle(request(internal=40000), CLIENT)
        self.assertEqual(len(machine.events), gateway.MAX_EVENTS)
        self.assertGreater(machine.dropped, 0)


class NftTests(unittest.TestCase):
    def test_the_rules_replace_the_whole_chain_in_one_script_and_name_only_the_granted_ports(self):
        text = gateway.dnat_rules("snaabbcc_mapgw", WAN, CLIENT, {40001, 40000})
        self.assertEqual(text.splitlines(), [
            "flush chain inet snaabbcc_mapgw dnat",
            "add rule inet snaabbcc_mapgw dnat ip daddr 203.0.113.2 udp dport 40000 counter name hits dnat ip to 10.0.2.2:40000",
            "add rule inet snaabbcc_mapgw dnat ip daddr 203.0.113.2 udp dport 40001 counter name hits dnat ip to 10.0.2.2:40001"])
        self.assertEqual(gateway.dnat_rules("t", WAN, CLIENT, set()), "flush chain inet t dnat\n")
        setup = gateway.setup_rules("snaabbcc_mapgw")
        self.assertIn("add counter inet snaabbcc_mapgw hits\n", setup)
        self.assertIn("add chain inet snaabbcc_mapgw dnat { type nat hook prerouting priority -100; policy accept; }\n", setup)

    def test_hits_are_read_from_the_named_counter_and_a_failed_tool_is_an_error(self):
        document = {"nftables": [{"metainfo": {}}, {"counter": {"family": "inet", "name": "hits", "table": "t", "packets": 3, "bytes": 300}}]}
        with mock.patch.object(gateway, "run_nft", return_value=json.dumps(document)) as tool:
            self.assertEqual(gateway.read_hits("/usr/sbin/nft", "t"), {"packets": 3, "bytes": 300})
        self.assertEqual(tool.call_args.args[1], ["--json", "list", "counter", "inet", "t", "hits"])
        with mock.patch.object(gateway, "run_nft", return_value=json.dumps({"nftables": []})), self.assertRaises(RuntimeError):
            gateway.read_hits("/usr/sbin/nft", "t")
        failed = mock.Mock(returncode=1, stderr="boom", stdout="")
        with mock.patch.object(gateway.subprocess, "run", return_value=failed), self.assertRaises(RuntimeError):
            gateway.run_nft("/usr/sbin/nft", ["list", "ruleset"])


class ServeTests(unittest.TestCase):
    def test_arguments_are_validated_before_anything_is_bound(self):
        self.assertEqual(gateway.parse_args(PREFIX_ARGS).mode, "grant")
        for name, value in (("--nonce", "xyz"), ("--prefix", "other"), ("--nft", "nft"), ("--wan", "not-an-ip"), ("--client", "10.0.2.256")):
            changed = list(PREFIX_ARGS)
            changed[changed.index(name) + 1] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                gateway.parse_args(changed)
        changed = list(PREFIX_ARGS)
        changed[-1] = "open"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            gateway.parse_args(changed)

    def test_the_serve_loop_answers_reports_ready_and_result_and_removes_its_table(self):
        sockets, calls = [], []

        class FakeSocket:
            def __init__(self, *args):
                self.sent, self.bound = [], None
                self.queue = [(request(), (CLIENT, 5000)), (request(lifetime=0), (CLIENT, 5000))]
                sockets.append(self)

            def bind(self, address):
                self.bound = address

            def recvfrom(self, size):
                if self.queue:
                    return self.queue.pop(0)
                raise gateway.Stop()

            def sendto(self, data, address):
                self.sent.append((data, address))

        def fake_nft(binary, args, text=None):
            calls.append((args, text))
            if args[:2] == ["--json", "list"]:
                return json.dumps({"nftables": [{"counter": {"name": "hits", "packets": 4, "bytes": 400}}]})
            return ""

        out = io.StringIO()
        with (mock.patch.object(gateway.socket, "socket", FakeSocket), mock.patch.object(gateway, "run_nft", fake_nft),
              mock.patch.object(gateway.signal, "signal"), contextlib.redirect_stdout(out)):
            self.assertEqual(gateway.serve(gateway.parse_args(PREFIX_ARGS)), 0)
        self.assertEqual(sockets[0].bound, ("10.0.2.1", gateway.PCP_PORT))
        self.assertEqual([address for _, address in sockets[0].sent], [(CLIENT, 5000)] * 2)
        lines = out.getvalue().splitlines()
        self.assertEqual([line.split(" ", 1)[0] for line in lines], ["SHAAR_NAT_READY", "SHAAR_NAT_RESULT"])
        ready, result = (json.loads(line.split(" ", 1)[1]) for line in lines)
        self.assertEqual((ready["role"], ready["nonce"], ready["mode"]), ("gateway", "a" * 32, "grant"))
        self.assertEqual([item["op"] for item in result["events"]], ["map", "delete"])
        self.assertEqual((result["active"], result["hits"], result["dropped"]), ([], {"packets": 4, "bytes": 400}, 0))
        self.assertIn("add table inet snaabbcc_mapgw", calls[0][1])
        self.assertIn("udp dport 48896", calls[1][1])
        self.assertEqual(calls[2][1], "flush chain inet snaabbcc_mapgw dnat\n")
        self.assertEqual(calls[-1][0], ["delete", "table", "inet", "snaabbcc_mapgw"])


if __name__ == "__main__":
    unittest.main()
