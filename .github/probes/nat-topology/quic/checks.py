"""CI-only pure capture/tuple rejection controls; never executes namespace commands."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import core  # noqa: E402
import ctparse  # noqa: E402
from capture import Capture, parse_rows, parse_stats  # noqa: E402

IPS = ["203.0.113.1", "203.0.113.2"]
PORTS = [41010, 41020]


def config():
    return {"prefix": "snabc123", "translated_ports": PORTS,
            "ns": {"rtr_a": "snabc123-rtr-a", "rtr_b": "snabc123-rtr-b"},
            "ip": {"host_a": "10.0.1.2", "host_b": "10.0.2.2", "rtr_a_wan": IPS[0], "rtr_b_wan": IPS[1]},
            "port": {"src_a": 40001, "src_b": 40002}}


def entry(side, unreplied=False):
    host, private = [("10.0.1.2", 40001), ("10.0.2.2", 40002)][side]
    own, other = IPS[side], IPS[1 - side]
    marker = " [UNREPLIED]" if unreplied else " [ASSURED]"
    return f"udp 17 29 src={host} dst={other} sport={private} dport={PORTS[1-side]} src={other} dst={own} sport={PORTS[1-side]} dport={PORTS[side]}{marker} mark=0 use=1"


class CaptureChecks(unittest.TestCase):
    def test_capture_drains_before_stop_and_rejects_kernel_loss(self):
        self.assertIsNone(parse_stats("1 packet captured\n"))
        self.assertEqual(parse_stats("tcpdump: 36 packets captured, 36 packets received by filter, 0 packets dropped by kernel\n"), (36, 36, 0))
        self.assertEqual(parse_stats("1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n"), (1, 1, 0))
        for dropped in [0, 1]:
            with tempfile.TemporaryDirectory() as temp:
                capture = Capture.__new__(Capture)
                capture.root = Path(temp)
                capture.stderr = capture.root / "stderr"
                capture.stderr.write_bytes(b"")
                class Process:
                    requests = 0
                    def poll(self): return None
                    def send_signal(self, _signal):
                        self.requests += 1
                        count = 1 if self.requests == 1 else 2
                        with capture.stderr.open("a", encoding="utf-8") as stream:
                            stream.write(f"tcpdump: {count} packets captured, 2 packets received by filter, {dropped} packets dropped by kernel\n")
                class Child:
                    proc = Process()
                capture.child = Child()
                if dropped:
                    with self.assertRaisesRegex(RuntimeError, "dropped packets"):
                        capture.drain()
                else:
                    capture.drain()
                    self.assertEqual(capture.child.proc.requests, 2)
                    self.assertTrue((capture.root / "capture-drain.json").is_file())

    def test_both_directions_exact_bytes_and_ports(self):
        text = f"{IPS[0]},41010,{IPS[1]},41020,10:20\n{IPS[1]},41020,{IPS[0]},41010,3040\n"
        packets, rows = parse_rows(text, IPS, PORTS)
        self.assertEqual(packets, [[[16, 32]], [[48, 64]]])
        self.assertEqual([row["side"] for row in rows], [0, 1])
        self.assertEqual(parse_rows("", IPS, PORTS), ([[], []], []))

    def test_unknown_truncated_empty_or_wrong_translation_is_rejected(self):
        for text in ["too,few", f"192.0.2.1,41010,{IPS[1]},41020,1020",
                     f"{IPS[0]},40001,{IPS[1]},41020,1020", f"{IPS[0]},41010,192.0.2.2,41020,1020",
                     f"{IPS[0]},41010,{IPS[1]},41020,", f"{IPS[0]},41010,{IPS[1]},41020,0",
                     f"{IPS[0]},41010,{IPS[1]},41020,zz"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_rows(text, IPS, PORTS)

    def test_capture_capacity_never_silently_truncates(self):
        row = f"{IPS[0]},41010,{IPS[1]},41020,1020\n"
        self.assertEqual(len(parse_rows(row * 256, IPS, PORTS)[0][0]), 256)
        with self.assertRaises(ValueError):
            parse_rows(row * 257, IPS, PORTS)


class TopologyChecks(unittest.TestCase):
    def test_unsolicited_native_filter_is_router_local_not_a_forwarding_bypass(self):
        cfg = config()
        calls = []
        def observe(_cfg, key, args, _path):
            calls.append((key, args))
            return "[]" if args[0] == "ip" else ""
        with tempfile.TemporaryDirectory() as temp, patch.object(core, "run", side_effect=observe):
            core.configure(cfg, Path(temp), "positive")
        filters = [(key, args) for key, args in calls if args[:3] == ["iptables", "-I", "INPUT"]]
        self.assertEqual(len(filters), 2)
        for side, (key, args) in enumerate(filters):
            self.assertEqual(key, ("rtr_a", "rtr_b")[side])
            self.assertEqual(args[args.index("-d") + 1], IPS[side])
            self.assertEqual(args[args.index("--dport") + 1], PORTS[side])
            self.assertEqual(args[-2:], ["-j", "DROP"])
        self.assertFalse(any("DNAT" in args or "ACCEPT" in args for _, args in calls))

    def test_failure_diagnostics_preserve_read_errors_and_scope(self):
        cfg = config()
        cfg["ns"].update(host_a="snabc123-host-a", host_b="snabc123-host-b")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = core.subprocess.CompletedProcess([], 0, "snapshot", "")
            with patch.object(core.subprocess, "run", return_value=result) as run:
                self.assertEqual(core.failure_snapshot(cfg, root), [])
                self.assertEqual(run.call_count, 6)
                for call in run.call_args_list:
                    self.assertEqual(call.args[0][:3], ["ip", "netns", "exec"])
                    self.assertIn(call.args[0][3], cfg["ns"].values())
                    self.assertEqual(call.kwargs["timeout"], 3)
            with patch.object(core.subprocess, "run", side_effect=core.subprocess.TimeoutExpired("read-only diagnostic", 3)):
                self.assertEqual(len(core.failure_snapshot(cfg, root)), 6)

    def test_namespace_ownership(self):
        cfg = config()
        self.assertEqual(core.command(cfg, "rtr_a", "true"), ["ip", "netns", "exec", "snabc123-rtr-a", "true"])
        cfg["ns"]["rtr_a"] = "another-namespace"
        with self.assertRaises(ValueError):
            core.command(cfg, "rtr_a", "true")

    def test_unprivileged_process_observation_is_not_a_declared_flag(self):
        with patch.object(core.Path, "read_text", return_value="Uid:\t1001\t1001\t1001\t1001\nCapEff:\t00000000\n"):
            self.assertEqual(core.unprivileged(123, 1001), {"uid": 1001, "effective_capabilities": 0})
        for status in ["Uid:\t0\t0\t0\t0\nCapEff:\t0\n", "Uid:\t1001\t1001\t1001\t1001\nCapEff:\t1\n"]:
            with patch.object(core.Path, "read_text", return_value=status), self.assertRaises(ValueError):
                core.unprivileged(123, 1001)

    def test_replied_translation_and_both_observed_sides_are_required(self):
        cfg = config()
        rows = [{"side": 0}, {"side": 1}]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lines = {"rtr_a": [entry(0)], "rtr_b": [entry(1)]}
            self.assertEqual(len(core.snapshot(cfg, root, "positive", ctparse, rows, lines)), 2)
            bad = copy.deepcopy(lines)
            bad["rtr_a"] = [entry(0, unreplied=True)]
            with self.assertRaises(ValueError):
                core.snapshot(cfg, root, "positive", ctparse, rows, bad)
            with self.assertRaises(ValueError):
                core.snapshot(cfg, root, "positive", ctparse, rows[:1], lines)

    def test_negative_controls_need_real_attempts(self):
        cfg = config()
        lines = {"rtr_a": [], "rtr_b": []}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(core, "run", return_value="[1:40] -A FORWARD --comment p03-native-block -j DROP"):
                self.assertEqual(len(core.snapshot(cfg, root, "blocked", ctparse, [], lines)), 2)
            with patch.object(core, "run", return_value="[0:0] -A FORWARD --comment p03-native-block -j DROP"):
                with self.assertRaises(ValueError):
                    core.snapshot(cfg, root, "blocked", ctparse, [], lines)
            with self.assertRaises(ValueError):
                core.snapshot(cfg, root, "wrong-tuple", ctparse, [], lines)
            rows = [{"side": 0, "dst": [IPS[1], 41021]}]
            self.assertEqual(core.snapshot(cfg, root, "wrong-tuple", ctparse, rows, lines), [])


if __name__ == "__main__":
    unittest.main()
