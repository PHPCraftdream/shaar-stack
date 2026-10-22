"""Bounded independent WAN observation; no QUIC decryption or path-ID inference."""
import csv
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def parse_rows(text, public_ips, mapped_ports):
    packets = [[], []]
    rows = []
    for values in csv.reader(io.StringIO(text)):
        if len(values) != 5:
            raise ValueError("WAN capture field count")
        source, sport, destination, dport, encoded = values
        if source not in public_ips:
            raise ValueError("unexpected WAN source")
        side = public_ips.index(source)
        if destination != public_ips[1 - side] or int(sport) != mapped_ports[side]:
            raise ValueError("WAN translation source/destination mismatch")
        if not encoded or len(encoded) > 3 * 65535:
            raise ValueError("empty/oversized UDP payload")
        payload = bytes.fromhex(encoded.replace(":", ""))
        if not payload or len(payload) > 65535 or len(packets[side]) == 256:
            raise ValueError("native capture limit")
        packets[side].append(list(payload))
        rows.append({"side": side, "src": [source, int(sport)],
                     "dst": [destination, int(dport)], "length": len(payload)})
    return packets, rows


def parse_stats(text):
    values = []
    for suffix in (r"packets? captured", r"packets? received by filter", r"packets? dropped by kernel"):
        matches = re.findall(r"(?m)^(\d+) " + suffix + r"$", text)
        if not matches:
            return None
        values.append(int(matches[-1]))
    return tuple(values)


class Capture:
    def __init__(self, cfg, root, child_type):
        self.cfg, self.root = cfg, Path(root)
        self.path = self.root / "native.pcap"
        self.stderr = self.root / "capture.stderr"
        a, b = cfg["ip"]["rtr_a_wan"], cfg["ip"]["rtr_b_wan"]
        expression = f"udp and ((src host {a} and dst host {b}) or (src host {b} and dst host {a}))"
        stderr = self.stderr.open("xb")
        try:
            # Capture both WAN observations; the oracle handles exact duplicate packets.
            # Immediate mode avoids libpcap block-retirement latency on fast cases.
            process = subprocess.Popen(
                ["ip", "netns", "exec", cfg["ns"]["wan"], "tcpdump", "-i", "any",
                 "--immediate-mode", "-n", "-U", "-s", "0", "-c", "1024", "-Z", "root",
                 "-w", str(self.path), expression],
                stdout=subprocess.DEVNULL, stderr=stderr,
                env=os.environ.copy() | {"LC_ALL": "C"})
        except BaseException:
            stderr.close()
            raise
        self.child = child_type("wan-capture", process, stderr,
                                str(self.root / "capture-stop-unused"), str(self.root / "capture-summary.json"))

    def ready(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.child.proc.poll() is not None:
                raise RuntimeError("WAN capture exited before readiness")
            if "listening on any" in self.stderr.read_text(encoding="utf-8", errors="replace"):
                return
            time.sleep(0.05)
        raise TimeoutError("WAN capture readiness deadline")

    def drain(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.child.proc.poll() is not None:
                raise RuntimeError("WAN capture exited during drain")
            offset = self.stderr.stat().st_size
            self.child.proc.send_signal(signal.SIGUSR1)
            stats = None
            while stats is None and time.monotonic() < deadline:
                stats = parse_stats(self.stderr.read_bytes()[offset:].decode("utf-8", errors="replace"))
                if stats is None:
                    time.sleep(0.01)
            if stats is None:
                break
            captured, received, dropped = stats
            if dropped:
                raise RuntimeError("WAN capture dropped packets in kernel")
            if captured == received:
                (self.root / "capture-drain.json").write_text(json.dumps({"captured": captured, "received": received, "dropped": dropped}), encoding="utf-8")
                return
            time.sleep(0.01)
        raise TimeoutError("WAN capture did not drain before stop")

    def finish(self):
        if self.child.proc.poll() is not None:
            raise RuntimeError("WAN capture exited without controlled stop (possibly capacity)")
        self.drain()
        self.child.proc.send_signal(signal.SIGINT)
        if self.child.proc.wait(timeout=10) != 0:
            raise RuntimeError("WAN capture stop failed")
        if self.path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("WAN pcap exceeds evidence size limit")
        stderr_path = self.root / "tshark.stderr"
        with stderr_path.open("xb") as stderr:
            result = subprocess.run(
                ["tshark", "-n", "-r", str(self.path), "-T", "fields", "-E", "separator=,",
                 "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.dst", "-e", "udp.dstport", "-e", "udp.payload"],
                stdout=subprocess.PIPE, stderr=stderr, text=True, timeout=20, check=True)
        (self.root / "native-fields.csv").write_text(result.stdout, encoding="utf-8")
        ips = [self.cfg["ip"]["rtr_a_wan"], self.cfg["ip"]["rtr_b_wan"]]
        packets, rows = parse_rows(result.stdout, ips, self.cfg["translated_ports"])
        (self.root / "native-captures.json").write_text(json.dumps(packets), encoding="utf-8")
        (self.root / "native-tuples.json").write_text(json.dumps(rows), encoding="utf-8")
        return rows
