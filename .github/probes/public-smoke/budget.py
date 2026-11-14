"""Sudo-free budget metering from /proc and `ss`, plus the byte/connection enforcer.

Counters are netns-wide (/proc/net/dev), so runner background traffic counts against
the caps: the meter can over-count but never under-count the product's traffic.
TCP detail comes only from sockets owned by the product PID (inode match), so the
runner agent and the harness itself are excluded from connection accounting.
"""

import ipaddress
import os
import re
import subprocess

_INODE = re.compile(r"ino:(\d+)")
_ACKED = re.compile(r"bytes_acked:(\d+)")
_RECEIVED = re.compile(r"bytes_received:(\d+)")
_SOCKET_LINK = re.compile(r"^socket:\[(\d+)\]$")


def parse_net_dev(text):
    """Return total (rx_bytes, tx_bytes) over every non-loopback interface."""
    rx = tx = 0
    for line in text.splitlines():
        name, separator, rest = line.partition(":")
        if not separator or name.strip() == "lo":
            continue
        fields = rest.split()
        if len(fields) < 9 or not all(field.isdigit() for field in fields[:9]):
            continue
        rx += int(fields[0])
        tx += int(fields[8])
    return rx, tx


def _split_endpoint(text):
    host, _, port = text.rpartition(":")
    host = host.strip("[]").split("%", 1)[0]
    if not port.isdigit():
        raise ValueError("bad endpoint")
    return ipaddress.ip_address(host), int(port)


def parse_ss(text):
    """Parse `ss -tineH`: {inode: {"state", "remote", "bytes"}}; skips unparsable entries."""
    entries, current = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if current is not None:
                current.append(line)
        else:
            current = [line]
            entries.append(current)
    sockets = {}
    for entry in entries:
        head = entry[0].split()
        joined = " ".join(entry)
        inode = _INODE.search(joined)
        if len(head) < 5 or not inode:
            continue
        try:
            remote = _split_endpoint(head[4])
        except ValueError:
            continue
        acked, received = _ACKED.search(joined), _RECEIVED.search(joined)
        sockets[int(inode[1])] = {"state": head[0], "remote": remote,
                                  "bytes": (int(acked[1]) if acked else 0) + (int(received[1]) if received else 0)}
    return sockets


def owned_inodes(pid, listdir=os.listdir, readlink=os.readlink):
    """Socket inodes open in the given PID (own child; readable without privilege)."""
    found = set()
    base = f"/proc/{int(pid)}/fd"
    try:
        names = listdir(base)
    except OSError:
        return found
    for name in names:
        try:
            match = _SOCKET_LINK.match(readlink(f"{base}/{name}"))
        except OSError:
            continue
        if match:
            found.add(int(match[1]))
    return found


def read_text(path, limit=4 * 1024 * 1024):
    with open(path, "rb") as stream:
        return stream.read(limit).decode("utf-8", "replace")


def run_ss(timeout=5):
    result = subprocess.run(["ss", "-tineH"], capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError("ss failed")
    return result.stdout


def preflight(read=read_text, ss=run_ss):
    """Fail closed when the caps cannot be enforced: counters and ss must both be readable."""
    parse_net_dev(read("/proc/net/dev"))
    parse_ss(ss())


class Meter:
    """Accumulates high-water marks and reports the first violation of each cap."""

    def __init__(self, per_job, allowed, baseline_nic):
        self.per_job = per_job
        self.allowed = allowed  # {"ygg": set of ip, "relay": set of ip}
        self.baseline = baseline_nic
        self.nic = 0
        self.seen = {}  # inode -> {"class", "remote", "bytes", "first"}
        self.violations = []

    def classify(self, ip):
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        for name, addresses in self.allowed.items():
            if ip in addresses:
                return name
        return "loopback" if ip.is_loopback else "unexpected"

    def observe(self, nic_total, sockets, elapsed):
        """One sample: `sockets` maps inode -> parsed entry for product-owned sockets only."""
        self.nic = max(self.nic, nic_total - self.baseline)
        for inode, item in sockets.items():
            kind = self.classify(item["remote"][0])
            if kind == "loopback":
                continue
            old = self.seen.get(inode)
            if old is None:
                old = self.seen[inode] = {"class": kind, "remote": item["remote"], "bytes": 0, "first": elapsed}
            old["bytes"] = max(old["bytes"], item["bytes"])
        return self._check()

    def totals(self):
        count, size = {"ygg": 0, "relay": 0, "unexpected": 0}, {"ygg": 0, "relay": 0, "unexpected": 0}
        for item in self.seen.values():
            count[item["class"]] += 1
            size[item["class"]] += item["bytes"]
        tcp = sum(size.values())
        return {"nic_bytes": self.nic, "ygg_tcp_bytes": size["ygg"], "relay_tcp_bytes": size["relay"],
                "dht_udp_bytes": max(0, self.nic - tcp), "ygg_connections": count["ygg"],
                "relay_connections": count["relay"], "unexpected_connections": count["unexpected"]}

    def _check(self):
        totals = self.totals()
        new = []
        if totals["unexpected_connections"]:
            new.append("unexpected_tcp_peer")
        for name, limit in self.per_job.items():
            if totals[name] > limit:
                new.append(name)
        fresh = [name for name in new if name not in self.violations]
        self.violations.extend(fresh)
        return fresh

    def peers(self):
        return sorted(({"class": item["class"], "remote": f"{item['remote'][0]}:{item['remote'][1]}",
                        "first_seen_s": round(item["first"], 1)} for item in self.seen.values()),
                      key=lambda row: (row["class"], row["remote"]))


def sample(pid, meter, elapsed, read=read_text, ss=run_ss, listdir=os.listdir, readlink=os.readlink):
    """Take one reading for `pid`; returns the new violations."""
    rx, tx = parse_net_dev(read("/proc/net/dev"))
    inodes = owned_inodes(pid, listdir, readlink)
    owned = {inode: item for inode, item in parse_ss(ss()).items() if inode in inodes}
    return meter.observe(rx + tx, owned, elapsed)
