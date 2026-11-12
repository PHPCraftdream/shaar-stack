"""Live NAT-mapping calibration: one fixed source port sends to several destinations; counters show whether the port is preserved."""

import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "runtime"))
import contract  # noqa: E402
import kernel  # noqa: E402

SOURCE_PORT = 40100
DEST_PORTS = (9001, 9002, 9003)
COUNTERS = ("kept", "moved")
# Same statements as the product rules (network.NAT_FLAVORS) so the probe exercises the exact NAT flavor.
STATEMENTS = {"cone": "masquerade", "random": "masquerade fully-random"}
SENDER = ("import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((%r, %d)); "
          "[s.sendto(bytes(8), (%r, p)) for p in %r]")


def table_name(prefix):
    contract.require(type(prefix) is str and re.fullmatch(r"sn[0-9a-f]{6}", prefix) is not None, "invalid owned network prefix")
    return prefix + "_nprobe"


def rules(prefix, flavor, host_ip, wan_ip):
    """Throwaway table: NAT the fixed-port host flow, then count translated packets whose source port is kept or changed."""
    contract.require(flavor in STATEMENTS, "unreviewed NAT flavor")
    table = table_name(prefix)
    low, high = DEST_PORTS[0], DEST_PORTS[-1]
    watched = f"ip saddr {wan_ip} ip daddr {contract.IPS['wan']} udp dport {low}-{high}"
    return "\n".join([
        f"add table inet {table}", f"add counter inet {table} kept", f"add counter inet {table} moved",
        f"add chain inet {table} pnat {{ type nat hook postrouting priority 100; policy accept; }}",
        f"add rule inet {table} pnat ip saddr {host_ip} ip protocol udp udp sport {SOURCE_PORT} {STATEMENTS[flavor]}",
        f"add chain inet {table} pseen {{ type filter hook postrouting priority 200; policy accept; }}",
        f"add rule inet {table} pseen {watched} udp sport {SOURCE_PORT} ct status snat counter name kept",
        f"add rule inet {table} pseen {watched} udp sport != {SOURCE_PORT} ct status snat counter name moved"]) + "\n"


def counts(document, prefix):
    table = table_name(prefix)
    found = {}
    for entry in document.get("nftables", []):
        raw = entry.get("counter")
        if raw is None:
            continue
        contract.require(raw.get("table") == table and raw.get("name") in COUNTERS and raw["name"] not in found
                         and type(raw.get("packets")) is int and raw["packets"] >= 0, "foreign, duplicate or malformed NAT probe counter")
        found[raw["name"]] = raw["packets"]
    contract.require(set(found) == set(COUNTERS), "incomplete NAT probe counter inventory")
    return found


def check(found, flavor):
    """cone: every translated datagram kept the source port; random: none did (3 of 3 changed)."""
    total = len(DEST_PORTS)
    expected = {"kept": total, "moved": 0} if flavor == "cone" else {"kept": 0, "moved": total}
    contract.require(flavor in STATEMENTS and found == expected,
                     f"NAT probe saw {found} for flavor {flavor}, expected {expected}")
    return dict(found)


def calibrate(cfg, tools, router, host, flavor, deadline):
    """Install the probe NAT, send from one fixed port to three destinations, read the counters, always remove the table."""
    table = table_name(cfg["prefix"])
    base = kernel.ns_argv(tools, cfg, router, tools["nft"])
    wan_ip = contract.IPS["rtr_a_wan" if router == "rtr_a" else "rtr_b_wan"]
    host_ip = cfg["ip"][host]
    kernel.checked(base + ["--file", "-"], deadline, rules(cfg["prefix"], flavor, host_ip, wan_ip).encode("ascii"), "NAT probe install")
    try:
        code = SENDER % (host_ip, SOURCE_PORT, contract.IPS["wan"], DEST_PORTS)
        kernel.checked(kernel.ns_argv(tools, cfg, host, tools["python"], "-I", "-c", code), deadline, what="NAT probe sender")
        document = json.loads(kernel.checked(base + ["--json", "list", "table", "inet", table], deadline, what="NAT probe snapshot"))
        found = check(counts(document, cfg["prefix"]), flavor)
    finally:
        kernel.checked(base + ["delete", "table", "inet", table], deadline, what="NAT probe removal")
    return {"router": router, "flavor": flavor, "source_port": SOURCE_PORT, **found}
