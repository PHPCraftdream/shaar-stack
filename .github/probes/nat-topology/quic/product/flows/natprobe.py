"""Live NAT-mapping calibration: one fixed source port sends to several destinations; counters show whether the port is preserved."""

import json
from pathlib import Path
import re
import subprocess
import sys
import time

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
# Exactly this many datagrams per side, 0.1 s apart (each side only listens between sends): a bounded control, not a load loop.
PUNCH_SENDS = 20
PUNCH = ("import json, socket\n"
         "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((%r, %d)); s.settimeout(0.1)\n"
         "sent, received, first = 0, 0, None\n"
         "for _ in range(%d):\n"
         "    s.sendto(b'punch', (%r, %d)); sent += 1\n"
         "    try:\n"
         "        while True:\n"
         "            data, address = s.recvfrom(64)\n"
         "            received += 1\n"
         "            first = first or list(address)\n"
         "    except socket.timeout:\n"
         "        pass\n"
         "print(json.dumps({'sent': sent, 'received': received, 'first': first}))\n")
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
        # Unsolicited inbound UDP to the router itself is dropped before conntrack confirms it (like a real NAT): otherwise it would create
        # an entry that takes the peer's preserved source port and breaks the hole punch control.
        f"add chain inet {table} punchin {{ type filter hook input priority 0; policy accept; }}",
        f"add rule inet {table} punchin ip daddr {wan_ip} udp dport {SOURCE_PORT} drop",
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


def check_punch(found):
    """Both plain sockets received datagrams whose source is the other router's WAN address with the preserved port."""
    expected = {"host_a": contract.IPS["rtr_b_wan"], "host_b": contract.IPS["rtr_a_wan"]}
    contract.require(len(found) == 2 and {item.get("host") for item in found} == set(expected), "punch control receipts incomplete")
    for item in found:
        contract.require(item["sent"] == PUNCH_SENDS and 0 < item["received"] <= PUNCH_SENDS and item["first"] == [expected[item["host"]], SOURCE_PORT],
                         f"punch control: {item['host']} did not receive from the peer's public endpoint: {item}")
    return found


def punch(cfg, tools, deadline):
    """Fixture control for the cone NATs: the harness knows both public endpoints, so two plain UDP sockets can punch through.

    It shows whether the topology and counters allow a punched path; the products have no source for these endpoints.
    Dispatch 43258223283 punched 4 of 4 times (with an unbounded loop), dispatch 43262313789 2 of 4 with the bounded one: the
    cause of the misses is not established, so the outcome is recorded per case and never decides a product verdict."""
    pairs = (("host_a", "rtr_a", contract.IPS["rtr_b_wan"]), ("host_b", "rtr_b", contract.IPS["rtr_a_wan"]))
    table, installed, processes, found = table_name(cfg["prefix"]), [], [], []
    try:
        for host, router, _ in pairs:
            wan_ip = contract.IPS["rtr_a_wan" if router == "rtr_a" else "rtr_b_wan"]
            kernel.checked(kernel.ns_argv(tools, cfg, router, tools["nft"]) + ["--file", "-"], deadline,
                           rules(cfg["prefix"], "cone", cfg["ip"][host], wan_ip).encode("ascii"), "punch control NAT install")
            installed.append(router)
        for host, _, peer in pairs:
            code = PUNCH % (cfg["ip"][host], SOURCE_PORT, PUNCH_SENDS, peer, SOURCE_PORT)
            argv = kernel.ns_argv(tools, cfg, host, tools["python"], "-I", "-c", code)
            processes.append((host, subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                     env=kernel.SAFE_ENV, close_fds=True)))
        for host, process in processes:
            out, err = process.communicate(timeout=max(1.0, deadline - time.monotonic()))
            contract.require(process.returncode == 0 and len(out) <= kernel.MAX_OUTPUT, f"punch control worker failed: {err[:200]!r}")
            found.append({"host": host, **json.loads(out)})
    finally:
        for _, process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
        for router in installed:
            kernel.checked(kernel.ns_argv(tools, cfg, router, tools["nft"]) + ["delete", "table", "inet", table], deadline,
                           what="punch control NAT removal")
    # Supporting evidence, not an oracle of the product: a mismatch is recorded, it does not fail the case.
    try:
        return {"status": "pass", "receipts": check_punch(found)}
    except ValueError as error:
        return {"status": "fail", "receipts": found, "error": str(error)[:300]}
