"""Observed no-n0 check: per-router counters for packets to destinations outside the owned address set."""

import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "runtime"))
import contract  # noqa: E402
import kernel  # noqa: E402

COUNTERS = ("outside_fwd", "outside_out", "udp53", "tcp443")
# Owned plan (10/8 LANs, 203.0.113.0/24 WAN segment) plus loopback and link-scope multicast/broadcast, which cannot leave the segment.
OWNED = "{ 10.0.0.0/8, 127.0.0.0/8, 203.0.113.0/24, 224.0.0.0/3 }"
# TEST-NET-1 target of the detector self-check; no namespace routes or answers it.
PROBE_TARGET = "192.0.2.77"
PROBE = ("import socket; u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
         "u.sendto(b'x', (%r, 53)); u.sendto(b'x', (%r, 9)); u.close(); "
         "t = socket.socket(socket.AF_INET, socket.SOCK_STREAM); t.settimeout(0.3); t.connect_ex((%r, 443)); t.close()"
         % (PROBE_TARGET, PROBE_TARGET, PROBE_TARGET))


def table_name(prefix):
    contract.require(type(prefix) is str and re.fullmatch(r"sn[0-9a-f]{6}", prefix) is not None, "invalid owned network prefix")
    return prefix + "_obs"


def rules(prefix):
    """Counter-only rules (never a verdict): forward sees Client-side hosts, output sees processes inside the router namespace."""
    table = table_name(prefix)
    lines = [f"add table inet {table}"]
    lines += [f"add counter inet {table} {name}" for name in COUNTERS]
    for chain, hook, outside in (("obsfwd", "forward", "outside_fwd"), ("obsout", "output", "outside_out")):
        lines += [f"add chain inet {table} {chain} {{ type filter hook {hook} priority -500; policy accept; }}",
                  f"add rule inet {table} {chain} ip daddr != {OWNED} counter name {outside} comment \"p13-obs-outside\"",
                  f"add rule inet {table} {chain} ip daddr != {OWNED} udp dport 53 counter name udp53 comment \"p13-obs-udp53\"",
                  f"add rule inet {table} {chain} ip daddr != {OWNED} tcp dport 443 counter name tcp443 comment \"p13-obs-tcp443\""]
    return "\n".join(lines) + "\n"


def counts(document, prefix):
    """Packet counts of exactly the four named counters of this owned table."""
    table = table_name(prefix)
    found = {}
    for entry in document.get("nftables", []):
        raw = entry.get("counter")
        if raw is None:
            continue
        contract.require(raw.get("table") == table and raw.get("family") == "inet" and raw.get("name") in COUNTERS
                         and raw["name"] not in found and type(raw.get("packets")) is int and raw["packets"] >= 0,
                         "foreign, duplicate or malformed observation counter")
        found[raw["name"]] = raw["packets"]
    contract.require(set(found) == set(COUNTERS), "incomplete observation counter inventory")
    return found


def verify_zero(found, router):
    contract.require(set(found) == set(COUNTERS), "observation counters incomplete")
    hits = {name: value for name, value in found.items() if value}
    contract.require(not hits, f"{router} observed traffic to destinations outside the owned address set: {hits}")
    return dict(found)


def check_detector(found):
    """The self-check sent 2 datagrams plus one SYN from a host and from the router namespace itself."""
    contract.require(found["outside_fwd"] >= 2 and found["outside_out"] >= 2 and found["udp53"] >= 2 and found["tcp443"] >= 2,
                     "observation rules did not detect known outside-destination probes")
    return dict(found)


def install(cfg, tools, router, deadline):
    argv = kernel.ns_argv(tools, cfg, router, tools["nft"], "--file", "-")
    kernel.checked(argv, deadline, rules(cfg["prefix"]).encode("ascii"), "observation rules install")


def read(cfg, tools, router, deadline):
    argv = kernel.ns_argv(tools, cfg, router, tools["nft"], "--json", "list", "table", "inet", table_name(cfg["prefix"]))
    return counts(json.loads(kernel.checked(argv, deadline, what="observation snapshot")), cfg["prefix"])


def calibrate(cfg, tools, router, host, deadline):
    """Prove the exact installed rules detect outside destinations, then reinstall them with zero counters."""
    install(cfg, tools, router, deadline)
    for namespace in (host, router):
        kernel.checked(kernel.ns_argv(tools, cfg, namespace, tools["python"], "-I", "-c", PROBE), deadline,
                       what="observation probe")
    detected = check_detector(read(cfg, tools, router, deadline))
    kernel.checked(kernel.ns_argv(tools, cfg, router, tools["nft"], "delete", "table", "inet", table_name(cfg["prefix"])),
                   deadline, what="observation table removal")
    install(cfg, tools, router, deadline)
    verify_zero(read(cfg, tools, router, deadline), router)
    return {"router": router, "detected": detected}
