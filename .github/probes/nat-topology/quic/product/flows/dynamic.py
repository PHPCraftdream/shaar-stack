"""Runtime path controls: a Native UDP, Ygg TCP or segment IPv4 UDP block inserted and removed as separate owned tables."""

import json
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "runtime"))
import contract  # noqa: E402
import kernel  # noqa: E402

KINDS = ("native", "ygg", "v4")
ROUTERS = ("rtr_a", "rtr_b")


def table_name(prefix, kind):
    contract.require(type(prefix) is str and re.fullmatch(r"sn[0-9a-f]{6}", prefix) is not None, "invalid owned network prefix")
    contract.require(kind in KINDS, "unreviewed dynamic block kind")
    return f"{prefix}_d{kind}"


def rules(prefix, kind, ports):
    """Same exemptions as the static blockade (only the DHT socket stays open for UDP); drops are counted separately."""
    table = table_name(prefix, kind)
    contract.require(type(ports) is dict and set(ports) >= {"dht", "transit"}
                     and all(type(ports[key]) is int and 1024 <= ports[key] <= 65535 for key in ("dht", "transit")),
                     "invalid owned fixture port")
    lines = [f"add table inet {table}", f"add counter inet {table} dyn_drop",
             f"add chain inet {table} dynblk {{ type filter hook {'output' if kind == 'v4' else 'forward'} priority -250; policy accept; }}"]
    if kind == "native":
        lines += [f"add rule inet {table} dynblk ip daddr 203.0.113.10 udp dport {ports['dht']} accept comment \"p13-dyn-dht-query\"",
                  f"add rule inet {table} dynblk ip saddr 203.0.113.10 udp sport {ports['dht']} accept comment \"p13-dyn-dht-reply\"",
                  f"add rule inet {table} dynblk meta l4proto udp counter name dyn_drop drop comment \"p13-dyn-native-block\""]
    elif kind == "v4":
        # Segment hosts only: each namespace sends Native UDP to the other host's IPv4 address; IPv6 stays open.
        lines.append(f"add rule inet {table} dynblk ip daddr {{ 203.0.113.1, 203.0.113.2 }} meta l4proto udp counter name dyn_drop drop comment \"p13-dyn-v4-block\"")
    else:
        lines += [f"add rule inet {table} dynblk ip daddr 203.0.113.10 tcp dport {ports['transit']} counter name dyn_drop drop comment \"p13-dyn-ygg-block\"",
                  f"add rule inet {table} dynblk ip saddr 203.0.113.10 tcp sport {ports['transit']} counter name dyn_drop drop comment \"p13-dyn-ygg-block\""]
    return "\n".join(lines) + "\n"


def drops(document, prefix, kind):
    """Packets and bytes dropped by this block's single counter."""
    table = table_name(prefix, kind)
    found = [entry["counter"] for entry in document.get("nftables", []) if "counter" in entry]
    contract.require(len(found) == 1 and found[0].get("table") == table and found[0].get("name") == "dyn_drop"
                     and type(found[0].get("packets")) is int and type(found[0].get("bytes")) is int,
                     "dynamic block counter inventory differs")
    return {"packets": found[0]["packets"], "bytes": found[0]["bytes"]}


def install(cfg, tools, kind, ports, deadline):
    """Insert the block in both routers; returns the monotonic time at which the last commit completed."""
    text = rules(cfg["prefix"], kind, ports).encode("ascii")
    for router in ROUTERS:
        kernel.checked(kernel.ns_argv(tools, cfg, router, tools["nft"], "--file", "-"), deadline, text,
                       f"dynamic {kind} block install")
    return time.monotonic()


def read(cfg, tools, router, kind, deadline):
    argv = kernel.ns_argv(tools, cfg, router, tools["nft"], "--json", "list", "table", "inet", table_name(cfg["prefix"], kind))
    return drops(json.loads(kernel.checked(argv, deadline, what=f"dynamic {kind} block snapshot")), cfg["prefix"], kind)


def remove(cfg, tools, kind, deadline):
    """Read each router's drop counter, then delete the table; returns the counters and the removal time."""
    seen = {}
    for router in ROUTERS:
        seen[router] = read(cfg, tools, router, kind, deadline)
        kernel.checked(kernel.ns_argv(tools, cfg, router, tools["nft"], "delete", "table", "inet", table_name(cfg["prefix"], kind)),
                       deadline, what=f"dynamic {kind} block removal")
    return seen, time.monotonic()
