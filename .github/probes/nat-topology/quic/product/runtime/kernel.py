"""Root-side kernel facilities inside owned router namespaces: nft rules, quota proof, NAT tuples."""

import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))
sys.path.insert(0, str(HERE.parent))
import contract  # noqa: E402
import ctparse  # noqa: E402
import network  # noqa: E402

MAX_OUTPUT = 1024 * 1024
PROBE_LIMIT = 1024
PROBE_DATAGRAMS = 24
PROBE_PORT = 9
SENDER = ("import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
          "[s.sendto(bytes(100), (%r, %d)) for _ in range(%d)]" % (contract.IPS["wan"], PROBE_PORT, PROBE_DATAGRAMS))
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def run_tool(argv, deadline, data=None):
    """One owned setup command: finite lifetime, reaped PID, bounded output (trusted system tools only)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("setup command budget exhausted before admission")
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=SAFE_ENV, close_fds=True)
    try:
        out, err = process.communicate(data, timeout=remaining)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise TimeoutError("setup command deadline exceeded") from error
    except BaseException:
        process.kill()
        process.communicate()
        raise
    contract.require(len(out) <= MAX_OUTPUT and len(err) <= MAX_OUTPUT, "setup command exceeded its output budget")
    return process.returncode, out, err


def checked(argv, deadline, data=None, what="setup command"):
    code, out, err = run_tool(argv, deadline, data)
    if code != 0:
        raise RuntimeError(f"{what} failed rc={code}: " + err.decode("utf-8", errors="replace")[:400])
    return out


def ns_argv(tools, cfg, key, *argv):
    contract.require(key in contract.SUFFIXES and cfg["ns"][key] == cfg["prefix"] + "-" + contract.SUFFIXES[key],
                     "foreign namespace")
    contract.require(all(type(item) is str and item.startswith("/") for item in tools.values()),
                     "tools must be absolute verified paths")
    return [tools["ip"], "netns", "exec", cfg["ns"][key], *argv]


def probe_rules(prefix, host_ip):
    """Throwaway tiny quota table proving enforcement before the product table exists."""
    table = network.table_name(prefix).replace("_product", "_qprobe")
    body = [f"add table inet {table}", f"add counter inet {table} probe_pass", f"add counter inet {table} probe_over",
            f"add quota inet {table} probe_budget {{ over {PROBE_LIMIT} bytes }}",
            f"add chain inet {table} f {{ type filter hook forward priority -400; policy accept; }}",
            f"add rule inet {table} f ip saddr {host_ip} udp dport {PROBE_PORT} quota name probe_budget counter name probe_over drop",
            f"add rule inet {table} f ip saddr {host_ip} udp dport {PROBE_PORT} counter name probe_pass"]
    return table, "\n".join(body) + "\n"


def probe_counts(document, table):
    counters, used = {}, None
    for entry in document.get("nftables", []):
        raw = entry.get("counter")
        if raw and raw.get("table") == table:
            counters[raw["name"]] = raw["packets"]
        raw = entry.get("quota")
        if raw and raw.get("table") == table:
            used = raw["used"]
    contract.require(set(counters) == {"probe_pass", "probe_over"} and type(used) is int, "quota probe inventory incomplete")
    return {"passed": counters["probe_pass"], "dropped": counters["probe_over"], "used": used}


def check_probe(counts):
    contract.require(counts["passed"] >= 1 and counts["dropped"] >= 1 and counts["passed"] + counts["dropped"] <= PROBE_DATAGRAMS
                     and counts["used"] >= PROBE_LIMIT, "kernel quota did not enforce its limit on live forwarded packets")
    return counts


def calibrate_quota(cfg, tools, router, host, deadline):
    """Real forwarded UDP from the owned host proves quota-over drops and counters work in this kernel."""
    table, text = probe_rules(cfg["prefix"], cfg["ip"][host])
    base = ns_argv(tools, cfg, router, tools["nft"])
    checked(base + ["--file", "-"], deadline, text.encode("ascii"), "quota probe install")
    try:
        checked(ns_argv(tools, cfg, host, tools["python"], "-I", "-c", SENDER), deadline, what="quota probe sender")
        document = json.loads(checked(base + ["--json", "list", "table", "inet", table], deadline, what="quota probe snapshot"))
        counts = check_probe(probe_counts(document, table))
    finally:
        # Cleanup of this exact owned table; a failure here is reported by the caller.
        checked(base + ["delete", "table", "inet", table], deadline, what="quota probe removal")
    return {"router": router, "limit_bytes": PROBE_LIMIT, "sent": PROBE_DATAGRAMS, **counts}


def install_rules(cfg, tools, router, case, ports, purpose, deadline):
    plan = network.commands(cfg, router, tools["nft"], tools["ip"])
    text = network.rules(cfg["prefix"], router, case, ports, purpose).encode("ascii")
    for setting in ("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=0"):
        checked(ns_argv(tools, cfg, router, tools["sysctl"], "-q", "-w", setting), deadline, what="router forwarding " + setting)
    readback = {}
    for family, name in (("ipv4", "net.ipv4.ip_forward"), ("ipv6", "net.ipv6.conf.all.forwarding")):
        value = checked(ns_argv(tools, cfg, router, tools["sysctl"], "-n", name), deadline, what="forwarding readback")
        readback[family] = value.decode("ascii").strip()
    contract.require(readback == {"ipv4": "1", "ipv6": "0"}, "router forwarding state differs from the plan")
    checked(plan["check_rules"], deadline, text, "nft rule syntax check")
    checked(plan["install_rules"], deadline, text, "nft rule install")
    return {"router": router, "forwarding": readback, "rules_bytes": len(text)}


def snapshot(cfg, tools, router, deadline):
    plan = network.commands(cfg, router, tools["nft"], tools["ip"])
    return json.loads(checked(plan["snapshot"], deadline, what="nft snapshot"))


def conntrack_lines(cfg, tools, router, deadline):
    reader = "import sys; sys.stdout.write(open('/proc/net/nf_conntrack', encoding='ascii').read())"
    code, out, err = run_tool(ns_argv(tools, cfg, router, tools["python"], "-I", "-c", reader), deadline)
    contract.require(code == 0, "conntrack procfs table unavailable in the router namespace (no conntrack CLI fallback)")
    lines = out.decode("utf-8", errors="replace").splitlines()
    contract.require(len(lines) <= 4096, "conntrack table exceeds the bounded inspection size")
    return lines


def native_candidates(addresses, dht_port):
    """Published WAN-side Native endpoints; the DHT socket is never a Native candidate."""
    result = []
    for text in addresses:
        host, _, port = text.rpartition(":")
        if host == contract.IPS["wan"] and port.isdigit() and int(port) != dht_port:
            result.append(int(port))
    return result


def nat_observation(lines, source_ip, router_wan, ports):
    """Replied UDP entry from the Client host to a published Native port with SNAT in the fixed range."""
    low, high = contract.TRANSLATED_RANGE
    wan = contract.IPS["wan"]
    for line in lines:
        entry = ctparse.parse_line(line)
        if not entry or entry["proto"] != "udp" or entry["unreplied"] or entry["reply"] is None:
            continue
        orig, reply = entry["orig"], entry["reply"]
        if (orig["src"] == source_ip and orig["dst"] == wan and orig["dport"] in ports
                and reply["src"] == wan and reply["sport"] == orig["dport"]
                and reply["dst"] == router_wan and low <= reply["dport"] <= high):
            return {"orig": orig, "reply": reply, "assured": entry["assured"]}
    return None
