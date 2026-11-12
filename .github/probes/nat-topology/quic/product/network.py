"""Pure namespace-only NAT/blockade plans and bounded nft evidence validation."""

import copy
import re

# udp: "blocked" installs the Native UDP block from the start; "open" and "runtime" (blocked later by a dynamic table) do not.
# tcp_a: owned TCP services the Client-side router forwards ("relay", "transit" = Ygg hub); the Server-side router allows both.
_NATIVE = {"udp": "open", "tcp_a": ("relay",)}
_BLOCKED = {"udp": "blocked", "tcp_a": ("transit",)}
_FAILOVER = {"udp": "runtime", "tcp_a": ("relay", "transit")}
PROFILES = {
    "native-signal": _NATIVE, "native-standby": _NATIVE,
    "blocked-standby": _BLOCKED, "blocked-signal": _BLOCKED,
    "lan-signal": {**_NATIVE, "lan": True}, "lan-standby": {**_NATIVE, "lan": True},
    "relay-denied-signal": {"udp": "open", "tcp_a": ("transit",)},
    "failover-standby": _FAILOVER, "failover-signal": _FAILOVER,
    "denied-blocked-standby": _BLOCKED,
    "dht-drop-signal": {"udp": "open", "tcp_a": ("relay", "transit"), "dht_drop": True},
    "outage-standby": {"udp": "blocked", "tcp_a": ()},
}
CASES = set(PROFILES)
COUNTERS = {"quota_drop", "ipv6_drop", "native_drop", "tcp_drop", "udp_nat", "tcp_nat", "native_snat",
            "ygg_tcp", "relay_tcp", "dht_drop", "lan_native", "lan_sent"}
QUOTAS = {"product": 2 * 1024 * 1024, "fault": 2 * 1024 * 1024}
CHAINS = {"budget": ("filter", "forward", -300), "paths": ("filter", "forward", -200),
          "natout": ("nat", "postrouting", 100), "seen": ("filter", "postrouting", 200),
          "lanin": ("filter", "input", -200), "lanout": ("filter", "output", -200)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def table_name(prefix):
    require(type(prefix) is str and re.fullmatch(r"sn[0-9a-f]{6}", prefix) is not None,
            "invalid owned network prefix")
    return prefix + "_product"


def rules(prefix, router, case, ports, purpose="product"):
    table = table_name(prefix)
    require(router in ("rtr_a", "rtr_b") and case in PROFILES, "unreviewed router/case")
    require(purpose in QUOTAS, "unreviewed traffic allocation")
    require(type(ports) is dict and set(ports) == {"dht", "relay", "transit"}, "fixture port inventory differs")
    require(all(type(value) is int and 1024 <= value <= 65535 for value in ports.values()),
            "invalid owned fixture port")
    # DHT uses UDP; relay and Ygg share TCP, so their listeners must be distinct.
    require(ports["relay"] != ports["transit"], "TCP fixture listeners overlap")
    host = "10.0.1.2" if router == "rtr_a" else "10.0.2.2"
    wan_ip = "203.0.113.1" if router == "rtr_a" else "203.0.113.2"
    profile = PROFILES[case]
    blocked = profile["udp"] == "blocked"
    lines = [f"add table inet {table}"]
    for name in sorted(COUNTERS):
        lines.append(f"add counter inet {table} {name}")
    lines += [f"add quota inet {table} phase_budget {{ over {QUOTAS[purpose]} bytes }}",
              f"add chain inet {table} budget {{ type filter hook forward priority -300; policy accept; }}",
              f"add rule inet {table} budget quota name phase_budget counter name quota_drop drop comment \"p13-budget\"",
              f"add chain inet {table} paths {{ type filter hook forward priority -200; policy accept; }}",
              f"add chain inet {table} lanin {{ type filter hook input priority -200; policy accept; }}",
              f"add chain inet {table} lanout {{ type filter hook output priority -200; policy accept; }}",
              f"add rule inet {table} paths meta nfproto ipv6 counter name ipv6_drop drop comment \"p13-no-ipv6\""]
    if profile.get("dht_drop") and router == "rtr_a":
        lines.append(f"add rule inet {table} paths ip daddr 203.0.113.10 udp dport {ports['dht']} counter name dht_drop drop comment \"p13-dht-block\"")
    if blocked:
        # Only the actual DHT socket is exempt, not established UDP connections.
        lines += [f"add rule inet {table} paths ip daddr 203.0.113.10 udp dport {ports['dht']} accept comment \"p13-dht-query\"",
                  f"add rule inet {table} paths ip saddr 203.0.113.10 udp sport {ports['dht']} accept comment \"p13-dht-reply\"",
                  f"add rule inet {table} paths meta l4proto udp counter name native_drop drop comment \"p13-native-block\""]
    allowed_tcp = profile["tcp_a"] if router == "rtr_a" else ("relay", "transit")
    for service, counter in (("relay", "relay_tcp"), ("transit", "ygg_tcp")):
        if service in allowed_tcp:
            port = ports[service]
            lines += [f"add rule inet {table} paths ip daddr 203.0.113.10 tcp dport {port} counter name {counter} accept comment \"p13-owned-tcp-query\"",
                      f"add rule inet {table} paths ip saddr 203.0.113.10 tcp sport {port} counter name {counter} accept comment \"p13-owned-tcp-reply\""]
    lines += [f"add rule inet {table} paths meta l4proto tcp counter name tcp_drop drop comment \"p13-other-tcp-block\"",
              f"add chain inet {table} natout {{ type nat hook postrouting priority 100; policy accept; }}",
              f"add rule inet {table} natout ip saddr {host} ip protocol udp counter name udp_nat masquerade to :41010-41020 comment \"p13-udp-nat\"",
              f"add rule inet {table} natout ip saddr {host} meta l4proto tcp counter name tcp_nat masquerade comment \"p13-tcp-nat\"",
              # Independent packet-level observation after NAT: translated non-DHT UDP toward the WAN host.
              f"add chain inet {table} seen {{ type filter hook postrouting priority 200; policy accept; }}",
              f"add rule inet {table} seen ip saddr {wan_ip} ip daddr 203.0.113.10 udp sport 41010-41020 udp dport != {ports['dht']} "
              f"ct status snat counter name native_snat comment \"p13-snat-seen\""]
    if profile.get("lan"):
        # LAN: Client (rtr_a ns) and Server (rtr_b ns) share one segment; count it on input, block the Client's Ygg dial on output.
        source, target = ("203.0.113.2", "203.0.113.1") if router == "rtr_a" else ("203.0.113.1", "203.0.113.2")
        lines.append(f"add rule inet {table} lanin ip saddr {source} ip daddr {target} meta l4proto udp counter name lan_native comment \"p13-lan-native\"")
        # Sender side of the same traffic: separates "never sent" from "sent but not delivered".
        lines.append(f"add rule inet {table} lanout ip saddr {target} ip daddr {source} meta l4proto udp counter name lan_sent comment \"p13-lan-sent\"")
        if router == "rtr_a":
            lines.append(f"add rule inet {table} lanout ip daddr 203.0.113.10 tcp dport {ports['transit']} counter name tcp_drop drop comment \"p13-lan-ygg-block\"")
    return "\n".join(lines) + "\n"


def commands(config, router, nft, ip):
    """Return argv only; the controller must own and bound each command's PID/I/O."""
    table = table_name(config.get("prefix"))
    require(router in ("rtr_a", "rtr_b"), "only owned routers may change forwarding")
    expected = config["prefix"] + ("-rtr-a" if router == "rtr_a" else "-rtr-b")
    require(config.get("ns", {}).get(router) == expected, "foreign router namespace")
    require(all(type(path) is str and path.startswith("/") and "\0" not in path for path in (ip, nft)),
            "network tools require absolute verified Linux paths")
    prefix = [ip, "netns", "exec", expected]
    return {"ipv4_forward": prefix + ["/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
            "ipv6_forward": prefix + ["/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=0"],
            "check_rules": prefix + [nft, "--check", "--file", "-"],
            "install_rules": prefix + [nft, "--file", "-"],
            "snapshot": prefix + [nft, "--json", "list", "table", "inet", table]}


def snapshot(document, prefix, purpose):
    """Validate named quota/counters and return immutable rules separately from usage."""
    table = table_name(prefix)
    require(purpose in QUOTAS and type(document) is dict, "unreviewed quota snapshot")
    entries = document.get("nftables")
    require(type(entries) is list and 1 <= len(entries) <= 64, "unbounded nft object inventory")
    counters, quotas, immutable, comments = {}, [], [], []
    for entry in entries:
        require(type(entry) is dict and len(entry) == 1, "malformed nft object")
        kind, raw = next(iter(entry.items()))
        if kind == "metainfo":
            continue
        require(kind in ("table", "chain", "rule", "counter", "quota") and type(raw) is dict,
                "unexpected nft object type")
        require(raw.get("family") == "inet", "nft family changed")
        require(raw.get("name") == table if kind == "table" else raw.get("table") == table,
                "nft object escaped its owned table")
        value = copy.deepcopy(raw)
        if kind == "counter":
            name = raw.get("name")
            require(name in COUNTERS and name not in counters, "missing/duplicate/foreign named counter")
            for field in ("packets", "bytes"):
                require(type(raw.get(field)) is int and raw[field] >= 0, "invalid nft counter value")
                value[field] = 0
            counters[name] = {key: raw[key] for key in ("packets", "bytes")}
        elif kind == "chain":
            require(raw.get("name") in CHAINS, "foreign nft chain")
            require((raw.get("type"), raw.get("hook"), raw.get("prio")) == CHAINS[raw["name"]]
                    and raw.get("policy") == "accept", "nft chain hook, priority or policy changed")
        elif kind == "rule":
            require(raw.get("chain") in CHAINS
                    and type(raw.get("expr")) is list and 1 <= len(raw["expr"]) <= 12,
                    "missing or unbounded installed rule expressions")
            comment = raw.get("comment", "")
            require(type(comment) is str and comment.startswith("p13-") and len(comment) <= 48,
                    "missing installed rule identity")
            comments.append(comment)
        elif kind == "quota":
            require(raw.get("name") == "phase_budget" and raw.get("bytes") == QUOTAS[purpose]
                    and type(raw.get("bytes")) is int and raw.get("inv") is True,
                    "kernel quota allocation or over-limit policy changed")
            require(type(raw.get("used")) is int and raw["used"] >= 0, "invalid kernel quota usage")
            quotas.append(raw["used"])
            value["used"] = 0
        immutable.append({kind: value})
    require(set(counters) == COUNTERS and len(quotas) == 1, "incomplete named quota/counter snapshot")
    require(sum("table" in item for item in immutable) == 1 and sum("chain" in item for item in immutable) == len(CHAINS)
            and {item["chain"]["name"] for item in immutable if "chain" in item} == set(CHAINS),
            "owned nft table/chain inventory changed")
    for comment in ("p13-budget", "p13-no-ipv6", "p13-other-tcp-block", "p13-udp-nat", "p13-tcp-nat", "p13-snat-seen"):
        require(comments.count(comment) == 1, "missing or duplicated installed rule identity")
    return {"immutable": immutable, "counters": counters, "quota_used": quotas[0], "comments": comments}


def verify(before, after, prefix, purpose, blocked=False, require_nat=False, require_drop=None):
    require(not (blocked and require_nat), "blockade and NAT-positive expectations are exclusive")
    initial, final = snapshot(before, prefix, purpose), snapshot(after, prefix, purpose)
    require(initial["immutable"] == final["immutable"], "installed nft objects changed during the case")
    require(final["quota_used"] >= initial["quota_used"], "kernel quota usage rolled back")
    for name in COUNTERS:
        for field in ("packets", "bytes"):
            require(final["counters"][name][field] >= initial["counters"][name][field], "named nft counter rolled back")
    require(initial["quota_used"] == 0 and all(value == 0 for counter in initial["counters"].values() for value in counter.values()),
            "case did not start with fresh kernel budgets")
    require(final["quota_used"] < QUOTAS[purpose] and final["counters"]["quota_drop"]["packets"] == 0,
            "kernel traffic allocation exhausted; this is not a passing blockade")
    require(final["counters"]["ipv6_drop"]["packets"] == 0, "unexpected IPv6 forwarding attempt")
    if blocked:
        require(all(final["comments"].count(comment) == 1 for comment in
                    ("p13-native-block", "p13-dht-query", "p13-dht-reply")), "missing installed UDP blockade rules")
    if blocked:
        require(final["counters"]["native_snat"]["packets"] == 0, "non-DHT UDP escaped the blockade after NAT")
    if blocked if require_drop is None else require_drop:
        require(final["counters"]["native_drop"]["packets"] > 0, "blockade never observed a Native UDP attempt")
    if require_nat:
        require(final["counters"]["udp_nat"]["packets"] > 0, "Native positive lacks observed UDP NAT admission")
        require(final["counters"]["native_snat"]["packets"] > 0, "Native positive lacks translated non-DHT UDP toward the WAN host")
    return {"quota_used": final["quota_used"], "quota_limit": QUOTAS[purpose], "counters": final["counters"]}
