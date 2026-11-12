"""Strict, per-class conclusions over raw case evidence; never trusts a bare exit status."""

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "runtime"))
import contract  # noqa: E402
import natprobe  # noqa: E402

OBSERVE_NAMES = ("outside_fwd", "outside_out", "udp53", "tcp443")


def packets(counters, router, name):
    return counters[router][name]["packets"]


def no_outside_contact(result):
    """F1: every router counter for destinations outside the owned address set is exactly zero."""
    watched = result.get("observe", {})
    contract.require(set(watched) == {"rtr_a", "rtr_b"}
                     and all(set(item) == set(OBSERVE_NAMES) and all(value == 0 for value in item.values())
                             for item in watched.values()), "observed traffic outside the owned address set, or receipt missing")
    detected = result.get("observe_calibration", [])
    contract.require(len(detected) == 2 and all(item["detected"]["outside_fwd"] >= 2 and item["detected"]["outside_out"] >= 2
                                                for item in detected), "outside-destination detector was not proven live")


def nat_or_blocked(spec, counters, observed):
    if spec["net"] == "blocked":
        contract.require(packets(counters, "rtr_a", "native_drop") > 0, "no dropped Native UDP attempt")
        contract.require(all(packets(counters, router, "native_snat") == 0 for router in counters),
                         "non-DHT UDP escaped the blockade")
        return
    contract.require(packets(counters, "rtr_a", "udp_nat") > 0 and packets(counters, "rtr_a", "native_snat") > 0,
                     "no real Native NAT observed by nft counters")
    contract.require("native_nat_tuple" in observed or "native_nat_tuple_unavailable" in observed,
                     "conntrack tuple outcome must be recorded either way")


def lan(counters, result, spec):
    """E1: nothing was forwarded or translated, yet Native UDP crossed the segment in both directions."""
    for router in counters:
        contract.require(result["kernel"][router]["quota_used"] == 0, f"{router} forwarded traffic in the LAN case")
        for name in ("udp_nat", "tcp_nat", "native_snat", "native_drop"):
            contract.require(packets(counters, router, name) == 0, f"{router} {name} is nonzero in the LAN case")
        contract.require(packets(counters, router, "lan_native") > 0 and packets(counters, router, "lan_sent") > 0,
                         f"{router} sent or saw no Native UDP on the LAN segment")
    published = [item.rpartition(":")[0] for item in result["publication"]["native_addresses"]]
    contract.require(published == [contract.ip_for(spec["server_ns"])], f"published addresses differ from the segment address: {published}")


def dht_drop(counters):
    """C2: with every DHT query dropped the signal-mode Client still reached the Server; only Native can carry APP there."""
    contract.require(packets(counters, "rtr_a", "dht_drop") > 0, "the DHT block never observed a query")
    contract.require(packets(counters, "rtr_a", "udp_nat") > 0 and packets(counters, "rtr_a", "native_snat") > 0,
                     "no translated Native UDP although the APP succeeded without the DHT")


def segment_hosts(counters, result):
    """Segment hosts (LAN, IPv6): nothing was forwarded or translated by either router."""
    for router in counters:
        contract.require(result["kernel"][router]["quota_used"] == 0, f"{router} forwarded traffic in a segment case")
        for name in ("udp_nat", "tcp_nat", "native_snat", "native_drop"):
            contract.require(packets(counters, router, name) == 0, f"{router} {name} is nonzero in a segment case")


def ipv6(counters, result):
    """A2b: with IPv4 Native UDP dropped, IPv6 Native UDP crossed the segment both ways and carried the APP; the record lists the IPv6 address."""
    segment_hosts(counters, result)
    for router in counters:
        contract.require(packets(counters, router, "lan6_native") > 0 and packets(counters, router, "lan6_sent") > 0,
                         f"{router} sent or saw no IPv6 Native UDP on the segment")
        contract.require(packets(counters, router, "lan_native") == 0, f"{router} received IPv4 Native UDP although IPv4 was dropped")
    observed = result.get("observations", {}).get("ipv6", {})
    contract.require(observed.get("hint", "").startswith("[" + contract.V6["rtr_b"] + "]:") and "v4_block_drops" in observed,
                     "IPv6 hint or IPv4 block receipt missing")
    published = [item.rpartition(":")[0].strip("[]") for item in result["publication"]["native_addresses"]]
    contract.require(contract.V6["rtr_b"] in published, f"signed record lacks the Server's IPv6 address: {published}")


def perturb(result):
    """D2, D4: APP 2 recovered within the bound and the change was visible in the counters."""
    obs = result.get("observations", {}).get("perturb", {})
    contract.require(0 <= obs.get("recovery_seconds", -1) <= contract.RECOVERY_SECONDS and obs.get("app2", {}).get("reply_bytes", 0) > 0,
                     "recovery bound or APP 2 reply missing")
    contract.require(obs["growth"]["native_new"] > 0, "no new Native NAT mapping after the change")


def nat_mapping(result, flavor):
    """The live probe showed the intended mapping flavor on both routers (kept = source port preserved)."""
    total = len(natprobe.DEST_PORTS)
    kept, moved = (total, 0) if flavor == "cone" else (0, total)
    found = result.get("nat_calibration", [])
    contract.require(len(found) == 2 and all(item["flavor"] == flavor and item["kept"] == kept and item["moved"] == moved for item in found),
                     f"NAT probe does not show the {flavor} mapping on both routers")


def punch_control(result):
    """The fixture itself can punch through the two cone NATs (harness-known public endpoints), so a missing path is the product's."""
    found = result.get("punch_control", [])
    expected = {"host_a": contract.IPS["rtr_b_wan"], "host_b": contract.IPS["rtr_a_wan"]}
    contract.require(len(found) == 2 and {item.get("host") for item in found} == set(expected)
                     and all(item["received"] > 0 and item["first"][0] == expected[item["host"]] for item in found),
                     "fixture hole punch control missing or failed")


def dnat(spec, counters, result):
    """A5/A6: double NAT, Native UDP allowed. A direct Native path needs translated Native UDP between the routers both ways."""
    nat_mapping(result, spec["nat"])
    if spec["nat"] == "cone":
        punch_control(result)
    if spec["direct"]:
        for router in counters:
            contract.require(packets(counters, router, "peer_sent") > 0 and packets(counters, router, "peer_recv") > 0,
                             f"{router} saw no translated Native UDP both ways between the routers (no hole punching)")
        contract.require(packets(counters, "rtr_a", "ygg_tcp") == 0, "Ygg TCP carried traffic although it was denied")
        return
    for router in counters:
        contract.require(packets(counters, router, "peer_recv") == 0, f"{router} received Native UDP from the other router: a direct path formed")
    ygg = packets(counters, "rtr_a", "ygg_tcp")
    if spec["ygg_client_blocked"]:
        contract.require(ygg == 0, "Ygg TCP carried traffic although it was denied")
    elif spec["mode"] == "standby":
        contract.require(ygg > 0, "standby APP succeeded without Ygg TCP traffic on the Client side")
    if spec.get("relay_first"):
        contract.require(packets(counters, "rtr_a", "dht_drop") > 0 and packets(counters, "rtr_a", "relay_tcp") > 0,
                         "the Client did not reach relay negotiation with its DHT queries dropped")


def recover(result):
    """C7: the outage failed closed and ended the Client; a fresh Client succeeded after the blocks were lifted."""
    obs = result.get("observations", {}).get("outage", {})
    contract.require(obs.get("client1_exit") == 1 and obs.get("app_outage", {}).get("denied") is True
                     and obs["app_outage"]["reply_bytes"] == 0, "outage did not fail closed")
    contract.require(0 <= obs.get("recovery_seconds", -1) <= contract.RECOVERY_SECONDS and obs.get("app2", {}).get("reply_bytes", 0) > 0,
                     "recovery bound or APP 2 reply missing after the outage")


def relay_full(result):
    """C5: the Server ended by itself with the typed reservation error within the bound; no Client or APP existed."""
    obs = result.get("observations", {}).get("relay_full", {})
    contract.require(obs.get("server_exit") == 1 and contract.RESERVE_FAIL.decode("ascii") in obs.get("message", ""),
                     "Server did not end with the typed relay reservation failure")
    contract.require("app" not in result.get("observations", {}), "an APP ran although the Server never started")


def failover(spec, result, counters):
    contract.require(packets(counters, "rtr_a", "udp_nat") > 0 and packets(counters, "rtr_a", "native_snat") > 0,
                     "no real Native NAT observed by nft counters before the block")
    obs = result.get("observations", {}).get("failover", {})
    contract.require(obs.get("app1_native_snat_packets") is not None and obs.get("block_native_snat_packets") == 0,
                     "failover evidence missing or Native escaped the block")
    contract.require(obs["native_block_drops"]["rtr_a"]["packets"] > 0, "runtime block never dropped Native UDP")
    if spec["mode"] == "signal":
        contract.require(obs["app2"]["reply_bytes"] == 0 and obs["app2"]["denied"] is True, "signal APP did not fail closed")
        return
    contract.require(0 <= obs["failover_seconds"] <= contract.FAILOVER_SECONDS and obs["block_ygg_tcp_packets"] > 0,
                     "failover bound or Ygg traffic evidence missing")
    contract.require(0 <= obs["recovery_seconds"] <= contract.RECOVERY_SECONDS and obs["recovery_native_snat_packets"] > 0,
                     "recovery bound or Native traffic evidence missing")
    contract.require(all(obs[name]["reply_bytes"] > 0 for name in ("app2", "app3")), "failover/recovery APP lacks reply bytes")


def denied_key(result):
    observed = result.get("observations", {})
    contract.require(observed.get("client1_exit") == 0 and observed.get("app", {}).get("denied") is False
                     and observed.get("denied_app", {}).get("denied") is True
                     and observed["denied_app"]["reply_bytes"] == 0, "authorized control or key denial evidence missing")


def verify_class(spec, result, counters):
    """Class-specific conclusions after the common quota, identity, accept and exit checks."""
    net, observed = spec["net"], result.get("observations", {})
    no_outside_contact(result)
    if net in ("nat", "blocked"):
        nat_or_blocked(spec, counters, observed)
    elif net == "lan":
        lan(counters, result, spec)
    elif net == "dht-drop":
        dht_drop(counters)
    elif net == "failover":
        failover(spec, result, counters)
    elif net == "ipv6":
        ipv6(counters, result)
    elif net == "dnat":
        dnat(spec, counters, result)
    elif net == "relay":
        relay_full(result)
    elif net == "recover":
        recover(result)
    else:
        raise ValueError("unreviewed case class")
    if spec.get("flow") in ("hole", "switch"):
        perturb(result)
    if spec.get("flow") == "denied-key":
        denied_key(result)
