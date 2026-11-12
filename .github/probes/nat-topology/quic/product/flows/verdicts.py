"""Strict, per-class conclusions over raw case evidence; never trusts a bare exit status."""

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import contract  # noqa: E402

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
    else:
        raise ValueError("unreviewed case class")
    if spec.get("flow") == "denied-key":
        denied_key(result)
