"""Closed product-case schema and bounds; no privileged action occurs on import."""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

# "net" selects the kernel-side expectation class; "flow" selects the controller flow (default: one APP campaign).
# Optional keys: "client_bind" (Client DHT/signaling bind address), "fillers" (extra Servers that hold relay reservations),
# "server_exit" (expected Server exit status, default 0), "client2_exit" (exit status of a replacement Client), "norelay"
# (no network.signaling relay fields at all), "publish" ("plain": the Server publishes the voted reflexive endpoint),
# "dht_denied" (Client-side DHT responses are dropped by the profile), "relay_punch" (the relay is pinned AND the punch must
# rendezvous over the carrier link of the relay circuit: the Client reaches only the relay, so Ygg carries nothing).
NETS = ("nat", "blocked", "lan", "dht-drop", "failover", "dnat", "mapped", "ipv6", "relay", "recover")
SEGMENT_NETS = ("lan", "ipv6")
# Documentation-prefix IPv6 addresses of the two segment hosts (same plan as network.V6).
V6 = {"rtr_a": "2001:db8:13::1", "rtr_b": "2001:db8:13::2"}
LAN = {"client_ns": "rtr_a", "server_ns": "rtr_b", "net": "lan", "udp_blocked": False, "ygg_client_blocked": True,
       "target_accepts": 1, "client_exit": 0}
NATIVE = {"server_ns": "wan", "net": "nat", "udp_blocked": False, "ygg_client_blocked": True, "target_accepts": 1, "client_exit": 0}
DNAT = {"server_ns": "host_b", "net": "dnat", "udp_blocked": False}
# Mapped-port cases (leaf DIRECT-T): the relay-less cone pair with a stateful gateway on each side, no Ygg path for the Client and
# no relay, so no punch can be coordinated: a direct path exists only if the Server's router, asked over PCP, forwards the Server's
# QUIC port. "gateway" says how the controller-owned PCP responder of the Server's router answers: "grant" or "refuse".
MAPPED = {**DNAT, "net": "mapped", "nat": "cone", "norelay": True, "dht_observed": True, "publish": "plain",
          "ygg_client_blocked": True}
CASES = {
    "native-signal": {"mode": "signal", "server_ns": "wan", "net": "nat", "udp_blocked": False, "ygg_client_blocked": True, "target_accepts": 1, "client_exit": 0},
    "native-standby": {"mode": "standby", "server_ns": "wan", "net": "nat", "udp_blocked": False, "ygg_client_blocked": True, "target_accepts": 1, "client_exit": 0},
    "blocked-standby": {"mode": "standby", "server_ns": "host_b", "net": "blocked", "udp_blocked": True, "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    "blocked-signal": {"mode": "signal", "server_ns": "host_b", "net": "blocked", "udp_blocked": True, "ygg_client_blocked": False, "target_accepts": 0, "client_exit": 1},
    # Client and Server are hosts on the owned 203.0.113.0/24 segment next to the DHT/relay/Ygg fixtures: no NAT, no forwarding.
    "lan-signal": {**LAN, "mode": "signal"},
    "lan-standby": {**LAN, "mode": "standby"},
    "relay-denied-signal": {"mode": "signal", "server_ns": "wan", "net": "nat", "udp_blocked": False, "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    "failover-standby": {"mode": "standby", "server_ns": "wan", "net": "failover", "flow": "failover", "udp_blocked": False, "ygg_client_blocked": False, "target_accepts": 3, "client_exit": 0},
    "failover-signal": {"mode": "signal", "server_ns": "wan", "net": "failover", "flow": "failover", "udp_blocked": False, "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    "denied-blocked-standby": {"mode": "standby", "server_ns": "host_b", "net": "blocked", "flow": "denied-key", "udp_blocked": True, "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0, "client2_exit": 1},
    "dht-drop-signal": {"mode": "signal", "server_ns": "wan", "net": "dht-drop", "udp_blocked": False, "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    "outage-standby": {"mode": "standby", "server_ns": "host_b", "net": "blocked", "udp_blocked": True, "ygg_client_blocked": True, "target_accepts": 0, "client_exit": 1},
    # Double NAT with Native UDP allowed (A5 endpoint-independent port-preserving mapping, A6 fully random ports).
    # "nat" is the mapping flavor, "direct" whether a direct Native path between the routers is expected (dispatch 43255837358 showed
    # it is not: the cone cases first expected a punch and failed; "relay_first" drops the Client's DHT queries so relay negotiation is reached).
    # The four relay-configured cone cases (A5) stay UNCHANGED on purpose, also after leaf L4b: they drop the Client's DHT
    # answers (or never publish a reflexive address), so neither side has a reflexive candidate to exchange over the
    # relay carrier, and they block Ygg, so no other rendezvous exists. Their fail-closed expectation is the regression
    # control that a config naming a relay without any reflexive source behaves as before; the L4b proof is the
    # "relaypunch" pair below. Oracles change only after a preserved FAILED privileged run, never to force green.
    "dnat-cone-signal": {**DNAT, "mode": "signal", "nat": "cone", "direct": False, "ygg_client_blocked": True, "target_accepts": 0, "client_exit": 1},
    "dnat-cone-standby": {**DNAT, "mode": "standby", "nat": "cone", "direct": False, "ygg_client_blocked": True, "target_accepts": 0, "client_exit": 1},
    "dnat-cone-relay-signal": {**DNAT, "mode": "signal", "nat": "cone", "direct": False, "relay_first": True, "ygg_client_blocked": True,
                               "target_accepts": 0, "client_exit": 1},
    "dnat-cone-relay-standby": {**DNAT, "mode": "standby", "nat": "cone", "direct": False, "relay_first": True, "ygg_client_blocked": True,
                                "target_accepts": 0, "client_exit": 1},
    # The L4 punch cases. No relay config at all: the Server publishes the voted reflexive endpoint (publish_address: plain)
    # and the owned DHT fixture stamps BEP 42 votes (dht_observed). Rendezvous rides the Ygg bridge, so both norelay variants leave Ygg transit open and
    # require Ygg TCP traffic (rendezvous) instead of zero; signal mode still carries no Ygg payload, proven by the
    # peer counters and the native route line.
    "dnat-cone-norelay-signal": {**DNAT, "mode": "signal", "nat": "cone", "direct": True, "norelay": True, "dht_observed": True,
                                 "publish": "plain", "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    "dnat-cone-norelay-standby": {**DNAT, "mode": "standby", "nat": "cone", "direct": True, "norelay": True, "dht_observed": True,
                                  "publish": "plain", "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    # The L4b punch cases: the relay is pinned in both configs, Ygg is closed to the Client, and the voted reflexive endpoint
    # is published, so the only rendezvous is the carrier link of the relay circuit (signaling only). Expected: direct path.
    "dnat-cone-relaypunch-signal": {**DNAT, "mode": "signal", "nat": "cone", "direct": True, "relay_punch": True, "dht_observed": True,
                                    "publish": "plain", "ygg_client_blocked": True, "target_accepts": 1, "client_exit": 0},
    "dnat-cone-relaypunch-standby": {**DNAT, "mode": "standby", "nat": "cone", "direct": True, "relay_punch": True, "dht_observed": True,
                                     "publish": "plain", "ygg_client_blocked": True, "target_accepts": 1, "client_exit": 0},
    # Fail-closed guard: cone NAT with DHT responses denied on the Client side must fail closed again, proving the
    # flip depends on the reflexive source, not a harness accident.
    # It is the norelay-signal case with ONLY the Client's DHT answers dropped: no record, no reflexive vote, nothing to offer.
    "dnat-cone-dhtdrop-signal": {**DNAT, "mode": "signal", "nat": "cone", "direct": False, "norelay": True, "dht_observed": True,
                                 "publish": "plain", "dht_denied": True, "ygg_client_blocked": False, "target_accepts": 0, "client_exit": 1},
    # The L3b pair: the relay-less punch pair with the Server publishing the SEALED record (publish_address: encrypted) and the
    # Client holding the key. The record the WAN helper stored carries no plain address (checked on its real bytes, see
    # validate_publication) and the Client route line must show a candidate resolved from the record, so the key opened it.
    # Expected: the same direct path as the plain pair. The oracle was written before any run.
    "dnat-cone-encrypted-signal": {**DNAT, "mode": "signal", "nat": "cone", "direct": True, "norelay": True, "dht_observed": True,
                                   "publish": "encrypted", "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    "dnat-cone-encrypted-standby": {**DNAT, "mode": "standby", "nat": "cone", "direct": True, "norelay": True, "dht_observed": True,
                                    "publish": "encrypted", "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    # The DIRECT-T trio. With the mapping granted the Client reaches the Server over a direct path and the exact payload crosses
    # (both modes: Ygg is closed to the Client, so the direct path is the only one); with the gateway refusing, the same topology
    # must fail closed, so the mapping and not the harness made the difference. Oracles were written before any run.
    "dnat-mapped-signal": {**MAPPED, "mode": "signal", "gateway": "grant", "route_line": True, "target_accepts": 1, "client_exit": 0},
    "dnat-mapped-standby": {**MAPPED, "mode": "standby", "gateway": "grant", "route_line": True, "target_accepts": 1, "client_exit": 0},
    "dnat-mapped-refused-signal": {**MAPPED, "mode": "signal", "gateway": "refuse", "target_accepts": 0, "client_exit": 1},
    # Deliberate A6 negative control: fully random port mappings, must NOT flip.
    "dnat-sym-signal": {**DNAT, "mode": "signal", "nat": "random", "direct": False, "ygg_client_blocked": False, "target_accepts": 0, "client_exit": 1},
    "dnat-sym-standby": {**DNAT, "mode": "standby", "nat": "random", "direct": False, "ygg_client_blocked": False, "target_accepts": 1, "client_exit": 0},
    # Single NAT; APP 1, a runtime perturbation, APP 2 over Native only (Ygg denied on the Client side).
    "hole-signal": {**NATIVE, "mode": "signal", "flow": "hole", "target_accepts": 2},
    "hole-standby": {**NATIVE, "mode": "standby", "flow": "hole", "target_accepts": 2},
    "switch-signal": {**NATIVE, "mode": "signal", "flow": "switch", "client_bind": "0.0.0.0", "target_accepts": 2},
    "switch-standby": {**NATIVE, "mode": "standby", "flow": "switch", "client_bind": "0.0.0.0", "target_accepts": 2},
    # The relay fixture allows two reservations; two extra Servers hold them, so the real Server cannot start.
    "relay-full-signal": {"mode": "signal", "server_ns": "wan", "net": "relay", "flow": "relay-full", "udp_blocked": False, "ygg_client_blocked": False,
                          "target_accepts": 0, "client_exit": None, "fillers": 2, "server_exit": 1},
    "relay-full-standby": {"mode": "standby", "server_ns": "wan", "net": "relay", "flow": "relay-full", "udp_blocked": False, "ygg_client_blocked": False,
                           "target_accepts": 0, "client_exit": None, "fillers": 2, "server_exit": 1},
    # "hint": the Client dials the Server's published IPv6 candidate (explicit direct-address hint) while IPv4 Native UDP between the hosts is
    # dropped for the whole case. Without the hint the key-only dial tries the published IPv4 candidate first, and a silent one stalls the attempt.
    "ipv6-signal": {**LAN, "mode": "signal", "net": "ipv6", "flow": "ipv6", "hint": "v6"},
    "ipv6-standby": {**LAN, "mode": "standby", "net": "ipv6", "flow": "ipv6", "hint": "v6"},
    "denied-native-signal": {**NATIVE, "mode": "signal", "flow": "denied-key", "client2_exit": 1},
    "recover-standby": {"mode": "standby", "server_ns": "wan", "net": "recover", "flow": "outage-recovery", "udp_blocked": False, "ygg_client_blocked": False,
                        "target_accepts": 1, "client_exit": 1, "client2_exit": 0},
}
IPS = {"wan": "203.0.113.10", "rtr_a_wan": "203.0.113.1", "rtr_b_wan": "203.0.113.2",
       "rtr_off_wan": "203.0.113.3", "host_a": "10.0.1.2", "host_b": "10.0.2.2", "host_off": "10.0.3.2"}
SUFFIXES = {"wan": "wan", "host_a": "host-a", "host_b": "host-b", "rtr_a": "rtr-a",
            "rtr_b": "rtr-b", "host_off": "host-off", "rtr_off": "rtr-off"}
IP_KEYS = {"rtr_a": "rtr_a_wan", "rtr_b": "rtr_b_wan"}
# The Server's default router on its LAN: where the Server's PCP and SSDP datagrams go (the PCP gateway of the mapped cases listens here).
ROUTER_LAN = {"rtr_b": "10.0.2.1"}
TRANSLATED_RANGE = (41010, 41020)
# Long-lived owned children whose /proc privilege receipt is read; short-lived keys/app/stop workers are not sampled.
IDENTITY_ROLES = ("wan", "target", "server", "client")
FAILOVER_SECONDS = 10.0
RECOVERY_SECONDS = 40.0
MAX_CHILDREN = 16
MAX_LINE = 8192
MAX_LOG = 1024 * 1024
MAX_REPORT = 65536
CASE_SECONDS = 150
ACTIVE_SECONDS = 90
PHASE_SECONDS = 1200
CLEANUP_RESERVE = 45
FRONT_PORT = 48001
TARGET_PORT = 48002
# Per router and case and traffic class: every dispatch group allocates at most 56 MiB (base: 12 cases + 2 live controls) of the 64 MiB phase budget.
PRODUCT_QUOTA = 2 * 1024 * 1024
FAULT_QUOTA = 2 * 1024 * 1024
# Typed Server startup error when the relay has no reservation left (StartupError::RelayReserve in crates/shaar).
RESERVE_FAIL = b"relay reservation failed at startup"
REQUEST_PREFIX = b"shaar-controlled-request:"
REPLY_PREFIX = b"shaar-fixed-target-reply:"
# Leaf L5 fixture part: the owned Mainline DHT fixture (the identity-helper "wan" role answering
# on dht_port) can stamp every KRPC reply with the requester's compact IPv4 endpoint (the BEP 42
# `ip` field), exactly like a real node. The fixture option is OFF by default and unreachable
# from every case unless the case opts in with the "dht_observed" spec key; the wan helper then reads DHT_OBSERVED_ENV=1 and chains the fixture option, and
# child_environment allows the name only together with the new L3/L4 cases, so accepted responses stay
# byte-identical otherwise.
DHT_OBSERVED_KEY = "dht_observed"
DHT_OBSERVED_ENV = "SHAAR_NAT_DHT_OBSERVED"
# Client stdout markers of the L4 punch (candidates line ending on the direct outcome) and the chosen route.
# Every attempt prints PUNCH_TRACE + "<n> outcome=direct|fallback ..."; early attempts may end on fallback (no candidates
# before the first reflexive vote), so the harness records the first line that ENDED direct (needle PUNCH_DIRECT).
PUNCH_TRACE = "shaar: client punch candidates="
PUNCH_DIRECT = "outcome=direct"
ROUTE_LINE = "shaar-client: route path=native"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ip_for(namespace):
    """Address a product binds in an owned namespace; router namespaces use their WAN-segment address."""
    return IPS[IP_KEYS.get(namespace, namespace)]


def client_ns(spec):
    return spec.get("client_ns", "host_a")


def client_bind(spec):
    """DHT/signaling bind address of the Client: its namespace address unless the case needs a wildcard socket."""
    return spec.get("client_bind") or ip_for(client_ns(spec))


def server_fails(spec):
    """True when the Server is expected to end on its own during startup (typed failure)."""
    return spec.get("server_exit", 0) != 0


def final_client_exit(spec):
    """Exit status of the Client that is alive at shutdown (the second Client when a case replaces it)."""
    return spec.get("client2_exit", spec["client_exit"])


def identity_roles(spec):
    roles = [role for role in IDENTITY_ROLES if role != "client" or spec["client_exit"] is not None]
    if spec.get("flow") in ("denied-key", "outage-recovery"):
        roles.append("client2")
    return tuple(roles) + tuple(f"filler{index}" for index in range(1, spec.get("fillers", 0) + 1))


def hex_value(value, size):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None


def validate_config(config, source, case):
    require(hex_value(source, 40) and case in CASES, "unreviewed product source/case")
    require(hex_value(config.get("nonce"), 32), "invalid case nonce")
    prefix = config.get("prefix", "")
    require(re.fullmatch(r"sn[0-9a-f]{6}", prefix) is not None, "invalid owned namespace prefix")
    require(config.get("ns") == {key: prefix + "-" + value for key, value in SUFFIXES.items()},
            "namespace inventory differs from the owned topology")
    require(config.get("ip") == IPS and config.get("translated_ports") == [41010, 41020],
            "address/translation targets differ from the controlled contract")
    for value in config["ip"].values():
        ipaddress.IPv4Address(value)
    require(type(config.get("run_pid")) is int and config["run_pid"] > 0, "missing owned setup PID")
    require(type(config.get("helper_uid")) is int and config["helper_uid"] > 0
            and type(config.get("helper_gid")) is int and config["helper_gid"] > 0,
            "normal products must use the unprivileged caller identity")
    root = Path(config["out_dir"]).resolve(strict=True)
    allowed = Path(__file__).resolve().parents[2] / "out"
    require(root != allowed and root.is_relative_to(allowed), "case output escapes the owned out directory")
    require(root.is_dir(), "case output directory missing")
    return root


def bounded_json(path, cap=MAX_REPORT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= cap,
                "evidence must be a bounded regular file")
        data = stream.read(cap + 1)
    require(len(data) <= cap, "evidence changed beyond its byte budget")
    return json.loads(data)


def file_digest(path, cap=1024 * 1024 * 1024):
    result, count = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= cap, "unbounded/nonregular product artifact")
        while True:
            block = stream.read(min(1024 * 1024, cap + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= cap, "product grew beyond the artifact byte budget")
            result.update(block)
    return result.hexdigest()


def validate_manifest(manifest, source):
    require(manifest.get("source_revision") == source and hex_value(source, 40), "product manifest source mismatch")
    require(manifest.get("normal_native_gate_enabled") is False, "normal product test gate must remain OFF")
    products = manifest.get("products", {})
    require(set(products) == {"shaar-server", "shaar-client", "identity-helper"}, "compiled product set mismatch")
    for name, product in products.items():
        require(hex_value(product.get("sha256"), 64) and type(product.get("bytes")) is int
                and 0 < product["bytes"] <= 1024 * 1024 * 1024, "product digest/size malformed")
        path = Path(product.get("executable", ""))
        require(path.is_absolute(), "product executable must be an absolute reviewed build artifact")
        if name != "identity-helper":
            require(product.get("profile_test") is False
                    and product.get("source_path", "").replace(chr(92), "/").endswith("/crates/" + name + "/src/main.rs"),
                    "normal product source/profile provenance mismatch")
    return products


def validate_ready(event, role, nonce, pid):
    require(event.get("role") == role and event.get("nonce") == nonce and event.get("pid") == pid,
            "helper role/nonce/owned PID mismatch")
    if role == "keys":
        require(hex_value(event.get("server_key"), 64) and hex_value(event.get("client_key"), 64)
                and event["server_key"] != event["client_key"], "provisioned public identities invalid")
    elif role == "wan":
        ports = [event.get(key) for key in ("dht_port", "relay_port", "transit_port", "control_port")]
        require(all(type(value) is int and 1024 <= value <= 65535 for value in ports), "WAN helper ports invalid")
        peer = event.get("relay_peer", "")
        require(type(peer) is str and 1 <= len(peer) <= 100 and peer.isascii() and peer.isalnum(),
                "WAN relay public identity malformed")
    elif role == "gateway":
        require(event.get("mode") in ("grant", "refuse"), "PCP gateway mode invalid")
    elif role not in ("target", "app"):
        raise ValueError("unreviewed helper role")


def validate_publication(event, nonce, server_key, sealed=False):
    require(hex_value(server_key, 64), "invalid expected service public key")
    require(event.get("nonce") == nonce and type(event.get("sequence")) is int and 0 <= event["sequence"] < 2 ** 63,
            "publication nonce/sequence mismatch")
    envelope = event.get("signed_envelope_hex", "")
    require(type(envelope) is str and 208 <= len(envelope) <= 2208 and len(envelope) % 2 == 0
            and re.fullmatch("[0-9a-f]+", envelope) is not None and envelope.startswith(server_key),
            "actual helper-verified signed publication envelope malformed")
    require(int.from_bytes(bytes.fromhex(envelope)[96:104], "big") == event["sequence"],
            "publication sequence differs from the observed signed envelope")
    addresses = event.get("native_addresses", [])
    if sealed:
        # Encrypted publication: the stored signed record holds a sealed value and no plain address, and none of the owned
        # addresses appears in its real bytes, neither as text nor as octets.
        require(event.get("sealed") is True and addresses == [], "the encrypted publication is not a sealed record without plain addresses")
        raw = bytes.fromhex(envelope)
        for value in IPS.values():
            octets = bytes(int(part) for part in value.split("."))
            require(value.encode("ascii") not in raw and octets not in raw, "an owned address appears in the sealed record")
        return event
    require(event.get("sealed", False) is False, "the plain publication is unexpectedly sealed")
    require(type(addresses) is list and 1 <= len(addresses) <= 4
            and all(type(value) is str and 1 <= len(value) <= 100 for value in addresses),
            "actual signed Server publication lacks bounded Native addresses")
    # Cryptographic verification is performed by the reused Rust pkarr codec, not reimplemented here.
    return event
