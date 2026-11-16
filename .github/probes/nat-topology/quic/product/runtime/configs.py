"""Pure ktav 0.8 Server/Client configuration text for the controlled product cases."""

from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import contract  # noqa: E402

PATH_PATTERN = r"/[A-Za-z0-9_./-]{1,200}"
WILDCARD = "0.0.0.0"


def owned_path(value):
    """Absolute plain path; no whitespace/quoting that could change the ktav structure."""
    contract.require(type(value) is str and re.fullmatch(PATH_PATTERN, value) is not None and ".." not in value.split("/"),
                     "configuration path must be a plain absolute path")
    return value


def network_text(bind_ip, ports, relay_peer=None):
    """Shared network object: owned DHT, relay and Ygg transit on the WAN address only; relay_peer None omits the relay."""
    wan = contract.IPS["wan"]
    contract.require(bind_ip in contract.IPS.values() or bind_ip == WILDCARD, "bind address outside the owned plan")
    contract.require(type(ports) is dict and set(ports) >= {"dht", "relay", "transit"}
                     and all(type(ports[key]) is int and 1024 <= ports[key] <= 65535 for key in ("dht", "relay", "transit")),
                     "owned WAN fixture ports invalid")
    contract.require(relay_peer is None or (type(relay_peer) is str
                     and re.fullmatch("[A-Za-z0-9]{1,100}", relay_peer) is not None), "relay identity malformed")
    signaling = ["signaling: {", f"bind: {bind_ip}:0"]
    if relay_peer is not None:
        signaling += [f"relay: {relay_peer}", f"relay_address: {wan}:{ports['relay']}"]
    lines = ["network: {", "mainline: {", f"bind: {bind_ip}:0", "bootstrap: [", f"{wan}:{ports['dht']}", "]", "}"]
    lines += signaling + ["}", "ygg: {", "peers: [", f"tcp://{wan}:{ports['transit']}", "]", "}", "}"]
    return "\n".join(lines) + "\n"


def mode_value(mode):
    contract.require(mode in ("signal", "standby"), "unreviewed fallback mode")
    return mode


def relay_binding(case, relay_peer):
    """Relay fields present in the config must match the case's expectation, in both directions."""
    spec = contract.CASES[case]
    norelay = bool(spec.get("norelay"))
    contract.require((relay_peer is None) == norelay, "relay fields present/absent contradict the case")
    return relay_peer


def server_text(case, key_file, allowlist_file, ports, relay_peer, ns=None, address_key=None):
    """ns: namespace the Server runs in when it differs from the case's Server namespace (relay filler Servers).
    address_key: key file of the encrypted publication; required exactly when the case publishes encrypted."""
    spec = contract.CASES[case]
    bind_ip = contract.ip_for(ns or spec["server_ns"])
    head = [f"target: 127.0.0.1:{contract.TARGET_PORT}"]
    publish = spec.get("publish")
    contract.require((address_key is not None) == (publish == "encrypted"), "the key file and the encrypted publication go together")
    if publish == "plain":
        head.append("publish_address: plain")
    elif publish == "encrypted":
        head += ["publish_address: encrypted", f"address_key_file:: {owned_path(address_key)}"]
    head += [f"allowlist_path:: {owned_path(allowlist_file)}",
             f"key_file:: {owned_path(key_file)}", f"fallback: {mode_value(spec['mode'])}"]
    return "\n".join(head) + "\n" + network_text(bind_ip, ports, relay_binding(case, relay_peer))


def client_text(case, server_key, key_file, ports, relay_peer, hint=None, address_key=None):
    """The Client names only the Server public key; hint (an IPv6 socket address) is the optional direct-address hint of the IPv6 cases."""
    spec = contract.CASES[case]
    contract.require(contract.hex_value(server_key, 64), "Server key must be 64 lowercase hex characters")
    head = [f"server: {server_key}", f"listen: 127.0.0.1:{contract.FRONT_PORT}",
            f"key_file:: {owned_path(key_file)}", f"fallback: {mode_value(spec['mode'])}"]
    if hint is not None:
        contract.require(type(hint) is str and re.fullmatch(r"\[[0-9a-f:]{2,39}\]:[0-9]{1,5}", hint) is not None, "invalid IPv6 direct-address hint")
        head.append(f"server_address:: {hint}")
    # The Client of an encrypted case holds the key that opens the Server's record; no other case names a key file.
    contract.require((address_key is not None) == (spec.get("publish") == "encrypted"), "the Client key file and the encrypted publication go together")
    if address_key is not None:
        head.append(f"address_key_file:: {owned_path(address_key)}")
    return "\n".join(head) + "\n" + network_text(contract.client_bind(spec), ports, relay_binding(case, relay_peer))


def allowlist_text(client_key):
    contract.require(contract.hex_value(client_key, 64), "allowlisted key must be 64 lowercase hex characters")
    return client_key + "\n"
