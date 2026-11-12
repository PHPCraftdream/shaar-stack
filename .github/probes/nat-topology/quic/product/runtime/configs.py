"""Pure ktav 0.8 Server/Client configuration text for the controlled product cases."""

from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import contract  # noqa: E402

PATH_PATTERN = r"/[A-Za-z0-9_./-]{1,200}"


def owned_path(value):
    """Absolute plain path; no whitespace/quoting that could change the ktav structure."""
    contract.require(type(value) is str and re.fullmatch(PATH_PATTERN, value) is not None and ".." not in value.split("/"),
                     "configuration path must be a plain absolute path")
    return value


def network_text(bind_ip, ports, relay_peer):
    """Shared network object: owned DHT, relay and Ygg transit on the WAN address only."""
    wan = contract.IPS["wan"]
    contract.require(bind_ip in contract.IPS.values(), "bind address outside the owned plan")
    contract.require(type(ports) is dict and set(ports) >= {"dht", "relay", "transit"}
                     and all(type(ports[key]) is int and 1024 <= ports[key] <= 65535 for key in ("dht", "relay", "transit")),
                     "owned WAN fixture ports invalid")
    contract.require(type(relay_peer) is str and re.fullmatch("[A-Za-z0-9]{1,100}", relay_peer) is not None,
                     "relay identity malformed")
    lines = ["network: {", "mainline: {", f"bind: {bind_ip}:0", "bootstrap: [", f"{wan}:{ports['dht']}", "]", "}",
             "signaling: {", f"bind: {bind_ip}:0", f"relay: {relay_peer}", f"relay_address: {wan}:{ports['relay']}", "}",
             "ygg: {", "peers: [", f"tcp://{wan}:{ports['transit']}", "]", "}", "}"]
    return "\n".join(lines) + "\n"


def mode_value(mode):
    contract.require(mode in ("signal", "standby"), "unreviewed fallback mode")
    return mode


def server_text(case, key_file, allowlist_file, ports, relay_peer):
    spec = contract.CASES[case]
    bind_ip = contract.ip_for(spec["server_ns"])
    head = [f"target: 127.0.0.1:{contract.TARGET_PORT}", f"allowlist_path:: {owned_path(allowlist_file)}",
            f"key_file:: {owned_path(key_file)}", f"fallback: {mode_value(spec['mode'])}"]
    return "\n".join(head) + "\n" + network_text(bind_ip, ports, relay_peer)


def client_text(case, server_key, key_file, ports, relay_peer):
    """The Client names only the Server public key: no server_address hint exists here."""
    spec = contract.CASES[case]
    contract.require(contract.hex_value(server_key, 64), "Server key must be 64 lowercase hex characters")
    head = [f"server: {server_key}", f"listen: 127.0.0.1:{contract.FRONT_PORT}",
            f"key_file:: {owned_path(key_file)}", f"fallback: {mode_value(spec['mode'])}"]
    return "\n".join(head) + "\n" + network_text(contract.ip_for(contract.client_ns(spec)), ports, relay_peer)


def allowlist_text(client_key):
    contract.require(contract.hex_value(client_key, 64), "allowlisted key must be 64 lowercase hex characters")
    return client_key + "\n"
