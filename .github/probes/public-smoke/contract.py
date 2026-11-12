"""Public-network smoke contract: dispatch validation, budgets and config rendering.

Pure and stdlib only. `contract.json` can only tighten the ceilings below: the
ceilings are the user's 2026-11-04 conditional public-smoke bounds, restated here
so that editing the JSON alone can never widen them.
"""

import hashlib
import ipaddress
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACT_PATH = HERE / "contract.json"
MIB = 1024 * 1024

# Ceilings per job (two jobs per dispatch: 2 x 5 MiB = the 10 MiB per-run bound).
CEILINGS = {
    "runs_per_dispatch": 1, "retries": 0, "runners": 2, "job_seconds": 300, "product_window_s": 120,
    "mainline_bootstrap": 2, "ygg_peers": 2, "relay_peers": 1,
    "per_job": {"nic_bytes": 5 * MIB, "ygg_tcp_bytes": 3 * MIB, "relay_tcp_bytes": 256 * 1024,
                "dht_udp_bytes": 3 * MIB // 2, "ygg_connections": 2, "relay_connections": 2},
    "app": {"exchanges": 1, "request_bytes_max": 128, "reply_bytes_max": 128, "payload_bytes_max": 64 * 1024},
    "sample_interval_ms": (100, 2000),
}
TIMELINE_KEYS = ("server_launch_deadline_s", "client_start_offset_s", "client_ready_wait_s",
                 "client_exchange_s", "shutdown_grace_s", "server_end_offset_s")
HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PEER_URI = re.compile(r"^tcp://((?:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}):([0-9]{1,5})$")
PEER_ID = re.compile(r"^12D3KooW[1-9A-HJ-NP-Za-km-z]{44}$")
RELAY_ADDRESS = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})$")
REVISION = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"[0-9]{1,20}")


class ContractError(ValueError):
    """Invalid contract or dispatch; never carries secrets."""


class Blocked(ContractError):
    """The contract is well-formed but not yet approved for execution."""


def _port(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ContractError(what + ": port out of range")
    return value


def _text(entry, field, what):
    value = entry.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > 600:
        raise ContractError(f"{what}: field {field} must be a non-empty bounded string")


def public_ipv4(value):
    """True only for a globally routable IPv4 literal."""
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _exact_keys(mapping, keys, what):
    if not isinstance(mapping, dict) or set(mapping) != set(keys):
        raise ContractError(what + ": unexpected or missing fields")


def _bounded(mapping, ceilings, what):
    for name, limit in ceilings.items():
        value = mapping[name]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= limit:
            raise ContractError(f"{what}.{name}: must be an integer in 1..{limit}")


def validate_contract(contract):
    """Strict schema and ceiling check; returns the contract unchanged."""
    _exact_keys(contract, ("schema", "scope", "approval", "targets", "budgets"), "contract")
    if contract["schema"] != 1 or contract["scope"] != "public-smoke-v1":
        raise ContractError("contract: unsupported schema or scope")
    targets = contract["targets"]
    _exact_keys(targets, ("mainline_bootstrap", "ygg_peers", "libp2p_relay"), "targets")
    boot, peers = targets["mainline_bootstrap"], targets["ygg_peers"]
    if not isinstance(boot, list) or not 1 <= len(boot) <= CEILINGS["mainline_bootstrap"]:
        raise ContractError("targets.mainline_bootstrap: 1..2 exact hosts")
    if not isinstance(peers, list) or not 1 <= len(peers) <= CEILINGS["ygg_peers"]:
        raise ContractError("targets.ygg_peers: 1..2 exact peers")
    seen = set()
    for entry in boot:
        _exact_keys(entry, ("host", "port", "operator", "basis"), "bootstrap entry")
        if not isinstance(entry["host"], str) or not HOST.match(entry["host"]):
            raise ContractError("bootstrap entry: invalid host")
        _port(entry["port"], "bootstrap entry")
        _text(entry, "operator", "bootstrap entry")
        _text(entry, "basis", "bootstrap entry")
        seen.add((entry["host"], entry["port"]))
    for entry in peers:
        _exact_keys(entry, ("uri", "operator", "basis"), "ygg peer")
        match = PEER_URI.match(entry["uri"]) if isinstance(entry["uri"], str) else None
        if not match:
            raise ContractError("ygg peer: only plain tcp://host:port without query is allowed")
        _port(int(match[3]), "ygg peer")
        _text(entry, "operator", "ygg peer")
        _text(entry, "basis", "ygg peer")
        seen.add(entry["uri"])
    if len(seen) != len(boot) + len(peers):
        raise ContractError("targets: duplicate entries")
    relay = targets["libp2p_relay"]
    if relay is not None:
        _exact_keys(relay, ("peer_id", "address", "operator", "basis"), "relay")
        if not isinstance(relay["peer_id"], str) or not PEER_ID.match(relay["peer_id"]):
            raise ContractError("relay: peer_id must be a base58 Ed25519 PeerId (12D3KooW...)")
        match = RELAY_ADDRESS.match(relay["address"]) if isinstance(relay["address"], str) else None
        if not match or not public_ipv4(match[1]):
            raise ContractError("relay: address must be a public IPv4 literal with a port")
        _port(int(match[2]), "relay")
        _text(relay, "operator", "relay")
        _text(relay, "basis", "relay")
    approval = contract["approval"]
    if approval is not None:
        _exact_keys(approval, ("date", "quote", "decision_log"), "approval")
        if not isinstance(approval["date"], str) or not re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", approval["date"]):
            raise ContractError("approval: date must be YYYY-MM-DD")
        _text(approval, "quote", "approval")
        _text(approval, "decision_log", "approval")
    _validate_budgets(contract["budgets"])
    return contract


def _validate_budgets(budgets):
    _exact_keys(budgets, ("runs_per_dispatch", "retries", "runners", "job_seconds", "timeline",
                          "per_job", "app", "sample_interval_ms"), "budgets")
    if budgets["runs_per_dispatch"] != 1 or budgets["retries"] != 0 or budgets["runners"] != 2:
        raise ContractError("budgets: exactly one run, zero retries, two runners")
    _bounded(budgets, {"job_seconds": CEILINGS["job_seconds"]}, "budgets")
    _exact_keys(budgets["per_job"], CEILINGS["per_job"], "budgets.per_job")
    _bounded(budgets["per_job"], CEILINGS["per_job"], "budgets.per_job")
    _exact_keys(budgets["app"], CEILINGS["app"], "budgets.app")
    _bounded(budgets["app"], CEILINGS["app"], "budgets.app")
    low, high = CEILINGS["sample_interval_ms"]
    if not isinstance(budgets["sample_interval_ms"], int) or not low <= budgets["sample_interval_ms"] <= high:
        raise ContractError("budgets.sample_interval_ms out of range")
    line = budgets["timeline"]
    _exact_keys(line, TIMELINE_KEYS, "budgets.timeline")
    _bounded(line, {name: budgets["job_seconds"] for name in TIMELINE_KEYS}, "budgets.timeline")
    client_exchange_end = (line["client_start_offset_s"] + line["client_ready_wait_s"]
                           + line["client_exchange_s"])
    client_window = line["client_ready_wait_s"] + line["client_exchange_s"] + line["shutdown_grace_s"]
    if line["server_launch_deadline_s"] >= line["client_start_offset_s"]:
        raise ContractError("timeline: the Server must launch before the Client starts")
    if client_exchange_end + 5 > line["server_end_offset_s"]:
        raise ContractError("timeline: the Server window must outlast the Client exchange")
    window = CEILINGS["product_window_s"]
    if line["server_end_offset_s"] + line["shutdown_grace_s"] > window or client_window > window:
        raise ContractError("timeline: a product process may run at most 120 s")


def load_contract(path=CONTRACT_PATH):
    """Read the contract bytes once; return (validated contract, SHA-256 of the exact bytes)."""
    data = Path(path).read_bytes()
    if len(data) > 64 * 1024:
        raise ContractError("contract file is too large")
    try:
        contract = json.loads(data)
    except ValueError as error:
        raise ContractError("contract is not valid JSON") from error
    return validate_contract(contract), hashlib.sha256(data).hexdigest()


def blockers(contract):
    """Why the contract cannot run yet (empty means runnable)."""
    found = []
    if contract["approval"] is None:
        found.append("no recorded user approval of these exact targets and budgets")
    if contract["targets"]["libp2p_relay"] is None:
        found.append("no libp2p relay target: the composed Server cannot start without a reservation")
    return found


def validate_dispatch(env, contract_digest):
    """Validate a workflow_dispatch request from environment text; fail closed, nothing else runs first."""
    def get(name):
        value = env.get(name)
        if not isinstance(value, str):
            raise ContractError(name + " is missing")
        return value

    if get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise ContractError("the public smoke runs only from workflow_dispatch")
    if not REVISION.fullmatch(get("SOURCE_REVISION")):
        raise ContractError("source_revision must be an exact 40-hex SHA")
    if get("GITHUB_RUN_ATTEMPT") != "1":
        raise ContractError("re-running is forbidden: one run per dispatch, no retries")
    for name in ("GITHUB_RUN_ID",):
        if not DECIMAL.fullmatch(get(name)):
            raise ContractError(name + " must be decimal")
    for name in ("DIRECT_FEEDBACK", "PREFLIGHT", "MATRIX"):
        if get(name) != "false":
            raise ContractError("the public smoke excludes the other dispatch modes")
    if get("PUBLIC_SMOKE") != "true":
        raise ContractError("public_smoke input is not set")
    supplied = get("CONTRACT_SHA256")
    if not DIGEST.fullmatch(supplied):
        raise ContractError("contract_sha256 must be 64 lowercase hex characters")
    if supplied != contract_digest:
        raise ContractError("contract_sha256 does not match the contract at this source revision")
    return {"revision": env["SOURCE_REVISION"], "run_id": env["GITHUB_RUN_ID"], "attempt": "1",
            "contract_sha256": supplied}


def require_runnable(contract):
    found = blockers(contract)
    if found:
        raise Blocked("; ".join(found))


def timeline(contract, t0):
    """Absolute epoch deadlines from the build-completion epoch."""
    line = contract["budgets"]["timeline"]
    return {"server_launch_by": t0 + line["server_launch_deadline_s"],
            "client_start_at": t0 + line["client_start_offset_s"],
            "server_end_at": t0 + line["server_end_offset_s"]}


def split_peer(uri):
    match = PEER_URI.match(uri)
    return match[1], int(match[3])


def render_network(bootstrap_ips, relay_peer, relay_address, peers):
    """`network` object text: bootstrap_ips are 'ip:port' strings, peers are tcp:// URIs."""
    lines = ["network: {", "    mainline: {", "        bootstrap: ["]
    lines += ["            " + item for item in bootstrap_ips]
    lines += ["        ]", "    }", "    signaling: {", "        relay: " + relay_peer,
              "        relay_address: " + relay_address, "    }", "    ygg: {", "        peers: ["]
    lines += ["            " + item for item in peers]
    lines += ["        ]", "    }", "}"]
    return "\n".join(lines) + "\n"


def render_server(target, network):
    return (f"target: {target}\nkey_file:: server.key\nallowlist_path:: allowlist.txt\n"
            "fallback: standby\n" + network)


def render_client(server_key_hex, listen, network):
    return (f"server: {server_key_hex}\nlisten: {listen}\nkey_file:: client.key\n"
            "fallback: standby\n" + network)


def app_request(nonce):
    return b"shaar-public-smoke/v1 req " + nonce.encode("ascii") + b"\n"


def app_reply(nonce):
    return b"shaar-public-smoke/v1 rep " + nonce.encode("ascii") + b"\n"
