"""Summarize a bounded cargo-deny list; this is graph evidence only."""
import json
from pathlib import Path
import sys
import tomllib
from urllib.parse import unquote

MAX_BYTES = 8 * 1024 * 1024
MAX_POLICY_BYTES = 64 * 1024
MAX_PACKAGES = 4096
MAX_ID_LENGTH = 4096
PREPARED = {
    "iroh": ("1.3.0", "target/backend/iroh/iroh-1.3.0"),
    "noq": ("1.3.0", "target/backend/noq/noq-1.3.0"),
    "noq-proto": ("1.3.0", "target/backend/noq-proto/noq-proto-1.3.0"),
    "hickory-resolver": ("0.26.3", "target/p2p/resolver/hickory-resolver-0.26.3"),
    "libp2p-dns": ("0.45.0", "target/p2p/dns/libp2p-dns-0.45.0"),
    "libp2p-kad": ("0.49.0", "target/p2p/kad/libp2p-kad-0.49.0"),
    "libp2p-relay": ("0.22.0", "target/p2p/relay/libp2p-relay-0.22.0"),
    "libp2p-swarm": ("0.48.0", "target/p2p/swarm/libp2p-swarm-0.48.0"),
}
NAMES = (*PREPARED, "attohttpc")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_policy(raw):
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("license policy exceeds limit")
    policy = tomllib.loads(raw.decode("utf-8"))
    graph = policy.get("graph", {})
    licenses = policy.get("licenses", {})
    if not isinstance(graph, dict) or not isinstance(licenses, dict):
        raise ValueError("invalid license policy")
    if graph.get("all-features") is not True:
        raise ValueError("license list requires all workspace features")
    if any(graph.get(key, False) is not False for key in (
        "no-default-features", "exclude-dev", "exclude-unpublished",
    )) or graph.get("features", []) != []:
        raise ValueError("license list graph options diverge from check")
    if licenses.get("include-dev") is not True or licenses.get("include-build") is not True:
        raise ValueError("license check must include workspace dev and build dependencies")


def summarize(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("license list exceeds limit")
    data = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or not data or len(data) > MAX_PACKAGES:
        raise ValueError("invalid license package list")
    selected = {name: [] for name in NAMES}
    for package_id, value in data.items():
        if not isinstance(package_id, str) or len(package_id) > MAX_ID_LENGTH:
            raise ValueError("invalid package identifier")
        if not isinstance(value, dict) or not isinstance(value.get("licenses"), list):
            raise ValueError("invalid package license entry")
        name = package_id.partition(" ")[0]
        if name in selected:
            selected[name].append(package_id)
    for name, (version, suffix) in PREPARED.items():
        matches = [item for item in selected[name] if item.startswith(f"{name} {version} ")]
        if len(matches) != 1 or not matches[0].startswith(f"{name} {version} path+file:"):
            raise ValueError(f"prepared {name} missing or ambiguous in license list")
        if not unquote(matches[0]).replace("\\", "/").endswith("/" + suffix):
            raise ValueError(f"prepared {name} has unexpected source path")
    return {"package_count": len(data), "selected": selected,
            "package_ids": sorted(data)}


if __name__ == "__main__":
    with Path(".github/deny.toml").open("rb") as policy_file:
        validate_policy(policy_file.read(MAX_POLICY_BYTES + 1))
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    summary = summarize(raw)
    if len(sys.argv) == 2:
        with Path(sys.argv[1]).open("xb") as output:
            output.write(raw)
    elif len(sys.argv) != 1:
        raise ValueError("expected optional list output path")
    print(json.dumps(summary, sort_keys=True, ensure_ascii=True))
