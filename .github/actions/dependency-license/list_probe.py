"""Summarize a bounded cargo-deny list; this is graph evidence only."""
import json
import sys

MAX_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 4096
MAX_ID_LENGTH = 4096
NAMES = (
    "iroh", "noq", "noq-proto", "hickory-resolver", "libp2p-dns",
    "libp2p-kad", "libp2p-relay", "libp2p-swarm", "attohttpc",
)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


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
    if not any(item.startswith("iroh 1.3.0 path+file:") for item in selected["iroh"]):
        raise ValueError("prepared iroh missing from license list")
    return {"package_count": len(data), "selected": selected}


if __name__ == "__main__":
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    print(json.dumps(summarize(raw), sort_keys=True, ensure_ascii=True))
