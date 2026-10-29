"""Conservative change-to-proof policy; full campaigns require explicit dispatch."""

DOMAINS = ("dns", "discovery", "carrier", "relay", "resolver", "kad", "backend", "sdk", "apps", "license")
P2P = {"dns", "discovery", "carrier", "relay", "resolver", "kad"}
ALL = set(DOMAINS)


def domains_for(path):
    if not path or path.startswith("/") or ".." in path.split("/"):
        return ALL.copy(), "unrecognized path"
    if path.endswith(".md"):
        return set(), "documentation"
    if path in {"LICENSE-MIT", "LICENSE-APACHE"}:
        return {"license"}, "project license"
    if path.startswith((".github/actions/dependency-license/", ".github/deny.toml",
                        ".github/scripts/dependency_licenses.py",
                        ".github/scripts/tests/test_dependency_licenses.py",
                        ".github/scripts/tests/test_notice_evidence.py")):
        return {"license"}, "license policy"
    if path.startswith("crates/shaar-p2p/src/dns/tests/"):
        return {"dns", "discovery", "carrier"}, "DNS fixtures and consumers"
    if path.startswith("crates/shaar-p2p/src/dns/"):
        return {"dns", "discovery", "carrier", "sdk", "apps"}, "owned DNS and consumers"
    if path.startswith("crates/shaar-p2p/src/discovery/"):
        return {"discovery", "carrier", "sdk", "apps"}, "discovery and Carrier boundary"
    if path.startswith("crates/shaar-p2p/") and not path.endswith("Cargo.toml"):
        return P2P | {"sdk", "apps"}, "shared p2p runtime"
    if path.startswith(".github/scripts/p2p/discovery/resolver/"):
        return {"resolver", "dns", "discovery", "carrier", "sdk", "apps"}, "resolver dependency"
    if path.startswith(".github/scripts/p2p/discovery/kad/"):
        return {"kad", "discovery", "carrier", "sdk", "apps"}, "Kademlia dependency"
    if path.startswith(".github/scripts/p2p/discovery/dns/"):
        return {"dns", "discovery", "carrier", "sdk", "apps"}, "DNS transport dependency"
    if path.startswith(".github/scripts/p2p/carrier-wire-proof/"):
        return {"carrier"}, "Carrier wire proof"
    if path.startswith(".github/scripts/p2p/relay/"):
        return {"relay", "carrier", "discovery", "sdk", "apps"}, "relay dependency"
    if path.startswith((".github/scripts/backend/", ".github/scripts/tests/noq_driver/",
                        ".github/probes/iroh-paths/gate/")):
        return {"backend", "sdk", "apps"}, "native backend and consumers"
    if path.startswith("crates/shaar/src/network/signaling/"):
        return {"sdk", "apps", "carrier", "relay", "discovery"}, "SDK signaling integration"
    if path.startswith(("crates/shaar/", "crates/shaar-platform/", "crates/shaar-server/",
                        "crates/shaar-client/", "crates/shaar-ygg/")) and not path.endswith("Cargo.toml"):
        return {"sdk", "apps"}, "SDK and application consumers"
    return ALL.copy(), "shared or unclassified source"


def select(paths, *, full=False, fallback=None):
    selected = ALL.copy() if full or fallback else set()
    reasons = []
    for path in sorted(set(paths)):
        domains, reason = domains_for(path)
        selected.update(domains)
        reasons.append({"path": path, "domains": sorted(domains), "reason": reason})
    if not paths and not full:
        selected = ALL.copy()
        fallback = fallback or "no changed paths established"
    flags = {name: name in selected for name in DOMAINS}
    flags.update(full=full, p2p=bool(selected & P2P))
    flags["rust"] = any(flags[name] for name in DOMAINS if name != "license")
    flags["prepare"] = flags["rust"] or flags["license"]
    return {"selection": flags, "fallback": fallback, "reasons": reasons}
