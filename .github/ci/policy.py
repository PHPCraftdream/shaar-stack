"""Explicit module ownership, not a transitive all-P2P test expansion."""

import re

DOMAINS = ("dns", "discovery", "mainline", "publication", "carrier", "carrier_frames", "relay", "resolver", "kad", "backend", "sdk", "apps", "license", "native_graph", "ygg")
PACKAGES = {
    "shaar-p2p": ("lib", "shaar_p2p"), "shaar": ("lib", "shaar"),
    "shaar-platform": ("lib", "shaar_platform"), "shaar-ygg": ("lib", "shaar_ygg"),
    "shaar-ygg-core": ("lib", "shaar_ygg_core"),
    "shaar-server": ("bin", "shaar-server"), "shaar-client": ("bin", "shaar-client"),
}
# Packages outside the root workspace: own manifest and lock, run by manifest path.
NESTED = {"shaar-ygg-core": "crates/shaar-ygg-core/Cargo.toml"}
# Manifests that link the Yggdrasil adapter into the guarded normal SDK graph; changing one runs the graph proof.
GRAPH_INPUTS = frozenset({"crates/shaar-ygg/Cargo.toml", "crates/shaar-ygg-core/Cargo.toml"})
SUITES = {
    "protocols": ("shaar-p2p", ("carrier::driver::protocols::", "infrastructure::tests::identification::")),
    "carrier-core": ("shaar-p2p", ("carrier::driver::tests::", "carrier::driver::fault_tests::", "carrier::driver::boundary::tests::", "carrier::driver::events::request_owner::tests::")),
    "infrastructure": ("shaar-p2p", ("carrier::driver::infrastructure::tests::",)),
    "carrier-admission": ("shaar-p2p", ("carrier_destination_",)),
    "roles": ("shaar-p2p", ("discovery::roles::",)),
    "contacts": ("shaar-p2p", ("discovery::roles::infrastructure::tests::contacts::",)),
    "discovery-config": ("shaar-p2p", ("discovery::tests::", "discovery_address_")),
    "addresses": ("shaar-p2p", ("discovery_address_",)),
    "destination-guard": ("shaar-p2p", ("destination_guard_",)),
    "owned-dns": ("shaar-p2p", ("owned_dns_", "wire_dns_")),
    "carrier-relay": ("shaar-p2p", ("carrier::driver::relay::", "carrier::driver::relay_")),
    "relay-gate": ("shaar-p2p", ("carrier::driver::roles_gate_tests::", "carrier::driver::roles_tests::",
                                 "infrastructure::tests::identification::handoff::")),
    "p2p-bridge": ("shaar-p2p", ("bridge::",)),
    "p2p-executor": ("shaar-p2p", ("executor::",)),
    "p2p-packet": ("shaar-p2p", ("packet::",)),
    "sdk-network": ("shaar", ("network::",)),
    "sdk-identity": ("shaar", ("identity::",)),
    "sdk-config": ("shaar", ("config::",)),
    "server-guide": ("shaar-server", ("tests::allowlist::",)),
    "sdk-signaling": ("shaar", ("network::signaling::",)),
    "sdk-admission": ("shaar", ("network::admission::",)),
    "sdk-forwarding": ("shaar", ("network::forwarding::",)),
    "native-discovery": ("shaar", ("native_discovery::",)),
    "sdk-path": ("shaar", ("path::",)),
    "sdk-startup": ("shaar", ("startup::",)),
    "startup-dht-contract": ("shaar", (
        "startup::tests::role_tests::lifecycle_cases::efficiency::"
        "known_and_cold_startup_measure_first_target_bytes_without_ready_route_bias",
    )),
}

# First matching owner wins. Shared wiring gets small contract suites, not SDK/dependency campaigns.
RULES = (
    ("crates/shaar-p2p/src/bridge/", ("p2p-bridge",)),
    ("crates/shaar-p2p/src/executor.rs", ("p2p-executor",)),
    ("crates/shaar-p2p/src/packet.rs", ("p2p-packet",)),
    ("crates/shaar/src/network/mod.rs", ("sdk-network",)),
    ("crates/shaar/src/network/session.rs", ("sdk-network",)),
    ("crates/shaar/src/network/error.rs", ("sdk-network",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/protocols/", ("protocols",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/infrastructure_tests/identification.rs", ("protocols",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/infrastructure", ("infrastructure",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/boundary", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/events.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/events/mod.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/events/request_owner.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/events/request_owner_tests.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/runtime/setup.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/mod.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/driver/admission_tests/", ("carrier-admission",)),
    ("crates/shaar-p2p/src/carrier/driver/roles_", ("carrier-admission",)),
    ("crates/shaar-p2p/src/carrier/driver/relay_", ("carrier-relay",)),
    ("crates/shaar-p2p/src/carrier/relay/gate", ("carrier-relay", "relay-gate")),
    ("crates/shaar-p2p/src/carrier/relay/", ("carrier-relay",)),
    ("crates/shaar-p2p/src/carrier/tests.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/fault_tests.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/carrier/admission.rs", ("carrier-admission", "infrastructure")),
    ("crates/shaar-p2p/src/carrier/mod.rs", ("carrier-core",)),
    ("crates/shaar-p2p/src/discovery/roles/infrastructure/tests/contacts.rs", ("contacts",)),
    ("crates/shaar-p2p/src/discovery/roles/", ("roles",)),
    ("crates/shaar-p2p/src/discovery/address", ("addresses",)),
    ("crates/shaar-p2p/src/discovery/scope", ("addresses",)),
    ("crates/shaar-p2p/src/discovery/", ("discovery-config",)),
    ("crates/shaar-p2p/src/dns/transport", ("destination-guard",)),
    ("crates/shaar-p2p/src/dns/", ("owned-dns",)),
    (".github/scripts/p2p/discovery/simple_dns/", ("native-discovery",)),
    ("crates/shaar/src/native_discovery/runtime/tests/fixture.rs",
     ("native-discovery", "startup-dht-contract")),
    ("crates/shaar/src/native_discovery/runtime/tests/fixture/",
     ("native-discovery", "startup-dht-contract")),
    ("crates/shaar/src/native_discovery/", ("native-discovery",)),
    ("crates/shaar/src/path/", ("sdk-path",)),
    ("crates/shaar/src/startup/", ("sdk-startup",)),
    ("crates/shaar/src/identity/", ("sdk-identity",)),
    ("crates/shaar/src/config/", ("sdk-config",)),
    # Documented examples are parsed verbatim by the tests of their owners.
    ("docs/guide/examples/allowlist", ("server-guide",)),
    ("docs/guide/examples/server", ("sdk-config",)),
    ("docs/guide/examples/client", ("sdk-config",)),
    ("crates/shaar/src/network/signaling/", ("sdk-signaling",)),
    ("crates/shaar/src/network/admission/", ("sdk-admission",)),
    ("crates/shaar/src/network/forwarding/", ("sdk-forwarding",)),
)
PROOFS = (
    (".github/probes/nat-topology/quic/product/", "ci_policy"),
    (".github/probes/nat-topology/", "ci_policy"),
    (".github/probes/native-graph-proof/", "native_graph"),
    (".github/probes/native-graph-multibase/", "native_graph"),
    (".github/probes/native-graph/", "native_graph"),
    (".github/probes/ygg/", "ygg"),
    (".github/probes/public-smoke/", "ci_policy"),
    (".github/probes/iroh-paths/carrier/", "carrier_frames"),
    (".github/probes/iroh-paths/gate/bridge/support/packet_identity.py", "carrier_frames"),
    (".github/scripts/p2p/carrier-wire-proof/", "carrier"),
    (".github/scripts/p2p/relay/", "relay"),
    (".github/scripts/p2p/discovery/mainline/ci/publication/", "publication"),
    (".github/scripts/p2p/discovery/mainline/", "mainline"),
    (".github/scripts/p2p/discovery/resolver/", "resolver"),
    (".github/scripts/p2p/discovery/kad/", "kad"),
    (".github/scripts/p2p/discovery/dns/", "dns"),
    (".github/scripts/p2p/discovery/owned_dns/", "ci_policy"),
    (".github/scripts/p2p/discovery/foundation", "dns"),
    (".github/probes/iroh-paths/ci/protocol_close.sh", "ci_policy"),
    (".github/probes/iroh-paths/ci/windows_native_lifecycle.sh", "ci_policy"),
    (".github/scripts/backend/", "backend"),
    (".github/scripts/tests/noq_driver/", "backend"),
    (".github/actions/dependency-license/", "license"),
    (".github/scripts/dependency_licenses.py", "license"),
    (".github/deny.toml", "license"),
    # The license action runs the notices generator tests directly.
    (".github/scripts/tests/test_notices", "license"),
    # Preserved third-party legal material; owned by the license domain like root LICENSE-*.
    ("docs/legal/notices-material/", "license"),
    (".github/ci/", "ci_policy"),
    (".github/workflows/ci.yml", "ci_policy"),
    (".github/workflows/sdk-lock.yml", "ci_policy"),
    (".github/workflows/nat-topology.yml", "ci_policy"),
    (".github/workflows/quic-nat.yml", "ci_policy"),
    (".github/actions/prepare-sources/", "ci_policy"),
    (".github/scripts/tests/", "ci_policy"),
    (".github/scripts/check_structure.py", "ci_policy"),
    (".github/scripts/scan_identity_output.py", "ci_policy"),
    (".github/scripts/p2p/prepare.py", "relay"),
    (".github/scripts/p2p/checks.py", "relay"),
    (".github/scripts/p2p/lease.rs", "relay"),
    (".github/scripts/p2p/graph.py", "carrier"),
    (".github/scripts/verify_infrastructure_registry.sh", "discovery"),
)


def target(package, filters=("",), kind=None, name=None):
    default_kind, default_name = PACKAGES[package]
    return {"package": package, "kind": kind or default_kind, "name": name or default_name,
            "filters": sorted(set(filters))}


def select(paths, *, full=False):
    flags = {name: full for name in (*DOMAINS, "ci_policy", "identity_probe")}
    targets, suites, reasons = {}, ({"full"} if full else set()), []
    if not paths and not full:
        raise ValueError("No comparison paths established; specify a valid base or explicit full trigger")
    manifest_packages = {path.split("/")[1] for path in paths
                         if re.fullmatch(r"crates/[^/]+/Cargo.toml", path)}

    def add(spec):
        key = (spec["package"], spec["kind"], spec["name"])
        old = targets.setdefault(key, {**spec, "filters": []})
        old["filters"] = sorted(set(old["filters"]) | set(spec["filters"]))

    for path in sorted(set(paths)):
        owned = []
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise ValueError("Invalid changed path")
        if path.endswith(".md") or path in {".gitignore", ".gitattributes", ".github/.gitattributes"}:
            owned = ["documentation"]
        elif full:
            owned = ["full"]
        elif path in {"LICENSE-MIT", "LICENSE-APACHE"}:
            flags["license"] = True
            owned = ["license"]
        elif path == "crates/shaar/Cargo.toml":
            add(target("shaar"))
            flags["license"] = True
            owned = ["package:shaar"]
        elif path == "Cargo.toml":
            for package in ("shaar", "shaar-p2p"):
                add(target(package))
            flags["license"] = True
            owned = ["workspace-manifest"]
        elif path == "Cargo.lock":
            if manifest_packages:
                flags["license"] = True
                for package in sorted(manifest_packages):
                    add(target(package))
                owned = sorted(manifest_packages)
            elif "Cargo.toml" in paths:
                flags["license"] = True
                for package in ("shaar", "shaar-p2p"):
                    add(target(package))
                owned = ["workspace-manifest"]
            else:
                raise ValueError("No test impact rule for Cargo.lock change without an owned manifest; no automatic full fallback")
        else:
            for prefix, names in RULES:
                if path.startswith(prefix):
                    for name in names:
                        package, filters = SUITES[name]
                        add(target(package, filters))
                    owned = list(names)
                    break
            if not owned:
                for prefix, proof in PROOFS:
                    if path.startswith(prefix):
                        flags[proof] = True
                        if proof == "native_graph":
                            add(target("shaar", kind="test", name="native_graph_witness"))
                        owned = [proof]
                        break
            if not owned:
                match = re.fullmatch(r"crates/([^/]+)/tests/([A-Za-z_][A-Za-z0-9_-]*)\.rs", path)
                if path == "docs/guide/examples/keygen.rs":
                    add(target("shaar", kind="test", name="sdk_network"))
                    owned = ["integration:sdk_network"]
                elif path.startswith("crates/shaar/tests/identity/"):
                    add(target("shaar", kind="test", name="identity"))
                    owned = ["integration:identity"]
                elif match and match[1] in PACKAGES:
                    add(target(match[1], kind="test", name=match[2]))
                    owned = ["integration:" + match[2]]
                else:
                    for package in PACKAGES:
                        binary_or_small = package not in {"shaar", "shaar-p2p"} and path.startswith(f"crates/{package}/src/")
                        shared_entry = path == f"crates/{package}/src/lib.rs"
                        nested_lock = package in NESTED and path == f"crates/{package}/Cargo.lock"
                        if binary_or_small or shared_entry or nested_lock or path == f"crates/{package}/Cargo.toml":
                            add(target(package))
                            if path.endswith("Cargo.toml"):
                                flags["license"] = True
                            owned = ["package:" + package]
                            break
        if not owned:
            raise ValueError("No test impact rule for " + path + "; add its owner mapping (no automatic full fallback)")
        if path.startswith("crates/shaar/src/identity/store"):
            flags["identity_probe"] = True
        suites.update(owned)
        reasons.append({"path": path, "suites": owned})
    if GRAPH_INPUTS & set(paths) and not full:
        flags["native_graph"] = True
        add(target("shaar", kind="test", name="native_graph_witness"))
    flags.update(full=full, rust=full or bool(targets), product=bool(targets))
    flags["prepare"] = full or bool(targets) or any(flags[name] for name in DOMAINS)
    return {"selection": flags, "targets": [targets[key] for key in sorted(targets)],
            "suites": sorted(suites), "reasons": reasons}
