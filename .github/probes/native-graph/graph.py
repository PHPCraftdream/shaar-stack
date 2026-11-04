# Copyright 2026 PHPCraftdream
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fail-closed Cargo lock delta and isolated normal graph audits."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tomllib


def build_projection_context(product_metadata: bytes, consumer_metadata: bytes, *, product_record: dict, consumer_record: dict, product_argv: list, consumer_argv: list, product_cwd: Path, consumer_cwd: Path, product_root_manifest: Path | None = None, future_archive: Path | None = None) -> dict:
    """Validate retained Cargo invocation receipts and parse projection metadata."""
    def parse(metadata_bytes: bytes, record: dict, expected_argv: list, expected_cwd: Path, label: str) -> tuple[dict, str]:
        digest = hashlib.sha256(metadata_bytes).hexdigest()
        if record.get("exit_code") != 0:
            raise ValueError(f"{label} metadata command did not succeed")
        if record.get("argv") != expected_argv:
            raise ValueError(f"{label} metadata argv mismatch")
        try:
            actual_cwd = Path(record["cwd"]).resolve()
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{label} metadata cwd is invalid") from exc
        if actual_cwd != expected_cwd.resolve():
            raise ValueError(f"{label} metadata cwd mismatch")
        if record.get("stdout_sha256") != digest:
            raise ValueError(f"{label} metadata stdout digest mismatch")
        try:
            document = json.loads(metadata_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{label} metadata JSON is malformed") from exc
        if not isinstance(document, dict) or not isinstance(document.get("packages"), list):
            raise ValueError(f"{label} metadata packages are malformed")
        resolve = document.get("resolve")
        if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
            raise ValueError(f"{label} metadata resolve nodes are malformed")
        for collection, field in ((document["packages"], "id"), (resolve["nodes"], "id")):
            seen = set()
            for item in collection:
                if not isinstance(item, dict) or not isinstance(item.get(field), str) or not item[field]:
                    raise ValueError(f"{label} metadata contains malformed {field}")
                if item[field] in seen:
                    raise ValueError(f"{label} metadata contains duplicate {field}: {item[field]}")
                seen.add(item[field])
        return document, digest

    product, product_hash = parse(product_metadata, product_record, product_argv, product_cwd, "product")
    consumer, consumer_hash = parse(consumer_metadata, consumer_record, consumer_argv, consumer_cwd, "consumer")
    result = {"product": product, "consumer": consumer,
              "metadata_sha256": {"product": product_hash, "consumer": consumer_hash}}
    if product_root_manifest is not None:
        root_path = Path(product_root_manifest)
        expected_path = product_cwd.resolve() / "Cargo.toml"
        if root_path.resolve() != expected_path:
            raise ValueError("product root manifest path mismatch")
        if root_path.is_symlink() or not root_path.is_file():
            raise ValueError("product root manifest missing or linked")
        root_bytes = root_path.read_bytes()
        try:
            tomllib.loads(root_bytes.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ValueError("product root manifest is malformed") from exc
        if not isinstance(product.get("workspace_root"), str) or not product["workspace_root"]:
            raise ValueError("product metadata workspace_root is missing or invalid")
        if Path(product["workspace_root"]).resolve() != product_cwd.resolve():
            raise ValueError("product metadata workspace_root mismatch")
        result["product_root_manifest"] = {
            "path": str(root_path), "sha256": hashlib.sha256(root_bytes).hexdigest()
        }
    if future_archive is not None:
        result["future_archive"] = str(future_archive)
    return result


GENERATED_PATHS = {
    "iroh-mainline-address-lookup": "target/native-graph/adapter/iroh-mainline-address-lookup",
    "n0-mainline": "target/native-graph/n0-mainline-0.7.0",
    "serde_bencode": "target/native-graph/serde_bencode-0.2.4",
    "iroh-dns": "target/native-graph/iroh-dns-1.3.0",
    "n0-future": "target/native-graph/n0-future-0.3.2",
}
ALLOWED_ADDITIONS = {
    ("iroh-mainline-address-lookup", "0.6.1", "path"),
    ("n0-mainline", "0.7.0", "path"),
    ("serde_bencode", "0.2.4", "path"),
    ("iroh-dns", "1.3.0", "path"),
    ("n0-future", "0.3.2", "path"),
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
REVIEWED_TRANSITIVES = {
    ("crc", "3.4.0", REGISTRY): {
        "name": "crc", "version": "3.4.0", "source": REGISTRY,
        "checksum": "5eb8a2a1cd12ab0d987a5d5e825195d372001a4094a0376319d5a0ad71c1ba0d",
        "dependencies": ["crc-catalog"],
    },
    ("crc-catalog", "2.5.0", REGISTRY): {
        "name": "crc-catalog", "version": "2.5.0", "source": REGISTRY,
        "checksum": "217698eaf96b4a3f0bc4f3662aaa55bdf913cd54d7204591faa790070c6d0853",
    },
    ("dyn-clone", "1.0.20", REGISTRY): {
        "name": "dyn-clone", "version": "1.0.20", "source": REGISTRY,
        "checksum": "d0881ea181b1df73ff77ffaaf9c7544ecc11e82fba9b5f27b262a3c73a332555",
    },
}
REQUIRED_NORMAL = {"iroh-mainline-address-lookup": "0.6.1", "n0-mainline": "0.7.0",
                   "serde_bencode": "0.2.4", "iroh-dns": "1.3.0", "tokio": "1.54.1",
                   "serde": "1.0.229", "noq-udp": "1.3.0", "iroh": "1.3.0",
                   "iroh-base": "1.3.0", "noq": "1.3.0", "noq-proto": "1.3.0", "n0-future": "0.3.2"}


def audit_product_workspace(manifest: dict) -> None:
    """Require the adapter's exact exclusion from the product workspace."""
    adapter_path = GENERATED_PATHS["iroh-mainline-address-lookup"]
    expected = [adapter_path]
    workspace = manifest.get("workspace", {})
    if workspace.get("exclude") != expected:
        raise ValueError(f"workspace.exclude must be exactly {expected}")
    members = workspace.get("members", [])
    if not isinstance(members, list):
        raise ValueError("workspace.members must be a list")
    if adapter_path in members:
        raise ValueError("adapter path must not be an explicit workspace member")


def audit_reviewed_normal_edges(metadata: dict) -> None:
    reviewed_names = {key[0] for key in REVIEWED_TRANSITIVES}
    packages_list = metadata.get("packages", [])
    present = {pkg.get("name") for pkg in packages_list} & reviewed_names
    if not present:
        return
    packages = {pkg["id"]: pkg for pkg in packages_list}
    resolve = metadata.get("resolve") or {}
    nodes = {node["id"]: node for node in resolve.get("nodes", [])}
    if present != reviewed_names:
        raise ValueError("normal metadata must contain the complete reviewed transitive set")
    ids = {}
    for name, version in (("crc", "3.4.0"), ("crc-catalog", "2.5.0"), ("dyn-clone", "1.0.20")):
        candidates = [pkg for pkg in packages_list if pkg.get("name") == name]
        if len(candidates) != 1 or candidates[0].get("version") != version or candidates[0].get("source") != REGISTRY or candidates[0]["id"] not in nodes:
            raise ValueError(f"reviewed normal package identity must resolve uniquely: {name}")
        ids[name] = candidates[0]["id"]
    n0 = [pkg for pkg in packages_list if pkg.get("name") == "n0-mainline" and pkg.get("version") == "0.7.0" and pkg.get("source") is None]
    if len(n0) != 1 or n0[0]["id"] not in nodes:
        raise ValueError("reviewed normal route requires path n0-mainline 0.7.0")
    n0_id = n0[0]["id"]

    def normal_targets(package_id):
        return {dep["pkg"] for dep in nodes[package_id].get("deps", []) if any(kind.get("kind") in (None, "normal") for kind in dep.get("dep_kinds", []))}

    if not {ids["crc"], ids["dyn-clone"]} <= normal_targets(n0_id):
        raise ValueError("n0-mainline lacks reviewed normal edges")

    expected = {"crc": {ids["crc-catalog"]}, "crc-catalog": set(), "dyn-clone": set()}
    for name, package_id in ids.items():
        if normal_targets(package_id) != expected[name]:
            raise ValueError(f"reviewed normal dependency edges mismatch: {name}")
    allowed_incoming = {n0_id: {ids["crc"], ids["dyn-clone"]}, ids["crc"]: {ids["crc-catalog"]}}
    for owner_id in nodes:
        for target in normal_targets(owner_id) & set(ids.values()):
            if target not in allowed_incoming.get(owner_id, set()):
                raise ValueError(f"unapproved normal incoming edge to reviewed package: {owner_id}")


def audit_product_metadata(metadata: dict, root: Path) -> None:
    """Verify the generated adapter remains a path dependency, not a member."""
    adapter_path = GENERATED_PATHS["iroh-mainline-address-lookup"]
    expected_manifest = (root / adapter_path / "Cargo.toml").resolve()
    adapters = [pkg for pkg in metadata.get("packages", [])
                if pkg.get("name") == "iroh-mainline-address-lookup"]
    if len(adapters) != 1:
        raise ValueError("expected exactly one adapter package in product metadata")
    adapter = adapters[0]
    if adapter.get("version") != "0.6.1":
        raise ValueError("adapter package version must be 0.6.1")
    if adapter.get("source") is not None:
        raise ValueError("adapter package must be a path source")
    if Path(adapter.get("manifest_path", "")).resolve() != expected_manifest:
        raise ValueError("wrong generated adapter manifest path")
    if adapter.get("id") in set(metadata.get("workspace_members", [])):
        raise ValueError("adapter must not be a product workspace member")
    audit_reviewed_normal_edges(metadata)


def audit_candidate_metadata(metadata: dict, root: Path) -> dict[str, str]:
    """Validate candidate package identities and the reviewed normal route."""
    packages_list = metadata.get("packages", [])
    if not isinstance(packages_list, list):
        raise ValueError("candidate metadata packages are malformed")
    package_ids = set()
    for package in packages_list:
        if (not isinstance(package, dict) or not isinstance(package.get("id"), str)
                or not package["id"] or package["id"] in package_ids):
            raise ValueError("candidate metadata package IDs must be unique non-empty strings")
        package_ids.add(package["id"])
    packages = {}
    for name, version in REQUIRED_NORMAL.items():
        matches = [pkg for pkg in packages_list if pkg.get("name") == name]
        if len(matches) != 1 or matches[0].get("version") != version:
            raise ValueError(f"candidate package identity must resolve uniquely: {name}")
        package = matches[0]
        if name == "tokio" and package.get("source") != REGISTRY:
            raise ValueError("candidate tokio package must be from crates.io registry")
        if name in GENERATED_PATHS:
            expected = (root / GENERATED_PATHS[name] / "Cargo.toml").resolve()
            if package.get("source") is not None or Path(package.get("manifest_path", "")).resolve() != expected:
                raise ValueError(f"candidate generated package path mismatch: {name}")
        packages[name] = package
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise ValueError("candidate metadata resolve nodes are malformed")
    nodes_list = resolve["nodes"]
    nodes = {}
    for node in nodes_list:
        if (not isinstance(node, dict) or not isinstance(node.get("id"), str)
                or not node["id"] or node["id"] in nodes):
            raise ValueError("candidate metadata node IDs must be unique non-empty strings")
        nodes[node["id"]] = node
    if not set(nodes) <= package_ids:
        raise ValueError('candidate resolved node package is unknown')
    for node in nodes_list:
        deps = node.get("deps", [])
        if not isinstance(deps, list):
            raise ValueError("candidate metadata dependencies are malformed")
        for dep in deps:
            if not isinstance(dep, dict) or not isinstance(dep.get("pkg"), str) or dep["pkg"] not in nodes:
                raise ValueError("candidate dependency target is unknown")
    ids = {name: package.get("id") for name, package in packages.items()}
    if any(package_id not in nodes for package_id in ids.values()):
        raise ValueError("candidate package is missing a resolved node")
    for owner, target in (("iroh", "n0-future"), ("n0-future", "tokio")):
        if not any(dep.get("pkg") == ids[target] and _normal_kinds(dep) for dep in nodes[ids[owner]].get("deps", [])):
            raise ValueError(f"candidate normal dependency edge missing: {owner} -> {target}")
    return ids


def identity(package: dict) -> tuple[str, str, str]:
    return package["name"], package["version"], package.get("source", "path")


def lock_packages(lock: dict) -> dict[tuple[str, str, str], dict]:
    packages: dict[tuple[str, str, str], dict] = {}
    for package in lock.get("package", []):
        key = identity(package)
        if key in packages:
            raise ValueError(f"duplicate lock package identity: {key}")
        packages[key] = package
    return packages


def audit_lock_delta(before_bytes: bytes, after_bytes: bytes) -> dict[str, list[tuple]]:
    before = lock_packages(tomllib.loads(before_bytes.decode("utf-8")))
    after = lock_packages(tomllib.loads(after_bytes.decode("utf-8")))
    removed = set(before) - set(after)
    added = set(after) - set(before)
    dns_old = ("iroh-dns", "1.3.0", REGISTRY)
    dns_new = ("iroh-dns", "1.3.0", "path")
    shaar_key = ("shaar", "0.1.0", "path")
    shaar_changed = shaar_key in before and shaar_key in after and before[shaar_key] != after[shaar_key]
    n0_old = ("n0-future", "0.3.2", REGISTRY)
    n0_new = ("n0-future", "0.3.2", "path")
    permitted_removed = ({dns_old} if dns_old in before and dns_new in after else set())
    if n0_new in after and n0_old in before and before[n0_old].get("checksum") == "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe":
        permitted_removed.add(n0_old)
    permitted_added = ALLOWED_ADDITIONS | set(REVIEWED_TRANSITIVES)
    unexpected_removed = removed - permitted_removed
    unexpected_added = added - permitted_added
    if unexpected_removed or unexpected_added:
        delta = {"added": sorted(added), "removed": sorted(removed),
                 "unapproved_added": sorted(unexpected_added), "unapproved_removed": sorted(unexpected_removed)}
        raise ValueError(f"unapproved lock delta: {delta}")
    reviewed_added = added & set(REVIEWED_TRANSITIVES)
    if reviewed_added:
        if reviewed_added != set(REVIEWED_TRANSITIVES):
            raise ValueError("reviewed transitive additions must appear as the exact complete set")
        for key, expected in REVIEWED_TRANSITIVES.items():
            if after[key] != expected:
                raise ValueError(f"reviewed transitive lock package fields mismatch: {key}")
        n0_key = ("n0-mainline", "0.7.0", "path")
        if n0_key not in after or ("shaar", "0.1.0", "path") not in after:
            raise ValueError("reviewed transitive route requires shaar and n0-mainline lock packages")
        n0_dependencies = set(after[n0_key].get("dependencies", []))
        if not {"crc", "dyn-clone"} <= {dep.split()[0] for dep in n0_dependencies}:
            raise ValueError("n0-mainline lock package lacks reviewed transitive dependencies")
        for owner, package in after.items():
            deps = package.get("dependencies", [])
            for target_name in ("crc", "crc-catalog", "dyn-clone"):
                if any(dep.split()[0] == target_name for dep in deps):
                    if not (owner == ("n0-mainline", "0.7.0", "path") and target_name in {"crc", "dyn-clone"}) and not (owner == ("crc", "3.4.0", REGISTRY) and target_name == "crc-catalog"):
                        raise ValueError(f"unapproved lock dependency to reviewed transitive: {owner} -> {target_name}")
    for key in set(before) | set(after):
        old = before.get(key)
        new = after.get(key)
        if key == shaar_key or key in {dns_old, dns_new}:
            continue
        if old is not None and new is not None and old != new:
            raise ValueError(f"unchanged lock identity changed fields: {key}")
    source_changes = []
    for old_key, new_key, checksum, label in ((dns_old, dns_new, None, "iroh-dns"), (n0_old, n0_new, "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe", "n0-future")):
        if old_key in removed or new_key in added:
            if old_key not in removed or new_key not in added:
                raise ValueError(f"{label} source replacement must remove registry identity and add path identity")
            old, new = before[old_key], after[new_key]
            if old.get("dependencies", []) != new.get("dependencies", []):
                raise ValueError(f"{label} replacement must retain the exact dependency list")
            if checksum is None:
                if "checksum" not in old or "checksum" in new:
                    raise ValueError("iroh-dns registry checksum removal semantics mismatch")
            elif old.get("checksum") != checksum or "checksum" in new:
                raise ValueError("n0-future registry checksum replacement mismatch")
            source_changes.append((old_key, new_key))
    if shaar_changed:
        shaar_old, shaar_new = before[shaar_key], after[shaar_key]
        old_deps = set(shaar_old.get("dependencies", []))
        new_deps = set(shaar_new.get("dependencies", []))
        expected = {"iroh-mainline-address-lookup", "n0-mainline"}
        if (new_deps - old_deps == {"serde_bencode"} and expected <= old_deps
                and ("serde_bencode", "0.2.4", "path") in before and before.keys() == after.keys()
                and len(shaar_new.get("dependencies", [])) == len(shaar_old.get("dependencies", [])) + 1
                and all(before[k] == after[k] for k in before if k != shaar_key)):
            expected = {"serde_bencode"}
        if new_deps - old_deps != expected or old_deps - new_deps:
            raise ValueError("shaar lock delta must match the reviewed normal route or isolated dev codec edge")
        for field in set(shaar_old) | set(shaar_new):
            if field != "dependencies" and shaar_old.get(field) != shaar_new.get(field):
                raise ValueError(f"shaar lock fields changed beyond reviewed dependency edges: {field}")
    return {"added": sorted(added), "removed": sorted(removed), "source_changed": source_changes}


def _normal_kinds(dep: dict) -> bool:
    return any(kind.get("kind") is None for kind in dep.get("dep_kinds", []))


def _prove_dev_projection(owner_identity, target_identity, context, *, target_retained=False) -> dict:
    """Prove a removed lock edge is dev-only from both Cargo graphs and manifest."""
    def norm(value):
        return value.replace("-", "_")

    def conditions(value):
        return value or ""

    def unique_package(metadata, wanted):
        found = [pkg for pkg in metadata.get("packages", []) if (pkg.get('name'), pkg.get('version'), pkg.get('source') or 'path') == wanted]
        if len(found) != 1:
            raise ValueError(f"projection identity must occur uniquely in metadata: {wanted}")
        return found[0]

    product, consumer = context["product"], context["consumer"]
    owner = unique_package(product, owner_identity)
    target = unique_package(product, target_identity)
    consumer_owner = unique_package(consumer, owner_identity)
    product_nodes = {node["id"]: node for node in product["resolve"]["nodes"]}
    consumer_nodes = {node["id"]: node for node in consumer["resolve"]["nodes"]}
    owner_node = product_nodes.get(owner["id"])
    consumer_node = consumer_nodes.get(consumer_owner["id"])
    if owner_node is None or consumer_node is None:
        raise ValueError("projection owner is absent from resolve graph")
    if Path(owner["manifest_path"]).resolve() != Path(consumer_owner["manifest_path"]).resolve():
        raise ValueError("product and consumer owner manifest paths differ")
    edges = [dep for dep in owner_node.get("deps", []) if dep.get("pkg") == target["id"]]
    if len(edges) != 1 or not edges[0].get("dep_kinds") or any(k.get("kind") != "dev" for k in edges[0]["dep_kinds"]):
        raise ValueError("product projection edge is not exclusively dev")
    retained = [pkg for pkg in consumer.get("packages", []) if (pkg.get('name'), pkg.get('version'), pkg.get('source') or 'path') == target_identity]
    if len(retained) > 1:
        raise ValueError("consumer target identity is ambiguous")
    if bool(retained) != bool(target_retained):
        raise ValueError("consumer target retention does not match audited lock")
    if retained:
        if Path(retained[0]["manifest_path"]).resolve() != Path(target["manifest_path"]).resolve():
            raise ValueError("patched consumer target manifest mismatch")
        if retained[0]["id"] not in consumer_nodes:
            raise ValueError("consumer target is not resolved")
        if any(dep.get("pkg") == retained[0]["id"] for dep in consumer_node.get("deps", [])):
            raise ValueError("consumer owner retains an edge to projected target")

    manifest_path = Path(owner["manifest_path"])
    workspace_root_value = product.get("workspace_root")
    if not isinstance(workspace_root_value, str) or not workspace_root_value:
        raise ValueError("missing product workspace root")
    workspace_root = Path(workspace_root_value).resolve()
    package_root = manifest_path.parent.resolve()
    if not workspace_root or (workspace_root not in package_root.parents and package_root != workspace_root):
        raise ValueError("product owner manifest escapes workspace root")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("product owner manifest missing or linked")
    manifest_bytes = manifest_path.read_bytes()
    manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    package = manifest.get("package", {})
    package_version = package.get("version")
    if isinstance(package_version, dict) and package_version.get("workspace") is True:
        package_version = tomllib.loads((workspace_root / "Cargo.toml").read_text(encoding="utf-8")).get("workspace", {}).get("package", {}).get("version")
    if package.get("name") != owner["name"] or package_version != owner["version"]:
        raise ValueError("product owner manifest package identity mismatch")
    declarations = [dep for dep in owner.get("dependencies", [])
                   if norm(dep.get("rename") or dep.get("name", "")) == norm(edges[0].get("name", ""))]
    if not declarations:
        raise ValueError("resolved edge has no metadata declaration")
    aliases = {dep.get("rename") or dep.get("name") for dep in declarations}
    if len(aliases) != 1:
        raise ValueError("projection dependency alias is ambiguous")
    alias = next(iter(aliases))
    if norm(alias) != norm(edges[0].get("name")):
        raise ValueError("resolved edge alias does not match metadata alias")
    declaration_by_condition = {}
    patch_proof = {}
    for dep in declarations:
        condition = conditions(dep.get("target"))
        if condition in declaration_by_condition:
            raise ValueError("projection metadata declaration condition is duplicated or ambiguous")
        declaration_by_condition[condition] = dep
        if (dep.get("name") != target["name"] or dep.get("kind") != "dev"
                or (dep.get("source") != target.get("source")
                    and not (target.get("source") is None and dep.get("source") == REGISTRY
                             and target.get("name") == "n0-future" and target.get("version") == "0.3.2"))):
            raise ValueError("metadata declaration does not corroborate dev projection")
    edge_conditions = {conditions(k.get("target")) for k in edges[0]["dep_kinds"]}
    if len(edge_conditions) != len(edges[0]["dep_kinds"]):
        raise ValueError("projection edge condition is duplicated or ambiguous")
    tables = [("", manifest)]
    for condition, table in manifest.get("target", {}).items():
        if isinstance(table, dict):
            tables.append((condition, table))
    actual, dev_conditions = [], set()
    for condition, table in tables:
        condition = conditions(condition)
        for section in ("dependencies", "build-dependencies", "dev-dependencies"):
            entries = table.get(section, {})
            for key, value in entries.items():
                spec = {"package": key} if isinstance(value, str) else value
                package_name = spec.get("package", key) if isinstance(spec, dict) else key
                if key == alias or package_name == target["name"]:
                    actual.append((condition, section, key, value))
                    if section == "dev-dependencies":
                        if condition in dev_conditions:
                            raise ValueError("actual dev dependency condition is duplicated or ambiguous")
                        dev_conditions.add(condition)
    if any(section != "dev-dependencies" for _, section, _, _ in actual):
        raise ValueError("projection alias also has normal or build dependency")
    if not actual or set(declaration_by_condition) != edge_conditions or edge_conditions != dev_conditions:
        raise ValueError("projection condition sets differ")
    for condition, _, key, value in actual:
        if key != alias:
            raise ValueError('actual manifest alias does not match metadata alias')
        spec = {"version": value} if isinstance(value, str) else value
        if not isinstance(spec, dict) or spec.get("package", key) != target["name"]:
            raise ValueError("actual manifest package rename mismatch")
        declaration = declaration_by_condition[condition]
        if bool(spec.get("optional", False)) != bool(declaration.get("optional", False)):
            raise ValueError("actual manifest optional flag mismatch")
        version = spec.get("version")
        if isinstance(version, dict) and version.get("workspace") is True:
            version = tomllib.loads((workspace_root / "Cargo.toml").read_text(encoding="utf-8")).get("workspace", {}).get("dependencies", {}).get(key, {}).get("version")
        if isinstance(version, str) and not version.startswith(("^", "=", ">", "<", "~")):
            version = "^" + version
        if version != declaration.get("req"):
            raise ValueError("actual manifest version requirement mismatch")
        source = target.get("source")
        if "git" in spec or "workspace" in spec:
            raise ValueError("git/workspace projection dependency is forbidden")
        if "path" in spec:
            actual_path = (manifest_path.parent / spec["path"]).resolve()
            metadata_path = declaration.get("path")
            if (source is not None or not metadata_path or Path(metadata_path).resolve() != actual_path
                    or actual_path != Path(target["manifest_path"]).resolve().parent or declaration.get("source") is not None):
                raise ValueError("path projection dependency does not resolve to target")
        else:
            if source is None:
                if (target.get("name"), target.get("version"), declaration.get("source")) != ("n0-future", "0.3.2", REGISTRY):
                    raise ValueError("registry projection dependency source mismatch")
                if (declaration.get("path") not in (None, "")
                        or spec.get("registry") not in (None, "crates-io")):
                    raise ValueError("registry patch declaration source mismatch")
                if declaration.get("req") != "=0.3.2":
                    raise ValueError("approved patched registry requirement mismatch")
                root_binding = context.get("product_root_manifest")
                if not isinstance(root_binding, dict):
                    raise ValueError("registry patch requires root manifest context")
                root_path = workspace_root / "Cargo.toml"
                if (root_path.resolve() != Path(root_binding.get("path", "")).resolve()
                        or root_path.is_symlink() or not root_path.is_file()):
                    raise ValueError("registry patch root manifest identity mismatch")
                root_bytes = root_path.read_bytes()
                root_hash = hashlib.sha256(root_bytes).hexdigest()
                if root_hash != root_binding.get("sha256"):
                    raise ValueError("registry patch root manifest snapshot mismatch")
                root_doc = tomllib.loads(root_bytes.decode("utf-8"))
                patch = root_doc.get("patch", {}).get("crates-io", {}).get("n0-future")
                if not isinstance(patch, dict) or set(patch) - {"path", "version"}:
                    raise ValueError("invalid n0-future crates.io patch")
                generated = (workspace_root / GENERATED_PATHS["n0-future"]).resolve()
                patch_path = (workspace_root / patch.get("path", "")).resolve()
                if patch_path != generated or generated != Path(target["manifest_path"]).resolve().parent:
                    raise ValueError("n0-future patch path mismatch")
                if "version" in patch and patch["version"] not in ("0.3.2", "=0.3.2"):
                    raise ValueError("n0-future patch version mismatch")
                archive = context.get("future_archive")
                if not isinstance(archive, str) or not archive:
                    raise ValueError("future archive context required")
                from prepare import verify_future_provenance
                future_proof = verify_future_provenance(Path(archive), workspace_root)
                if Path(future_proof["prepared_manifest_path"]).resolve() != Path(target["manifest_path"]).resolve():
                    raise ValueError("future provenance target manifest mismatch")
                patch_proof = {**future_proof, "root_manifest_path": str(root_path),
                               "root_manifest_sha256": root_hash}
            elif (source != REGISTRY or declaration.get("source") != REGISTRY
                    or declaration.get("path") not in (None, "")
                    or spec.get("registry") not in (None, "crates-io")):
                raise ValueError("registry projection dependency source mismatch")
    return {"owner": list(owner_identity), "target": list(target_identity), "manifest_path": str(manifest_path),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "alias": alias,
            "target_conditions": sorted(edge_conditions), **patch_proof}


def audit_consumer_lock(product_bytes: bytes, consumer_bytes: bytes, *, projection_context=None) -> dict[str, list[tuple[str, str, str]]]:
    product = lock_packages(tomllib.loads(product_bytes.decode("utf-8")))
    consumer = lock_packages(tomllib.loads(consumer_bytes.decode("utf-8")))
    root = ("native-graph-normal-consumer", "0.0.0", "path")
    additions = set(consumer) - set(product)
    if additions != {root}:
        raise ValueError(f"consumer lock must add only its exact root package: {sorted(additions)}")
    root_package = consumer[root]
    if root_package.get("dependencies") != ["shaar"]:
        raise ValueError("consumer root must declare only the normal shaar edge")
    missing = set(product) - set(consumer)
    proven_edges = []
    for identity, package in consumer.items():
        if identity == root:
            continue
        original = product.get(identity)
        if original is None:
            raise ValueError(f"consumer lock identity not in product lock: {identity}")
        for field in ("name", "version", "source", "checksum"):
            if package.get(field) != original.get(field):
                raise ValueError(f"consumer lock identity drift in {field}: {identity}")
        old_dependencies = set(original.get("dependencies", []))
        new_dependencies = set(package.get("dependencies", []))
        if not new_dependencies <= old_dependencies:
            raise ValueError(f"consumer lock adds dependency edges: {identity}")
        removed_edges = old_dependencies - new_dependencies
        for dependency in removed_edges:
            fields = dependency.split()
            target_name = fields[0]
            candidates = [key for key in product if key[0] == target_name]
            if len(fields) >= 2:
                candidates = [key for key in candidates if key[1] == fields[1]]
            if len(fields) >= 3:
                source_text = " ".join(fields[2:]).strip("()")
                candidates = [key for key in candidates if key[2] == source_text]
            if len(candidates) != 1:
                raise ValueError(f"consumer lock removed an edge not uniquely identified: {identity}: {dependency}")
            if projection_context is None:
                raise ValueError(f"removed direct edge requires projection evidence: {identity}: {dependency}")
            proven_edges.append(_prove_dev_projection(identity, candidates[0], projection_context, target_retained=candidates[0] not in missing))
    return {"consumer_only": sorted(additions), "removed_projection_packages": sorted(missing),
            "proven_projection_edges": proven_edges,
            "metadata_sha256": projection_context.get("metadata_sha256", {}) if projection_context is not None else {}}


def audit_normal_metadata(metadata: dict, generated_root: Path, *, normal_consumer: bool) -> dict[str, set[str]]:
    if not normal_consumer:
        raise ValueError("normal graph must come from isolated downstream consumer")
    packages = {pkg["id"]: pkg for pkg in metadata.get("packages", [])}
    resolve = metadata.get("resolve")
    if not resolve:
        raise ValueError("Cargo metadata resolve graph is required")
    nodes = {node["id"]: node for node in resolve.get("nodes", [])}
    audit_reviewed_normal_edges(metadata)
    roots = [pkg for pkg in packages.values() if pkg.get("name") == "shaar"]
    if len(roots) != 1:
        raise ValueError("expected exactly one shaar package")
    shaar = roots[0]
    if shaar["id"] not in nodes:
        raise ValueError("shaar missing from resolved graph")
    workspace_members = set(metadata.get("workspace_members", []))
    if shaar["id"] in workspace_members:
        raise ValueError("normal consumer metadata must not include shaar as workspace member")
    root_ids = set(resolve.get("root", [])) if isinstance(resolve.get("root"), list) else {resolve.get("root")}
    if len(root_ids) != 1:
        raise ValueError("isolated consumer metadata must have exactly one workspace root")
    consumer_id = next(iter(root_ids))
    if consumer_id not in nodes or consumer_id not in packages:
        raise ValueError("isolated consumer root package is absent from metadata resolve graph")
    if workspace_members != {consumer_id}:
        raise ValueError("isolated consumer must be the sole workspace member")
    if not any(dep["pkg"] == shaar["id"] and _normal_kinds(dep)
               for dep in nodes[consumer_id].get("deps", [])):
        raise ValueError("consumer root must depend normally on shaar")
    reachable: set[str] = set()
    pending = [shaar["id"]]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for dep in nodes[current].get("deps", []):
            if _normal_kinds(dep):
                pending.append(dep["pkg"])
    by_name: dict[str, list[dict]] = {}
    for package_id in reachable:
        package = packages[package_id]
        by_name.setdefault(package["name"], []).append(package)
    for name, version in REQUIRED_NORMAL.items():
        candidates = by_name.get(name, [])
        if len(candidates) != 1 or candidates[0]["version"] != version:
            raise ValueError(f"required package must resolve uniquely in normal graph: {name}={version}")
    for name, relative in GENERATED_PATHS.items():
        package = by_name[name][0]
        if package.get("source") is not None:
            raise ValueError(f"generated package is not a path source: {name}")
        expected_manifest = (generated_root / relative / "Cargo.toml").resolve()
        if Path(package["manifest_path"]).resolve() != expected_manifest:
            raise ValueError(f"wrong generated manifest path for {name}")
    direct = {packages[dep["pkg"]]["name"] for dep in nodes[shaar["id"]].get("deps", []) if _normal_kinds(dep)}
    needed_direct = {"iroh-mainline-address-lookup", "n0-mainline", "iroh-dns"}
    if not needed_direct <= direct:
        raise ValueError(f"missing direct normal SDK edges: {sorted(needed_direct - direct)}")
    adapter_id = by_name["iroh-mainline-address-lookup"][0]["id"]
    mainline_id = by_name["n0-mainline"][0]["id"]
    parser_id = by_name["serde_bencode"][0]["id"]
    adapter_deps = {packages[dep["pkg"]]["name"] for dep in nodes[adapter_id].get("deps", []) if _normal_kinds(dep)}
    adapter_dependency_ids = {dep["pkg"] for dep in nodes[adapter_id].get("deps", []) if _normal_kinds(dep)}
    mainline_deps = {packages[dep["pkg"]]["name"] for dep in nodes[mainline_id].get("deps", []) if _normal_kinds(dep)}
    if parser_id not in {dep["pkg"] for dep in nodes[mainline_id].get("deps", []) if _normal_kinds(dep)}:
        raise ValueError("n0-mainline normal graph lacks serde_bencode")
    if not {"iroh-base", "iroh-dns", "n0-mainline"} <= adapter_deps or by_name["iroh-base"][0]["id"] not in adapter_dependency_ids:
        raise ValueError("adapter normal graph lacks required direct normal dependencies")
    for name in ("iroh", "iroh-base", "noq", "noq-proto", "noq-udp", "libp2p"):
        required_version = {"libp2p": "0.57.1"}.get(name, "1.3.0")
        candidates = by_name.get(name, [])
        if name == "libp2p" and not candidates:
            continue
        if not candidates or len(candidates) != 1 or candidates[0]["version"] != required_version:
            raise ValueError(f"product package must resolve uniquely at its pin: {name}={required_version}")
    features = {package_id: set(node.get("features", []))
                for package_id, node in nodes.items() if package_id in reachable}
    required_features = {
        "tokio": {"fs", "io-util", "rt", "sync", "time", "net", "macros"},
        "iroh": {"tls-ring", "unstable-custom-transports"},
        "iroh-base": {"key", "relay"},
    }
    for package_id, active in features.items():
        name = packages[package_id]["name"]
        if name in required_features and not required_features[name] <= active:
            missing = sorted(required_features[name] - active)
            raise ValueError(f"required normal product features missing for {name}: {missing}")
        if "test-util" in active:
            raise ValueError(f"test-util feature leaked into normal package {name}")
    n0_future_id = by_name["n0-future"][0]["id"]
    tokio_ids = [pkg["id"] for pkg in metadata.get("packages", []) if pkg.get("name") == "tokio"]
    future_edges = {dep["pkg"] for dep in nodes[n0_future_id].get("deps", []) if _normal_kinds(dep)}
    iroh_ids = {dep["pkg"] for dep in nodes[by_name["iroh"][0]["id"]].get("deps", []) if _normal_kinds(dep)}
    if n0_future_id not in iroh_ids or len(tokio_ids) != 1 or tokio_ids[0] not in future_edges:
        raise ValueError("iroh -> n0-future -> tokio normal route is required")
    n0_future = packages[n0_future_id]
    n0_tokio_dependencies = [dep for dep in n0_future.get("dependencies", [])
                             if dep.get("name") == "tokio"]
    target = 'cfg(not(all(target_family = "wasm", target_os = "unknown")))'
    native_normal = [dep for dep in n0_tokio_dependencies
                     if dep.get("kind") in (None, "normal") and dep.get("target") == target]
    native_dev = [dep for dep in n0_tokio_dependencies
                  if dep.get("kind") == "dev" and dep.get("target") == target]
    def tokio_decl_matches(dep, kind, features):
        return (dep.get("name") == "tokio" and dep.get("kind") == kind
                and dep.get("target") == target and dep.get("source") == REGISTRY
                and dep.get("req") == "^1.28" and dep.get("features") == features)
    if (len(native_normal) != 1 or not tokio_decl_matches(native_normal[0], None, ["rt", "time", "macros"])
            or len(native_dev) != 1 or not tokio_decl_matches(native_dev[0], "dev", ["test-util"])):
        raise ValueError("n0-future Tokio dependency declarations mismatch")
    return {"normal_packages": set(by_name), "normal_features": features}


def normal_feature_receipt(metadata: dict, generated_root: Path, cargo_tree_features: str, *, normal_consumer: bool) -> str:
    audit = audit_normal_metadata(metadata, generated_root, normal_consumer=normal_consumer)
    if not cargo_tree_features.strip():
        raise ValueError("normal-only cargo tree feature evidence is empty")
    package_features = {package_id: sorted(features)
                        for package_id, features in sorted(audit["normal_features"].items())}
    evidence = {"package_features": package_features, "cargo_tree": cargo_tree_features}
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()


def _wrapper_record_streams(record, artifacts, index, version, compiler):
    for stream in ("stdout", "stderr"):
        name = record.get(stream)
        digest = record.get(stream + "_sha256")
        if not isinstance(name, str) or name not in artifacts or not isinstance(artifacts[name], bytes):
            raise ValueError("wrapper stream artifact missing or not bytes")
        if hashlib.sha256(artifacts[name]).hexdigest() != digest:
            raise ValueError("wrapper stream artifact digest mismatch")
    if index == 1 and artifacts[record["stdout"]].decode(errors="strict") != version:
        raise ValueError("wrapper compiler version mismatch")
    if index == 0 and artifacts[record["stdout"]].decode(errors="strict").strip() != compiler:
        raise ValueError("wrapper compiler path mismatch")


def read_lock(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("lockfile missing or linked")
    return path.read_bytes()
