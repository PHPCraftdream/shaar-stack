# SPDX-License-Identifier: MIT OR Apache-2.0
"""Source-bound development-edge projection for baseline/normal consumers."""
import hashlib
from pathlib import Path
import tomllib

def prove_dev_projection(owner_identity, target_identity, context, *, target_retained=False, registry, generated_paths) -> dict:
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
                    and not (target.get("source") is None and dep.get("source") == registry
                             and (target.get("name"), target.get("version")) in
                             {("n0-future", "0.3.2"), ("serde_bencode", "0.2.4")}))):
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
                name, approved_version = target.get("name"), target.get("version")
                if ((name, approved_version) not in {("n0-future", "0.3.2"), ("serde_bencode", "0.2.4")}
                        or declaration.get("source") != registry):
                    raise ValueError("registry projection dependency source mismatch")
                if (declaration.get("path") not in (None, "")
                        or spec.get("registry") not in (None, "crates-io")):
                    raise ValueError("registry patch declaration source mismatch")
                if declaration.get("req") != "=" + approved_version:
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
                patch = root_doc.get("patch", {}).get("crates-io", {}).get(name)
                if not isinstance(patch, dict) or set(patch) - {"path", "version"}:
                    raise ValueError("invalid approved crates.io patch")
                generated = (workspace_root / generated_paths[name]).resolve()
                patch_path = (workspace_root / patch.get("path", "")).resolve()
                if patch_path != generated or generated != Path(target["manifest_path"]).resolve().parent:
                    raise ValueError("approved patch path mismatch")
                if "version" in patch and patch["version"] not in (approved_version, "=" + approved_version):
                    raise ValueError("approved patch version mismatch")
                archive_key = "future_archive" if name == "n0-future" else "bencode_archive"
                archive = context.get(archive_key)
                if not isinstance(archive, str) or not archive:
                    raise ValueError(archive_key + " context required")
                from prepare import verify_bencode_provenance, verify_future_provenance
                verifier = verify_future_provenance if name == "n0-future" else verify_bencode_provenance
                source_proof = verifier(Path(archive), workspace_root)
                if Path(source_proof["prepared_manifest_path"]).resolve() != Path(target["manifest_path"]).resolve():
                    raise ValueError("approved provenance target manifest mismatch")
                patch_proof = {**source_proof, "root_manifest_path": str(root_path),
                               "root_manifest_sha256": root_hash}
            elif (source != registry or declaration.get("source") != registry
                    or declaration.get("path") not in (None, "")
                    or spec.get("registry") not in (None, "crates-io")):
                raise ValueError("registry projection dependency source mismatch")
    return {"owner": list(owner_identity), "target": list(target_identity), "manifest_path": str(manifest_path),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "alias": alias,
            "target_conditions": sorted(edge_conditions), **patch_proof}
