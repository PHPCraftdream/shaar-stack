import argparse
import gzip
import importlib.util
import io
import json
import os
import re
import sys
import tarfile
import tomllib
import unicodedata
from pathlib import Path
from urllib.parse import quote

RECEIPT_SHA = "f88dd58897b88c2a964c6b6d00ba5e7ca6c2109c70680a98f7e76124f00b4ff1"
RECEIPT_BYTES = 243217
ARCHIVE_COUNT = 515
LOCKED_IDENTITY_COUNT = 533
COMPRESSED_CAP = 64 * 1024 * 1024
DECODED_CAP = 256 * 1024 * 1024
TOTAL_DECODED_CAP = 2 * 1024 * 1024 * 1024
MEMBER_CAP = 32 * 1024 * 1024
EVIDENCE_CAP = 4 * 1024 * 1024
TOTAL_EVIDENCE_CAP = 128 * 1024 * 1024
MEMBERS_PER_ARCHIVE = 20000
TOTAL_MEMBERS_CAP = 250000
RECEIPT_REL = "notices-registry-authorized-1109/receipt.json"


def load_sibling(name):
    key = "notices_registry_" + name
    module = sys.modules.get(key)
    if module is None:
        spec = importlib.util.spec_from_file_location(key, Path(__file__).with_name(name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return module


data_io = load_sibling("data_io")
raw_sources = load_sibling("raw_sources")
digest = data_io.digest
bounded_regular = data_io.bounded_regular
safe_relative_path = data_io.safe_relative_path
no_link_path = data_io.no_link_path


def archive_path(name, directory, expected_root):
    if not isinstance(name, str) or not name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ValueError(f"Unsafe archive member path: {name!r}")
    normalized = name[:-1] if directory and name.endswith("/") else name
    parts = safe_relative_path(normalized)
    if parts[0] != expected_root:
        raise ValueError(f"Archive member outside package root: {name!r}")
    return normalized, unicodedata.normalize("NFC", normalized).casefold()


def lock_identities(path):
    raw = bounded_regular(path, 16 * 1024 * 1024)
    lock = tomllib.loads(raw.decode("utf-8"))
    identities = set()
    for package in lock.get("package", []):
        source = package.get("source")
        checksum = package.get("checksum")
        if isinstance(source, str) and source.startswith("registry+"):
            if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError(f"Registry lock row lacks valid checksum: {package.get('name')}@{package.get('version')}")
            identity = (source, package["name"], package["version"], checksum)
            if identity in identities:
                raise ValueError(f"Duplicate identity in lockfile: {identity}")
            identities.add(identity)
    return identities


def parse_archive(compressed, identity, expected_member_count, requested_members, totals):
    if len(compressed) > COMPRESSED_CAP:
        raise ValueError(f"Compressed archive cap exceeded: {identity['name']}@{identity['version']}")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
        decoded = stream.read(DECODED_CAP + 1)
    if len(decoded) > DECODED_CAP:
        raise ValueError(f"Decoded archive cap exceeded: {identity['name']}@{identity['version']}")
    totals["decoded"] += len(decoded)
    if totals["decoded"] > TOTAL_DECODED_CAP:
        raise ValueError("Aggregate decoded tar cap exceeded")

    expected_root = f"{identity['name']}-{identity['version']}"
    seen_paths = set()
    members = {}
    member_count = 0
    regular_bytes = 0
    evidence_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        for member in archive:
            member_count += 1
            totals["members"] += 1
            if member_count > MEMBERS_PER_ARCHIVE or totals["members"] > TOTAL_MEMBERS_CAP:
                raise ValueError("Archive member-count bound exceeded")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"Link or special tar member rejected: {member.name}")
            normalized, folded = archive_path(member.name, member.isdir(), expected_root)
            if folded in seen_paths:
                raise ValueError(f"Duplicate normalized tar member: {member.name}")
            seen_paths.add(folded)
            if member.isdir():
                continue
            if member.size < 0 or member.size > MEMBER_CAP:
                raise ValueError(f"Regular member size bound exceeded: {member.name}")
            regular_bytes += member.size
            totals["regular_bytes"] += member.size
            if totals["regular_bytes"] > TOTAL_DECODED_CAP:
                raise ValueError("Aggregate regular member bytes exceeded")
            if normalized in requested_members:
                if member.size > EVIDENCE_CAP:
                    raise ValueError(f"Selected evidence item size bound exceeded: {normalized}")
                evidence_bytes += member.size
                totals["evidence_bytes"] += member.size
                if totals["evidence_bytes"] > TOTAL_EVIDENCE_CAP:
                    raise ValueError("Aggregate selected evidence bound exceeded")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Unable to read regular member: {normalized}")
                data = source.read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError(f"Short or oversized archive member read: {normalized}")
                members[normalized] = data
    if expected_member_count is not None and member_count != expected_member_count:
        raise ValueError(f"Member count mismatch for {identity['name']}@{identity['version']}: {member_count}")
    return decoded, member_count, regular_bytes, members


def validate_terms_evidence(row):
    terms = row.get("terms_evidence")
    if not isinstance(terms, dict) or terms.get("declared_expression") != row.get("declared_license"):
        raise ValueError(f"Missing or mismatched per-row terms evidence: {row['name']}@{row['version']}")
    material_map = {item["material_path"]: item for item in row.get("materials", [])}
    raw_map = {item["material_path"]: item for item in row.get("raw_materials", [])}
    groups = terms.get("groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError(f"No retained expression groups: {row['name']}@{row['version']}")
    for group in groups:
        alternatives = group.get("alternatives")
        if not isinstance(alternatives, list) or not alternatives:
            raise ValueError(f"Expression group without alternatives: {row['name']}@{row['version']}")
        available = []
        for alternative in alternatives:
            state = alternative.get("availability")
            evidence = alternative.get("evidence")
            if state not in ("available", "unestablished") or not isinstance(evidence, list):
                raise ValueError(f"Malformed alternative evidence: {row['name']}@{row['version']}")
            if state == "available":
                if not evidence:
                    raise ValueError(f"Available alternative lacks source evidence: {row['name']}@{row['version']}")
                for item in evidence:
                    if "raw_material_path" in item:
                        raw = raw_map.get(item["raw_material_path"])
                        if (raw is None or raw.get("role") != "package_terms"
                                or alternative.get("expression") not in raw.get("identifiers", [])
                                or item.get("sha256") != raw.get("material_sha256")
                                or item.get("url") != raw.get("url")):
                            raise ValueError("Alternative does not bind exact raw package terms")
                        continue
                    material = material_map.get(item.get("material_path"))
                    if material is None or item.get("archive_member") != material["archive_member"] or item.get("sha256") != material["material_sha256"]:
                        raise ValueError(f"Alternative evidence does not bind a retained material: {row['name']}@{row['version']}")
                    if material.get("role") not in ("package_terms", "package_embedded_terms"):
                        raise ValueError(f"Non-package material used to establish alternative: {row['name']}@{row['version']}")
            elif evidence or not alternative.get("unestablished_reason"):
                raise ValueError(f"Unestablished alternative is missing its explicit reason: {row['name']}@{row['version']}")
            available.append(state == "available")
        satisfied = any(available)
        if group.get("satisfied_by_available_text") is not satisfied:
            raise ValueError(f"Expression-group availability summary mismatch: {row['name']}@{row['version']}")
        if row["classification"] == "package-complete" and not satisfied:
            raise ValueError(f"Package-complete classification lacks package-scope text: {row['name']}@{row['version']}")


def registry_shape(registry):
    pending = [registry]
    directories = 0
    maximum_items = 0
    while pending:
        directory = pending.pop()
        entries = list(os.scandir(directory))
        directories += 1
        maximum_items = max(maximum_items, len(entries))
        if len(entries) > 7:
            raise ValueError(f"Registry directory fanout exceeds seven: {directory}")
        for entry in entries:
            if entry.is_symlink():
                raise ValueError(f"Symlink in registry tree: {entry.path}")
            if entry.is_dir(follow_symlinks=False):
                pending.append(Path(entry.path))
    return directories, maximum_items


def gap_archive_members(data_root, relative, checksum, name, version, items, totals):
    compressed = bounded_regular(no_link_path(data_root, relative), COMPRESSED_CAP)
    if digest(compressed) != checksum:
        raise ValueError(f"Gap archive checksum mismatch: {name}@{version}")
    wanted = {f"{name}-{version}/{file}" for file in items}
    return parse_archive(compressed, {"name": name, "version": version}, None, wanted, totals)[3]


def replay_unindexed_gap_rows(inventory, data_root, registry, receipt):
    """Validate gap bindings whose archives sit outside the 515-archive receipt (legacy rows, path packages)."""
    count = size = packages = 0
    totals = {"decoded": 0, "members": 0, "regular_bytes": 0, "evidence_bytes": 0}
    items = (".cargo_vcs_info.json", "Cargo.toml")
    rows = [(row, row["archive_data"][0]["path"], row["checksum"]) for row in inventory["identities"]
            if not any("receipt_index" in item for item in row["archive_data"])
            and (row["name"], row["version"]) in raw_sources.GAP_PACKAGES]
    prepared = json.loads(bounded_regular(no_link_path(registry.parent, "prepared/inventory.json"), 1024 * 1024))
    rows += [(row, row["upstream_archive"]["path"], row["upstream_archive"]["sha256"]) for row in prepared["identities"]
             if (row["cargo_identity"]["name"], row["cargo_identity"]["version"]) in raw_sources.GAP_PACKAGES]
    if len(rows) != 5:
        raise ValueError("Unindexed gap row set mismatch")
    for row, relative, checksum in rows:
        name, version, _, _ = raw_sources.gap_view(row)
        members = gap_archive_members(data_root, relative, checksum, name, version, items, totals)
        view = raw_sources.terms_view(row)
        validate_terms_evidence(view)
        if view["classification"] != "package-complete":
            raise ValueError(f"Gap row not package-complete: {name}@{version}")
        added, added_bytes = raw_sources.validate_gap_binding(row, registry, members, receipt)
        count, size, packages = count + added, size + added_bytes, packages + 1
    return count, size, packages


def main():
    parser = argparse.ArgumentParser(description="Read-only bounded Task13/N1 DATA replay")
    parser.add_argument("worktree_root", type=Path)
    parser.add_argument("primary_data_root", nargs="?", type=Path)
    arguments = parser.parse_args()
    worktree = arguments.worktree_root.resolve(strict=True)
    if not worktree.is_dir():
        raise ValueError("Worktree root must be a directory")
    if arguments.primary_data_root is None:
        data_root = (worktree / "../../.rush/downloads").resolve(strict=True)
    else:
        data_root = arguments.primary_data_root.resolve(strict=True)
    if not data_root.is_dir():
        raise ValueError("Primary data root must be a directory")
    registry = worktree / "docs/legal/notices-material/registry"
    inventory_path = no_link_path(worktree, "docs/legal/notices-material/registry/inventory.json")
    receipt_path = no_link_path(data_root, RECEIPT_REL)
    inventory_raw = bounded_regular(inventory_path, 16 * 1024 * 1024)
    receipt_raw = bounded_regular(receipt_path, 2 * 1024 * 1024)
    if digest(receipt_raw) != RECEIPT_SHA:
        raise ValueError("Authorized receipt digest mismatch")
    if len(receipt_raw) != RECEIPT_BYTES:
        raise ValueError("Acquisition receipt byte size mismatch")
    inventory = json.loads(inventory_raw)
    inventory_sha = digest(inventory_raw)
    if inventory.get("acquisition_receipt", {}).get("sha256") != RECEIPT_SHA:
        raise ValueError("Inventory does not retain the authorized receipt digest")
    if inventory.get("acquisition_receipt", {}).get("bytes") != RECEIPT_BYTES:
        raise ValueError("Inventory does not retain the authorized receipt size")
    if inventory.get("acquisition_receipt", {}).get("data_root_relative_to_worktree") != "../../.rush/downloads":
        raise ValueError("Inventory data-root handoff is not the authorized relative path")
    if inventory.get("current_data_pass", {}).get("data_root_relative_to_worktree") != "../../.rush/downloads":
        raise ValueError("Current pass data-root handoff mismatch")

    records = json.loads(receipt_raw).get("records", [])
    if len(records) != ARCHIVE_COUNT:
        raise ValueError("Receipt does not contain exactly 515 archive records")
    receipt_by_index = {record.get("index"): record for record in records}
    if set(receipt_by_index) != set(range(ARCHIVE_COUNT)):
        raise ValueError("Receipt indexes are not exactly 0..514")
    identities_by_key = {}
    identities_by_index = {}
    for row in inventory.get("identities", []):
        key = (row["source"], row["name"], row["version"], row["checksum"])
        if key in identities_by_key:
            raise ValueError(f"Duplicate locked identity in inventory: {key}")
        identities_by_key[key] = row
        for item in row.get("archive_data", []):
            if "receipt_index" in item:
                index = item["receipt_index"]
                if index in identities_by_index:
                    raise ValueError(f"Duplicate archive receipt index: {index}")
                identities_by_index[index] = row
    if len(identities_by_key) != LOCKED_IDENTITY_COUNT or set(identities_by_index) != set(range(ARCHIVE_COUNT)):
        raise ValueError("Inventory identity or exact archive count mismatch")

    receipt_urls = set()
    archive_bytes = 0
    totals = {"decoded": 0, "members": 0, "regular_bytes": 0, "evidence_bytes": 0}
    material_rows = material_bytes = old_material_rows = 0
    material_archive_rows = 0
    classification_counts = {}
    raw_count = raw_bytes = raw_packages = 0
    gap_count = gap_bytes = gap_packages = 0
    pinned_raw_receipt = raw_sources.raw_receipt(registry)
    status_counts = {}
    for index in range(ARCHIVE_COUNT):
        receipt = receipt_by_index[index]
        row = identities_by_index[index]
        validate_terms_evidence(row)
        identity = row
        key = (identity["source"], identity["name"], identity["version"], identity["checksum"])
        if identities_by_key.get(key) is not row:
            raise ValueError(f"Inventory archive identity mismatch: {index}")
        encoded_name = quote(identity["name"], safe="")
        encoded_version = quote(identity["version"], safe="")
        expected_url = f"https://static.crates.io/crates/{encoded_name}/{encoded_name}-{encoded_version}.crate"
        if receipt.get("url") != expected_url:
            raise ValueError(f"Receipt URL mismatch: {index}")
        if receipt.get("name") != identity["name"] or receipt.get("version") != identity["version"]:
            raise ValueError(f"Receipt package identity mismatch: {index}")
        if receipt.get("index") != index or receipt.get("path") != f"{index:04d}.crate":
            raise ValueError(f"Receipt index/path mismatch: {index}")
        if receipt.get("http_status") != 200 or receipt.get("status") != "verified":
            raise ValueError(f"Receipt HTTP/verification status mismatch: {index}")
        if receipt.get("expected_sha256") != identity["checksum"] or receipt.get("actual_sha256") != identity["checksum"]:
            raise ValueError(f"Receipt checksum mismatch: {index}")
        if receipt["url"] in receipt_urls:
            raise ValueError(f"Duplicate receipt URL: {receipt['url']}")
        receipt_urls.add(receipt["url"])
        archive_record = row["archive_data"]
        if len(archive_record) != 1 or archive_record[0].get("receipt_index") != index:
            raise ValueError(f"Expected one archive handoff row: {index}")
        archive_ref = archive_record[0]
        expected_archive_path = f"notices-registry-authorized-1109/{index:04d}.crate"
        if archive_ref.get("path") != expected_archive_path or archive_ref.get("path") != f"notices-registry-authorized-1109/{receipt['path']}":
            raise ValueError(f"Durable archive path mismatch: {index}")
        if archive_ref.get("url") != expected_url or archive_ref.get("bytes") != receipt.get("bytes") or archive_ref.get("sha256") != identity["checksum"]:
            raise ValueError(f"Durable archive handoff mismatch: {index}")
        archive_path_on_disk = no_link_path(data_root, expected_archive_path)
        compressed = bounded_regular(archive_path_on_disk, COMPRESSED_CAP)
        if len(compressed) != receipt["bytes"] or digest(compressed) != row["checksum"]:
            raise ValueError(f"Archive byte size or checksum mismatch: {index}")
        archive_bytes += len(compressed)
        if archive_bytes > 1024 * 1024 * 1024:
            raise ValueError("Aggregate compressed archive cap exceeded")
        requested = {f"{identity['name']}-{identity['version']}/Cargo.toml"}
        for material in row.get("materials", []):
            if material.get("archive_index") != index:
                raise ValueError(f"New material archive index mismatch: {index}")
            requested.add(material["archive_member"])
        if row.get("raw_source_binding") or row.get("raw_materials"):
            for item in row.get("raw_source_binding", {}).get("archive_metadata", {}).values():
                requested.add(item["archive_member"])
        decoded, actual_members, _, source_members = parse_archive(compressed, identity, row["archive_member_count"], requested, totals)
        if len(decoded) != row["decoded_tar_bytes"]:
            raise ValueError(f"Archive decoded size mismatch: {index}")
        manifest_rows = row.get("manifest_evidence", [])
        if len(manifest_rows) != 1:
            raise ValueError(f"Expected one retained Cargo.toml manifest row: {index}")
        manifest = manifest_rows[0]
        manifest_path = f"{identity['name']}-{identity['version']}/Cargo.toml"
        if manifest["archive_member"] != manifest_path or manifest_path not in source_members:
            raise ValueError(f"Exact package-root Cargo.toml evidence missing: {index}")
        manifest_bytes = source_members[manifest_path]
        if len(manifest_bytes) != manifest["bytes"] or digest(manifest_bytes) != manifest["sha256"]:
            raise ValueError(f"Cargo.toml retained manifest digest mismatch: {index}")
        package = tomllib.loads(manifest_bytes.decode("utf-8")).get("package", {})
        if package.get("name") != identity["name"] or package.get("version") != identity["version"]:
            raise ValueError(f"Cargo.toml package identity mismatch: {index}")
        if package.get("license") != row["declared_license"] or package.get("license_file") != manifest.get("license_file"):
            raise ValueError(f"Cargo.toml declaration mismatch: {index}")
        if row.get("raw_source_binding") or row.get("raw_materials"):
            if (identity["name"], identity["version"]) in raw_sources.GAP_PACKAGES:
                count, size = raw_sources.validate_gap_binding(row, registry, source_members, pinned_raw_receipt)
                gap_count += count
                gap_bytes += size
                gap_packages += 1
            else:
                count, size = raw_sources.validate_raw_sources(row, registry, source_members, pinned_raw_receipt)
                raw_count += count
                raw_bytes += size
                raw_packages += 1
        for material in row.get("materials", []):
            relative_material = material["material_path"]
            material_path_on_disk = no_link_path(registry, relative_material)
            content = bounded_regular(material_path_on_disk, MEMBER_CAP)
            if len(content) != material["material_bytes"] or digest(content) != material["material_sha256"] or digest(content) != material["slice_sha256"]:
                raise ValueError(f"Material whole/slice digest mismatch: {relative_material}")
            member = source_members.get(material["archive_member"])
            if member is None:
                raise ValueError(f"Material source member not selected/read: {material['archive_member']}")
            if len(member) != material["member_bytes"] or digest(member) != material["member_sha256"]:
                raise ValueError(f"Source archive member digest mismatch: {material['archive_member']}")
            start, end = material["byte_range"]
            if start < 0 or end < start or end > len(member) or member[start:end] != content:
                raise ValueError(f"Material bytes differ from exact source slice: {relative_material}")
            if end - start != len(content):
                raise ValueError(f"Material byte-range length mismatch: {relative_material}")
            material_rows += 1
            material_bytes += len(content)
            material_archive_rows += 1

    for row in inventory["identities"]:
        classification_counts[row["classification"]] = classification_counts.get(row["classification"], 0) + 1
        for material in row.get("materials", []):
            if "archive_index" in material:
                continue
            path = no_link_path(registry, material["material_path"])
            content = bounded_regular(path, MEMBER_CAP)
            if len(content) != material["material_bytes"] or digest(content) != material["material_sha256"] or digest(content) != material["slice_sha256"]:
                raise ValueError(f"Preserved pre-existing material digest mismatch: {material['material_path']}")
            old_material_rows += 1
            material_rows += 1
            material_bytes += len(content)
        if row.get("archive_data") and any("receipt_index" in item for item in row["archive_data"]):
            status_counts[row["classification"]] = status_counts.get(row["classification"], 0) + 1

    extra = replay_unindexed_gap_rows(inventory, data_root, registry, pinned_raw_receipt)
    gap_count, gap_bytes, gap_packages = (gap_count + extra[0], gap_bytes + extra[1], gap_packages + extra[2])
    supplement = inventory.get("raw_source_supplement", {})
    if (raw_count, raw_bytes, raw_packages) != (8, 38580, 5):
        raise ValueError("Raw supplement replay totals mismatch")
    if (gap_count, gap_bytes, gap_packages) != raw_sources.GAP_TOTALS:
        raise ValueError(f"Gap raw replay totals mismatch: {gap_count}/{gap_bytes}/{gap_packages}")
    if (supplement.get("receipt_path") != "raw-sources/receipts/receipt.json"
            or supplement.get("receipt_sha256") != raw_sources.RAW_RECEIPT_SHA
            or supplement.get("receipt_bytes") != 5542
            or supplement.get("macro_receipt_path") != "raw-sources/receipts/jni-macro-receipt.json"
            or supplement.get("macro_receipt_sha256") != raw_sources.MACRO_RECEIPT_SHA
            or supplement.get("macro_receipt_bytes") != raw_sources.MACRO_RECEIPT_BYTES
            or supplement.get("material_count") != raw_count
            or supplement.get("material_bytes") != raw_bytes
            or supplement.get("package_count") != raw_packages
            or supplement.get("gap_receipt_path") != "raw-sources/receipts/n1-gap-receipt.json"
            or supplement.get("gap_receipt_sha256") != raw_sources.GAP_RECEIPT_SHA
            or supplement.get("gap_receipt_bytes") != raw_sources.GAP_RECEIPT_BYTES
            or supplement.get("gap_material_count") != gap_count
            or supplement.get("gap_material_bytes") != gap_bytes
            or supplement.get("gap_package_count") != gap_packages
            or supplement.get("no_license_choice_or_legal_clearance") is not True):
        raise ValueError("Raw supplement inventory mismatch")
    root_locks = lock_identities(worktree / "Cargo.lock")
    nested_locks = lock_identities(worktree / "crates/shaar-ygg-core/Cargo.lock")
    expected_identities = set(identities_by_key)
    if root_locks | nested_locks != expected_identities:
        raise ValueError("Current root/nested Cargo.lock identity tuples differ from inventory")
    root_count = len(root_locks)
    nested_count = len(nested_locks)
    shared_count = len(root_locks & nested_locks)
    for key, row in identities_by_key.items():
        if row["root_lock"] != (key in root_locks) or row["nested_lock"] != (key in nested_locks):
            raise ValueError(f"Lock membership booleans changed: {row['name']}@{row['version']}")
    counts = inventory["counts"]
    if root_count != 513 or nested_count != 215 or shared_count != 195 or len(expected_identities) != 533:
        raise ValueError("Lock membership totals differ from exact 533-identity baseline")
    if material_rows != 917 or old_material_rows != 23 or material_archive_rows != 894 or material_bytes != 4505353:
        raise ValueError(f"Material row/byte totals unexpected: rows={material_rows}, old={old_material_rows}, new={material_archive_rows}, bytes={material_bytes}")
    if counts.get("current_pass_material_file_count") != 894 or counts.get("current_pass_material_bytes") != 4421514:
        raise ValueError("Current-pass material totals mismatch")
    if counts.get("current_pass_status_counts") != status_counts:
        raise ValueError("Current-pass classification counts mismatch")
    if len(receipt_urls) != ARCHIVE_COUNT or totals["decoded"] != inventory["current_data_pass"]["decoded_tar_bytes"] or totals["members"] != inventory["current_data_pass"]["member_count"]:
        raise ValueError("Exact receipt URL set or aggregate archive totals mismatch")
    if totals["regular_bytes"] != inventory["current_data_pass"]["regular_member_bytes"]:
        raise ValueError("Aggregate regular archive member bytes mismatch")

    output = {
        "status": "PASS",
        "raw_packages": raw_packages,
        "raw_material_rows": raw_count,
        "raw_material_bytes": raw_bytes,
        "gap_raw_packages": gap_packages,
        "gap_raw_material_rows": gap_count,
        "gap_raw_material_bytes": gap_bytes,
        "actual_inventory_sha256": inventory_sha,
        "actual_inventory_bytes": len(inventory_raw),
        "receipt_sha256": digest(receipt_raw),
        "receipt_bytes": len(receipt_raw),
        "archive_count": ARCHIVE_COUNT,
        "archive_urls_unique_and_verified": len(receipt_urls),
        "archive_compressed_bytes": archive_bytes,
        "decoded_tar_bytes": totals["decoded"],
        "regular_member_bytes": totals["regular_bytes"],
        "archive_member_count": totals["members"],
        "selected_evidence_bytes_replayed": totals["evidence_bytes"],
        "material_rows": material_rows,
        "new_material_rows_source_equal": material_archive_rows,
        "old_material_rows_hash_preserved": old_material_rows,
        "material_bytes_all_rows": material_bytes,
        "locked_identities": len(expected_identities),
        "root_lock_identities": root_count,
        "nested_lock_identities": nested_count,
        "shared_lock_identities": shared_count,
        "root_only_lock_identities": root_count - shared_count,
        "nested_only_lock_identities": nested_count - shared_count,
        "current_pass_classifications": status_counts,
        "inventory_classifications": classification_counts,
        "read_only": True,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
