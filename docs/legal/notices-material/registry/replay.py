import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_regular(path, cap):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > cap:
        raise ValueError(f"Not a bounded regular file: {path}")
    with path.open("rb") as stream:
        data = stream.read(cap + 1)
    if len(data) != metadata.st_size or len(data) > cap:
        raise ValueError(f"Bounded read mismatch: {path}")
    return data


def safe_relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError(f"Unsafe relative path: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") or "\x00" in part for part in parts):
        raise ValueError(f"Unsafe path component: {value!r}")
    return parts


def no_link_path(root, relative):
    parts = safe_relative_path(relative)
    current = root
    for part in parts:
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"Symlink in DATA path: {current}")
    return current


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
    if member_count != expected_member_count:
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


RAW_RECEIPT_SHA = "d4f45767bba3d21266670faa1ffeacc8076c9768a2da5f23d382aac2ebf8bfd5"
MACRO_RECEIPT_SHA = "1a9f927618e812d27bdd1d1850042b9efa21a9f1f42396add47a468eac1aa120"
MACRO_RECEIPT_BYTES = 5646
MACRO_PROPOSAL_SHA = "dca3218e59f24108feedbc36fdb416c500792a35c5aee50b48ee1b3fadf457a7"
MACRO_READMES = {("jni-macros", "0.22.4"): None, ("jni-sys-macros", "0.4.1"): "README.md"}
RAW_PACKAGES = {
    ("dlopen2", "0.8.2"): (
        "5e2c5bd4158e66d1e215c49b837e11d62f3267b30c92f1d171c4d3105e3dc4d4",
        "cc80e4a0a90d499b677fdf7743699b4b3a43a989", "dlopen2", "OpenByteDev/dlopen2"),
    ("valuable", "0.1.1"): (
        "ba73ea9cf16a25df0c8caa16c51acb937d5712a8429db78a3ee29d5dcacd3a65",
        "9efc29b6e58cef28f6566a47aa7e142a55fead77", "valuable", "tokio-rs/valuable"),
    ("jni", "0.22.4"): (
        "5efd9a482cf3a427f00d6b35f14332adc7902ce91efb778580e180ff90fa3498",
        "5ae9458a4ec44c5318f37ddc7569c1d4ae8a69e7", "crates/jni", "jni-rs/jni-rs"),
    ("jni-macros", "0.22.4"): (
        "a00109accc170f0bdb141fed3e393c565b6f5e072365c3bd58f5b062591560a3",
        "33045a124105c939d1e2cbdcb5a39e5d868ffa03", "crates/jni-macros", "jni-rs/jni-rs"),
    ("jni-sys-macros", "0.4.1"): (
        "38c0b942f458fe50cdac086d2f946512305e5631e720728f2a61aabcd47a6264",
        "64d77b7a5f119d7b55b4e2c169a4668067ff59e6", "jni-sys-macros", "jni-rs/jni-sys"),
}


def macro_records(document):
    """Validate the second acquisition format before adapting its separate DATA records."""
    attempts = document.get("attempts", [])
    elapsed = document.get("elapsed_seconds")
    if (document.get("proposal_sha256") != MACRO_PROPOSAL_SHA or document.get("status") != "completed"
            or len(attempts) != 4 or type(elapsed) not in (int, float) or not 0 <= elapsed <= 300):
        raise ValueError("Macro acquisition proposal/status/pass budget mismatch")
    records, seen = [], set()
    for attempt in attempts:
        candidate = attempt.get("candidate", {})
        package = candidate.get("package", {})
        key = (package.get("name"), package.get("version"))
        if key not in MACRO_READMES:
            raise ValueError("Unreviewed macro acquisition package")
        checksum, revision, package_path, repository = RAW_PACKAGES[key]
        name = candidate.get("root_candidate_path")
        url = f"https://raw.githubusercontent.com/{repository}/{revision}/{name}"
        size, seconds = attempt.get("bytes"), attempt.get("request_seconds")
        if (name not in {"LICENSE-APACHE", "LICENSE-MIT"} or (key, name) in seen
                or package.get("checksum") != checksum or candidate.get("revision") != revision
                or candidate.get("package_path_in_vcs") != package_path
                or candidate.get("repository") != "https://github.com/" + repository
                or candidate.get("url") != url or attempt.get("attempt_number_for_url") != 1
                or attempt.get("status") != "completed" or attempt.get("text_available") is not True
                or attempt.get("http_status_output") != "200" or attempt.get("curl_exit_code") != 0
                or type(size) is not int or not 0 < size <= 65536
                or type(seconds) not in (int, float) or not 0 <= seconds <= 30):
            raise ValueError("Macro acquisition identity/HTTP/material/request budget mismatch")
        seen.add((key, name))
        records.append({"url": url, "status": "fetched", "http_status": 200,
                        "identities": [f"{key[0]}@{key[1]}"], "revision": revision,
                        "source_file": name, "bytes": size, "sha256": attempt.get("sha256"),
                        "acquisition_proposal_sha256": MACRO_PROPOSAL_SHA})
    expected = {(key, name) for key in MACRO_READMES for name in ("LICENSE-APACHE", "LICENSE-MIT")}
    total = sum(record["bytes"] for record in records)
    if seen != expected or document.get("body_bytes_total") != total or total > 262144:
        raise ValueError("Macro acquisition material set/total budget mismatch")
    return records


def raw_receipt(registry):
    data = bounded_regular(no_link_path(registry, "raw-sources/receipt.json"), 65536)
    if len(data) != 5542 or digest(data) != RAW_RECEIPT_SHA:
        raise ValueError("Pinned raw acquisition receipt mismatch")
    receipt = json.loads(data)
    data = bounded_regular(no_link_path(registry, "raw-sources/jni-macro-receipt.json"), 65536)
    if len(data) != MACRO_RECEIPT_BYTES or digest(data) != MACRO_RECEIPT_SHA:
        raise ValueError("Pinned macro acquisition receipt mismatch")
    receipt["records"].extend(macro_records(json.loads(data)))
    receipt["macro_proposal_sha256"] = MACRO_PROPOSAL_SHA
    return receipt


def validate_raw_sources(row, registry, source_members, receipt):
    """Bind separate repository-root DATA to one exact locked archive revision."""
    key = (row["name"], row["version"])
    expected = RAW_PACKAGES.get(key)
    if expected is None or row.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
        raise ValueError("Unreviewed raw-source package identity")
    checksum, revision, package_path, repository = expected
    binding = row.get("raw_source_binding", {})
    if (row.get("checksum") != checksum or binding.get("revision") != revision
            or binding.get("package_path_in_vcs") != package_path
            or binding.get("repository") != "https://github.com/" + repository):
        raise ValueError("Raw-source archive/revision/repository binding mismatch")
    metadata = binding.get("archive_metadata", {})
    if set(metadata) != {".cargo_vcs_info.json", "Cargo.toml.orig"}:
        raise ValueError("Raw-source archived metadata set mismatch")
    decoded = {}
    for name, item in metadata.items():
        member = f"{row['name']}-{row['version']}/{name}"
        content = source_members.get(member)
        if (item.get("archive_member") != member or content is None
                or len(content) > 65536 or digest(content) != item.get("sha256")
                or content.hex() != item.get("bytes_hex")):
            raise ValueError("Raw-source metadata differs from archived bytes")
        decoded[name] = content.decode("utf-8")
    vcs = json.loads(decoded[".cargo_vcs_info.json"])
    original = tomllib.loads(decoded["Cargo.toml.orig"]).get("package", {})
    readme = MACRO_READMES[key] if key in MACRO_READMES else (
        "../README.md" if package_path.count("/") == 0 else "../../README.md")
    if key in MACRO_READMES and (original.get("license") != "MIT OR Apache-2.0"
            or original.get("repository") != "https://github.com/" + repository
            or vcs.get("git", {}).get("dirty", False)
            or receipt.get("macro_proposal_sha256") != MACRO_PROPOSAL_SHA):
        raise ValueError("Macro archived license/repository/clean revision/proposal scope mismatch")
    if (vcs.get("git", {}).get("sha1") != revision or vcs.get("path_in_vcs") != package_path
            or original.get("readme") != readme or binding.get("original_readme") != readme):
        raise ValueError("Archived VCS/readme scope mismatch")
    if receipt.get("proposal_sha256") != "5a3d9d02e89b33df6c677268a44735c9770a4d7f8d92835718cb21798232dc6b":
        raise ValueError("Raw acquisition proposal mismatch")
    materials = row.get("raw_materials", [])
    filenames = {"LICENSE-APACHE", "LICENSE-MIT"} if key[0] == "jni" or key in MACRO_READMES else {"LICENSE"}
    if len(materials) != len(filenames) or {m.get("source_file") for m in materials} != filenames:
        raise ValueError("Reviewed raw material set mismatch")
    total = 0
    for material in materials:
        name = material["source_file"]
        url = f"https://raw.githubusercontent.com/{repository}/{revision}/{name}"
        records = [r for r in receipt.get("records", []) if r.get("url") == url]
        if len(records) != 1:
            raise ValueError("Raw acquisition URL absent or duplicated")
        record = records[0]
        if key in MACRO_READMES and record.get("acquisition_proposal_sha256") != MACRO_PROPOSAL_SHA:
            raise ValueError("Macro material acquisition proposal mismatch")
        identity = f"{key[0]}@{key[1]}"
        path = f"raw-sources/{key[0]}-{key[1]}/{name}"
        identifiers = ["Apache-2.0" if name == "LICENSE-APACHE" else "MIT"]
        if (record.get("status") != "fetched" or record.get("http_status") != 200
                or record.get("identities") != [identity] or record.get("revision") != revision
                or record.get("source_file") != name or material.get("url") != url
                or material.get("material_path") != path or material.get("role") != "package_terms"
                or material.get("identifiers") != identifiers):
            raise ValueError("Raw material receipt identity/scope mismatch")
        content = bounded_regular(no_link_path(registry, path), 65536)
        if (len(content) != record.get("bytes") or len(content) != material.get("material_bytes")
                or digest(content) != record.get("sha256")
                or digest(content) != material.get("material_sha256")):
            raise ValueError("Raw material bytes differ from pinned receipt")
        total += len(content)
    return len(materials), total



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
    pinned_raw_receipt = raw_receipt(registry)
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
            count, size = validate_raw_sources(row, registry, source_members, pinned_raw_receipt)
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

    supplement = inventory.get("raw_source_supplement", {})
    if (raw_count, raw_bytes, raw_packages) != (8, 38580, 5):
        raise ValueError("Raw supplement replay totals mismatch")
    if (supplement.get("receipt_path") != "raw-sources/receipt.json"
            or supplement.get("receipt_sha256") != RAW_RECEIPT_SHA
            or supplement.get("receipt_bytes") != 5542
            or supplement.get("macro_receipt_path") != "raw-sources/jni-macro-receipt.json"
            or supplement.get("macro_receipt_sha256") != MACRO_RECEIPT_SHA
            or supplement.get("macro_receipt_bytes") != MACRO_RECEIPT_BYTES
            or supplement.get("material_count") != raw_count
            or supplement.get("material_bytes") != raw_bytes
            or supplement.get("package_count") != raw_packages
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
