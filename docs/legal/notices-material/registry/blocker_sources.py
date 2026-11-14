"""Release-blocker evidence with an explicit provenance class (stdlib only).

predecessor-repository: the project's own earlier repository holds the text; the packaged
repository was extracted from it and holds none.
package-license-index: the package's own LICENSE names the retained files that carry its terms.
"""

import hashlib
import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path


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

CLASS_PREDECESSOR = "predecessor-repository"
CLASS_INDEX = "package-license-index"
CLASSES = frozenset({CLASS_PREDECESSOR, CLASS_INDEX})
RECEIPT_REL = "raw-sources/receipts/blocker-receipt.json"
RECEIPT_SHA = "28f437fce7c3f535c8bd652349ca7e8331466f7beb632e03e70c1260aa4dea15"
RECEIPT_BYTES = 1748
SCHEMA = "n1-blocker-raw-acquisition-v1"
TOTALS = (1, 1074, 1)  # predecessor texts, bytes, packages
OBJECT_CAP = 65536
ARCHIVE_URL = "https://static.crates.io/crates/{0}/{0}-{1}.crate"
# (checksum, revision, path_in_vcs, repository, predecessor crate version, its checksum,
#  predecessor revision, predecessor path_in_vcs, predecessor repository, text file)
PREDECESSOR = {
    ("futures-bounded", "0.3.0"): (
        "b604752cefc5aa3ab98992a107a8bd99465d2825c1584e0b60cb6957b21e19d7",
        "d0fc40e0fe6c12b92696f766db6b62fd8f9051bc", "", "thomaseizinger/rust-futures-bounded",
        "0.2.3", "e1e2774cc104e198ef3d3e1ff4ab40f86fa3245d6cb6a3a46174f21463cee173",
        "edca09b58e19dd1e6ca5183898ad24b0cfb32d92", "misc/futures-bounded", "libp2p/rust-libp2p",
        "LICENSE"),
}
CURRENT_FILES = {".cargo_vcs_info.json", "Cargo.toml", "CHANGELOG.md"}
PREDECESSOR_FILES = {".cargo_vcs_info.json", "Cargo.toml"}
# ring: the package LICENSE names the files carrying its terms; one expression each.
INDEX = {
    ("ring", "0.17.14"): {
        "checksum": "a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7",
        "declared": "Apache-2.0 AND ISC",
        "index": "LICENSE",
        "maps": {"LICENSE-other-bits": "ISC", "LICENSE-BoringSSL": "Apache-2.0"},
    },
}


def text_matches(identifier, content):
    if identifier == "ISC":
        return b"Permission to use, copy, modify, and/or distribute this software for any" in content
    return raw_sources.text_matches(identifier, content)


def predecessor_url(key):
    pin = PREDECESSOR[key]
    return raw_sources.raw_url(pin[8], pin[6], pin[9])


def receipt_records(document):
    """Validate the one-request acquisition receipt into adapted records."""
    expected = {predecessor_url(key): [f"{key[0]}@{key[1]}"] for key in PREDECESSOR}
    entries = document.get("records", [])
    elapsed = document.get("elapsed_seconds")
    bounds = document.get("bounds", {})
    if (document.get("schema") != SCHEMA or document.get("status") != "completed"
            or document.get("execution_or_import") is not False or len(entries) != len(expected)
            or bounds.get("requests_max") != len(expected) or bounds.get("per_object_bytes_max") != OBJECT_CAP
            or bounds.get("redirects") != 0 or bounds.get("retries") != 0
            or type(elapsed) not in (int, float) or not 0 <= elapsed <= 300):
        raise ValueError("Blocker acquisition schema/status/bounds mismatch")
    records, seen = [], set()
    for entry in entries:
        url = entry.get("url")
        size, seconds = entry.get("bytes"), entry.get("request_seconds")
        if (url not in expected or url in seen or entry.get("identities") != expected[url]
                or entry.get("source_file") != url.rsplit("/", 1)[1] or entry.get("revision") != url.split("/")[5]
                or entry.get("status") != "completed" or entry.get("http_status") != 200
                or entry.get("curl_exit_code") != 0 or entry.get("git_blob_matches_listing") is not True
                or entry.get("git_blob_sha1") != entry.get("listing_git_blob_sha1")
                or entry.get("listing_size") != size
                or type(size) is not int or not 0 < size <= OBJECT_CAP
                or type(seconds) not in (int, float) or not 0 <= seconds <= 30
                or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256")))):
            raise ValueError("Blocker acquisition URL/HTTP/blob/request budget mismatch")
        seen.add(url)
        records.append({"url": url, "status": "fetched", "http_status": 200, "identities": expected[url],
                        "revision": entry["revision"], "source_file": entry["source_file"], "bytes": size,
                        "sha256": entry["sha256"], "git_blob_sha1": entry["git_blob_sha1"],
                        "acquisition": "blocker"})
    total = sum(record["bytes"] for record in records)
    if seen != set(expected) or document.get("body_bytes_total") != total:
        raise ValueError("Blocker acquisition URL set/total budget mismatch")
    return records


def blocker_receipt(registry):
    """Return the validated records of the pinned blocker acquisition receipt."""
    data = data_io.bounded_regular(data_io.no_link_path(registry, RECEIPT_REL), 65536)
    if len(data) != RECEIPT_BYTES or data_io.digest(data) != RECEIPT_SHA:
        raise ValueError("Pinned blocker acquisition receipt mismatch")
    return {"records": receipt_records(json.loads(data))}


def decode_metadata(metadata, members, prefix, wanted):
    """Return {file: text} after proving each retained record equals the archived member bytes."""
    if set(metadata) != wanted:
        raise ValueError("Archived metadata set mismatch")
    decoded = {}
    for file_name, item in metadata.items():
        member = f"{prefix}/{file_name}"
        content = members.get(member)
        if (item.get("archive_member") != member or content is None or len(content) > OBJECT_CAP
                or data_io.digest(content) != item.get("sha256") or content.hex() != item.get("bytes_hex")
                or item.get("bytes") != len(content)):
            raise ValueError("Retained metadata differs from archived bytes")
        decoded[file_name] = content.decode("utf-8")
    return decoded


def check_manifest(decoded, name, version, declared, slug, revision, path):
    git = json.loads(decoded[".cargo_vcs_info.json"])
    package = tomllib.loads(decoded["Cargo.toml"]).get("package", {})
    if (git.get("git", {}).get("sha1") != revision or git.get("git", {}).get("dirty", False)
            or git.get("path_in_vcs", "") != path or package.get("name") != name
            or package.get("version") != version or package.get("license") != declared
            or raw_sources.repository_slug(package.get("repository")) != slug):
        raise ValueError("Archived VCS/manifest scope mismatch")


def validate_predecessor(row, registry, members, receipt):
    """Bind a predecessor-repository text to the packaged archive and the predecessor archive's revision."""
    key = (row.get("name"), row.get("version"))
    pin = PREDECESSOR.get(key)
    if pin is None or row.get("source") != raw_sources.REGISTRY_SOURCE or row.get("checksum") != pin[0]:
        raise ValueError("Unreviewed predecessor identity/checksum")
    checksum, revision, path, slug, old_version, old_checksum, old_revision, old_path, old_slug, source_file = pin
    binding = row.get("raw_source_binding", {})
    old = binding.get("predecessor", {})
    if (row.get("provenance_class") != CLASS_PREDECESSOR or binding.get("provenance_class") != CLASS_PREDECESSOR
            or binding.get("revision") != revision or binding.get("package_path_in_vcs") != path
            or binding.get("repository") != "https://github.com/" + slug
            or binding.get("text_repository") != "https://github.com/" + old_slug
            or binding.get("text_revision") != old_revision
            or old.get("version") != old_version
            or old.get("url") != ARCHIVE_URL.format(key[0], old_version) or old.get("sha256") != old_checksum
            or old.get("package_path_in_vcs") != old_path):
        raise ValueError("Predecessor binding revision/repository/class mismatch")
    declared = row.get("declared_license")
    prefix = f"{key[0]}-{key[1]}"
    current = decode_metadata(binding.get("archive_metadata", {}), members, prefix, CURRENT_FILES)
    check_manifest(current, key[0], key[1], declared, slug, revision, path)
    if f"https://github.com/{old_slug}/pull/" not in current["CHANGELOG.md"]:
        raise ValueError("Packaged changelog does not tie the package to the predecessor repository")
    old_members = {f"{key[0]}-{old_version}/{n}": bytes.fromhex(i.get("bytes_hex", ""))
                   for n, i in old.get("archive_metadata", {}).items()}
    earlier = decode_metadata(old.get("archive_metadata", {}), old_members, f"{key[0]}-{old_version}",
                              PREDECESSOR_FILES)
    check_manifest(earlier, key[0], old_version, declared, old_slug, old_revision, old_path)
    materials = row.get("raw_materials", [])
    if len(materials) != 1 or materials[0].get("source_file") != source_file or declared != "MIT":
        raise ValueError("Reviewed predecessor material set mismatch")
    material, url = materials[0], predecessor_url(key)
    records = [r for r in receipt.get("records", []) if r.get("url") == url]
    path_rel = raw_sources.material_path(key[0], key[1], source_file)
    if (len(records) != 1 or f"{key[0]}@{key[1]}" not in records[0].get("identities", [])
            or material.get("url") != url or material.get("material_path") != path_rel
            or material.get("role") != "package_terms" or material.get("identifiers") != ["MIT"]):
        raise ValueError("Predecessor material receipt identity/scope mismatch")
    content = data_io.bounded_regular(data_io.no_link_path(registry, path_rel), OBJECT_CAP)
    blob = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
    if (len(content) != records[0]["bytes"] or len(content) != material.get("material_bytes")
            or data_io.digest(content) != records[0]["sha256"] or data_io.digest(content) != material.get("material_sha256")
            or blob != records[0]["git_blob_sha1"] or not text_matches("MIT", content)):
        raise ValueError("Predecessor text differs from the pinned receipt or is not the declared license text")
    return 1, len(content)


def validate_index(row, registry, members):
    """Prove a package LICENSE names the retained files and each carries the mapped license text."""
    key = (row.get("name"), row.get("version"))
    pin = INDEX.get(key)
    if pin is None or row.get("source") != raw_sources.REGISTRY_SOURCE or row.get("checksum") != pin["checksum"]:
        raise ValueError("Unreviewed license-index identity/checksum")
    index = row.get("license_index", {})
    prefix = f"{key[0]}-{key[1]}/"
    if (row.get("provenance_class") != CLASS_INDEX or row.get("declared_license") != pin["declared"]
            or row.get("classification") != "package-complete"
            or index.get("archive_member") != prefix + pin["index"]
            or sorted(index.get("maps", {})) != sorted(pin["maps"])):
        raise ValueError("License-index class/declaration/member mismatch")
    content = members.get(index["archive_member"])
    if content is None or data_io.digest(content) != index.get("sha256") or len(content) != index.get("bytes"):
        raise ValueError("License-index bytes differ from the archived member")
    by_member = {m.get("archive_member"): m for m in row.get("materials", [])}
    for file_name, expression in pin["maps"].items():
        item = index["maps"][file_name]
        material = by_member.get(prefix + file_name)
        if (item.get("expression") != expression or material is None or material.get("role") != "package_terms"
                or b"See " + file_name.encode() not in content):
            raise ValueError("License index does not name the mapped terms file")
        text = data_io.bounded_regular(data_io.no_link_path(registry, material["material_path"]), OBJECT_CAP)
        if (data_io.digest(text) != item.get("sha256") or data_io.digest(text) != material.get("material_sha256")
                or not text_matches(expression, text)):
            raise ValueError("Mapped terms file is not the declared license text")
        groups = [g for g in row["terms_evidence"]["groups"] if g.get("expression_group") == expression]
        evidence = [e for g in groups for a in g["alternatives"] for e in a["evidence"]]
        if len(groups) != 1 or [e.get("material_path") for e in evidence] != [material["material_path"]]:
            raise ValueError("Terms evidence does not bind the mapped terms file")
    return len(pin["maps"])
