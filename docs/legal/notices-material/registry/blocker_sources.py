"""Release-blocker evidence with an explicit provenance class (stdlib only).

predecessor-repository: the project's own earlier repository holds the text; the packaged
repository was extracted from it and holds none.
package-license-index: the package's own LICENSE names the retained files that carry its terms.
elected-canonical-text: the package's manifest declares MIT OR Apache-2.0 and it ships no
license file; the Apache-2.0 alternative is elected on the owner's 2026-11-14 delegation and
the canonical Apache-2.0 text acquired from apache.org is retained byte-exact. This is an
engineering decision, not legal advice and not release authority.
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
CLASS_ELECTED = "elected-canonical-text"
CLASSES = frozenset({CLASS_PREDECESSOR, CLASS_INDEX, CLASS_ELECTED})
RECEIPT_REL = "raw-sources/receipts/blocker-receipt.json"
RECEIPT_SHA = "28f437fce7c3f535c8bd652349ca7e8331466f7beb632e03e70c1260aa4dea15"
RECEIPT_BYTES = 1748
SCHEMA = "n1-blocker-raw-acquisition-v1"
TOTALS = (1, 1074, 1)  # predecessor texts, bytes, packages
OBJECT_CAP = 65536
ELECTED_RECEIPT_REL = "raw-sources/receipts/apache-canonical-receipt.json"
ELECTED_RECEIPT_SHA = "d1d45a8baf42cc1b6b7716c3fa61b61f398fb399de74e9b5e65ee33308c7a1db"
ELECTED_RECEIPT_BYTES = 1717
ELECTED_SCHEMA = "canonical-license-acquisition-v1"
CANONICAL_URL = "https://www.apache.org/licenses/LICENSE-2.0.txt"
CANONICAL_MATERIAL_REL = "raw-sources/canonical/LICENSE-APACHE"
CANONICAL_SHA = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
CANONICAL_BYTES = 11358
ELECTED_TOTALS = (2, 22716, 2)  # canonical texts, bytes, packages
LICENSE_LIKE = re.compile(r"license|licence|copying|unlicense|copyright|notice", re.IGNORECASE)
# (registry checksum, archive member count, repository slug, declared expression) per identity.
ELECTED = {
    ("enum-assoc", "1.4.1"): (
        "0590c4a94da3372e83493b956755a6e2266830b6e4e3b101afe66e3f39477b91", 12, "Eolu/enum-assoc",
        "MIT OR Apache-2.0"),
    ("if-watch", "3.2.2"): (
        "71c02a5161c313f0cbdbadc511611893584a10a7b6153cb554bdf83ddce99ec2", 16, "libp2p/if-watch",
        "MIT OR Apache-2.0"),
}
ELECTED_MATERIAL = {
    "source_file": "LICENSE-APACHE",
    "material_path": CANONICAL_MATERIAL_REL,
    "role": "package_terms",
    "identifiers": ["Apache-2.0"],
    "url": CANONICAL_URL,
    "material_bytes": CANONICAL_BYTES,
    "material_sha256": CANONICAL_SHA,
}
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


def elected_receipt(registry):
    """Return the validated records of the pinned canonical acquisition receipt."""
    data = data_io.bounded_regular(data_io.no_link_path(registry, ELECTED_RECEIPT_REL), 65536)
    if len(data) != ELECTED_RECEIPT_BYTES or data_io.digest(data) != ELECTED_RECEIPT_SHA:
        raise ValueError("Pinned canonical acquisition receipt mismatch")
    return {"records": canonical_records(json.loads(data))}


def canonical_records(document):
    """Validate the one-request canonical Apache-2.0 acquisition receipt into adapted records."""
    entries = document.get("records", [])
    bounds = document.get("bounds", {})
    if (document.get("schema") != ELECTED_SCHEMA or document.get("status") != "completed"
            or document.get("date") != "2026-11-14" or document.get("execution_or_import") is not False
            or bounds.get("requests_max") != 1 or bounds.get("per_object_bytes_max") != OBJECT_CAP
            or bounds.get("redirects") != 0 or bounds.get("retries") != 0 or bounds.get("concurrency") != 1
            or len(entries) != 1):
        raise ValueError("Canonical acquisition schema/status/bounds mismatch")
    entry = entries[0]
    size = entry.get("bytes")
    if (entry.get("url") != CANONICAL_URL or entry.get("source_file") != "LICENSE-APACHE"
            or entry.get("identities") != sorted(f"{key[0]}@{key[1]}" for key in ELECTED)
            or entry.get("status") != "completed" or entry.get("http_status") != 200
            or entry.get("date") != "2026-11-14" or entry.get("redirects") != 0
            or type(size) is not int or not 0 < size <= OBJECT_CAP
            or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256")))):
        raise ValueError("Canonical acquisition URL/HTTP/identity/budget mismatch")
    if document.get("body_bytes_total") != size:
        raise ValueError("Canonical acquisition URL set/total budget mismatch")
    return [{"url": CANONICAL_URL, "status": "fetched", "http_status": 200, "identities": entry["identities"],
             "source_file": "LICENSE-APACHE", "bytes": size, "sha256": entry["sha256"], "redirects": 0,
             "acquisition": "canonical"}]


def validate_elected(row, registry, source_members, member_names, receipt):
    """Bind an elected Apache-2.0 alternative to the canonical text, its receipt and the archive."""
    key = (row.get("name"), row.get("version"))
    pin = ELECTED.get(key)
    if pin is None or row.get("source") != raw_sources.REGISTRY_SOURCE or row.get("checksum") != pin[0]:
        raise ValueError("Unreviewed elected identity/checksum")
    _, member_count, slug, declared = pin
    binding = row.get("elected_source_binding", {})
    prefix = f"{key[0]}-{key[1]}"
    member = prefix + "/Cargo.toml"
    manifest = source_members.get(member)
    if (row.get("provenance_class") != CLASS_ELECTED or binding.get("provenance_class") != CLASS_ELECTED
            or binding.get("archive_member_count") != member_count
            or binding.get("manifest_member") != member or manifest is None
            or len(manifest) != binding.get("manifest_bytes") or len(manifest) != row["manifest_evidence"][0]["bytes"]
            or data_io.digest(manifest) != binding.get("manifest_sha256")
            or binding.get("no_license_file_members") is not True
            or binding.get("canonical_text_url") != CANONICAL_URL
            or binding.get("canonical_text_sha256") != CANONICAL_SHA
            or binding.get("canonical_text_bytes") != CANONICAL_BYTES
            or binding.get("elected_alternative") != "Apache-2.0"
            or binding.get("declared_alternatives") != ["Apache-2.0", "MIT"]
            or row.get("declared_license") != declared):
        raise ValueError("Elected binding class/manifest/canonical-text pins mismatch")
    package = tomllib.loads(manifest.decode("utf-8")).get("package", {})
    if (package.get("name") != key[0] or package.get("version") != key[1]
            or package.get("license") != declared
            or raw_sources.repository_slug(package.get("repository")) != slug
            or raw_sources.declared_identifiers(declared) != ["Apache-2.0", "MIT"]):
        raise ValueError("Archived manifest does not offer the elected MIT OR Apache-2.0 alternative")
    for name in member_names:
        if LICENSE_LIKE.search(name):
            raise ValueError(f"Elected archive unexpectedly carries a license-named member: {name}")
    if len(member_names) != member_count:
        raise ValueError("Elected archive member-name count mismatch")
    if row.get("raw_materials") != [ELECTED_MATERIAL]:
        raise ValueError("Elected raw material set mismatch")
    records = [r for r in receipt.get("records", []) if r.get("url") == CANONICAL_URL]
    if len(records) != 1 or records[0].get("identities") != sorted(f"{k[0]}@{k[1]}" for k in ELECTED):
        raise ValueError("Canonical receipt does not bind both elected identities")
    record = records[0]
    content = data_io.bounded_regular(data_io.no_link_path(registry, CANONICAL_MATERIAL_REL), OBJECT_CAP)
    if (len(content) != record.get("bytes") or len(content) != CANONICAL_BYTES
            or data_io.digest(content) != record.get("sha256") or data_io.digest(content) != CANONICAL_SHA
            or not raw_sources.text_matches("Apache-2.0", content)):
        raise ValueError("Canonical text differs from the pinned receipt or is not the Apache-2.0 text")
    groups = (row.get("terms_evidence") or {}).get("groups", [])
    alternatives = groups[0].get("alternatives", []) if len(groups) == 1 else []
    by_expression = {a.get("expression"): a for a in alternatives}
    mit, apache = by_expression.get("MIT"), by_expression.get("Apache-2.0")
    if (len(alternatives) != 2 or mit is None or apache is None
            or mit.get("availability") != "unestablished" or mit.get("evidence") != []
            or not mit.get("unestablished_reason")
            or apache.get("availability") != "available"
            or apache.get("evidence") != [{"raw_material_path": CANONICAL_MATERIAL_REL, "sha256": CANONICAL_SHA,
                                           "url": CANONICAL_URL}]
            or groups[0].get("satisfied_by_available_text") is not True):
        raise ValueError("Elected terms evidence does not record the explicit OR election")
    return 1, len(content)


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
