"""Repository-root license DATA: pinned receipts and exact archive bindings (stdlib only)."""

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

REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
PROPOSAL_SHA = "5a3d9d02e89b33df6c677268a44735c9770a4d7f8d92835718cb21798232dc6b"
RAW_RECEIPT_SHA = "d4f45767bba3d21266670faa1ffeacc8076c9768a2da5f23d382aac2ebf8bfd5"
MACRO_RECEIPT_SHA = "1a9f927618e812d27bdd1d1850042b9efa21a9f1f42396add47a468eac1aa120"
MACRO_RECEIPT_BYTES = 5646
MACRO_PROPOSAL_SHA = "dca3218e59f24108feedbc36fdb416c500792a35c5aee50b48ee1b3fadf457a7"
MACRO_READMES = {("jni-macros", "0.22.4"): None, ("jni-sys-macros", "0.4.1"): "README.md"}
GAP_RECEIPT_SHA = "3f6f2c53fb29aebd923e9e60cd36671a86f9f988d916e0a69c2fb03fc677e0e3"
GAP_RECEIPT_BYTES = 27525
GAP_SCHEMA = "n1-gap-raw-acquisition-v1"
GAP_TOTALS = (32, 182118, 17)  # files, bytes, packages
OBJECT_CAP = 65536
REPOSITORY_REGISTRY = "docs/legal/notices-material/registry/"
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
# (crate checksum, revision, path_in_vcs, repository, root files, source kind) per gap binding.
GAP_PACKAGES = {
    ("asn1-rs-impl", "0.2.0"): (
        "7b18050c2cd6fe86c3a76584ef5e0baf286d038cda203eb6223df2cc413565f7",
        "a20e5f7319c896737ad0f2557037817b91ad854f", "impl", "rusticata/asn1-rs",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("gloo-timers", "0.3.0"): (
        "bbb143cf96099802033e0d4f4963b19fd2e0b728bcf076cd9cf7f6634f092994",
        "f3bb1d1a1c33dbcccaf26446aca7d0cea8e9d574", "crates/timers", "rustwasm/gloo",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("gloo-timers", "0.4.0"): (
        "482ce8a491a501da4cd806bd190275363d674f2845005c6ddbd5d3e1dd54495d",
        "c8feeb18bf5dde6b7aed80c749e1aef89b34fb52", "crates/timers", "rustwasm/gloo",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("iroh-base", "1.3.0"): (
        "6ae9092be76c9f5429776ab3394f5a5a78dc19dc2524267e884a5b9781546c3f",
        "0072d7d84b233f9e7185eb676f049beaf557ac03", "iroh-base", "n0-computer/iroh",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("iroh-dns", "1.3.0"): (
        "80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1",
        "17c0612f80f78f5288e97b818b1360ae6ea0a51a", "iroh-dns", "n0-computer/iroh",
        ("LICENSE-APACHE", "LICENSE-MIT"), "path"),
    ("iroh-metrics-derive", "1.0.1"): (
        "1ae5f0c4405d1fbc9fb16ff422ca40620e93dc36c30ecaba0c2aee3992b7bd48",
        "a9afb7cd49bb3804fffefec61647993851f9b8c8", "iroh-metrics-derive", "n0-computer/iroh-metrics",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("iroh-relay", "1.3.0"): (
        "ee116a8233f84980574bb8d11e4517503080cd2c3605bafca04ee9c35d708bd9",
        "0072d7d84b233f9e7185eb676f049beaf557ac03", "iroh-relay", "n0-computer/iroh",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("iroh", "1.3.0"): (
        "885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833",
        "0072d7d84b233f9e7185eb676f049beaf557ac03", "iroh", "n0-computer/iroh",
        ("LICENSE-APACHE", "LICENSE-MIT"), "path"),
    ("n0-error-macros", "1.0.1"): (
        "4412346410d6616f3668c40e53c298e5320c7b856f7a960e5914e442601be79f",
        "596f4113918712d545cbb25b7fa12c7153706f54", "n0-error-macros", "n0-computer/n0-error",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("ndk-context", "0.1.1"): (
        "27b02d87554356db9e9a873add8782d4ea6e3e58ea071a9adb9a2e8ddb884a8b",
        "10f2ba388fca20f7349996ebae26ccda7a6fda5c", "ndk-context", "rust-windowing/android-ndk-rs",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("netwatch", "0.19.3"): (
        "39da9cad5f23aa43401f09497d3b280e51b5feba115d9ffbf38ca35d6ff95e96",
        "0030e57fc70981895bb86212ff0f059cc41c8a4e", "netwatch", "n0-computer/net-tools",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("prost-codec", "0.4.0"): (
        "f1da63327bb7a8c30a2227df7f43379d0a4731a2eb517b0f61416da6c2a3c739",
        "7171dce2f90c05ba7892d4ba926abb1881db27c7", "misc/prost-codec", "libp2p/rust-libp2p",
        ("LICENSE",), "registry"),
    ("rustls-platform-verifier-android", "0.2.0"): (
        "eec689c0bc40ff2458a5977b6619cb718087084a18e02a131c599b62d05e1a5f",
        "252e25161a91af476cbea620e29d277592d27ec7", "android-release-support",
        "rustls/rustls-platform-verifier", ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("rw-stream-sink", "0.5.0"): (
        "57736c2b47f266c94699b56dc7b4f0a5a669ee87e5ef62bc4a54d8e05945353d",
        "7171dce2f90c05ba7892d4ba926abb1881db27c7", "misc/rw-stream-sink", "libp2p/rust-libp2p",
        ("LICENSE",), "registry"),
    ("uint", "0.10.2"): (
        "2833f28e3adbd1b867292ee4053252ea89ab85e44e5e4701ffead8cada0539fa",
        "d2817a6d9118ee985805c37b2a44c0f2c9ae3e93", "uint", "paritytech/parity-common",
        ("LICENSE-APACHE2", "LICENSE-MIT"), "registry"),
    ("yamux", "0.14.1"): (
        "4f4e661d6ba6f09a768e31c6f3d88f9fac596ad5d376515d598a37b62d220b34",
        "cc3d0e89f615ef4f329f7a246c95a8ff1e8cc12d", "yamux", "paritytech/yamux",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
    ("yasna", "0.5.2"): (
        "e17bb3549cc1321ae1296b9cdc2698e2b6cb1992adfa19a8c72e5b7a738f44cd",
        "b7e65f9a4c317494cce2d18ea02b3d6eaaea7985", "", "qnighy/yasna.rs",
        ("LICENSE-APACHE", "LICENSE-MIT"), "registry"),
}
FILE_IDENTIFIER = {"LICENSE-APACHE": "Apache-2.0", "LICENSE-APACHE2": "Apache-2.0",
                   "LICENSE-MIT": "MIT", "LICENSE": "MIT"}


def package_group(name):
    first = name[0]
    return "a-f" if first <= "f" else "g-i" if first <= "i" else "j-l" if first <= "l" else "m-r" if first <= "r" else "s-z"


def material_path(name, version, source_file):
    return f"raw-sources/{package_group(name)}/{name}-{version}/{source_file}"


def raw_url(repository, revision, source_file):
    return f"https://raw.githubusercontent.com/{repository}/{revision}/{source_file}"


def declared_identifiers(declared):
    if not isinstance(declared, str) or re.search(r"\b(AND|WITH)\b", declared):
        raise ValueError("Unsupported license expression for a raw binding")
    return sorted(set(re.split(r"\s+OR\s+|/", declared.strip())))


def text_matches(identifier, content):
    if identifier == "MIT":
        return b"Permission is hereby granted, free of charge" in content
    return identifier == "Apache-2.0" and b"Apache License" in content and b"Version 2.0, January 2004" in content


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
        url = raw_url(repository, revision, name)
        size, seconds = attempt.get("bytes"), attempt.get("request_seconds")
        if (name not in {"LICENSE-APACHE", "LICENSE-MIT"} or (key, name) in seen
                or package.get("checksum") != checksum or candidate.get("revision") != revision
                or candidate.get("package_path_in_vcs") != package_path
                or candidate.get("repository") != "https://github.com/" + repository
                or candidate.get("url") != url or attempt.get("attempt_number_for_url") != 1
                or attempt.get("status") != "completed" or attempt.get("text_available") is not True
                or attempt.get("http_status_output") != "200" or attempt.get("curl_exit_code") != 0
                or type(size) is not int or not 0 < size <= OBJECT_CAP
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


def gap_url_identities():
    urls = {}
    for (name, version), (_, revision, _, repository, files, _) in GAP_PACKAGES.items():
        for source_file in files:
            urls.setdefault(raw_url(repository, revision, source_file), []).append(f"{name}@{version}")
    return {url: sorted(identities) for url, identities in urls.items()}


def gap_records(document):
    """Validate the gap acquisition receipt (one GET per exact pinned URL) into adapted records."""
    expected = gap_url_identities()
    entries = document.get("records", [])
    elapsed = document.get("elapsed_seconds")
    bounds = document.get("bounds", {})
    if (document.get("schema") != GAP_SCHEMA or document.get("status") != "completed"
            or document.get("execution_or_import") is not False or len(entries) != len(expected)
            or bounds.get("requests_max") != len(expected) or bounds.get("per_object_bytes_max") != OBJECT_CAP
            or bounds.get("redirects") != 0 or bounds.get("retries") != 0
            or type(elapsed) not in (int, float) or not 0 <= elapsed <= 1800):
        raise ValueError("Gap acquisition schema/status/bounds mismatch")
    records, seen = [], set()
    for entry in entries:
        url = entry.get("url")
        size, seconds = entry.get("bytes"), entry.get("request_seconds")
        if (url not in expected or url in seen or sorted(entry.get("identities", [])) != expected[url]
                or entry.get("source_file") != url.rsplit("/", 1)[1] or entry.get("revision") != url.split("/")[5]
                or entry.get("status") != "completed" or entry.get("http_status") != 200
                or entry.get("curl_exit_code") != 0 or entry.get("git_blob_matches_listing") is not True
                or entry.get("git_blob_sha1") != entry.get("listing_git_blob_sha1")
                or entry.get("listing_size") != size
                or type(size) is not int or not 0 < size <= OBJECT_CAP
                or type(seconds) not in (int, float) or not 0 <= seconds <= 30
                or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256")))):
            raise ValueError("Gap acquisition URL/HTTP/blob/request budget mismatch")
        seen.add(url)
        records.append({"url": url, "status": "fetched", "http_status": 200, "identities": expected[url],
                        "revision": entry["revision"], "source_file": entry["source_file"], "bytes": size,
                        "sha256": entry["sha256"], "git_blob_sha1": entry["git_blob_sha1"], "acquisition": "gap"})
    total = sum(record["bytes"] for record in records)
    if seen != set(expected) or document.get("body_bytes_total") != total or total > len(expected) * OBJECT_CAP:
        raise ValueError("Gap acquisition URL set/total budget mismatch")
    return records


def pinned_receipt(registry, relative, size, sha):
    data = data_io.bounded_regular(data_io.no_link_path(registry, relative), 65536 * 2)
    if len(data) != size or data_io.digest(data) != sha:
        raise ValueError(f"Pinned acquisition receipt mismatch: {relative}")
    return json.loads(data)


def raw_receipt(registry):
    receipt = pinned_receipt(registry, "raw-sources/receipts/receipt.json", 5542, RAW_RECEIPT_SHA)
    macro = pinned_receipt(registry, "raw-sources/receipts/jni-macro-receipt.json", MACRO_RECEIPT_BYTES, MACRO_RECEIPT_SHA)
    receipt["records"].extend(macro_records(macro))
    receipt["macro_proposal_sha256"] = MACRO_PROPOSAL_SHA
    gap = pinned_receipt(registry, "raw-sources/receipts/n1-gap-receipt.json", GAP_RECEIPT_BYTES, GAP_RECEIPT_SHA)
    receipt["records"].extend(gap_records(gap))
    return receipt


def validate_raw_sources(row, registry, source_members, receipt):
    """Bind separate repository-root DATA to one exact locked archive revision."""
    key = (row["name"], row["version"])
    expected = RAW_PACKAGES.get(key)
    if expected is None or row.get("source") != REGISTRY_SOURCE:
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
                or len(content) > 65536 or data_io.digest(content) != item.get("sha256")
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
    if receipt.get("proposal_sha256") != PROPOSAL_SHA:
        raise ValueError("Raw acquisition proposal mismatch")
    materials = row.get("raw_materials", [])
    filenames = {"LICENSE-APACHE", "LICENSE-MIT"} if key[0] == "jni" or key in MACRO_READMES else {"LICENSE"}
    if len(materials) != len(filenames) or {m.get("source_file") for m in materials} != filenames:
        raise ValueError("Reviewed raw material set mismatch")
    total = 0
    for material in materials:
        name = material["source_file"]
        url = raw_url(repository, revision, name)
        records = [r for r in receipt.get("records", []) if r.get("url") == url]
        if len(records) != 1:
            raise ValueError("Raw acquisition URL absent or duplicated")
        record = records[0]
        if key in MACRO_READMES and record.get("acquisition_proposal_sha256") != MACRO_PROPOSAL_SHA:
            raise ValueError("Macro material acquisition proposal mismatch")
        identity = f"{key[0]}@{key[1]}"
        path = material_path(key[0], key[1], name)
        identifiers = ["Apache-2.0" if name == "LICENSE-APACHE" else "MIT"]
        if (record.get("status") != "fetched" or record.get("http_status") != 200
                or record.get("identities") != [identity] or record.get("revision") != revision
                or record.get("source_file") != name or material.get("url") != url
                or material.get("material_path") != path or material.get("role") != "package_terms"
                or material.get("identifiers") != identifiers):
            raise ValueError("Raw material receipt identity/scope mismatch")
        content = data_io.bounded_regular(data_io.no_link_path(registry, path), 65536)
        if (len(content) != record.get("bytes") or len(content) != material.get("material_bytes")
                or data_io.digest(content) != record.get("sha256")
                or data_io.digest(content) != material.get("material_sha256")):
            raise ValueError("Raw material bytes differ from pinned receipt")
        total += len(content)
    return len(materials), total


def gap_view(row):
    """Return (name, version, checksum, declared license) for a registry row or a path row."""
    if "cargo_identity" in row:
        identity, manifest = row["cargo_identity"], row.get("package_manifest", {})
        return (identity.get("name"), identity.get("version"),
                row.get("upstream_archive", {}).get("sha256"), manifest.get("declared_license"))
    return row.get("name"), row.get("version"), row.get("checksum"), row.get("declared_license")


def terms_view(row):
    """Normalize a registry or path row for the shared terms-evidence validator."""
    if "cargo_identity" not in row:
        return row
    name, version, _, declared = gap_view(row)
    return {"name": name, "version": version, "declared_license": declared,
            "classification": row.get("classification"), "materials": [],
            "raw_materials": row.get("raw_materials", []), "terms_evidence": row.get("terms_evidence")}


def repository_slug(url):
    match = re.fullmatch(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/.*)?", url or "")
    return match.group(1) if match else None


def validate_gap_binding(row, registry, members, receipt):
    """Bind pinned repository-root license DATA to an exact archive's VCS revision and manifest."""
    name, version, checksum, declared = gap_view(row)
    expected = GAP_PACKAGES.get((name, version))
    if expected is None:
        raise ValueError("Unreviewed gap binding identity")
    pin, revision, package_path, repository, files, kind = expected
    if (("cargo_identity" in row) != (kind == "path") or (kind == "registry" and row.get("source") != REGISTRY_SOURCE)
            or checksum != pin):
        raise ValueError("Gap binding source kind/checksum mismatch")
    binding = row.get("raw_source_binding", {})
    if (binding.get("revision") != revision or binding.get("package_path_in_vcs") != package_path
            or binding.get("repository") != "https://github.com/" + repository):
        raise ValueError("Gap binding revision/path/repository mismatch")
    metadata = binding.get("archive_metadata", {})
    if set(metadata) != {".cargo_vcs_info.json", "Cargo.toml"}:
        raise ValueError("Gap archived metadata set mismatch")
    decoded = {}
    for file_name, item in metadata.items():
        member = f"{name}-{version}/{file_name}"
        content = members.get(member)
        if (item.get("archive_member") != member or content is None or len(content) > 65536
                or data_io.digest(content) != item.get("sha256") or content.hex() != item.get("bytes_hex")
                or item.get("bytes") != len(content)):
            raise ValueError("Gap metadata differs from archived bytes")
        decoded[file_name] = content.decode("utf-8")
    vcs = json.loads(decoded[".cargo_vcs_info.json"])
    git = vcs.get("git", {})
    package = tomllib.loads(decoded["Cargo.toml"]).get("package", {})
    if (git.get("sha1") != revision or git.get("dirty", False) or vcs.get("path_in_vcs", "") != package_path
            or package.get("name") != name or package.get("version") != version
            or package.get("license") != declared or repository_slug(package.get("repository")) != repository):
        raise ValueError("Archived VCS/manifest scope mismatch")
    materials = row.get("raw_materials", [])
    wanted = {FILE_IDENTIFIER[f] for f in files}
    if (len(materials) != len(files) or {m.get("source_file") for m in materials} != set(files)
            or sorted(wanted) != declared_identifiers(declared)):
        raise ValueError("Reviewed gap material set does not cover the declared expression")
    total = 0
    for material in materials:
        source_file = material["source_file"]
        url = raw_url(repository, revision, source_file)
        records = [r for r in receipt.get("records", []) if r.get("url") == url]
        if len(records) != 1:
            raise ValueError("Gap acquisition URL absent or duplicated")
        record = records[0]
        identifiers = [FILE_IDENTIFIER[source_file]]
        path = material_path(name, version, source_file)
        recorded = REPOSITORY_REGISTRY + path if kind == "path" else path  # path rows use repository-relative paths
        if (record.get("acquisition") != "gap" or f"{name}@{version}" not in record.get("identities", [])
                or material.get("url") != url or material.get("material_path") != recorded
                or material.get("role") != "package_terms" or material.get("identifiers") != identifiers):
            raise ValueError("Gap material receipt identity/scope mismatch")
        content = data_io.bounded_regular(data_io.no_link_path(registry, path), OBJECT_CAP)
        blob = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
        if (len(content) != record.get("bytes") or len(content) != material.get("material_bytes")
                or data_io.digest(content) != record.get("sha256")
                or data_io.digest(content) != material.get("material_sha256")
                or blob != record.get("git_blob_sha1") or not text_matches(identifiers[0], content)):
            raise ValueError("Gap material bytes differ from pinned receipt or are not the declared license text")
        total += len(content)
    return len(materials), total
