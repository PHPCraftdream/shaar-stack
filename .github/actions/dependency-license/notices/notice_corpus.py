"""Load the accepted notices corpus and read its license texts byte-exactly."""

import hashlib
import json
import stat
from pathlib import PurePosixPath
from typing import NamedTuple

BASE = "docs/legal/notices-material"
REGISTRY_INVENTORY = BASE + "/registry/inventory.json"
PREPARED_INVENTORY = BASE + "/prepared/inventory.json"
MAX_JSON = 16 * 1024 * 1024
MAX_TEXT = 4 * 1024 * 1024
# Retained files that mention a license without being its terms.
REFERENCE_KINDS = frozenset({"reference_context", "partial-license-reference-only-not-license-terms"})
COMPLETE = frozenset({"package-complete", "preserved_complete_text"})


class CorpusError(ValueError):
    pass


class Text(NamedTuple):
    path: str
    sha256: str
    size: int
    label: str
    role: str


class Entry(NamedTuple):
    kind: str
    name: str
    version: str
    source: object
    checksum: object
    declared: str
    complete: bool
    texts: tuple
    reason: str
    provenance: str = ""  # non-default text provenance class; empty means the packaged revision


def read_bounded(root, rel, cap):
    """Read a regular file below `root` without following links, bounded to `cap` bytes."""
    path = PurePosixPath(rel)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") or "\\" in part for part in path.parts):
        raise CorpusError("unsafe corpus path: %r" % rel)
    target = root
    for part in path.parts:
        target = target / part
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise CorpusError("corpus path is a link: %s" % rel)
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        raise CorpusError("corpus file is not a bounded regular file: %s" % rel)
    with target.open("rb") as stream:
        data = stream.read(cap + 1)
    if len(data) != info.st_size:
        raise CorpusError("corpus file changed while reading: %s" % rel)
    return data


def read_text(root, text):
    """Return the exact bytes of `text`, verifying its recorded size and SHA-256."""
    data = read_bounded(root, text.path, MAX_TEXT)
    if len(data) != text.size or hashlib.sha256(data).hexdigest() != text.sha256:
        raise CorpusError("retained text does not match its inventory record: %s" % text.path)
    if not data:
        raise CorpusError("retained text is empty: %s" % text.path)
    return data


def member_label(member):
    return member.split("/", 1)[-1]


def alternatives_covered(row, shas):
    """Every declared alternative must be available and backed by a loaded text."""
    groups = (row.get("terms_evidence") or {}).get("groups")
    if groups is None:
        return True
    for group in groups:
        if not group.get("satisfied_by_available_text"):
            return False
        for alternative in group["alternatives"]:
            if alternative["availability"] == "available" and not any(e["sha256"] in shas for e in alternative["evidence"]):
                return False
    return True


def registry_entry(row):
    texts = []
    for material in row.get("materials", []):
        role = material.get("role") or material.get("kind")
        if role in REFERENCE_KINDS or material.get("kind") in REFERENCE_KINDS:
            continue
        label = material.get("source_relative_path") or member_label(material["archive_member"])
        texts.append(Text(BASE + "/registry/" + material["material_path"], material["material_sha256"],
                          material["material_bytes"], label, role))
    for material in row.get("raw_materials", []):
        texts.append(Text(BASE + "/registry/" + material["material_path"], material["material_sha256"],
                          material["material_bytes"], material["source_file"], material["role"]))
    return texts


def prepared_entry(row):
    texts = []
    for material in row.get("materials", []):
        body = material.get("slice") or material
        scope = material.get("scope")
        label = member_label(material["source_member"])
        texts.append(Text(material["preserved_path"], body["sha256"], body["bytes"], label,
                          "component_terms" if scope == "component_notice" else "package_terms"))
    for material in row.get("raw_materials", []):
        texts.append(Text(material["material_path"], material["material_sha256"], material["material_bytes"],
                          material["source_file"], material["role"]))
    shared = row.get("shared_material_reference")
    if shared:
        texts.append(Text(shared["preserved_path"], shared["sha256"], shared["bytes"],
                          member_label(shared["source_member"]), "package_terms"))
    return texts


def build(rows, prepared):
    entries = {}
    for row in rows:
        if prepared:
            ident = row["cargo_identity"]
            name, version, source, checksum = ident["name"], ident["version"], None, None
            declared = (row.get("package_manifest") or {}).get("declared_license", "")
            texts = prepared_entry(row)
            classified = row.get("classification") in (None, *COMPLETE)
            complete = classified and any(t.role != "component_terms" for t in texts)
            reason = "no complete package-level license text is retained"
        else:
            name, version, source, checksum = row["name"], row["version"], row["source"], row["checksum"]
            declared = row["declared_license"]
            texts = registry_entry(row)
            complete = row["classification"] in COMPLETE and any(t.role != "component_terms" for t in texts)
            reason = row.get("review_note") or "classification " + row["classification"]
        if complete and not alternatives_covered(row, {t.sha256 for t in texts}):
            complete = False
        key = (name, version, source)
        if key in entries:
            raise CorpusError("duplicate corpus identity %s %s" % (name, version))
        kind = "path" if prepared else "registry"
        entries[key] = Entry(kind, name, version, source, checksum, declared, complete, tuple(texts), reason,
                             row.get("provenance_class", ""))
    return entries


def load(root):
    """Return (entries keyed by (name, version, source-or-None), digests of both inventories)."""
    registry_raw = read_bounded(root, REGISTRY_INVENTORY, MAX_JSON)
    prepared_raw = read_bounded(root, PREPARED_INVENTORY, MAX_JSON)
    registry = json.loads(registry_raw)["identities"]
    prepared = json.loads(prepared_raw)["identities"]
    entries = build(registry, False)
    for key, entry in build(prepared, True).items():
        if key in entries:
            raise CorpusError("path identity collides with a registry identity")
        entries[key] = entry
    digests = {"registry": hashlib.sha256(registry_raw).hexdigest(), "prepared": hashlib.sha256(prepared_raw).hexdigest()}
    return entries, digests
