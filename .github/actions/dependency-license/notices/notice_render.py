"""Deterministic THIRD-PARTY-NOTICES text and per-target manifest rendering."""

import hashlib
import json

import notice_corpus as corpus

GENERATOR = "shaar-notices 1"
ROLE_ORDER = {"package_terms": 0, "package_embedded_terms": 1, "component_terms": 2, "legal_context": 3}
PREAMBLE = (
    "This file reproduces, byte for byte, the license and notice texts retained from the upstream\n"
    "sources of every third-party package linked into the products named below for the stated target.\n"
    "Where a package declares alternatives joined by OR, the texts of all alternatives are listed and\n"
    "no alternative is elected. Identical texts are printed once and referenced by number. Each text\n"
    "is framed by BEGIN and END lines; its byte count and SHA-256 are on the BEGIN line, and one\n"
    "newline is added before the END line. This file is not a legal determination.\n"
)


def sort_key(entry):
    return (entry.name, entry.version, entry.source or "")


def label(text):
    prefix = "" if text.role == "package_terms" else text.role.replace("_terms", "").replace("_", "-") + ":"
    return prefix + text.label


def ordered_texts(entry):
    return sorted(entry.texts, key=lambda t: (ROLE_ORDER.get(t.role, 9), t.label, t.sha256))


def render_notices(root, target, products, entries, digests, blockers):
    """Return (bytes, ordered text hashes) for the corpus entries linked on the target."""
    numbers, order, lines = {}, [], []
    for entry in sorted(entries, key=sort_key):
        refs, seen = [], set()
        for text in ordered_texts(entry):
            if text.sha256 in seen:
                continue
            seen.add(text.sha256)
            if text.sha256 not in numbers:
                numbers[text.sha256] = len(numbers) + 1
                order.append(text)
            refs.append("T%03d=%s" % (numbers[text.sha256], label(text)))
        state = "" if entry.complete else " INCOMPLETE"
        lines.append("%s %s | %s | %s%s | %s\n" % (entry.name, entry.version, entry.declared, entry.kind, state,
                                                  " ".join(refs) or "-"))
    head = ["THIRD-PARTY NOTICES\n", "Target: %s\n" % target, "Products: %s\n" % ", ".join(products),
            "Generator: %s\n" % GENERATOR, "Registry inventory sha256: %s\n" % digests["registry"],
            "Prepared inventory sha256: %s\n" % digests["prepared"],
            "Packages: %d (%d with complete authentic text, %d release blockers)\n"
            % (len(entries), sum(1 for e in entries if e.complete), len(blockers)), "\n", PREAMBLE, "\n"]
    if blockers:
        head.append("RELEASE BLOCKERS: the packages below lack complete authentic license text in the corpus;\n"
                    "this bundle must not be released until each is resolved. Nothing has been synthesized.\n")
        head.extend("  %s %s: %s\n" % (b["name"], b["version"], b["reason"]) for b in blockers)
        head.append("\n")
    head.append("PACKAGES (name version | declared license | source kind | texts)\n")
    out = ["".join(head).encode("utf-8"), "".join(lines).encode("utf-8"), b"\nTEXTS\n"]
    for text in order:
        data = corpus.read_text(root, text)
        number = numbers[text.sha256]
        out.append(("-----BEGIN TEXT T%03d sha256=%s bytes=%d-----\n" % (number, text.sha256, len(data))).encode("ascii"))
        out.append(data)
        out.append(("\n-----END TEXT T%03d-----\n" % number).encode("ascii"))
    return b"".join(out), [t.sha256 for t in order]


def line(value):
    return json.dumps(value, sort_keys=True, separators=(", ", ": "), ensure_ascii=True)


def render_manifest(fields, entries):
    """Serialize `fields` plus one JSON line per identity; stable bytes, no host data."""
    parts = ["{\n"]
    for key in sorted(fields):
        parts.append(" %s: %s,\n" % (json.dumps(key), line(fields[key])))
    parts.append(' "identities": [\n')
    lines = []
    for entry in sorted(entries, key=sort_key):
        lines.append("  " + line({
            "name": entry.name, "version": entry.version, "kind": entry.kind, "checksum": entry.checksum,
            "declared": entry.declared, "complete": entry.complete,
            "texts": [t.sha256 for t in ordered_texts(entry)]}))
    parts.append(",\n".join(lines))
    parts.append("\n ]\n}\n")
    return "".join(parts).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()
