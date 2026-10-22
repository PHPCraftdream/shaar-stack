"""Conntrack line parser for the P03 NAT topology fixture (stdlib only).

Supports BOTH `conntrack -L -p udp` output and /proc/net/nf_conntrack lines.
Parsing is field-by-field tokenization, never substring matching: the line is
split into whitespace tokens, and the first contiguous run of
src/dst/sport/dport key=value tokens forms the ORIGINAL tuple while the next
run forms the REPLY tuple. Bracketed flags such as [UNREPLIED] and [ASSURED]
are collected, and the protocol token ("udp"/"17", "tcp"/"6", ...) is
detected, tolerating the "ipv4 2" / "udp 17" prefixes used by /proc.
"""

PROTO_NAMES = {"udp", "tcp", "sctp", "icmp", "icmpv6", "gre", "dccp"}
PROTO_NUMS = {1, 6, 17, 47, 58, 132}
# Only these four keys participate in tuple construction; every other
# key=value field (mark=, use=, zone=, secmark=, ...) is ignored.
TUPLE_KEYS = ("src", "dst", "sport", "dport")


def _is_flag(token):
    return token.startswith("[") and token.endswith("]")


def _detect_proto(token):
    tl = token.lower()
    if tl in PROTO_NAMES:
        return tl
    if tl.isdigit() and int(tl) in PROTO_NUMS:
        # Canonicalize the protocols we care about by name.
        return {17: "udp", 6: "tcp"}.get(int(tl), tl)
    return None


def _tuple_from_pairs(pairs):
    if len(pairs) < 4:
        return None
    t = dict(pairs[:4])
    try:
        t["sport"] = int(t["sport"])
        t["dport"] = int(t["dport"])
    except (KeyError, ValueError):
        return None
    for k in ("src", "dst"):
        v = t.get(k, "")
        if not v or ("." not in v and ":" not in v):
            return None
    return {"src": t["src"], "sport": t["sport"],
            "dst": t["dst"], "dport": t["dport"]}


def parse_line(line):
    """Parse one conntrack line into a dict, or return None if unusable.

    Returned shape:
      {"raw", "proto", "flags", "unreplied", "assured",
       "orig": {src, sport, dst, dport} | None,
       "reply": {src, sport, dst, dport} | None}
    """
    if not line or not line.strip():
        return None
    proto = None
    flags = []
    tuples = []
    pairs = []
    for token in line.split():
        if _is_flag(token):
            f = token[1:-1].upper()
            flags.append(f)
            continue
        if "=" in token:
            key, _, val = token.partition("=")
            if key in TUPLE_KEYS:
                pairs.append((key, val))
                if len(pairs) % 4 == 0:
                    t = _tuple_from_pairs(pairs[-4:])
                    if t is None:
                        return None
                    tuples.append(t)
            # Non-tuple key=value fields are deliberately ignored.
            continue
        if proto is None:
            proto = _detect_proto(token)
        # Anything else (e.g. "ipv4", "2", table names) is ignored.
    if not tuples:
        return None
    # Tolerate key-order variation inside a tuple: _tuple_from_pairs only
    # counts keys, so sport=.. src=.. dport=.. dst=.. parses identically.
    return {
        "raw": line,
        "proto": proto,
        "flags": flags,
        "unreplied": "UNREPLIED" in flags,
        "assured": "ASSURED" in flags,
        "orig": tuples[0],
        "reply": tuples[1] if len(tuples) > 1 else None,
    }


def _orig_matches(entry, orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port):
    o = entry["orig"]
    return (o["src"] == orig_src_ip and o["sport"] == orig_src_port
            and o["dst"] == orig_dst_ip and o["dport"] == orig_dst_port)


def _entries_matching_orig(lines, orig_src_ip, orig_src_port,
                           orig_dst_ip, orig_dst_port, proto):
    """Yield EVERY parsed entry whose original tuple matches exactly.

    Multiple conntrack entries can share an original tuple (e.g. a stale
    unreplied entry plus a fresh replied one); callers that need a specific
    translation must consider all candidates, not just the first.
    """
    for line in lines:
        entry = parse_line(line)
        if (entry and entry["proto"] == proto
                and _orig_matches(entry, orig_src_ip, orig_src_port,
                                  orig_dst_ip, orig_dst_port)):
            yield entry


def find_entry(lines, orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port,
               proto="udp"):
    """Return the first parsed entry whose ORIGINAL tuple matches exactly.

    Both the full private source ip:port AND the destination ip:port must
    match (no partial matches), and the entry's protocol must equal `proto`
    (default udp): a tcp line with identical endpoints must not match.
    Returns None when no entry matches.
    """
    for entry in _entries_matching_orig(lines, orig_src_ip, orig_src_port,
                                        orig_dst_ip, orig_dst_port, proto):
        return entry
    return None


def has_replied_entry(lines, orig_src_ip, orig_src_port, orig_dst_ip,
                      orig_dst_port, proto="udp"):
    """True iff ANY entry matching the orig tuple is NOT marked [UNREPLIED].

    Used for REPLIED-presence checks where a wrong-token stale entry must
    not shadow a later genuine reply.
    """
    for entry in _entries_matching_orig(lines, orig_src_ip, orig_src_port,
                                        orig_dst_ip, orig_dst_port, proto):
        if not entry["unreplied"]:
            return True
    return False


def find_translation(lines, orig_src_ip, orig_src_port, orig_dst_ip,
                     orig_dst_port, responder_ip, responder_port,
                     translated_dst_ip, translated_port, proto="udp"):
    """Require a full, REPLIED address+port translation.

    Searches ALL entries matching the original tuple (not just the first):
    returns the first candidate whose reply tuple matches EXACTLY and whose
    protocol matches. Conditions (all mandatory):
      - orig tuple == full private source ip:port + destination ip:port
      - entry protocol == proto (a tcp entry with identical tuples never
        matches a udp query)
      - reply.src == responder ip:port (the real server answers)
      - reply.dst.ip == translated_dst_ip and reply.dst.port ==
        translated_port (exact ints, no range tolerance)
      - entry NOT marked [UNREPLIED] (return traffic was actually seen)
    Returns the parsed entry dict (with its raw line) or None.
    """
    for entry in _entries_matching_orig(lines, orig_src_ip, orig_src_port,
                                        orig_dst_ip, orig_dst_port, proto):
        reply = entry["reply"]
        if reply is None or entry["unreplied"]:
            continue
        if (reply["src"] == responder_ip and reply["sport"] == responder_port
                and reply["dst"] == translated_dst_ip
                and reply["dport"] == translated_port):
            return entry
    return None
