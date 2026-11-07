# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact Yggdrasil closure that P10 leaf 2a adds to the approved route.

Historical identities and edges were read from the Linux and Windows graph
jobs (CI run 42068466717). The four direct shaar-ygg declarations are reviewed
additions awaiting CI evidence. The closure is all or nothing.
"""
import json

_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
_EMOJI = frozenset({"base256emoji", "const-str", "match-lookup"})
_VOLATILE = ("features", "dependencies", "owner", "sha256")
PREPARED = {"ironwood": "0.2.1", "yggdrasil": "0.3.1"}
WORKSPACE = ("shaar-ygg-core", "0.1.0")

# Locked crates.io archives added by the closure.
REG = {
    ('bit-vec', '0.9.1'): "b71798fca2c1fe1086445a7258a4bc81e6e49dcd24c8d0dd9a1e57395b603f51",
    ('blake2', '0.11.0'): "5b5d4d889834ee8ecfc0f8426ad30faf7cdcb10f741a8e6d7224d95325479f6f",
    ('const-oid', '0.9.6'): "c2459377285ad874054d797f3ccebf984978aa39129f6eafde5cdc8315b612f8",
    ('crypto_box', '0.9.1'): "16182b4f39a82ec8a6851155cc4c0cda3065bb1db33651726a29e1951de0f009",
    ('crypto_secretbox', '0.1.1'): "b9d6cf87adf719ddf43a805e92c6870a531aedda35ff640442cbaf8674e141e1",
    ('der', '0.7.10'): "e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb",
    ('ed25519', '2.2.3'): "115531babc129696a58c64a4fef0a8bf9e9698629fb97e9e40767d235cfbcd53",
    ('ed25519-dalek', '2.2.0'): "70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9",
    ('getifaddrs', '0.6.2'): "a542e1b7ac1f3d62c5777d430d66eca9cb59e813c46b86e29fa9ce94ff9a4810",
    ('getopts', '0.2.24'): "cfe4fbac503b8d1f88e6676011885f34b7174f46e59956bba534ba83abded4df",
    ('glob-match', '0.2.1'): "9985c9503b412198aa4197559e9a318524ebc4519c229bfa05a535828c950b9d",
    ('murmur3', '0.5.2'): "9252111cf132ba0929b6f8e030cac2a24b507f3a4d6db6fb2896f27b354c714b",
    ('num_threads', '0.1.8'): "cabcc654086861f9e1bc5115258de62ef92c79b20f4615a1b0cc57c4e82027d4",
    ('pem', '4.0.0'): "d354a98a3d1251555de99e8fdd8afda05573c31b82f59063a7b0a29b5527f120",
    ('pkcs8', '0.10.2'): "f950b2377845cebe5cf8b5165cb3cc1a5e0fa5cfa3e1f7f55707d8fd82e0a7b7",
    ('ppv-lite86', '0.2.21'): "85eae3c4ed2f50dcfe72643da4befc30deadb458a9b590d720cde2f2b1e97da9",
    ('rand', '0.8.8'): "e058c7de0b26af77780c769414d6257830bb240f3c38477dbc2c16e5f54d6d4c",
    ('rand_chacha', '0.3.1'): "e6c10a63a0fa32252be49d21e7709d4d4baf8d231c2dbce1eaa8141b9b127d88",
    ('rand_core', '0.6.4'): "ec0be4795e2f6a28069bec0b5ff3e2ac9bafc99e6a9a7dc3547996c5c816922c",
    ('rcgen', '0.14.10'): "8774e05a7d0de114588e6a28fe7e71694b82614ed569d86d8b389dfbc98b8ad8",
    ('salsa20', '0.10.2'): "97a22f5af31f73a954c10289c93e8a50cc23d971e80ee446f1f6f7137a088213",
    ('serde_json', '1.0.154'): "e7e9cc8b1b85264074fbcc02a88680c4096b1e47df8f739dceb03bf482f04bd6",
    ('serde_spanned', '1.1.2'): "4e7523beb55eece201a2356bee0bbca0d1ab466c14c07703b2e0ee6d42cb0c2c",
    ('signature', '2.2.0'): "77549399552de45a898a580c1b41d445bf730df867cc44e6c0233bbc4b8329de",
    ('spki', '0.7.3'): "d91ed6c858b01f942cd56b37a94b3e0a1798290327d1236e4d9cf4eaca44d29d",
    ('toml', '1.2.0+spec-1.1.0'): "c5ffcdf8f50436dbbfd675c1fe1b8e0854f42b7defea8584bdebe1aee900e561",
    ('toml_writer', '1.2.0+spec-1.1.0'): "009dbb7700f11c55ef83aebbe4c0e9cf1f1ac0844bd8d6f00dc38f302026e13a",
    ('unicode-width', '0.2.3'): "ca718471876992059f251e33aafc334346ada08042b7661dd1fe313a9bced557",
    ('windows-service', '0.8.1'): "857224b3b211c6f3616921f081ee54721ee3ad2ace2fac6a6337e032f7b4dcf2",
    ('zmij', '1.0.23'): "29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b",
}

PREPARED_ARCHIVE = "4d978c1a8714e0569fd0a3782adab2f6b81b9c9e54d733dbeaa023aaebae96c1"
PREPARED_RECIPE = "1fde87853a5dfdccdc9770569952dcd0cd9fea7e7a97fb7a7b0f723b2256c93f"

FEATURE_ADDS = {
    ('aead', '0.5.2'): frozenset(('alloc', 'getrandom', 'rand_core')),
    ('cipher', '0.4.4'): frozenset(('zeroize',)),
    ('crypto-common', '0.1.7'): frozenset(('getrandom', 'rand_core')),
    ('curve25519-dalek', '4.1.3'): frozenset(('alloc', 'digest', 'precomputed-tables', 'zeroize')),
    ('displaydoc', '0.2.7'): frozenset(('default', 'std')),
    ('generic-array', '0.14.7'): frozenset(('zeroize',)),
    ('getrandom', '0.2.17'): frozenset(('std',)),
    ('hex', '0.4.3'): frozenset(('default',)),
    ('log', '0.4.34'): frozenset(('alloc', 'std')),
    ('num-traits', '0.2.19'): frozenset(('i128',)),
    ('time', '0.3.55'): frozenset(('formatting', 'local-offset', 'macros', 'parsing')),
    ('tokio', '1.54.1'): frozenset(('full', 'parking_lot', 'process', 'signal', 'signal-hook-registry')),
    ('toml_datetime', '1.1.2+spec-1.1.0'): frozenset(('serde',)),
    ('toml_edit', '0.25.17+spec-1.1.0'): frozenset(('default', 'display')),
    ('tracing-core', '0.1.36'): frozenset(('default',)),
    ('tracing-subscriber', '0.3.20'): frozenset(('local-time', 'time')),
    ('windows', '0.62.2'): frozenset(('Win32_System_LibraryLoader',)),
    ('windows-sys', '0.61.2'): frozenset(('Win32_System_Console', 'Win32_System_Power', 'Win32_System_RemoteDesktop', 'Win32_System_Services', 'Win32_UI', 'Win32_UI_WindowsAndMessaging')),
    ('x509-parser', '0.18.1'): frozenset(('ring', 'verify')),
    ('yasna', '0.6.0'): frozenset(('std', 'time')),
    ('zerocopy', '0.8.63'): frozenset(('simd',)),
}

METADATA_EDGES = frozenset({
    (('curve25519-dalek', '4.1.3'), ('digest', '0.10.7')),
    (('curve25519-dalek', '4.1.3'), ('zeroize', '1.9.1')),
    (('generic-array', '0.14.7'), ('zeroize', '1.9.1')),
    (('shaar', '0.1.0'), ('url', '2.5.8')),
    (('shaar-ygg', '0.1.0'), ('iroh', '1.3.0')),
    (('shaar-ygg', '0.1.0'), ('iroh-base', '1.3.0')),
    (('shaar-ygg', '0.1.0'), ('n0-watcher', '1.0.0')),
    (('shaar-ygg', '0.1.0'), ('noq-udp', '1.3.0')),
    (('shaar-ygg', '0.1.0'), ('tokio', '1.54.1')),
    (('shaar-ygg-core', '0.1.0'), ('zeroize', '1.9.1')),
    (('time', '0.3.55'), ('libc', '0.2.191')),
    (('tokio', '1.54.1'), ('parking_lot', '0.12.5')),
    (('tracing-subscriber', '0.3.20'), ('time', '0.3.55')),
    (('x509-parser', '0.18.1'), ('ring', '0.17.14')),
    (('yasna', '0.6.0'), ('time', '0.3.55')),
})

UNIT_EDGES = frozenset({
    (('cipher', '0.4.4'), ('zeroize', '1.9.1')),
    (('generic-array', '0.14.7'), ('zeroize', '1.9.1')),
    (('shaar', '0.1.0'), ('url', '2.5.8')),
    (('shaar-ygg', '0.1.0'), ('iroh', '1.3.0')),
    (('shaar-ygg', '0.1.0'), ('iroh-base', '1.3.0')),
    (('shaar-ygg', '0.1.0'), ('n0-watcher', '1.0.0')),
    (('shaar-ygg', '0.1.0'), ('noq-udp', '1.3.0')),
    (('shaar-ygg', '0.1.0'), ('tokio', '1.54.1')),
    (('shaar-ygg-core', '0.1.0'), ('zeroize', '1.9.1')),
    (('time', '0.3.55'), ('libc', '0.2.191')),
    (('tokio', '1.54.1'), ('parking_lot', '0.12.5')),
})

FIRST_UNITS = frozenset({
    ('asn1-rs', '0.7.2'),
    ('asn1-rs-derive', '0.6.0'),
    ('asn1-rs-impl', '0.2.0'),
    ('curve25519-dalek', '4.1.3'),
    ('der-parser', '10.0.0'),
    ('errno', '0.3.14'),
    ('lazy_static', '1.5.1'),
    ('matchers', '0.2.0'),
    ('minimal-lexical', '0.2.1'),
    ('nom', '7.1.3'),
    ('nu-ansi-term', '0.50.3'),
    ('num-bigint', '0.4.8'),
    ('num-integer', '0.1.47'),
    ('oid-registry', '0.8.1'),
    ('poly1305', '0.8.0'),
    ('regex-automata', '0.4.18'),
    ('regex-syntax', '0.8.11'),
    ('rusticata-macros', '4.1.0'),
    ('sharded-slab', '0.1.7'),
    ('signal-hook-registry', '1.4.8'),
    ('synstructure', '0.13.2'),
    ('thread_local', '1.1.10'),
    ('time-macros', '0.2.32'),
    ('tracing-log', '0.2.0'),
    ('tracing-subscriber', '0.3.20'),
    ('x509-parser', '0.18.1'),
    ('yasna', '0.6.0'),
    ('zerocopy', '0.8.63'),
})

NEW_SHARED_UNITS = frozenset({
    ('num-conv', '0.2.2', 'host'),
    ('time-core', '0.1.9', 'host'),
    ('toml_datetime', '1.1.2+spec-1.1.0', 'target'),
    ('toml_edit', '0.25.17+spec-1.1.0', 'target'),
    ('toml_parser', '1.1.5+spec-1.1.0', 'target'),
    ('winnow', '1.0.4', 'target'),
})

CLOSURE = frozenset(REG) | frozenset(PREPARED.items()) | {WORKSPACE}
NEW_UNIT_PACKAGES = CLOSURE | FIRST_UNITS


def _need(ok, message):
    if not ok:
        from features import AuditError
        raise AuditError(message)


def _source_ok(key):
    name, version, source = key
    if (name, version) in REG:
        return source == _REGISTRY + ":" + REG[(name, version)]
    if PREPARED.get(name) == version:
        return (source.startswith("path:prepared:" + name + "@" + version + ":archive=" + PREPARED_ARCHIVE + ":")
                and source.endswith(":recipe=" + PREPARED_RECIPE))
    return source == "path:workspace:" + name + "@" + version


def present(features):
    """True when the candidate carries any closure identity."""
    return any(key[:2] in CLOSURE for key in features)


def reduce_metadata(control, candidate):
    """Return the candidate package features without the declared closure and feature growth."""
    added = {key for key in candidate if key[:2] in CLOSURE}
    if not added:
        return candidate
    _need({key[:2] for key in added} == CLOSURE and len(added) == len(CLOSURE),
          "yggdrasil closure identities differ from the declaration")
    _need(not any(key[:2] in CLOSURE for key in control), "yggdrasil closure already present in the control")
    for key in added:
        _need(_source_ok(key), "unapproved yggdrasil closure source: " + key[0])
    reduced = {}
    for key, features in candidate.items():
        if key in added:
            continue
        base = control.get(key)
        if base is None:
            reduced[key] = features
            continue
        extra = set(features) - set(base)
        _need(set(base) <= set(features) and extra <= FEATURE_ADDS.get(key[:2], frozenset()),
              "unapproved feature change: " + key[0] + " +" + ",".join(sorted(extra)))
        reduced[key] = base
    return reduced


def _normal_edges(parsed):
    packages, nodes, root = parsed[1], parsed[2], parsed[3]["id"]
    seen, stack, edges = set(), [root], set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        source = (packages[pid]["name"], packages[pid]["version"])
        for dep in nodes[pid].get("deps", []):
            if any(kind.get("kind") in (None, "normal") for kind in dep.get("dep_kinds", [])):
                target = packages[dep["pkg"]]
                edges.add((source, (target["name"], target["version"])))
                stack.append(dep["pkg"])
    return edges


def check_edges(control, candidate):
    """Normal metadata edges may grow only through the closure or declared pairs."""
    before, after = _normal_edges(control), _normal_edges(candidate)
    for edge in after - before:
        _need(edge[0] in CLOSURE or edge[1] in CLOSURE or edge in METADATA_EDGES,
              "unapproved dependency edge: " + edge[0][0] + " -> " + edge[1][0])
    for edge in before - after:
        _need(edge[0][0] in _EMOJI or edge[1][0] in _EMOJI,
              "unapproved dependency edge removal: " + edge[0][0] + " -> " + edge[1][0])


def _label(form):
    name, version = form["package"][:2]
    return name + "@" + version + " " + str(form.get("target")) + " " + str(form.get("context"))


def _index(forms, role):
    index = {}
    for form in forms:
        key = json.dumps({k: v for k, v in form.items() if k not in _VOLATILE}, sort_keys=True)
        _need(key not in index, role + " units share one identity: " + _label(form))
        index[key] = form
    return index


def _edges(form):
    return {(dep["alias"], tuple(dep["kind"]), tuple(dep["unit"]["package"][:2]),
             json.dumps({k: v for k, v in dep["unit"].items() if k != "features"}, sort_keys=True))
            for dep in form.get("dependencies", [])}


def check_units(control, candidate):
    """Candidate units must embed the control units; every extra is declared."""
    before, after = _index(control, "control"), _index(candidate, "candidate")
    for key, old in before.items():
        new = after.get(key)
        _need(new is not None, "control unit missing from candidate: " + _label(old))
        ident = tuple(old["package"][:2])
        extra = set(new["features"]) - set(old["features"])
        _need(set(old["features"]) <= set(new["features"]) and extra <= FEATURE_ADDS.get(ident, frozenset()),
              "unapproved unit feature change: " + _label(old) + " +" + ",".join(sorted(extra)))
        had, has = _edges(old), _edges(new)
        _need(had <= has, "control dependency missing from candidate: " + _label(old))
        for _, _, owner, _ in has - had:
            _need(owner in NEW_UNIT_PACKAGES or (ident, owner) in UNIT_EDGES,
                  "unapproved unit dependency: " + _label(old) + " -> " + owner[0])
    for key, unit in after.items():
        if key not in before:
            ident = tuple(unit["package"][:2])
            _need(ident in NEW_UNIT_PACKAGES or ident + (unit.get("context"),) in NEW_SHARED_UNITS,
                  "unapproved candidate unit: " + _label(unit))
