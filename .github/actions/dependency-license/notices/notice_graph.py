"""Per-target linked-package sets from Cargo metadata and the lock file."""

import tomllib

import notice_cfg as cfg


class GraphError(ValueError):
    pass


def load_lock(raw):
    """Map (name, version, source-or-None) to the lock checksum (None for path packages)."""
    packages = tomllib.loads(raw.decode("utf-8")).get("package")
    if not packages:
        raise GraphError("lock file has no packages")
    table = {}
    for package in packages:
        key = (package["name"], package["version"], package.get("source"))
        if key in table:
            raise GraphError("duplicate lock identity %s %s" % key[:2])
        table[key] = package.get("checksum")
    return table


def index(metadata):
    """Return (package id -> (name, version, source), node id -> deps list, member ids)."""
    resolve = metadata.get("resolve") if isinstance(metadata, dict) else None
    if not resolve or not resolve.get("nodes"):
        raise GraphError("metadata has no resolved graph")
    packages = {}
    for package in metadata["packages"]:
        if package["id"] in packages:
            raise GraphError("duplicate package id in metadata")
        packages[package["id"]] = (package["name"], package["version"], package.get("source"))
    nodes = {}
    for node in resolve["nodes"]:
        if node["id"] not in packages or node["id"] in nodes:
            raise GraphError("resolve node without a unique package")
        nodes[node["id"]] = node["deps"]
    for deps in nodes.values():
        for dep in deps:
            if dep["pkg"] not in nodes:
                raise GraphError("dangling resolve edge")
    return packages, nodes, set(metadata["workspace_members"])


def applies(dep, triple, cfgs):
    """True when some normal edge kind of `dep` applies; `cfgs=None` trusts a platform-filtered graph."""
    for kind in dep["dep_kinds"]:
        if kind["kind"] is not None:
            continue
        if cfgs is None or cfg.matches(kind["target"], triple, cfgs):
            return True
    return False


def closure(metadata, roots, triple=None, cfgs=None):
    """Ids reachable from each named workspace binary over normal edges applicable to the target."""
    packages, nodes, members = index(metadata)
    out = {}
    for root in roots:
        starts = [i for i in members if packages[i][0] == root]
        if len(starts) != 1:
            raise GraphError("workspace member %s is not unique" % root)
        seen, stack = {starts[0]}, [starts[0]]
        while stack:
            for dep in nodes[stack.pop()]:
                if dep["pkg"] not in seen and applies(dep, triple, cfgs):
                    seen.add(dep["pkg"])
                    stack.append(dep["pkg"])
        out[root] = {packages[i] for i in seen}
    return out


def boundary(metadata, target_name, linked, triple, cfgs):
    """Edges from linked packages into the unlinked region above `target_name` (exact exclusion evidence).

    The last column is true when a normal edge is allowed by the target cfg and was excluded by feature selection.
    """
    packages, nodes, _ = index(metadata)
    ids = [i for i, key in packages.items() if key[:2] == target_name]
    parents = {}
    for parent, deps in nodes.items():
        for dep in deps:
            parents.setdefault(dep["pkg"], []).append(parent)
    above, stack = set(ids), list(ids)
    while stack:
        for parent in parents.get(stack.pop(), ()):
            if parent not in above:
                above.add(parent)
                stack.append(parent)
    rows = set()
    for parent, deps in nodes.items():
        if packages[parent] not in linked:
            continue
        for dep in deps:
            if dep["pkg"] in above and packages[dep["pkg"]] not in linked:
                for kind in dep["dep_kinds"]:
                    feature_gated = kind["kind"] is None and cfg.matches(kind["target"], triple, cfgs)
                    rows.add((packages[parent][0], packages[parent][1], packages[dep["pkg"]][0],
                              packages[dep["pkg"]][1], kind["kind"] or "normal", kind["target"] or "", feature_gated))
    return sorted(rows)


def tree_identities(text):
    """Parse `cargo tree --prefix none --format '{p}'` into a set of (name, version, is_path)."""
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        while True:
            for suffix in (" (*)", " (proc-macro)"):
                if line.endswith(suffix):
                    line = line[: -len(suffix)]
                    break
            else:
                break
        name, separator, rest = line.partition(" v")
        version, _, marker = rest.partition(" ")
        if not separator or not name or not version or " " in name:
            raise GraphError("unexpected cargo tree line: %r" % raw[:80])
        out.add((name, version, bool(marker)))
    return out


def tree_keys(metadata, tree):
    """Map cargo tree identities to metadata package keys (name, version, source)."""
    packages, _, _ = index(metadata)
    by_shape = {}
    for key in packages.values():
        by_shape.setdefault((key[0], key[1], key[2] is None), []).append(key)
    out = set()
    for shape in tree:
        keys = by_shape.get(shape)
        if not keys or len(keys) != 1:
            raise GraphError("cargo tree package %s %s is not a unique metadata package" % shape[:2])
        out.add(keys[0])
    return out
