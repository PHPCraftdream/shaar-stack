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


def boundary(metadata, target_name, linked):
    """Edges from linked packages into the unlinked region above `target_name` (exact exclusion evidence)."""
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
                    rows.add((packages[parent][0], packages[parent][1], packages[dep["pkg"]][0],
                              packages[dep["pkg"]][1], kind["kind"] or "normal", kind["target"] or ""))
    return sorted(rows)


def tree_identities(text):
    """Parse `cargo tree --prefix none --format '{p}'` output into a set of (name, version)."""
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) < 2 or not parts[1].startswith("v"):
            raise GraphError("unexpected cargo tree line: %r" % line[:80])
        out.add((parts[0], parts[1][1:]))
    return out
