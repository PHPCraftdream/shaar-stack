"""Generate and check per-target THIRD-PARTY-NOTICES for the shipped binaries.

    notices.py generate --root . --metadata M --lock Cargo.lock --out DIR [--manifest-only]
    notices.py check    --root . --metadata M --lock Cargo.lock --out DIR [--tree TARGET=FILE] [--release]

Stdlib only; run with `python -I -X utf8`. Never touches the network.
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import notice_corpus as corpus  # noqa: E402
import notice_cfg as cfg  # noqa: E402
import notice_graph as graph  # noqa: E402
import notice_render as render  # noqa: E402

RELEASE = corpus.BASE + "/release"
MAX_INPUT = 64 * 1024 * 1024


class NoticeError(ValueError):
    pass


def read_input(path, cap=MAX_INPUT):
    data = Path(path).read_bytes()
    if len(data) > cap:
        raise NoticeError("input exceeds bound: %s" % path)
    return data


def load_policy(root):
    policy = json.loads(corpus.read_bounded(root, RELEASE + "/policy.json", corpus.MAX_JSON))
    gaps = {}
    for item in policy["gaps"]:
        key = (item["name"], item["version"])
        if key in gaps or not item["reason"].strip():
            raise NoticeError("policy gap duplicated or without a reason: %s %s" % key)
        gaps[key] = item["reason"]
    policy["gap_table"] = gaps
    return policy


def check_gap_policy(policy, entries):
    """The reviewed gap list must equal the set of corpus identities without complete text."""
    missing = {(e.name, e.version) for e in entries.values() if not e.complete}
    reviewed = set(policy["gap_table"])
    if missing != reviewed:
        raise NoticeError("reviewed gap list differs from the corpus: unreviewed=%s stale=%s"
                          % (sorted(missing - reviewed), sorted(reviewed - missing)))


def resolve_rows(sets, entries, lock, first_party):
    """Map linked package keys to corpus entries; unknown identities fail closed."""
    rows, excluded = [], 0
    union = set().union(*sets.values())
    for key in sorted(union, key=lambda k: (k[0], k[1], k[2] or "")):
        name, version, source = key
        if source is None and (name, version) in first_party:
            excluded += 1
            continue
        if source is not None and not source.startswith("registry+"):
            raise NoticeError("unsupported package source for %s %s" % (name, version))
        entry = entries.get(key)
        if entry is None:
            raise NoticeError("linked package %s %s has no corpus identity" % (name, version))
        if source is not None and lock.get(key) != entry.checksum:
            raise NoticeError("lock checksum differs from the corpus for %s %s" % (name, version))
        rows.append((entry, tuple(sorted(p for p, s in sets.items() if key in s))))
    return rows, excluded


def build_target(ctx, target):
    policy, root = ctx["policy"], ctx["root"]
    cfgs = cfg.parse_rustc_cfg(policy["targets"][target]["cfg"])
    products = policy["products"]
    sets = graph.closure(ctx["metadata"], products, target, cfgs)
    first_party = {tuple(x.split(" ")) for x in policy["first_party"]}
    rows, excluded = resolve_rows(sets, ctx["entries"], ctx["lock"], first_party)
    reasons = policy["gap_table"]
    blockers = [{"name": e.name, "version": e.version, "reason": reasons[(e.name, e.version)]}
                for e, _ in rows if not e.complete]
    linked = set().union(*sets.values())
    present = {(e.name, e.version) for e, _ in rows}
    outside = [{"name": n, "version": v, "reason": reasons[(n, v)],
                "boundary": [list(r) for r in graph.boundary(ctx["metadata"], (n, v), linked)]}
               for (n, v) in sorted(reasons) if (n, v) not in present]
    text, order = render.render_notices(root, target, products, rows, ctx["digests"], blockers)
    name = "THIRD-PARTY-NOTICES-%s.txt" % target
    fields = {
        "schema": 1, "generator": render.GENERATOR, "target": target, "products": products,
        "inventories": ctx["digests"], "release_ready": not blockers,
        "counts": {"third_party": len(rows), "complete": len(rows) - len(blockers), "blockers": len(blockers),
                   "registry": sum(1 for e, _ in rows if e.kind == "registry"),
                   "path": sum(1 for e, _ in rows if e.kind == "path"), "first_party_excluded": excluded,
                   "per_product": {p: sum(1 for _, b in rows if p in b) for p in products}},
        "blockers": blockers, "not_distributed": outside,
        "notices": {"file": name, "sha256": render.sha256(text), "bytes": len(text), "texts": len(order)},
    }
    return {"name": name, "text": text, "manifest": render.render_manifest(fields, rows), "blockers": blockers,
            "linked": {(k[0], k[1]) for k in linked}, "outside": outside, "count": len(rows)}


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def compare_tree(result, tree_path):
    """The evaluator's linked set must equal Cargo's own `cargo tree -e normal` for the target."""
    expected = graph.tree_identities(read_input(tree_path).decode("utf-8"))
    if expected != result["linked"]:
        raise NoticeError("evaluated linked set differs from cargo tree: only-evaluated=%s only-cargo=%s" % (
            sorted(result["linked"] - expected)[:20], sorted(expected - result["linked"])[:20]))


def compare_record(root, target, result):
    committed = corpus.read_bounded(root, "%s/manifest-%s.json" % (RELEASE, target), corpus.MAX_JSON)
    if committed != result["manifest"]:
        old, new = set(committed.decode("utf-8").splitlines()), set(result["manifest"].decode("utf-8").splitlines())
        raise NoticeError("committed manifest for %s differs from the regenerated one: removed=%s added=%s" % (
            target, sorted(old - new)[:12], sorted(new - old)[:12]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--tree", action="append", default=[], metavar="TARGET=FILE")
    parser.add_argument("--release", action="store_true", help="also fail while distributed blockers remain")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        entries, digests = corpus.load(root)
        policy = load_policy(root)
        check_gap_policy(policy, entries)
        ctx = {"root": root, "policy": policy, "entries": entries, "digests": digests,
               "metadata": json.loads(read_input(args.metadata)), "lock": graph.load_lock(read_input(args.lock))}
        trees = dict(item.split("=", 1) for item in args.tree)
        if not set(trees) <= set(policy["targets"]):
            raise NoticeError("--tree names a target outside the policy")
        failed = False
        for target in sorted(policy["targets"]):
            result = build_target(ctx, target)
            if not args.manifest_only:
                write_atomic(args.out / result["name"], result["text"])
            write_atomic(args.out / ("manifest-%s.json" % target), result["manifest"])
            if args.command == "check":
                compare_record(root, target, result)
                if target in trees:
                    compare_tree(result, trees[target])
            print("%s: %d third-party packages linked, %d release blockers, %d reviewed gaps not distributed" % (
                target, result["count"], len(result["blockers"]), len(result["outside"])))
            for blocker in result["blockers"]:
                print("  RELEASE BLOCKER %s %s: %s" % (blocker["name"], blocker["version"], blocker["reason"]))
            failed = failed or (args.release and bool(result["blockers"]))
        return 1 if failed else 0
    except (NoticeError, corpus.CorpusError, graph.GraphError, cfg.CfgError, OSError, KeyError, ValueError) as error:
        print("notices: FAIL: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
