# SPDX-License-Identifier: MIT OR Apache-2.0
"""Exact comparison-only identities for the owner-approved, default-off IP gate.

Fingerprints are retained by both OS proofs of CI 42894735758 and 42905449848.
Original proof bindings and digests remain unchanged; no arbitrary source drift
is normalized. Backend reversal controls independently validate the gate patch.
"""
OLD_RECIPE = "331d95d85eb52c0f6262e755a89e00f85fd4dc0f53c0b88938a7588b1e6b73a3"
NEW_RECIPE = "a0c72a29554aafee6327fddc7cc6b5a7a095982ee175f9b7dca82f7bab33e3bb"
SOURCES = {
    "iroh": {
        "archive": "885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833",
        "old_tree": "c8182c55a66810eed855e52543edb1d0691e6b4e2393d3025588c2da67615be6",
        "new_tree": "d0c57c59c14d2d5a1985e6d5e2c4cae3ebdc9452ca810b27c2c72984c74413f8",
        "old_manifest": "d9d5c5df6b0ee9358e9310f0d941cc58fb2bd03d9368c9c0215fff8011e831d1",
        "new_manifest": "a0af76b5b80c9ad91d57aaa3211809c379106eac14c53bcbc29f6cbceaab42bf",
    },
    "noq": {
        "archive": "b78be567e796cfa74bb9bdc4117790af2d505eb887019cf8803244353eb09d89",
        "old_tree": "ea2455871fb6dda13c1d03218beea5f825105f467d753063f875635bf252afaf",
        "new_tree": "ea2455871fb6dda13c1d03218beea5f825105f467d753063f875635bf252afaf",
        "old_manifest": "a49ba8ddcd1c5ad6d90a4d197f88fe97e831c0e40f50386f7a1eca51556b4975",
        "new_manifest": "a49ba8ddcd1c5ad6d90a4d197f88fe97e831c0e40f50386f7a1eca51556b4975",
    },
    "noq-proto": {
        "archive": "7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f",
        "old_tree": "0e7da31c77c716cd0a40386650d2fd8ba4fb86191fc00626e00d961bfebd263f",
        "new_tree": "0e7da31c77c716cd0a40386650d2fd8ba4fb86191fc00626e00d961bfebd263f",
        "old_manifest": "eb3d46d3486b825d9671b410de97613da59ef6c98365c89d83363e5569307dcb",
        "new_manifest": "eb3d46d3486b825d9671b410de97613da59ef6c98365c89d83363e5569307dcb",
    },
}


def key(name, side):
    source = SOURCES[name]
    recipe = OLD_RECIPE if side == "old" else NEW_RECIPE
    return (name, "1.3.0", f"path:prepared:{name}@1.3.0:archive={source['archive']}:"
            f"tree={source[side + '_tree']}:recipe={recipe}")


def comparison_mapping(control, candidate, control_bindings, candidate_bindings):
    """Validate the entire exact transition before returning candidate->control keys."""
    from features import AuditError
    changed = any({k for k in control if k[0] == name} != {k for k in candidate if k[0] == name}
                  for name in SOURCES)
    if not changed:
        return {}
    result = {}
    for name, source in SOURCES.items():
        old, new = key(name, "old"), key(name, "new")
        if {k for k in control if k[0] == name} != {old} or {k for k in candidate if k[0] == name} != {new}:
            raise AuditError("unapproved backend source transition: " + name)
        for bindings, side in ((control_bindings, "old"), (candidate_bindings, "new")):
            matches = [b for b in bindings.values() if b.get("package") == name]
            expected = {
                "identity": "prepared", "package": name, "version": "1.3.0",
                "archive_sha256": source["archive"], "tree_sha256": source[side + "_tree"],
                "manifest_sha256": source[side + "_manifest"],
                "recipe_sha256": OLD_RECIPE if side == "old" else NEW_RECIPE,
            }
            if len(matches) != 1 or any(matches[0].get(k) != v for k, v in expected.items()):
                raise AuditError("unapproved backend source binding: " + name)
        if "shaar-native-gate" in candidate[new]:
            raise AuditError("native test gate is enabled in the normal comparison")
        result[new] = old
    return result


def comparison_inputs(parsed, unitsets):
    """Return comparison copies; never rewrite retained bindings or proof digests."""
    control, candidate = parsed["approved_route"], parsed["candidate"]
    mapping = comparison_mapping(control[4], candidate[4], control[6], candidate[6])
    if not mapping:
        return parsed, unitsets
    fields = list(candidate)
    fields[4] = {mapping.get(k, k): v for k, v in candidate[4].items()}
    units = []
    for unit in unitsets["candidate"]:
        form = dict(unit, package=mapping.get(tuple(unit["package"]), tuple(unit["package"])))
        form["dependencies"] = [
            dict(dep, unit=dict(dep["unit"], package=mapping.get(
                tuple(dep["unit"]["package"]), tuple(dep["unit"]["package"]))))
            for dep in unit.get("dependencies", [])]
        units.append(form)
    return dict(parsed, candidate=tuple(fields)), dict(unitsets, candidate=units)
