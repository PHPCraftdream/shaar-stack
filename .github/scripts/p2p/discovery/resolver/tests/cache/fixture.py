"""Cache-only counterfactual deltas and reversible fixture observation points."""
from pathlib import Path

HERE = Path(__file__).resolve().parent
MECHANISMS = ("cache_constructor", "cache_positive", "cache_error", "cache_alias", "cache_storage")
MODULES = {
    "src/lib.rs": ("support",),
    "src/cache.rs": ("storage",),
    "src/caching_client.rs": ("client",),
}
INPUTS = ("support.rs", "storage.rs", "client.rs", "semantics.rs", "dnssec.rs")


def counterfactual(files, mechanism, prepare):
    patch = prepare.cache_patch
    replacements = {
        "cache_constructor": ("src/cache.rs", "cache: (capacity != 0).then(|| {", "cache: Some({"),
        "cache_positive": ("src/caching_client.rs", patch.POSITIVE_NEW, patch.POSITIVE_OLD),
        "cache_error": ("src/caching_client.rs", patch.ERROR_NEW, patch.ERROR_OLD),
        "cache_alias": ("src/caching_client.rs", patch.CNAME_GUARD, ""),
        # Keep the optional type: restore zero-Moka construction only for the write path.
        "cache_storage": ("src/cache.rs", patch.UPSERT_GUARD,
            "        let fallback;\n        let cache = match &self.cache {\n"
            "            Some(cache) => cache,\n            None => {\n"
            "                fallback = Cache::builder().max_capacity(0).expire_after(EntryExpiry).build();\n"
            "                &fallback\n            }\n        };\n"),
    }
    name, old, new = replacements[mechanism]
    files[name] = prepare.patch.replace(files[name].decode(), old, new).encode()
    return name


def probes(files, replace, reverse=False):
    edits = {
        "src/cache.rs": [
            ("                Cache::builder()", "Build"),
            ("        let (ttl, result) = match result {", "Storage"),
        ],
        "src/caching_client.rs": [
            ("        let mut message = Message::response(0, OpCode::Query);", "Alias"),
        ],
    }
    for name, points in edits.items():
        text, boundary, tests = files[name].decode().partition("\n#[cfg(test)]\n")
        if not boundary:
            raise ValueError("cache fixture production boundary changed")
        for anchor, work in points:
            indent = anchor[:len(anchor) - len(anchor.lstrip())]
            added = (indent + '#[cfg(all(test, feature = "tokio"))]\n'
                     + indent + f"crate::no_cache_support::record(crate::no_cache_support::Work::{work});\n"
                     + anchor)
            text = replace(text, added, anchor) if reverse else replace(text, anchor, added)
        files[name] = (text + boundary + tests).encode()
    name = "src/caching_client.rs"
    old = "Err(err.clone())"
    new = ('Err({\n                        #[cfg(all(test, feature = "tokio"))]\n'
           '                        crate::no_cache_support::record(crate::no_cache_support::Work::ErrorClone);\n'
           '                        err.clone()\n                    })')
    files[name] = replace(files[name].decode(), new, old).encode() if reverse else replace(files[name].decode(), old, new).encode()


def instrument(files, prepare):
    probes(files, prepare.patch.replace)
    for parent, modules in MODULES.items():
        for name in modules:
            files[parent] += suffix(name)
    for name in INPUTS:
        files[f"src/no_cache_{name}"] = (HERE / name).read_bytes()


def suffix(name):
    return f'\n#[cfg(all(test, feature = "tokio"))]\n#[path = "no_cache_{name}.rs"]\nmod no_cache_{name};\n'.encode()


def uninstrument(files, prepare):
    for parent, modules in MODULES.items():
        for name in reversed(modules):
            ending = suffix(name)
            if not files[parent].endswith(ending):
                raise ValueError("cache fixture module suffix changed")
            files[parent] = files[parent].removesuffix(ending)
    for name in INPUTS:
        if files.pop(f"src/no_cache_{name}") != (HERE / name).read_bytes():
            raise ValueError("cache fixture input changed")
    probes(files, prepare.patch.replace, reverse=True)
