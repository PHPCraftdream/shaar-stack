# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the prepare-only recipes of action.yml from LOCAL archives (no network).

Usage: python -I .github/actions/prepare-sources/local_prepare.py --archives DIR [--recursive]

Every candidate archive in DIR is hashed once and located by its pinned SHA-256
(the pins are copied from the recipe scripts, see PINS). A recipe runs only when
all of its archives are present with the pinned digest; the recipe scripts then
verify the digests again themselves. Only prepare steps run: never checks.py,
fixtures, graph/lease checks, cargo or any download.

Store choice: sources are prepared once into the PRIMARY checkout's ignored
`target/`. Recipes run with cwd = the repo root containing this script and the
relative `target/...` destinations. In a linked worktree `target` must be a
junction/symlink to the primary `target/`; if missing it is created here, if it
is anything else the script refuses. The primary checkout is found by reading
`.git` (gitdir -> commondir); no git command is run.

A recipe whose destination already exists is left untouched (the recipe scripts
refuse to overwrite a prepared tree) and reported as prepared.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SUFFIXES = (".crate", ".tar.gz", ".tgz")

# (recipe, label, natural file name, sha256, where the pin lives)
P = ".github/scripts/p2p/"
PINS = (
    ("native-graph", "iroh-address-lookups adapter (0f5f547)", "adapter-source.tar.gz",
     "035d35f41362c79d43f44dc1d5cdaf9c8c718fa3781fd09cf458b7b47cb014ba",
     ".github/probes/native-graph/prepare.py:22 ADAPTER_SHA"),
    ("native-graph", "n0-mainline-0.7.0", "n0-mainline-0.7.0.crate",
     "f64972176bd209d1ebe98310743614e19728a33a4b288ae8147cca9f0b8c7463",
     P + "discovery/mainline/prepare.py:19 ARCHIVE_SHA256"),
    ("native-graph", "n0-future-0.3.2", "n0-future-0.3.2.crate",
     "e2ab99dfb861450e68853d34ae665243a88b8c493d01ba957321a1e9b2312bbe",
     ".github/probes/native-graph/prepare.py:28 FUTURE_SHA"),
    ("native-graph", "serde_bencode-0.2.4", "serde_bencode-0.2.4.crate",
     "a70dfc7b7438b99896e7f8992363ab8e2c4ba26aa5ec675d32d1c3c2c33d413e",
     P + "discovery/mainline/ci/bencode/prepare.py:16 ARCHIVE_SHA256"),
    ("native-graph", "iroh-dns-1.3.0", "iroh-dns-1.3.0.crate",
     "80276761b56e904e26ea71d0863beef0bb8d5ab6b639cbd1338e4b615209e3a1",
     P + "discovery/mainline/ci/publication/prepare.py:12 ARCHIVE_SHA256"),
    ("native-graph", "multibase-0.9.3", "multibase-0.9.3.crate",
     "7e0e4a371cbf1dfd666b658ba137763edb23c45beb43cfe369b5593cd6b437b6",
     ".github/probes/native-graph/prepare.py:31 MULTIBASE_SHA"),
    ("ygg", "Yggdrasil-ng (c9a54f1)", "yggdrasil-ng.tar.gz",
     "4d978c1a8714e0569fd0a3782adab2f6b81b9c9e54d733dbeaa023aaebae96c1",
     ".github/probes/ygg/prepare.py:31 ARCHIVE_SHA256"),
    ("backend", "noq-proto-1.3.0", "noq-proto-1.3.0.crate",
     "7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f",
     ".github/scripts/backend/prepare.py:16 PACKAGES"),
    ("backend", "iroh-1.3.0", "iroh-1.3.0.crate",
     "885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833",
     ".github/scripts/backend/prepare.py:17 PACKAGES"),
    ("backend", "noq-1.3.0", "noq-1.3.0.crate",
     "b78be567e796cfa74bb9bdc4117790af2d505eb887019cf8803244353eb09d89",
     ".github/scripts/backend/prepare.py:18 PACKAGES"),
    ("simple-dns", "simple-dns-0.12.0", "simple-dns-0.12.0.crate",
     "2b6f884fa9a8d48101774bfbd3aeb81e968dd22cffd19a372da69f183db22c1a",
     P + "discovery/simple_dns/prepare.py:15 ARCHIVE_SHA256"),
    ("relay", "libp2p-relay-0.22.0", "libp2p-relay-0.22.0.crate",
     "e5227b053db429996242c00f6c756fd9b5382b942a03eec34b465431df29697a",
     P + "prepare.py:10 DIGEST"),
    ("relay", "libp2p-swarm-0.48.0", "libp2p-swarm-0.48.0.crate",
     "57ccbe1baeaef036ffde4b265871e11c64d29464036bba635378f356bcdca854",
     P + "prepare.py:12 SWARM_DIGEST"),
    ("dns", "libp2p-dns-0.45.0", "libp2p-dns-0.45.0.crate",
     "18694695e98ff9ce26ee245fdede7cd0b4186cb793b25da3258d9c053400a291",
     P + "discovery/dns/prepare.py:16 DIGEST"),
    ("resolver", "hickory-resolver-0.26.3", "hickory-resolver-0.26.3.crate",
     "3f3da5255c95d5a716857d54b5b8f4e8d67c3484d3beaaaae2ce25063b3ba981",
     P + "discovery/resolver/prepare.py:21 DIGEST"),
    ("kad", "libp2p-kad-0.49.0", "libp2p-kad-0.49.0.crate",
     "973caa45045e53f3cf1cf3d596888b82602b30640fd75485836c81aa66e7c38a",
     P + "discovery/kad/kad.py:11 DIGEST"),
)


def _cmd(script, *args):
    return [sys.executable, "-I", script, *args]


def command(recipe, a):
    """Argument list of the prepare-only step (mirrors action.yml, curl replaced)."""
    f = {label: str(path) for (label, path) in a.items()}
    if recipe == "native-graph":
        return _cmd(".github/probes/native-graph/prepare.py",
                    "--adapter-archive", f["adapter-source.tar.gz"],
                    "--mainline-archive", f["n0-mainline-0.7.0.crate"],
                    "--future-archive", f["n0-future-0.3.2.crate"],
                    "--bencode-archive", f["serde_bencode-0.2.4.crate"],
                    "--dns-archive", f["iroh-dns-1.3.0.crate"],
                    "--multibase-archive", f["multibase-0.9.3.crate"],
                    "--destination", "target/native-graph")
    if recipe == "ygg":
        return _cmd(".github/probes/ygg/prepare.py", "prepare",
                    "--archive", f["yggdrasil-ng.tar.gz"], "--destination", "target/ygg")
    if recipe == "backend":
        return _cmd(".github/scripts/backend/prepare.py",
                    "--noq-archive", f["noq-proto-1.3.0.crate"],
                    "--iroh-archive", f["iroh-1.3.0.crate"],
                    "--runtime-archive", f["noq-1.3.0.crate"],
                    "--lock", ".github/probes/iroh-paths/Cargo.lock",
                    "--destination", "target/backend")
    if recipe == "simple-dns":
        return _cmd(P + "discovery/simple_dns/prepare.py", "prepare",
                    "--archive", f["simple-dns-0.12.0.crate"],
                    "--destination", "target/p2p/simple-dns")
    if recipe == "relay":
        return _cmd(P + "prepare.py", "--archive", f["libp2p-relay-0.22.0.crate"],
                    "--destination", "target/p2p/relay",
                    "--swarm-archive", f["libp2p-swarm-0.48.0.crate"],
                    "--swarm-destination", "target/p2p/swarm")
    if recipe == "dns":
        return _cmd(P + "discovery/dns/prepare.py", "prepare",
                    "--archive", f["libp2p-dns-0.45.0.crate"],
                    "--destination", "target/p2p/dns")
    if recipe == "resolver":
        return _cmd(P + "discovery/resolver/prepare.py",
                    "--archive", f["hickory-resolver-0.26.3.crate"],
                    "--destination", "target/p2p/resolver")
    if recipe == "kad":
        return _cmd(P + "discovery/kad/kad.py", "prepare",
                    "--archive", f["libp2p-kad-0.49.0.crate"],
                    "--destination", "target/p2p/kad")
    raise ValueError(recipe)


# First destination of every recipe (existence means already prepared).
DESTINATIONS = {
    "native-graph": "target/native-graph", "ygg": "target/ygg",
    "backend": "target/backend", "simple-dns": "target/p2p/simple-dns",
    "relay": "target/p2p/relay", "dns": "target/p2p/dns",
    "resolver": "target/p2p/resolver", "kad": "target/p2p/kad",
}


def primary_checkout(root: Path) -> Path:
    """Primary checkout from `.git` (dir => root itself, file => gitdir -> commondir)."""
    git = root / ".git"
    if git.is_dir():
        return root
    text = git.read_text(encoding="utf-8").strip()
    if not text.startswith("gitdir:"):
        raise SystemExit("unrecognised .git file")
    gitdir = (root / text[len("gitdir:"):].strip()).resolve()
    common = gitdir / "commondir"
    if not common.is_file():
        return gitdir.parent.parent.parent
    return (gitdir / common.read_text(encoding="utf-8").strip()).resolve().parent


def link_target(root: Path, primary: Path) -> None:
    """Make root/target resolve to primary/target (no-op for the primary itself)."""
    store = primary / "target"
    store.mkdir(exist_ok=True)
    if root == primary:
        return
    link = root / "target"
    if not link.exists() and not link.is_symlink():
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(store)],
                           check=True, stdout=subprocess.DEVNULL)
        else:
            os.symlink(store, link, target_is_directory=True)
        return
    linked = link.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(link))
    if not linked or os.path.realpath(link) != os.path.realpath(store):
        raise SystemExit(f"refusing: {link} is not a link to {store}")


def scan(directory: Path, recursive: bool) -> dict[str, list[Path]]:
    """Hash every candidate file once; digest -> paths."""
    walker = directory.rglob("*") if recursive else directory.glob("*")
    found: dict[str, list[Path]] = {}
    for path in sorted(walker):
        if path.is_file() and not path.is_symlink() and path.name.endswith(SUFFIXES):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            found.setdefault(digest, []).append(path)
    return found


def locate(recipe, digests, directory):
    """Return (archives by natural name, problem line or None) for one recipe."""
    paths, problems = {}, []
    for rec, label, name, pin, _source in PINS:
        if rec != recipe:
            continue
        if pin in digests:
            paths[name] = digests[pin][0]
        elif (directory / name).is_file() or any(directory.rglob(name)):
            problems.append(f"digest mismatch {label} ({name}) expected sha256={pin}")
        else:
            problems.append(f"missing {label} sha256={pin}")
    return paths, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--recursive", action="store_true", help="scan subdirectories too")
    args = parser.parse_args()
    directory = args.archives.resolve()
    if not directory.is_dir():
        raise SystemExit(f"archive directory not found: {directory}")
    primary = primary_checkout(ROOT)
    link_target(ROOT, primary)
    os.chdir(ROOT)
    digests = scan(directory, args.recursive)
    failed = False
    for recipe in DESTINATIONS:
        paths, problems = locate(recipe, digests, directory)
        if problems:
            failed = True
            for problem in problems:
                print(f"{recipe}: {problem}")
            continue
        if (ROOT / DESTINATIONS[recipe]).exists():
            print(f"{recipe}: prepared (already present, left untouched)")
            continue
        result = subprocess.run(command(recipe, paths), cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            failed = True
            print(f"{recipe}: failed exit={result.returncode}")
            sys.stderr.write(result.stderr[-2000:])
        else:
            print(f"{recipe}: prepared")
    if os.name == "nt":
        hint = f"cmd /c mklink /J target {primary / 'target'}"
    else:
        hint = f"ln -s {primary / 'target'} target"
    print(f"link other worktrees (from their root): {hint}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
