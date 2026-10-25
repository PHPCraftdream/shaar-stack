"""Verify and prepare isolated Noq source as data; compilation belongs to CI."""
import argparse
import hashlib
from pathlib import Path
import tarfile
import tomllib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transform import apply  # noqa: E402


DIGEST = "7c1e5b6fe668491eca022f745a0a9402585626c73a7b839b3424ace15d6a9c8f"
MULTIPATH_DIGEST = "d07edffd87b1f17cc2d45d1e7827cd977304bf9a7c4558681651a306ee3c6e20"
PATH_TEST_START = "#[test]\nfn open_path_validation_fails_server_side() -> TestResult {"
PATH_TEST_END = "\n/// client starts opening a path but the client fails to validate the path"
PATH_TEST_SWAPS = (
    (PATH_TEST_START, """#[test]
fn open_path_validation_fails_server_side() -> TestResult {
    path_validation_fails_server_side(false)
}

#[test]
fn open_path_validation_fails_server_side_key_discard_first() -> TestResult {
    path_validation_fails_server_side(true)
}

fn path_validation_fails_server_side(key_discard_first: bool) -> TestResult {"""),
    ("    let path_id = pair.open_path(Client, network_path, PathStatus::Available)?;",
     """    // No packet returns on this path; only its first send arms the eight-second idle timer.
    let deadline = pair.time + Duration::from_secs(8);
    let path_id = pair.open_path(Client, network_path, PathStatus::Available)?;"""),
    ('    info!("manual keep-alive of PathId::ZERO");', """    if key_discard_first {
        // Force the real key-discard ordering instead of relying on random phase exhaustion.
        pair.force_key_update(Client);
    }
    info!("manual keep-alive of PathId::ZERO");"""),
    ("""    info!("advancing time to past client path {path_id} idle");
    pair.advance_time();
    pair.drive();

    // The client gave up first and timed out.
    assert_matches!(
        pair.poll(Client),""", """    // drive() treats idle and key-discard timers as quiescent, not as completed.
    let mut event = pair.poll(Client);
    let mut wakeups = 0;
    while event.is_none() {
        assert!(pair.time < deadline, "path abandonment missing at its idle deadline");
        assert!(wakeups < 64, "path abandonment made no bounded timer progress");
        assert!(pair.advance_time(), "path abandonment has no pending wakeup");
        assert!(pair.time <= deadline, "next wakeup exceeds the path idle deadline");
        pair.drive_client();
        pair.drive_server();
        wakeups += 1;
        event = pair.poll(Client);
        if key_discard_first && wakeups == 1 {
            assert!(pair.time < deadline, "control requires an earlier competing timer");
            assert_matches!(event, None);
        }
    }

    if key_discard_first {
        assert!(wakeups > 1, "control must expose the old single-wakeup assumption");
    }
    // The client gave up first and timed out; unrelated events must fail immediately.
    assert_matches!(
        event,"""),
    ("    // The server sees a closed path being abandoned, never emits this to the application.",
     """    assert!(!pair.drive_bounded(64), "path abandonment signaling did not settle");
    for side in [Client, Server] {
        assert!(!pair.is_closed(side), "the original connection must survive");
        assert!(pair.paths(side).contains(&PathId::ZERO));
        assert_eq!(pair.path_status(side, PathId::ZERO)?, PathStatus::Available);
    }
    assert_matches!(pair.poll(Client), None);
    // The server sees a closed path being abandoned, never emits this to the application."""),
)


def path_timer_fixture(text, *, reverse=False):
    """Patch only this fixture; reversal must recover the exact published source."""
    original_start = PATH_TEST_SWAPS[0][1] if reverse else PATH_TEST_START
    if text.count(original_start) != 1 or text.count(PATH_TEST_END) != 1:
        raise ValueError("path timer fixture boundary changed")
    start = text.index(original_start)
    end = text.index(PATH_TEST_END, start)
    body = text[start:end]
    swaps = reversed(PATH_TEST_SWAPS) if reverse else PATH_TEST_SWAPS
    for old, new in swaps:
        before, after = (new, old) if reverse else (old, new)
        if body.count(before) != 1:
            raise ValueError("path timer fixture anchor changed")
        body = body.replace(before, after, 1)
    result = text[:start] + body + text[end:]
    original = result if reverse else text
    if hashlib.sha256(original.encode("utf-8")).hexdigest() != MULTIPATH_DIGEST:
        raise ValueError("path timer fixture differs from the reviewed archive source")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    lock = tomllib.loads(args.lock.read_text(encoding="utf-8"))
    entry = next(p for p in lock["package"]
                 if p["name"] == "noq-proto" and p["version"] == "1.3.0")
    if args.archive.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("reviewed Noq archive must not exceed 2 MiB")
    digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if digest != DIGEST or entry["checksum"] != DIGEST:
        raise ValueError("Noq archive does not match the reviewed lock checksum")
    args.destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(args.archive) as archive:
        archive.extractall(args.destination, filter="data")
    root = args.destination / "noq-proto-1.3.0"
    multipath = root / "src/tests/multipath.rs"
    original = multipath.read_text(encoding="utf-8")
    patched = path_timer_fixture(original)
    if path_timer_fixture(patched, reverse=True) != original:
        raise ValueError("path timer fixture reversal did not preserve archive source")
    apply(root, Path(__file__).with_name("payload_policy.rs"))
    multipath.write_text(patched, encoding="utf-8", newline="\n")
    manifest = root / "Cargo.toml"
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n[workspace]\n", encoding="utf-8")
    print(f"Prepared checksum-verified Noq spike at {root}; no downloaded code executed")


if __name__ == "__main__":
    main()
