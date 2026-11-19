#![forbid(unsafe_code)]
use super::*;
use crate::identity::Identity;
use std::{
    cell::Cell,
    future::Future,
    io::{self, Write},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    sync::mpsc,
    task::{Context, Waker},
    time::Duration,
};

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/identity-store-fixtures");
        std::fs::create_dir_all(&base).expect("fixture parent");
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("fixture directory: {err}"),
            }
        }
        panic!("fixture namespace exhausted");
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn partial_write_and_sync_failures_remove_only_the_new_file() {
    let dir = FixtureDir::new();
    for sync_failure in [false, true] {
        let path = dir.0.join(if sync_failure { "sync" } else { "write" });
        let writes = Cell::new(0);
        let syncs = Cell::new(0);
        let err = create_new_with_io(
            &path,
            &[8; 32],
            |file, bytes| {
                writes.set(writes.get() + 1);
                let data: &[u8] = if sync_failure { bytes } else { &bytes[..7] };
                file.write_all(data)?;
                assert_eq!(file.metadata()?.len(), data.len() as u64);
                if sync_failure {
                    Ok(())
                } else {
                    Err(io::Error::other("injected write failure"))
                }
            },
            |_| {
                syncs.set(syncs.get() + 1);
                Err(io::Error::other("injected sync failure"))
            },
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)));
        assert_eq!(writes.get(), 1);
        assert_eq!(syncs.get(), usize::from(sync_failure));
        assert!(!path.exists(), "failed creation must remove its new file");
    }
}

#[test]
fn existing_file_is_not_opened_for_injected_write_or_sync() {
    let dir = FixtureDir::new();
    let path = dir.0.join("existing");
    std::fs::write(&path, [6; 32]).unwrap();
    let err = create_new_with_io(
        &path,
        &[8; 32],
        |_, _| panic!("write on existing key"),
        |_| panic!("sync on existing key"),
    )
    .unwrap_err();
    assert!(matches!(err, IdentityError::AlreadyExists));
    assert_eq!(std::fs::read(path).unwrap(), [6; 32]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_waiter_does_not_interrupt_owned_worker_cleanup() {
    let dir = FixtureDir::new();
    let path = dir.0.join("cancelled");
    let worker_path = path.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut worker = tokio::task::spawn_blocking(move || {
        let seed = zeroize::Zeroizing::new([8; 32]);
        create_new_with_io(
            &worker_path,
            &seed,
            move |file, bytes| {
                file.write_all(&bytes[..7])?;
                let length = file.metadata()?.len();
                started_tx
                    .send(length)
                    .map_err(|_| io::Error::other("observer dropped"))?;
                release_rx
                    .recv()
                    .map_err(|_| io::Error::other("release dropped"))?;
                Err(io::Error::other("injected partial-write failure"))
            },
            File::sync_all,
        )
    });
    let length = match started_rx.await {
        Ok(length) => length,
        Err(err) => {
            let result = worker.await;
            panic!("worker failed before observation: {err}; {result:?}");
        }
    };
    assert_eq!(
        length, 7,
        "the worker must already own a partially written file"
    );
    // Cancel only the borrowed waiter; the test retains and joins the worker.
    let mut waiter = Box::pin(async { (&mut worker).await });
    let mut cx = Context::from_waker(Waker::noop());
    assert!(waiter.as_mut().poll(&mut cx).is_pending());
    drop(waiter);
    release_tx.send(()).unwrap();
    let err = worker.await.expect("worker joined").unwrap_err();
    assert!(matches!(err, IdentityError::Io(_)));
    assert!(
        !path.exists(),
        "cleanup completes after cancellation of the waiter"
    );
}

#[test]
fn only_open_not_found_is_classified_as_absent() {
    let dir = FixtureDir::new();
    let absent = load_if_present_with(&dir.0.join("missing"), |_| panic!("read on missing file"))
        .expect("missing file is not a read error");
    assert!(absent.is_none());
}

#[test]
fn read_not_found_is_an_error_not_permission_to_create() {
    let dir = FixtureDir::new();
    let path = dir.0.join("existing");
    std::fs::write(&path, [2; 32]).unwrap();
    let err = load_if_present_with(&path, |_| {
        Err(IdentityError::Io(io::Error::from(io::ErrorKind::NotFound)))
    })
    .unwrap_err();
    assert!(matches!(err, IdentityError::Io(ref io) if io.kind() == io::ErrorKind::NotFound));
    assert_eq!(std::fs::read(path).unwrap(), [2; 32]);
}

// P04: public-future cancellation through the real public APIs, no mocks.
// Fixture assumption (pinned tokio 1.54.1 blocking-pool source, not a public
// API promise): `max_blocking_threads(1)` drains the pool queue strictly
// FIFO, so the sentinel below starts only after the cancelled future's
// queued job has fully run. Runtime drop is not used as the completion
// barrier: queued never-started blocking jobs may be dropped at shutdown.
// Panic safety: dropping `release_tx` disconnects the channel and releases
// the blocker even when an assert fails, so `Drop` for the runtime cannot
// hang.
// Observation bound for a blocked blocker/sentinel; failing fast beats hanging.
const CANCELLATION_OBSERVE_TIMEOUT: Duration = Duration::from_secs(30);

fn cancel_public_future<F: Future>(make_future: impl FnOnce() -> F) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()
        .expect("test runtime");

    let (started_tx, started_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let blocker = rt.spawn_blocking(move || {
        started_tx.send(()).expect("blocker start signal");
        // Channel disconnect is the intentional release signal; it must
        // release normally, including on a test-panic unwind.
        let _ = release_rx.recv();
    });

    started_rx
        .recv_timeout(CANCELLATION_OBSERVE_TIMEOUT)
        .expect("blocker started");
    {
        let _enter = rt.enter();
        let mut fut = Box::pin(make_future());
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(
            fut.as_mut().poll(&mut cx).is_pending(),
            "public future should be pending behind the blocker"
        );
        drop(fut); // cancellation
    }

    let (future_done_tx, future_done_rx) = mpsc::channel::<()>();
    let sentinel = rt.spawn_blocking(move || {
        let _ = future_done_tx.send(());
    });

    drop(release_tx);
    future_done_rx
        .recv_timeout(CANCELLATION_OBSERVE_TIMEOUT)
        .expect("sentinel ran after cancelled future's blocking job");

    rt.block_on(sentinel).expect("sentinel join");
    rt.block_on(blocker).expect("blocker join");
    drop(rt); // shutdown barrier: queue is empty, nothing is dropped
}

#[test]
fn cancelled_create_new_worker_still_completes_a_valid_private_file() {
    let dir = FixtureDir::new();
    let path = dir.0.join("cancelled-create");
    cancel_public_future(|| Identity::create_new(path.clone()));
    // The cancelled future itself yields no return value; its worker still
    // completed a full 32-byte private seed file.
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    use std::io::Read;
    let mut file = std::fs::File::open(&path).expect("cancelled create_new wrote private file");
    file.read_exact(seed.as_mut()).expect("full 32-byte seed");
    // Stability: derive the expected public key from the actual on-disk
    // seed and compare it with a fresh public load.
    let expected = Identity::from_seed(*seed);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("load runtime");
    let loaded = rt
        .block_on(Identity::load(path.clone()))
        .expect("stable load after cancelled create_new");
    drop(rt);
    assert_eq!(
        loaded.public_key_bytes(),
        expected.public_key_bytes(),
        "loaded identity must match the seed written by the cancelled create_new"
    );
}

#[test]
fn cancelled_load_never_modifies_the_existing_private_file() {
    let dir = FixtureDir::new();
    let path = dir.0.join("cancelled-load-existing");
    create_new_blocking(&path, &[6u8; 32]).expect("private fixture");
    cancel_public_future(|| Identity::load(path.clone()));
    assert_eq!(
        std::fs::read(&path).expect("private file readable"),
        [6u8; 32],
        "cancelled load left the existing private file unchanged"
    );
}

#[test]
fn cancelled_load_or_create_on_absent_path_never_creates_the_file() {
    let dir = FixtureDir::new();
    let path = dir.0.join("cancelled-load-or-create");
    cancel_public_future(|| Identity::load_or_create(path.clone()));
    assert!(
        !path.exists(), // creation cannot proceed after cancellation
        "cancelled load_or_create must not create the private file"
    );
}

// SEC-KEY-02 evidence: an actual unprivileged read attempt must fail with
// EACCES both before the first seed byte and after the full 32-byte write.
// Linux-only: relies on sudo -u nobody and Unix permission semantics.
#[cfg(target_os = "linux")]
mod unprivileged_reader {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::Command;

    const READER_SCRIPT: &str = "\
import os, sys
euid = os.geteuid()
owner = int(sys.argv[2])
if euid == 0 or euid == owner:
    print('BADUID')
    sys.exit(3)
try:
    with open(sys.argv[1], 'rb') as f:
        data = f.read(33)
except PermissionError as exc:
    if exc.errno == 13:
        print('DENIED')
        sys.exit(0)
    print('UNEXPECTED-ERRNO', exc.errno)
    sys.exit(4)
print('READ', len(data), data == b'readable')
";

    /// Runs the fixed Python script as `nobody` under a hard timeout.
    /// Any setup, script, or native failure (nonzero exit, stderr, timeout
    /// exit code 124) is a test failure, never a skip or a pass.
    fn run_as_nobody(path: &Path, owner_uid: u32, expect: &str) {
        let output = Command::new("sudo")
            .args([
                "-n",
                "-u",
                "nobody",
                "--",
                "/usr/bin/timeout",
                "15",
                "/usr/bin/python3",
                "-I",
                "-c",
                READER_SCRIPT,
            ])
            .arg(path)
            .arg(owner_uid.to_string())
            .output()
            .expect("sudo -n -u nobody must be available in the CI job");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "child failed: status={:?} stderr={stderr}",
            output.status.code()
        );
        assert!(stderr.is_empty(), "child wrote stderr: {stderr}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            expect,
            "unexpected reader protocol output"
        );
    }

    fn shared_fixture_dir() -> FixtureDir {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // Workspace ancestors may deny traversal to nobody. Create a fresh
        // directory under the system temporary root; never chmod ancestors.
        for _ in 0..64 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("shaar-foreign-reader-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return FixtureDir(path),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("foreign reader fixture directory: {err}"),
            }
        }
        panic!("foreign reader fixture namespace exhausted");
    }

    fn positive_control(dir: &FixtureDir) -> (PathBuf, u32) {
        let path = dir.0.join("positive-control");
        std::fs::write(&path, b"readable").expect("write positive control");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod positive control");
        let uid = std::fs::metadata(&path)
            .expect("stat positive control")
            .uid();
        (path, uid)
    }

    fn assert_positive(path: &Path, uid: u32) {
        run_as_nobody(path, uid, "READ 8 True\n");
    }

    #[test]
    #[ignore = "SEC-KEY-02: requires passwordless sudo -u nobody; run explicitly by the Ubuntu CI step"]
    fn identity_unprivileged_uid_cannot_read_seed_file() {
        let dir = shared_fixture_dir();
        // Only newly created fixture paths are chmodded, never ancestors.
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fixture dir");
        let (control, uid) = positive_control(&dir);
        assert_positive(&control, uid);

        let key_path = dir.0.join("key");
        let seed = zeroize::Zeroizing::new([7u8; 32]);
        create_new_with_io(
            &key_path,
            &seed,
            |file, bytes| {
                let meta = file.metadata()?;
                assert_eq!(meta.len(), 0, "file must be zero length before write");
                assert_eq!(
                    meta.permissions().mode() & 0o077,
                    0,
                    "no group/other permissions at open"
                );
                // Denied read BEFORE the first seed byte is written.
                run_as_nobody(&key_path, uid, "DENIED\n");
                file.write_all(bytes)?;
                file.flush()?;
                file.sync_all()?;
                assert_eq!(file.metadata()?.len(), 32);
                // Denied read AFTER the actual 32-byte write.
                run_as_nobody(&key_path, uid, "DENIED\n");
                Ok(())
            },
            File::sync_all,
        )
        .expect("key creation with reader probes must succeed");
        assert_eq!(
            std::fs::read(&key_path).expect("read back key"),
            seed.as_ref(),
            "seed content must be intact after probes"
        );
        // Positive control must still be readable in the exact same
        // directory, so a traversal failure cannot masquerade as proof.
        assert_positive(&control, uid);
    }
}
