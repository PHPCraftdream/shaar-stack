#![forbid(unsafe_code)]
use super::*;
use std::{
    cell::Cell,
    future::Future,
    io::{self, Write},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Waker},
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
