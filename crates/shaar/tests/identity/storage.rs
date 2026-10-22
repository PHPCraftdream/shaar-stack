#![forbid(unsafe_code)]
//! P04 identity integration tests: key-file storage semantics
//! (roundtrip, size boundaries, no-overwrite, races, cancellation).

use crate::common::{self, TempDir};

use shaar::identity::{Identity, IdentityError};

/// 5. Roundtrip: create_new then load → same public key; exactly 32
/// bytes on disk; loading does not rewrite the file.
#[tokio::test]
async fn roundtrip_create_then_load_is_stable() {
    let td = TempDir::new("roundtrip");
    let path = td.key_path();

    let id = Identity::create_new(&path).await.expect("create_new");
    let pub1 = id.public_key_bytes();

    let before = std::fs::read(&path).expect("read key file");
    assert_eq!(before.len(), 32);

    let meta1 = std::fs::metadata(&path)
        .expect("stat")
        .modified()
        .expect("mtime");
    let id2 = Identity::load(&path).await.expect("load");
    assert_eq!(id2.public_key_bytes(), pub1);

    let meta2 = std::fs::metadata(&path)
        .expect("stat")
        .modified()
        .expect("mtime");
    assert_eq!(
        meta1, meta2,
        "load must not rewrite the key file (mtime changed)"
    );
    assert_eq!(std::fs::read(&path).expect("read again"), before);
}

/// 10. Any 32-byte payload is an Ed25519 seed, not a serialized curve point.
/// An all-zero seed is accepted when the file passes the privacy checks.
/// The identity must be stable across reloads.
#[tokio::test]
async fn any_32_byte_file_loads_and_is_stable() {
    let (_td, path) = common::write_private_fixture("zeros", &[0u8; 32]).await;

    let id = Identity::load(&path).await.expect("load all-zero seed");
    let pub1 = id.public_key_bytes();
    let id2 = Identity::load(&path).await.expect("reload");
    assert_eq!(id2.public_key_bytes(), pub1);

    // And load_or_create on an existing (all-zero) file loads, not recreates.
    let id3 = Identity::load_or_create(&path)
        .await
        .expect("load_or_create");
    assert_eq!(id3.public_key_bytes(), pub1);
}

/// 6. Size boundaries: 31, 33, and 1 MiB files all fail to load and are
/// left byte-for-byte unchanged.
#[tokio::test]
async fn size_boundaries_rejected_and_unchanged() {
    for (tag, content) in [
        ("short", vec![0xabu8; 31]),
        ("long", vec![0xcdu8; 33]),
        ("huge", vec![0u8; 1024 * 1024]),
    ] {
        // Private fixture so the permission check passes and the load
        // actually reaches the intended InvalidFormat content path.
        let (_td, path) = common::write_private_fixture(tag, &content).await;

        let err = Identity::load(&path)
            .await
            .expect_err("boundary file must not load");
        assert!(
            matches!(err, IdentityError::InvalidFormat),
            "expected InvalidFormat for {tag}, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("reread"),
            content,
            "failed load must not modify the file"
        );
    }
}

/// 8 (part 1). create_new on an existing path errors AlreadyExists and
/// leaves the existing content untouched.
#[tokio::test]
async fn create_new_never_overwrites() {
    let td = TempDir::new("nooverwrite");
    let path = td.key_path();

    let id1 = Identity::create_new(&path).await.expect("first create");
    let original = std::fs::read(&path).expect("read");

    let err = Identity::create_new(&path)
        .await
        .expect_err("second create must fail");
    assert!(matches!(err, IdentityError::AlreadyExists), "got {err:?}");
    assert_eq!(
        std::fs::read(&path).expect("reread"),
        original,
        "existing key file must be unchanged"
    );
    let id2 = Identity::load(&path).await.expect("load original");
    assert_eq!(id2.public_key_bytes(), id1.public_key_bytes());
}

/// 8 (part 2). N concurrent create_new calls on a fresh path: exactly
/// one Ok; the file afterwards is a valid key.
#[tokio::test]
async fn concurrent_create_new_exactly_one_winner() {
    let td = TempDir::new("race");
    let path = td.key_path();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = path.clone();
        handles.push(tokio::spawn(async move { Identity::create_new(p).await }));
    }
    let mut oks = 0;
    let mut winner_pub = None;
    for h in handles {
        match h.await.expect("join") {
            Ok(id) => {
                oks += 1;
                winner_pub = Some(id.public_key_bytes());
            }
            Err(IdentityError::AlreadyExists) => {}
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert_eq!(oks, 1, "exactly one create_new must win");
    let loaded = Identity::load(&path).await.expect("load winner");
    assert_eq!(Some(loaded.public_key_bytes()), winner_pub);
}

/// 8 (part 3). Concurrent load_or_create on a fresh path: at most one
/// public key is ever produced (all Ok values equal; failures allowed).
#[tokio::test]
async fn load_or_create_race_produces_single_identity() {
    let td = TempDir::new("race-lorc");
    let path = td.key_path();

    let mut handles = Vec::new();
    for _ in 0..4 {
        let p = path.clone();
        handles.push(tokio::spawn(
            async move { Identity::load_or_create(p).await },
        ));
    }
    let mut pubs = Vec::new();
    for h in handles {
        if let Ok(Ok(id)) = h.await {
            pubs.push(id.public_key_bytes());
        }
    }
    assert!(!pubs.is_empty(), "at least one caller must succeed");
    for p in &pubs {
        assert_eq!(p, &pubs[0], "no second identity may appear under a race");
    }
}

/// 9. Write-failure safety: a missing parent directory and a
/// directory-as-path both error and create nothing.
///
/// This covers open-time failures. Private store unit tests separately inject
/// partial-write and sync failures after real exclusive creation.
#[tokio::test]
async fn create_new_error_paths_create_nothing() {
    let td = TempDir::new("errpaths");

    let missing = td.path().join("no-such-subdir").join("identity.key");
    let err = Identity::create_new(&missing)
        .await
        .expect_err("missing parent");
    assert!(matches!(err, IdentityError::Io(_)), "got {err:?}");
    assert!(!td.path().join("no-such-subdir").exists());

    let as_dir = td.path().join("subdir");
    std::fs::create_dir(&as_dir).expect("make dir");
    let err = Identity::create_new(&as_dir)
        .await
        .expect_err("directory as path");
    // Unix exclusive creation reports EEXIST for a directory entry; the
    // Windows native file-only create reports an I/O failure instead.
    #[cfg(unix)]
    assert!(matches!(err, IdentityError::AlreadyExists), "got {err:?}");
    #[cfg(windows)]
    assert!(matches!(err, IdentityError::Io(_)), "got {err:?}");
    assert!(as_dir.is_dir(), "directory must remain");
    assert!(
        std::fs::read_dir(&as_dir).unwrap().next().is_none(),
        "no child may be created"
    );
}

/// 11. A storage task that runs to COMPLETION over an existing key file
/// leaves it untouched: load_or_create on an existing file deterministically
/// loads (the JoinHandle is awaited to completion, proving the storage op
/// ran), and afterwards the file bytes and identity are unchanged.
///
/// Coverage note: MID-OPERATION abort of the inner blocking task is NOT
/// covered. Aborting the async future cannot stop an already-running
/// blocking task (documented in store.rs), and there is no production
/// hook to observe the start of that task — observing a mid-op abort
/// would require a test hook or flaky timing. That cancellation window
/// is disclosed as a gap instead of faked here.
#[tokio::test]
async fn completed_task_leaves_existing_file_untouched() {
    let td = TempDir::new("cancel");
    let path = td.key_path();

    let id = Identity::create_new(&path).await.expect("create");
    let original = std::fs::read(&path).expect("read");

    // Awaited to completion: the storage operation deterministically ran.
    let handle = tokio::spawn({
        let p = path.clone();
        async move { Identity::load_or_create(p).await }
    });
    let reloaded = handle.await.expect("join").expect("load_or_create");
    assert_eq!(reloaded.public_key_bytes(), id.public_key_bytes());

    // The existing file must be intact and still load to the same key.
    assert_eq!(std::fs::read(&path).expect("reread"), original);
    let again = Identity::load(&path).await.expect("reload");
    assert_eq!(again.public_key_bytes(), id.public_key_bytes());
}

/// 4 (part 2 of the redaction checks lives in vectors.rs). Errors
/// produced here are additionally formatted and checked for the absence
/// of the seed hex of the file that triggered them.
#[tokio::test]
async fn error_values_do_not_leak_seed_bytes() {
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    use std::fmt::Write as _;
    let mut fixture_hex = String::with_capacity(64);
    for byte in common::TEST1_SEED {
        write!(&mut fixture_hex, "{byte:02x}").unwrap();
    }
    assert_eq!(
        fixture_hex, seed_hex,
        "the sentinel must match the actual fixture bytes"
    );

    // A 33-byte fixture built from the ACTUAL TEST1 seed bytes
    // (seed || 0xFF) via the private fixture helper, so the load
    // deterministically fails at the trailing-byte check with a file
    // whose leading bytes are the seed; any leak of that material into
    // the error becomes detectable.
    let mut leaky = Vec::new();
    leaky.extend_from_slice(&common::TEST1_SEED);
    leaky.push(0xFF);
    let path_sentinel = "zz_private_path_zz";
    let (_td, path) = common::write_private_fixture(path_sentinel, &leaky).await;
    assert!(path.to_string_lossy().contains(path_sentinel));

    let err = Identity::load(&path).await.expect_err("33-byte file");
    let dbg = format!("{err:?}");
    let disp = format!("{err}");
    // Positive controls: both formats are non-empty.
    assert!(!dbg.is_empty());
    assert!(!disp.is_empty());
    assert!(
        !dbg.to_ascii_lowercase().contains(seed_hex),
        "Debug of error contains seed hex: {dbg}"
    );
    assert!(
        !disp.to_ascii_lowercase().contains(seed_hex),
        "Display of error contains seed hex: {disp}"
    );
    let decimal_seed = format!("{:?}", common::TEST1_SEED);
    let decimal_prefix = decimal_seed.trim_end_matches(']');
    for rendered in [&dbg, &disp] {
        assert!(
            !rendered.contains(decimal_prefix),
            "error exposed seed bytes"
        );
        assert!(
            !rendered.contains(path_sentinel),
            "error exposed its input path"
        );
    }
}
