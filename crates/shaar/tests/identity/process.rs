#![forbid(unsafe_code)]

use std::{
    ffi::OsStr,
    io::{Read, Write},
    process::{Child, Command, Stdio},
};

use crate::common::TempDir;

const CHILD_ENV: &str = "SHAAR_TEST_PROCESS_RACE_CHILD";
const KEY_PATH_ENV: &str = "SHAAR_TEST_PROCESS_RACE_KEY_PATH";
const CHILD_TEST: &str = "process::create_new_child";

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn two_process_create_new_race_same_fresh_key() {
    let td = TempDir::new("proc-race");
    let key_path = td.key_path();
    let executable = std::env::current_exe().expect("locate test harness executable");

    let mut first = OwnedChild(
        Command::new(&executable)
            .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env(KEY_PATH_ENV, &key_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn first child"),
    );
    let mut second = OwnedChild(
        Command::new(&executable)
            .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env(KEY_PATH_ENV, &key_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn second child"),
    );

    for child in [&mut first, &mut second] {
        child
            .0
            .stdin
            .take()
            .expect("child stdin piped")
            .write_all(b"r")
            .expect("release child");
    }

    let first_status = first.0.wait().expect("wait for first child");
    let second_status = second.0.wait().expect("wait for second child");
    let codes = (first_status.code(), second_status.code());
    assert!(
        matches!(codes, (Some(0), Some(42)) | (Some(42), Some(0))),
        "expected child exit codes 0 and 42, got {codes:?}"
    );

    assert_eq!(
        std::fs::metadata(&key_path).expect("key metadata").len(),
        32
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build runtime");
    let first = runtime
        .block_on(shaar::identity::Identity::load(&key_path))
        .expect("load identity");
    let second = runtime
        .block_on(shaar::identity::Identity::load(&key_path))
        .expect("load identity again");
    assert_eq!(first.public_key_bytes(), second.public_key_bytes());
}

#[test]
#[ignore = "parent-only subprocess helper"]
fn create_new_child() {
    assert_eq!(
        std::env::var_os(CHILD_ENV).as_deref(),
        Some(OsStr::new("1"))
    );
    let key_path = std::env::var_os(KEY_PATH_ENV).expect("child key path is required");

    let mut release = [0u8; 1];
    std::io::stdin()
        .read_exact(&mut release)
        .expect("read parent release byte");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build runtime");
    let result = runtime.block_on(shaar::identity::Identity::create_new(key_path));
    let exit_code = match result {
        Ok(_) => 0,
        Err(shaar::identity::IdentityError::AlreadyExists) => 42,
        Err(_) => 43,
    };
    drop(runtime);
    std::process::exit(exit_code);
}
