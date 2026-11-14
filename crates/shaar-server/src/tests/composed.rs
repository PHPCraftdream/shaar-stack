use iroh_base::PublicKey;
use shaar::identity::Identity;

use crate::test_support::check_composed_limit;

fn key(seed: u8) -> PublicKey {
    PublicKey::from_bytes(&Identity::from_seed([seed; 32]).public_key_bytes()).unwrap()
}

#[test]
fn composed_limit_is_the_signaling_peer_bound_of_sixteen() {
    assert_eq!(shaar::startup::MAX_STARTUP_APP_PEERS, 16);
    let max = shaar::startup::MAX_STARTUP_APP_PEERS;
    let at_limit: Vec<_> = (0..16).map(key).collect();
    assert_eq!(check_composed_limit(&at_limit, max), Ok(()));
    let over: Vec<_> = (0..17).map(key).collect();
    let error = check_composed_limit(&over, max).unwrap_err();
    assert!(error.contains("`allowlist_path`"), "{error}");
    assert!(error.contains("17") && error.contains("16"), "{error}");
}

#[test]
fn composed_limit_counts_distinct_keys_only() {
    let mut keys: Vec<_> = (0..16).map(key).collect();
    keys.extend((0..16).map(key));
    assert_eq!(check_composed_limit(&keys, 16), Ok(()));
}

/// Child fixture: arms the real shutdown signal and waits for SIGTERM.
#[cfg(unix)]
#[tokio::test]
#[ignore = "child fixture launched by the SIGTERM regression"]
async fn sigterm_child_fixture() {
    use std::{future::Future, future::poll_fn, task::Poll, time::Duration};
    let mut signal = Box::pin(super::super::shutdown_signal());
    // The first poll registers the handlers; SIGTERM would kill the process without one.
    assert!(poll_fn(|cx| Poll::Ready(signal.as_mut().poll(cx).is_pending())).await);
    println!("SIGTERM_FIXTURE_READY");
    tokio::time::timeout(Duration::from_secs(20), signal)
        .await
        .expect("SIGTERM must complete the shutdown signal")
        .expect("signal handler failed");
}

#[cfg(unix)]
#[test]
fn sigterm_stops_a_process_gracefully() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "tests::composed::sigterm_child_fixture",
            "--nocapture",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = lines
        .by_ref()
        .any(|line| line.is_ok_and(|line| line.contains("SIGTERM_FIXTURE_READY")));
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture child never armed its signal handler");
    }
    let sent = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(sent.success());
    let status = child.wait().unwrap();
    drop(lines);
    assert!(
        status.success(),
        "SIGTERM must stop the process gracefully: {status}"
    );
}
