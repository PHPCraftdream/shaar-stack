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

#[cfg(unix)]
#[tokio::test]
async fn sigterm_completes_the_shutdown_signal() {
    use std::{future::Future, future::poll_fn, task::Poll, time::Duration};
    let mut signal = Box::pin(super::super::shutdown_signal());
    // The first poll registers the handlers; SIGTERM would kill the process without one.
    assert!(poll_fn(|cx| Poll::Ready(signal.as_mut().poll(cx).is_pending())).await);
    let status = std::process::Command::new("/bin/kill")
        .arg("-TERM")
        .arg(std::process::id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    tokio::time::timeout(Duration::from_secs(10), signal)
        .await
        .expect("SIGTERM must complete the shutdown signal")
        .expect("signal handler failed");
}
