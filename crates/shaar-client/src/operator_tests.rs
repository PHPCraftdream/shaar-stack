#![forbid(unsafe_code)]

use shaar::identity::Identity;

#[test]
fn composed_banner_names_own_key_and_pinned_server_key_separately() {
    let own = Identity::from_seed([7; 32]);
    let server = "ab".repeat(32);
    let own_hex: String = own
        .public_key_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let banner = super::composed_banner(&own, &server, "signal", "none");
    assert_eq!(
        banner,
        format!(
            "composed startup: public_key={own_hex} server={server} fallback=signal server_address=none"
        )
    );
    assert!(!banner.contains(&format!("public_key={server}")));
}

#[cfg(unix)]
#[tokio::test]
async fn sigterm_completes_the_shutdown_signal() {
    use std::{future::Future, future::poll_fn, task::Poll, time::Duration};
    let mut signal = Box::pin(super::shutdown_signal());
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
