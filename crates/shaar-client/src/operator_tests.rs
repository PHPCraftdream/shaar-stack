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

/// Child fixture: arms the real shutdown signal and waits for SIGTERM.
#[cfg(unix)]
#[tokio::test]
#[ignore = "child fixture launched by the SIGTERM regression"]
async fn sigterm_child_fixture() {
    use std::{future::Future, future::poll_fn, task::Poll, time::Duration};
    let mut signal = Box::pin(super::shutdown_signal());
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
            "operator_tests::sigterm_child_fixture",
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
