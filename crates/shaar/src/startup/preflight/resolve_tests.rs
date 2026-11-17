//! Bootstrap resolution: injected lookups cover success, partial and total
//! failure, the deadline and IPv4 filtering; one case uses the real system
//! resolver for `localhost`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use crate::config::{NetworkSettings, ServerConfig, ServerOverrides};
use crate::startup::StartupError;

use super::{resolve_network, resolve_with};

fn network(entries: &[&str]) -> NetworkSettings {
    let mut lines = String::new();
    for entry in entries {
        lines.push_str(&format!("            {entry}\n"));
    }
    let text = format!(
        "target: 127.0.0.1:9000\nnetwork: {{\n    mainline: {{\n        bootstrap: [\n{lines}        ]\n    }}\n    signaling: {{\n        bind: 0.0.0.0:0\n    }}\n    ygg: {{\n        peers: [\n            tcp://127.0.0.1:9001\n        ]\n    }}\n}}\n"
    );
    ServerConfig::from_text(&text, &ServerOverrides::default())
        .unwrap()
        .network()
        .unwrap()
        .clone()
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
}

/// Fixed answers by host name; unknown names fail like NXDOMAIN.
async fn table(name: String, port: u16) -> io::Result<Vec<SocketAddr>> {
    match name.as_str() {
        "one.example" => Ok(vec![
            SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], port)),
            SocketAddr::from(([0, 0, 0, 0], port)),
            SocketAddr::from(([198, 51, 100, 7], port)),
            SocketAddr::from(([198, 51, 100, 8], port)),
        ]),
        "two.example" => Ok(vec![SocketAddr::from(([203, 0, 113, 9], port))]),
        "dup.example" => Ok(vec![SocketAddr::from(([192, 0, 2, 10], port))]),
        "v6only.example" => Ok(vec![SocketAddr::from((
            [0x2001, 0xdb8, 0, 0, 0, 0, 0, 2],
            port,
        ))]),
        _ => Err(io::Error::other("no such host")),
    }
}

#[tokio::test]
async fn numeric_only_settings_are_left_unchanged() {
    let settings = network(&["192.0.2.10:6881"]);
    let calls = std::cell::Cell::new(0);
    let resolved = resolve_with(&settings, Duration::from_secs(5), |_, _| {
        calls.set(calls.get() + 1);
        async { Err(io::Error::other("unexpected lookup")) }
    })
    .await;
    assert_eq!(resolved, Ok(None));
    assert_eq!(calls.get(), 0, "a numeric entry must not be looked up");
    assert_eq!(resolve_network(None).await, Ok(None));
}

#[tokio::test]
async fn each_host_contributes_its_first_usable_ipv4_after_the_numeric_entries() {
    let settings = network(&["one.example:6881", "192.0.2.10:6881", "two.example:25401"]);
    let resolved = resolve_with(&settings, Duration::from_secs(5), table)
        .await
        .unwrap()
        .expect("hosts were resolved");
    let mainline = resolved.mainline().unwrap();
    assert_eq!(
        mainline.bootstrap(),
        [
            v4(192, 0, 2, 10, 6881),
            v4(198, 51, 100, 7, 6881),
            v4(203, 0, 113, 9, 25401),
        ]
    );
    assert!(mainline.hosts().is_empty());
    assert_eq!(resolved.signaling(), settings.signaling());
    assert_eq!(resolved.ygg(), settings.ygg());
}

#[tokio::test]
async fn failed_hosts_are_skipped_and_duplicates_dropped() {
    let settings = network(&["192.0.2.10:6881", "dup.example:6881", "gone.example:6881"]);
    let resolved = resolve_with(&settings, Duration::from_secs(5), table)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resolved.mainline().unwrap().bootstrap(),
        [v4(192, 0, 2, 10, 6881)]
    );
}

#[tokio::test]
async fn no_usable_entry_fails_with_a_redacted_error() {
    let settings = network(&["gone.example:6881", "v6only.example:6881"]);
    let error = resolve_with(&settings, Duration::from_secs(5), table)
        .await
        .unwrap_err();
    assert_eq!(error, StartupError::BootstrapUnresolved);
    for shown in [error.to_string(), format!("{error:?}")] {
        assert!(shown.contains("network.mainline.bootstrap"), "{shown}");
        assert!(!shown.contains("gone.example"), "{shown}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_lookup_that_never_answers_ends_at_the_deadline() {
    let settings = network(&["slow.example:6881", "two.example:6881"]);
    let started = tokio::time::Instant::now();
    let resolved = resolve_with(&settings, Duration::from_secs(5), |name, port| async move {
        if name == "slow.example" {
            std::future::pending::<()>().await;
        }
        table(name, port).await
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(
        resolved.mainline().unwrap().bootstrap(),
        [v4(203, 0, 113, 9, 6881)]
    );
}

#[tokio::test]
async fn the_system_resolver_maps_localhost_to_loopback() {
    let settings = network(&["localhost:6881"]);
    let resolved = resolve_network(Some(&settings)).await.unwrap().unwrap();
    assert_eq!(
        resolved.mainline().unwrap().bootstrap(),
        [v4(127, 0, 0, 1, 6881)]
    );
}
