//! Network choice of generated files: `Public` files parse to the composed
//! shape and pass the composed preflight; `Private` stays direct-only; an
//! existing file is never rewritten by a different choice.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use iroh_base::PublicKey;

use super::*;
use crate::config::{ClientConfig, ClientOverrides, ServerConfig, ServerOverrides};
use crate::startup::preflight::{preflight_client, preflight_server};

// RFC 8032 section 7.1 test-vector 1 public key.
const SERVER_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target/identity-provision-network-fixtures");
        std::fs::create_dir_all(&base).expect("fixture parent");
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("fresh fixture directory");
        Self(path)
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn server_overrides() -> ServerOverrides {
    ServerOverrides {
        target: Some("127.0.0.1:8080".to_owned()),
        ..ServerOverrides::default()
    }
}

#[tokio::test]
async fn a_public_server_file_is_composed_and_passes_preflight() {
    let dir = FixtureDir::new();
    let provisioned = provision_with(Role::Server, &dir.0, None, None, NetworkChoice::Public)
        .await
        .unwrap();
    let text = std::fs::read_to_string(&provisioned.report.paths.config).unwrap();
    assert!(text.ends_with(public_network_text()));
    let config = ServerConfig::from_text(&text, &server_overrides()).unwrap();
    let network = config
        .network()
        .expect("public file carries a network object");
    let mainline = network.mainline().unwrap();
    assert!(mainline.bootstrap().is_empty());
    let hosts: Vec<(&str, u16)> = mainline
        .hosts()
        .iter()
        .map(|h| (h.name(), h.port()))
        .collect();
    assert_eq!(
        hosts,
        [
            ("dht.libtorrent.org", 25401),
            ("router.bittorrent.com", 6881)
        ]
    );
    assert_eq!(
        network.ygg().unwrap().peers(),
        [
            "tcp://ygg-pa.incognet.io:8883",
            "tcp://mo.us.ygg.triplebit.org:9000"
        ]
    );
    assert!(
        network.signaling().unwrap().relay().is_none(),
        "no relay default"
    );
    preflight_server(&config, &provisioned.identity, &[]).unwrap();
}

#[tokio::test]
async fn a_public_client_file_finds_the_server_by_key_alone() {
    let dir = FixtureDir::new();
    let provisioned = provision_with(
        Role::Client,
        &dir.0,
        Some(SERVER_HEX),
        None,
        NetworkChoice::Public,
    )
    .await
    .unwrap();
    let text = std::fs::read_to_string(&provisioned.report.paths.config).unwrap();
    let config = ClientConfig::from_text(&text, &ClientOverrides::default()).unwrap();
    assert!(config.server_address().is_none(), "key only");
    assert!(config.network().is_some());
    let server = PublicKey::from_bytes(config.server_key_bytes()).unwrap();
    preflight_client(&config, &provisioned.identity, &[server]).unwrap();
}

#[tokio::test]
async fn private_and_legacy_provisioning_stay_direct_only() {
    for choice in [None, Some(NetworkChoice::Private)] {
        let dir = FixtureDir::new();
        let provisioned = match choice {
            None => provision(Role::Server, &dir.0, None, None).await,
            Some(choice) => provision_with(Role::Server, &dir.0, None, None, choice).await,
        }
        .unwrap();
        let text = std::fs::read_to_string(&provisioned.report.paths.config).unwrap();
        assert!(!text.contains("network:"), "{text}");
        let config = ServerConfig::from_text(&text, &server_overrides()).unwrap();
        assert!(config.network().is_none());
    }
    assert_eq!(NetworkChoice::default(), NetworkChoice::Private);
}

#[tokio::test]
async fn an_existing_file_is_kept_whatever_the_choice() {
    let dir = FixtureDir::new();
    let first = provision(
        Role::Client,
        &dir.0,
        Some(SERVER_HEX),
        Some("192.0.2.1:7000"),
    )
    .await
    .unwrap();
    let before = std::fs::read(&first.report.paths.config).unwrap();
    let second = provision_with(Role::Client, &dir.0, None, None, NetworkChoice::Public)
        .await
        .unwrap();
    assert_eq!(second.report.config, FileState::Kept);
    assert_eq!(std::fs::read(&second.report.paths.config).unwrap(), before);
    assert_eq!(
        second.identity.public_key_bytes(),
        first.identity.public_key_bytes()
    );
}
