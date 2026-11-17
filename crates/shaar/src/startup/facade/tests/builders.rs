//! Builders validate with the rules of a configuration file; `from_config_file`
//! loads identity, allowlist and target from disk.

use std::net::SocketAddr;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{FixtureDir, identity};
use crate::config::{ConfigError, Fallback, PublishAddress, ValidationKind};
use crate::identity::Identity;
use crate::startup::facade::{
    AllowList, Client, Network, NetworkSpec, PeerKey, SdkError, Server, Service,
};

fn key(seed: u8) -> PeerKey {
    PeerKey::of(&identity(seed))
}

fn target() -> SocketAddr {
    "127.0.0.1:9000".parse().unwrap()
}

fn spec() -> NetworkSpec {
    NetworkSpec {
        bootstrap: vec![
            "192.0.2.10:6881".to_owned(),
            "dht.example.org:6881".to_owned(),
        ],
        ygg_peers: vec!["tcp://192.0.2.30:1514".to_owned()],
        relay: None,
    }
}

fn config_error(result: Result<impl std::fmt::Debug, SdkError>) -> (&'static str, ValidationKind) {
    match result {
        Err(SdkError::Config(ConfigError::Validation { field, kind })) => (field, kind),
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn a_server_needs_a_service() {
    let error = Server::builder(identity(1)).build().unwrap_err();
    assert!(matches!(error, SdkError::Setup(_)), "{error}");
    assert_eq!(error.to_string(), "a Server needs forward_to or handler");
}

#[test]
fn a_direct_server_takes_a_target_a_bind_and_a_handler_without_a_target() {
    let server = Server::builder(identity(1))
        .forward_to(target())
        .bind("127.0.0.1:7000".parse().unwrap())
        .fallback(Fallback::Signal)
        .build()
        .unwrap();
    assert_eq!(server.address(), key(1));
    assert_eq!(server.config().target(), target());
    assert_eq!(server.config().bind().to_string(), "127.0.0.1:7000");
    assert_eq!(server.config().fallback(), Fallback::Signal);
    assert!(server.config().network().is_none());
    assert_eq!(
        format!("{:?}", Service::Target(target())),
        "Target(127.0.0.1:9000)"
    );
    // A handler needs no target; the placeholder is never dialed.
    let handled = Server::builder(identity(1))
        .handler(|_peer: PeerKey, _stream: crate::network::ServiceStream| async {})
        .build()
        .unwrap();
    assert!(handled.config().network().is_none());
}

#[test]
fn server_settings_are_refused_with_the_field_and_kind_of_a_file() {
    let refused = |builder: crate::startup::facade::ServerBuilder| builder.build();
    assert_eq!(
        config_error(refused(
            Server::builder(identity(1)).forward_to("192.0.2.1:80".parse().unwrap())
        )),
        ("target", ValidationKind::NotLoopback)
    );
    assert_eq!(
        config_error(refused(
            Server::builder(identity(1)).forward_to("127.0.0.1:0".parse().unwrap())
        )),
        ("target", ValidationKind::InvalidPort)
    );
    assert_eq!(
        config_error(refused(
            Server::builder(identity(1))
                .forward_to(target())
                .publish_address(PublishAddress::Encrypted)
        )),
        ("address_key_file", ValidationKind::MissingRequired)
    );
    assert_eq!(
        config_error(refused(
            Server::builder(identity(1))
                .forward_to(target())
                .address_key_file("address.key")
        )),
        ("address_key_file", ValidationKind::NotApplicable)
    );
    // The composed shape binds its own sockets.
    assert_eq!(
        config_error(refused(
            Server::builder(identity(1))
                .forward_to(target())
                .network(Network::Public)
                .bind("127.0.0.1:7000".parse().unwrap())
        )),
        ("bind", ValidationKind::NotApplicable)
    );
}

#[test]
fn the_composed_shapes_carry_a_network_object() {
    let public = Server::builder(identity(1))
        .forward_to(target())
        .network(Network::Public)
        .publish_address(PublishAddress::Plain)
        .build()
        .unwrap();
    let network = public.config().network().expect("public network");
    assert_eq!(network.mainline().unwrap().hosts().len(), 2);
    assert_eq!(network.ygg().unwrap().peers().len(), 2);
    assert!(network.signaling().unwrap().relay().is_none());
    assert_eq!(public.config().publish_address(), PublishAddress::Plain);

    let custom = Server::builder(identity(1))
        .forward_to(target())
        .network(Network::Custom(spec()))
        .build()
        .unwrap();
    let mainline = custom.config().network().unwrap().mainline().unwrap();
    assert_eq!(mainline.bootstrap().len(), 1);
    assert_eq!(mainline.hosts()[0].name(), "dht.example.org");
}

#[test]
fn a_custom_network_is_validated_and_a_relay_needs_a_valid_peer_id() {
    let mut empty = spec();
    empty.bootstrap.clear();
    assert_eq!(
        config_error(
            Server::builder(identity(1))
                .forward_to(target())
                .network(Network::Custom(empty))
                .build()
        ),
        ("network.mainline.bootstrap", ValidationKind::TooFew)
    );
    let mut relayed = spec();
    relayed.relay = Some((
        "not-a-peer-id".to_owned(),
        "192.0.2.20:4001".parse().unwrap(),
    ));
    assert_eq!(
        config_error(
            Server::builder(identity(1))
                .forward_to(target())
                .network(Network::Custom(relayed))
                .build()
        ),
        ("network.signaling.relay", ValidationKind::InvalidKey)
    );
    let mut multiline = spec();
    multiline.ygg_peers = vec!["tcp://192.0.2.30:1514\nfallback: x".to_owned()];
    let error = Server::builder(identity(1))
        .forward_to(target())
        .network(Network::Custom(multiline))
        .build()
        .unwrap_err();
    assert!(matches!(error, SdkError::Setup(_)), "{error}");
}

#[test]
fn a_client_builder_checks_the_shape_and_the_listen_address() {
    let server = key(1);
    let direct = Client::builder(identity(2), server).build().unwrap_err();
    assert!(matches!(direct, SdkError::Setup(_)), "{direct}");
    let client = Client::builder(identity(2), server)
        .server_address("198.51.100.8:49152".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(client.server(), server);
    assert_eq!(client.key(), key(2));
    assert_eq!(client.config().listen().to_string(), "127.0.0.1:0");
    assert_eq!(
        config_error(
            Client::builder(identity(2), server)
                .server_address("198.51.100.8:49152".parse().unwrap())
                .listen("192.0.2.1:2222".parse().unwrap())
                .build()
        ),
        ("listen", ValidationKind::NotLoopback)
    );
    // The composed shape needs no address.
    let composed = Client::builder(identity(2), server)
        .network(Network::Public)
        .fallback(Fallback::Signal)
        .build()
        .unwrap();
    assert!(composed.config().server_address().is_none());
    assert_eq!(composed.config().fallback(), Fallback::Signal);
    assert!(composed.config().network().is_some());
}

async fn write_server_files(dir: &Path, target: SocketAddr, allowed: PeerKey) -> Identity {
    let identity = Identity::create_new(dir.join("server.key")).await.unwrap();
    std::fs::write(dir.join("allowed.txt"), format!("# clients\n{allowed}\n")).unwrap();
    let text = format!(
        "target:: {target}\nbind:: 127.0.0.1:0\nkey_file:: {}\nallowlist_path:: {}\n",
        dir.join("server.key").display(),
        dir.join("allowed.txt").display()
    );
    std::fs::write(dir.join("server.ktav"), text).unwrap();
    identity
}

#[tokio::test]
async fn a_server_and_a_client_load_from_configuration_files_and_exchange_bytes() {
    let dir = FixtureDir::new();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = echo.accept().await {
            let (mut read, mut write) = stream.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    let client_identity = Identity::create_new(dir.0.join("client.key"))
        .await
        .unwrap();
    let server_identity =
        write_server_files(&dir.0, echo_addr, PeerKey::of(&client_identity)).await;

    let server = Server::from_config_file(dir.0.join("server.ktav"))
        .await
        .unwrap();
    assert_eq!(server.address(), PeerKey::of(&server_identity));
    let running = server.start().await.unwrap();

    let text = format!(
        "server:: {}\nserver_address:: {}\nlisten:: 127.0.0.1:0\nkey_file:: {}\n",
        running.address(),
        running.local_addr().unwrap(),
        dir.0.join("client.key").display()
    );
    std::fs::write(dir.0.join("client.ktav"), text).unwrap();
    let client = Client::from_config_file(dir.0.join("client.ktav"))
        .await
        .unwrap();
    assert_eq!(client.key(), PeerKey::of(&client_identity));
    let client = client.start().await.unwrap();

    let mut stream = client.connect().await.unwrap();
    stream.write_all(b"from files").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"from files");
    client.shutdown().await.unwrap();
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn loading_reports_the_failing_part_without_secrets() {
    let dir = FixtureDir::new();
    let missing = Server::from_config_file(dir.0.join("none.ktav"))
        .await
        .unwrap_err();
    assert!(matches!(missing, SdkError::Config(_)), "{missing}");
    // A readable config whose allowlist file is absent names the allowlist.
    let identity = Identity::create_new(dir.0.join("server.key"))
        .await
        .unwrap();
    let text = format!(
        "target:: 127.0.0.1:9000\nkey_file:: {}\nallowlist_path:: {}\n",
        dir.0.join("server.key").display(),
        dir.0.join("absent.txt").display()
    );
    std::fs::write(dir.0.join("server.ktav"), text).unwrap();
    let error = Server::from_config_file(dir.0.join("server.ktav"))
        .await
        .unwrap_err();
    assert!(matches!(error, SdkError::AllowList(_)), "{error}");
    assert_eq!(error.to_string(), "could not read allowlist");
    let shown = format!("{error:?} {error}");
    assert!(!shown.contains(&PeerKey::of(&identity).to_string()));
    // An allowlist of the empty list is valid and admits nobody.
    assert!(AllowList::empty().is_empty());
}
