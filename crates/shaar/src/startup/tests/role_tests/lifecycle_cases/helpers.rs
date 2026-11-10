//! One-shot postconditions for role close and identity ownership.

use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

use shaar_ygg::{YggConfig, YggError, YggTransport};

use crate::config::{ClientConfig, ServerConfig};

const RELEASE_BUDGET: Duration = Duration::from_secs(20);

pub(super) async fn assert_key_released_once(seed: u8, who: &str) {
    let config = YggConfig {
        seed: [seed; 32],
        listen: Vec::new(),
        peers: Vec::new(),
        allowed_public_keys: Vec::new(),
        group_password: None,
    };
    let transport = match YggTransport::start(config).await {
        Ok(transport) => transport,
        Err(YggError::KeyInUse) => panic!("{who}: identity claim remains after joined close"),
        Err(error) => panic!("{who}: first Ygg reuse attempt failed: {error}"),
    };
    tokio::time::timeout(RELEASE_BUDGET, transport.close())
        .await
        .unwrap_or_else(|_| panic!("{who}: one-shot Ygg reuse transport close timed out"))
        .unwrap_or_else(|error| {
            panic!("{who}: one-shot Ygg reuse transport close failed: {error}")
        });
}

pub(super) fn assert_client_binds_released(config: &ClientConfig, who: &str) {
    let network = config
        .network()
        .expect("role config retains network settings");
    let mainline = network.mainline().expect("Mainline settings present");
    let udp = UdpSocket::bind(mainline.bind()).unwrap_or_else(|error| {
        panic!("{who}: joined close did not release Mainline bind: {error}")
    });
    drop(udp);
    let signaling = network.signaling().expect("signaling settings present");
    let tcp = TcpListener::bind(signaling.bind()).unwrap_or_else(|error| {
        panic!("{who}: joined close did not release signaling bind: {error}")
    });
    drop(tcp);
}

pub(super) fn assert_role_binds_released(config: &ServerConfig, who: &str) {
    let network = config
        .network()
        .expect("role config retains network settings");
    let mainline = network.mainline().expect("Mainline settings present");
    let udp = UdpSocket::bind(mainline.bind()).unwrap_or_else(|error| {
        panic!("{who}: joined close did not release Mainline bind: {error}")
    });
    drop(udp);
    let signaling = network.signaling().expect("signaling settings present");
    let tcp = TcpListener::bind(signaling.bind()).unwrap_or_else(|error| {
        panic!("{who}: joined close did not release signaling bind: {error}")
    });
    drop(tcp);
}
