#![forbid(unsafe_code)]
//! Shared fixed-policy fixture; no production transport authorization API.

use iroh::endpoint::{QuicTransportConfig, presets};
use iroh::{Endpoint, SecretKey, address_lookup::memory::MemoryLookup};
use iroh_paths_probe::{MemTransport, harness};
use std::{net::IpAddr, path::Path, sync::Arc, time::Duration};

// Conservatively deny every internal synthetic subnet, never authorize custom by prefix.
pub(super) fn native_only(tuple: noq_proto::FourTuple) -> bool {
    match tuple.remote().ip().to_canonical() {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => ip.octets()[..6] != [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b],
    }
}

/// cancel-safe: NO — fixture termination does not retry partially completed bind.
pub(super) async fn bind(
    key: SecretKey,
    transport: Arc<MemTransport>,
    lookup: MemoryLookup,
    directory: &Path,
    prefix: &str,
) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![harness::ALPN.to_vec()])
        .address_lookup(lookup)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .expect("loopback bind config")
        .add_custom_transport(transport)
        .transport_config(
            QuicTransportConfig::builder()
                .application_data_filter(native_only)
                .spike_disable_nat_traversal()
                .send_observed_address_reports(false)
                .receive_observed_address_reports(false)
                .send_window(8)
                .datagram_send_buffer_size(8)
                .keep_alive_interval(Duration::from_millis(40))
                .qlog_from_path(directory, prefix)
                .build(),
        )
        .bind()
        .await
        .expect("bind mixed endpoint")
}
