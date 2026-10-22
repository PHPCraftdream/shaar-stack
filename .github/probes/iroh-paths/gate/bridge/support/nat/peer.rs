#![forbid(unsafe_code)]
//! Real iroh peer owned by one helper process; all keys are synthetic test fixtures.

use super::{protocol::Nonce, transport::Factory};
use iroh::endpoint::{
    Connection, NetReportConfig, PortmapperConfig, QuicTransportConfig, SendStream, presets,
};
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};
use iroh_paths_probe::harness;
use std::{io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

pub struct Config {
    pub side: u8,
    pub relay: SocketAddr,
    pub control_bind: SocketAddr,
    pub native_bind: Option<SocketAddr>,
    pub external_addr: Option<SocketAddr>,
    pub expect_native: bool,
    pub nonce: Nonce,
    pub qlog: PathBuf,
}

pub struct Session {
    endpoint: Endpoint,
    connection: Connection,
    stream: SendStream,
    transport: Arc<Factory>,
    pub side: u8,
}

fn native_only(path: noq_proto::FourTuple) -> bool {
    match path.remote().ip().to_canonical() {
        std::net::IpAddr::V4(_) => true,
        std::net::IpAddr::V6(ip) => ip.octets()[..6] != [0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b],
    }
}

/// cancel-safe: NO — the process terminates on deadline; this bootstrap is never retried.
pub async fn start(config: &Config) -> io::Result<Session> {
    if config.side > 1
        || config.native_bind.is_some() != config.external_addr.is_some()
        || (config.expect_native && config.native_bind.is_none())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid peer side/native fields",
        ));
    }
    let transport =
        Factory::register(config.control_bind, config.relay, config.nonce, config.side).await?;
    let key = SecretKey::from([11 + config.side; 32]);
    let peer = SecretKey::from([12 - config.side; 32]).public();
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![harness::ALPN.to_vec()])
        .add_custom_transport(transport.clone())
        .clear_ip_transports()
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .transport_config(
            QuicTransportConfig::builder()
                .application_data_filter(native_only)
                .send_observed_address_reports(false)
                .receive_observed_address_reports(false)
                .send_window(8)
                .datagram_send_buffer_size(8)
                .keep_alive_interval(Duration::from_millis(100))
                .qlog_from_path(&config.qlog, "peer")
                .build(),
        );
    if let Some(bind) = config.native_bind {
        builder = builder.bind_addr(bind).map_err(io::Error::other)?;
    }
    let endpoint = builder.bind().await.map_err(io::Error::other)?;
    let connection = if config.side == 0 {
        endpoint
            .connect(
                EndpointAddr::from_parts(peer, [TransportAddr::Custom(transport.remote_addr())]),
                harness::ALPN,
            )
            .await
            .map_err(io::Error::other)?
    } else {
        endpoint
            .accept()
            .await
            .ok_or_else(|| io::Error::other("accept ended"))?
            .await
            .map_err(io::Error::other)?
    };
    if connection.remote_id() != peer {
        return Err(io::Error::other("unexpected authenticated peer"));
    }
    let mut stream = connection.open_uni().await.map_err(io::Error::other)?;
    stream
        .write_all(b"queued!!")
        .await
        .map_err(io::Error::other)?;
    stream.finish().map_err(io::Error::other)?;
    connection
        .send_datagram(b"queued!!".to_vec().into())
        .map_err(io::Error::other)?;
    let before = transport.stats();
    if tokio::time::timeout(Duration::from_millis(250), connection.accept_uni())
        .await
        .is_ok()
        || tokio::time::timeout(Duration::from_millis(250), connection.read_datagram())
            .await
            .is_ok()
    {
        return Err(io::Error::other(
            "payload escaped before native candidate publication",
        ));
    }
    let after = transport.stats();
    if after.0 <= before.0 || after.1 <= before.1 {
        return Err(io::Error::other(
            "custom control must remain active while payload is queued",
        ));
    }
    Ok(Session {
        endpoint,
        connection,
        stream,
        transport,
        side: config.side,
    })
}

impl Session {
    /// cancel-safe: NO — frame reads are terminal on deadline, never resumed after cancellation.
    pub async fn observe(&self, config: &Config) -> io::Result<()> {
        let Some(external) = config.external_addr else {
            return Ok(());
        };
        self.endpoint.add_external_addr(external).await;
        if config.expect_native {
            let result = async {
                let bytes = self
                    .connection
                    .accept_uni()
                    .await
                    .map_err(io::Error::other)?
                    .read_to_end(8)
                    .await
                    .map_err(io::Error::other)?;
                if bytes != b"queued!!" {
                    return Err(io::Error::other("incorrect native STREAM bytes"));
                }
                let bytes = self
                    .connection
                    .read_datagram()
                    .await
                    .map_err(io::Error::other)?;
                if bytes.as_ref() != b"queued!!" {
                    return Err(io::Error::other("incorrect native DATAGRAM bytes"));
                }
                Ok(())
            };
            tokio::time::timeout(Duration::from_secs(20), result)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native traversal deadline"))?
        } else {
            let before = self.transport.stats();
            if tokio::time::timeout(Duration::from_secs(2), self.connection.accept_uni())
                .await
                .is_ok()
                || tokio::time::timeout(Duration::from_secs(2), self.connection.read_datagram())
                    .await
                    .is_ok()
            {
                return Err(io::Error::other(
                    "negative native case delivered payload or closed early",
                ));
            }
            let after = self.transport.stats();
            if after.0 <= before.0 || after.1 <= before.1 {
                return Err(io::Error::other("negative case lost custom control"));
            }
            Ok(())
        }
    }

    pub async fn close(self) -> (u64, u64) {
        self.connection.close(0u32.into(), b"fixture done");
        drop(self.stream);
        drop(self.connection);
        self.endpoint.close().await;
        self.transport.stats()
    }
}
