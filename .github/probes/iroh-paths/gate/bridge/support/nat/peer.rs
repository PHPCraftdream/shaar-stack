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
    pub recovery: bool,
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

pub struct Recovery {
    stream: SendStream,
    old_path: noq_proto::PathId,
    stable_id: usize,
    lost_before: u64,
    stream_frames_before: u64,
    stream_frames_lost: u64,
    control_before: (u64, u64),
}

impl Recovery {
    pub fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"sent_stream": u64::from(self.stream.id()),
            "old_path": self.old_path.to_string(), "stable_id": self.stable_id,
            "lost_before": self.lost_before, "stream_frames_before": self.stream_frames_before,
            "stream_frames_lost": self.stream_frames_lost})
    }
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
        || (config.recovery && !config.expect_native)
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
    let interval = if config.recovery {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(100)
    };
    let mut quic = QuicTransportConfig::builder()
        .application_data_filter(native_only)
        .send_observed_address_reports(false)
        .receive_observed_address_reports(false)
        .send_window(8)
        .datagram_send_buffer_size(8)
        .keep_alive_interval(interval)
        .qlog_from_path(&config.qlog, "peer");
    if config.recovery {
        quic = quic
            .default_path_max_idle_timeout(Duration::from_secs(3))
            .default_path_keep_alive_interval(interval);
    }
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![harness::ALPN.to_vec()])
        .add_custom_transport(transport.clone())
        .clear_ip_transports()
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .transport_config(quic.build());
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
    let negative_wait = if config.recovery {
        Duration::from_millis(1250)
    } else {
        Duration::from_millis(250)
    };
    if tokio::time::timeout(negative_wait, connection.accept_uni())
        .await
        .is_ok()
        || tokio::time::timeout(negative_wait, connection.read_datagram())
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

/// cancel-safe: yes — only metadata snapshots and timer waits; caller owns the deadline.
async fn observe_native_path(
    mut snapshot: impl FnMut() -> io::Result<Option<noq_proto::PathId>>,
) -> io::Result<noq_proto::PathId> {
    loop {
        if let Some(path) = snapshot()? {
            return Ok(path);
        }
        // The iroh actor may publish Established after Noq wakes application reads.
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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

    /// cancel-safe: yes — stopped only observes acknowledgement or peer STOP_SENDING.
    pub async fn ack_initial(&self) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            if self
                .stream
                .stopped()
                .await
                .map_err(io::Error::other)?
                .is_some()
            {
                return Err(io::Error::other("initial STREAM was stopped, not ACKed"));
            }
            observe_native_path(|| self.native_path()).await?;
            Ok(())
        })
        .await
        .map_err(|_| io::Error::other("initial STREAM ACK/path observation deadline"))?
    }

    fn native_path(&self) -> io::Result<Option<noq_proto::PathId>> {
        let paths = self.connection.paths();
        let mut native = paths.iter().filter(|path| path.is_ip());
        let Some(path) = native.next() else {
            return Ok(None);
        };
        if native.next().is_some() {
            return Err(io::Error::other("expected exactly one native path"));
        }
        Ok(Some(path.id()))
    }

    /// cancel-safe: NO — terminal deadline; the single application write is never retried.
    pub async fn lose_native(&self) -> io::Result<Recovery> {
        tokio::time::timeout(Duration::from_secs(20), async {
            let old_path = self
                .native_path()?
                .ok_or_else(|| io::Error::other("no native path before loss"))?;
            let stats = self.connection.stats();
            let lost_before = stats.lost_packets;
            let stream_frames_before = stats.frame_tx.stream;
            let control_before = self.transport.stats();
            let mut stream = self.connection.open_uni().await.map_err(io::Error::other)?;
            stream
                .write_all(b"recover!")
                .await
                .map_err(io::Error::other)?;
            stream.finish().map_err(io::Error::other)?;
            loop {
                let paths = self.connection.paths();
                if !paths.iter().any(|path| path.is_ip()) {
                    if paths.is_empty() {
                        return Err(io::Error::other("custom path vanished with native path"));
                    }
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            // Unreliable DATAGRAM is queued only after the failed native path is gone.
            self.connection
                .send_datagram(b"recover!".to_vec().into())
                .map_err(io::Error::other)?;
            if tokio::time::timeout(Duration::from_millis(1250), stream.stopped())
                .await
                .is_ok()
                || tokio::time::timeout(Duration::from_millis(250), self.connection.accept_uni())
                    .await
                    .is_ok()
                || tokio::time::timeout(Duration::from_millis(250), self.connection.read_datagram())
                    .await
                    .is_ok()
            {
                return Err(io::Error::other(
                    "payload delivered or connection closed during native loss",
                ));
            }
            let control_after = self.transport.stats();
            let stats = self.connection.stats();
            if control_after.0 <= control_before.0
                || control_after.1 <= control_before.1
                || stats.lost_packets <= lost_before
                || stats.frame_tx.stream <= stream_frames_before
            {
                return Err(io::Error::other(
                    "missing live custom control or actual STREAM transmission/loss",
                ));
            }
            Ok(Recovery {
                stream,
                old_path,
                stable_id: self.connection.stable_id(),
                lost_before,
                stream_frames_before,
                stream_frames_lost: stats.frame_tx.stream,
                control_before,
            })
        })
        .await
        .map_err(|_| io::Error::other("physical path loss deadline"))?
    }

    /// cancel-safe: NO — terminal deadline; received bytes and STREAM are never replayed.
    pub async fn recover_native(&self, recovery: Recovery) -> io::Result<serde_json::Value> {
        // Upstream's unchanged automatic path-upgrade timer is 60 seconds.
        tokio::time::timeout(Duration::from_secs(90), async {
            let mut incoming = self
                .connection
                .accept_uni()
                .await
                .map_err(io::Error::other)?;
            let received_stream = u64::from(incoming.id());
            let bytes = incoming.read_to_end(8).await.map_err(io::Error::other)?;
            if bytes != b"recover!" {
                return Err(io::Error::other("incorrect recovered STREAM bytes/FIN"));
            }
            let datagram = self
                .connection
                .read_datagram()
                .await
                .map_err(io::Error::other)?;
            if datagram.as_ref() != b"recover!" {
                return Err(io::Error::other("incorrect recovered DATAGRAM bytes"));
            }
            if recovery
                .stream
                .stopped()
                .await
                .map_err(io::Error::other)?
                .is_some()
            {
                return Err(io::Error::other("recovery STREAM was stopped, not ACKed"));
            }
            let new_path = observe_native_path(|| self.native_path()).await?;
            let control_after = self.transport.stats();
            if new_path == recovery.old_path
                || self.connection.stable_id() != recovery.stable_id
                || self.connection.stats().frame_tx.stream <= recovery.stream_frames_lost
                || control_after.0 <= recovery.control_before.0
                || control_after.1 <= recovery.control_before.1
            {
                return Err(io::Error::other(
                    "missing fresh native path or original live connection",
                ));
            }
            Ok(
                serde_json::json!({"sent_stream":u64::from(recovery.stream.id()),
                "received_stream":received_stream,"old_path":recovery.old_path.to_string(),
                "new_path":new_path.to_string(),"stable_id":self.connection.stable_id(),
                "lost_packets":self.connection.stats().lost_packets,
                "stream_frames_recovered":self.connection.stats().frame_tx.stream,"payload":"recover!"}),
            )
        })
        .await
        .map_err(|_| io::Error::other("automatic re-punch deadline"))?
    }

    pub async fn close(self) -> (u64, u64) {
        self.connection.close(0u32.into(), b"fixture done");
        drop(self.stream);
        drop(self.connection);
        self.endpoint.close().await;
        self.transport.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_observation_accepts_current_or_later_actor_snapshot() {
        for pending in [0, 2] {
            let mut calls = 0;
            let path = tokio::time::timeout(
                Duration::from_secs(5),
                observe_native_path(|| {
                    calls += 1;
                    Ok((calls > pending).then_some(2u32.into()))
                }),
            )
            .await
            .expect("observation deadline")
            .expect("published path");
            assert_eq!(path, 2u32.into());
            assert_eq!(calls, pending + 1);
        }
    }

    #[tokio::test]
    async fn native_observation_preserves_terminal_snapshot_errors() {
        let mut calls = 0;
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            observe_native_path(|| {
                calls += 1;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ambiguous path snapshot",
                ))
            }),
        )
        .await
        .expect("error must not be retried")
        .expect_err("snapshot error");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn native_observation_can_be_cancelled_without_fabricating_readiness() {
        assert!(
            tokio::time::timeout(Duration::from_millis(1), observe_native_path(|| Ok(None)))
                .await
                .is_err()
        );
        let path = tokio::time::timeout(
            Duration::from_secs(5),
            observe_native_path(|| Ok(Some(3u32.into()))),
        )
        .await
        .expect("fresh observation deadline")
        .expect("fresh path");
        assert_eq!(path, 3u32.into());
    }
}
