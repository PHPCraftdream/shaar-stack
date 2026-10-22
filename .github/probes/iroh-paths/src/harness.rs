//! Shared baseline harness: endpoint construction, echo protocol, qlog dir.
//!
//! All same-host, in-memory: API and observability proofs only. NOT proof of
//! NAT traversal; that stage is not part of this published substage.

use std::{
    path::PathBuf,
    process,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use iroh::{
    Endpoint,
    endpoint::{Connection, QuicTransportConfig, presets, transports::CustomTransport},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};

use crate::mem_transport::{MemTransport, TEST_TRANSPORT_ID};

/// ALPN used by the baseline test.
pub const ALPN: &[u8] = b"iroh-paths/baseline/1";

/// Timeout applied to every await that could hang.
pub const PHASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent bidi streams one Echo handler accepts at once.
const ECHO_STREAM_CAP: usize = 8;

/// Echo protocol handler: a REAL accept loop over bidirectional streams.
///
/// Each accepted connection is served until the peer closes it: streams are
/// accepted in a loop, copied back, and finished. A bounded concurrency
/// guard (atomic counter, cap [`ECHO_STREAM_CAP`]) rejects further streams
/// beyond the cap instead of queueing unbounded work.
#[derive(Debug, Clone, Default)]
pub struct Echo {
    active: Arc<AtomicUsize>,
}

struct StreamPermit<'a>(&'a AtomicUsize);

impl Drop for StreamPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Echo {
    fn try_acquire(&self) -> Option<StreamPermit<'_>> {
        loop {
            let cur = self.active.load(Ordering::SeqCst);
            if cur >= ECHO_STREAM_CAP {
                return None;
            }
            if self
                .active
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(StreamPermit(self.active.as_ref()));
            }
        }
    }
}

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                // Connection closed: the accept loop terminates cleanly.
                Err(_) => return Ok(()),
            };
            let Some(_permit) = self.try_acquire() else {
                return Err(AcceptError::NotAllowed {
                    meta: n0_error::Meta::new(),
                });
            };
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
        }
    }
}

/// Creates a fresh qlog output directory for one test invocation.
///
/// MUST live under the workspace `target/iroh-paths/` (tests run with the
/// package dir as cwd; CI uploads `target/iroh-paths/`). Deliberately NOT
/// `std::env::temp_dir()`.
pub fn qlog_dir(tag: &str) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let dir = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("target")
        .join("iroh-paths")
        .join(format!("{tag}-{pid}-{millis}", pid = process::id()));
    std::fs::create_dir_all(&dir).expect("create qlog dir");
    dir
}

/// Endpoint configuration for [`build_endpoint`].
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// Secret key (determines the endpoint id).
    pub secret_key: iroh::SecretKey,
    /// Custom mem transport to attach, if any.
    pub mem_transport: Option<Arc<MemTransport>>,
    /// Remove all IP transports (custom-only baseline ONLY).
    pub custom_only: bool,
    /// Qlog directory and file prefix (feature `qlog`).
    pub qlog: Option<(PathBuf, String)>,
}

impl EndpointConfig {
    /// Minimal config: crypto only, no transports beyond defaults.
    pub fn new(secret_key: iroh::SecretKey) -> Self {
        Self {
            secret_key,
            mem_transport: None,
            custom_only: false,
            qlog: None,
        }
    }
}

/// Builds and binds an endpoint per [`EndpointConfig`].
///
/// Uses `presets::Minimal` (crypto provider only; no n0 relays or DNS, no
/// network use beyond the in-memory pipe). `clear_ip_transports` is called
/// ONLY when `custom_only` is set (the custom-only baseline).
pub async fn build_endpoint(
    config: EndpointConfig,
) -> std::result::Result<Endpoint, iroh::endpoint::BindError> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(config.secret_key)
        .alpns(vec![ALPN.to_vec()]);
    if let Some((dir, prefix)) = config.qlog {
        // Public qlog injection (iroh v1.3.0, endpoint/quic.rs, feature
        // "qlog"): `QuicTransportConfig::builder().qlog_from_path(dir, prefix)`.
        builder = builder.transport_config(
            QuicTransportConfig::builder()
                .qlog_from_path(&dir, &prefix)
                .build(),
        );
    }
    if let Some(transport) = config.mem_transport {
        builder = builder.add_custom_transport(transport as Arc<dyn CustomTransport>);
    }
    if config.custom_only {
        builder = builder.clear_ip_transports();
    }
    builder.bind().await
}

/// Spawns an echo server for [`ALPN`] on `ep`.
///
/// This Router is the ONLY consumer of incoming connections on `ep` — no
/// `ep.accept` task runs alongside it.
pub fn spawn_echo(ep: &Endpoint) -> Router {
    Router::builder(ep.clone())
        .accept(ALPN, Echo::default())
        .spawn()
}

/// Snapshots `conn.paths()` into diagnostic strings and logs them.
pub fn snapshot_paths(label: &str, conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    for path in conn.paths().iter() {
        let line = format!(
            "{} path: remote={} selected={} custom={} rtt={:?}",
            label,
            path.remote_addr(),
            path.is_selected(),
            matches!(path.remote_addr(), iroh::TransportAddr::Custom(a) if a.id() == TEST_TRANSPORT_ID),
            path.rtt(),
        );
        eprintln!("{line}");
        out.push(line);
    }
    out
}

/// Returns `true` if the currently selected path is the custom transport.
pub fn custom_path_selected(conn: &Connection) -> bool {
    conn.paths().iter().any(|p| {
        p.is_selected()
            && matches!(p.remote_addr(), iroh::TransportAddr::Custom(a) if a.id() == TEST_TRANSPORT_ID)
    })
}

/// Runs one echo round trip over `conn` and asserts the response.
pub async fn echo_roundtrip(conn: &Connection, msg: &[u8]) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(PHASE_TIMEOUT, conn.open_bi())
        .await
        .expect("open_bi timed out")
        .anyerr()?;
    send.write_all(msg).await.anyerr()?;
    send.finish().anyerr()?;
    let response = tokio::time::timeout(PHASE_TIMEOUT, recv.read_to_end(64 * 1024))
        .await
        .expect("read_to_end timed out")
        .anyerr()?;
    assert_eq!(response, msg, "echo round trip mismatch");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn stream_permits_are_bounded_and_reusable() {
        let echo = Echo::default();
        let mut permits: Vec<_> = (0..ECHO_STREAM_CAP)
            .map(|_| echo.try_acquire().expect("available slot"))
            .collect();
        assert!(echo.try_acquire().is_none());
        drop(permits.pop());
        assert!(echo.try_acquire().is_some());
        drop(permits);
        assert_eq!(echo.active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancellation_releases_an_already_acquired_stream_permit() {
        let echo = Echo::default();
        let mut task = Box::pin(async {
            let _permit = echo.try_acquire().expect("available slot");
            std::future::pending::<()>().await;
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(task.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(echo.active.load(Ordering::SeqCst), 1);
        drop(task);
        assert_eq!(echo.active.load(Ordering::SeqCst), 0);
        assert!(echo.try_acquire().is_some());
    }
}
