//! P14 resource budgets over real products on loopback (Linux, CI-only, ignored by default).
//!
//! Drives the CI-built `shaar-server` and `shaar-client` through warm-up, idle, latency,
//! bulk, per-stream, back-pressure and client-restart churn phases while sampling
//! `/proc`; budgets are in `docs/verification/scenarios.md` section 11. Run only by
//! `.github/ci/run.py resource-budget`, never in the ordinary test selection.

#![forbid(unsafe_code)]

use super::*;
use std::{path::PathBuf, sync::Arc, time::Instant};
use tokio::sync::{Notify, mpsc, oneshot, watch};

mod probe;
mod traffic;

use probe::{Report, Sample, cpu_percent, percentile, sample};
use traffic::{
    bulk, hold_streams, round_trip, round_trip_eventually, stalled_upload, target_service,
};

/// Per-mode ceilings and phase sizes.
struct Limits {
    rss_mib: f64,
    peak_mib: f64,
    idle_cpu_pct: f64,
    idle_seconds: u64,
    churn: usize,
}

const DIRECT: Limits = Limits {
    rss_mib: 48.0,
    peak_mib: 96.0,
    idle_cpu_pct: 1.0,
    idle_seconds: 30,
    churn: 15,
};
// The idle window exceeds the 60 s publication refresh.
const COMPOSED: Limits = Limits {
    rss_mib: 96.0,
    peak_mib: 160.0,
    idle_cpu_pct: 2.0,
    idle_seconds: 65,
    churn: 6,
};
const SESSION_MIB: f64 = 4.0;
const STREAM_KIB: f64 = 512.0;
const LATENCY_P95_MS: f64 = 100.0;
const THROUGHPUT_MIB_S: f64 = 20.0;
const STALL_ACCEPTED_MIB: f64 = 32.0;
const STALL_RSS_MIB: f64 = 12.0;
const LEAK_FDS: f64 = 2.0;
const LEAK_THREADS: f64 = 2.0;
const LEAK_RSS_MIB: f64 = 4.0;
const STOP_MS: f64 = 5000.0;
const STREAMS: usize = 16;

fn pid(processes: &Processes, index: usize) -> Result<u32, String> {
    processes.0[index]
        .child
        .id()
        .ok_or_else(|| "process PID unavailable".to_owned())
}

async fn pause(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

fn mib(kib: u64) -> f64 {
    kib as f64 / 1024.0
}

/// Replaceable client process in front of the fixed target.
struct Rig {
    server: usize,
    client: usize,
    front: SocketAddr,
    release: Arc<Notify>,
    client_exe: String,
    client_config: PathBuf,
    workdir: PathBuf,
    direct: bool,
}

impl Rig {
    /// Gracefully stops the client, starts a fresh one and proves one exchange.
    async fn restart_client(&mut self, processes: &mut Processes) -> Result<(), String> {
        super::super::shutdown::signal_owned(processes, self.client).await?;
        super::payload::require_exit(processes, self.client).await?;
        let index = processes.spawn(&self.client_exe, &self.client_config, &self.workdir)?;
        if self.direct {
            let line = ready_line(&mut processes.0[index].stdout).await?;
            if line.trim().strip_prefix("listening=").is_none() {
                return Err("invalid restarted client readiness".into());
            }
        }
        self.client = index;
        round_trip_eventually(self.front, b"restart").await?;
        Ok(())
    }
}

fn pair(processes: &Processes, rig: &Rig) -> Result<(Sample, Sample), String> {
    Ok((
        sample(pid(processes, rig.server)?)?,
        sample(pid(processes, rig.client)?)?,
    ))
}

async fn measure(
    processes: &mut Processes,
    rig: &mut Rig,
    limits: &Limits,
    pre_client: Sample,
    report: &mut Report,
) -> Result<(), String> {
    let server_pid = pid(processes, rig.server)?;
    // Warm-up and steady state.
    for _ in 0..20 {
        round_trip(rig.front, b"warm").await?;
    }
    pause(2).await;
    let (server, client) = pair(processes, rig)?;
    report.at_most("server_steady_rss_mib", server.rss_mib(), limits.rss_mib);
    report.at_most("client_steady_rss_mib", client.rss_mib(), limits.rss_mib);
    report.at_most(
        "server_session_cost_mib",
        server.rss_mib() - pre_client.rss_mib(),
        SESSION_MIB,
    );
    // Idle CPU with no connections.
    let (server_before, client_before) = (server, client);
    pause(limits.idle_seconds).await;
    let (server_after, client_after) = pair(processes, rig)?;
    let seconds = limits.idle_seconds as f64;
    report.at_most(
        "server_idle_cpu_pct",
        cpu_percent(&server_before, &server_after, seconds),
        limits.idle_cpu_pct,
    );
    report.at_most(
        "client_idle_cpu_pct",
        cpu_percent(&client_before, &client_after, seconds),
        limits.idle_cpu_pct,
    );
    // Sequential new-connection latency.
    let mut millis = Vec::with_capacity(200);
    for _ in 0..200 {
        millis.push(round_trip(rig.front, b"latency").await?.as_secs_f64() * 1000.0);
    }
    millis.sort_by(f64::total_cmp);
    report.at_most(
        "round_trip_p50_ms",
        percentile(&millis, 0.5),
        LATENCY_P95_MS,
    );
    report.at_most(
        "round_trip_p95_ms",
        percentile(&millis, 0.95),
        LATENCY_P95_MS,
    );
    // Bulk echo and peak memory.
    report.at_least(
        "bulk_echo_mib_per_s",
        bulk(rig.front, 64).await?,
        THROUGHPUT_MIB_S,
    );
    let (server_peak, client_peak) = pair(processes, rig)?;
    report.at_most(
        "server_peak_rss_mib",
        mib(server_peak.hwm_kib),
        limits.peak_mib,
    );
    report.at_most(
        "client_peak_rss_mib",
        mib(client_peak.hwm_kib),
        limits.peak_mib,
    );
    // Memory per concurrent stream.
    let (server_idle, client_idle) = pair(processes, rig)?;
    let held = hold_streams(rig.front, STREAMS).await?;
    let (server_held, client_held) = pair(processes, rig)?;
    let per_stream = |after: &Sample, before: &Sample| {
        after.rss_kib.saturating_sub(before.rss_kib) as f64 / STREAMS as f64
    };
    report.at_most(
        "server_per_stream_kib",
        per_stream(&server_held, &server_idle),
        STREAM_KIB,
    );
    report.at_most(
        "client_per_stream_kib",
        per_stream(&client_held, &client_idle),
        STREAM_KIB,
    );
    drop(held);
    pause(2).await;
    // Back-pressure: a target that never reads must stop the writer at bounded buffering.
    let (server_before, client_before) = pair(processes, rig)?;
    let (accepted, stalled) = stalled_upload(rig.front, 96).await?;
    pause(1).await;
    let (server_stalled, client_stalled) = pair(processes, rig)?;
    report.at_most(
        "stalled_upload_accepted_mib",
        accepted as f64 / (1024.0 * 1024.0),
        STALL_ACCEPTED_MIB,
    );
    let delta =
        |after: &Sample, before: &Sample| (after.rss_kib as f64 - before.rss_kib as f64) / 1024.0;
    report.at_most(
        "server_stalled_rss_delta_mib",
        delta(&server_stalled, &server_before),
        STALL_RSS_MIB,
    );
    report.at_most(
        "client_stalled_rss_delta_mib",
        delta(&client_stalled, &client_before),
        STALL_RSS_MIB,
    );
    rig.release.notify_waiters();
    drop(stalled);
    pause(2).await;
    // Connect/disconnect churn: the server must return to its baseline.
    let base = sample(server_pid)?;
    for _ in 0..limits.churn {
        rig.restart_client(processes).await?;
    }
    pause(3).await;
    let after = sample(server_pid)?;
    report.at_most(
        "server_fd_growth_after_churn",
        after.fds as f64 - base.fds as f64,
        LEAK_FDS,
    );
    report.at_most(
        "server_thread_growth_after_churn",
        after.threads as f64 - base.threads as f64,
        LEAK_THREADS,
    );
    report.at_most(
        "server_rss_growth_after_churn_mib",
        delta(&after, &base),
        LEAK_RSS_MIB.max(base.rss_mib() * 0.10),
    );
    // Joined shutdown releases promptly.
    let started = Instant::now();
    super::super::shutdown::signal_owned(processes, rig.server).await?;
    super::payload::require_exit(processes, rig.server).await?;
    report.at_most(
        "server_stop_ms",
        started.elapsed().as_secs_f64() * 1000.0,
        STOP_MS,
    );
    Ok(())
}

async fn reserved_front() -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    listener.local_addr().map_err(|e| e.to_string())
}

async fn direct(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
) -> Result<(), String> {
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let target_addr = target.local_addr().map_err(|e| e.to_string())?;
    let release = Arc::new(Notify::new());
    tasks.spawn(target_service(target, Arc::clone(&release)));
    let server_key = hex(&Identity::from_seed([0xb1; 32]).public_key_bytes());
    let client_key = hex(&Identity::from_seed([0xb2; 32]).public_key_bytes());
    key_file(&temp.0.join("server.key"), [0xb1; 32]).map_err(|e| e.to_string())?;
    key_file(&temp.0.join("client.key"), [0xb2; 32]).map_err(|e| e.to_string())?;
    fs::write(temp.0.join("allowed.txt"), format!("{client_key}\n")).map_err(|e| e.to_string())?;
    let server_config = temp.0.join("server.ktav");
    fs::write(
        &server_config,
        format!("target: {target_addr}\nbind: 127.0.0.1:0\nkey_file:: server.key\nallowlist_path:: allowed.txt\nfallback: signal\n"),
    )
    .map_err(|e| e.to_string())?;
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|e| e.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|e| e.to_string())?;
    let server = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let line = ready_line(&mut processes.0[server].stdout).await?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 2
        || !fields[0].starts_with("bound=")
        || fields[1] != format!("public_key={server_key}")
    {
        return Err("invalid server readiness output".into());
    }
    let bound: SocketAddr = fields[0]
        .trim_start_matches("bound=")
        .parse()
        .map_err(|error: std::net::AddrParseError| error.to_string())?;
    let direct_address = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    let front = reserved_front().await?;
    let client_config = temp.0.join("client.ktav");
    fs::write(
        &client_config,
        format!("server: {server_key}\nserver_address: {direct_address}\nlisten: {front}\nkey_file:: client.key\nfallback: signal\n"),
    )
    .map_err(|e| e.to_string())?;
    let pre_client = sample(pid(processes, server)?)?;
    let client = processes.spawn(&client_exe, &client_config, &temp.0)?;
    let line = ready_line(&mut processes.0[client].stdout).await?;
    if line.trim().strip_prefix("listening=").is_none() {
        return Err("invalid client readiness output".into());
    }
    let mut rig = Rig {
        server,
        client,
        front,
        release,
        client_exe,
        client_config,
        workdir: temp.0.clone(),
        direct: true,
    };
    let mut report = Report::new("direct");
    let outcome = measure(processes, &mut rig, &DIRECT, pre_client, &mut report).await;
    let finished = report.finish();
    outcome?;
    finished
}

/// Composed standby processes over the owned relay, Mainline fixture and Ygg transit.
/// cancel-safe: NO — the parent retains children and actor tasks for finalize.
pub(super) async fn composed(
    temp: &Temp,
    processes: &mut Processes,
    tasks: &mut JoinSet<Result<(), String>>,
    relay: &shaar_p2p::RelayAddr,
    transit: &str,
) -> Result<(), String> {
    let server_key = Identity::from_seed([0xd1; 32]).public_key_bytes();
    let client_key = Identity::from_seed([0xd2; 32]).public_key_bytes();
    key_file(&temp.0.join("res-server.key"), [0xd1; 32]).map_err(|e| e.to_string())?;
    key_file(&temp.0.join("res-client.key"), [0xd2; 32]).map_err(|e| e.to_string())?;
    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let target_addr = target.local_addr().map_err(|e| e.to_string())?;
    let release = Arc::new(Notify::new());
    tasks.spawn(target_service(target, Arc::clone(&release)));
    let front = reserved_front().await?;
    let server_peer = super::mainline_fixture::LoopbackPeer::bind().await;
    let client_peer = super::mainline_fixture::LoopbackPeer::bind().await;
    let server_bootstrap = server_peer.address;
    let client_bootstrap = client_peer.address;
    let (record, records) =
        watch::channel::<Option<Arc<super::mainline_fixture::CapturedPut>>>(None);
    let (publications, mut observed) = mpsc::channel(8);
    let (get_seen, get_received) = oneshot::channel();
    let server_records = records.clone();
    let server_publications = publications.clone();
    tasks.spawn(async move {
        server_peer
            .serve_composed(server_records, server_publications, None)
            .await;
        Ok(())
    });
    tasks.spawn(async move {
        client_peer
            .serve_composed(records, publications, Some(get_seen))
            .await;
        Ok(())
    });
    tokio::fs::write(
        temp.0.join("res-allowed.txt"),
        format!("{}\n", hex(&client_key)),
    )
    .await
    .map_err(|e| e.to_string())?;
    let server_config = temp.0.join("res-server.ktav");
    let client_config = temp.0.join("res-client.ktav");
    let server_text = format!(
        "target: {target_addr}\nallowlist_path:: res-allowed.txt\nkey_file:: res-server.key\nfallback: standby\n{}",
        super::payload::network(server_bootstrap, relay, transit).await?,
    );
    let client_text = format!(
        "server: {}\nlisten: {front}\nkey_file:: res-client.key\nfallback: standby\n{}",
        hex(&server_key),
        super::payload::network(client_bootstrap, relay, transit).await?,
    );
    tokio::fs::write(&server_config, server_text)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::write(&client_config, client_text)
        .await
        .map_err(|e| e.to_string())?;
    let server_exe = std::env::var("SHAAR_SERVER_EXE").map_err(|e| e.to_string())?;
    let client_exe = std::env::var("SHAAR_CLIENT_EXE").map_err(|e| e.to_string())?;
    let server = processes.spawn(&server_exe, &server_config, &temp.0)?;
    let first = super::payload::publication(&mut observed, server_key).await?;
    record.send(Some(first)).map_err(|e| e.to_string())?;
    // Later refreshes keep the served record inside the signed-age limit across restarts.
    tasks.spawn(async move {
        while let Some(item) = observed.recv().await {
            if item.key == server_key {
                let _ = record.send(Some(item));
            }
        }
        Ok(())
    });
    let pre_client = sample(pid(processes, server)?)?;
    let client = processes.spawn(&client_exe, &client_config, &temp.0)?;
    timeout(IO_TIMEOUT, get_received)
        .await
        .map_err(|_| "no actual service-key GET")?
        .map_err(|_| "service-key GET actor ended")?;
    round_trip_eventually(front, b"first").await?;
    let mut rig = Rig {
        server,
        client,
        front,
        release,
        client_exe,
        client_config,
        workdir: temp.0.clone(),
        direct: false,
    };
    let mut report = Report::new("composed");
    let outcome = measure(processes, &mut rig, &COMPOSED, pre_client, &mut report).await;
    let finished = report.finish();
    outcome?;
    finished
}

async fn run_direct() -> Result<(), String> {
    let temp = Temp::new().map_err(|e| e.to_string())?;
    let mut processes = Processes::default();
    let mut tasks = JoinSet::new();
    let result = std::panic::AssertUnwindSafe(timeout(
        Duration::from_secs(300),
        direct(&temp, &mut processes, &mut tasks),
    ))
    .catch_unwind()
    .await;
    finalize(&mut processes, &mut tasks, result).await
}

#[tokio::test]
#[ignore = "P14 measurement: requires CI-built release shaar-server and shaar-client"]
async fn measure_resource_budget_direct() {
    run_direct().await.unwrap();
}

#[tokio::test]
#[ignore = "P14 measurement: requires CI-built release shaar-server and shaar-client"]
async fn measure_resource_budget_composed() {
    super::run(super::Case::Resources).await.unwrap();
}
