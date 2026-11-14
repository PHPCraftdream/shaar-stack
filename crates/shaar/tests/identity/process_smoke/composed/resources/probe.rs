//! Linux `/proc` sampling and the budget report of the P14 resource harness.

#![forbid(unsafe_code)]

use std::{fmt::Write as _, fs, path::PathBuf};

/// Linux USER_HZ; `/proc/<pid>/stat` CPU times are in these ticks.
const CLOCK_TICKS: f64 = 100.0;

/// One point-in-time reading of a child process.
#[derive(Clone, Copy, Debug)]
pub(super) struct Sample {
    pub rss_kib: u64,
    pub hwm_kib: u64,
    pub threads: u64,
    pub fds: u64,
    pub cpu_ticks: u64,
}

impl Sample {
    pub fn rss_mib(&self) -> f64 {
        self.rss_kib as f64 / 1024.0
    }
}

fn status_field(status: &str, name: &str) -> Result<u64, String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
        .ok_or_else(|| format!("missing {name} in /proc status"))
}

pub(super) fn sample(pid: u32) -> Result<Sample, String> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    // Fields after the parenthesised command name: utime and stime are 14 and 15.
    let tail = stat.rsplit_once(')').ok_or("malformed /proc stat")?.1;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let tick = |index: usize| -> Result<u64, String> {
        fields
            .get(index)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "malformed /proc stat times".to_owned())
    };
    let fds = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|e| e.to_string())?
        .count() as u64;
    Ok(Sample {
        rss_kib: status_field(&status, "VmRSS:")?,
        hwm_kib: status_field(&status, "VmHWM:")?,
        threads: status_field(&status, "Threads:")?,
        fds,
        cpu_ticks: tick(11)? + tick(12)?,
    })
}

/// Average CPU use of one core, in percent, between two samples of one process.
pub(super) fn cpu_percent(before: &Sample, after: &Sample, seconds: f64) -> f64 {
    after.cpu_ticks.saturating_sub(before.cpu_ticks) as f64 / CLOCK_TICKS / seconds * 100.0
}

pub(super) fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    let index = ((sorted.len() as f64 - 1.0) * quantile).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

struct Row {
    name: String,
    value: f64,
    limit: f64,
    upper: bool,
}

impl Row {
    fn ok(&self) -> bool {
        if self.upper {
            self.value <= self.limit
        } else {
            self.value >= self.limit
        }
    }
}

/// Measured values against their approved budgets; written even when a budget fails.
pub(super) struct Report {
    mode: &'static str,
    rows: Vec<Row>,
}

fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || " .-_:".contains(*c))
        .collect()
}

fn environment() -> String {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let memory = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("MemTotal:").map(str::to_owned))
        })
        .unwrap_or_default();
    let cpus = std::thread::available_parallelism().map_or(0, |n| n.get());
    let profile = std::env::var("SHAAR_RESOURCE_PROFILE").unwrap_or_else(|_| "unknown".into());
    format!(
        "{{\"kernel\":\"{}\",\"mem_total\":\"{}\",\"cpus\":{cpus},\"profile\":\"{}\"}}",
        clean(kernel.trim()),
        clean(memory.trim()),
        clean(&profile)
    )
}

impl Report {
    pub fn new(mode: &'static str) -> Self {
        Self {
            mode,
            rows: Vec::new(),
        }
    }

    /// The value must not exceed `limit`.
    pub fn at_most(&mut self, name: &str, value: f64, limit: f64) {
        self.push(name, value, limit, true);
    }

    /// The value must reach `limit`.
    pub fn at_least(&mut self, name: &str, value: f64, limit: f64) {
        self.push(name, value, limit, false);
    }

    fn push(&mut self, name: &str, value: f64, limit: f64, upper: bool) {
        let value = if value.is_finite() { value } else { f64::MAX };
        eprintln!(
            "resource-budget {}: {name}={value:.3} {} {limit:.3}",
            self.mode,
            if upper { "<=" } else { ">=" }
        );
        self.rows.push(Row {
            name: name.to_owned(),
            value,
            limit,
            upper,
        });
    }

    fn json(&self) -> String {
        let mut out = format!(
            "{{\"mode\":\"{}\",\"environment\":{},\"rows\":[",
            self.mode,
            environment()
        );
        for (index, row) in self.rows.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"name\":\"{}\",\"value\":{:.3},\"limit\":{:.3},\"bound\":\"{}\",\"ok\":{}}}",
                row.name,
                row.value,
                row.limit,
                if row.upper { "max" } else { "min" },
                row.ok()
            );
        }
        out.push_str("]}\n");
        out
    }

    /// Writes `<SHAAR_RESOURCE_REPORT_DIR>/<mode>.json` when configured, then
    /// fails with every violated budget.
    pub fn finish(self) -> Result<(), String> {
        if let Some(dir) = std::env::var_os("SHAAR_RESOURCE_REPORT_DIR") {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            fs::write(dir.join(format!("{}.json", self.mode)), self.json())
                .map_err(|e| e.to_string())?;
        }
        let failed: Vec<String> = self
            .rows
            .iter()
            .filter(|row| !row.ok())
            .map(|row| format!("{}={:.3} vs {:.3}", row.name, row.value, row.limit))
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!("budgets violated: {}", failed.join("; ")))
        }
    }
}

#[test]
fn report_marks_violations_and_renders_json_rows() {
    let mut report = Report::new("unit");
    report.at_most("a", 1.0, 2.0);
    report.at_most("b", 3.0, 2.0);
    report.at_least("c", 5.0, 4.0);
    report.at_least("d", 1.0, 4.0);
    let json = report.json();
    assert_eq!(json.matches("\"ok\":true").count(), 2);
    assert_eq!(json.matches("\"ok\":false").count(), 2);
    let error = report.finish().unwrap_err();
    assert!(error.contains("b=3.000") && error.contains("d=1.000"));
    assert!(!error.contains("a=1.000") && !error.contains("c=5.000"));
}

#[test]
fn percentile_and_cpu_math_follow_their_definitions() {
    let sorted = [1.0, 2.0, 3.0, 4.0, 100.0];
    assert_eq!(percentile(&sorted, 0.0), 1.0);
    assert_eq!(percentile(&sorted, 0.5), 3.0);
    assert_eq!(percentile(&sorted, 1.0), 100.0);
    let before = Sample {
        rss_kib: 0,
        hwm_kib: 0,
        threads: 1,
        fds: 3,
        cpu_ticks: 100,
    };
    let after = Sample {
        cpu_ticks: 160,
        ..before
    };
    assert!((cpu_percent(&before, &after, 30.0) - 2.0).abs() < 1e-9);
    assert_eq!(cpu_percent(&after, &before, 30.0), 0.0);
}

#[test]
fn own_process_sample_reads_real_proc_values() {
    let own = sample(std::process::id()).unwrap();
    assert!(own.rss_kib > 0 && own.hwm_kib >= own.rss_kib);
    assert!(own.threads >= 1 && own.fds >= 3);
}
