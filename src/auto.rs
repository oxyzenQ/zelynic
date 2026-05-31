// SPDX-License-Identifier: GPL-3.0-only
/// Auto-throttle: background daemon mode for automatic bandwidth management.
///
/// Monitors total system bandwidth and automatically applies limits or
/// takes action when thresholds are exceeded.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::limiter::{apply_limit, check_root, resolve_pids};
use crate::monitor::{aggregate_by_process, collect_bandwidth_stats};
use crate::units::{format_bytes, BandwidthRate};

/// PID file for daemon.
const DAEMON_PID_FILE: &str = "/run/oxy/auto_daemon.pid";

/// Auto-throttle state.
#[derive(Debug)]
pub struct AutoThrottle {
    /// Download threshold in bytes/sec (None = no threshold)
    download_threshold: Option<u64>,
    /// Upload threshold in bytes/sec (None = no threshold)
    upload_threshold: Option<u64>,
    /// Target process to limit (None = system-wide only)
    target: Option<String>,
    /// Kill instead of limit
    kill: bool,
    /// Check interval
    interval: Duration,
    /// Previously limited PIDs (for cleanup)
    limited_pids: HashMap<u32, bool>,
    /// Last snapshot for rate calculation
    last_snapshot: Option<(Instant, u64, u64)>,
    /// Interface override from --iface flag
    iface_override: Option<String>,
}

impl AutoThrottle {
    fn new(
        download: Option<u64>,
        upload: Option<u64>,
        target: Option<String>,
        kill: bool,
        interval_secs: u64,
        iface_override: Option<String>,
    ) -> Self {
        Self {
            download_threshold: download,
            upload_threshold: upload,
            target,
            kill,
            interval: Duration::from_secs(interval_secs),
            limited_pids: HashMap::new(),
            last_snapshot: None,
            iface_override,
        }
    }

    /// Run the auto-throttle loop.
    fn run(&mut self) -> Result<()> {
        check_root()?;

        println!("{} Auto-throttle daemon started", "→".cyan().bold());

        if let Some(dl) = self.download_threshold {
            println!("  Download threshold: {}/s", format_bytes(dl));
        }
        if let Some(ul) = self.upload_threshold {
            println!("  Upload threshold: {}/s", format_bytes(ul));
        }
        if let Some(ref target) = self.target {
            if self.kill {
                println!("  Action: Kill {} when threshold exceeded", target.red());
            } else {
                println!(
                    "  Action: Limit {} when threshold exceeded",
                    target.yellow()
                );
            }
        }
        println!("  Check interval: {}s", self.interval.as_secs());
        println!();

        // Write PID file
        self.write_pid_file()?;

        // Setup cleanup on exit
        let _guard = AutoThrottleGuard;

        // Initial snapshot
        self.update_snapshot()?;

        loop {
            thread::sleep(self.interval);

            if let Err(e) = self.check_and_act() {
                eprintln!("{} Check failed: {}", "WARNING".yellow(), e);
            }
        }
    }

    /// Update bandwidth snapshot.
    fn update_snapshot(&mut self) -> Result<()> {
        let entries = collect_bandwidth_stats()?;
        let processes = aggregate_by_process(&entries);

        let total_rx: u64 = processes.iter().map(|p| p.total_received).sum();
        let total_tx: u64 = processes.iter().map(|p| p.total_sent).sum();

        self.last_snapshot = Some((Instant::now(), total_rx, total_tx));
        Ok(())
    }

    /// Check thresholds and take action.
    fn check_and_act(&mut self) -> Result<()> {
        let entries = collect_bandwidth_stats()?;
        let processes = aggregate_by_process(&entries);

        let total_rx: u64 = processes.iter().map(|p| p.total_received).sum();
        let total_tx: u64 = processes.iter().map(|p| p.total_sent).sum();

        // Calculate rates if we have previous snapshot
        let (rx_rate, tx_rate) = if let Some((prev_time, prev_rx, prev_tx)) = self.last_snapshot {
            let elapsed = prev_time.elapsed().as_secs_f64().max(0.001);
            let rx = ((total_rx.saturating_sub(prev_rx)) as f64 / elapsed) as u64;
            let tx = ((total_tx.saturating_sub(prev_tx)) as f64 / elapsed) as u64;
            (rx, tx)
        } else {
            (0, 0)
        };

        // Update snapshot
        self.last_snapshot = Some((Instant::now(), total_rx, total_tx));

        // Check thresholds
        let dl_exceeded = self
            .download_threshold
            .map(|t| rx_rate > t)
            .unwrap_or(false);
        let ul_exceeded = self.upload_threshold.map(|t| tx_rate > t).unwrap_or(false);

        if dl_exceeded || ul_exceeded {
            let timestamp = chrono_now();
            println!(
                "[{}] {} Threshold exceeded! RX: {}/s, TX: {}/s",
                timestamp.dimmed(),
                "⚠".yellow(),
                format_bytes(rx_rate),
                format_bytes(tx_rate)
            );

            if let Some(target) = self.target.clone() {
                self.act_on_target(&target, &processes)?;
            }
        }

        Ok(())
    }

    /// Take action on target process.
    fn act_on_target(
        &mut self,
        target: &str,
        processes: &[crate::monitor::ProcessBandwidth],
    ) -> Result<()> {
        // Use shared resolve_pids for conservative process-name matching
        let target_pids = match resolve_pids(target) {
            Ok(pids) => pids,
            Err(_) => return Ok(()),
        };
        let target_pid_set: std::collections::HashSet<u32> = target_pids.into_iter().collect();

        let targets: Vec<_> = processes
            .iter()
            .filter(|p| target_pid_set.contains(&p.pid))
            .collect();

        if targets.is_empty() {
            return Ok(());
        }

        for proc in targets {
            if self.kill {
                // Kill the process
                println!(
                    "  {} Killing {} (PID: {})",
                    "→".red(),
                    proc.name.yellow(),
                    proc.pid
                );
                let _ = Command::new("kill")
                    .arg(proc.pid.to_string())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            } else if self.limited_pids.insert(proc.pid, true).is_none() {
                // Limit the process (if not already limited)
                println!(
                    "  {} Limiting {} (PID: {}) to 1mbit/1mbit",
                    "→".yellow(),
                    proc.name.yellow(),
                    proc.pid
                );
                if let Err(e) = apply_limit(
                    &proc.pid.to_string(),
                    Some("1mbit"),
                    Some("1mbit"),
                    self.iface_override.as_deref(),
                ) {
                    eprintln!("    Failed to limit: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Write PID file.
    fn write_pid_file(&self) -> Result<()> {
        let pid = std::process::id().to_string();
        fs::create_dir_all(Path::new(DAEMON_PID_FILE).parent().unwrap())?;
        fs::write(DAEMON_PID_FILE, pid)?;
        Ok(())
    }
}

/// Guard to clean up PID file on exit.
struct AutoThrottleGuard;

impl Drop for AutoThrottleGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(DAEMON_PID_FILE);
    }
}

/// Run auto-throttle in daemon mode.
pub fn run_auto(
    download: Option<&str>,
    upload: Option<&str>,
    target: Option<&str>,
    kill: bool,
    daemon: bool,
    interval: u64,
    iface_override: Option<&str>,
) -> Result<()> {
    check_root()?;

    // Check if daemon already running
    if Path::new(DAEMON_PID_FILE).exists() {
        let pid = fs::read_to_string(DAEMON_PID_FILE)?;
        println!(
            "{} Auto-throttle daemon already running (PID: {})",
            "✗".red(),
            pid.trim()
        );
        bail!("daemon already running");
    }

    // Parse thresholds
    let dl_threshold = download
        .map(|s| BandwidthRate::parse(s).map(|r| r.bytes_per_sec))
        .transpose()
        .context("invalid download threshold")?;
    let ul_threshold = upload
        .map(|s| BandwidthRate::parse(s).map(|r| r.bytes_per_sec))
        .transpose()
        .context("invalid upload threshold")?;

    if dl_threshold.is_none() && ul_threshold.is_none() && target.is_none() {
        bail!("at least one threshold (--download or --upload) or --target is required");
    }

    let target_owned = target.map(|s| s.to_string());

    if daemon {
        println!("{}", "Daemon mode not yet implemented.".yellow());
        println!("Running in foreground mode instead. Press Ctrl+C to stop.");
        println!();
    }

    let mut auto = AutoThrottle::new(
        dl_threshold,
        ul_threshold,
        target_owned,
        kill,
        interval,
        iface_override.map(|s| s.to_string()),
    );
    auto.run()
}

/// Show auto-throttle status.
pub fn auto_status() -> Result<()> {
    if Path::new(DAEMON_PID_FILE).exists() {
        let pid = fs::read_to_string(DAEMON_PID_FILE)?;
        println!(
            "{} Auto-throttle daemon running (PID: {})",
            "●".green(),
            pid.trim()
        );
    } else {
        println!("{} Auto-throttle daemon not running", "○".red());
    }
    Ok(())
}

/// Generate timestamp string.
fn chrono_now() -> String {
    let now = SystemTime::now();
    let datetime = chrono::DateTime::<chrono::Local>::from(now);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}
