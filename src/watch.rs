/// Bandwidth watch module for monitoring and alerting.
///
/// Provides `oxy watch --alert` functionality to monitor a process
/// and send notifications when bandwidth exceeds specified thresholds.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::limiter::{get_process_name, resolve_pids};
use crate::monitor::{aggregate_by_process, collect_bandwidth_stats};
use crate::units::BandwidthRate;

/// Bandwidth watch state for a single process.
#[derive(Debug)]
struct WatchState {
    /// Last known bandwidth rate
    last_rate: u64,
    /// Whether currently in alert state (to avoid spam)
    in_alert: bool,
    /// Last snapshot for rate calculation
    last_snapshot: Option<(Instant, u64)>,
}

/// Watch a process and alert when bandwidth exceeds threshold.
pub fn watch_process(
    target: &str,
    alert_threshold: &str,
    interval_secs: u64,
    notify_cmd: Option<&str>,
) -> Result<()> {
    // Parse threshold
    let threshold_rate = BandwidthRate::parse(alert_threshold)
        .with_context(|| format!("invalid threshold: {}", alert_threshold))?;
    let threshold_bps = threshold_rate.bytes_per_sec;

    // Resolve target to PID(s)
    let pids = resolve_pids(target)?;
    if pids.is_empty() {
        bail!("no process found matching '{}'", target);
    }

    let pid = pids[0]; // Watch first matching process
    let process_name = get_process_name(pid);

    println!(
        "{} Watching {} (PID: {}) — alert when rate exceeds {}",
        "→".cyan(),
        process_name.yellow(),
        pid,
        alert_threshold.cyan()
    );
    println!(
        "  Check interval: {}s | Press Ctrl+C to stop",
        interval_secs
    );
    println!();

    let interval = Duration::from_secs(interval_secs);
    let mut state = WatchState {
        last_rate: 0,
        in_alert: false,
        last_snapshot: None,
    };

    // Initial snapshot
    if let Ok(bytes) = get_process_bytes(pid) {
        state.last_snapshot = Some((Instant::now(), bytes));
    }

    loop {
        thread::sleep(interval);

        match check_bandwidth(pid, &mut state) {
            Ok(Some(rate)) if rate > threshold_bps && !state.in_alert => {
                state.in_alert = true;
                let msg = format!(
                    "{} rate exceeded: {}/s (threshold: {}/s)",
                    process_name,
                    format_bytes(rate),
                    alert_threshold
                );

                println!(
                    "[{}] {} {}",
                    chrono_now().dimmed(),
                    "⚠ ALERT:".red().bold(),
                    msg
                );

                // Send notification
                if let Err(e) = send_notification(&process_name, &msg, notify_cmd) {
                    eprintln!("  {} Failed to send notification: {}", "→".yellow(), e);
                }
            }
            Ok(Some(rate)) if rate <= threshold_bps && state.in_alert => {
                // Bandwidth back below threshold
                state.in_alert = false;
                println!(
                    "[{}] {} Rate back to normal: {}/s",
                    chrono_now().dimmed(),
                    "✓".green(),
                    format_bytes(rate)
                );
            }
            Ok(Some(rate)) => {
                // Normal monitoring output (optional, can be verbose)
                if rate > 0 {
                    println!(
                        "[{}] {} {} - {}/s",
                        chrono_now().dimmed(),
                        "●".cyan(),
                        process_name,
                        format_bytes(rate)
                    );
                }
            }
            Ok(None) => {
                // Process not found or no data
            }
            Err(e) => {
                eprintln!("{} Check failed: {}", "WARNING".yellow(), e);
            }
        }
    }
}

/// Check current bandwidth for a process.
fn check_bandwidth(pid: u32, state: &mut WatchState) -> Result<Option<u64>> {
    let bytes = get_process_bytes(pid)?;
    let now = Instant::now();

    let rate = if let Some((prev_time, prev_bytes)) = state.last_snapshot {
        let elapsed = prev_time.elapsed().as_secs_f64().max(0.001);
        let delta = bytes.saturating_sub(prev_bytes);
        (delta as f64 / elapsed) as u64
    } else {
        0
    };

    state.last_rate = rate;
    state.last_snapshot = Some((now, bytes));

    Ok(Some(rate))
}

/// Get total bytes transferred by a process.
fn get_process_bytes(pid: u32) -> Result<u64> {
    let entries = collect_bandwidth_stats()?;
    let processes = aggregate_by_process(&entries);

    let proc = processes
        .iter()
        .find(|p| p.pid == pid)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("process {} not found", pid))?;

    // Total bytes = RX + TX
    Ok(proc.total_received + proc.total_sent)
}

/// Send desktop notification or stderr fallback.
fn send_notification(process: &str, message: &str, custom_cmd: Option<&str>) -> Result<()> {
    let summary = format!("oxy: {} alert", process);

    // Try custom command first
    if let Some(cmd) = custom_cmd {
        let _ = Command::new(cmd)
            .args([process, message])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return Ok(());
    }

    // Try notify-send
    let result = Command::new("notify-send")
        .args(["--urgency=normal", &summary, message])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if let Ok(status) = result {
        if status.success() {
            return Ok(());
        }
    }

    // Fallback: just print to stderr (already done by caller)
    eprintln!(
        "  {} (notification not sent - no notify-send)",
        message.dimmed()
    );

    Ok(())
}

/// Format bytes for display.
fn format_bytes(bytes: u64) -> String {
    crate::units::format_bytes(bytes)
}

/// Generate timestamp string.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let datetime = chrono::DateTime::<chrono::Local>::from(now);
    datetime.format("%H:%M:%S").to_string()
}
