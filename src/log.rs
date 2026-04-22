// SPDX-License-Identifier: MIT
/// Historical bandwidth logging module.
///
/// Persists bandwidth snapshots over time for trend analysis.
/// Stores data in ~/.local/share/oxy/history/ with rotation.
use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::monitor::{aggregate_by_process, collect_bandwidth_stats, ProcessBandwidth};

/// Directory for history files.
const HISTORY_DIR: &str = "/run/oxy/history";
/// Maximum number of snapshot files to keep (rotation).
const MAX_HISTORY_FILES: usize = 100;

/// A single bandwidth snapshot at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthSnapshot {
    /// Timestamp when the snapshot was taken
    pub timestamp: DateTime<Utc>,
    /// Process bandwidth data at this snapshot
    pub processes: Vec<ProcessBandwidth>,
    /// Total system bytes sent at snapshot time
    pub total_sent: u64,
    /// Total system bytes received at snapshot time
    pub total_received: u64,
}

impl BandwidthSnapshot {
    /// Create a new snapshot from current bandwidth data.
    pub fn capture() -> Result<Self> {
        let entries = collect_bandwidth_stats()?;
        let processes = aggregate_by_process(&entries);

        let total_sent: u64 = processes.iter().map(|p| p.total_sent).sum();
        let total_received: u64 = processes.iter().map(|p| p.total_received).sum();

        Ok(Self {
            timestamp: Utc::now(),
            processes,
            total_sent,
            total_received,
        })
    }
}

/// Save a snapshot to the history directory.
pub fn save_snapshot() -> Result<()> {
    // Ensure history directory exists
    fs::create_dir_all(HISTORY_DIR).context("failed to create history directory")?;

    // Capture current snapshot
    let snapshot = BandwidthSnapshot::capture()?;

    // Generate filename with timestamp
    let local_time: DateTime<Local> = snapshot.timestamp.into();
    let filename = format!(
        "{}/snapshot_{}.json",
        HISTORY_DIR,
        local_time.format("%Y%m%d_%H%M%S")
    );

    // Serialize and save
    let json = serde_json::to_string_pretty(&snapshot).context("failed to serialize snapshot")?;
    fs::write(&filename, json)
        .with_context(|| format!("failed to write snapshot to {}", filename))?;

    println!("{} Bandwidth snapshot saved: {}", "✓".green(), filename);

    // Rotate old snapshots
    rotate_history()?;

    Ok(())
}

/// Load all snapshots from history directory.
pub fn load_snapshots(hours: Option<u64>) -> Result<Vec<BandwidthSnapshot>> {
    let history_path = Path::new(HISTORY_DIR);

    if !history_path.exists() {
        return Ok(Vec::new());
    }

    let cutoff_time = hours.map(|h| Utc::now() - chrono::Duration::hours(h as i64));

    let mut snapshots: Vec<BandwidthSnapshot> = fs::read_dir(history_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|n| n.starts_with("snapshot_") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .filter_map(|entry| {
            fs::read_to_string(entry.path())
                .ok()
                .and_then(|content| serde_json::from_str::<BandwidthSnapshot>(&content).ok())
        })
        .filter(|snap| {
            // Filter by time window if specified
            cutoff_time
                .map(|cutoff| snap.timestamp >= cutoff)
                .unwrap_or(true)
        })
        .collect();

    // Sort by timestamp (oldest first)
    snapshots.sort_by_key(|a| a.timestamp);

    Ok(snapshots)
}

/// Display bandwidth history.
pub fn show_history(hours: Option<u64>, json_output: bool) -> Result<()> {
    let snapshots = load_snapshots(hours)?;

    if snapshots.is_empty() {
        println!("{} No bandwidth history found.", "Info:".yellow());
        println!("  Run 'oxy log --snapshot' to record current state.");
        return Ok(());
    }

    if json_output {
        // JSON output for scripting/analysis
        let json =
            serde_json::to_string_pretty(&snapshots).context("failed to serialize history")?;
        println!("{}", json);
        return Ok(());
    }

    // Human-readable output
    let time_range = hours.map(|h| format!(" (last {}h)", h)).unwrap_or_default();
    println!("{}{}", "Bandwidth History".green().bold(), time_range);
    println!();

    // Summary statistics
    if snapshots.len() >= 2 {
        let first = &snapshots[0];
        let last = &snapshots[snapshots.len() - 1];

        let duration = last.timestamp.signed_duration_since(first.timestamp);
        let hours = duration.num_hours();
        let minutes = duration.num_minutes() % 60;

        println!("  Snapshots:  {}", snapshots.len());
        println!("  Duration:   {}h {}m", hours, minutes);
        println!();

        // Calculate deltas
        let rx_delta = last.total_received.saturating_sub(first.total_received);
        let tx_delta = last.total_sent.saturating_sub(first.total_sent);

        println!(
            "  Total RX:   {} ({})",
            crate::units::format_bytes(last.total_received),
            crate::units::format_bytes(rx_delta)
        );
        println!(
            "  Total TX:   {} ({})",
            crate::units::format_bytes(last.total_sent),
            crate::units::format_bytes(tx_delta)
        );
        println!();
    }

    // Per-process summary (average over all snapshots)
    let mut process_totals: HashMap<u32, (String, u64, u64, usize)> = HashMap::new();

    for snap in &snapshots {
        for proc in &snap.processes {
            let entry = process_totals
                .entry(proc.pid)
                .or_insert((proc.name.clone(), 0, 0, 0));
            entry.1 += proc.total_sent;
            entry.2 += proc.total_received;
            entry.3 += 1;
        }
    }

    if !process_totals.is_empty() {
        println!("  Per-Process Average:");
        println!();

        // Sort by total traffic (sent + received)
        let mut sorted: Vec<_> = process_totals.iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1 .1 + b.1 .2));

        for (pid, (name, sent, recv, count)) in sorted.iter().take(10) {
            let _avg_sent = *sent / *count as u64;
            let _avg_recv = *recv / *count as u64;

            println!(
                "    {:<8} {:<20} Avg: RX {} / TX {}",
                pid,
                name,
                crate::units::format_bytes(_avg_recv),
                crate::units::format_bytes(_avg_sent)
            );
        }
    }

    println!();
    println!("  {} Use --json for detailed analysis", "Tip:".cyan());

    Ok(())
}

/// Rotate old history files, keeping only the most recent MAX_HISTORY_FILES.
fn rotate_history() -> Result<()> {
    let history_path = Path::new(HISTORY_DIR);

    if !history_path.exists() {
        return Ok(());
    }

    let mut files: Vec<_> = fs::read_dir(history_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|n| n.starts_with("snapshot_") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();

    // Sort by modification time (newest first)
    files.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    // Remove old files beyond the limit
    if files.len() > MAX_HISTORY_FILES {
        for old_file in &files[MAX_HISTORY_FILES..] {
            let _ = fs::remove_file(old_file.path());
        }
    }

    Ok(())
}
