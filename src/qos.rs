// SPDX-License-Identifier: MIT
/// Quality of Service (QoS) priority-based bandwidth shaping module.
///
/// Instead of hard bandwidth limits, assigns processes to priority tiers.
/// High priority processes get bandwidth first; idle bandwidth from
/// low-priority processes redistributes to high-priority ones automatically.
///
/// Uses HTB (Hierarchical Token Bucket) with priority bands:
/// - Priority 0: High (gets tokens first)
/// - Priority 7: Low (gets leftover tokens)
use anyhow::{bail, Context, Result};
use colored::Color;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::limiter::{
    check_root, get_default_interface, next_class_id, resolve_pids, setup_cgroup,
    validate_interface,
};

/// QoS state file.
const QOS_STATE_FILE: &str = "/run/oxy/qos_state.json";

/// Priority tier for a process.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PriorityTier {
    /// High priority - gets bandwidth first
    High,
    /// Low priority - gets leftover bandwidth
    Low,
}

impl PriorityTier {
    /// Get the HTB priority number (0 = highest, 7 = lowest).
    fn htb_priority(&self) -> u8 {
        match self {
            PriorityTier::High => 0,
            PriorityTier::Low => 7,
        }
    }

    /// Get human-readable name.
    fn name(&self) -> &'static str {
        match self {
            PriorityTier::High => "high",
            PriorityTier::Low => "low",
        }
    }
}

/// A QoS assignment for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosAssignment {
    /// Process name
    pub target: String,
    /// Process PID when assigned
    pub pid: u32,
    /// Priority tier
    pub priority: PriorityTier,
    /// HTB class ID
    pub class_id: u32,
    /// When assigned
    pub assigned_at: String,
}

/// QoS state database.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QosState {
    /// Active QoS assignments
    pub assignments: Vec<QosAssignment>,
}

impl QosState {
    /// Load QoS state from disk.
    pub fn load() -> Result<Self> {
        let path = Path::new(QOS_STATE_FILE);

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read QoS state from {}", QOS_STATE_FILE))?;

        let state: QosState =
            serde_json::from_str(&content).with_context(|| "failed to parse QoS state")?;

        Ok(state)
    }

    /// Save QoS state to disk.
    pub fn save(&self) -> Result<()> {
        // Ensure directory exists
        if let Some(dir) = Path::new(QOS_STATE_FILE).parent() {
            fs::create_dir_all(dir)?;
        }

        let json = serde_json::to_string_pretty(self).context("failed to serialize QoS state")?;

        fs::write(QOS_STATE_FILE, json)
            .with_context(|| format!("failed to write QoS state to {}", QOS_STATE_FILE))?;

        Ok(())
    }
}

/// Set QoS priority for a process.
pub fn set_priority(
    target: &str,
    priority: PriorityTier,
    iface_override: Option<&str>,
) -> Result<()> {
    check_root()?;

    let interface = match iface_override {
        Some(i) => {
            validate_interface(i)?;
            i.to_string()
        }
        None => get_default_interface()?,
    };

    // Resolve target to PID(s)
    let pids = resolve_pids(target)?;

    if pids.is_empty() {
        bail!("no process found matching '{}'", target);
    }

    let mut state = QosState::load()?;

    for pid in pids {
        // Get or create class ID
        let class_id = next_class_id()?;

        // Set up cgroup
        let _ = setup_cgroup(pid, class_id)?;

        // Create HTB class with priority
        // High priority = class with low priority number (0)
        // Low priority = class with high priority number (7)
        let class_id_str = format!("1:{:04x}", class_id);
        let prio = priority.htb_priority();

        // Create HTB class with very high rate limit but specific priority
        // The priority determines who gets tokens first
        let output = Command::new("tc")
            .args([
                "class",
                "add",
                "dev",
                &interface,
                "parent",
                "1:",
                "classid",
                &class_id_str,
                "htb",
                "rate",
                "1000mbit", // Very high ceiling
                "ceil",
                "1000mbit",
                "prio",
                &prio.to_string(),
            ])
            .output();

        if let Err(e) = output {
            eprintln!("{}: Failed to create QoS class: {}", "WARNING".yellow(), e);
            continue;
        }

        // Add cgroup filter
        let _ = Command::new("tc")
            .args([
                "filter",
                "add",
                "dev",
                &interface,
                "protocol",
                "ip",
                "parent",
                "1:0",
                "prio",
                "1",
                "handle",
                &format!("1{:04x}::1", class_id),
                "cgroup",
            ])
            .output();

        // Record assignment
        let assignment = QosAssignment {
            target: target.to_string(),
            pid,
            priority,
            class_id,
            assigned_at: chrono_now(),
        };

        // Remove any existing assignment for this target
        state.assignments.retain(|a| a.target != target);
        state.assignments.push(assignment);

        println!(
            "{} Set {} priority for {} (PID: {}) - class {} (prio {})",
            "✓".green(),
            priority.name().cyan(),
            target.yellow(),
            pid,
            class_id_str,
            prio
        );
    }

    state.save()?;

    Ok(())
}

/// Show current QoS status.
pub fn show_qos_status() -> Result<()> {
    check_root()?;

    let state = QosState::load()?;

    if state.assignments.is_empty() {
        println!("{} No active QoS assignments.", "Info:".yellow());
        println!();
        println!("  Use 'oxy qos high <process>' to prioritize a process");
        println!("  Use 'oxy qos low <process>' to deprioritize a process");
        return Ok(());
    }

    println!("{}", "Active QoS Assignments".green().bold());
    println!();
    println!(
        "  {:<15} {:<8} {:<10} {:<12} {}",
        "Target".bold(),
        "PID".bold(),
        "Priority".bold(),
        "Class".bold(),
        "Assigned".dimmed()
    );
    println!("  {}", "─".repeat(70).dimmed());

    for assignment in &state.assignments {
        let prio_color = match assignment.priority {
            PriorityTier::High => Color::Green,
            PriorityTier::Low => Color::Yellow,
        };

        println!(
            "  {:<15} {:<8} {:<10} {:<12} {}",
            assignment.target.cyan(),
            assignment.pid,
            assignment.priority.name().color(prio_color),
            format!("1:{:04x}", assignment.class_id),
            assignment.assigned_at.dimmed()
        );
    }

    println!();
    println!(
        "  {} High priority gets bandwidth first; low gets leftovers",
        "Tip:".cyan()
    );

    Ok(())
}

/// Reset all QoS rules.
pub fn reset_qos(iface_override: Option<&str>) -> Result<()> {
    check_root()?;

    let interface = match iface_override {
        Some(i) => {
            validate_interface(i)?;
            i.to_string()
        }
        None => get_default_interface()?,
    };
    let state = QosState::load()?;

    if state.assignments.is_empty() {
        println!("{} No QoS rules to reset.", "Info:".yellow());
        return Ok(());
    }

    println!(
        "{} Resetting {} QoS assignment(s)...",
        "→".cyan(),
        state.assignments.len()
    );
    println!();

    for assignment in &state.assignments {
        let class_id_str = format!("1:{:04x}", assignment.class_id);

        // Remove tc class
        let _ = Command::new("tc")
            .args(["class", "del", "dev", &interface, "classid", &class_id_str])
            .output();

        // Remove cgroup
        let _ = crate::limiter::remove_cgroup(assignment.pid);

        println!(
            "  {} Removed {} priority for {} (PID: {})",
            "✓".green(),
            assignment.priority.name(),
            assignment.target.yellow(),
            assignment.pid
        );
    }

    // Clear state
    let new_state = QosState::default();
    new_state.save()?;

    println!();
    println!("{}", "oxy qos: all rules reset".green().bold());

    Ok(())
}

/// Generate a human-readable timestamp string.
fn chrono_now() -> String {
    use std::time::SystemTime;

    let now = SystemTime::now();
    let datetime = chrono::DateTime::<chrono::Local>::from(now);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}
