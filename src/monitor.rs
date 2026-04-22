// SPDX-License-Identifier: MIT
/// Network bandwidth monitoring module.
///
/// This module monitors per-process network bandwidth usage by combining
/// data from the Linux `ss` utility with `/proc` filesystem scanning.
///
/// The approach:
/// 1. Run `ss -tuneiH` to get socket addresses, inodes, and TCP byte stats
/// 2. Group multi-line entries (TCP info appears on continuation lines)
/// 3. Resolve socket inodes to owning processes via `/proc/<pid>/fd/`
/// 4. Aggregate bandwidth statistics per process
use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::units::format_bytes;

/// Represents a single network socket connection observed on the system.
#[derive(Debug, Clone)]
pub struct SocketEntry {
    /// Protocol type (TCP, UDP, TCPv6, UDPv6)
    #[allow(dead_code)]
    pub protocol: String,
    /// Connection state (ESTAB, TIME-WAIT, LISTEN, UNCONN, etc.)
    #[allow(dead_code)]
    pub state: String,
    /// Local address and port (e.g., "192.168.1.100:52341")
    #[allow(dead_code)]
    pub local_addr: String,
    /// Remote address and port (e.g., "93.184.216.34:443")
    #[allow(dead_code)]
    pub remote_addr: String,
    /// Owning process name (e.g., "firefox")
    pub process_name: String,
    /// Owning process ID
    pub pid: u32,
    /// Cumulative bytes sent on this socket
    pub bytes_sent: u64,
    /// Cumulative bytes received on this socket
    pub bytes_received: u64,
}

/// Aggregated bandwidth statistics for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBandwidth {
    /// Process ID (primary)
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Number of active network connections
    pub connection_count: u32,
    /// Total bytes sent across all sockets
    pub total_sent: u64,
    /// Total bytes received across all sockets
    pub total_received: u64,
    /// Sum of sent + received
    pub total_bytes: u64,
    /// Individual socket entries
    #[allow(dead_code)]
    #[serde(skip)]
    pub sockets: Vec<SocketEntry>,
}

/// Cache of inode -> (pid, process_name) mappings built from /proc scanning.
type InodeCache = HashMap<u64, (u32, String)>;

/// Build a cache mapping socket inodes to their owning (pid, process_name).
///
/// Scans /proc/<pid>/fd/ for every accessible process and reads each symlink.
/// If a symlink target is `socket:[<inode>]`, the inode is mapped to that PID.
fn build_inode_cache() -> InodeCache {
    let mut cache = HashMap::new();
    let proc_dir = Path::new("/proc");

    let entries = match std::fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(_) => return cache,
    };

    for entry in entries.flatten() {
        let dir_name = entry.file_name();
        let name_str = dir_name.to_string_lossy();

        // Only consider numeric directories (PIDs)
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{}/fd", pid);
        let fd_entries = match std::fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut process_name = String::new();

        for fd_entry in fd_entries.flatten() {
            let link_target = match std::fs::read_link(fd_entry.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let link_str = link_target.to_string_lossy();

            // Check if this fd is a socket: socket:[<inode>]
            if let Some(inode_str) = link_str.strip_prefix("socket:[") {
                let inode_str = inode_str.strip_suffix(']').unwrap_or(inode_str);
                if let Ok(inode) = inode_str.parse::<u64>() {
                    // Lazily read process name on first match
                    if process_name.is_empty() {
                        process_name = crate::limiter::get_process_name(pid);
                    }
                    cache.insert(inode, (pid, process_name.clone()));
                }
            }
        }
    }

    cache
}

/// Run the `ss` command and parse its output to discover active sockets
/// and their bandwidth statistics.
///
/// Uses `ss -tuneiH` which provides:
/// - `-t` TCP sockets
/// - `-u` UDP sockets
/// - `-n` Numeric addresses (no DNS resolution)
/// - `-e` Extended info (uid, inode)
/// - `-i` TCP internal info (bytes_sent, bytes_received on continuation lines)
/// - `-H` Suppress header line
///
/// Note: We intentionally do NOT use `-p` here because:
/// 1. It requires elevated privileges and may not show info for all processes
/// 2. The output format varies between iproute2 versions
/// 3. We resolve process ownership ourselves via /proc inode matching
pub fn collect_bandwidth_stats() -> Result<Vec<SocketEntry>> {
    let output = Command::new("ss")
        .args(["-tuneiH"])
        .output()
        .context("failed to execute 'ss' command. Is iproute2 installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ss command failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Build inode -> process mapping from /proc
    let inode_cache = build_inode_cache();

    parse_ss_output(&stdout, &inode_cache)
}

/// Parse the raw `ss -tuneiH` output into structured SocketEntry records.
///
/// Handles multi-line output where TCP info (bytes_sent, bytes_received)
/// appears on a continuation line starting with whitespace.
fn parse_ss_output(output: &str, inode_cache: &InodeCache) -> Result<Vec<SocketEntry>> {
    let mut entries = Vec::new();
    let mut current_line = String::new();

    for raw_line in output.lines() {
        // Continuation lines start with whitespace (TCP info)
        if raw_line.starts_with(char::is_whitespace) && !current_line.is_empty() {
            // Append continuation data to current entry
            current_line.push(' ');
            current_line.push_str(raw_line.trim());
        } else {
            // Process the previous accumulated line
            if !current_line.is_empty() {
                if let Some(entry) = parse_ss_entry(&current_line, inode_cache) {
                    entries.push(entry);
                }
            }
            current_line = raw_line.to_string();
        }
    }

    // Process the last accumulated line
    if !current_line.is_empty() {
        if let Some(entry) = parse_ss_entry(&current_line, inode_cache) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Parse a single logical ss entry (main line + any continuation data).
///
/// Main line format:
///   tcp ESTAB 0 0 192.168.1.2:22 192.168.1.1:54321 ino:12345 sk:1 ...
///
/// Continuation data (TCP info) may contain:
///   bytes_sent:N bytes_received:N ...
fn parse_ss_entry(line: &str, inode_cache: &InodeCache) -> Option<SocketEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 6 {
        return None;
    }

    // Determine protocol from netid field (parts[0])
    let netid = parts[0];
    let protocol = match netid {
        "tcp" => "TCP",
        "tcp6" => "TCPv6",
        "udp" => "UDP",
        "udp6" => "UDPv6",
        "raw" => "RAW",
        _ => netid,
    };

    // Detect column layout: parts[1] is either a state (alphabetic) or recv-q (numeric)
    let (state, addr_start) = if parts[1].chars().all(|c| c.is_ascii_digit()) {
        // UDP-style: recv-q at [1], send-q at [2], addresses at [3] and [4]
        ("UNCONN".to_string(), 3)
    } else {
        // TCP-style: state at [1], recv-q at [2], send-q at [3], addresses at [4] and [5]
        (parts[1].to_string(), 4)
    };

    let local_addr = parts.get(addr_start).unwrap_or(&"*").to_string();
    let remote_addr = parts.get(addr_start + 1).unwrap_or(&"*").to_string();

    // Extract inode from the "remaining" fields (after addresses)
    let remaining_start = addr_start + 2;
    let remaining = if parts.len() > remaining_start {
        parts[remaining_start..].join(" ")
    } else {
        String::new()
    };

    // Extract socket inode from "ino:NNNNN"
    let inode = extract_inode(&remaining);

    // Resolve process from inode cache
    let (process_name, pid) = if let Some(&(pid, ref name)) = inode_cache.get(&inode) {
        (name.clone(), pid)
    } else {
        // Try extracting process info from ss "users:((" pattern" as fallback
        let (name, p) = extract_process_info_from_ss(&remaining);
        (name, p)
    };

    // Parse bytes_sent and bytes_received from TCP info section
    let (bytes_sent, bytes_received) = extract_bytes_info(&remaining);

    Some(SocketEntry {
        protocol: protocol.to_string(),
        state,
        local_addr,
        remote_addr,
        process_name,
        pid,
        bytes_sent,
        bytes_received,
    })
}

/// Extract socket inode number from the "ino:NNNNN" field in ss output.
fn extract_inode(text: &str) -> u64 {
    for part in text.split_whitespace() {
        if let Some(ino_str) = part.strip_prefix("ino:") {
            if let Ok(ino) = ino_str.parse::<u64>() {
                return ino;
            }
        }
    }
    0
}

/// Fallback: extract process name and PID from ss `users:(("name",pid=N))` pattern.
///
/// This is only used when /proc inode resolution fails (e.g., insufficient permissions).
fn extract_process_info_from_ss(text: &str) -> (String, u32) {
    if let Some(start) = text.find("users:(") {
        let inner = &text[start..];

        // Extract PID
        let pid = extract_pid_from_pattern(inner);

        // Extract process name - handle both "name" and 'name' quoting styles
        let name = if let Some(name_start) = inner.find('"') {
            if let Some(name_end) = inner[name_start + 1..].find('"') {
                inner[name_start + 1..name_start + 1 + name_end].to_string()
            } else {
                String::new()
            }
        } else if let Some(name_start) = inner.find('\'') {
            if let Some(name_end) = inner[name_start + 1..].find('\'') {
                inner[name_start + 1..name_start + 1 + name_end].to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        (name, pid)
    } else {
        // Try to find pid= pattern directly
        let pid = extract_pid_from_pattern(text);
        (String::new(), pid)
    }
}

/// Extract PID from a "pid=N" pattern in text.
fn extract_pid_from_pattern(text: &str) -> u32 {
    if let Some(pos) = text.find("pid=") {
        let after = &text[pos + 4..];
        let end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        after[..end].parse::<u32>().unwrap_or(0)
    } else {
        0
    }
}

/// Extract bytes_sent and bytes_received from the TCP info section.
///
/// Looks for patterns like `bytes_sent:12345` and `bytes_received:67890`
/// anywhere in the text (main line or continuation line).
fn extract_bytes_info(text: &str) -> (u64, u64) {
    let mut sent = 0u64;
    let mut received = 0u64;

    // Look for bytes_sent:N
    if let Some(pos) = text.find("bytes_sent:") {
        let after = &text[pos + 11..];
        let end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        if let Ok(val) = after[..end].parse::<u64>() {
            sent = val;
        }
    }

    // Look for bytes_received:N
    if let Some(pos) = text.find("bytes_received:") {
        let after = &text[pos + 15..];
        let end = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        if let Ok(val) = after[..end].parse::<u64>() {
            received = val;
        }
    }

    (sent, received)
}

/// Aggregate socket entries by process (PID + name).
///
/// Groups all sockets belonging to the same process and sums their
/// bandwidth statistics. Connections without a known process are
/// grouped under a "[system]" label.
pub fn aggregate_by_process(entries: &[SocketEntry]) -> Vec<ProcessBandwidth> {
    let mut process_map: HashMap<String, ProcessBandwidth> = HashMap::new();

    for entry in entries {
        let key = if entry.pid > 0 && !entry.process_name.is_empty() {
            format!("{}:{}", entry.pid, entry.process_name)
        } else {
            "system:kernel".to_string()
        };

        let proc_bw = process_map.entry(key).or_insert_with(|| ProcessBandwidth {
            pid: entry.pid,
            name: if entry.process_name.is_empty() {
                "[system]".to_string()
            } else {
                entry.process_name.clone()
            },
            connection_count: 0,
            total_sent: 0,
            total_received: 0,
            total_bytes: 0,
            sockets: Vec::new(),
        });

        proc_bw.total_sent += entry.bytes_sent;
        proc_bw.total_received += entry.bytes_received;
        proc_bw.total_bytes += entry.bytes_sent + entry.bytes_received;
        proc_bw.connection_count += 1;
        proc_bw.sockets.push(entry.clone());
    }

    let mut result: Vec<ProcessBandwidth> = process_map.into_values().collect();

    // Sort by total bytes descending
    result.sort_by_key(|b| std::cmp::Reverse(b.total_bytes));

    result
}

/// Display bandwidth usage for all processes in a formatted table.
///
/// Sorts by total bytes descending (same as `--high-to-low-usage-net` since
/// `aggregate_by_process()` already sorts this way).
pub fn display_usage_all() -> Result<()> {
    let entries = collect_bandwidth_stats()?;

    if entries.is_empty() {
        println!("{}", "No active network connections found.".yellow());
        return Ok(());
    }

    let processes = aggregate_by_process(&entries);
    print_process_table(&processes);

    Ok(())
}

/// Display bandwidth usage sorted from highest to lowest usage.
///
/// Delegates to `display_usage_all()` since `aggregate_by_process()` already
/// returns processes sorted by total bytes descending.
pub fn display_usage_high_to_low() -> Result<()> {
    display_usage_all()
}

/// Print a formatted table of process bandwidth statistics.
fn print_process_table(processes: &[ProcessBandwidth]) {
    let header_pid = "PID";
    let header_name = "PROCESS";
    let header_conns = "CONN";
    let header_download = "DOWNLOAD (RX)";
    let header_upload = "UPLOAD (TX)";
    let header_total = "TOTAL";

    let col_pid = 8;
    let col_name = 28;
    let col_conns = 6;
    let col_download = 18;
    let col_upload = 18;
    let col_total = 18;

    // Header
    println!(
        "{:<col_pid$} {:<col_name$} {:>col_conns$} {:>col_download$} {:>col_upload$} {:>col_total$}",
        header_pid,
        header_name,
        header_conns,
        header_download,
        header_upload,
        header_total,
        col_pid = col_pid,
        col_name = col_name,
        col_conns = col_conns,
        col_download = col_download,
        col_upload = col_upload,
        col_total = col_total,
    );

    // Separator
    let separator = format!(
        "{:-<col_pid$} {:-<col_name$} {:-^col_conns$} {:-^col_download$} {:-^col_upload$} {:-^col_total$}",
        "", "", "", "", "", "",
        col_pid = col_pid,
        col_name = col_name,
        col_conns = col_conns,
        col_download = col_download,
        col_upload = col_upload,
        col_total = col_total,
    );
    println!("{}", separator.dimmed());

    for proc in processes {
        let pid_str = if proc.pid > 0 {
            proc.pid.to_string()
        } else {
            "-".to_string()
        };

        let name = truncate_str(&proc.name, col_name - 2);

        // Color code based on usage intensity
        let (download_str, upload_str, total_str) = if proc.total_bytes > 100 * 1024 * 1024 {
            (
                format_bytes(proc.total_received).red().to_string(),
                format_bytes(proc.total_sent).red().to_string(),
                format_bytes(proc.total_bytes).red().bold().to_string(),
            )
        } else if proc.total_bytes > 10 * 1024 * 1024 {
            (
                format_bytes(proc.total_received).yellow().to_string(),
                format_bytes(proc.total_sent).yellow().to_string(),
                format_bytes(proc.total_bytes).yellow().bold().to_string(),
            )
        } else if proc.total_bytes > 0 {
            (
                format_bytes(proc.total_received).green().to_string(),
                format_bytes(proc.total_sent).green().to_string(),
                format_bytes(proc.total_bytes).green().bold().to_string(),
            )
        } else {
            (
                format_bytes(proc.total_received).dimmed().to_string(),
                format_bytes(proc.total_sent).dimmed().to_string(),
                format_bytes(proc.total_bytes).dimmed().to_string(),
            )
        };

        println!(
            "{:<col_pid$} {:<col_name$} {:>col_conns$} {:>col_download$} {:>col_upload$} {:>col_total$}",
            pid_str,
            name,
            proc.connection_count,
            download_str,
            upload_str,
            total_str,
            col_pid = col_pid,
            col_name = col_name,
            col_conns = col_conns,
            col_download = col_download,
            col_upload = col_upload,
            col_total = col_total,
        );
    }

    println!(
        "\n{}",
        "Note: Bandwidth values show cumulative bytes since socket creation.".dimmed()
    );
    println!(
        "{}",
        "For real-time rate monitoring, use oxy list --live.".dimmed()
    );
}

/// Truncate a string to fit within a maximum width, appending "..." if truncated.
///
/// Always pads the result to exactly `max_len` characters for column alignment.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:<width$}", s, width = max_len)
    } else if max_len > 3 {
        let truncated = &s[..max_len - 3];
        format!("{:<width$}", format!("{}...", truncated), width = max_len)
    } else {
        format!("{:<width$}", s, width = max_len)
    }
}

/// Output bandwidth usage as JSON for scripting integration.
pub fn display_usage_json() -> Result<()> {
    let entries = collect_bandwidth_stats()?;
    let processes = aggregate_by_process(&entries);

    // Serialize to JSON and print
    let json = serde_json::to_string_pretty(&processes)
        .context("failed to serialize bandwidth data to JSON")?;
    println!("{}", json);

    Ok(())
}

/// Live bandwidth monitoring with real-time rate display.
///
/// Enters alternate screen and continuously refreshes showing
/// per-process bandwidth rates (bytes/sec) calculated from delta
/// between samples.
pub fn display_usage_live(interval_secs: u64, iface_override: Option<&str>) -> Result<()> {
    // Use the new ratatui-based TUI
    crate::tui::run_live_tui(interval_secs, iface_override)
}

/// Display verbose bandwidth usage with per-connection breakdown.
///
/// Shows individual socket connections for each process including
/// remote IP, port, protocol (TCP/UDP), and bytes transferred.
pub fn display_usage_verbose() -> Result<()> {
    use colored::Colorize;

    let entries = collect_bandwidth_stats()?;
    let processes = aggregate_by_process(&entries);

    if processes.is_empty() {
        println!("{}", "No active network connections found.".dimmed());
        return Ok(());
    }

    println!("{}", "Network Bandwidth Usage (Verbose)".green().bold());
    println!(
        "  {} {}",
        "Generated:".dimmed(),
        chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
            .dimmed()
    );
    println!();

    for proc in &processes {
        // Print process header
        let rx_str = format_bytes(proc.total_received);
        let tx_str = format_bytes(proc.total_sent);
        let total_str = format_bytes(proc.total_received + proc.total_sent);

        println!(
            "{} {} (PID: {}) ─ RX: {} │ TX: {} │ Total: {}",
            "▶".cyan().bold(),
            proc.name.cyan().bold(),
            proc.pid,
            rx_str.green(),
            tx_str.yellow(),
            total_str.white().bold()
        );

        // Print individual connections
        if proc.sockets.is_empty() {
            println!("  {} No socket details available", "•".dimmed());
        } else {
            for socket in &proc.sockets {
                // Parse local and remote addresses
                let (local_ip, local_port) = parse_addr_port(&socket.local_addr);
                let (remote_ip, remote_port) = parse_addr_port(&socket.remote_addr);

                // Determine protocol from protocol field
                let protocol = if socket.protocol.contains("UDP") {
                    "UDP"
                } else {
                    "TCP"
                };

                let proto_color = match protocol {
                    "TCP" => "cyan",
                    "UDP" => "yellow",
                    _ => "white",
                };

                // Determine connection state
                let state_str = match socket.state.as_str() {
                    "ESTAB" | "ESTABLISHED" => "",
                    "LISTEN" => " [LISTEN]",
                    "TIME-WAIT" => " [TIME-WAIT]",
                    "CLOSE-WAIT" => " [CLOSE]",
                    s if s.contains("UDP") => "",
                    _ => &format!(" [{}]", socket.state),
                };

                println!(
                    "  {} {:<5} {}:{:<6} → {}:{:<6} │ RX: {} │ TX: {}{}",
                    "•".dimmed(),
                    protocol.color(proto_color),
                    local_ip.dimmed(),
                    local_port.dimmed(),
                    remote_ip,
                    remote_port,
                    format_bytes(socket.bytes_received).green(),
                    format_bytes(socket.bytes_sent).yellow(),
                    state_str.dimmed()
                );
            }
        }

        println!(); // Empty line between processes
    }

    Ok(())
}

/// Parse IP:port string into separate components.
///
/// Handles both IPv4 (`1.2.3.4:80`) and IPv6 bracket notation (`[::1]:443`).
/// Bare IPv6 addresses without a port are returned as-is with port "?".
fn parse_addr_port(addr: &str) -> (String, String) {
    // IPv6 bracket notation: [ip]:port
    if let Some(bracket_end) = addr.find(']') {
        if bracket_end + 1 < addr.len() && addr.as_bytes()[bracket_end + 1] == b':' {
            let ip = addr[1..bracket_end].to_string();
            let port = addr[bracket_end + 2..].to_string();
            return (ip, port);
        }
        // Bracket but no port: [::1]
        return (addr[1..bracket_end].to_string(), "?".to_string());
    }

    // IPv4: 1.2.3.4:80 — split on last colon
    if let Some(pos) = addr.rfind(':') {
        // Guard against bare IPv6 (contains multiple colons, no brackets)
        let colon_count = addr.chars().filter(|&c| c == ':').count();
        if colon_count == 1 {
            let (ip, port) = addr.split_at(pos);
            return (ip.to_string(), port[1..].to_string());
        }
    }

    // Fallback: no parseable port
    (addr.to_string(), "?".to_string())
}
