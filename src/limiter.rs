/// Bandwidth limiting module using Linux traffic control (tc) and cgroups.
///
/// Architecture:
///
/// **Upload (egress) limiting:**
///   Process → nftables output (meta skuid → mark) → tc fw filter → HTB class (rate-limited)
///   On cgroup v1/hybrid: also uses tc cgroup filter as fallback for existing connections.
///
/// **Download (ingress) limiting:**
///   NIC → IP stack → conntrack lookup → nftables inet PREROUTING (ct mark → meta mark →
///        limit rate over X burst Y drop)
///
/// IMPORTANT: nftables `limit rate` uses per-CPU token buckets. The effective
/// aggregate rate is `configured_rate × active_cpus`. We compensate by reading
/// the actual number of active network CPUs from `/proc/net/softnet_stat` (which
/// accounts for RPS even on single-queue NICs) and dividing the rate accordingly.
///
/// Without `socket cgroupv2` kernel support, per-process distinction is not possible
/// at the nftables level. Both egress marking and download rate limiting operate
/// per-UID: all PIDs sharing a UID get the same packet mark and share a single
/// rate limit (the minimum among all configured rates for that UID).
///
/// State is persisted to disk so that limits survive across invocations
/// and can be cleaned up properly with `oxy unstrict`.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::units::BandwidthRate;

/// Directory where oxy stores its runtime state.
const STATE_DIR: &str = "/run/oxy";
/// Path to the state file containing active bandwidth limits.
const STATE_FILE: &str = "/run/oxy/state.json";
/// Base path for oxy's cgroup management.
const CGROUP_BASE: &str = "/sys/fs/cgroup/oxy";

/// Detect cgroup version (v1, v2, or hybrid).
///
/// Returns (is_v2, is_hybrid) tuple.
fn detect_cgroup_version() -> (bool, bool) {
    // Check if cgroup2 filesystem is mounted at /sys/fs/cgroup
    let cgroup_mount = Command::new("mount").args(["-t", "cgroup2"]).output().ok();

    let _has_cgroup2 = cgroup_mount
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Check if cgroup v1 controllers are present
    let v1_controllers = Path::new("/sys/fs/cgroup/net_cls").exists()
        || Path::new("/sys/fs/cgroup/memory").exists()
        || Path::new("/sys/fs/cgroup/cpu").exists();

    // Check for hybrid mode - both v1 and v2 controllers exist
    let cgroup_controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    let has_v2_controllers = cgroup_controllers.exists();

    if has_v2_controllers && v1_controllers {
        // Hybrid mode: v2 unified hierarchy with v1 controllers
        (true, true)
    } else if has_v2_controllers && !v1_controllers {
        // Pure cgroup v2
        (true, false)
    } else {
        // cgroup v1 only
        (false, false)
    }
}

/// Ensure required kernel modules for traffic control are loaded.
fn ensure_kernel_modules() -> Result<()> {
    // List of modules required for tc bandwidth limiting
    let modules = [
        "sch_htb",      // HTB qdisc (for upload shaping)
        "cls_fw",       // fw classifier (fwmark-based routing)
        "sch_ingress",  // ingress qdisc (for download policing)
        "nf_conntrack", // conntrack (mark propagation for download on cgroup v1/hybrid)
    ];

    for module in modules {
        // Use modprobe to load modules. Ignore errors; they may be built-in.
        let _ = Command::new("modprobe").arg(module).output();
    }

    Ok(())
}

/// Ensure netfilter conntrack is enabled for mark propagation.
///
/// Required for download limiting: egress marks are saved to conntrack and
/// restored for reply packets at PREROUTING, where nftables applies rate limits.
fn ensure_conntrack() -> Result<()> {
    let _ = Command::new("modprobe").args(["nf_conntrack"]).output();

    let params = [
        ("net.netfilter.nf_conntrack_acct", "1"),
        ("net.netfilter.nf_conntrack_mark", "1"),
    ];

    for (key, val) in params {
        let _ = Command::new("sysctl")
            .args(["-w", &format!("{}={}", key, val)])
            .output();
    }

    Ok(())
}

/// Get the UID of a process.
///
/// Used with nftables `meta skuid` to match egress packets from specific users.
fn get_process_uid(pid: u32) -> Option<u32> {
    let uid_path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(&uid_path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return parts[1].parse::<u32>().ok();
                }
            }
        }
    }
    None
}

/// Estimate the number of CPUs that handle network receive traffic.
///
/// nftables `limit rate` uses per-CPU token buckets, so the effective
/// aggregate rate is `configured_rate × active_cpus`. Reading the number
/// of hardware rx queues from sysfs is insufficient because RPS (Receive
/// Packet Steering) can distribute softirq processing across more CPUs
/// than the number of rx queues (e.g., a Wi-Fi adapter with 1 rx queue
/// may have packets processed by 2+ CPUs).
///
/// Instead, we read `/proc/net/softnet_stat` which shows per-CPU network
/// processing counters. Any CPU with a non-zero packet counter is considered
/// active for network processing.
fn get_active_net_cpus() -> usize {
    if let Ok(content) = fs::read_to_string("/proc/net/softnet_stat") {
        let count = content
            .lines()
            .filter(|line| {
                // Each line has space-separated hex values.
                // The first field is the total received packet count;
                // a non-zero value indicates this CPU has processed packets.
                line.split_whitespace()
                    .next()
                    .and_then(|v| u64::from_str_radix(v, 16).ok())
                    .map(|v| v > 0)
                    .unwrap_or(false)
            })
            .count();
        if count > 0 {
            return count.max(1);
        }
    }
    // Fallback: use available parallelism with a minimum of 2
    // (even single-queue NICs often have RPS distributing to 2+ CPUs)
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .max(2)
}

// ---------------------------------------------------------------------------
// nftables rules management
// ---------------------------------------------------------------------------

/// Build the nftables `inet oxy` table for egress marking + download rate limiting.
///
/// Uses `inet` (IPv4 + IPv6) so both protocol families are handled.
///
/// Output chain: marks egress packets by UID (deduplicated — one rule per UID).
/// Postrouting: saves mark to conntrack for reply (download) packets.
/// Prerouting: restores mark from conntrack for incoming packets, then applies
///             per-UID download rate limits via `limit rate over X burst Y drop`.
///
/// Note: nftables `limit rate` uses per-CPU token buckets. The effective rate
/// is approximately `configured_rate × active_cpus`. We compensate by dividing
/// the configured rate by the number of active network CPUs, read from
/// `/proc/net/softnet_stat`. We also set an explicit `burst 1 kbytes` to
/// minimize initial burst overage.
fn build_nft_ip_ruleset(limits: &[LimitRecord]) -> String {
    let mut ruleset = String::new();
    ruleset.push_str("table inet oxy {\n");

    // Output: mark egress packets by UID (deduplicated).
    // When multiple PIDs share the same UID, nftables cannot distinguish them
    // via `meta skuid` alone — all matching rules fire and the last mark wins.
    // We deduplicate by UID and use the UID itself as the mark value so that
    // every packet from the same UID gets a consistent mark for conntrack.
    ruleset.push_str("  chain output {\n");
    ruleset.push_str("    type filter hook output priority mangle; policy accept;\n");

    let mut seen_uids = std::collections::HashSet::new();
    for record in limits {
        if let Some(uid) = get_process_uid(record.pid) {
            if seen_uids.insert(uid) {
                ruleset.push_str(&format!(
                    "    meta skuid {} meta mark set 0x{:08x};\n",
                    uid, uid
                ));
            }
        }
    }
    ruleset.push_str("  }\n");

    // Postrouting: save mark into conntrack for reply packets
    ruleset.push_str("  chain postrouting {\n");
    ruleset.push_str("    type filter hook postrouting priority srcnat; policy accept;\n");
    ruleset.push_str("    meta mark != 0 ct mark set meta mark;\n");
    ruleset.push_str("  }\n");

    // Prerouting: restore mark from conntrack, then apply download rate limits.
    // Rate limit is per-UID using the minimum rate among all PIDs with that
    // UID (conservative: ensures no process exceeds its requested limit).
    ruleset.push_str("  chain prerouting {\n");
    ruleset.push_str("    type filter hook prerouting priority dstnat; policy accept;\n");
    ruleset.push_str("    ct mark != 0 meta mark set ct mark;\n");

    // Compute minimum download rate per UID (in kbytes/second for nftables).
    // nftables 'limit rate over' expects bytes, kbytes, or mbytes — not kbit.
    //
    // IMPORTANT: nftables `limit rate` maintains per-CPU token buckets, so the
    // effective aggregate rate is `rate × active_cpus`. We compensate by
    // dividing the rate by the number of active network CPUs (estimated from
    // /proc/net/softnet_stat, which reflects actual softirq distribution
    // including RPS).
    let num_cpus = get_active_net_cpus();

    let mut uid_min_dl: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    for record in limits.iter().filter(|l| l.download_bytes_per_sec.is_some()) {
        if let Some(uid) = get_process_uid(record.pid) {
            let dl_kbytes = (record.download_bytes_per_sec.unwrap() / 1024).max(1);
            let compensated = (dl_kbytes / num_cpus as u64).max(1);
            uid_min_dl
                .entry(uid)
                .and_modify(|min| *min = (*min).min(compensated))
                .or_insert(compensated);
        }
    }

    for (uid, rate_kbytes) in &uid_min_dl {
        ruleset.push_str(&format!(
            "    meta mark 0x{:08x} limit rate over {} kbytes/second burst 1 kbytes drop;\n",
            uid, rate_kbytes
        ));
    }

    ruleset.push_str("  }\n");

    ruleset.push_str("}\n");
    ruleset
}

/// Apply (or refresh) the nftables inet oxy table.
fn refresh_nft_ip_rules(limits: &[LimitRecord]) -> Result<()> {
    if limits.is_empty() {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "oxy"])
            .output();
        return Ok(());
    }

    let ruleset = build_nft_ip_ruleset(limits);

    let nft_file = "/run/oxy/oxy.nft";
    fs::create_dir_all(STATE_DIR).ok();
    fs::write(nft_file, &ruleset).context("failed to write nft ruleset file")?;

    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "oxy"])
        .output();

    let output = Command::new("nft")
        .args(["-f", nft_file])
        .output()
        .context("failed to run nft. Is nftables installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to apply nft inet table: {}", stderr);
    }

    Ok(())
}

/// Refresh all nftables rules (inet table: IPv4 + IPv6).
fn refresh_all_nft_rules(limits: &[LimitRecord], _interface: &str) -> Result<()> {
    refresh_nft_ip_rules(limits)
}

// ---------------------------------------------------------------------------
// TC transaction helper
// ---------------------------------------------------------------------------

/// The next available class ID counter file.
const CLASS_ID_FILE: &str = "/run/oxy/.next_class_id";

/// Transactional tc command executor with rollback support.
struct TcTransaction {
    commands: Vec<(String, Vec<String>, Vec<String>)>,
    executed: Vec<(String, Vec<String>)>,
}

impl TcTransaction {
    fn new() -> Self {
        Self {
            commands: Vec::new(),
            executed: Vec::new(),
        }
    }

    fn add(&mut self, desc: &str, cmd_args: Vec<String>, rollback_args: Vec<String>) {
        self.commands
            .push((desc.to_string(), cmd_args, rollback_args));
    }

    fn execute(mut self) -> Result<()> {
        let commands = std::mem::take(&mut self.commands);

        for (desc, cmd_args, rollback_args) in commands {
            let output = Command::new("tc").args(&cmd_args).output();

            match output {
                Ok(o) if o.status.success() => {
                    self.executed.push((desc.clone(), rollback_args));
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if stderr.contains("File exists") {
                        continue;
                    }

                    eprintln!(
                        "{}: Command '{}' failed: {}",
                        "ERROR".red().bold(),
                        desc,
                        stderr
                    );
                    if !self.executed.is_empty() {
                        eprintln!(
                            "{}: Rolling back {} previously applied tc commands...",
                            "WARNING".yellow(),
                            self.executed.len()
                        );
                        for (_rb_desc, rb_args) in self.executed.iter().rev() {
                            let _ = Command::new("tc").args(rb_args).output();
                        }
                    }
                    bail!("tc command failed: {}", stderr);
                }
                Err(e) => {
                    eprintln!(
                        "{}: Failed to execute command '{}': {}",
                        "ERROR".red().bold(),
                        desc,
                        e
                    );
                    if !self.executed.is_empty() {
                        eprintln!(
                            "{}: Rolling back {} previously applied tc commands...",
                            "WARNING".yellow(),
                            self.executed.len()
                        );
                        for (_rb_desc, rb_args) in self.executed.iter().rev() {
                            let _ = Command::new("tc").args(rb_args).output();
                        }
                    }
                    bail!("failed to execute tc: {}", e);
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

/// Persistent record of an active bandwidth limit for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitRecord {
    pub target: String,
    pub pid: u32,
    pub download_bytes_per_sec: Option<u64>,
    pub upload_bytes_per_sec: Option<u64>,
    pub download_display: Option<String>,
    pub upload_display: Option<String>,
    pub interface: String,
    pub class_id: u32,
    pub applied_at: String,
    /// Handle for the ingress (download) tc fw filter.
    /// No longer used (download limiting is handled by nftables PREROUTING).
    /// Kept for state file backward compatibility; always None for new limits.
    #[serde(default)]
    pub ingress_handle: Option<u32>,
}

/// Full state file structure containing all active limits.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OxyState {
    pub limits: Vec<LimitRecord>,
}

impl OxyState {
    pub fn load() -> Result<Self> {
        if !Path::new(STATE_FILE).exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(STATE_FILE).context("failed to read oxy state file")?;
        let state: OxyState =
            serde_json::from_str(&content).context("failed to parse oxy state file")?;
        Ok(state)
    }

    pub fn save(&self) -> Result<()> {
        fs::create_dir_all(STATE_DIR).context("failed to create oxy state directory")?;

        let content =
            serde_json::to_string_pretty(self).context("failed to serialize oxy state")?;
        fs::write(STATE_FILE, content).context("failed to write oxy state file")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Check if the current process is running as root (UID 0).
pub fn check_root() -> Result<()> {
    let uid = nix::unistd::Uid::current();
    if !uid.is_root() {
        bail!(
            "{} root privileges are required for bandwidth limiting operations.\n  {} Run with: sudo oxy strict ...",
            "ERROR:".red().bold(),
            "Hint:".yellow()
        );
    }
    Ok(())
}

/// Detect the primary network interface by reading the default route.
pub fn get_default_interface() -> Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("failed to execute 'ip route' command. Is iproute2 installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("ip route command failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let default_line = stdout
        .lines()
        .next()
        .context("no default route found. Is the system connected to a network?")?;

    if let Some(dev_pos) = default_line.find("dev ") {
        let after_dev = &default_line[dev_pos + 4..];
        let iface = after_dev
            .split_whitespace()
            .next()
            .context("could not parse interface name from default route")?;
        return Ok(iface.to_string());
    }

    bail!("could not determine default network interface from route table");
}

/// Resolve a target string (process name or PID) to actual running PIDs.
pub fn resolve_pids(target: &str) -> Result<Vec<u32>> {
    if let Ok(pid) = target.parse::<u32>() {
        if Path::new(&format!("/proc/{}", pid)).exists() {
            return Ok(vec![pid]);
        } else {
            bail!("process with PID {} not found", pid);
        }
    }

    let mut pids = Vec::new();
    let proc_dir = Path::new("/proc");

    for entry in fs::read_dir(proc_dir).context("failed to read /proc directory")? {
        let entry = entry?;
        let dir_name = entry.file_name();
        let name_str = dir_name.to_string_lossy();

        if name_str.chars().all(|c| c.is_ascii_digit()) {
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                let binary_name = cmdline.split('\0').next().unwrap_or("");
                let program_name = binary_name.rsplit('/').next().unwrap_or(binary_name);

                if program_name.to_lowercase().contains(&target.to_lowercase()) {
                    pids.push(pid);
                }
            }
        }
    }

    if pids.is_empty() {
        bail!(
            "no running process found matching '{}'.\n  {} Use 'ps aux' to list running processes.",
            target,
            "Hint:".yellow()
        );
    }

    Ok(pids)
}

/// Get the process name for a given PID.
pub fn get_process_name(pid: u32) -> String {
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(name) = fs::read_to_string(&comm_path) {
        name.trim().to_string()
    } else {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            cmdline
                .split('\0')
                .next()
                .unwrap_or("")
                .rsplit('/')
                .next()
                .unwrap_or("[unknown]")
                .to_string()
        } else {
            "[unknown]".to_string()
        }
    }
}

/// Get the next available TC class ID and increment the counter.
pub fn next_class_id() -> Result<u32> {
    let id = if Path::new(CLASS_ID_FILE).exists() {
        let content = fs::read_to_string(CLASS_ID_FILE).unwrap_or_default();
        content.trim().parse::<u32>().unwrap_or(100)
    } else {
        100
    };

    fs::create_dir_all(STATE_DIR).ok();
    fs::write(CLASS_ID_FILE, (id + 1).to_string()).ok();

    Ok(id)
}

// ---------------------------------------------------------------------------
// TC qdisc/class setup
// ---------------------------------------------------------------------------

/// Set up the HTB qdisc root on the specified interface if not already present.
fn ensure_htb_qdisc(interface: &str) -> Result<()> {
    let check = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output()
        .context("failed to check existing tc qdisc")?;

    let stdout = String::from_utf8_lossy(&check.stdout);
    if stdout.contains("qdisc htb 1:") {
        return Ok(());
    }

    let output = Command::new("tc")
        .args([
            "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "999",
        ])
        .output()
        .context("failed to create tc qdisc. Is the 'tc' command available?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to create HTB qdisc on {}: {}", interface, stderr);
    }

    let output = Command::new("tc")
        .args([
            "class", "add", "dev", interface, "parent", "1:", "classid", "1:999", "htb", "rate",
            "100gbit", "ceil", "100gbit",
        ])
        .output()
        .context("failed to create default tc class")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to create default tc class: {}", stderr);
    }

    Ok(())
}

/// Ensure the ingress qdisc (ffff:) exists on the interface.
///
/// The ingress qdisc is where we attach fw filters with police actions
/// for download (ingress) bandwidth limiting.
#[allow(dead_code)]
fn ensure_ingress_qdisc(interface: &str) -> Result<()> {
    let check = Command::new("tc")
        .args(["qdisc", "show", "dev", interface, "ingress"])
        .output()
        .ok();

    let ingress_exists = check
        .as_ref()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("ingress") || stdout.contains("clsact")
        })
        .unwrap_or(false);

    if !ingress_exists {
        let output = Command::new("tc")
            .args(["qdisc", "add", "dev", interface, "ingress"])
            .output();

        if let Ok(o) = output {
            if !o.status.success() {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // clsact might already exist, which is fine
                if !stderr.contains("File exists") {
                    bail!(
                        "failed to create ingress qdisc on {}: {}",
                        interface,
                        stderr
                    );
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Cgroup management
// ---------------------------------------------------------------------------

/// Create a cgroup for the target process and assign it a net_cls classid.
pub fn setup_cgroup(pid: u32, class_id: u32) -> Result<(String, bool)> {
    let cgroup_path = format!("{}/pid_{}", CGROUP_BASE, pid);

    let (is_v2, is_hybrid) = detect_cgroup_version();

    if is_v2 && !is_hybrid {
        // Pure cgroup v2 - create under unified hierarchy
        let unified_base = "/sys/fs/cgroup";
        let v2_cgroup_path = format!("{}/oxy/pid_{}", unified_base, pid);
        fs::create_dir_all(&v2_cgroup_path)
            .context("failed to create cgroup v2 directory. Is cgroup2 filesystem mounted?")?;

        let procs_path = format!("{}/cgroup.procs", v2_cgroup_path);
        if Path::new(&procs_path).exists() {
            fs::write(&procs_path, pid.to_string())
                .context(format!("failed to move PID {} to cgroup v2", pid))?;
        }

        let cg_id_path = format!("{}/cgroup.id", v2_cgroup_path);
        if Path::new(&cg_id_path).exists() {
            return Ok((v2_cgroup_path, true));
        }

        return Ok((v2_cgroup_path, true));
    }

    // cgroup v1 or hybrid - use net_cls
    fs::create_dir_all(&cgroup_path)
        .context("failed to create cgroup directory. Is cgroup filesystem mounted?")?;

    let classid_hex = format!("0x0001{:04x}", class_id);
    let classid_path = format!("{}/net_cls.classid", cgroup_path);

    if Path::new(&classid_path).exists() {
        fs::write(&classid_path, &classid_hex).context("failed to set net_cls.classid")?;
    } else if is_hybrid {
        let cg_id_path = format!("{}/cgroup.id", cgroup_path);
        if Path::new(&cg_id_path).exists() {
            return Ok((cgroup_path, true));
        }
    }

    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    if Path::new(&procs_path).exists() {
        fs::write(&procs_path, pid.to_string())
            .context(format!("failed to move PID {} to cgroup", pid))?;
    }

    Ok((cgroup_path, false))
}

/// Remove a cgroup and move its processes back to the root cgroup.
pub fn remove_cgroup(pid: u32) -> Result<()> {
    let cgroup_path = format!("{}/pid_{}", CGROUP_BASE, pid);

    if !Path::new(&cgroup_path).exists() {
        return Ok(());
    }

    let (is_v2, is_hybrid) = detect_cgroup_version();

    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    if Path::new(&procs_path).exists() {
        if let Ok(content) = fs::read_to_string(&procs_path) {
            for pid_str in content.lines() {
                if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                    let root_procs = if is_v2 && !is_hybrid {
                        "/sys/fs/cgroup/cgroup.procs".to_string()
                    } else {
                        format!("{}/cgroup.procs", CGROUP_BASE)
                    };
                    if Path::new(&root_procs).exists() {
                        fs::write(&root_procs, proc_pid.to_string()).ok();
                    }
                }
            }
        }
    }

    let mut removed = false;
    for _ in 0..5 {
        match fs::remove_dir(&cgroup_path) {
            Ok(()) => {
                removed = true;
                break;
            }
            Err(_) => {
                if Path::new(&procs_path).exists() {
                    if let Ok(content) = fs::read_to_string(&procs_path) {
                        for pid_str in content.lines() {
                            if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                                let root_procs = if is_v2 && !is_hybrid {
                                    "/sys/fs/cgroup/cgroup.procs".to_string()
                                } else {
                                    format!("{}/cgroup.procs", CGROUP_BASE)
                                };
                                if Path::new(&root_procs).exists() {
                                    let _ = fs::write(&root_procs, proc_pid.to_string());
                                }
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    if !removed {
        fs::remove_dir(&cgroup_path).context("failed to remove cgroup directory")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main: apply_limit
// ---------------------------------------------------------------------------

/// Apply a bandwidth limit (strict) to a target process.
///
/// This is the main entry point for the `oxy strict` command.
pub fn apply_limit(
    target: &str,
    download: Option<&str>,
    upload: Option<&str>,
    download_only: bool,
    upload_only: bool,
) -> Result<()> {
    check_root()?;

    if download.is_none() && upload.is_none() && !download_only && !upload_only {
        bail!(
            "no bandwidth limit specified.\n  {} Usage: oxy strict -d <rate> -u <rate> <target>",
            "ERROR:".red().bold()
        );
    }

    let download_rate = download.map(BandwidthRate::parse).transpose()?;
    let upload_rate = upload.map(BandwidthRate::parse).transpose()?;

    let (dl_bps, ul_bps, dl_display, ul_display) = if download_only {
        let rate = download_rate.context("download rate required with -d only")?;
        (Some(rate.bytes_per_sec), None, Some(rate.raw.clone()), None)
    } else if upload_only {
        let rate = upload_rate.context("upload rate required with -u only")?;
        (None, Some(rate.bytes_per_sec), None, Some(rate.raw.clone()))
    } else {
        (
            download_rate.as_ref().map(|r| r.bytes_per_sec),
            upload_rate.as_ref().map(|r| r.bytes_per_sec),
            download_rate.as_ref().map(|r| r.raw.clone()),
            upload_rate.as_ref().map(|r| r.raw.clone()),
        )
    };

    let pids = resolve_pids(target)?;
    let interface = get_default_interface()?;

    // Ensure kernel modules
    if let Err(e) = ensure_kernel_modules() {
        eprintln!(
            "{}: Failed to ensure kernel modules: {}",
            "WARNING".yellow(),
            e
        );
    }

    // Detect cgroup version
    let (cg_is_v2, cg_is_hybrid) = detect_cgroup_version();
    let use_cgroup_v1_backend = !cg_is_v2 || cg_is_hybrid;

    // Set up HTB qdisc for upload (egress) shaping
    ensure_htb_qdisc(&interface)?;

    // If download limiting is requested, ensure conntrack mark propagation
    if dl_bps.is_some() {
        if let Err(e) = ensure_conntrack() {
            eprintln!(
                "{}: conntrack setup failed: {}. Download limiting may not work.",
                "WARNING".yellow(),
                e
            );
        }
    }

    // For cgroup v1/hybrid, add tc cgroup filter on egress for reliable upload limiting
    // that works for existing connections (not just new sockets)
    if use_cgroup_v1_backend {
        let check = Command::new("tc")
            .args(["filter", "show", "dev", &interface, "parent", "1:0"])
            .output()
            .ok();

        let has_cgroup_filter = check
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("cgroup"))
            .unwrap_or(false);

        if !has_cgroup_filter {
            let output = Command::new("tc")
                .args([
                    "filter", "add", "dev", &interface, "parent", "1:0", "protocol", "ip", "prio",
                    "1", "cgroup",
                ])
                .output();

            if let Ok(o) = output {
                if !o.status.success() {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    eprintln!(
                        "{}: Failed to add tc cgroup filter (v1 fallback): {}",
                        "WARNING".yellow(),
                        stderr
                    );
                }
            }
        }
    }

    // Load existing state
    let mut state = OxyState::load()?;

    // Phase 1: Create per-PID cgroups and records
    let mut applied_count = 0;
    for pid in &pids {
        let class_id = next_class_id()?;
        let _process_name = get_process_name(*pid);
        let (_cgroup_path, _is_cgroup_v2) = setup_cgroup(*pid, class_id)?;

        let record = LimitRecord {
            target: target.to_string(),
            pid: *pid,
            download_bytes_per_sec: dl_bps,
            upload_bytes_per_sec: ul_bps,
            download_display: dl_display.clone(),
            upload_display: ul_display.clone(),
            interface: interface.clone(),
            class_id,
            applied_at: chrono_now(),
            ingress_handle: None,
        };

        state.limits.push(record);
        applied_count += 1;
    }

    // Save state (needed before computing per-UID tc objects)
    state.save()?;

    // Phase 2: Create per-UID egress tc objects (HTB class + fw filter).
    // Since the nftables mark is the UID value, the fw filter handle must also
    // be the UID. All PIDs sharing a UID share one HTB class (upload) rate.
    let mut uid_min_ul: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    let mut seen_uids = std::collections::HashSet::new();
    for record in &state.limits {
        if let Some(uid) = get_process_uid(record.pid) {
            let ul_kbit = record
                .upload_bytes_per_sec
                .map(|bps| (bps * 8) / 1000)
                .unwrap_or(100_000_000);
            uid_min_ul
                .entry(uid)
                .and_modify(|min| *min = (*min).min(ul_kbit))
                .or_insert(ul_kbit);
            seen_uids.insert(uid);
        }
    }

    let mut tx = TcTransaction::new();
    for uid in &seen_uids {
        let class_id_str = format!("1:{:04x}", uid);
        let ul_kbit = uid_min_ul[uid];
        let ceil_kbit = (ul_kbit as f64 * 1.1) as u64;

        // --- Upload (egress): HTB class for this UID ---
        tx.add(
            &format!("egress class for UID {}", uid),
            vec![
                "class".into(),
                "add".into(),
                "dev".into(),
                interface.clone(),
                "parent".into(),
                "1:".into(),
                "classid".into(),
                class_id_str.clone(),
                "htb".into(),
                "rate".into(),
                format!("{}kbit", ul_kbit),
                "ceil".into(),
                format!("{}kbit", ceil_kbit),
                "burst".into(),
                "15k".into(),
                "cburst".into(),
                "15k".into(),
            ],
            vec![
                "class".into(),
                "del".into(),
                "dev".into(),
                interface.clone(),
                "classid".into(),
                class_id_str.clone(),
            ],
        );

        // --- Upload (egress): fw filter matching UID mark → UID HTB class ---
        tx.add(
            &format!("egress fw filter for UID {}", uid),
            vec![
                "filter".into(),
                "add".into(),
                "dev".into(),
                interface.clone(),
                "parent".into(),
                "1:0".into(),
                "protocol".into(),
                "ip".into(),
                "prio".into(),
                "100".into(),
                "handle".into(),
                uid.to_string(),
                "fw".into(),
                "classid".into(),
                class_id_str.clone(),
            ],
            vec![
                "filter".into(),
                "del".into(),
                "dev".into(),
                interface.clone(),
                "parent".into(),
                "1:0".into(),
                "protocol".into(),
                "ip".into(),
                "prio".into(),
                "100".into(),
                "handle".into(),
                uid.to_string(),
                "fw".into(),
            ],
        );
    }

    if let Err(e) = tx.execute() {
        eprintln!("{}: Failed to apply tc rules: {}", "ERROR".red().bold(), e);
        // Rollback cgroups
        for pid in &pids {
            let _ = remove_cgroup(*pid);
        }
        return Err(e);
    }

    // Refresh all nftables rules
    if let Err(e) = refresh_all_nft_rules(&state.limits, &interface) {
        eprintln!(
            "{}: Failed to apply nft packet marking rules: {}",
            "ERROR".red().bold(),
            e
        );
        eprintln!(
            "  {} Without nftables rules, packets will not be classified.",
            "NOTE:".yellow()
        );
    }

    // Print summary
    if applied_count == 0 {
        println!(
            "{}",
            "oxy strict: no bandwidth limits were applied"
                .yellow()
                .bold()
        );
        return Ok(());
    }

    println!("{}", "oxy strict: bandwidth limit applied".green().bold());
    println!();
    println!("  Target:    {}", target);
    println!(
        "  PIDs:      {}",
        pids.iter()
            .map(|p| format!("{}", p))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(ref dl) = dl_display {
        println!("  Download:  {} (limited, nft limit rate)", dl.cyan());
    } else {
        println!("  Download:  {}", "unlimited".dimmed());
    }
    if let Some(ref ul) = ul_display {
        println!("  Upload:    {} (limited, HTB)", ul.cyan());
    } else {
        println!("  Upload:    {}", "unlimited".dimmed());
    }
    println!("  Interface: {}", interface);
    println!(
        "  Backend:   nftables inet (PREROUTING limit rate) + tc HTB (cgroup v{})",
        if use_cgroup_v1_backend {
            "1/hybrid"
        } else {
            "2"
        }
    );
    println!("  Applied:   {} process(es)", applied_count);

    // Warn about per-UID mode when multiple PIDs share a UID
    let unique_pids_uids: std::collections::HashSet<u32> = pids
        .iter()
        .filter_map(|pid| get_process_uid(*pid))
        .collect();
    if unique_pids_uids.len() < pids.len() {
        println!(
            "  {} Rate limiting is per-UID ({} PIDs share {} UID).",
            "NOTE:".yellow(),
            pids.len(),
            unique_pids_uids.len()
        );
    }

    println!();
    println!(
        "  {} Use 'oxy unstrict {}' to remove limits.",
        "Info:".yellow(),
        target
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Main: remove_limit
// ---------------------------------------------------------------------------

/// Remove all bandwidth limits (unstrict) from a target process.
pub fn remove_limit(target: &str) -> Result<()> {
    check_root()?;

    let pids = resolve_pids(target)?;

    let mut state = OxyState::load()?;

    let mut removed_count = 0;
    let target_lower = target.to_lowercase();

    let mut to_remove = Vec::new();

    for (idx, record) in state.limits.iter().enumerate() {
        let rec_lower = record.target.to_lowercase();
        let matches = pids.contains(&record.pid)
            || rec_lower == target_lower
            || rec_lower.contains(&target_lower)
            || target_lower.contains(&rec_lower);

        if matches {
            to_remove.push(idx);
        }
    }

    if to_remove.is_empty() {
        println!(
            "{} No active bandwidth limits found for '{}'.",
            "Info:".yellow(),
            target
        );
        return Ok(());
    }

    // Collect interfaces and UIDs for cleanup
    let removed_ifaces: Vec<String> = to_remove
        .iter()
        .map(|&idx| state.limits[idx].interface.clone())
        .collect();

    // Collect UIDs of records being removed
    let removed_uids: std::collections::HashSet<u32> = to_remove
        .iter()
        .filter_map(|&idx| get_process_uid(state.limits[idx].pid))
        .collect();

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        // Remove cgroup for this PID
        remove_cgroup(record.pid)?;

        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

    // Clean up per-UID tc objects for UIDs that no longer have any limits.
    // Compute remaining UIDs after removal.
    let remaining_uids: std::collections::HashSet<u32> = state
        .limits
        .iter()
        .filter_map(|r| get_process_uid(r.pid))
        .collect();

    for uid in &removed_uids {
        if !remaining_uids.contains(uid) {
            let uid_class_id_str = format!("1:{:04x}", uid);
            for iface in &removed_ifaces {
                // Remove per-UID HTB class
                let _ = Command::new("tc")
                    .args(["class", "del", "dev", iface, "classid", &uid_class_id_str])
                    .output();
                // Remove per-UID fw filter (handle = UID)
                let _ = Command::new("tc")
                    .args([
                        "filter",
                        "del",
                        "dev",
                        iface,
                        "parent",
                        "1:0",
                        "protocol",
                        "ip",
                        "prio",
                        "100",
                        "handle",
                        &uid.to_string(),
                        "fw",
                    ])
                    .output();
            }
        }
    }

    // Refresh nft rules (removes marking for removed processes)
    if let Err(e) = refresh_all_nft_rules(
        &state.limits,
        removed_ifaces.first().unwrap_or(&"".to_string()),
    ) {
        eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
    }

    // Clean up tc cgroup filter if no limits remain
    if state.limits.is_empty() {
        for iface in &removed_ifaces {
            let _ = Command::new("tc")
                .args([
                    "filter", "del", "dev", iface, "parent", "1:0", "protocol", "ip", "prio", "1",
                    "cgroup",
                ])
                .output();
        }

        // Clean up ingress qdisc
        for iface in &removed_ifaces {
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", iface, "ingress"])
                .output();
        }

        // Clean up all nftables tables
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "oxy"])
            .output();
    }

    println!(
        "{}",
        "oxy unstrict: bandwidth limits removed".green().bold()
    );
    println!();
    println!("  Target:    {}", target);
    println!("  Removed:   {} limit(s)", removed_count);
    println!(
        "  {} All bandwidth restrictions for '{}' have been lifted.",
        "Info:".yellow(),
        target
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Main: list_active_limits
// ---------------------------------------------------------------------------

/// List all currently active bandwidth limits.
pub fn list_active_limits() -> Result<()> {
    let _ = check_respawns();

    let state = OxyState::load()?;

    if state.limits.is_empty() {
        println!("{} No active bandwidth limits.", "Info:".yellow());
        return Ok(());
    }

    println!("{}", "Active Bandwidth Limits:".green().bold());
    println!();

    for record in &state.limits {
        let process_name = get_process_name(record.pid);
        println!("  Target:    {} (PID: {})", record.target, record.pid);
        println!("  Process:   {}", process_name);
        if let Some(ref dl) = record.download_display {
            println!("  Download:  {} (police)", dl);
        } else {
            println!("  Download:  {}", "unlimited".dimmed());
        }
        if let Some(ref ul) = record.upload_display {
            println!("  Upload:    {} (HTB)", ul);
        } else {
            println!("  Upload:    {}", "unlimited".dimmed());
        }
        println!("  Interface: {}", record.interface);
        println!("  Class ID:  1:{:04x}", record.class_id);
        println!("  Since:     {}", record.applied_at);
        println!();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Orphan cleanup & respawn handling
// ---------------------------------------------------------------------------

/// Clean up orphaned bandwidth limits for processes that have exited.
pub fn clean_orphans() -> Result<()> {
    check_root()?;

    let mut state = OxyState::load()?;

    if state.limits.is_empty() {
        println!("{} No active bandwidth limits to clean.", "Info:".yellow());
        return Ok(());
    }

    let mut removed_count = 0;
    let mut kept_count = 0;

    let mut to_remove = Vec::new();

    for (idx, record) in state.limits.iter().enumerate() {
        let proc_path = format!("/proc/{}", record.pid);
        let is_alive = std::path::Path::new(&proc_path).exists();

        if is_alive {
            kept_count += 1;
        } else {
            to_remove.push(idx);
        }
    }

    if to_remove.is_empty() {
        println!(
            "{} All {} limit(s) are for running processes. No cleanup needed.",
            "Info:".yellow(),
            kept_count
        );
        return Ok(());
    }

    println!(
        "{} Found {} orphaned limit(s) to clean up...",
        "Cleaning:".cyan(),
        to_remove.len()
    );

    // Collect UIDs of records being removed
    let removed_uids: std::collections::HashSet<u32> = to_remove
        .iter()
        .filter_map(|&idx| get_process_uid(state.limits[idx].pid))
        .collect();

    // Collect interfaces for cleanup
    let removed_ifaces: std::collections::HashSet<String> = to_remove
        .iter()
        .map(|&idx| state.limits[idx].interface.clone())
        .collect();

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        println!(
            "  Removing stale rules for {} (PID: {}, class: 1:{:04x})...",
            record.target, record.pid, record.class_id
        );

        // Remove cgroup
        let _ = remove_cgroup(record.pid);

        // Remove from state
        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

    // Clean up per-UID tc objects for UIDs that no longer have any limits.
    let remaining_uids: std::collections::HashSet<u32> = state
        .limits
        .iter()
        .filter_map(|r| get_process_uid(r.pid))
        .collect();

    for uid in &removed_uids {
        if !remaining_uids.contains(uid) {
            let uid_class_id_str = format!("1:{:04x}", uid);
            for iface in &removed_ifaces {
                let _ = Command::new("tc")
                    .args(["class", "del", "dev", iface, "classid", &uid_class_id_str])
                    .output();
                let _ = Command::new("tc")
                    .args([
                        "filter",
                        "del",
                        "dev",
                        iface,
                        "parent",
                        "1:0",
                        "protocol",
                        "ip",
                        "prio",
                        "100",
                        "handle",
                        &uid.to_string(),
                        "fw",
                    ])
                    .output();
            }
        }
    }

    println!();
    println!("{}", "oxy clean: orphaned limits removed".green().bold());
    println!();
    println!("  Removed:   {} orphaned limit(s)", removed_count);
    println!("  Remaining: {} active limit(s)", kept_count);
    println!();
    println!(
        "  {} Run 'oxy status' to see current active limits.",
        "Info:".yellow()
    );

    Ok(())
}

/// Generate a human-readable timestamp string for the applied_at field.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let datetime = time::OffsetDateTime::from(now);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        datetime.year(),
        datetime.month() as u8,
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

/// Check for process respawns and re-apply limits to new PIDs.
pub fn check_respawns() -> Result<()> {
    check_root()?;

    let mut state = OxyState::load()?;

    if state.limits.is_empty() {
        return Ok(());
    }

    let mut respawned: Vec<(usize, Vec<u32>)> = Vec::new();

    // Check each limit for process death and potential respawn
    for (idx, record) in state.limits.iter().enumerate() {
        let proc_path = format!("/proc/{}", record.pid);
        let is_alive = std::path::Path::new(&proc_path).exists();

        if !is_alive {
            // Process died - look for respawned instances with same name
            let current_pids = resolve_pids(&record.target)?;

            if !current_pids.is_empty() {
                respawned.push((idx, current_pids));
            }
        }
    }

    if respawned.is_empty() {
        return Ok(());
    }

    println!(
        "{}",
        "oxy: detected process respawn(s), re-applying limits..."
            .yellow()
            .bold()
    );
    println!();

    // Re-apply limits to respawned processes
    for (idx, new_pids) in respawned {
        let record = &state.limits[idx];

        println!(
            "  Target '{}' (PID: {} -> new PID(s): {:?})",
            record.target, record.pid, new_pids
        );

        // Get first PID and update record
        let first_pid = new_pids[0];

        // Re-apply for each new PID
        for &new_pid in &new_pids {
            let (cgroup_path, _) = setup_cgroup(new_pid, record.class_id)?;

            // Move process to cgroup
            let procs_path = format!("{}/cgroup.procs", cgroup_path);
            if std::path::Path::new(&procs_path).exists() {
                let _ = std::fs::write(&procs_path, new_pid.to_string());
            }
        }

        // Update record with first new PID as primary
        state.limits[idx].pid = first_pid;
        state.limits[idx].applied_at = chrono_now();

        println!("  {} Re-applied limits to PID {}", "✓".green(), first_pid);
    }

    // Save updated state
    state.save()?;

    println!();
    println!("{}", "oxy: respawn handling complete".green().bold());

    Ok(())
}
