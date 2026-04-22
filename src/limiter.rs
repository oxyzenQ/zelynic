// SPDX-License-Identifier: MIT
/// Bandwidth limiting module using Linux traffic control (tc) and cgroups.
///
/// Architecture:
///
/// **Upload (egress) limiting:**
///   Process (in target cgroup) → tc cgroup filter → HTB class (rate-limited)
///   On cgroup v1/hybrid: per-PID cgroups with net_cls.classid as fallback.
///
/// **Download (ingress) limiting (nftables socket cgroupv2 + limit rate):**
///   NIC → nftables inet input (socket cgroupv2 <cg_id> limit rate → accept/drop)
///   Match: `socket cgroupv2 <cg_id>` — matches packets whose socket belongs
///   to a specific per-target cgroup (new connections created after the
///   process was moved to the cgroup).
///
/// **Per-target cgroups:**
///   All target PIDs are moved to `/sys/fs/cgroup/oxy/target_<sanitized_name>/`
///   so that nftables `socket cgroupv2` can match traffic per target for NEW
///   connections.  On cgroup v1/hybrid, per-PID cgroups with net_cls.classid
///   are used instead.
///
/// **Per-target nftables matching (download):**
///   1. `socket cgroupv2 <cg_id>` — primary (NEW connections, per-target)
///   2. `ct mark <target_hash>` — existing connections via conntrack mark
///
/// NOTE: `meta skuid` is intentionally NOT used — it would leak limits to
/// all processes of the same UID, breaking per-target isolation.
///
/// State is persisted to disk so that limits survive across invocations
/// and can be cleaned up properly with `oxy unstrict`.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
        "nf_conntrack", // conntrack
    ];

    for module in modules {
        // Use modprobe to load modules. Ignore errors; they may be built-in.
        let _ = Command::new("modprobe").arg(module).output();
    }

    Ok(())
}

/// Ensure netfilter conntrack is enabled for ct mark propagation.
/// Required for the download fallback: egress marks are saved to conntrack,
/// then matched on reply (download) packets via `ct mark`.
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
/// Retained for potential future use (e.g., v1/hybrid cgroup backends).
#[allow(dead_code)]
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

/// Sanitize a target name for use as a cgroup directory name.
///
/// Rules: lowercase, replace non-alphanumeric chars with underscore, max 64 chars.
fn sanitize_target_name(target: &str) -> String {
    let sanitized: String = target
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Truncate to max 64 characters
    sanitized.chars().take(64).collect()
}

/// Derive a stable HTB class ID (minor) from a target name.
///
/// Uses a simple hash of the sanitized target name, mapped into range 100..65535.
fn target_class_id(target: &str) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    target.hash(&mut hasher);
    let hash = hasher.finish() as u32;
    // Map into range 100..65535 (avoid 0 and very low numbers, stay within u16)
    100 + (hash % 65435)
}

// ---------------------------------------------------------------------------
// nftables rules management
// ---------------------------------------------------------------------------

/// Build the nftables `inet oxy` table for egress marking (upload) and
/// download rate limiting via `socket cgroupv2`.
///
/// Uses `inet` (IPv4 + IPv6) so both protocol families are handled.
///
/// Architecture (per-target isolation via socket cgroupv2):
///
/// **Output chain**: marks egress packets for tc fw filter upload shaping.
///   - `socket cgroupv2 <cg_id>` — matches sockets created after the
///     process was moved to the per-target cgroup. Per-target isolation.
///   NOTE: No `meta skuid` fallback — it would leak marks to all processes
///   of the same UID, breaking per-target isolation.
///
/// **Postrouting chain**: saves the fw mark into conntrack for reply packets.
///   This is critical: download packets arrive as replies to egress packets.
///   The ct mark lets us identify which download packets belong to limited
///   connections, even for connections that predate the cgroup assignment.
///
/// **Download chain**: rate-limits inbound traffic at the input hook.
///   Two tiers provide coverage for different connection states:
///   1. `socket cgroupv2 <cg_id>` — primary (NEW connections, per-target)
///   2. `ct mark <target_hash>` — fallback (EXISTING connections via ct mark)
///   NOTE: `meta skuid` is intentionally NOT used — it would leak limits
///   to all processes of the same UID, breaking per-target isolation.
fn build_nft_ip_ruleset(limits: &[LimitRecord]) -> String {
    let mut ruleset = String::new();
    ruleset.push_str("table inet oxy {\n");

    // ---- Output chain: mark egress packets ----
    ruleset.push_str("  chain output {\n");
    ruleset.push_str("    type filter hook output priority mangle; policy accept;\n");

    // Tier 1: socket cgroupv2 — per-target (new sockets only)
    let mut cg_to_mark: HashMap<u64, u32> = HashMap::new();
    for record in limits {
        if let Some(cgid) = record.cgroup_id {
            cg_to_mark
                .entry(cgid)
                .or_insert_with(|| target_class_id(&sanitize_target_name(&record.target)));
        }
    }
    for (cgid, mark) in &cg_to_mark {
        ruleset.push_str(&format!(
            "    socket cgroupv2 {} meta mark set {};\n",
            cgid, mark
        ));
    }

    ruleset.push_str("  }\n");

    // ---- Postrouting chain: save mark to conntrack ----
    ruleset.push_str("  chain postrouting {\n");
    ruleset.push_str("    type filter hook postrouting priority srcnat; policy accept;\n");
    ruleset.push_str("    meta mark != 0 ct mark set meta mark;\n");
    ruleset.push_str("  }\n");

    // ---- Download chain: rate-limit inbound traffic ----
    ruleset.push_str("  chain download {\n");
    ruleset.push_str("    type filter hook input priority mangle; policy accept;\n");

    // Collect per-cgroup_id download limits (for socket cgroupv2 primary tier)
    let mut cg_dl_info: HashMap<u64, u64> = HashMap::new();
    for record in limits.iter().filter(|l| l.download_bytes_per_sec.is_some()) {
        if let Some(cgid) = record.cgroup_id {
            let dl_bps = record.download_bytes_per_sec.unwrap();
            let entry = cg_dl_info.entry(cgid).or_insert(dl_bps);
            *entry = (*entry).min(dl_bps);
        }
    }

    // Collect per-target mark → download rate (for ct mark fallback tier)
    let mut mark_dl_info: HashMap<u32, u64> = HashMap::new();
    for record in limits.iter().filter(|l| l.download_bytes_per_sec.is_some()) {
        let dl_bps = record.download_bytes_per_sec.unwrap();
        let mark = target_class_id(&sanitize_target_name(&record.target));
        let entry = mark_dl_info.entry(mark).or_insert(dl_bps);
        *entry = (*entry).min(dl_bps);
    }

    // Tier 1: socket cgroupv2 — per-target (new connections)
    for (cgid, dl_bps) in &cg_dl_info {
        let burst = (*dl_bps / 2).max(65536);
        ruleset.push_str(&format!(
            "    socket cgroupv2 {} limit rate {} bytes/second burst {} bytes accept;\n",
            cgid, dl_bps, burst
        ));
        ruleset.push_str(&format!("    socket cgroupv2 {} drop;\n", cgid));
    }

    // Tier 2: ct mark — existing connections (marked by output chain)
    for (mark, dl_bps) in &mark_dl_info {
        let burst = (*dl_bps / 2).max(65536);
        ruleset.push_str(&format!(
            "    ct mark {} limit rate {} bytes/second burst {} bytes accept;\n",
            mark, dl_bps, burst
        ));
        ruleset.push_str(&format!("    ct mark {} drop;\n", mark));
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
    /// No longer used (download limiting is handled by nftables input hook).
    /// Kept for state file backward compatibility; always None for new limits.
    #[serde(default)]
    pub ingress_handle: Option<u32>,
    /// Cgroup v2 ID (inode number) for the per-target cgroup associated with
    /// this record.  Used by nftables `socket cgroupv2` to match download
    /// traffic in the inet input hook.
    #[serde(default)]
    pub cgroup_id: Option<u64>,
    /// Path to the per-target cgroup (e.g., `/sys/fs/cgroup/oxy/target_helium`).
    /// New for per-target isolation; None for legacy state files.
    #[serde(default)]
    pub target_cgroup_path: Option<String>,
    /// UID of the target process.  Kept for backward compatibility with
    /// legacy state files; always None for new limits (meta skuid fallback
    /// was removed to prevent per-UID cross-process leaks).
    #[serde(default)]
    pub uid: Option<u32>,
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

/// List all available network interfaces on the system.
pub fn list_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                // Skip loopback
                if name != "lo" {
                    ifaces.push(name.to_string());
                }
            }
        }
    }
    ifaces.sort();
    ifaces
}

/// Validate that a given interface name exists on the system.
/// Returns an error with available interfaces listed if invalid.
pub fn validate_interface(name: &str) -> Result<()> {
    let available = list_interfaces();
    if available.iter().any(|i| i == name) {
        return Ok(());
    }
    bail!(
        "unknown interface '{}'.\n  Available interfaces: {}",
        name,
        if available.is_empty() {
            "(none found)".to_string()
        } else {
            available.join(", ")
        }
    );
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
///
/// Uses file locking (`flock`) to prevent race conditions when multiple
/// `oxy strict` invocations run concurrently.
pub fn next_class_id() -> Result<u32> {
    fs::create_dir_all(STATE_DIR).context("failed to create oxy state directory")?;

    // Open (or create) the counter file with exclusive lock to prevent
    // concurrent oxy processes from reading the same ID.
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(CLASS_ID_FILE)
        .context("failed to open class ID counter file")?;

    // flock(2) — exclusive lock, blocks until available
    let fd = file.as_raw_fd();
    unsafe {
        let ret = libc::flock(fd, libc::LOCK_EX);
        if ret != 0 {
            anyhow::bail!("failed to lock class ID file (flock)");
        }
    }

    let id = {
        let mut content = String::new();
        use std::io::Read;
        let _ = std::io::BufReader::new(&file).read_to_string(&mut content);
        content.trim().parse::<u32>().unwrap_or(100)
    };

    // Write back incremented counter
    use std::io::{Seek, SeekFrom, Write};
    let mut file = file;
    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.set_len(0);
    let _ = file.write_all((id + 1).to_string().as_bytes());
    let _ = file.sync_all();

    // Release lock (happens automatically on file close/drop, but be explicit)
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
    }

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

    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    if Path::new(&procs_path).exists() {
        if let Ok(content) = fs::read_to_string(&procs_path) {
            for pid_str in content.lines() {
                if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                    // Skip dead processes — kernel removes them from cgroup.procs automatically
                    if !std::path::Path::new(&format!("/proc/{}", proc_pid)).exists() {
                        continue;
                    }
                    // Move living processes to parent oxy cgroup (NOT system root cgroup).
                    // Writing to /sys/fs/cgroup/cgroup.procs (root) breaks systemd --user
                    // cgroup delegation and can prevent all user apps from launching.
                    let safe_procs = format!("{}/cgroup.procs", CGROUP_BASE);
                    if Path::new(&safe_procs).exists() {
                        fs::write(&safe_procs, proc_pid.to_string()).ok();
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
                                // Skip dead processes
                                if !std::path::Path::new(&format!("/proc/{}", proc_pid)).exists() {
                                    continue;
                                }
                                let safe_procs = format!("{}/cgroup.procs", CGROUP_BASE);
                                if Path::new(&safe_procs).exists() {
                                    let _ = fs::write(&safe_procs, proc_pid.to_string());
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

/// Remove a per-target cgroup directory and move its processes back to root.
///
/// On cgroup v2, per-target cgroups live at `/sys/fs/cgroup/oxy/target_<name>/`.
/// This function evicts all member PIDs and deletes the directory.
fn remove_target_cgroup(sanitized_name: &str) -> Result<()> {
    let cgroup_path = format!("{}/target_{}", CGROUP_BASE, sanitized_name);

    if !Path::new(&cgroup_path).exists() {
        return Ok(());
    }

    let procs_path = format!("{}/cgroup.procs", cgroup_path);

    // Move all processes back to parent oxy cgroup
    if Path::new(&procs_path).exists() {
        if let Ok(content) = fs::read_to_string(&procs_path) {
            for pid_str in content.lines() {
                if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                    // Skip dead processes
                    if !std::path::Path::new(&format!("/proc/{}", proc_pid)).exists() {
                        continue;
                    }
                    let safe_procs = format!("{}/cgroup.procs", CGROUP_BASE);
                    if Path::new(&safe_procs).exists() {
                        fs::write(&safe_procs, proc_pid.to_string()).ok();
                    }
                }
            }
        }
    }

    // Retry removal up to 5 times (processes may linger briefly)
    let mut removed = false;
    for _ in 0..5 {
        match fs::remove_dir(&cgroup_path) {
            Ok(()) => {
                removed = true;
                break;
            }
            Err(_) => {
                // Re-evict any remaining processes
                if Path::new(&procs_path).exists() {
                    if let Ok(content) = fs::read_to_string(&procs_path) {
                        for pid_str in content.lines() {
                            if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                                // Skip dead processes
                                if !std::path::Path::new(&format!("/proc/{}", proc_pid)).exists() {
                                    continue;
                                }
                                let safe_procs = format!("{}/cgroup.procs", CGROUP_BASE);
                                if Path::new(&safe_procs).exists() {
                                    let _ = fs::write(&safe_procs, proc_pid.to_string());
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
        fs::remove_dir(&cgroup_path).context("failed to remove target cgroup directory")?;
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
    iface_override: Option<&str>,
) -> Result<()> {
    check_root()?;

    // Auto-cleanup: remove stale limits for dead processes before applying new limits.
    // This prevents accumulation of orphaned state when target processes exit
    // without running `oxy unstrict` first.
    if let Err(e) = clean_orphans() {
        // Don't fail — just log. The user's requested operation is more important.
        eprintln!("{}: auto-cleanup failed: {}", "WARNING".yellow(), e);
    }

    if download.is_none() && upload.is_none() {
        bail!(
            "no bandwidth limit specified.\n  {} Usage: oxy strict -d <rate> -u <rate> <target>",
            "ERROR:".red().bold()
        );
    }

    // Resolve and validate interface early (before doing anything else)
    let interface = match iface_override {
        Some(i) => {
            validate_interface(i)?;
            i.to_string()
        }
        None => get_default_interface()?,
    };

    let download_rate = download.map(BandwidthRate::parse).transpose()?;
    let upload_rate = upload.map(BandwidthRate::parse).transpose()?;

    let (dl_bps, ul_bps, dl_display, ul_display) = (
        download_rate.as_ref().map(|r| r.bytes_per_sec),
        upload_rate.as_ref().map(|r| r.bytes_per_sec),
        download_rate.as_ref().map(|r| r.to_string()),
        upload_rate.as_ref().map(|r| r.to_string()),
    );

    let pids = resolve_pids(target)?;
    let sanitized = sanitize_target_name(target);

    println!("{} Using interface: {}", "→".cyan(), interface.cyan());

    // Auto-clean: remove any existing limits for this target to allow
    // seamless re-running `oxy strict` without manual unstrict first.
    if let Ok(mut state) = OxyState::load() {
        let target_lower = target.to_lowercase();
        let existing: Vec<usize> = state
            .limits
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let rec_lower = r.target.to_lowercase();
                pids.contains(&r.pid)
                    || rec_lower == target_lower
                    || rec_lower.contains(&target_lower)
                    || target_lower.contains(&rec_lower)
            })
            .map(|(i, _)| i)
            .collect();

        if !existing.is_empty() {
            // Collect info for cleanup before removing
            let removed_ifaces: HashSet<String> = existing
                .iter()
                .map(|&i| state.limits[i].interface.clone())
                .collect();

            // Remove per-PID cgroups and state records
            for &idx in existing.iter().rev() {
                let _ = remove_cgroup(state.limits[idx].pid);
                state.limits.remove(idx);
            }
            state.save()?;

            // Clean up per-target tc objects if no limits remain for this target
            let remaining_targets: HashSet<String> = state
                .limits
                .iter()
                .map(|r| sanitize_target_name(&r.target))
                .collect();

            if !remaining_targets.contains(&sanitized) {
                let tid = target_class_id(&sanitized);
                let target_class_id_str = format!("1:{:04x}", tid);
                for iface in &removed_ifaces {
                    let _ = Command::new("tc")
                        .args([
                            "class",
                            "del",
                            "dev",
                            iface,
                            "classid",
                            &target_class_id_str,
                        ])
                        .output();
                    // Remove fw filter for this target
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
                            &tid.to_string(),
                            "fw",
                        ])
                        .output();
                }
                let _ = remove_target_cgroup(&sanitized);
            }

            // Refresh nft rules
            if let Err(e) = refresh_nft_ip_rules(&state.limits) {
                eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
            }

            println!(
                "  {} Auto-cleaned {} previous limit(s) for '{}'",
                "Info:".dimmed(),
                existing.len(),
                target
            );
        }
    }

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
    let is_pure_v2 = cg_is_v2 && !cg_is_hybrid;

    // Set up HTB qdisc for upload (egress) shaping
    ensure_htb_qdisc(&interface)?;

    // If download limiting is requested, ensure conntrack
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

    // Phase 1: Create per-target cgroup (v2) or per-PID cgroups (v1).
    // All PIDs for this target share one cgroup on pure cgroup v2.
    let target_cg_path = format!("{}/target_{}", CGROUP_BASE, sanitized);
    let mut cgroup_id: Option<u64> = None;

    if is_pure_v2 {
        // Create per-target cgroup under /sys/fs/cgroup/oxy/target_<name>/
        fs::create_dir_all(&target_cg_path).context(format!(
            "failed to create cgroup v2 directory for target '{}'. Is cgroup2 mounted?",
            target
        ))?;

        // Move all PIDs into the target cgroup
        for pid in &pids {
            let procs_path = format!("{}/cgroup.procs", target_cg_path);
            if Path::new(&procs_path).exists() {
                let _ = fs::write(&procs_path, pid.to_string());
            }
        }

        // Read the cgroup.id for nftables socket cgroupv2 matching
        let cg_id_path = format!("{}/cgroup.id", target_cg_path);
        cgroup_id = if Path::new(&cg_id_path).exists() {
            fs::read_to_string(&cg_id_path)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        } else {
            None
        };

    }

    // Phase 2: Create records for each PID
    let mut applied_count = 0;
    for pid in &pids {
        let class_id = next_class_id()?;

        if !is_pure_v2 {
            // For v1/hybrid: create per-PID cgroup and ignore cgroup_id
            let _ = setup_cgroup(*pid, class_id);
        }

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
            cgroup_id,
            target_cgroup_path: if is_pure_v2 {
                Some(target_cg_path.clone())
            } else {
                None
            },
            uid: None,
        };

        state.limits.push(record);
        applied_count += 1;
    }

    // Save state (needed before computing per-target tc objects)
    state.save()?;

    // Phase 3: Create per-target egress tc objects (HTB class + cgroup filter).
    // Compute minimum upload rate across all active limits for this target.
    let mut target_min_ul: HashMap<String, u64> = HashMap::new();
    for record in &state.limits {
        let ul_kbit = record
            .upload_bytes_per_sec
            .map(|bps| (bps * 8) / 1000)
            .unwrap_or(100_000_000);
        let san = sanitize_target_name(&record.target);
        target_min_ul
            .entry(san)
            .and_modify(|min| *min = (*min).min(ul_kbit))
            .or_insert(ul_kbit);
    }

    let tid = target_class_id(&sanitized);
    let class_id_str = format!("1:{:04x}", tid);

    let mut tx = TcTransaction::new();

    if let Some(&ul_kbit) = target_min_ul.get(&sanitized) {
        let ceil_kbit = (ul_kbit as f64 * 1.1) as u64;

        // --- Upload (egress): HTB class for this target ---
        // Pre-delete existing class to make the operation idempotent.
        let _ = Command::new("tc")
            .args(["class", "del", "dev", &interface, "classid", &class_id_str])
            .output();

        tx.add(
            &format!("egress class for target {}", target),
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

        // --- Upload (egress): fw filter matching mark → target HTB class ---
        // On pure v2, nftables output chain sets meta mark per target cgroup.
        // The tc fw filter routes marked packets to the correct HTB class.
        // Pre-delete existing filter to make the operation idempotent.
        if is_pure_v2 {
            let _ = Command::new("tc")
                .args([
                    "filter",
                    "del",
                    "dev",
                    &interface,
                    "parent",
                    "1:0",
                    "protocol",
                    "ip",
                    "prio",
                    "100",
                    "handle",
                    &tid.to_string(),
                    "fw",
                ])
                .output();

            tx.add(
                &format!("egress fw filter for target {}", target),
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
                    tid.to_string(),
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
                    tid.to_string(),
                    "fw".into(),
                ],
            );
        }
    }

    if let Err(e) = tx.execute() {
        eprintln!("{}: Failed to apply tc rules: {}", "ERROR".red().bold(), e);
        // Rollback cgroups
        for pid in &pids {
            let _ = remove_cgroup(*pid);
        }
        return Err(e);
    }

    // Refresh nftables rules (download chain with socket cgroupv2)
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!(
            "{}: Failed to apply nft packet marking rules: {}",
            "ERROR".red().bold(),
            e
        );
        eprintln!(
            "  {} Without nftables rules, download packets will not be rate-limited.",
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
        println!(
            "  Download:  {} (limited, socket cgroupv2 + nftables policer)",
            dl.cyan()
        );
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
        "  Backend:   nftables + HTB | cgroup v{}",
        if use_cgroup_v1_backend {
            "1/hybrid"
        } else {
            "2"
        }
    );
    println!("  Applied:   {} process(es)", applied_count);

    if is_pure_v2 {
        println!("  Cgroup:    {} (per-target isolation)", target_cg_path);
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

    let mut state = OxyState::load()?;
    let target_lower = target.to_lowercase();
    let mut removed_count = 0;
    let mut to_remove = Vec::new();

    // Strategy 1: Match by target name in state file (works even if process has exited).
    // This is the primary lookup — it ensures cleanup always works regardless of
    // whether the target process is still running.
    for (idx, record) in state.limits.iter().enumerate() {
        let rec_lower = record.target.to_lowercase();
        let matches = rec_lower == target_lower
            || rec_lower.contains(&target_lower)
            || target_lower.contains(&rec_lower);

        if matches {
            to_remove.push(idx);
        }
    }

    // Strategy 2: If no name match, try matching by numeric PID.
    if to_remove.is_empty() {
        if let Ok(pid) = target.parse::<u32>() {
            for (idx, record) in state.limits.iter().enumerate() {
                if record.pid == pid {
                    to_remove.push(idx);
                }
            }
        }
    }

    // Strategy 3: Try resolving running processes by name (for running processes
    // whose binary name differs from the stored target string).
    if to_remove.is_empty() {
        if let Ok(pids) = resolve_pids(target) {
            for (idx, record) in state.limits.iter().enumerate() {
                if pids.contains(&record.pid) {
                    to_remove.push(idx);
                }
            }
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

    // Collect interfaces for cleanup
    let removed_ifaces: Vec<String> = to_remove
        .iter()
        .map(|&idx| state.limits[idx].interface.clone())
        .collect();

    // Collect sanitized target names of records being removed
    let removed_targets: HashSet<String> = to_remove
        .iter()
        .map(|&idx| sanitize_target_name(&state.limits[idx].target))
        .collect();

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        // Remove per-PID cgroup for this PID (v1/hybrid)
        remove_cgroup(record.pid)?;

        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

    // Clean up per-target tc objects for targets that no longer have any limits.
    // Compute remaining sanitized target names after removal.
    let remaining_targets: HashSet<String> = state
        .limits
        .iter()
        .map(|r| sanitize_target_name(&r.target))
        .collect();

    for san_name in &removed_targets {
        if !remaining_targets.contains(san_name) {
            let tid = target_class_id(san_name);
            let target_class_id_str = format!("1:{:04x}", tid);
            for iface in &removed_ifaces {
                // Remove per-target HTB class
                let _ = Command::new("tc")
                    .args([
                        "class",
                        "del",
                        "dev",
                        iface,
                        "classid",
                        &target_class_id_str,
                    ])
                    .output();
                // Remove per-target fw filter
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
                        &tid.to_string(),
                        "fw",
                    ])
                    .output();
            }

            // Remove per-target cgroup
            let _ = remove_target_cgroup(san_name);
        }
    }

    // Refresh nft rules (removes marking for removed processes)
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
    }

    // Clean up if no limits remain
    if state.limits.is_empty() {
        for iface in &removed_ifaces {
            // Remove the v1/hybrid cgroup filter (no-op if not present)
            let _ = Command::new("tc")
                .args([
                    "filter", "del", "dev", iface, "parent", "1:0", "protocol", "ip", "prio", "1",
                    "cgroup",
                ])
                .output();
        }

        // Clean up all per-target cgroups
        for san_name in &removed_targets {
            let _ = remove_target_cgroup(san_name);
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
            println!("  Download:  {} (socket cgroupv2 + nftables policer)", dl);
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

    // Collect sanitized target names of records being removed
    let removed_targets: HashSet<String> = to_remove
        .iter()
        .map(|&idx| sanitize_target_name(&state.limits[idx].target))
        .collect();

    // Collect interfaces for cleanup
    let removed_ifaces: HashSet<String> = to_remove
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

    // Clean up per-target tc objects for targets that no longer have any limits.
    let remaining_targets: HashSet<String> = state
        .limits
        .iter()
        .map(|r| sanitize_target_name(&r.target))
        .collect();

    for san_name in &removed_targets {
        if !remaining_targets.contains(san_name) {
            let tid = target_class_id(san_name);
            let target_class_id_str = format!("1:{:04x}", tid);
            for iface in &removed_ifaces {
                let _ = Command::new("tc")
                    .args([
                        "class",
                        "del",
                        "dev",
                        iface,
                        "classid",
                        &target_class_id_str,
                    ])
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
                        &tid.to_string(),
                        "fw",
                    ])
                    .output();
            }

            // Remove per-target cgroup
            let _ = remove_target_cgroup(san_name);
        }
    }

    // Refresh nft rules
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
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

/// Emergency cleanup: remove ALL oxy state, nftables rules, tc objects, and cgroups.
///
/// This is the "nuclear option" for when normal unstrict fails — for example,
/// when the target process has exited and the system's cgroup delegation has
/// been corrupted by oxy writing PIDs to the root cgroup.
///
/// Call with: `oxy clean --all`
pub fn emergency_cleanup() -> Result<()> {
    check_root()?;

    println!(
        "{}",
        "oxy clean: performing full emergency cleanup..."
            .yellow()
            .bold()
    );

    // 1. Remove nftables inet oxy table (stops all packet marking/rate limiting)
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "oxy"])
        .output();
    println!("  {} Removed nftables inet oxy table", "✓".green());

    // 2. Remove HTB qdisc and all oxy classes/filters on all interfaces
    let interfaces = list_interfaces();
    for iface in &interfaces {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "root", "handle", "1:"])
            .output();
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "ingress"])
            .output();
    }
    println!(
        "  {} Removed tc qdiscs on {} interface(s)",
        "✓".green(),
        interfaces.len()
    );

    // 3. Remove all oxy cgroups (per-target and per-PID)
    let oxy_base = Path::new(CGROUP_BASE);
    if oxy_base.exists() {
        // Remove all sub-cgroups (target_* and pid_*)
        if let Ok(entries) = fs::read_dir(oxy_base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Evict any living processes to parent oxy cgroup (NOT root)
                    let procs_path = path.join("cgroup.procs");
                    if procs_path.exists() {
                        if let Ok(content) = fs::read_to_string(&procs_path) {
                            for pid_str in content.lines() {
                                if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                                    // Skip dead processes
                                    if !std::path::Path::new(&format!("/proc/{}", proc_pid))
                                        .exists()
                                    {
                                        continue;
                                    }
                                    // Move to parent oxy cgroup, NOT system root
                                    let parent_procs = format!("{}/cgroup.procs", CGROUP_BASE);
                                    if Path::new(&parent_procs).exists() {
                                        let _ = fs::write(&parent_procs, proc_pid.to_string());
                                    }
                                }
                            }
                        }
                    }
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }
        // Remove the base oxy cgroup itself
        let _ = fs::remove_dir(CGROUP_BASE);
        println!("  {} Removed all oxy cgroups", "✓".green());
    } else {
        println!("  {} No oxy cgroups found", "✓".dimmed());
    }

    // 4. Remove state files
    if Path::new(STATE_DIR).exists() {
        let _ = fs::remove_dir_all(STATE_DIR);
        println!("  {} Removed state directory {}", "✓".green(), STATE_DIR);
    } else {
        println!("  {} No state directory found", "✓".dimmed());
    }

    println!();
    println!(
        "{}",
        "oxy clean: all oxy state has been removed".green().bold()
    );
    println!(
        "  {} System should now be fully restored.",
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

    let (cg_is_v2, cg_is_hybrid) = detect_cgroup_version();
    let is_pure_v2 = cg_is_v2 && !cg_is_hybrid;

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

        for &new_pid in &new_pids {
            if is_pure_v2 {
                // On pure cgroup v2: move respawned PID to per-target cgroup
                let san = sanitize_target_name(&record.target);
                let target_cg_path = format!("{}/target_{}", CGROUP_BASE, san);
                let procs_path = format!("{}/cgroup.procs", target_cg_path);
                if Path::new(&procs_path).exists() {
                    let _ = fs::write(&procs_path, new_pid.to_string());
                }
            } else {
                // On cgroup v1/hybrid: create per-PID cgroup as before
                let (cgroup_path, _) = setup_cgroup(new_pid, record.class_id)?;
                let procs_path = format!("{}/cgroup.procs", cgroup_path);
                if Path::new(&procs_path).exists() {
                    let _ = fs::write(&procs_path, new_pid.to_string());
                }
            }
        }

        // Update record with first new PID as primary
        state.limits[idx].pid = first_pid;
        state.limits[idx].applied_at = chrono_now();

        println!("  {} Re-applied limits to PID {}", "✓".green(), first_pid);
    }

    // Save updated state
    state.save()?;

    // Refresh nft rules to pick up new cgroup memberships
    if let Err(e) = refresh_nft_ip_rules(&state.limits) {
        eprintln!(
            "{}: Failed to refresh nft rules after respawn: {}",
            "WARNING".yellow(),
            e
        );
    }

    println!();
    println!("{}", "oxy: respawn handling complete".green().bold());

    Ok(())
}
