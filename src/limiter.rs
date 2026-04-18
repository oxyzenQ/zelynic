/// Bandwidth limiting module using Linux traffic control (tc) and cgroups.
///
/// This module implements per-process bandwidth limiting by:
/// 1. Creating an HTB (Hierarchical Token Bucket) qdisc on the network interface
/// 2. Creating traffic classes with configurable rate limits
/// 3. Using cgroup net_cls to tag traffic from specific processes
/// 4. Using tc filters to route tagged traffic to the appropriate class
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
        "sch_htb",      // HTB qdisc
        "cls_fw",       // fw classifier (fwmark-based routing)
        "sch_ingress",  // ingress qdisc
        "act_mirred",   // mirred action (for IFB redirect)
        "nf_conntrack", // conntrack (for mark propagation to download traffic)
    ];

    for module in modules {
        // Use modprobe to load modules. Ignore errors; they may be built-in.
        let _ = Command::new("modprobe").arg(module).output();
    }

    Ok(())
}

/// Get the UID of a process.
///
/// Used with nftables `meta uid` to match packets from specific users.
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

/// Ensure netfilter conntrack is enabled for mark propagation.
///
/// Required for download (ingress) limiting via conntrack mark restore.
/// Conntrack saves the packet mark on outgoing packets and restores it
/// on reply packets, allowing us to classify download traffic on IFB.
fn ensure_conntrack() -> Result<()> {
    // Ensure nf_conntrack module is loaded
    let _ = Command::new("modprobe").args(["nf_conntrack"]).output();

    // Enable conntrack accounting and mark preservation
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

/// Apply (or refresh) the nftables oxy table.
///
/// Completely replaces the table so no stale per-process rules remain.
/// If no limits are active, the table is deleted entirely.
fn refresh_nft_rules(limits: &[LimitRecord]) -> Result<()> {
    if limits.is_empty() {
        // Nothing to mark; remove the table if it exists
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", "oxy"])
            .output();
        return Ok(());
    }

    // Build ip table with conntrack mark propagation
    let mut ruleset = String::new();
    ruleset.push_str("table ip oxy {\n");

    // Output: mark egress packets by UID
    ruleset.push_str("  chain output {\n");
    ruleset.push_str("    type filter hook output priority mangle; policy accept;\n");

    let mut seen_pids = std::collections::HashMap::new();
    for record in limits {
        seen_pids.insert(record.pid, record.class_id);
    }
    for (pid, mark) in &seen_pids {
        if let Some(uid) = get_process_uid(*pid) {
            ruleset.push_str(&format!(
                "    meta skuid {} counter meta mark set {};\n",
                uid, mark
            ));
        }
    }
    ruleset.push_str("  }\n");

    // Postrouting: save mark into conntrack for reply packets
    ruleset.push_str("  chain postrouting {\n");
    ruleset.push_str("    type filter hook postrouting priority srcnat; policy accept;\n");
    ruleset.push_str("    meta mark != 0 ct mark set meta mark;\n");
    ruleset.push_str("  }\n");

    // Prerouting: restore mark from conntrack for incoming packets
    ruleset.push_str("  chain prerouting {\n");
    ruleset.push_str("    type filter hook prerouting priority dstnat; policy accept;\n");
    ruleset.push_str("    ct mark != 0 counter meta mark set ct mark;\n");
    ruleset.push_str("  }\n");

    ruleset.push_str("}\n");

    // Write ruleset to a temp file then load it atomically
    let nft_file = "/run/oxy/oxy.nft";
    fs::create_dir_all(STATE_DIR).ok();
    fs::write(nft_file, &ruleset).context("failed to write nft ruleset file")?;

    // Delete existing table first (ignore error if it doesn't exist yet)
    let _ = Command::new("nft")
        .args(["delete", "table", "ip", "oxy"])
        .output();

    // Load the new ruleset
    let output = Command::new("nft")
        .args(["-f", nft_file])
        .output()
        .context("failed to run nft. Is nftables installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "failed to apply nft ruleset: {}",
            stderr
        );
    }

    Ok(())
}
/// The next available class ID counter file.
const CLASS_ID_FILE: &str = "/run/oxy/.next_class_id";

/// Transactional tc command executor with rollback support.
///
/// Ensures atomicity of tc operations: either all commands succeed,
/// or all are rolled back to maintain consistent state.
struct TcTransaction {
    /// List of (description, command_args, rollback_args) tuples
    commands: Vec<(String, Vec<String>, Vec<String>)>,
    /// Track which commands were successfully executed (for rollback)
    executed: Vec<(String, Vec<String>)>,
}

impl TcTransaction {
    /// Create a new empty transaction.
    fn new() -> Self {
        Self {
            commands: Vec::new(),
            executed: Vec::new(),
        }
    }

    /// Add a tc command with its corresponding rollback command.
    ///
    /// # Arguments
    /// * `desc` - Description of the operation
    /// * `cmd_args` - Arguments for the tc command to execute
    /// * `rollback_args` - Arguments to undo this command if rollback needed
    fn add(&mut self, desc: &str, cmd_args: Vec<String>, rollback_args: Vec<String>) {
        self.commands
            .push((desc.to_string(), cmd_args, rollback_args));
    }

    /// Execute all commands in the transaction.
    ///
    /// If any command fails, automatically rollback all previously
    /// executed commands and return an error.
    fn execute(mut self) -> Result<()> {
        // Take ownership of commands to avoid partial move issues
        let commands = std::mem::take(&mut self.commands);

        for (desc, cmd_args, rollback_args) in commands {
            // Execute the command
            let output = Command::new("tc").args(&cmd_args).output();

            match output {
                Ok(o) if o.status.success() => {
                    // Command succeeded, track it for potential rollback
                    self.executed.push((desc.clone(), rollback_args));
                }
                Ok(o) => {
                    // Command failed - check if it's a "file exists" error (idempotent)
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if stderr.contains("File exists") {
                        // Already exists, consider it success but don't add to rollback
                        // (we don't want to delete existing rules on rollback)
                        continue;
                    }

                    // Command failed - rollback previously executed commands
                    eprintln!(
                        "{}: Command '{}' failed: {}",
                        "ERROR".red().bold(),
                        desc,
                        stderr
                    );
                    // Rollback in reverse order
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
                    // Failed to execute command
                    eprintln!(
                        "{}: Failed to execute command '{}': {}",
                        "ERROR".red().bold(),
                        desc,
                        e
                    );
                    // Rollback in reverse order
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

/// Persistent record of an active bandwidth limit for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitRecord {
    /// Target process name (as provided by user)
    pub target: String,
    /// Process ID at the time the limit was applied
    pub pid: u32,
    /// Download rate limit in bytes per second (None = no limit)
    pub download_bytes_per_sec: Option<u64>,
    /// Upload rate limit in bytes per second (None = no limit)
    pub upload_bytes_per_sec: Option<u64>,
    /// Human-readable download limit string (e.g., "500kb")
    pub download_display: Option<String>,
    /// Human-readable upload limit string (e.g., "500kb")
    pub upload_display: Option<String>,
    /// Network interface the limit is applied on
    pub interface: String,
    /// TC class ID assigned to this limit
    pub class_id: u32,
    /// Timestamp when the limit was applied
    pub applied_at: String,
}

/// Full state file structure containing all active limits.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OxyState {
    /// Currently active bandwidth limits
    pub limits: Vec<LimitRecord>,
}

impl OxyState {
    /// Load state from disk, or return empty state if not found.
    pub fn load() -> Result<Self> {
        if !Path::new(STATE_FILE).exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(STATE_FILE).context("failed to read oxy state file")?;
        let state: OxyState =
            serde_json::from_str(&content).context("failed to parse oxy state file")?;
        Ok(state)
    }

    /// Save state to disk.
    pub fn save(&self) -> Result<()> {
        // Ensure state directory exists
        fs::create_dir_all(STATE_DIR).context("failed to create oxy state directory")?;

        let content =
            serde_json::to_string_pretty(self).context("failed to serialize oxy state")?;
        fs::write(STATE_FILE, content).context("failed to write oxy state file")?;
        Ok(())
    }
}

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
///
/// Parses the output of `ip route show default` to find the interface
/// that handles the system's default network traffic.
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

    // Try to find "dev <name>" pattern directly
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
///
/// If the target is numeric, it's treated as a PID directly.
/// If the target is a string, it's matched against running process names
/// via /proc filesystem scanning.
pub fn resolve_pids(target: &str) -> Result<Vec<u32>> {
    // If the target is a numeric PID
    if let Ok(pid) = target.parse::<u32>() {
        // Verify the process exists
        if Path::new(&format!("/proc/{}", pid)).exists() {
            return Ok(vec![pid]);
        } else {
            bail!("process with PID {} not found", pid);
        }
    }

    // Search for processes by name
    let mut pids = Vec::new();
    let proc_dir = Path::new("/proc");

    for entry in fs::read_dir(proc_dir).context("failed to read /proc directory")? {
        let entry = entry?;
        let dir_name = entry.file_name();
        let name_str = dir_name.to_string_lossy();

        // Only consider numeric directories (PIDs)
        if name_str.chars().all(|c| c.is_ascii_digit()) {
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read the process command line
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
                // cmdline is null-separated; take the first part (the binary name)
                let binary_name = cmdline.split('\0').next().unwrap_or("");

                // Extract just the binary name from the full path
                let program_name = binary_name.rsplit('/').next().unwrap_or(binary_name);

                // Match if the program name contains the target (case-insensitive)
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

    // Save next ID
    fs::create_dir_all(STATE_DIR).ok();
    fs::write(CLASS_ID_FILE, (id + 1).to_string()).ok();

    Ok(id)
}

/// Set up the HTB qdisc root on the specified interface if not already present.
///
/// Creates a root HTB (Hierarchical Token Bucket) queueing discipline which
/// serves as the parent for all bandwidth-limiting classes.
fn ensure_htb_qdisc(interface: &str) -> Result<()> {
    // Check if qdisc already exists
    let check = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output()
        .context("failed to check existing tc qdisc")?;

    let stdout = String::from_utf8_lossy(&check.stdout);
    if stdout.contains("qdisc htb 1:") {
        // HTB root qdisc already exists
        return Ok(());
    }

    // Create root HTB qdisc with default class 1:999 (unlimited)
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

    // Create default class (unlimited) for unclassified traffic
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

/// IFB device name for ingress traffic mirroring.
const IFB_DEVICE: &str = "ifb0";

/// Ensure IFB device exists and is up.
///
/// IFB (Intermediate Functional Block) is used to mirror ingress traffic
/// from the main interface, allowing us to apply per-process HTB shaping
/// on the mirrored traffic (which becomes egress from IFB perspective).
fn ensure_ifb_device() -> Result<()> {
    // Check if IFB module is loaded
    let ifb_check = Command::new("ip")
        .args(["link", "show", IFB_DEVICE])
        .output()
        .ok();

    let ifb_exists = ifb_check
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !ifb_exists {
        // Try to load IFB module and create device
        let _ = Command::new("modprobe").args(["ifb", "numifbs=1"]).output();

        // Alternative: create via ip link
        let _ = Command::new("ip")
            .args(["link", "add", IFB_DEVICE, "type", "ifb"])
            .output();
    }

    // Bring up the IFB device
    let output = Command::new("ip")
        .args(["link", "set", IFB_DEVICE, "up"])
        .output()
        .context("failed to bring up IFB device")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to bring up IFB device: {}", stderr);
    }

    Ok(())
}

/// Setup HTB qdisc on IFB device for download shaping.
///
/// This creates the same HTB structure on the IFB device that we use
/// for egress shaping on the main interface.
fn ensure_ifb_htb() -> Result<()> {
    // Check if HTB already exists on IFB
    let check = Command::new("tc")
        .args(["qdisc", "show", "dev", IFB_DEVICE])
        .output()
        .context("failed to check IFB qdisc")?;

    let stdout = String::from_utf8_lossy(&check.stdout);
    if stdout.contains("qdisc htb 1:") {
        return Ok(());
    }

    // Create HTB root on IFB
    let output = Command::new("tc")
        .args([
            "qdisc", "add", "dev", IFB_DEVICE, "root", "handle", "1:", "htb", "default", "999",
        ])
        .output()
        .context("failed to create HTB on IFB")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") {
            bail!("failed to create HTB on IFB: {}", stderr);
        }
    }

    // Create default unlimited class on IFB
    let output = Command::new("tc")
        .args([
            "class", "add", "dev", IFB_DEVICE, "parent", "1:", "classid", "1:999", "htb", "rate",
            "100gbit", "ceil", "100gbit",
        ])
        .output();

    if let Ok(o) = output {
        if !o.status.success() && !String::from_utf8_lossy(&o.stderr).contains("File exists") {
            // Non-fatal, continue
        }
    }

    Ok(())
}

/// Setup redirect from main interface ingress to IFB.
///
/// All ingress traffic on the main interface is mirrored to the IFB device
/// where we can apply per-process HTB shaping.
fn setup_ifb_redirect(interface: &str) -> Result<()> {
    // First ensure IFB device and HTB are ready
    ensure_ifb_device()?;
    ensure_ifb_htb()?;

    // Check if ingress redirect already exists
    let check = Command::new("tc")
        .args(["filter", "show", "dev", interface, "ingress"])
        .output()
        .ok();

    let has_redirect = check
        .as_ref()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("ifb") || stdout.contains("mirred")
        })
        .unwrap_or(false);

    if has_redirect {
        return Ok(());
    }

    // Ensure ingress qdisc exists on main interface
    let ingress_check = Command::new("tc")
        .args(["qdisc", "show", "dev", interface, "ingress"])
        .output()
        .ok();

    let ingress_exists = ingress_check
        .as_ref()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("ingress")
        })
        .unwrap_or(false);

    if !ingress_exists {
        let _ = Command::new("tc")
            .args(["qdisc", "add", "dev", interface, "ingress"])
            .output();
    }

    // Add redirect filter: all ingress -> IFB
    // Use mirred action to mirror traffic to IFB
    let output = Command::new("tc")
        .args([
            "filter", "add", "dev", interface, "ingress", "protocol", "ip", "prio", "10", "u32",
            "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", IFB_DEVICE,
        ])
        .output()
        .context("failed to setup IFB redirect")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("File exists") && !stderr.contains("directory") {
            bail!("failed to setup IFB redirect: {}", stderr);
        }
    }

    Ok(())
}

/// Create a cgroup for the target process and assign it a net_cls classid.
///
/// Uses cgroup v1 net_cls controller on hybrid systems, or cgroup v2
/// path-based classification on pure v2 systems.
/// The classid is set in hex format: 0x0001XXXX where XXXX is the class ID.
pub fn setup_cgroup(pid: u32, class_id: u32) -> Result<(String, bool)> {
    let cgroup_path = format!("{}/pid_{}", CGROUP_BASE, pid);

    // Detect cgroup version
    let (is_v2, is_hybrid) = detect_cgroup_version();

    if is_v2 && !is_hybrid {
        // Pure cgroup v2 - create under unified hierarchy
        let unified_base = "/sys/fs/cgroup";
        let v2_cgroup_path = format!("{}/oxy/pid_{}", unified_base, pid);
        fs::create_dir_all(&v2_cgroup_path)
            .context("failed to create cgroup v2 directory. Is cgroup2 filesystem mounted?")?;

        // Move the process into this cgroup
        let procs_path = format!("{}/cgroup.procs", v2_cgroup_path);
        if Path::new(&procs_path).exists() {
            fs::write(&procs_path, pid.to_string())
                .context(format!("failed to move PID {} to cgroup v2", pid))?;
        }

        // On pure cgroup v2, we use cgroup.id based classification
        // The cgroup.id file contains a unique ID for this cgroup
        let cg_id_path = format!("{}/cgroup.id", v2_cgroup_path);
        if Path::new(&cg_id_path).exists() {
            return Ok((v2_cgroup_path, true));
        }

        // Fallback: use path-based matching (requires newer tc)
        return Ok((v2_cgroup_path, true));
    }

    // cgroup v1 or hybrid - use net_cls
    fs::create_dir_all(&cgroup_path)
        .context("failed to create cgroup directory. Is cgroup filesystem mounted?")?;

    // Set net_cls classid (major:1, minor:class_id) in hex
    let classid_hex = format!("0x0001{:04x}", class_id);
    let classid_path = format!("{}/net_cls.classid", cgroup_path);

    // Check if net_cls.classid exists (cgroup v1 or hybrid)
    if Path::new(&classid_path).exists() {
        fs::write(&classid_path, &classid_hex).context("failed to set net_cls.classid")?;
    } else if is_hybrid {
        // Hybrid mode but net_cls not available in this subtree
        // Use cgroup v2 approach
        let cg_id_path = format!("{}/cgroup.id", cgroup_path);
        if Path::new(&cg_id_path).exists() {
            return Ok((cgroup_path, true));
        }
    }

    // Move the process into this cgroup
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

    // Detect cgroup version to determine correct root cgroup path
    let (is_v2, is_hybrid) = detect_cgroup_version();

    // Read PIDs in the cgroup and move them to root
    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    if Path::new(&procs_path).exists() {
        if let Ok(content) = fs::read_to_string(&procs_path) {
            for pid_str in content.lines() {
                if let Ok(proc_pid) = pid_str.trim().parse::<u32>() {
                    // Move back to root cgroup
                    // On pure cgroup v2, root is /sys/fs/cgroup; on v1/hybrid, use CGROUP_BASE
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

    // Remove the cgroup directory
    // cgroup v2 directories must be removed with rmdir (remove_dir), not remove_dir_all
    // Retry a few times in case processes are still draining
    let mut removed = false;
    for _ in 0..5 {
        match fs::remove_dir(&cgroup_path) {
            Ok(()) => {
                removed = true;
                break;
            }
            Err(_) => {
                // Re-read and move any remaining processes
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
        // Final attempt - report error if still failing
        fs::remove_dir(&cgroup_path).context("failed to remove cgroup directory")?;
    }

    Ok(())
}

/// Apply a bandwidth limit (strict) to a target process.
///
/// This is the main entry point for the `oxy strict` command. It:
/// 1. Resolves the target to one or more PIDs
/// 2. Sets up tc qdisc and classes
/// 3. Creates cgroups and moves processes
/// 4. Persists the state for later cleanup
pub fn apply_limit(
    target: &str,
    download: Option<&str>,
    upload: Option<&str>,
    download_only: bool,
    upload_only: bool,
) -> Result<()> {
    check_root()?;

    // Validate: at least one direction must be specified
    if download.is_none() && upload.is_none() && !download_only && !upload_only {
        bail!(
            "no bandwidth limit specified.\n  {} Usage: oxy strict -d <rate> -u <rate> <target>",
            "ERROR:".red().bold()
        );
    }

    // Parse rate values
    let download_rate = download.map(BandwidthRate::parse).transpose()?;
    let upload_rate = upload.map(BandwidthRate::parse).transpose()?;

    // Handle "only" flags
    let (dl_bps, ul_bps, dl_display, ul_display) = if download_only {
        // Limit only download direction
        let rate = download_rate.context("download rate required with -d only")?;
        (Some(rate.bytes_per_sec), None, Some(rate.raw.clone()), None)
    } else if upload_only {
        // Limit only upload direction
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

    // Resolve target to PIDs
    let pids = resolve_pids(target)?;
    let interface = get_default_interface()?;

    // Ensure necessary kernel modules are loaded
    if let Err(e) = ensure_kernel_modules() {
        eprintln!(
            "{}: Failed to ensure kernel modules: {}",
            "WARNING".yellow(),
            e
        );
    }

    // Set up HTB qdisc
    ensure_htb_qdisc(&interface)?;

    // Detect cgroup version for backend selection
    let (cg_is_v2, cg_is_hybrid) = detect_cgroup_version();
    let use_cgroup_v1_backend = !cg_is_v2 || cg_is_hybrid;

    // Ensure conntrack for download (ingress) limiting via mark propagation
    if dl_bps.is_some() {
        if let Err(e) = ensure_conntrack() {
            eprintln!(
                "{}: conntrack setup failed: {}. Download limiting may not work.",
                "WARNING".yellow(),
                e
            );
        }
    }

    // For cgroup v1/hybrid, add tc cgroup filter for reliable egress classification.
    // This catches existing connections that nftables socket cgroupv2 would miss,
    // because tc cgroup reads the current task's net_cls.classid at send time
    // rather than the socket's cgroup at creation time.
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

    // Apply limits to each PID
    let mut applied_count = 0;
    for pid in &pids {
        let class_id = next_class_id()?;
        let _process_name = get_process_name(*pid);

        // Set up cgroup (returns path and is_v2 flag)
        let (_cgroup_path, _is_cgroup_v2) = setup_cgroup(*pid, class_id)?;

        // Create tc class for this process
        // Download limit (ingress): controlled via a class on the IFB device or using police
        // Upload limit (egress): controlled via the main HTB class
        let rate_kbit = if let Some(bps) = ul_bps {
            // Convert bytes/sec to kilobits/sec for tc
            (bps * 8) / 1000
        } else {
            // Default to a very high ceiling if only download is limited
            100_000_000 // 100 Gbit/s
        };

        let ceil_kbit = (rate_kbit as f64 * 1.1) as u64; // 10% burst allowance

        // Create the egress class (upload)
        let class_id_str = format!("1:{:04x}", class_id);

        // Build transaction for tc commands (with rollback support)
        let mut tx = TcTransaction::new();

        // Add egress class (upload) with rollback
        tx.add(
            &format!("egress class for PID {}", pid),
            vec![
                "class".to_string(),
                "add".to_string(),
                "dev".to_string(),
                interface.clone(),
                "parent".to_string(),
                "1:".to_string(),
                "classid".to_string(),
                class_id_str.clone(),
                "htb".to_string(),
                "rate".to_string(),
                format!("{}kbit", rate_kbit),
                "ceil".to_string(),
                format!("{}kbit", ceil_kbit),
                "burst".to_string(),
                "15k".to_string(),
                "cburst".to_string(),
                "15k".to_string(),
            ],
            vec![
                "class".to_string(),
                "del".to_string(),
                "dev".to_string(),
                interface.clone(),
                "classid".to_string(),
                class_id_str.clone(),
            ],
        );

        // Add egress fw filter to classify marked packets into this process's HTB class
        // nftables marks packets by cgroup in output chain, fw filter classifies by mark
        tx.add(
            &format!("egress fw filter for PID {}", pid),
            vec![
                "filter".to_string(),
                "add".to_string(),
                "dev".to_string(),
                interface.clone(),
                "parent".to_string(),
                "1:0".to_string(),
                "protocol".to_string(),
                "ip".to_string(),
                "prio".to_string(),
                "100".to_string(),
                "handle".to_string(),
                class_id.to_string(),
                "fw".to_string(),
                "classid".to_string(),
                class_id_str.clone(),
            ],
            vec![
                "filter".to_string(),
                "del".to_string(),
                "dev".to_string(),
                interface.clone(),
                "parent".to_string(),
                "1:0".to_string(),
                "protocol".to_string(),
                "ip".to_string(),
                "prio".to_string(),
                "100".to_string(),
                "handle".to_string(),
                class_id.to_string(),
                "fw".to_string(),
            ],
        );

        // For download (ingress) limiting, use IFB (Intermediate Functional Block)
        // to mirror traffic and apply per-process HTB shaping
        if let Some(dl_bps) = dl_bps {
            // Setup IFB redirect from main interface (non-transactional, setup only)
            if let Err(e) = setup_ifb_redirect(&interface) {
                eprintln!(
                    "{}: IFB setup failed: {}. Download limiting may not work properly.",
                    "WARNING".yellow(),
                    e
                );
            }

            let dl_rate_kbit = (dl_bps * 8) / 1000;
            let dl_ceil_kbit = (dl_rate_kbit as f64 * 1.1) as u64;

            // Add IFB class for download with rollback
            tx.add(
                &format!("IFB class for PID {}", pid),
                vec![
                    "class".to_string(),
                    "add".to_string(),
                    "dev".to_string(),
                    IFB_DEVICE.to_string(),
                    "parent".to_string(),
                    "1:".to_string(),
                    "classid".to_string(),
                    class_id_str.clone(),
                    "htb".to_string(),
                    "rate".to_string(),
                    format!("{}kbit", dl_rate_kbit),
                    "ceil".to_string(),
                    format!("{}kbit", dl_ceil_kbit),
                    "prio".to_string(),
                    "2".to_string(),
                ],
                vec![
                    "class".to_string(),
                    "del".to_string(),
                    "dev".to_string(),
                    IFB_DEVICE.to_string(),
                    "classid".to_string(),
                    class_id_str.clone(),
                ],
            );

            // Add IFB fw filter: classifies download packets by fw mark
            // The connmark restore happens via nftables prerouting
            tx.add(
                &format!("IFB fw filter for PID {}", pid),
                vec![
                    "filter".to_string(),
                    "add".to_string(),
                    "dev".to_string(),
                    IFB_DEVICE.to_string(),
                    "parent".to_string(),
                    "1:0".to_string(),
                    "protocol".to_string(),
                    "ip".to_string(),
                    "prio".to_string(),
                    "100".to_string(),
                    "handle".to_string(),
                    class_id.to_string(),
                    "fw".to_string(),
                    "classid".to_string(),
                    class_id_str.clone(),
                ],
                vec![
                    "filter".to_string(),
                    "del".to_string(),
                    "dev".to_string(),
                    IFB_DEVICE.to_string(),
                    "parent".to_string(),
                    "1:0".to_string(),
                    "protocol".to_string(),
                    "ip".to_string(),
                    "prio".to_string(),
                    "100".to_string(),
                    "handle".to_string(),
                    class_id.to_string(),
                    "fw".to_string(),
                ],
            );
        }

        // Execute all tc commands atomically with rollback on failure
        if let Err(e) = tx.execute() {
            eprintln!(
                "{}: Failed to apply tc rules for PID {}: {}",
                "ERROR".red().bold(),
                pid,
                e
            );
            // Remove the cgroup we created since tc failed
            let _ = remove_cgroup(*pid);
            continue;
        }

        // Remove any existing record for this PID to avoid duplicates
        state.limits.retain(|r| r.pid != *pid);

        // Create the limit record
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
        };

        state.limits.push(record);
        applied_count += 1;
    }

    // Save state
    state.save()?;

    // Refresh nftables marking rules for all active limits.
    // This is critical: without nftables rules, no packets get marked,
    // and all traffic falls through to the default unlimited class.
    if let Err(e) = refresh_nft_rules(&state.limits) {
        eprintln!(
            "{}: Failed to apply nft packet marking rules: {}",
            "ERROR".red().bold(),
            e
        );
        if !use_cgroup_v1_backend {
            eprintln!(
                "  {} On pure cgroup v2, nftables is required for bandwidth limiting.",
                "NOTE:".yellow()
            );
            eprintln!("  {} Verify: nft list table ip oxy", "NOTE:".yellow());
        }
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
        println!("  Download:  {} (limited)", dl.cyan());
    } else {
        println!("  Download:  {}", "unlimited".dimmed());
    }
    if let Some(ref ul) = ul_display {
        println!("  Upload:    {} (limited)", ul.cyan());
    } else {
        println!("  Upload:    {}", "unlimited".dimmed());
    }
    println!("  Interface: {}", interface);
    println!(
        "  Backend:   {}",
        if use_cgroup_v1_backend {
            format!(
                "tc cgroup + nftables ({})",
                if cg_is_hybrid {
                    "cgroup hybrid"
                } else {
                    "cgroup v1"
                }
            )
        } else {
            "nftables + tc fw + IFB (cgroup v2)".to_string()
        }
    );
    println!("  Applied:   {} process(es)", applied_count);
    println!();
    println!(
        "  {} Use 'oxy unstrict {}' to remove limits.",
        "Info:".yellow(),
        target
    );

    Ok(())
}

/// Remove all bandwidth limits (unstrict) from a target process.
///
/// Cleans up tc classes, filters, and cgroups. Handles cases where
/// the tc rules may have already been removed externally.
pub fn remove_limit(target: &str) -> Result<()> {
    check_root()?;

    // Resolve target
    let pids = resolve_pids(target)?;

    // Load state
    let mut state = OxyState::load()?;

    let mut removed_count = 0;
    let target_lower = target.to_lowercase();

    // Find and remove matching limits
    let mut to_remove = Vec::new();

    for (idx, record) in state.limits.iter().enumerate() {
        let matches = pids.contains(&record.pid)
            || record.target.to_lowercase() == target_lower
            || record.target.to_lowercase().contains(&target_lower)
            || target_lower.contains(&record.target.to_lowercase());

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

    // Collect interfaces from records we're about to remove (for tc cgroup cleanup)
    let removed_ifaces: Vec<String> = to_remove
        .iter()
        .map(|&idx| state.limits[idx].interface.clone())
        .collect();

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        // Remove tc class
        let class_id_str = format!("1:{:04x}", record.class_id);
        Command::new("tc")
            .args([
                "class",
                "del",
                "dev",
                &record.interface,
                "classid",
                &class_id_str,
            ])
            .output()
            .ok();

        // Remove tc fw filter for egress
        Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                &record.interface,
                "parent",
                "1:0",
                "protocol",
                "ip",
                "prio",
                "100",
                "handle",
                &record.class_id.to_string(),
                "fw",
            ])
            .output()
            .ok();

        // Remove IFB fw filter for download
        Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                IFB_DEVICE,
                "parent",
                "1:0",
                "protocol",
                "ip",
                "prio",
                "100",
                "handle",
                &record.class_id.to_string(),
                "fw",
            ])
            .output()
            .ok();

        // Remove IFB class
        Command::new("tc")
            .args(["class", "del", "dev", IFB_DEVICE, "classid", &class_id_str])
            .output()
            .ok();

        // Remove cgroup
        remove_cgroup(record.pid)?;

        // Remove from state
        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

    // Refresh nft rules (removes marking for the removed process)
    if let Err(e) = refresh_nft_rules(&state.limits) {
        eprintln!("{}: Failed to refresh nft rules: {}", "WARNING".yellow(), e);
    }

    // Clean up IFB device and tc qdiscs if no limits remain
    if state.limits.is_empty() {
        let removed_interfaces: std::collections::HashSet<String> = to_remove
            .iter()
            .filter_map(|&idx| removed_ifaces.get(idx).cloned())
            .collect();

        for iface in removed_interfaces {
            // Remove ingress qdisc from main interface
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", &iface, "ingress"])
                .output();
            // Remove root qdisc from main interface
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", &iface, "root"])
                .output();
        }

        // Bring down and delete IFB device
        let _ = Command::new("ip")
            .args(["link", "set", "dev", IFB_DEVICE, "down"])
            .output();
        let _ = Command::new("ip")
            .args(["link", "delete", "dev", IFB_DEVICE, "type", "ifb"])
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

/// List all currently active bandwidth limits.
pub fn list_active_limits() -> Result<()> {
    // First check for process respawns and re-apply limits automatically
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
            println!("  Download:  {}", dl);
        } else {
            println!("  Download:  {}", "unlimited".dimmed());
        }
        if let Some(ref ul) = record.upload_display {
            println!("  Upload:    {}", ul);
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

/// Clean up orphaned bandwidth limits for processes that have exited.
///
/// Scans the state file and removes tc classes, filters, and cgroups
/// for any process that is no longer running.
pub fn clean_orphans() -> Result<()> {
    check_root()?;

    // Load state
    let mut state = OxyState::load()?;

    if state.limits.is_empty() {
        println!("{} No active bandwidth limits to clean.", "Info:".yellow());
        return Ok(());
    }

    let mut removed_count = 0;
    let mut kept_count = 0;

    // Check each limit - process alive?
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

    // Process removals in reverse order to maintain indices
    for &idx in to_remove.iter().rev() {
        let record = &state.limits[idx];

        println!(
            "  Removing stale rules for {} (PID: {}, class: 1:{:04x})...",
            record.target, record.pid, record.class_id
        );

        // Remove tc class
        let class_id_str = format!("1:{:04x}", record.class_id);
        let _ = Command::new("tc")
            .args([
                "class",
                "del",
                "dev",
                &record.interface,
                "classid",
                &class_id_str,
            ])
            .output();

        // Remove tc filter - no longer needed per class since filters are now global

        // Remove legacy ingress filter if it exists

        // Remove IFB class for download limiting (if exists)
        let _ = Command::new("tc")
            .args(["class", "del", "dev", IFB_DEVICE, "classid", &class_id_str])
            .output();

        // Remove IFB filter - no longer needed per class since filters are now global

        // Remove cgroup
        let _ = remove_cgroup(record.pid);

        // Remove from state
        state.limits.remove(idx);
        removed_count += 1;
    }

    // Save updated state
    state.save()?;

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
/// Format: YYYY-MM-DD HH:MM:SS (local time)
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
///
/// Scans active limits and detects when a target process has restarted
/// with a new PID. Automatically re-applies bandwidth limits to the
/// new process instance.
///
/// Called automatically during `oxy status` to keep limits current.
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
        let is_alive = Path::new(&proc_path).exists();

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
            // Set up cgroup for new PID
            let (cgroup_path, _) = setup_cgroup(new_pid, record.class_id)?;

            // Move process to cgroup
            let procs_path = format!("{}/cgroup.procs", cgroup_path);
            if Path::new(&procs_path).exists() {
                let _ = fs::write(&procs_path, new_pid.to_string());
            }
        }

        // Update record with first new PID as primary
        // (Keep the same class_id for tc rules)
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
