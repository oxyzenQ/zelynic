// SPDX-License-Identifier: MIT
/// Bandwidth limiting module using Linux traffic control (tc) and cgroups.
///
/// Architecture:
///
/// **Upload (egress) limiting:**
///   Process (in target cgroup) → tc fw filter → HTB class (rate-limited)
///   On cgroup v1/hybrid: per-PID cgroups with net_cls.classid as fallback.
///
/// **Download (ingress) limiting (nftables ct mark + limit rate):**
///   NIC → nftables inet input (ct mark → limit rate → accept/drop)
///   ct mark is set by the output chain on egress packets via
///   `socket cgroupv2`, then copied to conntrack by the postrouting chain.
///   Reply (download) packets are matched by their ct mark.
///
/// **Per-target cgroups:**
///   All target PIDs are moved to `/sys/fs/cgroup/oxy/target_<sanitized_name>/`
///   so that nftables can match traffic per target:
///   - `socket cgroupv2` (output hook): matches egress from sockets whose
///     cgroup (at creation time) is the target cgroup.  Returns the 64-bit
///     cgroup ID (= kernfs inode on 64-bit kernels).  A brief UID-based
///     egress drop after rule application forces existing connections to
///     re-establish inside the correct cgroup.
///   - `ct mark` (input hook): matches download traffic via conntrack mark.
///
///   On cgroup v1/hybrid, per-PID cgroups with net_cls.classid are used instead.
///
/// **Per-target nftables matching:**
///   Output (egress): `socket cgroupv2 level <depth> == <inode>` → mark → tc HTB
///   Input (download): `ct mark` → limit rate (ingress policing)
///
///   The `level` parameter specifies the depth of the target cgroup in the
///   unified cgroup hierarchy (0 = root).  For oxy's per-target cgroups at
///   `/sys/fs/cgroup/oxy/target_<name>/`, the level is 2.
///
/// NOTE: `meta skuid` is intentionally NOT used — it would leak limits to
/// all processes of the same UID, breaking per-target isolation.
///
/// IMPORTANT: `meta cgroup` in nftables is a cgroup v1-only feature that
/// returns `net_cls.classid`.  On cgroup v2 systems, `socket cgroupv2` must
/// be used instead.  `socket cgroupv2` was added in kernel 5.7.
///
/// State is persisted to disk so that limits survive across invocations
/// and can be cleaned up properly with `oxy unstrict`.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use crate::units::BandwidthRate;

/// Directory where oxy stores its runtime state.
const STATE_DIR: &str = "/run/oxy";
/// Path to the state file containing active bandwidth limits.
const STATE_FILE: &str = "/run/oxy/state.json";
/// Root of the unified cgroup v2 hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
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
        "sch_fq_codel", // Fair Queuing / CoDel (better queuing discipline)
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

fn pid_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn pid_cgroup_v2_line(pid: u32) -> String {
    let cgroup_file = format!("/proc/{}/cgroup", pid);
    match fs::read_to_string(&cgroup_file) {
        Ok(content) => content
            .lines()
            .find(|line| line.starts_with("0::"))
            .unwrap_or("(no cgroup v2 line)")
            .to_string(),
        Err(e) => format!("(failed to read {}: {})", cgroup_file, e),
    }
}

/// Verify that a PID is actually in the expected cgroup.
///
/// Reads /proc/<pid>/cgroup and checks if the target cgroup path appears
/// in the cgroup v2 hierarchy entry (the line starting with "0::").
fn verify_pid_in_cgroup(pid: u32, expected_cg_path: &str) -> bool {
    let cgroup_file = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = fs::read_to_string(&cgroup_file) {
        for line in content.lines() {
            // cgroup v2: "0::/path/to/cgroup"
            if let Some(cg_path) = line.strip_prefix("0::") {
                return cg_path.contains(&expected_cg_path.replace("/sys/fs/cgroup", ""));
            }
        }
    }
    false
}

struct PidCgroupMove {
    moved: bool,
    verified: bool,
    vanished: bool,
    cgroup_line: String,
    error: Option<String>,
}

/// Move a PID to a cgroup with verification and retry.
///
/// Writes the PID to cgroup.procs, then verifies membership.
/// Retries up to 3 times because systemd may immediately move the PID back.
/// Returns structured coverage information for strict diagnostics.
fn move_pid_to_cgroup_with_verify(pid: u32, target_cg_path: &str) -> PidCgroupMove {
    let procs_path = format!("{}/cgroup.procs", target_cg_path);

    if !Path::new(&procs_path).exists() {
        return PidCgroupMove {
            moved: false,
            verified: false,
            vanished: !pid_exists(pid),
            cgroup_line: pid_cgroup_v2_line(pid),
            error: Some(format!("{} does not exist", procs_path)),
        };
    }

    let mut moved = false;
    let mut last_error = None;

    for attempt in 0..3 {
        if !pid_exists(pid) {
            return PidCgroupMove {
                moved,
                verified: false,
                vanished: true,
                cgroup_line: "(process vanished)".to_string(),
                error: last_error,
            };
        }

        if let Err(e) = fs::write(&procs_path, pid.to_string()) {
            last_error = Some(e.to_string());
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        moved = true;

        // Verify the PID is actually in the cgroup
        if verify_pid_in_cgroup(pid, target_cg_path) {
            return PidCgroupMove {
                moved: true,
                verified: true,
                vanished: false,
                cgroup_line: pid_cgroup_v2_line(pid),
                error: None,
            };
        }

        // systemd may have moved the PID back — retry
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    }

    PidCgroupMove {
        moved,
        verified: false,
        vanished: !pid_exists(pid),
        cgroup_line: pid_cgroup_v2_line(pid),
        error: last_error,
    }
}

/// Resolve all PIDs of a process tree (parent + all descendants).
///
/// This is critical for multi-process applications like browsers (Brave, Chrome, Firefox)
/// which spawn many child processes (renderers, GPU, network service, sandbox, etc.).
/// Only the processes that actually do network I/O need to be in the cgroup, but
/// to be safe we move the entire tree.
#[allow(dead_code)]
pub fn resolve_process_tree(root_pids: &[u32]) -> Vec<u32> {
    let mut all_pids = Vec::new();
    let mut queue: std::collections::VecDeque<u32> = root_pids.iter().copied().collect();

    while let Some(pid) = queue.pop_front() {
        if all_pids.contains(&pid) {
            continue;
        }
        all_pids.push(pid);

        // Find children by scanning /proc for processes whose ppid matches
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name_str = entry.file_name().to_string_lossy().to_string();
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let child_pid: u32 = match name_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Read stat to get ppid (format: pid (comm) state ppid ...)
                let stat_path = format!("/proc/{}/stat", child_pid);
                if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                    // The comm field can contain spaces and parentheses, so find
                    // the last ')' and parse from there
                    if let Some(close_paren) = stat_content.rfind(')') {
                        let after_comm = &stat_content[close_paren + 2..];
                        let fields: Vec<&str> = after_comm.split_whitespace().collect();
                        // ppid is the first field after ') state'
                        if fields.len() >= 2 {
                            if let Ok(ppid) = fields[1].parse::<u32>() {
                                if ppid == pid && !all_pids.contains(&child_pid) {
                                    queue.push_back(child_pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    all_pids
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

/// Convert an absolute cgroup v2 path into the relative path nftables expects.
fn relative_cgroupv2_path(full_path: &str, target: &str) -> Result<String> {
    let relative = Path::new(full_path)
        .strip_prefix(CGROUP_ROOT)
        .with_context(|| {
            format!(
                "failed to compute relative cgroupv2 path\n  full cgroup path: {}\n  expected root: {}\n  target: {}",
                full_path, CGROUP_ROOT, target
            )
        })?
        .to_string_lossy()
        .trim_matches('/')
        .to_string();

    if relative.is_empty() {
        bail!(
            "failed to compute relative cgroupv2 path\n  full cgroup path: {}\n  expected root: {}\n  target: {}",
            full_path,
            CGROUP_ROOT,
            target
        );
    }

    Ok(relative)
}

/// Calculate the cgroup hierarchy depth from a relative cgroup v2 path.
fn cgroup_level_from_relative(relative_path: &str) -> u32 {
    let relative_path = relative_path.trim_matches('/');
    if relative_path.is_empty() {
        0
    } else {
        relative_path
            .split('/')
            .filter(|component| !component.is_empty())
            .count() as u32
    }
}

/// Calculate the cgroup hierarchy depth for diagnostics.
fn cgroup_level(cg_path: Option<&str>) -> u32 {
    match cg_path {
        Some(path) => relative_cgroupv2_path(path, "unknown")
            .map(|relative| cgroup_level_from_relative(&relative))
            .unwrap_or(2),
        None => 2,
    }
}

/// Escape a string for use inside an nftables quoted string literal.
fn escape_nft_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn diagnostic_command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            format!(
                "status={} stdout={} stderr={}",
                output.status,
                if stdout.is_empty() {
                    "(empty)"
                } else {
                    &stdout
                },
                if stderr.is_empty() {
                    "(empty)"
                } else {
                    &stderr
                }
            )
        }
        Err(e) => format!("failed to run: {}", e),
    }
}

fn cgroup_mode_label_from_flags(is_v2: bool, is_hybrid: bool) -> &'static str {
    match (is_v2, is_hybrid) {
        (true, true) => "hybrid (cgroup v2 + v1 controllers)",
        (true, false) => "pure cgroup v2",
        (false, false) => "cgroup v1",
        (false, true) => "unknown hybrid state",
    }
}

fn cgroup_mode_label() -> &'static str {
    let (is_v2, is_hybrid) = detect_cgroup_version();
    cgroup_mode_label_from_flags(is_v2, is_hybrid)
}

fn cgroup2_mount_info_from_mountinfo(content: &str) -> String {
    let lines: Vec<&str> = content
        .lines()
        .filter(|line| line.contains(" - cgroup2 "))
        .collect();
    if lines.is_empty() {
        "(no cgroup2 mount found in /proc/self/mountinfo)".to_string()
    } else {
        lines.join("\n")
    }
}

fn cgroup2_mount_info() -> String {
    match fs::read_to_string("/proc/self/mountinfo") {
        Ok(content) => cgroup2_mount_info_from_mountinfo(&content),
        Err(e) => format!("(failed to read /proc/self/mountinfo: {})", e),
    }
}

fn print_strict_diagnostic_header(
    target: &str,
    pids: &[u32],
    target_cg_path: &str,
    relative_cg_path: &str,
    level: u32,
) {
    println!("{}", "Strict backend diagnostics".bold());
    println!("  target: {}", target);
    println!("  kernel: {}", diagnostic_command_output("uname", &["-r"]));
    println!(
        "  nft: {}",
        diagnostic_command_output("nft", &["--version"])
    );
    println!("  tc: {}", diagnostic_command_output("tc", &["-V"]));
    println!("  cgroup mode: {}", cgroup_mode_label());
    println!("  cgroup2 mount info:\n{}", cgroup2_mount_info());
    println!("  target PIDs: {:?}", pids);
    println!("  target cgroup absolute path: {}", target_cg_path);
    println!("  target cgroup nft relative path: {}", relative_cg_path);
    println!("  computed cgroup level: {}", level);
}

fn print_state_file_diagnostic() {
    println!("strict diagnostic: state file path: {}", STATE_FILE);
    match fs::read_to_string(STATE_FILE) {
        Ok(content) => println!("strict diagnostic: state file contents:\n{}", content),
        Err(e) => println!("strict diagnostic: failed to read state file: {}", e),
    }
}

fn is_chromium_based_target(target: &str) -> bool {
    let target = target.to_lowercase();
    target.contains("brave") || target.contains("chrome") || target.contains("chromium")
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
/// download rate limiting via cgroup matching.
///
/// Uses `inet` (IPv4 + IPv6) so both protocol families are handled.
///
/// Architecture (per-target isolation via cgroup v2):
///
/// **Output chain**: marks egress packets for tc fw filter upload shaping.
///   - `socket cgroupv2 level <depth> "<path>"` — matches egress packets
///     whose socket belongs to the target cgroup at the specified hierarchy
///     depth.  Level 0 is the root cgroup, level 1 is the first child, etc.
///     For oxy's cgroups at `/oxy/target_<name>/`, level 2 matches the
///     socket's own cgroup.
///     NOTE: sockets created BEFORE the PID was moved retain their
///     original cgroup and will NOT be matched.  To handle this, oxy
///     briefly drops all egress from the target UID after applying the
///     rules, forcing existing connections to re-establish with new
///     sockets inside the target cgroup.
///
///   NOTE: `meta skuid` is intentionally NOT used for packet marking —
///   it would leak marks to all processes of the same UID, breaking
///   per-target isolation.
///
///   NOTE: `meta cgroup` is NOT used because it only works with cgroup v1
///   `net_cls.classid`.  On cgroup v2 systems, `socket cgroupv2` must be
///   used instead (available since kernel 5.7).
///
/// **Postrouting chain**: saves the fw mark into conntrack for reply packets.
///   This is critical: download packets arrive as replies to egress packets.
///   The ct mark lets us identify which download packets belong to limited
///   connections, even for connections that predate the cgroup assignment.
///
/// **Download chain**: rate-limits inbound traffic at the input hook.
///   Uses `ct mark <target_hash>` for connections whose egress was marked
///   by the output chain.  After force-reconnect, all active connections
///   will have been re-established with sockets inside the target cgroup,
///   so their egress is correctly marked and replies are rate-limited.
///
///   NOTE: `meta skuid` is intentionally NOT used — it would leak
///   limits to all processes of the same UID, breaking per-target isolation.
fn build_nft_ip_ruleset(limits: &[LimitRecord]) -> Result<String> {
    let mut ruleset = String::new();
    ruleset.push_str("table inet oxy {\n");

    // ---- Output chain: mark egress packets ----
    ruleset.push_str("  chain output {\n");
    ruleset.push_str("    type filter hook output priority mangle; policy accept;\n");

    // socket cgroupv2 — per-target (all egress, including pre-existing sockets)
    //
    // The `level` parameter specifies the depth of the cgroup in the unified
    // hierarchy (0 = root).  For oxy's cgroups at /sys/fs/cgroup/oxy/target_<name>/,
    // the depth is always 2 (oxy + target_name).  This is required by nftables
    // to correctly resolve the cgroup path during rule validation.
    //
    // From the nftables(8) man page:
    //   "if the socket belongs to cgroupv2 a/b, ancestor level 1 checks for
    //    a matching on cgroup a and ancestor level 2 checks for a matching
    //    on cgroup b"
    // So level = depth from root, where level 0 is the root cgroup.
    let mut cg_info: HashMap<String, (u32, u32)> = HashMap::new(); // relative path -> (mark, level)
    for record in limits {
        if record.cgroup_id.is_some() || record.target_cgroup_path.is_some() {
            let full_path = record.target_cgroup_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "failed to compute relative cgroupv2 path\n  full cgroup path: unavailable\n  expected root: {}\n  target: {}",
                    CGROUP_ROOT,
                    record.target
                )
            })?;
            let relative_path = relative_cgroupv2_path(full_path, &record.target)?;
            let mark = target_class_id(&sanitize_target_name(&record.target));
            let level = cgroup_level_from_relative(&relative_path);
            cg_info.entry(relative_path).or_insert((mark, level));
        }
    }
    for (relative_path, (mark, level)) in &cg_info {
        let escaped_path = escape_nft_string(relative_path);
        ruleset.push_str(&format!(
            "    socket cgroupv2 level {} \"{}\" counter meta mark set {};\n",
            level, escaped_path, mark
        ));
    }

    ruleset.push_str("  }\n");

    // ---- Postrouting chain: save mark to conntrack ----
    ruleset.push_str("  chain postrouting {\n");
    ruleset.push_str("    type filter hook postrouting priority srcnat; policy accept;\n");
    ruleset.push_str("    meta mark != 0 counter ct mark set meta mark;\n");
    ruleset.push_str("  }\n");

    // ---- Download chain: rate-limit inbound traffic ----
    ruleset.push_str("  chain download {\n");
    ruleset.push_str("    type filter hook input priority mangle; policy accept;\n");

    // Collect per-target mark → download rate
    // Download limiting uses ct mark exclusively: the output chain marks
    // egress packets via socket cgroupv2, postrouting copies to ct mark,
    // and the input hook matches ct mark on reply (download) packets.
    let mut mark_dl_info: HashMap<u32, u64> = HashMap::new();
    for record in limits.iter().filter(|l| l.download_bytes_per_sec.is_some()) {
        let dl_bps = record.download_bytes_per_sec.unwrap();
        let mark = target_class_id(&sanitize_target_name(&record.target));
        let entry = mark_dl_info.entry(mark).or_insert(dl_bps);
        *entry = (*entry).min(dl_bps);
    }

    // ct mark — all connections (marked by output chain via socket cgroupv2)
    for (mark, dl_bps) in &mark_dl_info {
        let burst = (*dl_bps / 2).max(65536);
        ruleset.push_str(&format!(
            "    ct mark {} counter limit rate {} bytes/second burst {} bytes accept;\n",
            mark, dl_bps, burst
        ));
        ruleset.push_str(&format!("    ct mark {} counter drop;\n", mark));
    }

    ruleset.push_str("  }\n");
    ruleset.push_str("}\n");
    Ok(ruleset)
}

/// Apply (or refresh) the nftables inet oxy table.
fn refresh_nft_ip_rules(limits: &[LimitRecord]) -> Result<()> {
    refresh_nft_ip_rules_with_diagnostics(limits, false)
}

fn refresh_nft_ip_rules_with_diagnostics(limits: &[LimitRecord], diagnostics: bool) -> Result<()> {
    if limits.is_empty() {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "oxy"])
            .output();
        return Ok(());
    }

    let ruleset = build_nft_ip_ruleset(limits)?;

    let nft_file = "/run/oxy/oxy.nft";
    if diagnostics {
        println!(
            "strict diagnostic: generated nft ruleset path: {}",
            nft_file
        );
        println!("strict diagnostic: generated nft ruleset:\n{}", ruleset);
    }
    fs::create_dir_all(STATE_DIR).ok();
    fs::write(nft_file, &ruleset).context("failed to write nft ruleset file")?;

    let nft_check_cmd = format!("nft -c -f {}", nft_file);
    let check_output = Command::new("nft")
        .args(["-c", "-f", nft_file])
        .output()
        .with_context(|| {
            format!(
                "failed to run nft preflight. Is nftables installed?\n  ruleset: {}\n  command: {}",
                nft_file, nft_check_cmd
            )
        })?;

    if diagnostics {
        println!(
            "strict diagnostic: command `{}` exited with {}",
            nft_check_cmd, check_output.status
        );
        println!(
            "strict diagnostic: nft -c stdout:\n{}",
            String::from_utf8_lossy(&check_output.stdout).trim_end()
        );
        println!(
            "strict diagnostic: nft -c stderr:\n{}",
            String::from_utf8_lossy(&check_output.stderr).trim_end()
        );
    }

    if !check_output.status.success() {
        let stdout = String::from_utf8_lossy(&check_output.stdout);
        let stderr = String::from_utf8_lossy(&check_output.stderr);
        bail!(
            "failed to preflight nft inet table\n  ruleset: {}\n  command: {}\n  stdout:\n{}\n  stderr:\n{}",
            nft_file,
            nft_check_cmd,
            stdout.trim_end(),
            stderr.trim_end()
        );
    }

    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "oxy"])
        .output();

    let nft_apply_cmd = format!("nft -f {}", nft_file);
    let output = Command::new("nft")
        .args(["-f", nft_file])
        .output()
        .with_context(|| {
            format!(
                "failed to run nft. Is nftables installed?\n  ruleset: {}\n  command: {}",
                nft_file, nft_apply_cmd
            )
        })?;

    if diagnostics {
        println!(
            "strict diagnostic: command `{}` exited with {}",
            nft_apply_cmd, output.status
        );
        println!(
            "strict diagnostic: nft -f stdout:\n{}",
            String::from_utf8_lossy(&output.stdout).trim_end()
        );
        println!(
            "strict diagnostic: nft -f stderr:\n{}",
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "failed to apply nft inet table\n  ruleset: {}\n  command: {}\n  stdout:\n{}\n  stderr:\n{}",
            nft_file,
            nft_apply_cmd,
            stdout.trim_end(),
            stderr.trim_end()
        );
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

    fn execute_with_diagnostics(mut self, diagnostics: bool) -> Result<()> {
        let commands = std::mem::take(&mut self.commands);

        for (desc, cmd_args, rollback_args) in commands {
            if diagnostics {
                println!(
                    "strict diagnostic: tc command ({}): tc {}",
                    desc,
                    cmd_args.join(" ")
                );
            }
            let output = Command::new("tc").args(&cmd_args).output();

            match output {
                Ok(o) if o.status.success() => {
                    if diagnostics {
                        println!("strict diagnostic: tc exit status: {}", o.status);
                        println!(
                            "strict diagnostic: tc stdout:\n{}",
                            String::from_utf8_lossy(&o.stdout).trim_end()
                        );
                        println!(
                            "strict diagnostic: tc stderr:\n{}",
                            String::from_utf8_lossy(&o.stderr).trim_end()
                        );
                    }
                    self.executed.push((desc.clone(), rollback_args));
                }
                Ok(o) => {
                    if diagnostics {
                        println!("strict diagnostic: tc exit status: {}", o.status);
                        println!(
                            "strict diagnostic: tc stdout:\n{}",
                            String::from_utf8_lossy(&o.stdout).trim_end()
                        );
                        println!(
                            "strict diagnostic: tc stderr:\n{}",
                            String::from_utf8_lossy(&o.stderr).trim_end()
                        );
                    }
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
    /// Cgroup v2 ID for the per-target cgroup.  This is the kernfs inode
    /// number of the cgroup directory (64-bit on 64-bit kernels).
    /// Used by nftables `socket cgroupv2 level <depth>` (output hook,
    /// egress marking) and `ct mark` (input hook, download policing).
    /// NOTE: `meta cgroup` is NOT used — it only returns cgroup v1
    /// `net_cls.classid`.  `socket cgroupv2` was added in kernel 5.7.
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
    let mut seen = HashSet::new();
    let proc_dir = Path::new("/proc");
    let target_lower = target.to_lowercase();

    for entry in fs::read_dir(proc_dir).context("failed to read /proc directory")? {
        let entry = entry?;
        let dir_name = entry.file_name();
        let name_str = dir_name.to_string_lossy();

        if name_str.chars().all(|c| c.is_ascii_digit()) {
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok();
            let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok();
            let exe = fs::read_link(format!("/proc/{}/exe", pid)).ok();

            let cmdline_match = cmdline
                .as_deref()
                .map(|cmd| {
                    let binary_name = cmd.split('\0').next().unwrap_or("");
                    let program_name = binary_name.rsplit('/').next().unwrap_or(binary_name);
                    program_name.to_lowercase().contains(&target_lower)
                        || cmd
                            .replace('\0', " ")
                            .to_lowercase()
                            .contains(&target_lower)
                })
                .unwrap_or(false);
            let comm_match = comm
                .as_deref()
                .map(|name| name.trim().to_lowercase().contains(&target_lower))
                .unwrap_or(false);
            let exe_match = exe
                .as_ref()
                .and_then(|path| path.file_name())
                .map(|name| {
                    name.to_string_lossy()
                        .to_lowercase()
                        .contains(&target_lower)
                })
                .unwrap_or(false);

            if (cmdline_match || comm_match || exe_match) && seen.insert(pid) {
                pids.push(pid);
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
    apply_limit_with_diagnostics(target, download, upload, iface_override, false)
}

pub fn apply_limit_with_diagnostics(
    target: &str,
    download: Option<&str>,
    upload: Option<&str>,
    iface_override: Option<&str>,
    diagnostics: bool,
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
                    // Remove fw filter for this target (IPv4)
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
                    // Remove fw filter for this target (IPv6)
                    let _ = Command::new("tc")
                        .args([
                            "filter",
                            "del",
                            "dev",
                            iface,
                            "parent",
                            "1:0",
                            "protocol",
                            "ipv6",
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

    // Detect cgroup version (informational)
    let (_cg_is_v2, _cg_is_hybrid) = detect_cgroup_version();

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

    // Load existing state
    let mut state = OxyState::load()?;

    // Phase 1: Create per-target cgroup and read cgroup.id.
    // We always try the v2 approach first, even on hybrid systems,
    // because cgroup.id and cgroup.procs are available in the v2 hierarchy.
    let target_cg_path = format!("{}/target_{}", CGROUP_BASE, sanitized);

    fs::create_dir_all(&target_cg_path).context(format!(
        "failed to create cgroup directory for target '{}'. Is cgroup2 mounted?",
        target
    ))?;

    if diagnostics {
        let relative = relative_cgroupv2_path(&target_cg_path, target)?;
        print_strict_diagnostic_header(
            target,
            &pids,
            &target_cg_path,
            &relative,
            cgroup_level_from_relative(&relative),
        );
        match fs::metadata(&target_cg_path) {
            Ok(metadata) => println!(
                "strict diagnostic: cgroup directory inode: {}",
                metadata.ino()
            ),
            Err(e) => println!("strict diagnostic: failed to stat cgroup directory: {}", e),
        }
        for pid in &pids {
            println!(
                "strict diagnostic: /proc/{}/cgroup before move: {}",
                pid,
                pid_cgroup_v2_line(*pid)
            );
        }
    }

    // Move all discovered PIDs into the target cgroup and verify coverage.
    let discovered_count = pids.len();
    let mut moved_count = 0usize;
    let mut vanished_pids = Vec::new();
    let mut failed_pids = Vec::new();
    let mut verified_pids = Vec::new();

    for pid in &pids {
        let result = move_pid_to_cgroup_with_verify(*pid, &target_cg_path);
        if diagnostics {
            println!(
                "strict diagnostic: write PID {} to {}/cgroup.procs: moved={} verified={} vanished={} error={}",
                pid,
                target_cg_path,
                result.moved,
                result.verified,
                result.vanished,
                result.error.as_deref().unwrap_or("none")
            );
            println!(
                "strict diagnostic: /proc/{}/cgroup after move: {}",
                pid, result.cgroup_line
            );
            println!(
                "strict diagnostic: verification for PID {}: {}",
                pid,
                if result.verified { "passed" } else { "failed" }
            );
        }
        if result.moved {
            moved_count += 1;
        }
        if result.verified {
            verified_pids.push(*pid);
        } else if result.vanished {
            vanished_pids.push(*pid);
        } else {
            failed_pids.push((*pid, result.cgroup_line, result.error));
        }
    }

    if !failed_pids.is_empty() {
        let examples = failed_pids
            .iter()
            .take(5)
            .map(|(pid, line, error)| {
                if let Some(error) = error {
                    format!("PID {}: {} ({})", pid, line, error)
                } else {
                    format!("PID {}: {}", pid, line)
                }
            })
            .collect::<Vec<_>>()
            .join("\n  ");
        let browser_hint = if is_chromium_based_target(target) {
            "\n  Hint: Chromium-based browsers spawn multiple processes; make sure the network service process is in the target cgroup."
        } else {
            ""
        };

        bail!(
            "strict process coverage failed for '{}'\n  discovered: {}\n  moved: {}\n  verified: {}\n  vanished: {}\n  failed: {}\n  failed examples:\n  {}{}",
            target,
            discovered_count,
            moved_count,
            verified_pids.len(),
            vanished_pids.len(),
            failed_pids.len(),
            examples,
            browser_hint
        );
    }

    if verified_pids.is_empty() {
        bail!(
            "none of the discovered PIDs could be verified in cgroup '{}'.\n  discovered: {}\n  moved: {}\n  verified: 0\n  vanished: {}\n  failed: 0",
            target_cg_path,
            discovered_count,
            moved_count,
            vanished_pids.len()
        );
    }

    // Re-check that all still-live matching PIDs are covered before saving state.
    if target.parse::<u32>().is_err() {
        let current_pids = resolve_pids(target)?;
        let mut uncovered = Vec::new();
        for pid in current_pids {
            if !verify_pid_in_cgroup(pid, &target_cg_path) {
                uncovered.push((pid, pid_cgroup_v2_line(pid)));
            }
        }

        if !uncovered.is_empty() {
            let examples = uncovered
                .iter()
                .take(5)
                .map(|(pid, line)| format!("PID {}: {}", pid, line))
                .collect::<Vec<_>>()
                .join("\n  ");
            let browser_hint = if is_chromium_based_target(target) {
                "\n  Hint: Chromium-based browsers spawn multiple processes; make sure the network service process is in the target cgroup."
            } else {
                ""
            };

            bail!(
                "strict process coverage changed while applying '{}'\n  initial discovered: {}\n  moved: {}\n  verified: {}\n  vanished: {}\n  newly uncovered live PIDs: {}\n  uncovered examples:\n  {}{}",
                target,
                discovered_count,
                moved_count,
                verified_pids.len(),
                vanished_pids.len(),
                uncovered.len(),
                examples,
                browser_hint
            );
        }
    }

    let pids = verified_pids;
    let verified_count = pids.len();
    let vanished_count = vanished_pids.len();
    let failed_count = failed_pids.len();

    // Read the cgroup ID for nftables `socket cgroupv2 level <depth>` matching.
    //
    // On 64-bit kernels, the cgroup v2 ID is simply the kernfs inode
    // number of the cgroup directory.  `socket cgroupv2 level <depth>`
    // returns this 64-bit value for matching in the output chain, where
    // <depth> is the cgroup's depth in the unified hierarchy (0 = root).
    //
    // NOTE: `meta cgroup` in nftables only works with cgroup v1
    // `net_cls.classid` and MUST NOT be used on cgroup v2 systems.
    let cgroup_id: Option<u64> = {
        let id_file = format!("{}/cgroup.id", target_cg_path);
        if Path::new(&id_file).exists() {
            fs::read_to_string(&id_file)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        } else {
            // cgroup v2: use directory inode (= kernfs inode = cgroup ID)
            fs::metadata(&target_cg_path).map(|m| m.ino()).ok()
        }
    };

    let use_v2 = cgroup_id.is_some();

    // For v1 fallback: add tc cgroup filter on egress
    if !use_v2 {
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

    // Phase 2: Create records for each PID
    let mut applied_count = 0;
    for pid in &pids {
        let class_id = next_class_id()?;

        if !use_v2 {
            // v1 fallback: per-PID cgroups with net_cls.classid
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
            target_cgroup_path: if use_v2 {
                Some(target_cg_path.clone())
            } else {
                None
            },
            uid: None,
        };

        state.limits.push(record);
        applied_count += 1;
    }

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
        if use_v2 {
            // Delete existing IPv4 filter
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
            // Delete existing IPv6 filter
            let _ = Command::new("tc")
                .args([
                    "filter",
                    "del",
                    "dev",
                    &interface,
                    "parent",
                    "1:0",
                    "protocol",
                    "ipv6",
                    "prio",
                    "101",
                    "handle",
                    &tid.to_string(),
                    "fw",
                ])
                .output();

            // Add IPv4 fw filter
            tx.add(
                &format!("egress fw filter (IPv4) for target {}", target),
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

            // Add IPv6 fw filter (same handle, different protocol, different prio)
            // NOTE: IPv6 filter uses prio 101 (IPv4 uses prio 100) because
            // modern kernels (6.x) reject two filters at the same priority
            // with different protocols on the same parent qdisc.
            tx.add(
                &format!("egress fw filter (IPv6) for target {}", target),
                vec![
                    "filter".into(),
                    "add".into(),
                    "dev".into(),
                    interface.clone(),
                    "parent".into(),
                    "1:0".into(),
                    "protocol".into(),
                    "ipv6".into(),
                    "prio".into(),
                    "101".into(),
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
                    "ipv6".into(),
                    "prio".into(),
                    "101".into(),
                    "handle".into(),
                    tid.to_string(),
                    "fw".into(),
                ],
            );
        }
    }

    if let Err(e) = tx.execute_with_diagnostics(diagnostics) {
        eprintln!("{}: Failed to apply tc rules: {}", "ERROR".red().bold(), e);
        // Rollback cgroups
        for pid in &pids {
            let _ = remove_cgroup(*pid);
        }
        return Err(e);
    }

    // Refresh nftables rules (output: socket cgroupv2, download: ct mark)
    if let Err(e) = refresh_nft_ip_rules_with_diagnostics(&state.limits, diagnostics) {
        return Err(e).with_context(|| {
            format!(
                "failed to apply nft packet marking rules for target '{}'\n  target cgroup path: {}\n  cgroup id: {}\n  computed level: {}",
                target,
                if use_v2 {
                    target_cg_path.as_str()
                } else {
                    "unavailable (cgroup v1 fallback)"
                },
                cgroup_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unavailable".to_string()),
                if use_v2 {
                    cgroup_level(Some(&target_cg_path)).to_string()
                } else {
                    "unavailable".to_string()
                }
            )
        });
    }

    state.save().with_context(|| {
        format!(
            "failed to save oxy state after applying strict limit for target '{}'",
            target
        )
    })?;

    if diagnostics {
        print_state_file_diagnostic();
    }

    // Force reconnection of existing sockets so that `socket cgroupv2`
    // can match them.  The cgroup association is stored in sk->sk_cgrp_data
    // at socket *creation* time — it is NOT updated when the process is
    // later moved to a different cgroup.  Without this step only sockets
    // created *after* the PID was moved would be matched, leaving
    // pre-existing browser connections untouched.
    //
    // We briefly drop all egress from the target UID (300 ms), forcing
    // every TCP/UDP flow to reconnect.  After the drop is lifted the
    // process creates new sockets inside the target cgroup, so
    // `socket cgroupv2` now matches and marks them.  Non-target processes
    // sharing the same UID are also briefly interrupted but reconnect
    // normally and remain unmarked (un-limited).
    if use_v2 {
        if let Some(uid) = get_process_uid(pids[0]) {
            let uid_str = uid.to_string();
            let uid_rule = format!("meta skuid {}", uid_str);

            let _ = Command::new("nft")
                .args(["add", "rule", "inet", "oxy", "output", &uid_rule, "drop"])
                .output();

            std::thread::sleep(std::time::Duration::from_millis(300));

            // Locate and remove the temporary DROP rule by its handle
            if let Ok(list_out) = Command::new("nft")
                .args(["-a", "list", "chain", "inet", "oxy", "output"])
                .output()
            {
                let list_stdout = String::from_utf8_lossy(&list_out.stdout);
                for line in list_stdout.lines() {
                    if line.contains(&uid_rule) {
                        if let Some(pos) = line.rfind("handle ") {
                            let handle = line[pos + 7..].trim();
                            let _ = Command::new("nft")
                                .args(["delete", "rule", "inet", "oxy", "output", "handle", handle])
                                .output();
                            break;
                        }
                    }
                }
            }
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
    println!("  Discovered PIDs: {}", discovered_count);
    println!("  Moved PIDs:      {}", moved_count);
    println!("  Verified PIDs:   {}", verified_count);
    println!("  Vanished PIDs:   {}", vanished_count);
    println!("  Failed PIDs:     {}", failed_count);
    println!(
        "  PIDs:      {}",
        pids.iter()
            .map(|p| format!("{}", p))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(ref dl) = dl_display {
        println!("  Download:  {} (limited, nftables policer)", dl.cyan());
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
        "  Backend:   nftables + HTB | {}",
        if use_v2 {
            "cgroup v2 (per-target isolation)"
        } else {
            "cgroup v1 fallback"
        }
    );
    println!("  Applied:   {} process(es)", applied_count);

    if use_v2 {
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
                // Remove per-target fw filter (IPv4)
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
                // Remove per-target fw filter (IPv6)
                let _ = Command::new("tc")
                    .args([
                        "filter",
                        "del",
                        "dev",
                        iface,
                        "parent",
                        "1:0",
                        "protocol",
                        "ipv6",
                        "prio",
                        "101",
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
            let _ = Command::new("tc")
                .args([
                    "filter", "del", "dev", iface, "parent", "1:0", "protocol", "ipv6", "prio",
                    "1", "cgroup",
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
            println!("  Download:  {} (nftables policer)", dl);
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
                // Remove IPv4 fw filter
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
                // Remove IPv6 fw filter
                let _ = Command::new("tc")
                    .args([
                        "filter",
                        "del",
                        "dev",
                        iface,
                        "parent",
                        "1:0",
                        "protocol",
                        "ipv6",
                        "prio",
                        "101",
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
            // Always try per-target cgroup first (v2 approach works on hybrid too)
            if let Some(ref tcg_path) = record.target_cgroup_path {
                let procs_path = format!("{}/cgroup.procs", tcg_path);
                if Path::new(&procs_path).exists() {
                    let _ = fs::write(&procs_path, new_pid.to_string());
                }
            } else {
                // v1 fallback: per-PID cgroups
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limit_record(target: &str, cgroup_path: &str) -> LimitRecord {
        LimitRecord {
            target: target.to_string(),
            pid: 1234,
            download_bytes_per_sec: Some(1024 * 1024),
            upload_bytes_per_sec: Some(1024 * 1024),
            download_display: Some("1 MB/s".to_string()),
            upload_display: Some("1 MB/s".to_string()),
            interface: "eth0".to_string(),
            class_id: 100,
            applied_at: "test".to_string(),
            ingress_handle: None,
            cgroup_id: Some(13886),
            target_cgroup_path: Some(cgroup_path.to_string()),
            uid: None,
        }
    }

    #[test]
    fn relative_cgroup_path_for_oxy_target() {
        let relative = relative_cgroupv2_path("/sys/fs/cgroup/oxy/target_brave", "brave").unwrap();

        assert_eq!(relative, "oxy/target_brave");
        assert_eq!(cgroup_level_from_relative(&relative), 2);
    }

    #[test]
    fn relative_cgroup_path_for_single_component() {
        let relative = relative_cgroupv2_path("/sys/fs/cgroup/foo", "foo").unwrap();

        assert_eq!(relative, "foo");
        assert_eq!(cgroup_level_from_relative(&relative), 1);
    }

    #[test]
    fn relative_cgroup_path_rejects_outside_root() {
        let err = relative_cgroupv2_path("/tmp/oxy/target_brave", "brave")
            .unwrap_err()
            .to_string();

        assert!(err.contains("/tmp/oxy/target_brave"));
        assert!(err.contains("/sys/fs/cgroup"));
        assert!(err.contains("brave"));
    }

    #[test]
    fn strict_diagnostic_cgroup_path_and_level_match_oxy_target_layout() {
        let target_cg_path = "/sys/fs/cgroup/oxy/target_firefox";
        let relative = relative_cgroupv2_path(target_cg_path, "firefox").unwrap();

        assert_eq!(relative, "oxy/target_firefox");
        assert_eq!(cgroup_level_from_relative(&relative), 2);
    }

    #[test]
    fn deeper_cgroup_path_preserves_full_relative_path_and_level() {
        let path = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/oxy/target_brave";
        let relative = relative_cgroupv2_path(path, "brave").unwrap();

        assert_eq!(
            relative,
            "user.slice/user-1000.slice/user@1000.service/oxy/target_brave"
        );
        assert_eq!(cgroup_level_from_relative(&relative), 5);
    }

    #[test]
    fn cgroup_mode_label_from_flags_covers_all_modes() {
        assert_eq!(
            cgroup_mode_label_from_flags(true, true),
            "hybrid (cgroup v2 + v1 controllers)"
        );
        assert_eq!(cgroup_mode_label_from_flags(true, false), "pure cgroup v2");
        assert_eq!(cgroup_mode_label_from_flags(false, false), "cgroup v1");
        assert_eq!(
            cgroup_mode_label_from_flags(false, true),
            "unknown hybrid state"
        );
    }

    #[test]
    fn cgroup2_mount_info_from_mountinfo_extracts_cgroup2_lines() {
        let input = "1 2 0:1 / / rw - ext4 /dev/root rw\n3 2 0:29 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n";

        assert_eq!(
            cgroup2_mount_info_from_mountinfo(input),
            "3 2 0:29 / /sys/fs/cgroup rw - cgroup2 cgroup rw"
        );
    }

    #[test]
    fn cgroup2_mount_info_from_mountinfo_reports_missing_cgroup2() {
        assert_eq!(
            cgroup2_mount_info_from_mountinfo("1 2 0:1 / / rw - ext4 /dev/root rw"),
            "(no cgroup2 mount found in /proc/self/mountinfo)"
        );
    }

    #[test]
    fn nft_string_escaping_handles_quote_and_backslash() {
        assert_eq!(
            escape_nft_string(r#"oxy/target_"brave\test"#),
            r#"oxy/target_\"brave\\test"#
        );
    }

    #[test]
    fn nft_ruleset_uses_cgroupv2_path_match() {
        let ruleset = build_nft_ip_ruleset(&[test_limit_record(
            "brave",
            "/sys/fs/cgroup/oxy/target_brave",
        )])
        .unwrap();

        assert!(
            ruleset.contains(r#"socket cgroupv2 level 2 "oxy/target_brave" counter meta mark set"#)
        );
        assert!(!ruleset.contains("socket cgroupv2 level 2 =="));
        assert!(!ruleset.contains("13886 meta mark set"));
    }

    #[test]
    fn nft_ruleset_adds_counters_to_strict_rules() {
        let ruleset = build_nft_ip_ruleset(&[test_limit_record(
            "brave",
            "/sys/fs/cgroup/oxy/target_brave",
        )])
        .unwrap();

        assert!(ruleset.contains("meta mark != 0 counter ct mark set meta mark;"));
        assert!(ruleset.contains(" counter limit rate "));
        assert!(ruleset.contains(" counter drop;"));
    }
}
