// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::{CGROUP_BASE, CGROUP_ROOT};

/// Detect cgroup version (v1, v2, or hybrid).
///
/// Returns (is_v2, is_hybrid) tuple.
pub(super) fn detect_cgroup_version() -> (bool, bool) {
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
fn pid_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

pub(super) fn pid_cgroup_v2_line(pid: u32) -> String {
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
pub(super) fn verify_pid_in_cgroup(pid: u32, expected_cg_path: &str) -> bool {
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

pub(super) struct PidCgroupMove {
    pub(super) moved: bool,
    pub(super) verified: bool,
    pub(super) vanished: bool,
    pub(super) cgroup_line: String,
    pub(super) error: Option<String>,
}

/// Move a PID to a cgroup with verification and retry.
///
/// Writes the PID to cgroup.procs, then verifies membership.
/// Retries up to 3 times because systemd may immediately move the PID back.
/// Returns structured coverage information for strict diagnostics.
pub(super) fn move_pid_to_cgroup_with_verify(pid: u32, target_cg_path: &str) -> PidCgroupMove {
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
/// Convert an absolute cgroup v2 path into the relative path nftables expects.
pub(super) fn relative_cgroupv2_path(full_path: &str, target: &str) -> Result<String> {
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
pub(super) fn cgroup_level_from_relative(relative_path: &str) -> u32 {
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
pub(super) fn cgroup_level(cg_path: Option<&str>) -> u32 {
    match cg_path {
        Some(path) => relative_cgroupv2_path(path, "unknown")
            .map(|relative| cgroup_level_from_relative(&relative))
            .unwrap_or(2),
        None => 2,
    }
}
pub(super) fn cgroup_mode_label_from_flags(is_v2: bool, is_hybrid: bool) -> &'static str {
    match (is_v2, is_hybrid) {
        (true, true) => "hybrid (cgroup v2 + v1 controllers)",
        (true, false) => "pure cgroup v2",
        (false, false) => "cgroup v1",
        (false, true) => "unknown hybrid state",
    }
}

pub(super) fn cgroup_mode_label() -> &'static str {
    let (is_v2, is_hybrid) = detect_cgroup_version();
    cgroup_mode_label_from_flags(is_v2, is_hybrid)
}

pub(super) fn cgroup2_mount_info_from_mountinfo(content: &str) -> String {
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

pub(super) fn cgroup2_mount_info() -> String {
    match fs::read_to_string("/proc/self/mountinfo") {
        Ok(content) => cgroup2_mount_info_from_mountinfo(&content),
        Err(e) => format!("(failed to read /proc/self/mountinfo: {})", e),
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
            "{} root privileges are required for bandwidth limiting operations.\n  {} Run with: sudo zelynic strict ...",
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
// ---------------------------------------------------------------------------
// Cgroup management
// ---------------------------------------------------------------------------

/// Create a cgroup for the target process and assign it a net_cls classid.
pub fn setup_cgroup(pid: u32, class_id: u32) -> Result<(String, bool)> {
    let cgroup_path = format!("{}/pid_{}", CGROUP_BASE, pid);

    let (is_v2, is_hybrid) = detect_cgroup_version();

    if is_v2 && !is_hybrid {
        // Pure cgroup v2 - create under unified hierarchy
        let v2_cgroup_path = format!("{}/pid_{}", CGROUP_BASE, pid);
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
                    // Move living processes to parent legacy cgroup (NOT system root cgroup).
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
/// On cgroup v2, per-target cgroups live at `/sys/fs/cgroup/zelynic/target_<name>/`.
/// This function evicts all member PIDs and deletes the directory.
pub(super) fn remove_target_cgroup(sanitized_name: &str) -> Result<()> {
    let cgroup_path = format!("{}/target_{}", CGROUP_BASE, sanitized_name);

    if !Path::new(&cgroup_path).exists() {
        return Ok(());
    }

    let procs_path = format!("{}/cgroup.procs", cgroup_path);

    // Move all processes back to parent legacy cgroup
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_base_path_uses_zelynic_namespace() {
        assert_eq!(super::super::CGROUP_BASE, "/sys/fs/cgroup/zelynic");
    }

    #[test]
    fn relative_cgroup_path_for_zelynic_target() {
        let relative =
            relative_cgroupv2_path("/sys/fs/cgroup/zelynic/target_brave", "brave").unwrap();

        assert_eq!(relative, "zelynic/target_brave");
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
        let err = relative_cgroupv2_path("/tmp/zelynic/target_brave", "brave")
            .unwrap_err()
            .to_string();

        assert!(err.contains("/tmp/zelynic/target_brave"));
        assert!(err.contains("/sys/fs/cgroup"));
        assert!(err.contains("brave"));
    }

    #[test]
    fn strict_diagnostic_cgroup_path_and_level_match_zelynic_target_layout() {
        let target_cg_path = "/sys/fs/cgroup/zelynic/target_firefox";
        let relative = relative_cgroupv2_path(target_cg_path, "firefox").unwrap();

        assert_eq!(relative, "zelynic/target_firefox");
        assert_eq!(cgroup_level_from_relative(&relative), 2);
    }

    #[test]
    fn deeper_cgroup_path_preserves_full_relative_path_and_level() {
        let path =
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/zelynic/target_brave";
        let relative = relative_cgroupv2_path(path, "brave").unwrap();

        assert_eq!(
            relative,
            "user.slice/user-1000.slice/user@1000.service/zelynic/target_brave"
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
}
