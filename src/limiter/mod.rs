// SPDX-License-Identifier: GPL-3.0-only
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
///   All target PIDs are moved to `/sys/fs/cgroup/zelynic/target_<sanitized_name>/`
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
///   unified cgroup hierarchy (0 = root).  For the per-target cgroups at
///   `/sys/fs/cgroup/zelynic/target_<name>/`, the level is 2.
///
/// NOTE: `meta skuid` is intentionally NOT used — it would leak limits to
/// all processes of the same UID, breaking per-target isolation.
///
/// IMPORTANT: `meta cgroup` in nftables is a cgroup v1-only feature that
/// returns `net_cls.classid`.  On cgroup v2 systems, `socket cgroupv2` must
/// be used instead.  `socket cgroupv2` was added in kernel 5.7.
///
/// State is persisted to disk so that limits survive across invocations
/// and can be cleaned up properly with `zelynic unstrict`.
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use crate::units::BandwidthRate;

mod attach;
mod cgroup;
mod cleanup;
mod diagnostics;
mod nft;
mod output;
mod prereq;
mod process;
mod reapply;
mod refresh;
mod state;
mod tc;

pub use cgroup::{
    check_root, get_default_interface, list_interfaces, remove_cgroup, setup_cgroup,
    validate_interface,
};
#[allow(unused_imports)]
pub use cleanup::{
    check_respawns, clean_orphans, emergency_cleanup, list_active_limits, remove_limit,
};
#[allow(unused_imports)]
pub use process::{
    get_process_name, resolve_pids, resolve_pids_detailed, resolve_process_tree,
    ProcessMatchReason, ResolvedPid,
};
pub use refresh::refresh_limit;
#[allow(unused_imports)]
pub use state::{LimitRecord, ZelynicState};
pub use tc::next_class_id;

use attach::{
    build_limit_record, dedupe_resolved_target_pids, LimitRecordTemplate, ResolvedTargetPid,
};
use cgroup::{
    cgroup_level, cgroup_level_from_relative, current_cgroup_v2_absolute_path,
    detect_cgroup_version, move_pid_to_cgroup_with_verify, pid_cgroup_v2_line,
    relative_cgroupv2_path, safe_original_cgroup_path, verify_pid_in_cgroup,
};
use cleanup::chrono_now;
use diagnostics::{print_state_file_diagnostic, print_strict_diagnostic_header};
use nft::refresh_nft_ip_rules_with_diagnostics;
use output::{print_strict_apply_summary, StrictApplySummary};
use prereq::{ensure_conntrack, ensure_kernel_modules, force_reconnect_existing_sockets};
use process::{is_chromium_based_target, sanitize_target_name};
use reapply::auto_clean_existing_limits;
use tc::{ensure_htb_qdisc, target_class_id, TcTransaction};

/// Directory where Zelynic stores runtime state.
const STATE_DIR: &str = "/run/zelynic";
/// Path to the state file containing active bandwidth limits.
const STATE_FILE: &str = "/run/zelynic/state.json";
/// Path to the generated nftables ruleset.
const NFT_RULESET_FILE: &str = "/run/zelynic/zelynic.nft";
/// Root of the unified cgroup v2 hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Base path for Zelynic's runtime cgroup management.
const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";
/// Runtime nftables table name.
const NFT_TABLE: &str = "zelynic";
/// Legacy v2.0.0 runtime state directory, cleaned up conservatively.
const LEGACY_STATE_DIR: &str = "/run/oxy";
/// Legacy v2.0.0 cgroup base, cleaned up only when empty/safe.
const LEGACY_CGROUP_BASE: &str = "/sys/fs/cgroup/oxy";
/// Legacy v2.0.0 nftables table name.
const LEGACY_NFT_TABLE: &str = "oxy";
// Main: apply_limit

/// Apply a bandwidth limit (strict) to a target process.
///
/// This is the main entry point for the `zelynic strict` command.
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
    cleanup::cleanup_legacy_runtime_namespace(true);

    // Auto-cleanup: remove stale limits for dead processes before applying new limits.
    // This prevents accumulation of orphaned state when target processes exit
    // without running `zelynic unstrict` first.
    if let Err(e) = clean_orphans() {
        // Don't fail — just log. The user's requested operation is more important.
        eprintln!("{}: auto-cleanup failed: {}", "WARNING".yellow(), e);
    }

    if download.is_none() && upload.is_none() {
        bail!(
            "no bandwidth limit specified.\n  {} Usage: zelynic strict -d <rate> -u <rate> <target>",
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

    let resolved_pids = resolve_pids_detailed(target)?
        .into_iter()
        .map(ResolvedTargetPid::from)
        .collect();

    apply_limit_to_resolved_pids(
        target,
        resolved_pids,
        download_rate,
        upload_rate,
        interface,
        diagnostics,
    )
}

pub(crate) fn apply_limit_to_resolved_pids(
    target: &str,
    resolved_pids: Vec<ResolvedTargetPid>,
    download_rate: Option<BandwidthRate>,
    upload_rate: Option<BandwidthRate>,
    interface: String,
    diagnostics: bool,
) -> Result<()> {
    let resolved_pids = dedupe_resolved_target_pids(resolved_pids)?;
    let (dl_bps, ul_bps, dl_display, ul_display) = (
        download_rate.as_ref().map(|r| r.bytes_per_sec),
        upload_rate.as_ref().map(|r| r.bytes_per_sec),
        download_rate.as_ref().map(|r| r.to_string()),
        upload_rate.as_ref().map(|r| r.to_string()),
    );

    let pids: Vec<u32> = resolved_pids.iter().map(|resolved| resolved.pid).collect();
    let sanitized = sanitize_target_name(target);

    println!("{} Using interface: {}", "→".cyan(), interface.cyan());

    auto_clean_existing_limits(target, &pids, &sanitized)?;

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
    let mut state = ZelynicState::load()?;

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
        for resolved in &resolved_pids {
            println!(
                "strict diagnostic: selected PID {} {}",
                resolved.pid,
                resolved.diagnostic_label()
            );
        }
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
    let mut original_cgroup_paths: HashMap<u32, Option<String>> = HashMap::new();

    for resolved in &resolved_pids {
        let pid = resolved.pid;
        let original_cgroup_path = resolved
            .original_cgroup_path
            .clone()
            .or_else(|| current_cgroup_v2_absolute_path(pid));
        let original_cgroup_path = safe_original_cgroup_path(original_cgroup_path);
        original_cgroup_paths.insert(pid, original_cgroup_path);
        let result = move_pid_to_cgroup_with_verify(pid, &target_cg_path);
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
            verified_pids.push(pid);
        } else if result.vanished {
            vanished_pids.push(pid);
        } else {
            failed_pids.push((pid, result.cgroup_line, result.error));
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
    let record_template = LimitRecordTemplate {
        target: target.to_string(),
        download_bytes_per_sec: dl_bps,
        upload_bytes_per_sec: ul_bps,
        download_display: dl_display.clone(),
        upload_display: ul_display.clone(),
        interface: interface.clone(),
        cgroup_id,
        target_cgroup_path: if use_v2 {
            Some(target_cg_path.clone())
        } else {
            None
        },
    };

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

        let mut resolved = resolved_pids
            .iter()
            .find(|resolved| resolved.pid == *pid)
            .cloned()
            .expect("verified PID came from resolved PID list");
        resolved.original_cgroup_path = original_cgroup_paths.get(pid).cloned().flatten();
        let record = build_limit_record(&record_template, &resolved, class_id, chrono_now());

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
            "failed to save zelynic state after applying strict limit for target '{}'",
            target
        )
    })?;

    if diagnostics {
        print_state_file_diagnostic();
    }

    force_reconnect_existing_sockets(use_v2, &pids);

    print_strict_apply_summary(&StrictApplySummary {
        target,
        discovered_count,
        moved_count,
        verified_count,
        vanished_count,
        failed_count,
        pids: &pids,
        download_display: dl_display.as_deref(),
        upload_display: ul_display.as_deref(),
        interface: &interface,
        use_v2,
        target_cg_path: &target_cg_path,
        applied_count,
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_pid_attach_api_rejects_empty_pid_list() {
        let err = apply_limit_to_resolved_pids(
            "helium",
            Vec::new(),
            None,
            None,
            "wlp1s0".to_string(),
            false,
        )
        .unwrap_err()
        .to_string();

        assert_eq!(err, "strict attach requires at least one resolved PID");
    }
}
