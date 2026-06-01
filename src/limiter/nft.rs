// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::process::Command;

use super::cgroup::{cgroup_level_from_relative, relative_cgroupv2_path};
use super::process::sanitize_target_name;
use super::state::LimitRecord;
use super::tc::target_class_id;
use super::{CGROUP_ROOT, NFT_RULESET_FILE, NFT_TABLE, STATE_DIR};

/// Escape a string for use inside an nftables quoted string literal.
fn escape_nft_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
// ---------------------------------------------------------------------------
// nftables rules management
// ---------------------------------------------------------------------------

/// Build the nftables `inet zelynic` table for egress marking (upload) and
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
///     For the cgroups at `/zelynic/target_<name>/`, level 2 matches the
///     socket's own cgroup.
///     NOTE: sockets created BEFORE the PID was moved retain their
///     original cgroup and will NOT be matched.  To handle this, Zelynic
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
    ruleset.push_str(&format!("table inet {} {{\n", NFT_TABLE));

    // ---- Output chain: mark egress packets ----
    ruleset.push_str("  chain output {\n");
    ruleset.push_str("    type filter hook output priority mangle; policy accept;\n");

    // socket cgroupv2 — per-target (all egress, including pre-existing sockets)
    //
    // The `level` parameter specifies the depth of the cgroup in the unified
    // hierarchy (0 = root).  For the cgroups at /sys/fs/cgroup/zelynic/target_<name>/,
    // the depth is always 2 (zelynic + target_name).  This is required by nftables
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

/// Apply (or refresh) the nftables inet zelynic table.
pub(super) fn refresh_nft_ip_rules(limits: &[LimitRecord]) -> Result<()> {
    refresh_nft_ip_rules_with_diagnostics(limits, false)
}

pub(super) fn refresh_nft_ip_rules_with_diagnostics(
    limits: &[LimitRecord],
    diagnostics: bool,
) -> Result<()> {
    if limits.is_empty() {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .output();
        return Ok(());
    }

    let ruleset = build_nft_ip_ruleset(limits)?;

    let nft_file = NFT_RULESET_FILE;
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
        .args(["delete", "table", "inet", NFT_TABLE])
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
    fn generated_nft_file_path_uses_zelynic_namespace() {
        assert_eq!(super::super::NFT_RULESET_FILE, "/run/zelynic/zelynic.nft");
    }

    #[test]
    fn nft_ruleset_uses_zelynic_table() {
        let ruleset = build_nft_ip_ruleset(&[test_limit_record(
            "brave",
            "/sys/fs/cgroup/zelynic/target_brave",
        )])
        .unwrap();

        assert!(ruleset.starts_with("table inet zelynic {"));
        assert!(!ruleset.contains("table inet oxy"));
    }

    #[test]
    fn nft_string_escaping_handles_quote_and_backslash() {
        assert_eq!(
            escape_nft_string(r#"zelynic/target_"brave\test"#),
            r#"zelynic/target_\"brave\\test"#
        );
    }

    #[test]
    fn nft_ruleset_uses_cgroupv2_path_match() {
        let ruleset = build_nft_ip_ruleset(&[test_limit_record(
            "brave",
            "/sys/fs/cgroup/zelynic/target_brave",
        )])
        .unwrap();

        assert!(ruleset
            .contains(r#"socket cgroupv2 level 2 "zelynic/target_brave" counter meta mark set"#));
        assert!(!ruleset.contains("socket cgroupv2 level 2 =="));
        assert!(!ruleset.contains("13886 meta mark set"));
    }

    #[test]
    fn nft_ruleset_adds_counters_to_strict_rules() {
        let ruleset = build_nft_ip_ruleset(&[test_limit_record(
            "brave",
            "/sys/fs/cgroup/zelynic/target_brave",
        )])
        .unwrap();

        assert!(ruleset.contains("meta mark != 0 counter ct mark set meta mark;"));
        assert!(ruleset.contains(" counter limit rate "));
        assert!(ruleset.contains(" counter drop;"));
    }
}
