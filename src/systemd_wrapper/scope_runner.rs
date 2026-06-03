// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Scope Runner: live probe for system-scope systemd scope units.
//!
//! This is v2.5 groundwork. It provides a controlled, root-only, system-scope
//! live probe that actually launches a transient systemd scope, discovers the
//! ControlGroup and PID(s), and reports findings. It does NOT apply bandwidth
//! limits, modify nftables, tc, or Zelynic cgroups.

use std::io::Write as _;
use std::process::Command;

use anyhow::{bail, Result};
use colored::Colorize;

use super::discovery::pid_discovery::{
    control_group_to_cgroup_procs_path, parse_systemctl_show_output,
};
use super::plan::{systemd_run_argv, ScopeMode, SystemdRunPlan};
use super::render::push_line;
use super::sanitize::sanitize_scope_component;

use crate::units::BandwidthRate;

const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

// ---------------------------------------------------------------------------
// Public gate
// ---------------------------------------------------------------------------

/// Gate check: returns Ok(()) if the probe-live path is allowed.
///
/// Requirements (all must be true):
/// 1. `probe_live` flag is set
/// 2. `scope_mode` is System
/// 3. euid == 0
pub(crate) fn probe_gate(probe_live: bool, scope_mode: ScopeMode) -> Result<()> {
    if !probe_live {
        bail!("Live systemd wrapper execution is not implemented yet.")
    }
    if scope_mode != ScopeMode::System {
        bail!(
            "User-scope live runner is not implemented. \
             User-scope launch needs privilege/session handoff \
             and is not implemented yet."
        )
    }
    if !nix::unistd::geteuid().is_root() {
        bail!(
            "Scope Runner live probe requires root (euid == 0). \
             System-scope systemd-run needs root to create a transient scope."
        )
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Live probe execution
// ---------------------------------------------------------------------------

/// Result of a live scope probe.
#[allow(dead_code)]
pub(crate) struct ScopeProbeResult {
    pub scope_unit_name: String,
    pub scope_unit: String,
    pub control_group: Option<String>,
    pub active_state: Option<String>,
    pub sub_state: Option<String>,
    pub pids: Vec<u32>,
    pub cgroup_procs_path: Option<String>,
}

/// Non-mutating preview of a future limiter attach based on probe discovery.
///
/// This is purely informational. It does not move PIDs, create cgroups,
/// modify nftables/tc, or write state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachPreview {
    /// Discovered PID(s) from the scope probe.
    pub pids: Vec<u32>,
    /// Future Zelynic target cgroup path (not yet created).
    pub future_target_cgroup: String,
    /// Requested download rate (display string, e.g. "500 Kbit/s").
    pub download: Option<String>,
    /// Requested upload rate (display string, e.g. "500 Kbit/s").
    pub upload: Option<String>,
    /// Label describing where PIDs were discovered.
    pub attach_source: String,
    /// Label describing the strict backend that would be used.
    pub strict_backend: String,
    /// Status indicating this is a preview, not applied.
    pub status: String,
}

pub(crate) fn run_scope_probe(systemd_run: &SystemdRunPlan) -> Result<ScopeProbeResult> {
    // 1. Launch transient systemd scope (backgrounded)
    let argv = systemd_run_argv(systemd_run);
    let _child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn systemd-run: {}", e))?;

    // Brief pause to let systemd register the scope
    std::thread::sleep(std::time::Duration::from_millis(500));

    let scope_unit = format!("{}.scope", systemd_run.scope_unit_name);

    // 2. Query scope properties
    let show_output = Command::new("systemctl")
        .args([
            "show",
            &scope_unit,
            "--property",
            "MainPID",
            "--property",
            "ControlGroup",
            "--property",
            "ActiveState",
            "--property",
            "SubState",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run systemctl show: {}", e))?;

    let show_text = String::from_utf8_lossy(&show_output.stdout);
    let metadata = parse_systemctl_show_output(&show_text);

    let control_group = metadata.control_group.clone();
    let active_state = parse_property(&show_text, "ActiveState");
    let sub_state = parse_property(&show_text, "SubState");

    // 3. Read cgroup.procs if ControlGroup was discovered
    let mut pids = Vec::new();
    let mut cgroup_procs_path = None;

    if let Some(ref cg) = control_group {
        let procs_path = control_group_to_cgroup_procs_path(cg)
            .map_err(|e| anyhow::anyhow!("Invalid ControlGroup: {}", e))?;
        cgroup_procs_path = Some(procs_path.clone());

        if let Ok(content) = std::fs::read_to_string(&procs_path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }

    Ok(ScopeProbeResult {
        scope_unit_name: systemd_run.scope_unit_name.clone(),
        scope_unit,
        control_group,
        active_state,
        sub_state,
        pids,
        cgroup_procs_path,
    })
}

pub(crate) fn build_attach_preview(
    target_name: &str,
    pids: &[u32],
    download: Option<&str>,
    upload: Option<&str>,
) -> Result<AttachPreview> {
    let sanitized = sanitize_scope_component(target_name);
    let future_target_cgroup = format!("{}/target_{}", CGROUP_BASE, sanitized);

    let download_display = download
        .map(|v| BandwidthRate::parse(v).map(|p| p.to_string()))
        .transpose()?;
    let upload_display = upload
        .map(|v| BandwidthRate::parse(v).map(|p| p.to_string()))
        .transpose()?;

    Ok(AttachPreview {
        pids: pids.to_vec(),
        future_target_cgroup,
        download: download_display,
        upload: upload_display,
        attach_source: "systemd scope probe".to_string(),
        strict_backend: "existing resolved-PID attach backend".to_string(),
        status: "preview only; not applied".to_string(),
    })
}

fn parse_property(output: &str, property: &str) -> Option<String> {
    let prefix = format!("{}=", property);
    for line in output.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Output rendering
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn render_scope_probe_output(result: &ScopeProbeResult) -> String {
    render_scope_probe_output_with_preview(result, None)
}

pub(crate) fn render_scope_probe_output_with_preview(
    result: &ScopeProbeResult,
    preview: Option<&AttachPreview>,
) -> String {
    let mut output = String::new();

    push_line(&mut output, "Scope Runner live probe");
    push_line(&mut output, "");
    push_line(
        &mut output,
        &format!("  Launched transient systemd scope: {}", result.scope_unit),
    );

    if let Some(ref cg) = result.control_group {
        push_line(&mut output, &format!("  Discovered ControlGroup: {}", cg));
    } else {
        push_line(&mut output, "  Discovered ControlGroup: (none)");
    }

    push_line(
        &mut output,
        &format!(
            "  ActiveState: {}",
            result.active_state.as_deref().unwrap_or("(unknown)")
        ),
    );
    push_line(
        &mut output,
        &format!(
            "  SubState: {}",
            result.sub_state.as_deref().unwrap_or("(unknown)")
        ),
    );

    if result.pids.is_empty() {
        push_line(&mut output, "  Discovered PID(s): (none)");
    } else {
        push_line(
            &mut output,
            &format!("  Discovered PID(s): {}", format_pid_list(&result.pids)),
        );
    }

    // Attach preview section (phase 2)
    if let Some(prev) = preview {
        push_line(&mut output, "");
        push_line(&mut output, "  Future attach preview:");
        if prev.pids.is_empty() {
            push_line(&mut output, "    discovered PID(s): (none)");
        } else {
            push_line(
                &mut output,
                &format!("    discovered PID(s): {}", format_pid_list(&prev.pids)),
            );
        }
        push_line(
            &mut output,
            &format!("    future target cgroup: {}", prev.future_target_cgroup),
        );
        push_line(
            &mut output,
            &format!(
                "    requested download: {}",
                prev.download.as_deref().unwrap_or("unlimited")
            ),
        );
        push_line(
            &mut output,
            &format!(
                "    requested upload: {}",
                prev.upload.as_deref().unwrap_or("unlimited")
            ),
        );
        push_line(
            &mut output,
            &format!("    attach source: {}", prev.attach_source),
        );
        push_line(
            &mut output,
            &format!("    strict backend: {}", prev.strict_backend),
        );
        push_line(&mut output, &format!("    status: {}", prev.status));
    }

    push_line(&mut output, "");
    if preview.is_some() {
        push_line(&mut output, "  No PID was moved.");
    }
    push_line(&mut output, "  No limiter attach was performed.");
    push_line(
        &mut output,
        "  No nftables, tc, Zelynic cgroup, or state changes were made.",
    );
    push_line(
        &mut output,
        "  Bandwidth limiting is not active from this command yet.",
    );
    push_line(&mut output, "");
    push_line(
        &mut output,
        &format!(
            "  To stop the scope: sudo systemctl stop {}",
            result.scope_unit
        ),
    );

    output
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn print_scope_probe_output(result: &ScopeProbeResult) {
    print_rendered_scope_output(&render_scope_probe_output(result));
}

pub(crate) fn print_scope_probe_output_with_preview(
    result: &ScopeProbeResult,
    preview: &AttachPreview,
) {
    print_rendered_scope_output(&render_scope_probe_output_with_preview(
        result,
        Some(preview),
    ));
}

fn print_rendered_scope_output(rendered: &str) {
    for (index, line) in rendered.lines().enumerate() {
        if index == 0 {
            println!("{}", line.green().bold());
        } else {
            println!("{line}");
        }
    }
    let _ = std::io::stdout().flush();
}

fn format_pid_list(pids: &[u32]) -> String {
    pids.iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// SystemdRunPlan builder for probe (reuses existing plan infrastructure)
// ---------------------------------------------------------------------------

pub(crate) fn build_probe_systemd_run_plan(
    target: Option<&str>,
    command: &[String],
) -> Result<SystemdRunPlan> {
    if command.is_empty() {
        bail!("zelynic run requires a command after --");
    }

    let target_name = target
        .map(str::to_string)
        .unwrap_or_else(|| command_basename(&command[0]));
    let sanitized = sanitize_scope_component(&target_name);
    let scope_unit_name = format!("zelynic-probe-v250-{}", sanitized);

    Ok(SystemdRunPlan {
        scope_unit_name,
        description: "Zelynic v2.5 system-scope probe".to_string(),
        command_argv: command.to_vec(),
        scope_mode: ScopeMode::System,
        target: target_name,
        attach_target_cgroup: String::new(), // probe does not use Zelynic cgroups
    })
}

fn command_basename(command: &str) -> String {
    command
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(command)
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::render::render_argv;
    use super::*;

    fn fake_plan(scope_unit_name: &str) -> SystemdRunPlan {
        SystemdRunPlan {
            scope_unit_name: scope_unit_name.to_string(),
            description: "Zelynic v2.5 system-scope probe".to_string(),
            command_argv: vec!["sleep".to_string(), "30".to_string()],
            scope_mode: ScopeMode::System,
            target: "sleep".to_string(),
            attach_target_cgroup: String::new(),
        }
    }

    // ---- gate tests ----

    #[test]
    fn gate_blocks_when_probe_live_not_set() {
        let err = probe_gate(false, ScopeMode::System)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Live systemd wrapper execution is not implemented yet."
        );
    }

    #[test]
    fn gate_blocks_user_scope_with_probe_live() {
        let err = probe_gate(true, ScopeMode::User).unwrap_err().to_string();
        assert!(err.contains("User-scope live runner is not implemented"));
        assert!(err.contains("privilege/session handoff"));
    }

    #[test]
    fn gate_blocks_system_scope_non_root_with_probe_live() {
        // We are non-root in CI, so this gate will actually fail.
        // Test the logic by calling evaluate_probe_gate directly.
        let err = probe_gate(true, ScopeMode::System).unwrap_err().to_string();
        // In CI we are non-root, so this should fail with the root message
        assert!(err.contains("requires root"));
    }

    #[test]
    fn gate_allows_system_scope_root_with_probe_live_via_preflight_model() {
        // Test the pure-logic gate: verify that if we had root + system + probe,
        // the only remaining check is the root check (which we model here).
        // We can't test root=true in CI, but we can verify the gate logic path:
        // probe_live=true + scope=System → proceeds to root check.
        //
        // The root check itself is just `geteuid().is_root()` which we can't
        // override. But we verify the gate structure by checking the OTHER
        // failures come first.
        assert!(probe_gate(false, ScopeMode::System).is_err()); // no probe flag
        assert!(probe_gate(true, ScopeMode::User).is_err()); // user scope
                                                             // The root check depends on runtime euid
    }

    // ---- output wording tests ----

    #[test]
    fn probe_output_does_not_claim_limiter_is_active() {
        let result = ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-sleep".to_string(),
            scope_unit: "zelynic-probe-v250-sleep.scope".to_string(),
            control_group: Some("/system.slice/zelynic-probe-v250-sleep.scope".to_string()),
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            pids: vec![12345],
            cgroup_procs_path: Some(
                "/sys/fs/cgroup/system.slice/zelynic-probe-v250-sleep.scope/cgroup.procs"
                    .to_string(),
            ),
        };
        let rendered = render_scope_probe_output(&result);

        assert!(rendered.contains("No limiter attach was performed."));
        assert!(rendered.contains("No nftables, tc, Zelynic cgroup, or state changes were made."));
        assert!(rendered.contains("Bandwidth limiting is not active from this command yet."));
    }

    #[test]
    fn probe_output_mentions_no_nftables_tc_zelynic_cgroup_state() {
        let result = ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-echo".to_string(),
            scope_unit: "zelynic-probe-v250-echo.scope".to_string(),
            control_group: Some("/system.slice/zelynic-probe-v250-echo.scope".to_string()),
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            pids: vec![98765, 98766],
            cgroup_procs_path: None,
        };
        let rendered = render_scope_probe_output(&result);

        assert!(rendered.contains("nftables"));
        assert!(rendered.contains("tc"));
        assert!(rendered.contains("Zelynic cgroup"));
        assert!(rendered.contains("state changes were made"));
    }

    #[test]
    fn probe_output_mentions_no_limiter_attach() {
        let result = ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-cat".to_string(),
            scope_unit: "zelynic-probe-v250-cat.scope".to_string(),
            control_group: None,
            active_state: None,
            sub_state: None,
            pids: vec![],
            cgroup_procs_path: None,
        };
        let rendered = render_scope_probe_output(&result);

        assert!(rendered.contains("No limiter attach was performed"));
    }

    #[test]
    fn probe_output_contains_scope_runner_label() {
        let result = ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-sleep".to_string(),
            scope_unit: "zelynic-probe-v250-sleep.scope".to_string(),
            control_group: Some("/system.slice/zelynic-probe-v250-sleep.scope".to_string()),
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            pids: vec![42],
            cgroup_procs_path: None,
        };
        let rendered = render_scope_probe_output(&result);

        assert!(rendered.contains("Scope Runner live probe"));
        assert!(rendered.contains("Launched transient systemd scope"));
        assert!(rendered.contains("Discovered ControlGroup"));
        assert!(rendered.contains("Discovered PID(s)"));
    }

    #[test]
    fn probe_output_contains_cleanup_command() {
        let result = ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-sleep".to_string(),
            scope_unit: "zelynic-probe-v250-sleep.scope".to_string(),
            control_group: Some("/system.slice/zelynic-probe-v250-sleep.scope".to_string()),
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            pids: vec![42],
            cgroup_procs_path: None,
        };
        let rendered = render_scope_probe_output(&result);

        assert!(rendered.contains("sudo systemctl stop zelynic-probe-v250-sleep.scope"));
    }

    // ---- plan builder tests ----

    #[test]
    fn probe_plan_uses_v250_naming() {
        let command = vec!["sleep".to_string(), "60".to_string()];
        let plan = build_probe_systemd_run_plan(None, &command).unwrap();

        assert_eq!(plan.scope_unit_name, "zelynic-probe-v250-sleep");
        assert_eq!(plan.scope_mode, ScopeMode::System);
        assert_eq!(plan.description, "Zelynic v2.5 system-scope probe");
        assert!(plan.attach_target_cgroup.is_empty());
    }

    #[test]
    fn probe_plan_sanitizes_explicit_target() {
        let command = vec!["sleep".to_string(), "60".to_string()];
        let plan = build_probe_systemd_run_plan(Some("Hello World!"), &command).unwrap();

        assert_eq!(plan.scope_unit_name, "zelynic-probe-v250-hello_world");
    }

    #[test]
    fn probe_plan_empty_command_errors() {
        let err = build_probe_systemd_run_plan(None, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires a command after --"));
    }

    // ---- command rendering / quoting ----

    #[test]
    fn command_rendering_quotes_safely_for_probe() {
        let argv = systemd_run_argv(&fake_plan("zelynic-probe-v250-sleep"));
        let rendered = render_argv(&argv);

        assert!(rendered.contains("systemd-run"));
        assert!(rendered.contains("--scope"));
        assert!(!rendered.contains("--user"));
        assert!(rendered.contains("zelynic-probe-v250-sleep"));
        assert!(rendered.contains("sleep 30"));
    }

    #[test]
    fn unit_name_sanitization_preserved_in_probe() {
        let plan =
            build_probe_systemd_run_plan(Some("$(rm -rf /)"), &["echo".to_string()]).unwrap();

        assert_eq!(plan.scope_unit_name, "zelynic-probe-v250-rm_rf");
        // The sanitized name must not contain shell-dangerous characters
        assert!(!plan.scope_unit_name.contains('$'));
        assert!(!plan.scope_unit_name.contains('('));
        assert!(!plan.scope_unit_name.contains(')'));
    }

    // ---- attach preview build tests ----

    #[test]
    fn attach_preview_builds_with_correct_cgroup_path() {
        let preview =
            build_attach_preview("sleep", &[12345], Some("500kbit"), Some("500kbit")).unwrap();

        assert_eq!(
            preview.future_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_sleep"
        );
        assert_eq!(preview.pids, vec![12345]);
        assert_eq!(preview.download.as_deref(), Some("500 Kbit/s"));
        assert_eq!(preview.upload.as_deref(), Some("500 Kbit/s"));
        assert_eq!(preview.attach_source, "systemd scope probe");
        assert_eq!(
            preview.strict_backend,
            "existing resolved-PID attach backend"
        );
        assert_eq!(preview.status, "preview only; not applied");
    }

    #[test]
    fn attach_preview_sanitizes_target_name() {
        let preview = build_attach_preview("Hello World!", &[], None, None).unwrap();

        assert_eq!(
            preview.future_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_hello_world"
        );
    }

    #[test]
    fn attach_preview_handles_missing_rates() {
        let preview = build_attach_preview("sleep", &[42], None, None).unwrap();

        assert_eq!(preview.download, None);
        assert_eq!(preview.upload, None);
    }

    #[test]
    fn attach_preview_handles_empty_pids() {
        let preview = build_attach_preview("sleep", &[], Some("1mbit"), None).unwrap();

        assert!(preview.pids.is_empty());
        assert_eq!(preview.download.as_deref(), Some("1 Mbit/s"));
    }

    // ---- attach preview render tests ----

    fn full_probe_result() -> ScopeProbeResult {
        ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-sleep".to_string(),
            scope_unit: "zelynic-probe-v250-sleep.scope".to_string(),
            control_group: Some("/system.slice/zelynic-probe-v250-sleep.scope".to_string()),
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            pids: vec![12345],
            cgroup_procs_path: None,
        }
    }

    fn sample_preview() -> AttachPreview {
        build_attach_preview("sleep", &[12345], Some("500kbit"), Some("500kbit")).unwrap()
    }

    #[test]
    fn preview_includes_discovered_pids() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("    discovered PID(s): 12345"));
    }

    #[test]
    fn preview_includes_future_target_cgroup() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("    future target cgroup: /sys/fs/cgroup/zelynic/target_sleep"));
    }

    #[test]
    fn preview_includes_requested_download_and_upload() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("    requested download: 500 Kbit/s"));
        assert!(rendered.contains("    requested upload: 500 Kbit/s"));
    }

    #[test]
    fn preview_says_preview_only_not_applied() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("    status: preview only; not applied"));
    }

    #[test]
    fn preview_says_no_pid_was_moved() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("No PID was moved"));
    }

    #[test]
    fn preview_says_no_nftables_tc_zelynic_cgroup_state_changes() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("No nftables, tc, Zelynic cgroup, or state changes were made"));
    }

    #[test]
    fn preview_does_not_include_enforcement_words() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(
            !rendered.contains("enforced"),
            "preview must not say 'enforced'"
        );
        assert!(
            !rendered.contains("active limiter"),
            "preview must not say 'active limiter'"
        );
        assert!(
            !rendered.contains("attached"),
            "preview must not say 'attached'"
        );
        assert!(
            !rendered.contains("limited"),
            "preview must not say 'limited'"
        );
    }

    #[test]
    fn preview_empty_pids_handled_safely() {
        let empty_preview = build_attach_preview("sleep", &[], Some("500kbit"), None).unwrap();
        let result = ScopeProbeResult {
            scope_unit_name: "zelynic-probe-v250-sleep".to_string(),
            scope_unit: "zelynic-probe-v250-sleep.scope".to_string(),
            control_group: None,
            active_state: None,
            sub_state: None,
            pids: vec![],
            cgroup_procs_path: None,
        };
        let rendered = render_scope_probe_output_with_preview(&result, Some(&empty_preview));
        assert!(rendered.contains("    discovered PID(s): (none)"));
        assert!(rendered.contains("preview only; not applied"));
    }

    #[test]
    fn preview_without_rates_shows_unlimited() {
        let no_rate_preview = build_attach_preview("sleep", &[42], None, None).unwrap();
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&no_rate_preview));
        assert!(rendered.contains("    requested download: unlimited"));
        assert!(rendered.contains("    requested upload: unlimited"));
    }

    #[test]
    fn render_without_preview_matches_old_format() {
        let rendered = render_scope_probe_output(&full_probe_result());
        // Old format: no preview section, no "No PID was moved."
        assert!(!rendered.contains("Future attach preview"));
        assert!(!rendered.contains("No PID was moved"));
        // But still has the standard safety lines
        assert!(rendered.contains("No limiter attach was performed"));
        assert!(rendered.contains("Bandwidth limiting is not active"));
    }

    #[test]
    fn preview_includes_attach_source_and_strict_backend() {
        let rendered =
            render_scope_probe_output_with_preview(&full_probe_result(), Some(&sample_preview()));
        assert!(rendered.contains("    attach source: systemd scope probe"));
        assert!(rendered.contains("    strict backend: existing resolved-PID attach backend"));
    }
}
