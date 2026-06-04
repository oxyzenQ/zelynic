// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Attach Preview: non-mutating preview of a future limiter attach based on
//! probe discovery. Purely informational — no PID movement, no cgroup
//! creation, no nftables/tc, no state writes.

use anyhow::Result;

use super::attach_safety::{
    build_attach_safety_preflight, render_attach_safety_preflight_section, AttachSafetyPreflight,
};
use super::experimental_attach_gate::{
    render_experimental_attach_gate_section, ExperimentalAttachGateChecklist,
};
use super::render::push_line;
use super::sanitize::sanitize_scope_component;

use crate::units::BandwidthRate;

const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

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
    /// Pure safety preflight for future live attach.
    pub safety_preflight: AttachSafetyPreflight,
    /// Optional explicit gate checklist for future experimental PID movement.
    pub experimental_attach_gate: Option<ExperimentalAttachGateChecklist>,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub(crate) fn build_attach_preview(
    target_name: &str,
    pids: &[u32],
    download: Option<&str>,
    upload: Option<&str>,
    live_cgroup_previews: Option<Vec<super::original_cgroup_preview::OriginalCgroupCapturePreview>>,
) -> Result<AttachPreview> {
    let sanitized = sanitize_scope_component(target_name);
    let future_target_cgroup = format!("{}/target_{}", CGROUP_BASE, sanitized);

    let download_display = download
        .map(|v| BandwidthRate::parse(v).map(|p| p.to_string()))
        .transpose()?;
    let upload_display = upload
        .map(|v| BandwidthRate::parse(v).map(|p| p.to_string()))
        .transpose()?;

    let safety_preflight =
        build_attach_safety_preflight(pids, &future_target_cgroup, live_cgroup_previews);

    Ok(AttachPreview {
        pids: pids.to_vec(),
        future_target_cgroup,
        download: download_display,
        upload: upload_display,
        attach_source: "systemd scope probe".to_string(),
        strict_backend: "existing resolved-PID attach backend".to_string(),
        status: "preview only; not applied".to_string(),
        safety_preflight,
        experimental_attach_gate: None,
    })
}

pub(crate) fn with_experimental_attach_gate(
    mut preview: AttachPreview,
    gate: ExperimentalAttachGateChecklist,
) -> AttachPreview {
    preview.experimental_attach_gate = Some(gate);
    preview
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub(crate) fn render_attach_preview_section(output: &mut String, preview: &AttachPreview) {
    push_line(output, "");
    push_line(output, "  Future attach preview:");
    if preview.pids.is_empty() {
        push_line(output, "    discovered PID(s): (none)");
    } else {
        push_line(
            output,
            &format!("    discovered PID(s): {}", format_pid_list(&preview.pids)),
        );
    }
    push_line(
        output,
        &format!("    future target cgroup: {}", preview.future_target_cgroup),
    );
    push_line(
        output,
        &format!(
            "    requested download: {}",
            preview.download.as_deref().unwrap_or("unlimited")
        ),
    );
    push_line(
        output,
        &format!(
            "    requested upload: {}",
            preview.upload.as_deref().unwrap_or("unlimited")
        ),
    );
    push_line(
        output,
        &format!("    attach source: {}", preview.attach_source),
    );
    push_line(
        output,
        &format!("    strict backend: {}", preview.strict_backend),
    );
    push_line(output, &format!("    status: {}", preview.status));
    render_attach_safety_preflight_section(output, &preview.safety_preflight);
    if let Some(gate) = &preview.experimental_attach_gate {
        render_experimental_attach_gate_section(output, gate);
    }
}

fn format_pid_list(pids: &[u32]) -> String {
    pids.iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_wrapper::experimental_attach_gate::{
        evaluate_experimental_attach_gate, ExperimentalAttachConsent, ExperimentalAttachGateInput,
    };
    use crate::systemd_wrapper::plan::ScopeMode;

    // ---- build tests ----

    #[test]
    fn attach_preview_builds_with_correct_cgroup_path() {
        let preview =
            build_attach_preview("sleep", &[12345], Some("500kbit"), Some("500kbit"), None)
                .unwrap();

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
        assert_eq!(
            preview.safety_preflight.future_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_sleep"
        );
    }

    #[test]
    fn attach_preview_sanitizes_target_name() {
        let preview = build_attach_preview("Hello World!", &[], None, None, None).unwrap();

        assert_eq!(
            preview.future_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_hello_world"
        );
    }

    #[test]
    fn attach_preview_handles_missing_rates() {
        let preview = build_attach_preview("sleep", &[42], None, None, None).unwrap();

        assert_eq!(preview.download, None);
        assert_eq!(preview.upload, None);
    }

    #[test]
    fn attach_preview_handles_empty_pids() {
        let preview = build_attach_preview("sleep", &[], Some("1mbit"), None, None).unwrap();

        assert!(preview.pids.is_empty());
        assert_eq!(preview.download.as_deref(), Some("1 Mbit/s"));
    }

    // ---- render tests ----

    fn sample_preview() -> AttachPreview {
        build_attach_preview("sleep", &[12345], Some("500kbit"), Some("500kbit"), None).unwrap()
    }

    #[test]
    fn preview_includes_discovered_pids() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());
        assert!(output.contains("    discovered PID(s): 12345"));
    }

    #[test]
    fn preview_includes_future_target_cgroup() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());
        assert!(output.contains("    future target cgroup: /sys/fs/cgroup/zelynic/target_sleep"));
    }

    #[test]
    fn preview_includes_requested_download_and_upload() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());
        assert!(output.contains("    requested download: 500 Kbit/s"));
        assert!(output.contains("    requested upload: 500 Kbit/s"));
    }

    #[test]
    fn preview_says_preview_only_not_applied() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());
        assert!(output.contains("    status: preview only; not applied"));
    }

    #[test]
    fn preview_does_not_include_enforcement_words() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());
        assert!(
            !output.contains("enforced"),
            "preview must not say 'enforced'"
        );
        assert!(
            !output.contains("active limiter"),
            "preview must not say 'active limiter'"
        );
        assert!(
            !output.contains("attached"),
            "preview must not say 'attached'"
        );
        assert!(
            !output.contains("limited"),
            "preview must not say 'limited'"
        );
    }

    #[test]
    fn preview_empty_pids_handled_safely() {
        let empty_preview =
            build_attach_preview("sleep", &[], Some("500kbit"), None, None).unwrap();
        let mut output = String::new();
        render_attach_preview_section(&mut output, &empty_preview);
        assert!(output.contains("    discovered PID(s): (none)"));
        assert!(output.contains("preview only; not applied"));
    }

    #[test]
    fn preview_without_rates_shows_unlimited() {
        let no_rate_preview = build_attach_preview("sleep", &[42], None, None, None).unwrap();
        let mut output = String::new();
        render_attach_preview_section(&mut output, &no_rate_preview);
        assert!(output.contains("    requested download: unlimited"));
        assert!(output.contains("    requested upload: unlimited"));
    }

    #[test]
    fn preview_includes_attach_source_and_strict_backend() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());
        assert!(output.contains("    attach source: systemd scope probe"));
        assert!(output.contains("    strict backend: existing resolved-PID attach backend"));
    }

    #[test]
    fn preview_includes_attach_safety_preflight() {
        let mut output = String::new();
        render_attach_preview_section(&mut output, &sample_preview());

        assert!(output.contains("original cgroup capture preview:"));
        assert!(output.contains("rollback target: pending original cgroup capture"));
        assert!(output.contains("self-protection: required before attach"));
        assert!(output.contains("Future attach transaction plan:"));
        assert!(output.contains("execution: blocked"));
        assert!(output.contains("live attach: not implemented"));
    }

    #[test]
    fn preview_can_include_experimental_attach_gate_when_supplied() {
        let checklist = evaluate_experimental_attach_gate(ExperimentalAttachGateInput {
            execute: true,
            scope_mode: ScopeMode::System,
            probe_live: true,
            attach_live: true,
            is_root: true,
            consent: ExperimentalAttachConsent {
                experimental_single_pid_attach: true,
                i_understand_this_moves_pids: true,
                rollback_required: true,
            },
            discovered_pid_count: 1,
            original_cgroup_capture_valid: true,
            pid_liveness_alive: true,
            self_protection_allowed: true,
            transaction_model_only: true,
            mutation_mode_move_only: true,
            nft_tc_state_disabled: true,
        });
        let preview = with_experimental_attach_gate(sample_preview(), checklist);
        let mut output = String::new();

        render_attach_preview_section(&mut output, &preview);

        assert!(output.contains("Experimental attach gate:"));
        assert!(output.contains("mutation mode: move-only"));
        assert!(output.contains("nft/tc/state: disabled"));
        assert!(output.contains("final: blocked"));
        assert!(output.contains("reason: experimental PID move is not implemented yet"));
    }
}
