// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;

use crate::limiter;

/// Apply bandwidth limits (strict) for a specific process.
///
/// Resolves optional preset values, then delegates to the limiter backend.
pub(crate) fn handle_strict(
    download: Option<String>,
    upload: Option<String>,
    preset: Option<String>,
    diagnose: bool,
    target: &str,
    iface_value: Option<&str>,
) -> Result<()> {
    // Resolve preset values if specified
    let (mut dl_value, mut ul_value) = (download, upload);

    if let Some(preset_name) = preset {
        // Validate preset name
        let preset_lower = preset_name.to_lowercase();
        let (preset_dl, preset_ul) = match preset_lower.as_str() {
            "gaming" => ("50mb", "50mb"),
            "streaming" => ("10mb", "5mb"),
            "background" => ("500kb", "100kb"),
            _ => {
                eprintln!(
                    "Unknown preset: {}. Available: gaming, streaming, background",
                    preset_name
                );
                std::process::exit(1);
            }
        };

        dl_value = Some(preset_dl.to_string());
        ul_value = Some(preset_ul.to_string());

        println!(
            "Using {} preset: {} down / {} up",
            preset_lower, preset_dl, preset_ul
        );
    }

    limiter::apply_limit_with_diagnostics(
        target,
        dl_value.as_deref(),
        ul_value.as_deref(),
        iface_value,
        diagnose,
    )
}

/// Remove all bandwidth limits from a process.
pub(crate) fn handle_unstrict(target: &str) -> Result<()> {
    limiter::remove_limit(target)
}

/// Refresh an existing limit after a target process respawns.
pub(crate) fn handle_refresh(target: &str) -> Result<()> {
    limiter::refresh_limit(target)
}

/// Show active bandwidth limits.
pub(crate) fn handle_status() -> Result<()> {
    limiter::list_active_limits()
}

/// Clean up orphaned bandwidth limits.
pub(crate) fn handle_clean(all: bool) -> Result<()> {
    if all {
        limiter::emergency_cleanup()
    } else {
        limiter::clean_orphans()
    }
}
