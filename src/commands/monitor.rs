// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;

use crate::{auto, log, monitor, watch};

/// List network bandwidth usage per process.
///
/// Routes to the appropriate display mode: live TUI, JSON, verbose,
/// all-programs (default), or sorted high-to-low.
pub(crate) fn handle_list(
    usage_all: bool,
    high_to_low: bool,
    json: bool,
    live: Option<Option<u64>>,
    interval: Option<u64>,
    verbose: bool,
    iface_value: Option<&str>,
) -> Result<()> {
    if live.is_some() {
        // --live N (shorthand) takes priority, then --interval, then default 1
        let interval_secs = live.and_then(|v| v).or(interval).unwrap_or(1);
        monitor::display_usage_live(interval_secs, iface_value)?;
    } else if json {
        monitor::display_usage_json()?;
    } else if verbose {
        monitor::display_usage_verbose()?;
    } else if !usage_all && !high_to_low {
        // Default: show usage-all if no flag specified
        monitor::display_usage_all()?;
    } else if usage_all {
        monitor::display_usage_all()?;
    } else {
        monitor::display_usage_high_to_low()?;
    }
    Ok(())
}

/// Show bandwidth usage history.
pub(crate) fn handle_log(snapshot: bool, last: Option<u64>, json: bool) -> Result<()> {
    if snapshot {
        log::save_snapshot()
    } else {
        log::show_history(last, json)
    }
}

/// Watch bandwidth and alert when thresholds are exceeded.
pub(crate) fn handle_watch(
    target: &str,
    alert: &str,
    interval: u64,
    notify_cmd: Option<&str>,
) -> Result<()> {
    watch::watch_process(target, alert, interval, notify_cmd)
}

/// Auto-throttle daemon mode.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_auto(
    download: Option<&str>,
    upload: Option<&str>,
    target: Option<&str>,
    kill: bool,
    daemon: bool,
    interval: u64,
    iface_value: Option<&str>,
    status: bool,
) -> Result<()> {
    if status {
        auto::auto_status()
    } else {
        auto::run_auto(
            download,
            upload,
            target,
            kill,
            daemon,
            interval,
            iface_value,
        )
    }
}
