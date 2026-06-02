// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::Result;

use crate::{profile, qos};

// --- Profile commands ---

/// Save a new bandwidth profile.
pub(crate) fn handle_profile_save(
    name: &str,
    download: Option<&str>,
    upload: Option<&str>,
) -> Result<()> {
    profile::save_profile(name, download, upload)
}

/// Apply a saved profile to a process.
pub(crate) fn handle_profile_apply(
    name: &str,
    target: &str,
    iface_value: Option<&str>,
) -> Result<()> {
    profile::apply_profile(name, target, iface_value)
}

/// List all saved profiles.
pub(crate) fn handle_profile_list() -> Result<()> {
    profile::list_profiles()
}

/// Delete a saved profile.
pub(crate) fn handle_profile_delete(name: &str) -> Result<()> {
    profile::delete_profile(name)
}

// --- QoS commands ---

/// Set high priority for a process.
pub(crate) fn handle_qos_high(target: &str, iface_value: Option<&str>) -> Result<()> {
    qos::set_priority(target, qos::PriorityTier::High, iface_value)
}

/// Set low priority for a process.
pub(crate) fn handle_qos_low(target: &str, iface_value: Option<&str>) -> Result<()> {
    qos::set_priority(target, qos::PriorityTier::Low, iface_value)
}

/// Show current QoS assignments.
pub(crate) fn handle_qos_status() -> Result<()> {
    qos::show_qos_status()
}

/// Reset all QoS rules.
pub(crate) fn handle_qos_reset(iface_value: Option<&str>) -> Result<()> {
    qos::reset_qos(iface_value)
}
