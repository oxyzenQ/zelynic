// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Dangerous-target guard — the blocklist of system processes that must
//! not be limited without an explicit `--force`.

#[cfg(feature = "ebpf")]
use anyhow::Result;

#[cfg(feature = "ebpf")]
use crate::output::eprintln_warn_labeled;

/// List of dangerous/system process names that should not be limited
/// without --force flag. Limiting these can destabilize the system.
pub(crate) const DANGEROUS_TARGETS: &[&str] = &[
    "root",
    "init",
    "kthreadd",
    "systemd",
    "systemd-journal",
    "systemd-logind",
    "systemd-udevd",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-hostnam",
    "systemd-machine",
    "systemd-oomd",
    "dbus-daemon",
    "dbus-broker",
    "polkitd",
    "rtkit-daemon",
    "wpa_supplicant",
    "NetworkManager",
    "gdm",
    "gdm3",
    "sddm",
    "sddm-helper",
    "lightdm",
    "sshd",
    "agetty",
    "login",
    "kerneloops",
    "irqbalance",
    "chronyd",
    "snapd",
    "udisksd",
    "upowerd",
    "accounts-daemon",
    "colord",
    "fwupd",
    "ModemManager",
    "avahi-daemon",
    "cupsd",
    "cups-browsed",
    "rsyslogd",
    "cron",
    "atd",
    "acpid",
    "bluetoothd",
    "bluez",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "pulseaudio",
    "gnome-shell",
    "gnome-session",
    "kwin_wayland",
    "kwin_x11",
    "Xorg",
    "Xwayland",
    "ksmserver",
    "plasmashell",
];

/// Check if a target name is dangerous (system process).
#[cfg(feature = "ebpf")]
pub(crate) fn is_dangerous_target(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    DANGEROUS_TARGETS
        .iter()
        .any(|d| d.to_lowercase() == name_lower)
}

/// Validate target against dangerous list. Returns Ok if safe, Err if dangerous.
#[cfg(feature = "ebpf")]
pub(crate) fn check_dangerous_target(target_str: &str, force: bool) -> Result<()> {
    // Numeric cgroup IDs are always allowed (user knows what they're doing).
    if target_str.parse::<u32>().is_ok() {
        return Ok(());
    }

    if is_dangerous_target(target_str) {
        if force {
            eprintln_warn_labeled(&format!(
                "'{target_str}' is a system process. Forcing with --force.\n  \
                 This may destabilize your system. Use 'zelynic unstrict {target_str}' to remove."
            ));
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "'{target_str}' is a system process. Limiting it may destabilize your system.\n  \
                 tip: re-run with --force if you really want this"
            ))
        }
    } else {
        Ok(())
    }
}
