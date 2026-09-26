// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Dangerous-target guard — the blocklist of system processes that
//! must not be limited without the unified `--force-this` override
//! (NIGHT-improve-30: the former `--allow-dangerous`/`--force` pair
//! is one flag, same function).

#[cfg(feature = "ebpf")]
use anyhow::Result;

#[cfg(feature = "ebpf")]
use crate::output::eprintln_warn_labeled;

/// List of dangerous/system process names that should not be limited
/// without the --force-this flag. Limiting these can destabilize the system.
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
///
/// NIGHT-depthbore-1 (the end-to-end depth audit): the match is
/// family-aware, not exact. Two real-world name shapes defeat an
/// exact-only list, and both are live on every current distro:
///
/// 1. THE TRUNCATED TWIN. The kernel caps comm at 15 bytes, and the
///    display-name enrichment (NIGHT-engrave-7) restores the full
///    name from argv[0] — list-apps shows "systemd-resolved" while
///    the blocklist carried the kernel-truncated "systemd-resolve",
///    so the copy-pasted target sailed past this guard with no
///    --force-this. The same enriched comms feed strict-all's sweep
///    and block-all's filters (identity walk -> is_dangerous_target),
///    so system daemons whose true names exceed the cap (resolved,
///    journald, timesyncd, hostnamed, machined) were swept INTO the
///    user-app set — limited with no override asked at all.
/// 2. THE SPLIT-DAEMON SUFFIX. OpenSSH 9.8+ runs the per-connection
///    process as "sshd-session" — a fresh name the exact list never
///    carried, so a strict-all sweep rate-limited every active SSH
///    session on a modern server: the exact "limit myself out of
///    SSH" hazard this list exists to prevent.
///
/// The rule: a name is dangerous when it EXTENDS a blocklist entry
/// (case-insensitive prefix). Both shapes above are entry+suffix; the
/// rule also covers the user typing a truncated spelling
/// ("gnome-session-b" extends "gnome-session") and the split-era
/// siblings of every listed daemon. Fail-safe by design: an innocent
/// app that merely shares a prefix (a hypothetical "rootlesskit"
/// under "root") costs one --force-this, while a missed system
/// daemon costs the system.
#[cfg(feature = "ebpf")]
pub(crate) fn is_dangerous_target(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    DANGEROUS_TARGETS
        .iter()
        .any(|d| name_lower.starts_with(&d.to_lowercase()))
}

// NIGHT-depthbore-1: the family-aware blocklist contract pins live
// under the single test/ tree (cosmostrix Pattern C), #[path]-wired
// exactly like the eagle and strict pins.
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/commands/safety_tests.rs"]
mod tests;

/// Validate target against dangerous list. Returns Ok if safe, Err if dangerous.
#[cfg(feature = "ebpf")]
pub(crate) fn check_dangerous_target(target_str: &str, force_this: bool) -> Result<()> {
    // Numeric cgroup IDs are always allowed (user knows what they're doing).
    if target_str.parse::<u32>().is_ok() {
        return Ok(());
    }

    if is_dangerous_target(target_str) {
        if force_this {
            // NIGHT-improve-30: ONE warn line, the concise-safety
            // contract. The override names itself — the user typed
            // --force-this — and this line names which guard lifted
            // (the blocklist fired). The destabilization prose and
            // the 'unstrict' removal form are the error path's and
            // the success epilogue's words respectively; repeating
            // them here was the verbosity this task retired.
            eprintln_warn_labeled(&format!(
                "'{target_str}' is a system process — forcing with --force-this."
            ));
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "'{target_str}' is a system process. Limiting it may destabilize your system.\n  \
                 tip: re-run with --force-this if you really want this"
            ))
        }
    } else {
        Ok(())
    }
}
