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
    // NIGHT-blade-18 (the micro-bug depth audit): the numeric bypass
    // is CLOSED. The old contract — "Numeric cgroup IDs are always
    // allowed (user knows what they're doing)" — let every cg: display
    // form route around this entire guard: eagle-eyes prints cg:<id>
    // for EVERY cgroup with traffic, including system daemons, and its
    // footer suggests exactly `ss cg:<id>`, so the monitor's own
    // suggestion could limit sshd's cgroup with no override asked
    // (the same "limit myself out of SSH" hazard this list exists to
    // prevent, arriving through the numeric door NIGHT-boost-37
    // opened for the round-trip). The id now resolves to its live
    // members and runs the same family-aware blocklist on their
    // names; --force-this lifts it exactly as it lifts names, and an
    // id with no live members (a dead id, or a container view whose
    // /proc walk resolves nothing) stays allowed — the policy against
    // it is a no-op, not a hazard.
    if let Some(id) = parse_target_id(target_str) {
        return check_dangerous_cgroup_id(id, force_this);
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

/// Parse a target token into a direct cgroup id — "48181", or the
/// canonical display form "cg:48181" (NIGHT-blade-18).
///
/// Mirrors `Target::parse`'s rule EXACTLY: a `cg:` prefix over a
/// numeric remainder is the id; anything else — including a
/// non-numeric remainder like "cg:brave" or a number beyond u32 — is
/// a process name and returns None. The mirror matters in both
/// directions: whatever the parser treats as an id the guard treats
/// as an id, and whatever stays a name keeps the name contract
/// (unknown names are the graceful no-op the battery pins).
#[cfg(feature = "ebpf")]
pub(crate) fn parse_target_id(s: &str) -> Option<u32> {
    let id_part = s.strip_prefix("cg:").unwrap_or(s);
    id_part.parse::<u32>().ok()
}

/// The pure verdict core of the cgroup-id guard: the first member
/// comm of a cgroup that trips the family-aware blocklist, if any.
/// Split from the /proc walk so the decision is unit-pinnable
/// independent of the machine's process table (NIGHT-blade-18).
#[cfg(feature = "ebpf")]
fn first_dangerous_member(member_comms: &[String]) -> Option<&str> {
    member_comms
        .iter()
        .map(|s| s.as_str())
        .find(|comm| is_dangerous_target(comm))
}

/// NIGHT-blade-18: the cgroup-id arm of the dangerous-target guard.
///
/// Walks /proc once, resolves every pid living in the target cgroup
/// (the same `pid_cgroup_id` / `pid_comm` canonical boundaries the
/// limiter's own name resolution uses), and runs the family-aware
/// blocklist on the member names: `ss cg:<sshd's-cgroup>` is refused
/// exactly like `ss sshd` is, with the same --force-this override and
/// the same wording family ("system process"), so the numeric door
/// and the name door enforce one contract.
///
/// Fail-safe directions, both deliberate:
///   - a cgroup hosting ANY blocklisted member is refused (kthreadd
///     lives in the root cgroup, so `cg:1` on a stock distro refuses);
///   - an id with NO live members (a dead id, or a container view
///     where the walk resolves nothing) stays allowed — the policy
///     written against it can never match a socket, so it is a
///     no-op, not a hazard.
#[cfg(feature = "ebpf")]
pub(crate) fn check_dangerous_cgroup_id(id: u32, force_this: bool) -> Result<()> {
    let mut members: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            if crate::ebpf::identity::pid_cgroup_id(pid) != Some(id) {
                continue;
            }
            if let Some(comm) = crate::ebpf::identity::pid_comm(pid) {
                if !members.iter().any(|m| m == &comm) {
                    members.push(comm);
                }
            }
        }
    }

    let Some(dangerous) = first_dangerous_member(&members) else {
        return Ok(());
    };

    if force_this {
        eprintln_warn_labeled(&format!(
            "'cg:{id}' (home of system process '{dangerous}') is a system process — forcing with --force-this."
        ));
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "'cg:{id}' (home of system process '{dangerous}') is a system process. Limiting it may destabilize your system.\n  \
             tip: re-run with --force-this if you really want this"
        ))
    }
}

/// NIGHT-blade-18: the colon-list grammar for the multi families
/// (strict-multi/sm, block-multi/bm, unstrict-multi/um).
///
/// The old parse was best-effort: trim, DROP empty segments, and let
/// anything else through as a name lookup. Three shapes that can only
/// be mistakes flowed silently:
///   - an EMPTY segment (`a::b`) — the dropped app was never limited,
///     and the user meant three apps, not two;
///   - a segment containing `/` (`a/`, `../../etc/passwd`) — comm can
///     never contain a path separator; the shape is a typo or a
///     traversal attempt, and as a name lookup it was always a no-op
///     that hid the mistake;
///   - a punctuation-only segment (`;`) — no alphanumeric characters
///     means no possible comm, and unquoted in a shell this exact
///     byte splits commands (`sm a:a/;/:1` — the owner's fatal
///     example, whose segments are ALL refused now).
///
/// What stays deliberately legal: numeric and `cg:<id>` segments
/// (their semantics belong to the cgroup-id guard above, not the
/// grammar), and alnum-bearing garbage like `$(reboot)` — the
/// no-execution proof the single-target battery pins (the payload is
/// echoed verbatim as data, never executed, never silently dropped).
///
/// Returns the validated segments (trimmed, in order). The all-empty
/// list keeps the historical "No targets specified" shape with the
/// family's own example command.
#[cfg(feature = "ebpf")]
pub(crate) fn validate_multi_targets(targets_str: &str, example: &str) -> Result<Vec<String>> {
    let segments: Vec<String> = targets_str
        .split(':')
        .map(|s| s.trim().to_string())
        .collect();

    if segments.iter().all(|s| s.is_empty()) {
        return Err(anyhow::anyhow!(
            "No targets specified. Use colon-separated list.\n  \
             Example: {example}"
        ));
    }

    if segments.iter().any(|s| s.is_empty()) {
        return Err(anyhow::anyhow!(
            "empty target in the list — '{targets_str}' (check the colons)"
        ));
    }

    for seg in &segments {
        if seg.contains('/') {
            return Err(anyhow::anyhow!(
                "target '{seg}' is not a valid app name (contains '/')"
            ));
        }
        if !seg.chars().any(|c| c.is_alphanumeric()) {
            return Err(anyhow::anyhow!("target '{seg}' is not a valid app name"));
        }
    }

    Ok(segments)
}
