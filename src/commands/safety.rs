// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Dangerous-target guard — the blocklist of system processes that
//! must not be limited without the unified `--force-this` override
//! (NIGHT-improve-30: the former `--allow-dangerous`/`--force` pair
//! is one flag, same function).

#[cfg(feature = "ebpf")]
use anyhow::Result;

#[cfg(feature = "ebpf")]
use crate::output::eprintln_warn_labeled;

// night-total-hardening-1 (the LOC-cap split, the improve-44 law):
// the id-door family — parse_target_id, the root catch-all, the
// member walk, the batched multi guard — moved to safety_id.rs (the
// sibling mod.rs declares it) as ONE cohesive concern. The
// re-export keeps every caller path (crate::commands::safety::*,
// the pins' `use super::*`) resolving identically: a pure move,
// gates green in between.
#[cfg(feature = "ebpf")]
pub(crate) use super::safety_id::{
    cgroupfs_root_id, check_dangerous_cgroup_id, check_dangerous_targets_multi,
    check_root_catch_all_resolved, parse_target_id,
};

/// List of dangerous/system process names that should not be limited
/// without the --force-this flag. Limiting these can destabilize the system.
///
/// NIGHT-ux-3 (the live-run find): the roster is NAME-based by
/// contract — the owner's own workloads run as root (a python3
/// trading bot is limited on purpose), so no uid guard belongs here;
/// unbound, sshguard, and the firewall/DHCP family joined after an
/// `s --all` sweep limited them on the host.
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
    // NIGHT-ux-3: the network-critical services — DNS, intrusion
    // prevention, wireless/DHCP control, and the firewall family.
    // Limiting any of them can take down the host's name resolution,
    // remote access, or connectivity wholesale.
    "unbound",
    "sshguard",
    "fail2ban",
    "iwd",
    "dhclient",
    "dhcpcd",
    "connman",
    "nft",
    "iptables",
    "firewalld",
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
///    --force-this. The same enriched comms feed the s --all sweep
///    and the b --all filters (identity walk -> is_dangerous_target),
///    so system daemons whose true names exceed the cap (resolved,
///    journald, timesyncd, hostnamed, machined) were swept INTO the
///    user-app set — limited with no override asked at all.
/// 2. THE SPLIT-DAEMON SUFFIX. OpenSSH 9.8+ runs the per-connection
///    process as "sshd-session" — a fresh name the exact list never
///    carried, so an s --all sweep rate-limited every active SSH
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

/// The sweeps' shared skip note (NIGHT-ux-3, reworded NIGHT-ux-4):
/// "24 were skipped" forced the reader to guess WHICH services the
/// sweep protected — the live run skipped unbound (the host's DNS) and
/// the count alone never said so. NIGHT-ux-4 then fixed the ux-3
/// wording's own mismatch: the live run printed "26 system app(s) …
/// (24 total)" where 26 counted cgroup rows, 24 counted distinct
/// names, and both were called "apps". The honest unit is the cgroup
/// — the sweep iterates cgroup rows — so the headline says "system
/// cgroups"; when a daemon owns several cgroups the name count is
/// labeled beside it ("across M names") and the "(N total)" tail is
/// gone, so the two counts can never masquerade as one.
///
/// The roster stays the first six distinct names sorted; when even
/// that roster clears ~120 cols (the narrow-terminal fallback) it is
/// explicitly a sample: "first six:".
///
/// `comms` is the per-identity-row skip list (a daemon in several
/// cgroups repeats — that repeat is exactly the rows/names gap the
/// headline now labels); the names dedup inside. Pure — both sweep
/// lanes (s --all, b --all) print it through the labeled warn channel,
/// which owns the "! " prefix.
#[cfg(feature = "ebpf")]
pub(crate) fn skipped_system_apps_note(comms: &[String]) -> String {
    const SAMPLE: usize = 6;
    const MAX_COLS: usize = 120;

    let rows = comms.len();
    let mut names: Vec<&str> = comms.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    let listed = names
        .iter()
        .take(SAMPLE)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    // The headline counts what the sweep iterates (cgroup rows); a
    // name owning several cgroups gets its own label instead of the
    // old "(N total)" tail that read as a second app count.
    let head = if names.len() < rows {
        format!("Skipped {rows} system cgroups across {} names", names.len())
    } else {
        format!("Skipped {rows} system cgroups")
    };
    let wide = format!("{head} — {listed} — re-run with --force-this to include.");
    if wide.chars().count() > MAX_COLS {
        format!("{head} — first six: {listed} — re-run with --force-this to include.")
    } else {
        wide
    }
}

// NIGHT-depthbore-1: the family-aware blocklist contract pins live
// under the single test/ tree (cosmostrix Pattern C), #[path]-wired
// exactly like the eagle and strict pins.
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/commands/safety_tests.rs"]
mod tests;

/// NIGHT-dinner-16 (the verifier-lineage mandate): the single-target
/// input boundary. An empty or whitespace-only target can only be a
/// mistake — a live process's comm is never empty, so the /proc walk
/// can never match it — yet the old path let `Target::parse("")`
/// flow as a `ProcessName("")` past every input check: the error a
/// non-root user saw first was "root required" (the parse-before-
/// execute ladder violated at its first rung), and `unstrict ""` read
/// as a no-match with an invisible target name. Refused at the same
/// boundary as the rate ladder and the blocklist, before any
/// privilege ask.
#[cfg(feature = "ebpf")]
pub(crate) fn validate_single_target(target_str: &str, example: &str) -> Result<()> {
    if target_str.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "target is empty — pass a process name or cgroup ID\n  \
             Example: {example}"
        ));
    }
    // night-total-hardening-1 (the owner's safety call, the numeric
    // class): an all-digit target beyond the 32-bit id space can
    // never name a cgroup — the maps key on the kernel's u32 kernfs
    // inode numbers — and the old path let it flow as a ProcessName
    // into a guaranteed no-match whose only answer was the /proc
    // walk's silence. The refusal names the bound instead, for both
    // spellings (the bare digits and the cg: display prefix).
    // Tradeoff, named: a pathological comm that is ALL digits and
    // longer than u32 would refuse here too — no real-world comm
    // has that shape, and the bound it teaches is worth the edge.
    let id_part = target_str.strip_prefix("cg:").unwrap_or(target_str);
    if !id_part.is_empty()
        && id_part.bytes().all(|b| b.is_ascii_digit())
        && id_part.parse::<u32>().is_err()
    {
        return Err(anyhow::anyhow!(
            "'{target_str}' is too large for a cgroup id — the kernel numbers them inside 32 bits\n  \
             tip: 'zelynic list-apps' prints live ids as cg:<number>"
        ));
    }
    Ok(())
}

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

// NIGHT-improve-53: the '::' list grammar moved to its own module
// (target_grammar.rs) with the masterclass unification — strict /
// block / unstrict are one verb each now, and the list law they
// route by (target_is_list + validate_multi_targets) is a theme of
// its own. The blade-18 / hunt-30 history rides with it.
