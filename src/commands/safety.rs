// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Dangerous-target guard — the blocklist of system processes that
//! must not be limited without the unified `--force-this` override
//! (NIGHT-improve-30: the former `--allow-dangerous`/`--force` pair
//! is one flag, same function).

#[cfg(feature = "ebpf")]
use anyhow::Result;

#[cfg(feature = "ebpf")]
use std::os::unix::fs::MetadataExt;

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

/// The cgroupfs mount's own kernfs id, truncated to u32 the same way
/// every id in the pipeline truncates (NIGHT-hunt-Z3): the hooks
/// attach at `/sys/fs/cgroup` and the AMMSP ancestor walk resolves
/// every socket in the namespace through this node's row when it
/// carries a policy — the machine-wide catch-all position. A
/// missing/unmounted cgroupfs is `None`, and every caller treats
/// that as "no root check possible" (the same honest absence the
/// id-arm walk's fail-open already owns for dead leaves).
#[cfg(feature = "ebpf")]
pub(crate) fn cgroupfs_root_id() -> Option<u32> {
    std::fs::metadata("/sys/fs/cgroup")
        .ok()
        .map(|m| m.ino() as u32)
}

/// The root catch-all verdict (NIGHT-hunt-Z3): a policy keyed at the
/// cgroupfs root is NOT one app's limit — the ancestor walk resolves
/// EVERY socket in the namespace through it, so the honest wording
/// names the blast radius, keeps the "system process" family the
/// batteries pin, and teaches the same `--force-this` lift every
/// other guard arm teaches. Pure message pair so the wording is
/// unit-pinnable (the warn side prints via the labeled channel the
/// force path already uses).
#[cfg(feature = "ebpf")]
fn root_catch_all_verdict(spelling: &str, id: u32, force_this: bool) -> Result<()> {
    if force_this {
        eprintln_warn_labeled(&format!(
            "'{spelling}' is the root cgroup (cg:{id}), a system process home — the policy catches EVERY socket on the machine, not one app's traffic. Forcing with --force-this."
        ));
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "'{spelling}' is the root cgroup (cg:{id}), a system process home — its policy catches EVERY socket on the machine through the ancestor walk, not one app's traffic.\n  \
             tip: re-run with --force-this if you really want this"
        ))
    }
}

/// NIGHT-hunt-Z3: the resolved-position check, post-privilege by
/// design. The pre-root rung stays the blocklist's (pure input
/// validation, pinned by the nonroot battery's "root required"
/// ladder); this arm runs after `ensure_root`, when the operator has
/// already asked for privilege, and answers the question neither
/// door below can: does the target RESOLVE to the cgroupfs root?
///
/// The holes it closes, all one shape — the root's policy is a
/// catch-all whatever spelling reached it:
///   - the name door: a non-blocklisted comm living IN the root
///     cgroup (a multi-threaded daemon on a no-systemd guest, where
///     every comm's cgroup IS the root — `strict <daemon>` landed a
///     machine-wide throttle with no warning and no override asked);
///   - the id door's member-walk fail-open: an id whose /proc walk
///     resolves no members (a container view where kthreadd is
///     invisible) was reasoned "a no-op, it can never match a
///     socket" — true for dead LEAF ids, false for the root, whose
///     row the ancestor walk matches for every socket regardless of
///     member visibility;
///   - the sweeps' force path: block-all --force-this mapped every
///     identity row to its cgroup id, the root row included — a
///     rate-0 write on the root is machine-wide network death.
///
/// Container targets are excluded on purpose: they resolve to the
/// workload's own scope subtree, never the namespace root.
#[cfg(feature = "ebpf")]
pub(crate) fn check_root_catch_all_resolved(
    targets: &[crate::ebpf::limiter::Target],
    force_this: bool,
) -> Result<()> {
    let Some(root_id) = cgroupfs_root_id() else {
        return Ok(());
    };
    for target in targets {
        let spelling = match target {
            crate::ebpf::limiter::Target::CgroupId(id) => {
                if *id == root_id {
                    format!("cg:{id}")
                } else {
                    continue;
                }
            }
            crate::ebpf::limiter::Target::ProcessName(name) => {
                if super::eagle::resolve_name(name).contains(&root_id) {
                    name.clone()
                } else {
                    continue;
                }
            }
            crate::ebpf::limiter::Target::Container(_) => continue,
        };
        return root_catch_all_verdict(&spelling, root_id, force_this);
    }
    Ok(())
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
///     no-op, not a hazard. NIGHT-hunt-Z3 correction: that reasoning
///     is sound for LEAF positions only; the root id itself is
///     answered by the position check above before this walk ever
///     runs (its row matches every socket regardless of members).
#[cfg(feature = "ebpf")]
pub(crate) fn check_dangerous_cgroup_id(id: u32, force_this: bool) -> Result<()> {
    // NIGHT-hunt-Z3: the root POSITION first, before the member walk
    // — the walk's fail-open ("an id with no live members ... can
    // never match a socket") is sound for dead leaf ids and UNSOUND
    // for the root: a container view where kthreadd is invisible
    // resolves no members for the root id, yet the ancestor walk
    // matches the root's row for every socket on the machine. The
    // position is one stat away and does not depend on /proc at all.
    if Some(id) == cgroupfs_root_id() {
        return root_catch_all_verdict(&format!("cg:{id}"), id, force_this);
    }

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
    // charger-core-2: a container URI anywhere in the list is a named
    // mistake — the colon grammar and the URI grammar fight over the
    // same bytes ('docker://nginx:brave' splits into 'docker',
    // '//nginx', 'brave'), so the refusal names the real fix
    // instead of letting the '/' check complain about a fragment the
    // URI never meant as a target.
    if targets_str.contains("://") {
        return Err(anyhow::anyhow!(
            "container targets (docker://<name>, k8s://<namespace>/<pod>) are \
             single-target verbs — apply each with strict-single"
        ));
    }

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
