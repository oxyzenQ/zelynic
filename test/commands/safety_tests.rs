// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the dangerous-target guard (NIGHT-depthbore-1): the
//! family-aware match rule, the two real-world name shapes it closes,
//! and the check_dangerous_target verdict ladder. The blocklist is a
//! SAFETY NET for system stability — every pin here fails in the safe
//! direction (an over-blocked innocent costs one --force-this; a
//! missed daemon costs the system).

use super::*;

/// The exact spellings stay blocked — the rule is a superset of the
/// old exact match, so nothing that was guarded before can slip now.
#[test]
fn exact_blocklist_names_stay_dangerous() {
    for name in [
        "root",
        "sshd",
        "systemd",
        "systemd-resolve",
        "systemd-journal",
        "NetworkManager",
        "gnome-shell",
        "plasmashell",
        "Xorg",
    ] {
        assert!(
            is_dangerous_target(name),
            "the exact blocklist name '{name}' must stay dangerous"
        );
    }
}

/// THE TRUNCATED TWIN (NIGHT-depthbore-1's find): the display-name
/// enrichment (NIGHT-engrave-7) restores the full daemon name from
/// argv[0] while the blocklist carried the kernel's 15-byte truncated
/// forms — list-apps showed "systemd-resolved", the guard compared
/// against "systemd-resolve", and the copy-pasted target (and the
/// strict-all sweep, which matches the same enriched comms) sailed
/// past with no --force-this. Every enriched twin must be dangerous.
#[test]
fn enriched_daemon_names_are_dangerous() {
    for name in [
        "systemd-resolved",
        "systemd-journald",
        "systemd-timesyncd",
        "systemd-hostnamed",
        "systemd-machined",
        "systemd-user-sessions",
    ] {
        assert!(
            is_dangerous_target(name),
            "the enriched daemon name '{name}' must be dangerous — \
             strict-all sweeps these comms"
        );
    }
}

/// THE SPLIT-DAEMON SUFFIX: OpenSSH 9.8+ runs each connection's
/// process as "sshd-session" — a fresh name the exact list never
/// carried, so a strict-all sweep rate-limited every active SSH
/// session (the exact hazard this list exists to prevent).
#[test]
fn split_daemon_siblings_are_dangerous() {
    assert!(is_dangerous_target("sshd-session"));
    assert!(is_dangerous_target("sshd-auth"));
    // The same family rule across case and the truncated spelling a
    // user might type from an old listing.
    assert!(is_dangerous_target("SSHD-Session"));
    assert!(is_dangerous_target("gnome-session-b"));
    assert!(is_dangerous_target("KWin_Waylandx"));
}

/// Ordinary apps stay clean — the prefix rule must not leak into the
/// names owners actually limit (the fail-safe direction only costs
/// --force-this, but the common set must stay friction-free).
#[test]
fn ordinary_app_names_stay_clean() {
    for name in [
        "brave",
        "firefox",
        "chrome",
        "curl",
        "wget",
        "pacman",
        "steam",
        "transmission",
        "my-app",
        // An INCOMPLETE prefix is not the entry: "pipewir" does not
        // extend "pipewire".
        "pipewir",
        "ssh",
        "system",
    ] {
        assert!(
            !is_dangerous_target(name),
            "the ordinary name '{name}' must stay clean"
        );
    }
}

/// The verdict ladder: the enriched spelling refuses without the
/// override and passes with it; numeric cgroup IDs bypass the name
/// guard entirely (the user targets the id deliberately).
#[test]
fn check_dangerous_target_verdict_ladder() {
    let err = check_dangerous_target("systemd-resolved", false)
        .expect_err("the enriched spelling must refuse without the override");
    let msg = format!("{err}");
    assert!(
        msg.contains("'systemd-resolved' is a system process"),
        "the refusal must name the target, got: {msg}"
    );
    assert!(
        msg.contains("--force-this"),
        "the refusal must teach the override, got: {msg}"
    );

    check_dangerous_target("systemd-resolved", true).expect("the override lifts the guard");
    check_dangerous_target("12345", false).expect("numeric ids bypass the name guard");
    check_dangerous_target("brave", false).expect("ordinary names pass");
}

/// The fail-safe direction, pinned as a CONTRACT: a hypothetical
/// innocent app that merely shares a prefix with a blocklist entry
/// ("rootlesskit" extends "root") is blocked — one --force-this is
/// the accepted cost, because the miss direction breaks systems.
#[test]
fn prefix_lookalikes_block_in_the_safe_direction() {
    assert!(is_dangerous_target("rootlesskit"));
    assert!(is_dangerous_target("cronhelper"));
}

/// NIGHT-blade-18: the numeric-target parse table. The mirror rule is
/// the whole contract — whatever `Target::parse` treats as an id, the
/// guard treats as an id; everything else keeps the name contract
/// (unknown names are the graceful no-op the battery pins).
#[test]
fn parse_target_id_mirrors_the_target_grammar() {
    assert_eq!(parse_target_id("48181"), Some(48181));
    assert_eq!(parse_target_id("cg:48181"), Some(48181));
    assert_eq!(parse_target_id("cg:0"), Some(0));
    assert_eq!(
        parse_target_id("cg:brave"),
        None,
        "a non-numeric remainder stays a name (the boost-37 typo contract)"
    );
    assert_eq!(parse_target_id("brave"), None);
    assert_eq!(parse_target_id(""), None);
    assert_eq!(
        parse_target_id("99999999999999999999"),
        None,
        "beyond u32 stays a name — the graceful no-op the battery pins"
    );
}

/// NIGHT-blade-18: the cgroup-id verdict core — a cgroup is dangerous
/// when ANY live member trips the family-aware blocklist (kthreadd in
/// the root cgroup, the truncated/split daemon shapes), and an id
/// with no live members is the allowed no-op direction.
#[test]
fn first_dangerous_member_finds_system_processes_in_a_cgroup() {
    let members = |names: &[&str]| -> Vec<String> { names.iter().map(|s| s.to_string()).collect() };
    assert_eq!(
        first_dangerous_member(&members(&["kthreadd", "bash"])),
        Some("kthreadd"),
        "the root cgroup's kthread member refuses the id"
    );
    assert_eq!(
        first_dangerous_member(&members(&["bash", "systemd-journald"])),
        Some("systemd-journald"),
        "the family rule covers the daemon shapes, found in any position"
    );
    assert_eq!(
        first_dangerous_member(&members(&["brave", "firefox", "curl"])),
        None,
        "a user-app cgroup flows friction-free"
    );
    assert_eq!(
        first_dangerous_member(&[]),
        None,
        "no live members = the allowed no-op direction (dead id, container view)"
    );
}

/// NIGHT-blade-18: the numeric door and the name door enforce ONE
/// contract. Resolved against the test process's OWN cgroup, so the
/// pin works on any machine: the test binary's comm is never
/// blocklisted, and on container views where the walk resolves no
/// members the verdict is the allowed no-op — both directions safe.
/// NIGHT-hunt-Z3: when the test process's own cgroup IS the cgroupfs
/// root (a container or no-systemd view — everything lives in the
/// namespace root there), the pin's user-cgroup premise does not
/// hold and the root position's refusal is the CORRECT contract;
/// the skip names it instead of failing environment-lucky.
#[test]
fn the_own_cgroup_id_flows_friction_free() {
    if let Some(cg) = crate::ebpf::identity::pid_cgroup_id(std::process::id()) {
        if Some(cg) == cgroupfs_root_id() {
            return; // the own cgroup is the root — see the docstring
        }
        assert!(
            check_dangerous_target(&format!("cg:{cg}"), false).is_ok(),
            "the boost-37 round-trip: a live user cgroup never trips the guard"
        );
        assert!(
            check_dangerous_target(&format!("{cg}"), false).is_ok(),
            "the bare numeric form of the same id answers identically"
        );
    }
}

/// NIGHT-hunt-Z3: the root catch-all verdict ladder, pinned against
/// the live cgroupfs root id — the position check fires BEFORE the
/// member walk (the fail-open that let a container view's root id
/// through with zero members and a whole-machine policy), refuses
/// without the override naming the blast radius, and lifts with it.
/// The wording keeps the "system process" family the blade-18
/// battery needles pin, so the supermassive dynamic cases (kthreadd's
/// home = the root in the no-systemd CI guest) ride one contract.
#[test]
fn the_root_catch_all_refuses_the_cgroupfs_root_id() {
    let Some(root) = cgroupfs_root_id() else {
        return; // no cgroupfs on this machine — the honest absence
    };
    let err = check_dangerous_cgroup_id(root, false)
        .expect_err("the root position must refuse without the override");
    let msg = format!("{err}");
    assert!(
        msg.contains("is the root cgroup"),
        "the refusal names the position, got: {msg}"
    );
    assert!(
        msg.contains("EVERY socket on the machine"),
        "the refusal names the blast radius, got: {msg}"
    );
    assert!(
        msg.contains("system process"),
        "the wording keeps the battery's needle family, got: {msg}"
    );
    assert!(
        msg.contains("--force-this"),
        "the refusal teaches the override, got: {msg}"
    );
    check_dangerous_cgroup_id(root, true).expect("the override lifts the root position");
}

/// NIGHT-hunt-Z3: the resolved-position check — the post-privilege
/// arm that answers the question neither door can: does the target
/// RESOLVE to the cgroupfs root? The id spelling refuses and lifts;
/// a non-root id and an unresolvable name flow friction-free. (The
/// name-resolving-to-root shape is the no-systemd-guest lane —
/// pinned end to end by the supermassive battery's dynamic cases,
/// not unitable without a process living in the root.)
#[test]
fn the_resolved_position_check_covers_the_root_spelling() {
    let Some(root) = cgroupfs_root_id() else {
        return;
    };
    use crate::ebpf::limiter::Target;
    let err = check_root_catch_all_resolved(&[Target::CgroupId(root)], false)
        .expect_err("the resolved root id must refuse");
    let msg = format!("{err}");
    assert!(
        msg.contains(&format!("cg:{root}")),
        "the refusal names the root id, got: {msg}"
    );
    check_root_catch_all_resolved(&[Target::CgroupId(root)], true)
        .expect("the override lifts the resolved root");
    check_root_catch_all_resolved(&[Target::CgroupId(root.wrapping_add(1))], false)
        .expect("a non-root id flows friction-free");
    check_root_catch_all_resolved(
        &[Target::ProcessName(
            "zelynic-no-such-comm-anywhere".to_string(),
        )],
        false,
    )
    .expect("an unresolvable name flows friction-free (the graceful no-match lane)");
}

/// NIGHT-hunt-28: the guard's name population resolves through ONE
/// snapshot now (the per-name resolve_name loop was O(names x
/// /proc), the residual hunt-27 named). The batched lane keeps the
/// guard's own contracts: a clean multi-name list flows
/// friction-free, and the id spelling AFTER clean names still
/// refuses at its list position (targets iterated in order, the
/// verdict at the first hit — the order the per-name loop owned).
#[test]
fn the_resolved_position_check_batches_the_name_list() {
    let Some(root) = cgroupfs_root_id() else {
        return;
    };
    use crate::ebpf::limiter::Target;
    check_root_catch_all_resolved(
        &[
            Target::ProcessName("zelynic-no-such-comm-a".to_string()),
            Target::ProcessName("zelynic-no-such-comm-b".to_string()),
            Target::CgroupId(root.wrapping_add(1)),
        ],
        false,
    )
    .expect("the clean multi-name list flows friction-free through the snapshot");
    let err = check_root_catch_all_resolved(
        &[
            Target::ProcessName("zelynic-no-such-comm-a".to_string()),
            Target::CgroupId(root),
        ],
        false,
    )
    .expect_err("the root id after clean names still refuses");
    let msg = format!("{err}");
    assert!(
        msg.contains(&format!("cg:{root}")),
        "the refusal names the root id at its list position, got: {msg}"
    );
}

/// NIGHT-dinner-16 (the verifier-lineage mandate): the single-target
/// input boundary — an empty or whitespace-only target can only be a
/// mistake (a live comm is never empty, so the /proc walk can never
/// match it), and it dies at the parse-before-execute rung, before the
/// blocklist and the root ask. The error names the fix with the
/// family's own example command.
#[test]
fn empty_single_target_is_refused_at_the_input_boundary() {
    let ex = "zelynic strict-single brave 100kb";
    for empty in ["", " ", "\t", "  \t "] {
        let msg = validate_single_target(empty, ex)
            .expect_err("an empty target must be refused")
            .to_string();
        assert!(
            msg.contains("target is empty"),
            "the verdict must lead, got: {msg}"
        );
        assert!(
            msg.contains(ex),
            "the refusal must carry the family's example command, got: {msg}"
        );
    }
    assert!(
        validate_single_target("brave", ex).is_ok(),
        "a real target passes the boundary untouched"
    );
    assert!(
        validate_single_target("cg:48181", ex).is_ok(),
        "the canonical display prefix round-trips the boundary"
    );
}

/// NIGHT-improve-50: the batched multi danger guard — one /proc walk
/// for every numeric segment in a colon list (the per-segment loop
/// was O(segments x processes); a fleet-scale strict-multi walked
/// /proc thousands of times before the policy write ever ran). The
/// batch must keep the loop's three observable contracts: segment
/// order (first refusal wins), the fail-open for ids with no live
/// members (a dead id is a no-op policy, not a hazard), and the
/// clean pass for a live user cgroup — plus the root position's
/// refusal with the same wording the single-id arm owns (both arms
/// share root_catch_all_verdict now; this pin holds that sharing).
#[test]
fn the_multi_danger_guard_batches_without_changing_the_verdicts() {
    let Some(root) = cgroupfs_root_id() else {
        return; // no cgroupfs on this machine — the honest absence
    };
    // The clean fleet: a dead id (fail-open) and, when the test
    // process's own cgroup differs from the root, the live user
    // cgroup — both must pass exactly as the single arm passes them.
    let dead = "4294967295"; // u32::MAX, effectively never a kernfs id
    let mut segments = vec![dead.to_string()];
    if let Some(cg) = crate::ebpf::identity::pid_cgroup_id(std::process::id()) {
        if cg != root {
            segments.push(cg.to_string());
        }
    }
    check_dangerous_targets_multi(&segments, false)
        .expect("the clean numeric list passes the batched guard");
    // The root anywhere in the list refuses, and the refusal is the
    // single arm's wording verbatim (the shared verdict path).
    for spelled in [
        vec![root.to_string()],
        vec![dead.to_string(), root.to_string()],
        vec![root.to_string(), dead.to_string()],
    ] {
        let err = check_dangerous_targets_multi(&spelled, false)
            .expect_err("the root position must refuse through the batch");
        assert_eq!(
            format!("{err}"),
            format!(
                "{}",
                check_dangerous_cgroup_id(root, false).expect_err("the single arm refuses too")
            ),
            "the batch's root refusal is the single arm's wording, verbatim"
        );
    }
    check_dangerous_targets_multi(&[root.to_string()], true)
        .expect("the override lifts the batched root position");
}

/// NIGHT-improve-50: the batch's segment ORDER — first refusal wins,
/// the same order the per-segment loop owned. A dangerous NAME in
/// segment 1 with the root id in segment 2 must refuse on the name;
/// reversed, it must refuse on the root. Both orderings are cheap to
/// prove without fabricating processes: the name arm is a string
/// check, the root arm is the live position.
#[test]
fn the_multi_danger_guard_keeps_first_refusal_order() {
    let Some(root) = cgroupfs_root_id() else {
        return; // no cgroupfs on this machine — the honest absence
    };
    let name_first = ["sshd".to_string(), root.to_string()];
    let err = check_dangerous_targets_multi(&name_first, false)
        .expect_err("the name segment refuses first");
    assert!(
        format!("{err}").contains("'sshd' is a system process"),
        "segment 1's name refusal wins, got: {err}"
    );
    let root_first = [root.to_string(), "sshd".to_string()];
    let err = check_dangerous_targets_multi(&root_first, false)
        .expect_err("the root segment refuses first");
    assert!(
        format!("{err}").contains("is the root cgroup"),
        "segment 1's root refusal wins, got: {err}"
    );
    // Mixed clean content passes untouched.
    check_dangerous_targets_multi(&["brave".to_string(), "curl".to_string()], false)
        .expect("the clean name list passes the batched guard");
}
