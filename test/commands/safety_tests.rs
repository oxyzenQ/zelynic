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
#[test]
fn the_own_cgroup_id_flows_friction_free() {
    if let Some(cg) = crate::ebpf::identity::pid_cgroup_id(std::process::id()) {
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

/// NIGHT-blade-18: the colon-list grammar. The owner's exact examples
/// are the contract: `sm a:b:c` is fine, `sm a:a/;/:1` is refused —
/// every segment of the fatal string (the path shape, the
/// punctuation-only shape) is named by the grammar, and the numeric
/// segment's semantics belong to the id guard, not the grammar.
#[test]
fn multi_list_grammar_refuses_the_mistake_shapes() {
    let ex = "zelynic strict-multi brave:curl:pacman 1mb";
    // The fine shapes.
    assert!(
        validate_multi_targets("a:b:c", ex).is_ok(),
        "the owner's fine example"
    );
    assert!(validate_multi_targets("brave:curl:pacman", ex).is_ok());
    assert!(
        validate_multi_targets("  brave : curl  ", ex).is_ok(),
        "trim is part of the contract"
    );
    assert!(
        validate_multi_targets("x:1", ex).is_ok(),
        "numeric segments are grammar-clean; the id guard owns their semantics"
    );
    assert!(
        validate_multi_targets("cg:48181:brave", ex).is_ok(),
        "the display form rides along"
    );
    assert!(
        validate_multi_targets("$(reboot):b", ex).is_ok(),
        "alnum-bearing garbage keeps the no-execution no-op class the battery pins"
    );
    // The fatal shapes.
    let err = validate_multi_targets("a:a/;/:1", ex).unwrap_err();
    assert!(
        err.to_string().contains("not a valid app name"),
        "the owner's fatal example is refused by name: {err}"
    );
    assert!(
        validate_multi_targets("a::b", ex)
            .unwrap_err()
            .to_string()
            .contains("empty target"),
        "a dropped segment is a named mistake, not a silent drop"
    );
    assert!(
        validate_multi_targets("x:;;:y", ex)
            .unwrap_err()
            .to_string()
            .contains("not a valid app name"),
        "punctuation-only segments can never be a comm"
    );
    assert!(
        validate_multi_targets("a/:b", ex)
            .unwrap_err()
            .to_string()
            .contains("contains '/'"),
        "the path shape names the separator"
    );
    assert!(
        validate_multi_targets(":", ex)
            .unwrap_err()
            .to_string()
            .contains("No targets specified"),
        "the all-empty list keeps the historical error shape"
    );
    assert!(
        validate_multi_targets("  :  ", ex)
            .unwrap_err()
            .to_string()
            .contains("No targets specified"),
        "whitespace-only segments are empty after the contract trim"
    );
}
