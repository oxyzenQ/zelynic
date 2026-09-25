// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the policy surface — kept in the repo's single test/
//! tree (NIGHT-hunt-17, cosmostrix Pattern C) and #[path]-wired from
//! policy.rs to hold the module under the 500-LOC cap (the check-loc
//! policy). Covers the NIGHT-hunt-9 trace wording and the
//! NIGHT-hunt-20 mid-flight error-path contract: rollback reporting,
//! ENOENT-vs-failure classification, and partial-removal honesty.

use super::*;
// The ENOENT classification pins construct map errors directly —
// the type lives in aya, imported here since the definition moved to
// reclaim.rs and policy.rs no longer re-exports it via glob.
use aya::maps::MapError;

/// NIGHT-hunt-9 drift pins: the verbose trace wording is part of the
/// diagnostic contract owners debug against — exact strings, pinned.

#[test]
fn policy_write_line_names_cgroup_direction_rate_and_burst() {
    assert_eq!(
        policy_write_line(73386, Direction::Download, 100_000),
        "[limiter] cg:73386 download → 100.0 KB/s (burst 100.0 KB)"
    );
    assert_eq!(
        policy_write_line(1, Direction::Upload, 1_000_000),
        "[limiter] cg:1 upload → 1.0 MB/s (burst 1.0 MB)"
    );
}

#[test]
fn policy_write_line_blocks_show_blocked_rate_and_floor_burst() {
    // Block commands write rate 0: the trace must say BLOCKED and
    // show the 64 KiB GSO super-packet floor (NIGHT-lts-8:
    // default_burst clamps to BURST_FLOOR_BYTES = 65,536).
    assert_eq!(
        policy_write_line(73386, Direction::Download, 0),
        "[limiter] cg:73386 download → BLOCKED (burst 65.5 KB)"
    );
}

#[test]
fn resolution_trace_line_reports_pids_per_cgroup_deterministically() {
    // Two pids share cg:73386 (the NIGHT-hunt-8 lie: one cgroup
    // hosting several processes), one more lands in cg:73390.
    // BTreeMap keeps the cgroup order stable regardless of walk order.
    assert_eq!(
        resolution_trace_line("brave", &[(202, 73386), (101, 73386), (303, 73390)]),
        "[limiter] 'brave' resolved: cg:73386 (2 pids), cg:73390 (1 pid)"
    );
    assert_eq!(
        resolution_trace_line("curl", &[(101, 73386)]),
        "[limiter] 'curl' resolved: cg:73386 (1 pid)"
    );
}

#[test]
fn resolution_trace_line_points_at_list_apps_when_nothing_matches() {
    assert_eq!(
        resolution_trace_line("nonexistent-app", &[]),
        "[limiter] 'nonexistent-app': no process matched in /proc walk — \
         try 'zelynic list-apps'"
    );
}

/// NIGHT-hunt-20 drift pins: the mid-flight error-path contract.

#[test]
fn map_remove_means_absent_classifies_enoent_only() {
    use aya::sys::SyscallError;

    fn syscall_err(code: i32) -> MapError {
        MapError::SyscallError(SyscallError {
            call: "bpf_map_delete_elem",
            io_error: std::io::Error::from_raw_os_error(code),
        })
    }

    // ENOENT — the one errno that means "key absent".
    assert!(map_remove_means_absent(&syscall_err(2)));

    // Real delete failures — the policy may still be enforced, so
    // these must NEVER read as "not found" (the old Err(_) => Ok(false)
    // conflation is exactly the silent-enforcement trap this closes).
    for code in [
        1,  /* EPERM */
        12, /* ENOMEM */
        13, /* EACCES */
        22, /* EINVAL */
    ] {
        assert!(
            !map_remove_means_absent(&syscall_err(code)),
            "errno {code} must not classify as absent"
        );
    }

    // Non-syscall map errors (e.g. wrong map type) are never "absent".
    assert!(!map_remove_means_absent(&MapError::InvalidMapType {
        map_type: 1
    }));
}

#[test]
fn partial_apply_failure_line_pins_both_rollback_outcomes() {
    // Clean rollback: strict all-or-nothing held — the error says so
    // instead of leaving the owner to wonder what survived.
    assert_eq!(
        partial_apply_failure_line("Failed to write policy: map full", 3, &[]),
        "Failed to write policy: map full — apply rolled back (3 partial policies), \
         no residue"
    );
    assert_eq!(
        partial_apply_failure_line("Failed to write policy: map full", 1, &[]),
        "Failed to write policy: map full — apply rolled back (1 partial policy), \
         no residue"
    );

    // Incomplete rollback: the survivors are named, never hidden.
    assert_eq!(
        partial_apply_failure_line(
            "Failed to write policy: map full",
            2,
            &[
                policy_survivor_line(73386, Direction::Download),
                policy_survivor_line(73390, Direction::Upload),
            ]
        ),
        "Failed to write policy: map full — rollback incomplete, still enforced: \
         cg:73386 download, cg:73390 upload; run 'zelynic unstrict' to clear"
    );
}

#[test]
fn policy_survivor_line_matches_the_trace_cg_style() {
    assert_eq!(
        policy_survivor_line(73386, Direction::Download),
        "cg:73386 download"
    );
    assert_eq!(policy_survivor_line(1, Direction::Upload), "cg:1 upload");
}
