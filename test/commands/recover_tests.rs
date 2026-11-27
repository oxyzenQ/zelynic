// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! NIGHT-dinner-23 pins: recover's none-branch verdict line — the
//! count-honesty contract. The assertions target the plain content
//! (substrings) rather than the full rendered line: the "none"
//! verdict word routes through the themeable brand tier, whose
//! escape bytes depend on the process-global capability cache and
//! the ACTIVE theme atom — cross-test state a wording pin must not
//! depend on (the theme tests in test/output/ switch the atom). The
//! counts and nouns are plain text by construction, so they pin the
//! contract deterministically under every theme and color depth.

use super::{orphans_none_line, sorted_orphan_ids};

/// The mislabel case the audit found: two dl+ul policies on ONE
/// cgroup. The old line printed the CGROUP count under the POLICY
/// noun ("all 1 policies") — wrong on the number and the noun at
/// once. The honest verdict names both dimensions.
#[test]
fn none_verdict_counts_policies_and_cgroups_separately() {
    let line = orphans_none_line(1, 1, 1);
    assert!(
        line.contains("Orphans: none"),
        "the affirmative verdict word survives every tier, got: {line}"
    );
    assert!(
        line.contains("(2 policies across 1 cgroup, all live)"),
        "two policies on one cgroup must say exactly that, got: {line}"
    );
}

/// Singular/plural awareness on BOTH axes (the entry/entries
/// contract this file already owns, applied to the verdict).
#[test]
fn none_verdict_is_singular_aware_on_both_axes() {
    let one_one = orphans_none_line(1, 0, 1);
    assert!(
        one_one.contains("(1 policy across 1 cgroup, all live)"),
        "singular both axes, got: {one_one}"
    );
    let many = orphans_none_line(3, 3, 4);
    assert!(
        many.contains("(6 policies across 4 cgroups, all live)"),
        "plural both axes, got: {many}"
    );
    // Mixed: one cgroup carrying both directions is still one
    // cgroup, plural policies.
    let mixed = orphans_none_line(2, 2, 1);
    assert!(
        mixed.contains("(4 policies across 1 cgroup, all live)"),
        "plural policies over singular cgroup, got: {mixed}"
    );
}

/// The empty skeleton (valid pins over empty maps) is named for
/// what it is — not a vacuous "0 across 0, all live".
#[test]
fn none_verdict_names_the_empty_skeleton() {
    let line = orphans_none_line(0, 0, 0);
    assert!(
        line.contains("(no policies pinned)"),
        "the zero-policies arm must name the empty skeleton, got: {line}"
    );
    assert!(
        !line.contains("across"),
        "the across phrasing belongs to the counted arm only, got: {line}"
    );
}

/// night-cafe-mclaren-2: the orphan census is a fixed total order —
/// ascending cgroup id regardless of the candidate set's per-process
/// iteration order, for the printed rows AND the delete sweep that
/// walks the same Vec (two identical machines must replay identical
/// deletes; the render surfaces pin the same law in
/// src/ebpf/display_order.rs).
#[test]
fn orphan_ids_ride_the_ascending_id_law() {
    use std::collections::HashSet;

    let policies: HashSet<u32> = [7, 3, 41, 15, 8].into_iter().collect();
    let alive: HashSet<u32> = [8, 3].into_iter().collect();
    let orphans = sorted_orphan_ids(&policies, &alive);
    assert_eq!(
        orphans,
        vec![7, 15, 41],
        "3 and 8 are alive; the rest walk ascending"
    );
    // Same inputs, same order — the determinism law, not a happy
    // accident of one process's hash seed.
    let again = sorted_orphan_ids(&policies, &alive);
    assert_eq!(orphans, again, "one input, one order, every process");

    // Nothing pinned: the census is empty, the sweep walks nothing.
    let none = sorted_orphan_ids(&HashSet::new(), &HashSet::new());
    assert!(none.is_empty(), "an empty candidate set is an empty census");

    // Every id alive: the census is empty before the sweep starts.
    let all_alive = sorted_orphan_ids(&policies, &policies);
    assert!(
        all_alive.is_empty(),
        "every id alive must yield an empty census"
    );
}
