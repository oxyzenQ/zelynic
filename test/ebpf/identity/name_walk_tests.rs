// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the one-walk name-set resolver (NIGHT-hunt-28, closing
//! hunt-27's named residual #1): the pure pair-to-id reduction
//! (dedup first-seen, the exact per-name walk semantics), the live
//! walk against the test process itself (the walker's own output
//! queried back through the walker — enrichment and all), the
//! empty-list contract the pure-id sweep lists ride, and the
//! single-vs-set agreement that holds the no-drift law (one walker,
//! every spelling).

use super::*;

/// The pure reduction: pairs collapse to ids first-seen — two pids
/// sharing one cgroup resolve it once (NIGHT-hunt-8's
/// aria2c/alacritty shape), the later duplicate spelling of an
/// already-seen cgroup adds nothing, and order is the pair order.
#[test]
fn the_reduction_dedups_first_seen_and_keeps_order() {
    assert_eq!(
        matched_pairs_to_ids(&[(9, 5), (10, 5), (11, 7), (12, 5), (13, 7)]),
        vec![5, 7],
        "one cgroup resolves once, in first-seen order"
    );
    assert_eq!(matched_pairs_to_ids(&[]), Vec::<u32>::new());
    assert_eq!(matched_pairs_to_ids(&[(1, 42)]), vec![42]);
}

/// The live walk: the test process's OWN comm resolves back to the
/// test process's own (pid, cgroup) pair — queried through the
/// walker's own canonical label (pid_comm, enrichment included), so
/// the pin holds whatever the kernel's 15-byte comm cap did to the
/// binary's name. The pair assertion rides the environment guard
/// the improve-50 pins own: on a pure-v2 host the own cgroup
/// resolves and the pair must ride the matched set; on the hybrid
/// v1 runner class (/proc's first cgroup line is a controller line,
/// so pid_cgroup_id honestly resolves nothing) the walker's
/// contract is the honest absence — no pair lands, no fabricated
/// match. The impossible-comm absence holds on every host class,
/// and the case-dedup (two spellings of one name, one set entry)
/// is provable wherever a match exists at all.
#[test]
fn the_walk_resolves_the_own_process_and_dedups_case() {
    let own = std::process::id();
    let Some(comm) = crate::ebpf::identity::pid_comm(own) else {
        panic!("the test process's own comm must be readable");
    };
    let impossible = "zelynic-no-such-comm-anywhere";
    let snapshot = resolve_name_set(&[comm.clone(), impossible.to_string()]);
    if let Some(cg) = crate::ebpf::identity::pid_cgroup_id(own) {
        let pairs = snapshot
            .get(&comm.to_lowercase())
            .expect("the own comm is matched when its cgroup resolves");
        assert!(
            pairs.contains(&(own, cg)),
            "the own (pid, cgroup) pair rides the matched set, got {pairs:?}"
        );
        // The case-dedup: one lowercased key for both spellings —
        // the duplicate the per-name loop walked twice is one entry.
        let both = resolve_name_set(&[comm.clone(), comm.to_uppercase()]);
        assert_eq!(
            both.len(),
            1,
            "two cases of one name are one set entry, got {both:?}"
        );
    }
    assert!(
        !snapshot.contains_key(impossible),
        "an impossible name is absent, never a fabricated match"
    );
}

/// The empty-list contract: no names, no walk, no entries — the
/// pure-id sweep lists (strict-all/block-all's identity-row shape)
/// ride the guard at zero /proc cost, exactly as before the batch.
#[test]
fn an_empty_name_list_resolves_to_nothing() {
    assert!(resolve_name_set(&[]).is_empty());
}

/// The no-drift law: the single spelling (eagle's resolve_name —
/// the wrapper the probe and `ss <name>` own) and the set spelling
/// (the batched multi lanes) resolve the same name to the same ids,
/// because both ride this walker. If anyone ever re-inlines one
/// site with different matching semantics, this pin fires.
#[test]
fn the_single_spelling_and_the_set_spelling_agree() {
    let Some(comm) = crate::ebpf::identity::pid_comm(std::process::id()) else {
        panic!("the test process's own comm must be readable");
    };
    let singles = crate::commands::eagle::resolve_name(&comm);
    let pairs = resolve_name_set(std::slice::from_ref(&comm))
        .remove(&comm.to_lowercase())
        .unwrap_or_default();
    assert_eq!(
        singles,
        matched_pairs_to_ids(&pairs),
        "one walker, one matching semantics, every spelling"
    );
}
