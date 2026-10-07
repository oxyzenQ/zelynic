// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the depth set walk (NIGHT-hunt-30, the eagle-eyes
//! depth report's per-id /proc quadratic closed): the empty-set
//! no-walk contract, the live walk against the test process's own
//! cgroup (guarded the improve-50 way for the hybrid-v1 runner
//! class where pid_cgroup_id honestly resolves nothing), and the
//! single-vs-set agreement that holds the no-drift law (deep_collect
//! is the set walk's single spelling — one walk, one facts
//! snapshot, whichever way the id arrives).

use super::*;

/// The empty-set contract: no ids, no walk, no entries — a depth
/// spec whose tokens all missed pays nothing at the walk layer.
#[test]
fn an_empty_id_set_collects_nothing() {
    assert!(deep_collect_set(&[]).is_empty());
}

/// The live walk: the test process's own cgroup, when the
/// environment resolves it (the pure-v2 class), collects a
/// CgroupDepth whose member facts include the test process itself,
/// in /proc order, with the rel_path from the first member. On the
/// hybrid-v1 runner class (pid_cgroup_id honestly resolves nothing)
/// the honest absence is the contract — no entry, no fabricated
/// members, exactly what the single-id walk always answered.
#[test]
fn the_set_walk_collects_the_own_process() {
    let own = std::process::id();
    let Some(cg) = crate::ebpf::identity::pid_cgroup_id(own) else {
        return; // the hybrid-v1 runner class — the honest absence
    };
    let set = deep_collect_set(&[cg, cg.wrapping_add(1)]);
    let depth = set.get(&cg).expect("the own cgroup collects a depth entry");
    assert!(
        depth.procs.iter().any(|p| p.pid == own),
        "the own pid rides the member facts, got {} procs",
        depth.procs.len()
    );
    // A set entry only exists for an id the walk actually matched —
    // the wanted-set membership is the whole short-circuit, and the
    // map key IS the cgroup the member facts belong to.
    for (key, value) in &set {
        assert!(
            value.procs.iter().all(|p| p.pid != own) || *key == cg,
            "the own pid's facts ride its own cgroup's entry only"
        );
    }
}

/// The no-drift law: the single spelling (deep_collect — pathwalk's
/// first arm) and the set spelling (the report's batch) collect the
/// same member pids for the same id, because both are the same
/// walk. If anyone ever re-inlines one site with different
/// membership semantics, this pin fires.
#[test]
fn the_single_spelling_and_the_set_spelling_agree() {
    let own = std::process::id();
    let Some(cg) = crate::ebpf::identity::pid_cgroup_id(own) else {
        return; // the hybrid-v1 runner class — both sides empty
    };
    let single = deep_collect(cg);
    let batched = deep_collect_set(&[cg])
        .remove(&cg)
        .expect("the set walk collects the own cgroup");
    let single_pids: Vec<u32> = single.procs.iter().map(|p| p.pid).collect();
    let batched_pids: Vec<u32> = batched.procs.iter().map(|p| p.pid).collect();
    assert_eq!(
        single_pids, batched_pids,
        "one walk, one membership, every spelling"
    );
    assert_eq!(single.rel_path, batched.rel_path);
}
