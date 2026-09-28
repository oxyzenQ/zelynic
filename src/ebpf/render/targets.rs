// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Eagle-eyes target resolution (NIGHT-dinner-18, the render-family
//! LOC-cap split — the beat.rs/screen.rs precedent): the per-frame
//! resolver that turns the monitor's parsed TARGETS tokens into the
//! watched cgroup-id set plus the unresolved-name notes.
//!
//! One contract, two homes by design: THIS resolver serves the live
//! frame (called every beat against the TTL-cached identity map, so
//! apps started mid-session appear on the next refresh); the launch
//! gate's twin (`commands::eagle::resolve_live_targets`) serves the
//! door — the same match semantics with the addition dead-cgroup-id
//! verdicts, so the gate can never accept a spec the frame could
//! never show, nor reject one it would. The two are deliberately
//! separate functions on separate trees (render vs commands): the
//! frame's resolver keeps its verbatim id lane (a watched id that
//! dies mid-session simply drops its rows — live reality, never a
//! refusal), while the gate owns the launch verdict. The
//! duplicate-token fix (NIGHT-dinner-18's audit find) landed in
//! BOTH: the match verdict and the id collection are separate
//! concerns, so a repeated token ('brave/brave') must never flip
//! its second copy to a miss.
//!
//! Pinned by test/ebpf/render/eagle_filter_tests.rs (the expansion,
//! miss-note, and duplicate-token contracts — `super::` reaches
//! this module through eagle.rs's import).

use crate::ebpf::identity::IdentityMap;
use crate::ebpf::limiter::Target;

/// Resolve target tokens against the identity map.
///
/// Numeric tokens (bare or `cg:`-prefixed — the display prefix
/// round-trips since NIGHT-boost-37, so a label copied off the
/// table watches the cgroup it names) are cgroup IDs verbatim;
/// name tokens expand to every cgroup whose comm matches
/// (case-insensitive) — `brave` watches ALL brave cgroups, the
/// whole-app semantics the strict/block family's /proc resolution
/// gives. Names that match nothing come back separately so the
/// frame can say so (a typo'd app name must not silently render an
/// empty table).
#[must_use]
pub(super) fn resolve_targets(
    tokens: &[Target],
    identity: &IdentityMap,
) -> (Vec<u32>, Vec<String>) {
    let mut ids: Vec<u32> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    for token in tokens {
        match token {
            Target::CgroupId(id) => {
                if !ids.contains(id) {
                    ids.push(*id);
                }
            }
            Target::ProcessName(name) => {
                let name_lower = name.to_lowercase();
                let mut matched = false;
                for entry in identity.all() {
                    if entry.comm.to_lowercase() == name_lower {
                        matched = true;
                        // NIGHT-dinner-18 (the duplicate-token
                        // false-miss): the match verdict and the id
                        // collection are SEPARATE concerns. The old
                        // combined condition let a repeated token
                        // ('brave/brave') flip its second copy to a
                        // miss — every matching cgroup was already in
                        // ids, so 'matched' never turned true and the
                        // frame rendered "no app named 'brave'" under
                        // a live brave. The verdict now keys on the
                        // comm match alone; the collection keeps its
                        // dedup guard.
                        if !ids.contains(&entry.cgroup_id) {
                            ids.push(entry.cgroup_id);
                        }
                    }
                }
                if !matched {
                    unresolved.push(name.clone());
                }
            }
        }
    }
    (ids, unresolved)
}
