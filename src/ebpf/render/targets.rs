// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

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
            // Container targets read as unresolved here: this resolver
            // is per-frame PURE over the identity map and cannot walk
            // docker/kubelet metadata — and the '/'-separated target
            // grammar splits a URI before it ever reaches the frame.
            // The honest bound: never a fabricated row (charger-core-2).
            Target::Container(c) => {
                unresolved.push(c.display());
            }
        }
    }
    (ids, unresolved)
}

/// The watched set's stack capacity (night-frontier-Z13 stage 5c):
/// the id lane resolves into a fixed stack buffer — 64 watched ids
/// on the frame stack. A spec naming MORE than this rides the owned
/// path below (the pathological shape pays the allocation the
/// steady shapes no longer do), so behavior is identical for every
/// shape; the buffer only moves where the allocation was.
pub(super) const WATCH_STACK_CAP: usize = 64;

/// Is this spec the id lane's stack shape? Every token a bare
/// cgroup id — the monitor's positional TARGETS watch (the focus
/// view's reach and the numeric ranked watch) — with room in the
/// buffer. Name and container tokens carry their own resolver cost
/// (the matcher's scratch, the miss notes) and ride the owned path.
pub(super) fn spec_is_stack_capable(tokens: &[Target]) -> bool {
    tokens.len() <= WATCH_STACK_CAP && tokens.iter().all(|t| matches!(t, Target::CgroupId(_)))
}

/// The stack-form of [`resolve_targets`] (night-frontier-Z13 stage
/// 5c): the SAME id lane — token order, the dedup guard, verbatim
/// ids — written into the caller's fixed buffer; the per-frame
/// `Vec` the owned path pushes is the event this form removes.
/// Returns the written count. Call only behind
/// [`spec_is_stack_capable`]; the unresolved half is empty by
/// construction for the id lane (a numeric token never matches
/// nothing — it watches verbatim, the resolver's own law).
pub(super) fn resolve_targets_stack(buf: &mut [u32; WATCH_STACK_CAP], tokens: &[Target]) -> usize {
    let mut len = 0usize;
    for token in tokens {
        if let Target::CgroupId(id) = token {
            // The dedup guard, verbatim (the owned path's contains
            // law): a repeated token is one watch, never two rows.
            if !buf[..len].contains(id) {
                buf[len] = *id;
                len += 1;
            }
        }
    }
    len
}
