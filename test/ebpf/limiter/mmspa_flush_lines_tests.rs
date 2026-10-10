// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-private-research-2 (MMSPA), re-stamped by NIGHT-perf-0:
//! wording pins for the userspace memo-invalidation surface
//! (src/ebpf/limiter/mmspa.rs). The generation-bump trace is the
//! verbose diagnostic contract — exact strings, pinned — and the
//! failure line is the never-silent-but-never-fatal contract the
//! unstrict partial-failure line set the precedent for. The legacy
//! sweep's trace stays pinned too: the sweep is the bump's failure
//! fallback, so its wording remains a live surface, not history.

// The invalidation formatters live in the userspace module under
// test; this file is wired INTO that module by its own #[path]
// include (the gate-tree discipline: src/ wirings stay under test/),
// so `super` is the mmspa module itself — the same `use super::*`
// shape the policy pins use.
use super::{bump_trace_line, flush_trace_line, invalidate_failed_line};

/// The bump trace: the generation pair and the re-resolve-once cost
/// statement (the owner-facing honest cost of the bump: every leaf
/// pays ONE re-walk, on its next packet — the lazy retirement that
/// makes a dead leaf never re-walk at all).
#[test]
fn bump_trace_pairs_generations_and_costs() {
    assert_eq!(
        bump_trace_line(3, 4),
        "[limiter] mmspa memo generation 3 -> 4 — every leaf re-resolves \
         once on its next packet"
    );
    assert_eq!(
        bump_trace_line(0, 1),
        "[limiter] mmspa memo generation 0 -> 1 — every leaf re-resolves \
         once on its next packet"
    );
}

/// The wraparound bump: the counter is total (wrapping, never
/// saturating), and the trace wording carries the pair verbatim —
/// u32::MAX -> 0 is one more ordinary bump, not a special case the
/// wording hides.
#[test]
fn bump_trace_carries_the_wraparound_pair_verbatim() {
    assert_eq!(
        bump_trace_line(u32::MAX, 0),
        "[limiter] mmspa memo generation 4294967295 -> 0 — every leaf \
         re-resolves once on its next packet"
    );
}

/// The zero-flush trace (the fallback sweep lane): the map was
/// already clean — the wording names the count and the state, never
/// a bare "done".
#[test]
fn flush_trace_zero_is_the_clean_state_line() {
    assert_eq!(
        flush_trace_line(0),
        "[limiter] mmspa leaf cache: 0 memos — resolution state already clean"
    );
}

/// The flushed trace (the fallback sweep lane): singular/plural
/// agreement and the re-resolve-once cost statement (each covered
/// leaf pays ONE re-walk).
#[test]
fn flush_trace_counts_and_costs_are_worded() {
    assert_eq!(
        flush_trace_line(1),
        "[limiter] mmspa leaf cache: flushed 1 memo — each covered leaf \
         re-resolves once on its next packet"
    );
    assert_eq!(
        flush_trace_line(7),
        "[limiter] mmspa leaf cache: flushed 7 memos — each covered leaf \
         re-resolves once on its next packet"
    );
}

/// The failure line: names BOTH causes (the bump that failed first,
/// the sweep that failed behind it), states the degradation honestly
/// (removals self-heal per packet; an addition's stale verdict can
/// outlive the apply — the exact half the stamp exists to cover,
/// stated plainly), and offers the recover tip — the same three-part
/// contract the unstrict partial-failure line holds.
#[test]
fn invalidate_failure_line_names_causes_degradation_and_tip() {
    let line = invalidate_failed_line(
        "pinned map /sys/fs/bpf/zelynic/mmspa_generation: gone",
        "mmspa_leaf_cache_dl not found in loaded object",
    );
    assert!(
        line.starts_with("mmspa memo invalidation failed (generation bump: "),
        "names the primary surface: {line}"
    );
    assert!(
        line.contains("; sweep: "),
        "names the fallback surface: {line}"
    );
    assert!(
        line.contains("removals still self-heal per packet"),
        "states what still heals: {line}"
    );
    assert!(
        line.contains("stale verdict can outlive this apply until the next mutation"),
        "states the honest degradation: {line}"
    );
    assert!(
        line.contains("zelynic recover"),
        "offers the repair tip: {line}"
    );
}
