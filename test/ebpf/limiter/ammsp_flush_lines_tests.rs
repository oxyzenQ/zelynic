// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-private-research-2 (AMMSP): wording pins for the userspace
//! flush surface (src/ebpf/limiter/ammsp.rs). The flush trace is the
//! verbose diagnostic contract — exact strings, pinned — and the
//! failure line is the never-silent-but-never-fatal contract the
//! unstrict partial-failure line set the precedent for.

// The flush formatters live in the userspace module under test; this
// file is wired INTO that module by its own #[path] include (the
// gate-tree discipline: src/ wirings stay under test/), so `super`
// is the ammsp module itself — the same `use super::*` shape the
// policy pins use.
use super::{flush_failed_line, flush_trace_line};

/// The zero-flush trace: the map was already clean — the wording
/// names the count and the state, never a bare "done".
#[test]
fn flush_trace_zero_is_the_clean_state_line() {
    assert_eq!(
        flush_trace_line(0),
        "[limiter] ammsp leaf cache: 0 memos — resolution state already clean"
    );
}

/// The flushed trace: singular/plural agreement and the
/// re-resolve-once cost statement (the owner-facing honest cost of
/// the flush: each covered leaf pays ONE re-walk).
#[test]
fn flush_trace_counts_and_costs_are_worded() {
    assert_eq!(
        flush_trace_line(1),
        "[limiter] ammsp leaf cache: flushed 1 memo — each covered leaf \
         re-resolves once on its next packet"
    );
    assert_eq!(
        flush_trace_line(7),
        "[limiter] ammsp leaf cache: flushed 7 memos — each covered leaf \
         re-resolves once on its next packet"
    );
}

/// The failure line: names the cause, states the degradation
/// (per-packet re-walks, never a wrong verdict), and offers the
/// recover tip — the same three-part contract the unstrict
/// partial-failure line holds.
#[test]
fn flush_failure_line_names_cause_degradation_and_tip() {
    let line = flush_failed_line("pinned map /sys/fs/bpf/zelynic/ammsp_leaf_cache: gone");
    assert!(
        line.starts_with("ammsp leaf cache flush failed ("),
        "names the surface: {line}"
    );
    assert!(
        line.contains("re-walk per packet until the next mutation"),
        "states the degradation: {line}"
    );
    assert!(
        line.contains("zelynic recover"),
        "offers the repair tip: {line}"
    );
}
