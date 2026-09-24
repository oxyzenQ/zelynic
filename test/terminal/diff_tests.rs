// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the diff-based render engine (NIGHT-improve-2) —
//! kept in the repo's single test/ tree (NIGHT-hunt-17, cosmostrix
//! Pattern C) and #[path]-wired from the engine to hold the engine
//! itself under the 500-LOC cap (the check-loc policy; same split
//! discipline as identity/).

// NON_LATIN_FIXTURE: the CJK rows in the unicode diff test below are
// intentional double-width glyph coverage, not prose
// (scripts/check-language.sh exemption).

use super::*;

fn screen() -> DiffScreen {
    DiffScreen::new()
}

fn sink() -> Vec<u8> {
    Vec::new()
}

fn lines_of(rows: &[&str]) -> Vec<String> {
    rows.iter().map(|s| s.to_string()).collect()
}

/// First frame: full reset — home + erase-below, every row, and
/// no per-row MoveTo (dense diff takes the sequential path).
#[test]
fn first_frame_is_full_reset() {
    let mut s = screen();
    let mut lines = lines_of(&["alpha", "beta", "gamma"]);
    let mut out = sink();
    let n = s.emit_at(80, 24, &mut lines, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.starts_with("\x1b[H\x1b[J"),
        "reset prefix, got {text:?}"
    );
    assert!(text.contains("alpha\x1b[K\nbeta\x1b[K\ngamma\x1b[K\n"));
    assert_eq!(n, out.len(), "return value == emitted bytes");
    assert!(
        !text[6..].contains(";1H"),
        "no row MoveTo in sequential mode"
    );
}

/// Idle frame: byte-identical content emits ZERO bytes.
#[test]
fn idle_frame_emits_zero_bytes() {
    let mut s = screen();
    let mut lines = lines_of(&["one", "two", "three"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    let mut lines2 = lines_of(&["one", "two", "three"]);
    let n = s.emit_at(80, 24, &mut lines2, &mut out);
    assert_eq!(n, 0);
    assert!(out.is_empty(), "idle frame must not write");
}

/// Sparse change: only the dirty rows are emitted, each run
/// carries one MoveTo, clean rows are absent from the stream.
#[test]
fn sparse_change_repositions_only_dirty_rows() {
    let mut s = screen();
    let rows = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"];
    let mut lines = lines_of(&rows);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    // Change rows 2 and 7 (0-based) -> runs at 1-based rows 3 and 8.
    let mut next: Vec<String> = rows.map(|r| r.to_string()).to_vec();
    next[2] = "R2".to_string();
    next[7] = "R7".to_string();
    s.emit_at(80, 24, &mut next, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.contains("\x1b[3;1HR2\x1b[K\n"),
        "row 3 repositioned, got {text:?}"
    );
    assert!(
        text.contains("\x1b[8;1HR7\x1b[K\n"),
        "row 8 repositioned, got {text:?}"
    );
    for clean in ["r0", "r1", "r3", "r4", "r5", "r6", "r8", "r9"] {
        assert!(!text.contains(clean), "clean row '{clean}' must be skipped");
    }
}

/// Consecutive dirty rows join into ONE run: one MoveTo, rows
/// LF-separated (the dragon engine's run batching).
#[test]
fn consecutive_dirty_rows_join_into_one_run() {
    let mut s = screen();
    let rows = ["a", "b", "c", "d"];
    let mut lines = lines_of(&rows);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    let mut next: Vec<String> = rows.map(|r| r.to_string()).to_vec();
    next[1] = "B".to_string();
    next[2] = "C".to_string();
    s.emit_at(80, 24, &mut next, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.contains("\x1b[2;1HB\x1b[K\nC\x1b[K\n"),
        "joined run, got {text:?}"
    );
    assert_eq!(
        text.matches(";1H").count(),
        1,
        "exactly one MoveTo (the run head)"
    );
}

/// Frame shrink: rows below the new frame are erased
/// (MoveTo(n+1) + erase-below), so no stale rows survive.
#[test]
fn shrink_clears_tail_rows() {
    let mut s = screen();
    let mut lines = lines_of(&["a", "b", "c", "d", "e", "f"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    let mut shorter = lines_of(&["a", "b", "c"]);
    s.emit_at(80, 24, &mut shorter, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.contains("\x1b[4;1H\x1b[J"),
        "tail erase from row 4, got {text:?}"
    );
}

/// Width change (resize): the shadow's geometry is stale — full
/// reset with erase-below, every row rewritten.
#[test]
fn width_change_forces_full_reset() {
    let mut s = screen();
    let mut lines = lines_of(&["a", "b"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    let mut same = lines_of(&["a", "b"]);
    s.emit_at(120, 24, &mut same, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.starts_with("\x1b[H\x1b[J"),
        "resize forces reset, got {text:?}"
    );
    assert!(text.contains("a\x1b[K\nb\x1b[K\n"));
}

/// Tall frame (rows >= terminal height): sequential is forced —
/// absolute row positioning would clamp to the bottom row, so
/// the pre-diff scrolling semantics are preserved.
#[test]
fn tall_frame_forces_sequential() {
    let mut s = screen();
    let rows: Vec<String> = (0..10).map(|i| format!("row{i}")).collect();
    let mut lines = rows.clone();
    let mut out = sink();
    s.emit_at(80, 10, &mut lines, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.starts_with("\x1b[H\x1b[J"));
    assert!(
        !text[6..].contains(";1H"),
        "no row MoveTo when frame >= height"
    );
}

/// The crossover is byte-exact: a one-row change in a wide frame
/// is sparse; changing every row of a narrow frame is
/// sequential (a MoveTo per row would cost more than rewriting
/// the clean rows).
#[test]
fn crossover_picks_the_cheaper_stream() {
    // 12 long rows, one changed: sparse must win.
    let long: Vec<String> = (0..12)
        .map(|i| format!("line-{:03}-{}", i, "x".repeat(60)))
        .collect();
    let mut s = screen();
    let mut first = long.clone();
    let mut out = sink();
    s.emit_at(80, 24, &mut first, &mut out);
    out.clear();
    let mut one_changed = long.clone();
    one_changed[5] = format!("CHANGED-{}", "y".repeat(60));
    s.emit_at(80, 24, &mut one_changed, &mut out);
    let sparse_text = String::from_utf8_lossy(&out).to_string();
    assert!(
        sparse_text.contains("\x1b[6;1HCHANGED"),
        "sparse path for one dirty row"
    );

    // All rows changed: sequential wins (no per-row MoveTo).
    out.clear();
    let mut all_changed: Vec<String> = (0..12).map(|i| format!("NEW-{i}")).collect();
    s.emit_at(80, 24, &mut all_changed, &mut out);
    let seq_text = String::from_utf8_lossy(&out).to_string();
    assert!(
        seq_text.starts_with("\x1b[H"),
        "sequential path for dense diff"
    );
    assert!(
        !seq_text[3..].contains(";1H"),
        "no per-row MoveTo in dense mode"
    );
}

/// Embedded styling bytes are part of the shadow comparison: a
/// style-only change is a row change (dragon-engine cell parity).
#[test]
fn style_bytes_participate_in_the_diff() {
    let mut s = screen();
    let mut lines = lines_of(&["\x1b[35mtitle\x1b[0m", "plain"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    let mut restyled = lines_of(&["\x1b[1;35mtitle\x1b[0m", "plain"]);
    s.emit_at(80, 24, &mut restyled, &mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("\x1b[1;35mtitle"), "restyled row re-emitted");
    assert!(!text.contains("plain"), "untouched row skipped");
}

/// Unicode-safe by construction: double-width glyphs never break
/// the diff (whole lines compare and write; cursor only lands on
/// row starts).
#[test]
fn unicode_rows_diff_correctly() {
    let mut s = screen();
    let mut lines = lines_of(&["谷歌浏览器 down", "firefox up"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    out.clear();

    let mut next = lines_of(&["谷歌浏览器 down", "firefox UP"]);
    s.emit_at(80, 24, &mut next, &mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.contains("firefox UP"),
        "dirty unicode-adjacent row emitted"
    );
    assert!(!text.contains("谷歌"), "clean CJK row skipped");
}

/// The caller's vector is swapped with the shadow — the contract
/// run_alt and the harness rely on (clear + refill).
#[test]
fn emit_swaps_shadow_with_caller_buffer() {
    let mut s = screen();
    let mut lines = lines_of(&["a", "b"]);
    let mut out = sink();
    s.emit_at(80, 24, &mut lines, &mut out);
    assert_eq!(
        lines,
        Vec::<String>::new(),
        "caller got the old (empty) shadow"
    );

    let mut next = lines_of(&["a", "c"]);
    s.emit_at(80, 24, &mut next, &mut out);
    assert_eq!(shadow_len(&s), 2, "shadow holds the second frame");
}

/// Tall-regime idle frame (n >= h, nothing changed): ZERO bytes.
/// The pre-improve-6 engine excluded seq_forced from the idle path,
/// so every refresh repainted the full frame (~1.4 KB per frame on
/// the classic 80x24) even while the monitor sat completely idle.
#[test]
fn tall_regime_idle_frame_emits_zero_bytes() {
    let mut s = screen();
    let rows: Vec<String> = (0..10).map(|i| format!("row{i}")).collect();
    let mut lines = rows.clone();
    let mut out = sink();
    s.emit_at(80, 10, &mut lines, &mut out); // first frame: full paint
    assert!(!out.is_empty());
    out.clear();

    let mut lines2 = rows.clone();
    let n = s.emit_at(80, 10, &mut lines2, &mut out);
    assert_eq!(n, 0, "tall-regime idle frame must emit nothing");
    assert!(out.is_empty(), "tall-regime idle frame must not write");
}

/// A tall-regime frame never ends its emission with a linefeed: the
/// final LF would be written with the cursor on the bottom row,
/// scrolling the screen up one line per refresh (title-bar drift +
/// layout shift). The stream ends with the last visible row's
/// erase-EOL, and only the rows ABOVE the bottom carry separators.
#[test]
fn tall_regime_emission_never_ends_with_linefeed() {
    let mut s = screen();
    let mut lines: Vec<String> = (0..10).map(|i| format!("row{i}")).collect();
    let mut out = sink();
    s.emit_at(80, 10, &mut lines, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("row9\x1b[K"), "last visible row present");
    assert!(
        !text.ends_with('\n'),
        "emission must not end with LF (bottom-row LF scrolls)"
    );
    assert_eq!(
        text.matches('\n').count(),
        9,
        "exactly h-1 separators — no LF after the final visible row"
    );
}

/// Degenerate tall frame (n > h, sub-8-row terminals): the emission
/// is top-aligned and clipped to the viewport — the first h rows,
/// nothing beyond, no trailing LF. The old engine wrote all n rows
/// sequentially, scrolling the frame bottom-over-top every refresh.
#[test]
fn tall_regime_clips_to_the_viewport_top_aligned() {
    let mut s = screen();
    let mut lines: Vec<String> = (0..8).map(|i| format!("clip{i}")).collect();
    let mut out = sink();
    s.emit_at(80, 5, &mut lines, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    for i in 0..5 {
        assert!(
            text.contains(&format!("clip{i}")),
            "visible row {i} painted"
        );
    }
    for i in 5..8 {
        assert!(
            !text.contains(&format!("clip{i}")),
            "row {i} beyond the viewport must be clipped"
        );
    }
    assert!(
        !text.ends_with('\n'),
        "no trailing LF at the viewport bottom"
    );
    assert_eq!(text.matches('\n').count(), 4, "h-1 separators only");
}

/// Rows clipped away by a shorter viewport are dirty by definition:
/// when the terminal grows, the newly revealed rows repaint even
/// though their content is byte-identical to the shadow (they were
/// never physically painted). The `painted` term pins that invariant.
#[test]
fn clipped_rows_repaint_when_the_terminal_grows() {
    let mut s = screen();
    let rows: Vec<String> = (0..8).map(|i| format!("grow{i}")).collect();
    let mut lines = rows.clone();
    let mut out = sink();
    s.emit_at(80, 5, &mut lines, &mut out); // clipped: rows 0..4 painted
    out.clear();

    // Terminal grows to 8 rows; frame content is IDENTICAL.
    let mut same = rows.clone();
    let n = s.emit_at(80, 8, &mut same, &mut out);
    assert!(n > 0, "revealed rows must repaint (never idle here)");
    let text = String::from_utf8_lossy(&out).to_string();
    for i in 5..8 {
        assert!(
            text.contains(&format!("grow{i}")),
            "revealed row {i} repainted"
        );
    }
    assert!(!text.ends_with('\n'), "still no trailing LF at the bottom");
}

/// Regime transition tall -> short: the first short-regime frame is
/// self-contained — home-anchored, every visible row re-emitted, tail
/// cleared below the frame. Physical alignment follows from the
/// no-trailing-LF pin (the screen never scrolled, so absolute rows
/// land where the shadow believes they are); this pin locks the
/// stream contract that makes that argument sound.
#[test]
fn tall_to_short_transition_stream_is_self_contained() {
    let mut s = screen();
    let mut lines: Vec<String> = (0..10).map(|i| format!("tall{i}")).collect();
    let mut out = sink();
    s.emit_at(80, 10, &mut lines, &mut out); // tall regime, full frame
    out.clear();

    // Terminal grows; the frame shrinks to 6 rows — short regime now.
    let mut shorter: Vec<String> = (0..6).map(|i| format!("short{i}")).collect();
    s.emit_at(80, 20, &mut shorter, &mut out);

    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.starts_with("\x1b[H"),
        "transition frame is home-anchored (self-contained), got {text:?}"
    );
    assert!(
        text.contains("\x1b[7;1H\x1b[J"),
        "tail erase below the shorter frame, got {text:?}"
    );
    for i in 0..6 {
        assert!(text.contains(&format!("short{i}")), "row {i} re-emitted");
    }
    assert!(!text.contains("tall"), "old tall rows fully replaced");
}

fn shadow_len(s: &DiffScreen) -> usize {
    s.prev.len()
}

/// NIGHT-hunt-26: a transient winsize probe failure (a mid-resize
/// 0x0 report, an ioctl hiccup) must reuse the last emitted geometry
/// on an already-painted screen — the old 80x24 fallback forced a
/// width-mismatch reset (HOME + erase-below + the full frame) on the
/// failing wake and a SECOND reset when the probe recovered: the
/// two-beat flash the owner reported on long-running monitors. The
/// pipe path (probe always None in tests) rides the sticky geometry
/// after the first frame, so identical content stays idle at the
/// injected size instead of resetting to the fallback.
#[test]
fn transient_probe_failure_reuses_last_geometry() {
    let mut s = DiffScreen::new();
    let mut out = Vec::new();
    let mut lines = lines_of(&["alpha", "beta"]);
    s.emit_at(100, 40, &mut lines, &mut out); // paint at an injected size

    // Same content through the PROBE path: winsize() returns None
    // (piped test stdout) — the sticky (100, 40) geometry must hold,
    // the frame stays idle, and no reset fires.
    out.clear();
    let mut same = lines_of(&["alpha", "beta"]);
    let n = s.emit(&mut same, &mut out);
    assert_eq!(
        n, 0,
        "probe failure must reuse the last geometry, not reset to 80x24"
    );
    assert!(
        out.is_empty(),
        "no emission for identical content at the sticky size"
    );

    // A real size change still resets: once the probe reports a new
    // width, the mismatch is honored (the resize contract is intact).
    out.clear();
    let mut moved = lines_of(&["alpha", "beta"]);
    let r = s.emit_at(120, 40, &mut moved, &mut out);
    assert!(r > 0, "a genuine width change still repaints in full");
    assert!(
        out.starts_with(b"\x1b[H\x1b[J"),
        "the resize reset keeps its erase"
    );
}
