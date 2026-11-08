// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The Shape B frame-law pins (night-ux-5): the status frame is the
//! CONTENT's own width — the widest line the output prints — every
//! line pads to that one right edge, and the narrow-terminal cut
//! eats the sacrifice ladder (footer prose first) without ever
//! touching the table or the stamp. Wired from display_lines.rs at
//! the display_tests LOC headroom, the house split discipline.
//! Colors are identity in the test env (Mono), so the escape path
//! rides hand-built SGR + bare-ESC strings — the exact bytes the
//! color layer emits on a real terminal.

use super::{
    StatusLineKind, counters_footer_line, frame_status_output, recwn_line, status_header_line,
    status_row_line,
};
use crate::ebpf::display::RecwnLane;
use crate::output::colored_display_width;

/// The frame law's input shape: the grid's two flanks, kind-tagged.
type Flanks = (Vec<(StatusLineKind, String)>, Vec<(StatusLineKind, String)>);

/// The owner's 2026-11-08 live run, composed: a 57-column table, a
/// 74-column RECWN line, a ~115-column footer prose, a short stamp.
fn owner_run_lines() -> Flanks {
    let widths = [17usize, 10, 10, 7, 7];
    let cells = (
        "cg:30501 (brave)".to_string(),
        "200.0 KB/s".to_string(),
        "200.0 KB/s".to_string(),
        "10.6 KB".to_string(),
        "0 B".to_string(),
    );
    let above = vec![(StatusLineKind::Protected, status_header_line(&widths))];
    let below = vec![
        (
            StatusLineKind::Protected,
            status_row_line(&cells.0, &cells, &widths),
        ),
        (StatusLineKind::FooterProse, counters_footer_line()),
        (
            StatusLineKind::Recwn,
            recwn_line(&RecwnLane {
                planted: true,
                window_bytes: Some(40_000),
                binding_policies: 2,
            })
            .unwrap(),
        ),
        (
            StatusLineKind::Protected,
            "  v80.1.0 (b521d47) by oxyzenQ".to_string(),
        ),
    ];
    (above, below)
}

/// The wide terminal: the frame widens to the footer prose — the
/// widest line the output prints — and EVERY line pads to that one
/// width, so the right edge is one straight column. The table (57)
/// and the RECWN line (74) ride inside the frame, byte-identical
/// with pad spaces after them.
#[test]
fn frame_widens_to_its_widest_content() {
    let (above, below) = owner_run_lines();
    let footer_w = below
        .iter()
        .filter(|(k, _)| *k == StatusLineKind::FooterProse)
        .map(|(_, l)| colored_display_width(l))
        .next()
        .unwrap();
    assert!(
        footer_w > 100,
        "the owner's prose is the wide line, got {footer_w}"
    );
    let frame = frame_status_output(above, below, 200);
    assert_eq!(
        frame.width, footer_w,
        "Shape B: the frame is the widest content line, not the table"
    );
    for line in frame.above_grid.iter().chain(frame.below_grid.iter()) {
        assert_eq!(
            colored_display_width(line),
            frame.width,
            "every line ends at the same right column, got: {line}"
        );
    }
    // The table's bytes ride untouched under the pad.
    let header = &frame.above_grid[0];
    assert!(header.contains("download") && header.contains("dropped"));
}

/// The narrow terminal: the footer prose cuts FIRST (the least
/// load-bearing line for a one-glance read), to exactly the budget,
/// ellipsis last — never wrapped. The RECWN line under it only cuts
/// when it too exceeds the budget; the table never cuts.
#[test]
fn narrow_terminal_cuts_the_footer_prose_first() {
    let (above, below) = owner_run_lines();
    let frame = frame_status_output(above, below, 80);
    let cut_footer = frame
        .below_grid
        .iter()
        .find(|l| l.contains("allowed / dropped"))
        .expect("the counter footer prints");
    assert_eq!(
        colored_display_width(cut_footer),
        80,
        "the cut lands exactly on the budget, got: {cut_footer}"
    );
    assert!(
        cut_footer.ends_with('…'),
        "ellipsis, never a wrap or a hard cut"
    );
    let recwn = frame
        .below_grid
        .iter()
        .find(|l| l.contains("RECWN window"))
        .expect("the RECWN line prints");
    assert!(
        !recwn.ends_with('…'),
        "the 74-column RECWN line fits the 80-column budget untouched"
    );
    assert_eq!(frame.width, 80);
    // The header row survives byte-identical (pad only).
    let header = &frame.above_grid[0];
    assert!(!header.contains('…') && header.contains("cgroup"));
}

/// The deeper squeeze: under a 60-column budget both the footer and
/// the RECWN line cut to the budget (the ladder in order), the
/// 57-column table rides under it, and the frame never exceeds the
/// widest SURVIVING line.
#[test]
fn the_cut_ladder_takes_the_prose_before_the_table() {
    let (above, below) = owner_run_lines();
    let frame = frame_status_output(above, below, 60);
    for line in frame.below_grid.iter().filter(|l| l.contains('…')) {
        assert_eq!(colored_display_width(line), 60, "cut to the budget: {line}");
    }
    assert_eq!(frame.width, 60, "the cut prose is the widest survivor");
    let header = &frame.above_grid[0];
    assert!(
        !header.contains('…'),
        "the table never truncates, got: {header}"
    );
}

/// The protected law: a terminal narrower than the TABLE cannot
/// claim the table — the protected lines pass through uncut and the
/// frame width follows them (the upstream column squeeze owns the
/// table's own narrow law; the frame never mutilates it).
#[test]
fn protected_lines_never_cut() {
    let (above, below) = owner_run_lines();
    let header_w = colored_display_width(&above[0].1);
    let frame = frame_status_output(above, below, 50);
    assert_eq!(
        colored_display_width(&frame.above_grid[0]),
        header_w,
        "the header row passes through byte-identical"
    );
    assert!(
        frame.width >= header_w,
        "the frame still bounds the table it exists to frame"
    );
}

/// The sacrifice ladder in its exact order — the owner's Shape B
/// boundary made code: the footer prose gives up first, then the
/// RECWN line, the quota line, the watchdog, the census, the row's
/// subordinate family; the table's header, the data rows, and the
/// stamp never give up.
#[test]
fn the_ladder_order_is_the_owners_boundary() {
    use super::StatusLineKind as K;
    let rank = |k: K| k.cut_rank();
    assert!(rank(K::FooterProse) < rank(K::Recwn));
    assert!(rank(K::Recwn) < rank(K::Quota));
    assert!(rank(K::Quota) < rank(K::Watchdog));
    assert!(rank(K::Watchdog) < rank(K::Census));
    assert!(rank(K::Census) < rank(K::RowSubordinate));
    assert_eq!(
        rank(K::Protected),
        None,
        "the table and the stamp never cut"
    );
}

/// The empty board: verdict and stamp only, no grid — the frame
/// still fits exactly what prints.
#[test]
fn the_empty_board_fits_its_two_lines() {
    let above = vec![(StatusLineKind::Census, "  active limits: none".to_string())];
    let below = vec![(
        StatusLineKind::Protected,
        "  v80.1.0 (b521d47) by oxyzenQ".to_string(),
    )];
    let frame = frame_status_output(above, below, 80);
    assert_eq!(frame.width, 30, "the stamp is the widest of the two");
    assert_eq!(frame.above_grid.len(), 1);
    assert_eq!(frame.below_grid.len(), 1);
    for line in frame.above_grid.iter().chain(frame.below_grid.iter()) {
        assert_eq!(colored_display_width(line), frame.width);
    }
}

/// The escape path on the frame law: a line colored the way the
/// color layer colors it on a real terminal (SGR open, bare-ESC
/// reset) measures, cuts, and pads by its VISIBLE width — the
/// escapes ride free, a cut re-closes the tier, and the pad lands
/// past the reset.
#[test]
fn colored_lines_frame_by_their_visible_width() {
    let footer = counters_footer_line();
    let plain_w = colored_display_width(&footer);
    let colored = format!("\x1b[38;2;139;139;139m{footer}\x1b");
    assert_eq!(
        colored_display_width(&colored),
        plain_w,
        "the SGR open and the bare-ESC reset claim zero columns"
    );
    let (above, below) = owner_run_lines();
    let mut below_colored = below;
    below_colored[1] = (StatusLineKind::FooterProse, colored);
    let frame = frame_status_output(above, below_colored, 80);
    assert_eq!(frame.width, 80);
    let cut = frame
        .below_grid
        .iter()
        .find(|l| l.contains("allowed / dropped"))
        .unwrap();
    assert_eq!(colored_display_width(cut), 80);
    assert!(
        cut.starts_with("\x1b[38;2;139;139;139m"),
        "the open SGR copies whole"
    );
    assert!(
        cut.ends_with("…\x1b"),
        "the cut re-closes the tier with the layer's own reset spelling"
    );
}
