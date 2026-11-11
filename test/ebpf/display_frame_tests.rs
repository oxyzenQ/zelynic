// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The Shape B frame-law pins (night-ux-5): the status frame is the
//! CONTENT's own width — the widest line the output prints — every
//! line pads to that one right edge, and the narrow-terminal cut
//! eats the sacrifice ladder (footer prose first) without ever
//! touching the table or the stamp. Wired from display_lines.rs at
//! the display_tests LOC headroom, the house split discipline.
//! night-docs-1: the footer is TWO lines (the window line, the
//! direction law), each its own frame entry, and both fit the
//! owner's 80-column budget whole — the pins below hold the fit,
//! the cut ladder, and the escape path. Colors are identity in the
//! test env (Mono), so the escape path rides hand-built SGR +
//! bare-ESC strings — the exact bytes the color layer emits on a
//! real terminal.

use super::{
    StatusLineKind, counters_footer_lines, frame_status_output, status_header_line, status_row_line,
};
use crate::ebpf::display::{RecwnLane, recwn_line};
use crate::output::colored_display_width;

/// The frame law's input shape: the grid's two flanks, kind-tagged.
type Flanks = (Vec<(StatusLineKind, String)>, Vec<(StatusLineKind, String)>);

/// The owner's 2026-11-08 live run, composed: a 57-column table, a
/// 74-column RECWN line (one binding policy — the owner's own
/// scenario), the night-docs-1 two-line footer (42 and 76 columns
/// — the direction line is the widest line the run carries), a
/// short stamp.
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
        (
            StatusLineKind::FooterProse,
            counters_footer_lines()[0].clone(),
        ),
        (
            StatusLineKind::FooterProse,
            counters_footer_lines()[1].clone(),
        ),
        (
            StatusLineKind::Recwn,
            recwn_line(&RecwnLane {
                planted: true,
                window_bytes: Some(40_000),
                binding_policies: 1,
                measured_srtt_us: None,
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

/// The wide terminal: the frame widens to the footer's direction
/// line — the widest line the output prints (76 columns) — and
/// EVERY line pads to that one width, so the right edge is one
/// straight column. The table (57) and the RECWN line (74) ride
/// inside the frame, byte-identical with pad spaces after them.
#[test]
fn frame_widens_to_its_widest_content() {
    let (above, below) = owner_run_lines();
    let footer_w = below
        .iter()
        .filter(|(k, _)| *k == StatusLineKind::FooterProse)
        .map(|(_, l)| colored_display_width(l))
        .max()
        .unwrap();
    assert_eq!(
        footer_w, 76,
        "the direction line is the wide line, 76 columns"
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

/// night-docs-1's own law: the two-line footer fits the owner's
/// 80-column budget WHOLE — no line cuts, and the direction clause
/// ("ingress burns quota, egress saves it") survives to its last
/// column. The single-line shape the task measured first could not
/// do this: cut at 80 it lost the direction clause entirely (the
/// cut landed mid-"working."), which is why the footer is two
/// lines, each its own frame entry.
#[test]
fn the_direction_footer_fits_the_80_column_budget() {
    let (above, below) = owner_run_lines();
    let frame = frame_status_output(above, below, 80);
    assert!(
        frame.width <= 80,
        "nothing in the composed run exceeds the budget, got {}",
        frame.width
    );
    let direction = frame
        .below_grid
        .iter()
        .find(|l| l.contains("ingress burns quota"))
        .expect("the direction line prints");
    assert!(
        direction.contains("egress saves it."),
        "the direction clause is never truncated at 80 columns: {direction}"
    );
    assert!(!direction.ends_with('…'), "no ellipsis at the budget");
}

/// The narrow terminal: the footer's direction line cuts FIRST (the
/// least load-bearing line for a one-glance read), to exactly the
/// budget, ellipsis last — never wrapped. At a 75-column budget the
/// 76-column direction line gives up its tail (the "egress saves
/// it" half truncates; the burn clause — the more important half —
/// survives the cut), the window line and the 74-column RECWN line
/// under it ride untouched, and the table never cuts.
#[test]
fn narrow_terminal_cuts_the_footer_prose_first() {
    let (above, below) = owner_run_lines();
    let frame = frame_status_output(above, below, 75);
    let cut_footer = frame
        .below_grid
        .iter()
        .find(|l| l.contains("ingress burns quota"))
        .expect("the direction line prints");
    assert_eq!(
        colored_display_width(cut_footer),
        75,
        "the cut lands exactly on the budget, got: {cut_footer}"
    );
    assert!(
        cut_footer.ends_with('…'),
        "ellipsis, never a wrap or a hard cut"
    );
    assert!(
        cut_footer.contains("ingress burns quota"),
        "the burn clause survives the cut: {cut_footer}"
    );
    let recwn = frame
        .below_grid
        .iter()
        .find(|l| l.contains("RECWN window"))
        .expect("the RECWN line prints");
    assert!(
        !recwn.ends_with('…'),
        "the 74-column RECWN line fits the 75-column budget untouched"
    );
    assert_eq!(frame.width, 75);
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
    let footer = counters_footer_lines()[1].clone();
    let plain_w = colored_display_width(&footer);
    assert_eq!(plain_w, 76, "the direction line is the wide one");
    let colored = format!("\x1b[38;2;139;139;139m{footer}\x1b");
    assert_eq!(
        colored_display_width(&colored),
        plain_w,
        "the SGR open and the bare-ESC reset claim zero columns"
    );
    let (above, below) = owner_run_lines();
    let mut below_colored = below;
    let idx = below_colored
        .iter()
        .position(|(k, l)| *k == StatusLineKind::FooterProse && l.contains("ingress"))
        .expect("the direction line sits in the lower flank");
    below_colored[idx] = (StatusLineKind::FooterProse, colored);
    let frame = frame_status_output(above, below_colored, 70);
    assert_eq!(frame.width, 70);
    let cut = frame
        .below_grid
        .iter()
        .find(|l| l.contains("ingress"))
        .unwrap();
    assert_eq!(colored_display_width(cut), 70);
    assert!(
        cut.starts_with("\x1b[38;2;139;139;139m"),
        "the open SGR copies whole"
    );
    assert!(
        cut.ends_with("…\x1b"),
        "the cut re-closes the tier with the layer's own reset spelling"
    );
}
