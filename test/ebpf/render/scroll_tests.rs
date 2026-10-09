// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the eagle-eyes scroll state (night-improve-58) —
//! kept in the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from scroll.rs. The pure surfaces pinned here:
//! the six-key decision core (left is ALWAYS the top process
//! section, right ALWAYS the baseline police panel, idempotent —
//! the owner's exact key map; up/down step the focused section
//! only), the clamp law (the window never outruns the rows the
//! frame holds, and the clamp writes home), and the scroll note's
//! four shapes (the advice that replaced "raise the window").

use super::*;

/// The key map itself: the section keys are idempotent and
/// unambiguous (left = top process, right = baseline police, no
/// wraparound — the owner's exact words), and a section key that
/// names the section already focused is a no-action, not a repaint
/// demand.
#[test]
fn section_keys_are_idempotent_and_unambiguous() {
    let mut scroll = ScrollState::new();
    assert_eq!(scroll.focused(), Section::TopProcess, "the resting focus");

    // Right lands on the baseline police, and says it moved.
    assert!(scroll.apply(InputAction::SectionNext));
    assert_eq!(scroll.focused(), Section::BaselinePolice);
    // Right again: already there — a no-action.
    assert!(!scroll.apply(InputAction::SectionNext));
    assert_eq!(scroll.focused(), Section::BaselinePolice);

    // Left lands back on the top process table.
    assert!(scroll.apply(InputAction::SectionPrev));
    assert_eq!(scroll.focused(), Section::TopProcess);
    assert!(!scroll.apply(InputAction::SectionPrev));
    assert_eq!(scroll.focused(), Section::TopProcess);
}

/// Up/down step the FOCUSED section only — the other section's
/// window keeps its place (switching focus never loses the other
/// side's scroll position), up clamps at zero, and the non-arrow
/// actions ride in from the same classification inert.
#[test]
fn arrows_step_the_focused_section_only() {
    let mut scroll = ScrollState::new();
    // Down twice on the table: 0 -> 1 -> 2.
    assert!(scroll.apply(InputAction::ScrollDown));
    assert!(scroll.apply(InputAction::ScrollDown));
    assert_eq!(scroll.table_window(50), 2, "two downs on the table");

    // Switch to the panel: its window is still at its top.
    assert!(scroll.apply(InputAction::SectionNext));
    assert_eq!(scroll.panel_window(50), 0, "the panel's window untouched");

    // Down on the panel steps the panel, not the table.
    assert!(scroll.apply(InputAction::ScrollDown));
    assert_eq!(scroll.panel_window(50), 1);
    assert_eq!(scroll.table_window(50), 2, "the table's window untouched");

    // Back to the table, up clamps at zero (three ups from 2).
    scroll.apply(InputAction::SectionPrev);
    scroll.apply(InputAction::ScrollUp);
    scroll.apply(InputAction::ScrollUp);
    assert!(
        !scroll.apply(InputAction::ScrollUp),
        "up at the top is a no-action"
    );
    assert_eq!(scroll.table_window(50), 0);

    // The panel's window survives the table's walk (focus switch
    // never resets the other side).
    assert_eq!(scroll.panel_window(50), 1);

    // The non-arrow actions are inert by construction.
    assert!(!scroll.apply(InputAction::None));
    assert!(!scroll.apply(InputAction::ThemeNext));
    assert!(!scroll.apply(InputAction::Quit));
}

/// The clamp law: a window never outruns the rows the frame holds —
/// a shrunken board snaps the window back to its last row, an
/// empty board sits at zero, and the clamp WRITES HOME so the next
/// arrow step rides the clamped value.
#[test]
fn the_window_clamps_to_the_rows_the_frame_holds() {
    let mut scroll = ScrollState::new();
    // Walk the table deep, then the board shrinks to 3 rows.
    for _ in 0..10 {
        scroll.apply(InputAction::ScrollDown);
    }
    assert_eq!(
        scroll.table_window(20),
        10,
        "the walk landed where it stepped"
    );
    assert_eq!(
        scroll.table_window(3),
        2,
        "a 3-row board snaps to its last row"
    );
    assert_eq!(scroll.table_window(3), 2, "and the clamp wrote home");
    assert_eq!(scroll.table_window(0), 0, "an empty board sits at zero");
    assert_eq!(scroll.table_window(1), 0, "a one-row board sits at zero");

    // The panel holds the same law one section over.
    scroll.apply(InputAction::SectionNext);
    for _ in 0..5 {
        scroll.apply(InputAction::ScrollDown);
    }
    assert_eq!(
        scroll.panel_window(4),
        3,
        "a 4-row panel snaps to its last row"
    );
    assert_eq!(scroll.panel_window(0), 0);
}

/// A wedged key repeat cannot grow the offset without bound: the
/// state-side belt caps the walk at the board's own ceiling, and
/// the render clamp eats whatever a belt could miss.
#[test]
fn a_wedged_hold_cannot_walk_past_the_ceiling() {
    let mut scroll = ScrollState::new();
    for _ in 0..(MAX_SCROLL_ROWS + 32) {
        scroll.apply(InputAction::ScrollDown);
    }
    assert_eq!(scroll.table_window(usize::MAX / 2), MAX_SCROLL_ROWS);
}

/// The scroll note (the advice that replaced "raise the window"):
/// four shapes, one spelling — nothing hidden reads clean (no
/// note), rows cut below, rows skipped above, and both at once.
#[test]
fn the_scroll_note_names_both_directions() {
    assert_eq!(scroll_note(0, 0), None, "everything fits — the clean read");
    assert_eq!(scroll_note(0, 7).as_deref(), Some("(+7 more — ↑↓ scroll)"));
    assert_eq!(scroll_note(3, 0).as_deref(), Some("(-3 above — ↑↓ scroll)"));
    assert_eq!(
        scroll_note(3, 7).as_deref(),
        Some("(-3 above · +7 more — ↑↓ scroll)")
    );
}
