// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The eagle-eyes scroll state (night-improve-58) — the owner's
//! six-key interactive contract: `q` quit, `t` theme, up/down
//! scroll the focused section, left/right switch it.
//!
//! The why is the owner's own: on a server or desktop with a
//! standard-height terminal, "raise the window" was the only way
//! to read the rows the frame cut — the old hidden note's advice
//! literally told the owner to grow the terminal. Scrolling is the
//! smaller ask: the window stays the terminal it is, the arrow
//! keys walk the rows instead. The ranked frame keeps its
//! two-section anatomy — the `top process` table and the
//! `baseline · policy aggregate` panel (the baseline police) — and
//! each section carries its own offset, so switching focus never
//! loses the other section's place.
//!
//! ── The key map (the owner's exact words) ─────────────────────
//!
//! * **left** is ALWAYS the top process section; **right** is
//!   ALWAYS the baseline police panel — idempotent, no wraparound
//!   (the theme key's modulo cycle is a different contract: two
//!   sections do not need a ring).
//! * **up/down** step the FOCUSED section one row at a time — the
//!   table steps whole board rows (a row plus its detail lines
//!   travel as the unit they render as), the panel steps verdict
//!   rows.
//! * Everything the arrows cannot reach is inert: the single-target
//!   focus view has no sections to steer (its detail is one
//!   cgroup's own), and the ranked frame below one data row has
//!   nothing to scroll — the offsets clamp at the render, and a
//!   shrunken board snaps its window back to the last row that
//!   exists.
//!
//! ── The clamp law (render-side, write-home) ────────────────────
//!
//! The state cannot know how many rows a section holds — the board
//! churns every frame and the panel's filtered count is the
//! panel's own arithmetic. So the state steps freely (bounded by
//! the board's own cap, a belt against a wedged hold), and each
//! section's RENDER clamps the offset against the rows it actually
//! holds and writes the clamped value home — the next key press
//! steps from where the window really is, never from a stale
//! offset past the end.

use crate::terminal::InputAction;

/// The ceiling a down-step may reach (the belt): the session board
/// itself caps at [`MAX_TRACKED_CGROUPS`](super::session) rows, and
/// the panel cannot exceed the ring read's own key set — an offset
/// past the cap could only come from a wedged key repeat, and the
/// render clamp would eat it the same frame anyway.
const MAX_SCROLL_ROWS: usize = 4096;

/// The two scrollable sections of the ranked frame
/// (night-improve-58): the `top process` table and the `baseline ·
/// policy aggregate` panel — the baseline police.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    /// The session leaderboard table (`top process`).
    TopProcess,
    /// The ruled verdict section under the table (the baseline
    /// police).
    BaselinePolice,
}

/// The monitor's scroll state: which section has the focus (the
/// gutter marker names it on the frame) and each section's first
/// visible row. Owned by the eagle-eyes handler's render closure;
/// stepped by [`ScrollState::apply`] from the classified
/// [`InputAction`], clamped by the renderers.
#[derive(Debug)]
pub(crate) struct ScrollState {
    focused: Section,
    top: usize,
    base: usize,
}

impl Default for ScrollState {
    fn default() -> Self {
        Self::new()
    }
}

impl ScrollState {
    /// The resting state: the top process table focused (the
    /// primary view), both windows at their tops.
    pub(crate) fn new() -> Self {
        ScrollState {
            focused: Section::TopProcess,
            top: 0,
            base: 0,
        }
    }

    /// The section the arrows steer (the gutter marker's owner).
    pub(crate) fn focused(&self) -> Section {
        self.focused
    }

    /// One classified input action onto the state. Returns whether
    /// the state MOVED (the caller's force flag — a focused-arrow
    /// press on the section it already names is a no-action, not a
    /// repaint demand). The non-arrow actions ride in from the same
    /// classification and are inert here by construction.
    pub(crate) fn apply(&mut self, action: InputAction) -> bool {
        match action {
            InputAction::ScrollUp => match self.focused {
                Section::TopProcess => {
                    let was = self.top;
                    self.top = self.top.saturating_sub(1);
                    self.top != was
                }
                Section::BaselinePolice => {
                    let was = self.base;
                    self.base = self.base.saturating_sub(1);
                    self.base != was
                }
            },
            InputAction::ScrollDown => match self.focused {
                Section::TopProcess => {
                    self.top = (self.top + 1).min(MAX_SCROLL_ROWS);
                    true
                }
                Section::BaselinePolice => {
                    self.base = (self.base + 1).min(MAX_SCROLL_ROWS);
                    true
                }
            },
            // The owner's exact key map: left is ALWAYS the top
            // process section, right ALWAYS the baseline police
            // panel — idempotent, no wraparound.
            InputAction::SectionPrev => {
                let was = self.focused;
                self.focused = Section::TopProcess;
                self.focused != was
            }
            InputAction::SectionNext => {
                let was = self.focused;
                self.focused = Section::BaselinePolice;
                self.focused != was
            }
            InputAction::Quit | InputAction::ThemeNext | InputAction::None => false,
        }
    }

    /// The table's window, clamped to the rows the board actually
    /// holds this frame (a shrunken board snaps the window back;
    /// an empty board sits at zero) — the clamped value is written
    /// home so the next step rides it.
    pub(crate) fn table_window(&mut self, rows: usize) -> usize {
        self.top = self.top.min(rows.saturating_sub(1));
        self.top
    }

    /// The panel's window, the table's own law one section over.
    pub(crate) fn panel_window(&mut self, rows: usize) -> usize {
        self.base = self.base.min(rows.saturating_sub(1));
        self.base
    }
}

/// The scroll-position note a truncating section renders instead of
/// the old "raise the window" advice (night-improve-58's whole
/// point: the window stays the terminal it is). `above` counts the
/// rows the offset skipped, `below` the rows the room cut — `None`
/// when the section holds everything (no note, the frame reads
/// clean). One spelling for both sections (the one-canonical-word
/// law): the counts vary, the advice never does.
pub(crate) fn scroll_note(above: usize, below: usize) -> Option<String> {
    match (above, below) {
        (0, 0) => None,
        (0, below) => Some(format!("(+{below} more — ↑↓ scroll)")),
        (above, 0) => Some(format!("(-{above} above — ↑↓ scroll)")),
        (above, below) => Some(format!("(-{above} above · +{below} more — ↑↓ scroll)")),
    }
}

// The scroll pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the session and baseline
// pins — one file per contract, the render family's own split
// discipline.
#[cfg(test)]
#[path = "../../../test/ebpf/render/scroll_tests.rs"]
mod scroll_tests;
