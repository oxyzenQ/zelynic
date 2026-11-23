// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The eagle-eyes column planner (night-frontier-Z13-10, the
//! 600-LOC owner cap): the degradation ladder as its own module —
//! one file per contract, the same split discipline focus, footer,
//! detail, rank, targets, and the ranked table each took. Moved
//! verbatim from the render mod; the re-export beside the mod
//! declaration keeps every existing `super::` path resolving (the
//! eagle frame, the row renderer, the ranked table, and the
//! header-alignment pins all read the pair through [`super`]).

/// Eagle-eyes column layout derived from the frame width.
///
/// Degradation ladder (the 7-column rank reserve of night-improve-61
/// — its 3-column `=> ` marker lane — engrave-4's 2-column right gutter):
/// - width >= 54: (rank) | top process | download | upload | total
/// - width >= 43: (rank) | top process | download | upload (total dropped)
/// - width  < 43: (rank) | top process (min 12) | download | upload at 9-wide
///
/// Download and upload carry per-frame RATES (delta / interval —
/// "what is moving right now"); total carries the session-accumulated
/// bytes (NIGHT-boost-5: the v10 "total accumulated" function
/// restored as the ranking key's own column). The old combined RATE
/// column was dl+ul restated — the total column replaces it.
///
/// NIGHT-engrave-4 (the symmetric-rails fix): the table's rows end
/// two columns short of the frame width — the RIGHT gutter, the
/// mirror of the left gutter every frame line starts with. The
/// TOTAL column's figures used to end flush against the right rail
/// (the owner's "too near the border, hard to see" — the digits and
/// the rail glyph fought for the same column); now the rightmost
/// numeric cell closes at the gutter's edge with the same two
/// columns of air the rank enjoys on the left. The label column
/// absorbs the gutter, so a full row still composes to an exact
/// width — just two columns short of the content inset, and the
/// border's fit() pads the rest.
///
/// NIGHT-boost-5: the header rank cell is blank (the owner's "#"
/// header retired) and the absorption math makes every data row end
/// at the right gutter's edge — the label column absorbs exactly what
/// the rank cell, the gaps, the numeric columns, and the right
/// gutter leave. The old reserve formula over-allocated three spare
/// columns, leaving every row 3 short of the separator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EagleColumns {
    pub(crate) label_w: usize,
    pub(crate) dl_w: usize,
    pub(crate) ul_w: usize,
    /// The retrans column's width (night-netrunner-4): 0 = the rung
    /// is hidden (the 54..=61 band and every narrower rung keep the
    /// pre-netrunner-4 shapes entirely). 7 = the full rung, the
    /// header spelled in full.
    pub(crate) retrans_w: usize,
    pub(crate) show_total: bool,
}

/// Plan the eagle-eyes column layout for a given terminal width.
#[must_use]
pub(crate) fn plan_eagle_columns(width: usize) -> EagleColumns {
    const RANK_W: usize = 7; // 3 marker lane + 2 rank digits + 2 gap
    const NUM_W: usize = 10;
    const NUM_W_TIGHT: usize = 9;
    const LABEL_MIN: usize = 12;
    // The retrans column (night-netrunner-4): width 7 — the header
    // spells `retrans` in full (the surface vocabulary never
    // abbreviates), the figure fits (a window's retransmit count is
    // small; saturation is the ladder's ceiling, not a real shape).
    const RETRANS_W: usize = 7;
    // The symmetric right gutter (NIGHT-engrave-4): the two columns
    // of air after the TOTAL column (the left lane is the `=> `
    // marker's estate since night-improve-61). Narrow-floor frames
    // drop it first — survival outranks harmony below the ladder.
    const RIGHT_GUTTER: usize = 2;

    // Full layout with the retrans rung (night-netrunner-4): rank +
    // label + dl + ul + retrans + total. The audit's reservation:
    // RANK_W + LABEL_MIN + 3 x (1 + NUM_W) for the three wide
    // numerics, + (1 + RETRANS_W) for the new rung, + the gutter =
    // 62 — the netrunner-3 ladder's exact math, one rung added
    // instead of the existing ones shifting.
    if width >= RANK_W + LABEL_MIN + 3 * (1 + NUM_W) + (1 + RETRANS_W) + RIGHT_GUTTER {
        return EagleColumns {
            label_w: width - RANK_W - 3 * (1 + NUM_W) - (1 + RETRANS_W) - RIGHT_GUTTER,
            dl_w: NUM_W,
            ul_w: NUM_W,
            retrans_w: RETRANS_W,
            show_total: true,
        };
    }

    // The pre-netrunner-4 full rung (54..=61): the retrans column
    // folds back into the detail family — a narrow frame never loses
    // a column it had, and the default table keeps the shape the
    // right-gutter contract gave it.
    if width >= RANK_W + LABEL_MIN + 3 * (1 + NUM_W) + RIGHT_GUTTER {
        return EagleColumns {
            label_w: width - RANK_W - 3 * (1 + NUM_W) - RIGHT_GUTTER,
            dl_w: NUM_W,
            ul_w: NUM_W,
            retrans_w: 0,
            show_total: true,
        };
    }

    // TOTAL dropped (the session figure survives in the focus view;
    // the live rates are the realtime sacrifice ladder's first cut):
    // rank + label + 2 numeric columns — the right gutter rides
    // along (the UPLOAD figures close at the gutter's edge too).
    if width >= RANK_W + LABEL_MIN + 2 * (1 + NUM_W) + RIGHT_GUTTER {
        return EagleColumns {
            label_w: width - RANK_W - 2 * (1 + NUM_W) - RIGHT_GUTTER,
            dl_w: NUM_W,
            ul_w: NUM_W,
            retrans_w: 0,
            show_total: false,
        };
    }

    // Narrow fallback: tighter numerics, label pinned to the minimum.
    EagleColumns {
        label_w: LABEL_MIN,
        dl_w: NUM_W_TIGHT,
        ul_w: NUM_W_TIGHT,
        retrans_w: 0,
        show_total: false,
    }
}
