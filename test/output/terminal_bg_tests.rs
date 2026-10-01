// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Terminal-background pins (NIGHT-boost-26/32): the pure escape
//! cores, the paintable-depth filter, and the live word's packing —
//! moved whole from theme_tests.rs when NIGHT-dinner-30's twelfth
//! palette pushed both files to the LOC cap (the background follow
//! is the terminal_bg module's concern, and its pins moved with it).

use super::{pack_bg, terminal_bg_at, terminal_bg_escape_at, unpack_bg};
use crate::output::color::ColorCapability;

/// The pure escape cores: TrueColor paints the exact OSC 11 triple;
/// Color256 quantizes onto the 6x6x6 cube (46,46,46 -> 59, the same
/// nearest-match arithmetic the rails ride); the shallow depths and
/// the absent triple paint NOTHING — the terminal default is the
/// honest background there, never an invented hue.
#[test]
fn terminal_bg_escape_shapes_by_depth() {
    let grey = Some((46, 46, 46));
    assert_eq!(
        terminal_bg_escape_at(grey, ColorCapability::TrueColor),
        "\x1b[48;2;46;46;46m"
    );
    assert_eq!(
        terminal_bg_escape_at(grey, ColorCapability::Color256),
        "\x1b[48;5;59m"
    );
    assert_eq!(
        terminal_bg_escape_at(grey, ColorCapability::Color16),
        String::new()
    );
    assert_eq!(
        terminal_bg_escape_at(grey, ColorCapability::Mono),
        String::new()
    );
    assert_eq!(
        terminal_bg_escape_at(None, ColorCapability::TrueColor),
        String::new()
    );
}

/// The stored triple survives only at the paint-capable depths
/// (the pure filter core): a Color16/Mono frame never paints a
/// background whatever the query answered.
#[test]
fn terminal_bg_survives_only_at_paintable_depths() {
    let grey = Some((46, 46, 46));
    assert_eq!(terminal_bg_at(grey, ColorCapability::TrueColor), grey);
    assert_eq!(terminal_bg_at(grey, ColorCapability::Color256), grey);
    assert_eq!(terminal_bg_at(grey, ColorCapability::Color16), None);
    assert_eq!(terminal_bg_at(grey, ColorCapability::Mono), None);
    assert_eq!(terminal_bg_at(None, ColorCapability::TrueColor), None);
}

/// The atomic word's packing round-trips every triple, and the
/// absent triple is the distinct word 0 — the live ask's updates
/// and the compositor's reads agree on one representation.
#[test]
fn bg_word_packing_round_trips() {
    assert_eq!(pack_bg(None), 0);
    assert_eq!(unpack_bg(0), None);
    for (r, g, b) in [(46, 46, 46), (255, 0, 0), (0, 128, 255), (1, 2, 3)] {
        let triple = Some((r, g, b));
        assert_eq!(unpack_bg(pack_bg(triple)), triple);
    }
    // Distinct triples pack to distinct words (a change verdict can
    // never collide), and the present flag never leaks into the
    // payload bits.
    let a = pack_bg(Some((0, 0, 46)));
    let b = pack_bg(Some((0, 0, 47)));
    assert_ne!(a, b);
    assert_eq!(a & 0x00FF_FFFF, 46);
}
