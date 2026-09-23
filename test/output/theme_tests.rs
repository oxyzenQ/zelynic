// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Theme catalog pins (NIGHT-boost-18 / improve-27): the netrunner
//! regression row (the default's encodings are byte-identical to the
//! pre-theme constants — the CLI's output cannot change), the cycle
//! wraparound in both directions (the cosmostrix modulo contract),
//! and the integrity walk over every theme x slot x capability.

use super::{active, cycle_from, escape_for, set, Slot, Theme, THEMES};
use crate::output::color::ColorCapability;

/// The netrunner regression row: every cell of the default table is
/// byte-identical to the constants the pre-theme color layer carried
/// — the pinned strings from src/output/color.rs's own tests. The
/// theme engine must be invisible until the monitor cycles it.
#[test]
fn netrunner_default_is_byte_identical_to_the_pre_theme_constants() {
    let t = Theme::Netrunner;
    // Brand: purple #A855F7, 256-index 135, 16-color magenta 35.
    assert_eq!(
        escape_for(t, Slot::Brand, false, ColorCapability::TrueColor),
        "\x1b[38;2;168;85;247m"
    );
    assert_eq!(
        escape_for(t, Slot::Brand, true, ColorCapability::TrueColor),
        "\x1b[1;38;2;168;85;247m"
    );
    assert_eq!(
        escape_for(t, Slot::Brand, false, ColorCapability::Color256),
        "\x1b[38;5;135m"
    );
    assert_eq!(
        escape_for(t, Slot::Brand, true, ColorCapability::Color256),
        "\x1b[1;38;5;135m"
    );
    assert_eq!(
        escape_for(t, Slot::Brand, false, ColorCapability::Color16),
        "\x1b[35m"
    );
    assert_eq!(
        escape_for(t, Slot::Brand, true, ColorCapability::Color16),
        "\x1b[1;35m"
    );
    // Ok: status green #50FA7B, 84, 32.
    assert_eq!(
        escape_for(t, Slot::Ok, false, ColorCapability::TrueColor),
        "\x1b[38;2;80;250;123m"
    );
    assert_eq!(
        escape_for(t, Slot::Ok, true, ColorCapability::Color256),
        "\x1b[1;38;5;84m"
    );
    assert_eq!(
        escape_for(t, Slot::Ok, false, ColorCapability::Color16),
        "\x1b[32m"
    );
    // Warn: yellow #FFEB3C, 220, 33.
    assert_eq!(
        escape_for(t, Slot::Warn, false, ColorCapability::TrueColor),
        "\x1b[38;2;255;235;60m"
    );
    assert_eq!(
        escape_for(t, Slot::Warn, true, ColorCapability::Color16),
        "\x1b[1;33m"
    );
    // Hot: champion red #FF3B30, 196, 91.
    assert_eq!(
        escape_for(t, Slot::Hot, false, ColorCapability::TrueColor),
        "\x1b[38;2;255;59;48m"
    );
    assert_eq!(
        escape_for(t, Slot::Hot, false, ColorCapability::Color256),
        "\x1b[38;5;196m"
    );
    assert_eq!(
        escape_for(t, Slot::Hot, false, ColorCapability::Color16),
        "\x1b[91m"
    );
    // Grey: calm grey #8B8B8B, 245, 90.
    assert_eq!(
        escape_for(t, Slot::Grey, false, ColorCapability::TrueColor),
        "\x1b[38;2;139;139;139m"
    );
    assert_eq!(
        escape_for(t, Slot::Grey, false, ColorCapability::Color256),
        "\x1b[38;5;245m"
    );
    assert_eq!(
        escape_for(t, Slot::Grey, false, ColorCapability::Color16),
        "\x1b[90m"
    );
    // Mono is empty everywhere.
    for slot in [Slot::Brand, Slot::Ok, Slot::Warn, Slot::Hot, Slot::Grey] {
        assert_eq!(escape_for(t, slot, false, ColorCapability::Mono), "");
        assert_eq!(escape_for(t, slot, true, ColorCapability::Mono), "");
    }
}

/// The cycle contract (cosmostrix modulo pattern): `t` steps
/// forward, `T` steps back, both wrap at the catalog edges.
#[test]
fn cycle_wraps_in_both_directions() {
    // Forward walk over the whole catalog, wrapping to the default.
    assert_eq!(cycle_from(Theme::Netrunner, 1), Theme::NightCyber);
    assert_eq!(cycle_from(Theme::NightCyber, 1), Theme::Forest);
    assert_eq!(cycle_from(Theme::Forest, 1), Theme::Spaceflight);
    assert_eq!(cycle_from(Theme::Spaceflight, 1), Theme::Carbon);
    assert_eq!(cycle_from(Theme::Carbon, 1), Theme::Atomic);
    assert_eq!(
        cycle_from(Theme::Atomic, 1),
        Theme::Netrunner,
        "forward wraps"
    );
    // Reverse walk: the uppercase twin.
    assert_eq!(
        cycle_from(Theme::Netrunner, -1),
        Theme::Atomic,
        "reverse wraps"
    );
    assert_eq!(cycle_from(Theme::NightCyber, -1), Theme::Netrunner);
    assert_eq!(cycle_from(Theme::Atomic, -1), Theme::Carbon);
    // Multi-step and the modulo math hold for larger jumps.
    assert_eq!(
        cycle_from(Theme::Netrunner, 6),
        Theme::Netrunner,
        "full lap"
    );
    assert_eq!(cycle_from(Theme::Netrunner, 7), Theme::NightCyber);
    assert_eq!(cycle_from(Theme::Netrunner, -7), Theme::Atomic);
}

/// Integrity walk: every theme x slot x capability produces a valid
/// SGR sequence (or the documented Mono empty string), every theme
/// differs from the default at TrueColor depth, and every theme's
/// title suffix is empty only for the default.
#[test]
fn catalog_integrity_walk() {
    let slots = [Slot::Brand, Slot::Ok, Slot::Warn, Slot::Hot, Slot::Grey];
    for theme in THEMES {
        for slot in slots {
            for bold in [false, true] {
                let esc = escape_for(theme, slot, bold, ColorCapability::TrueColor);
                assert!(
                    esc.starts_with("\x1b[") && esc.ends_with('m'),
                    "{:?}/{:?}/bold={} truecolor escape malformed: {esc:?}",
                    theme,
                    slot,
                    bold
                );
                let esc256 = escape_for(theme, slot, bold, ColorCapability::Color256);
                assert!(esc256.starts_with("\x1b[38;5;") || esc256.starts_with("\x1b[1;38;5;"));
                assert!(escape_for(theme, slot, bold, ColorCapability::Mono).is_empty());
            }
        }
        // Distinctness: every NON-default theme's brand escape
        // differs from the default's (a cycle that changes nothing is
        // a broken cycle); the default equals itself, trivially.
        let default_brand = escape_for(
            Theme::Netrunner,
            Slot::Brand,
            false,
            ColorCapability::TrueColor,
        );
        let theme_brand = escape_for(theme, Slot::Brand, false, ColorCapability::TrueColor);
        if theme == Theme::Netrunner {
            assert_eq!(theme_brand, default_brand, "the default is itself");
        } else {
            assert_ne!(
                theme_brand, default_brand,
                "{theme:?} brand must differ from the default"
            );
        }
        // Suffix honesty: only the default renders suffix-free; every
        // cycled theme names itself in the title suffix.
        if theme == Theme::Netrunner {
            assert_eq!(theme.title_suffix(), "");
        } else {
            assert!(theme.title_suffix().starts_with(" — "));
            assert!(theme.title_suffix().contains(theme.name()));
        }
    }
}

/// The global state: set/cycle/active round-trip, and the default is
/// netrunner before anything writes it. Restores the default on the
/// way out — the color-layer shape tests run in parallel and read
/// through this global (their assertions are shape-based, so any
/// theme passes them, but hygiene is cheap).
#[test]
fn global_state_round_trips_and_restores() {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            set(Theme::Netrunner);
        }
    }
    let _guard = Restore;
    assert_eq!(active(), Theme::Netrunner, "the process default");
    set(Theme::Atomic);
    assert_eq!(active(), Theme::Atomic);
    assert_eq!(
        super::cycle(1),
        Theme::Netrunner,
        "cycle returns what it became"
    );
    assert_eq!(active(), Theme::Netrunner);
    assert_eq!(super::cycle(-1), Theme::Atomic);
    assert_eq!(active(), Theme::Atomic);
}
