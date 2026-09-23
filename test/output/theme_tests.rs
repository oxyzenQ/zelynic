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
/// forward with wraparound; the pure math keeps both directions
/// (NIGHT-engrave-2 retired the `T` key, not the wraparound).
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
    // Reverse walk: pinned math, unbound key (engrave-2).
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
/// SGR sequence (or the documented Mono empty string) and every
/// theme differs from the default at TrueColor depth. (The
/// title-suffix pins retired with the suffix itself — NIGHT-engrave-2
/// moved the theme name to the footer's status line.)
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

/// The NIGHT-boost-23 masterclass audit pins (the five non-default
/// themes): the corrected 256-depth indices — nearest-cube for the
/// brand/ok slots (hue reads true), the documented visibility corners
/// where hue holds — and the absolute 16-color distinctness contract
/// (no two slots of one theme share an SGR; the brand takes the
/// bright slot on the two themes whose brand collided with data).
#[test]
fn boost23_audit_fixes_the_fallback_table() {
    let idx256 = |t: Theme, s: Slot| escape_for(t, s, false, ColorCapability::Color256);
    let sgr16 = |t: Theme, s: Slot| escape_for(t, s, false, ColorCapability::Color16);

    // Nearest-cube corrections (brand/ok slots — hue must read true):
    // forest's leaf-green brand 71 (olive) -> 107; carbon's silver
    // brand 250 (the 188 grey rung, BELOW its own 16-color fallback)
    // -> 231; carbon's pale-mint ok 48 (saturated spring green, 28x
    // the nearest error) -> 157; night_cyber's mint ok 48 -> 49;
    // atomic's vivid-green ok 46 -> 42.
    assert_eq!(idx256(Theme::Forest, Slot::Brand), "\x1b[38;5;107m");
    assert_eq!(idx256(Theme::Carbon, Slot::Brand), "\x1b[38;5;231m");
    assert_eq!(idx256(Theme::Carbon, Slot::Ok), "\x1b[38;5;157m");
    assert_eq!(idx256(Theme::NightCyber, Slot::Ok), "\x1b[38;5;49m");
    assert_eq!(idx256(Theme::Atomic, Slot::Ok), "\x1b[38;5;42m");

    // Per-theme hue-truth corrections for warn/hot: night_cyber's
    // soft-amber warn lands on the khaki rung 221 (not the pure gold
    // 220 its b=87 does not earn); atomic's near-pure yellow warn
    // joins the 220 family (226 retired); forest's burnt-orange hot
    // renders its true 166 (202 was a brighter orange than the
    // palette's own crown); carbon's soft red hot takes 203; atomic's
    // pink-leaning hot takes 197.
    assert_eq!(idx256(Theme::NightCyber, Slot::Warn), "\x1b[38;5;221m");
    assert_eq!(idx256(Theme::Atomic, Slot::Warn), "\x1b[38;5;220m");
    assert_eq!(idx256(Theme::Forest, Slot::Hot), "\x1b[38;5;166m");
    assert_eq!(idx256(Theme::Carbon, Slot::Hot), "\x1b[38;5;203m");
    assert_eq!(idx256(Theme::Atomic, Slot::Hot), "\x1b[38;5;197m");

    // The 16-color collision fixes: forest brand shares no SGR with
    // its ok (brand takes BRIGHT green 92, ok keeps green 32);
    // atomic brand takes BRIGHT yellow 93, clear of warn's 33.
    assert_eq!(sgr16(Theme::Forest, Slot::Brand), "\x1b[92m");
    assert_eq!(sgr16(Theme::Forest, Slot::Ok), "\x1b[32m");
    assert_eq!(sgr16(Theme::Atomic, Slot::Brand), "\x1b[93m");
    assert_eq!(sgr16(Theme::Atomic, Slot::Warn), "\x1b[33m");
}

/// The audit's standing contract, walked live over the whole catalog:
/// within every theme, the five slots' 16-color SGRs are pairwise
/// DISTINCT (a legacy terminal must never merge the frame's identity,
/// data tiers, warning, crown, and subordinates into one color), and
/// every theme's grey slot rides the uniform ramp 245 / bright black
/// 90 (subordination outranks nearest-match).
#[test]
fn sixteen_color_slots_stay_distinct_per_theme() {
    for theme in THEMES {
        let slots = [Slot::Brand, Slot::Ok, Slot::Warn, Slot::Hot, Slot::Grey];
        let mut seen: Vec<&str> = Vec::new();
        for slot in slots {
            let esc = escape_for(theme, slot, false, ColorCapability::Color16);
            assert!(
                !seen.contains(&esc),
                "{theme:?} slot {slot:?} repeats 16-color SGR {esc:?} — legacy terminals would merge slots"
            );
            seen.push(esc);
        }
        // The uniform grey tier (the documented contract).
        assert_eq!(
            escape_for(theme, Slot::Grey, false, ColorCapability::Color256),
            "\x1b[38;5;245m",
            "{theme:?} grey rides the neutral ramp"
        );
        assert_eq!(
            escape_for(theme, Slot::Grey, false, ColorCapability::Color16),
            "\x1b[90m",
            "{theme:?} grey rides bright black at 16 depth"
        );
    }
}
