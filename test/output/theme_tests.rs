// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Theme catalog pins (NIGHT-boost-18 / improve-27): the netrunner
//! regression row (the default's encodings are byte-identical to the
//! pre-theme constants — the CLI's output cannot change), the cycle
//! wraparound in both directions (the cosmostrix modulo contract),
//! and the integrity walk over every theme x slot x capability.
//! The catalog's public face (names + brand RGBs) is pinned against
//! the BRANDING.md 2.2 palette table — and those calls are what keep
//! `name()`/`brand_rgb()` alive in the featureless test build (the
//! CI dead-code fix: their only other callers sit behind the ebpf
//! feature).

use super::{
    active, cycle_from, escape_for, set, terminal_bg_at, terminal_bg_escape_at, Slot, Theme, THEMES,
};
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
/// NIGHT-engrave-7 grew the lap to eleven — the five new palettes
/// (cafe, server, moonlight, hacker, depth_sea) close the ring.
#[test]
fn cycle_wraps_in_both_directions() {
    // Forward walk over the whole catalog, wrapping to the default.
    assert_eq!(cycle_from(Theme::Netrunner, 1), Theme::NightCyber);
    assert_eq!(cycle_from(Theme::NightCyber, 1), Theme::Forest);
    assert_eq!(cycle_from(Theme::Forest, 1), Theme::Spaceflight);
    assert_eq!(cycle_from(Theme::Spaceflight, 1), Theme::Carbon);
    assert_eq!(cycle_from(Theme::Carbon, 1), Theme::Atomic);
    assert_eq!(cycle_from(Theme::Atomic, 1), Theme::Cafe);
    assert_eq!(cycle_from(Theme::Cafe, 1), Theme::Server);
    assert_eq!(cycle_from(Theme::Server, 1), Theme::Moonlight);
    assert_eq!(cycle_from(Theme::Moonlight, 1), Theme::Hacker);
    assert_eq!(cycle_from(Theme::Hacker, 1), Theme::DepthSea);
    assert_eq!(
        cycle_from(Theme::DepthSea, 1),
        Theme::Netrunner,
        "forward wraps"
    );
    // Reverse walk: pinned math, unbound key (engrave-2).
    assert_eq!(
        cycle_from(Theme::Netrunner, -1),
        Theme::DepthSea,
        "reverse wraps"
    );
    assert_eq!(cycle_from(Theme::NightCyber, -1), Theme::Netrunner);
    assert_eq!(cycle_from(Theme::Atomic, -1), Theme::Carbon);
    assert_eq!(cycle_from(Theme::Cafe, -1), Theme::Atomic);
    assert_eq!(cycle_from(Theme::DepthSea, -1), Theme::Hacker);
    // Multi-step and the modulo math hold for larger jumps.
    assert_eq!(
        cycle_from(Theme::Netrunner, 11),
        Theme::Netrunner,
        "full lap"
    );
    assert_eq!(cycle_from(Theme::Netrunner, 12), Theme::NightCyber);
    assert_eq!(cycle_from(Theme::Netrunner, -12), Theme::DepthSea);
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
        Theme::Cafe,
        "cycle returns what it became (engrave-7: atomic's neighbor is cafe)"
    );
    assert_eq!(active(), Theme::Cafe);
    assert_eq!(super::cycle(-1), Theme::Atomic);
    assert_eq!(active(), Theme::Atomic);
    // The catalog's wraparound (engrave-7's eleven-wide ring): the
    // last theme steps forward into the default, and the default
    // steps back into the last.
    set(Theme::DepthSea);
    assert_eq!(super::cycle(1), Theme::Netrunner, "forward wraps");
    assert_eq!(active(), Theme::Netrunner);
    assert_eq!(super::cycle(-1), Theme::DepthSea, "reverse wraps");
    assert_eq!(active(), Theme::DepthSea);
}

/// The catalog's public face, pinned against BRANDING.md 2.2: every
/// theme's name and brand RGB match the documented palette — the
/// footer's status line renders the name (NIGHT-engrave-2) and the
/// border gradient ramps the brand RGB (NIGHT-boost-20), so neither
/// may drift from the docs. These calls also keep both methods alive
/// in the plain (non-ebpf) test build, where their only other
/// callers sit behind the monitor feature — the exact gap that
/// reddened CI for six commits (`-D dead-code` on the default
/// featureless test build after engrave-2 retired the title-suffix
/// pin; a test-only gap, the shipped binary was never wrong).
/// NIGHT-engrave-7: the catalog grew to eleven (the owner's frontier
/// five: cafe, server, moonlight, hacker, depth_sea).
#[test]
fn catalog_names_and_brand_rgbs_match_the_branding_docs() {
    let pinned: [(Theme, &str, (u8, u8, u8)); 11] = [
        (Theme::Netrunner, "netrunner", (168, 85, 247)),
        (Theme::NightCyber, "night_cyber", (0, 229, 255)),
        (Theme::Forest, "forest", (124, 179, 66)),
        (Theme::Spaceflight, "spaceflight", (79, 195, 247)),
        (Theme::Carbon, "carbon", (214, 214, 214)),
        (Theme::Atomic, "atomic", (255, 109, 0)),
        (Theme::Cafe, "cafe", (198, 139, 89)),
        (Theme::Server, "server", (110, 155, 197)),
        (Theme::Moonlight, "moonlight", (184, 204, 232)),
        (Theme::Hacker, "hacker", (51, 255, 51)),
        (Theme::DepthSea, "depth_sea", (31, 191, 173)),
    ];
    assert_eq!(
        THEMES.len(),
        pinned.len(),
        "the catalog and the documented palette stay in lockstep"
    );
    for (theme, name, rgb) in pinned {
        assert_eq!(
            theme.name(),
            name,
            "{theme:?} name matches the BRANDING.md 2.2 spelling"
        );
        assert_eq!(
            theme.brand_rgb(),
            rgb,
            "{theme:?} brand RGB matches the BRANDING.md 2.2 hex"
        );
        // The slot! table and brand_rgb() derive from the same
        // numbers: the TrueColor brand escape and the gradient's
        // ramp source cannot drift apart.
        let (r, g, b) = rgb;
        assert_eq!(
            escape_for(theme, Slot::Brand, false, ColorCapability::TrueColor),
            format!("\x1b[38;2;{r};{g};{b}m"),
            "{theme:?} truecolor brand escape derives from brand_rgb()"
        );
        // The engraved lowercase contract: the status line renders
        // `theme {name}` in the all-lowercase frame.
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{theme:?} name is lowercase"
        );
    }
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

/// The NIGHT-engrave-7 frontier five (cafe, server, moonlight,
/// hacker, depth_sea): the same boost-23 fallback contract, pinned
/// per theme — brand/ok on their computed NEAREST cube indices (the
/// quantization was computed, not eyeballed), warn/hot on the
/// documented visibility precedents (the saturated corner where the
/// hue family holds, per-theme hue-truth rungs where the palette
/// earns them), and the 16-color picks that keep every theme's five
/// slots pairwise distinct.
#[test]
fn engrave7_frontier_five_follow_the_fallback_contract() {
    let idx256 = |t: Theme, s: Slot| escape_for(t, s, false, ColorCapability::Color256);
    let sgr16 = |t: Theme, s: Slot| escape_for(t, s, false, ColorCapability::Color16);

    // Nearest-cube brand/ok (hue must read true):
    // cafe: caramel brand 173 (215,135,95), pistachio ok 150.
    assert_eq!(idx256(Theme::Cafe, Slot::Brand), "\x1b[38;5;173m");
    assert_eq!(idx256(Theme::Cafe, Slot::Ok), "\x1b[38;5;150m");
    // server: rack steel brand 68 (95,135,215), LED green ok 78.
    assert_eq!(idx256(Theme::Server, Slot::Brand), "\x1b[38;5;68m");
    assert_eq!(idx256(Theme::Server, Slot::Ok), "\x1b[38;5;78m");
    // moonlight: moonlit blue brand 152 (175,215,215), mist ok 151.
    assert_eq!(idx256(Theme::Moonlight, Slot::Brand), "\x1b[38;5;152m");
    assert_eq!(idx256(Theme::Moonlight, Slot::Ok), "\x1b[38;5;151m");
    // hacker: phosphor brand 83 (95,255,95), mint ok 43 (0,215,175).
    assert_eq!(idx256(Theme::Hacker, Slot::Brand), "\x1b[38;5;83m");
    assert_eq!(idx256(Theme::Hacker, Slot::Ok), "\x1b[38;5;43m");
    // depth_sea: bioluminescent teal brand 37 (0,175,175), kelp ok 78.
    assert_eq!(idx256(Theme::DepthSea, Slot::Brand), "\x1b[38;5;37m");
    assert_eq!(idx256(Theme::DepthSea, Slot::Ok), "\x1b[38;5;78m");

    // Warn/hot: the corner where the family holds, the rung where
    // the palette earns it. cafe's honey amber joins the khaki 221
    // (night_cyber's precedent); its burnt-sienna crown keeps the
    // pure red corner 196 (the hue family holds — 6 degrees).
    // server's amber LED takes its true 215 (255,175,95), the alarm
    // red its nearest 167 (215,95,95) — carbon's soft-red lineage one
    // rung darker. moonlight's pale gold and dusk rose ride their
    // nearest rungs 186/174 (a pale palette must not scream).
    // hacker's terminal yellow takes the saturated corner 220, its
    // pink-leaning alert red the 197 atomic precedent. depth_sea's
    // sand gold takes 185, its coral 203 (carbon's precedent).
    assert_eq!(idx256(Theme::Cafe, Slot::Warn), "\x1b[38;5;221m");
    assert_eq!(idx256(Theme::Cafe, Slot::Hot), "\x1b[38;5;196m");
    assert_eq!(idx256(Theme::Server, Slot::Warn), "\x1b[38;5;215m");
    assert_eq!(idx256(Theme::Server, Slot::Hot), "\x1b[38;5;167m");
    assert_eq!(idx256(Theme::Moonlight, Slot::Warn), "\x1b[38;5;186m");
    assert_eq!(idx256(Theme::Moonlight, Slot::Hot), "\x1b[38;5;174m");
    assert_eq!(idx256(Theme::Hacker, Slot::Warn), "\x1b[38;5;220m");
    assert_eq!(idx256(Theme::Hacker, Slot::Hot), "\x1b[38;5;197m");
    assert_eq!(idx256(Theme::DepthSea, Slot::Warn), "\x1b[38;5;185m");
    assert_eq!(idx256(Theme::DepthSea, Slot::Hot), "\x1b[38;5;203m");

    // 16-color picks: the brand takes a bright slot where the
    // identity must outrank data (cafe 93, server 94, moonlight 94,
    // hacker 92); depth_sea's cyan brand needs no bright escape
    // (its ok is green, no collision). All five stay pairwise
    // distinct per the standing walk below.
    assert_eq!(sgr16(Theme::Cafe, Slot::Brand), "\x1b[93m");
    assert_eq!(sgr16(Theme::Server, Slot::Brand), "\x1b[94m");
    assert_eq!(sgr16(Theme::Moonlight, Slot::Brand), "\x1b[94m");
    assert_eq!(sgr16(Theme::Hacker, Slot::Brand), "\x1b[92m");
    assert_eq!(sgr16(Theme::DepthSea, Slot::Brand), "\x1b[36m");
}

// ── The terminal-following background (NIGHT-boost-26) ────────────────────

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
