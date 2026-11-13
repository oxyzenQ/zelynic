// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The positional-overflow pins (the reaudit find): a bare word that
//! overflows eagle-eyes' single TARGETS slot teaches the
//! '/'-separated grammar at the death site, a bare word never
//! renders a flag suggestion, and the grammar tip stays keyed to
//! eagle-eyes. Wired as the ux_tests/usage_tests siblings were (the
//! 500-LOC cap split, one theme one file).

use super::*;

/// The overflow lane's own footer literal (the ux_tests const is that
/// module's; the one-footer law is re-pinned here for the new lane).
const HELP_FOOTER: &str = "For more information, try '--help'.";

/// `zelynic ee brave electron` died raw — clap has no voice for the
/// overflow, and the grammar that joins targets into one argument is
/// '/'-separated. Both spellings (the alias and the canonical name)
/// land on the same tip.
#[test]
fn positional_overflow_on_eagle_eyes_teaches_the_slash_grammar() {
    for argv in [
        vec!["zelynic", "ee", "brave", "electron"],
        vec!["zelynic", "eagle-eyes", "brave", "electron"],
    ] {
        let rendered = render_via_bridge(&argv);
        assert!(
            rendered.contains("tip: targets are ONE slash-separated argument"),
            "the overflow must teach the slash grammar for {argv:?}, got:\n{rendered}"
        );
        assert!(
            rendered.contains("zelynic eagle-eyes brave/electron"),
            "the tip must carry the copy-pasteable example, got:\n{rendered}"
        );
        assert_eq!(
            rendered.matches(HELP_FOOTER).count(),
            1,
            "exactly one help footer for {argv:?}, got:\n{rendered}"
        );
    }
}

/// A bare word is a target the user meant, never a flag typo — and
/// `deep` sits one jaro-step from `--depth`, so the flag rescues
/// suggesting it would be worse than no tip. The bare-word lane
/// belongs to the positional-overflow rescue alone.
#[test]
fn bare_word_overflow_never_suggests_a_flag() {
    let argv = vec!["zelynic", "ee", "brave", "deep"];
    let rendered = render_via_bridge(&argv);
    assert!(
        !rendered.contains("similar argument"),
        "a bare word must not render a flag suggestion, got:\n{rendered}"
    );
    assert!(
        rendered.contains("slash-separated"),
        "the slash grammar tip owns the lane, got:\n{rendered}"
    );
}

/// The grammar tip is keyed to the failing command: a bare-word
/// overflow on another command keeps its plain error — an honest
/// "unexpected argument" without a grammar that does not apply.
#[test]
fn positional_overflow_elsewhere_stays_plain() {
    let argv = vec!["zelynic", "status", "brave"];
    let rendered = render_via_bridge(&argv);
    assert!(
        !rendered.contains("slash-separated"),
        "non-eagle overflow must not teach the slash grammar, got:\n{rendered}"
    );
}

/// The dashed lane is untouched by the overflow rescue: an unknown
/// flag on eagle-eyes still rides the flag rescues (the closest-match
/// suggestion), and the escape-hatch honesty gate keeps its seat.
#[test]
fn dashed_flag_on_eagle_eyes_still_rides_the_flag_rescues() {
    let argv = vec!["zelynic", "ee", "brave", "--dept"];
    let rendered = render_via_bridge(&argv);
    assert!(
        rendered.contains("--depth"),
        "a near-miss flag must render its suggestion, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("slash-separated"),
        "the flag lane must not teach the target grammar, got:\n{rendered}"
    );
}
