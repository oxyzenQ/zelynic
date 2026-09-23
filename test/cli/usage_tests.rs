// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Usage-line pins: subcommand-scoped usage (NIGHT-boost-13) — an
//! error inside a subcommand shows that subcommand's grammar, the
//! narrowed usage regenerates from the failing command, and a
//! top-level death keeps the top-level line. Split from ux_tests.rs
//! when the usage pins pushed it past the 500-LOC cap (one file per
//! contract, the same #[path] discipline as diff_tests/guard_tests);
//! shares the ux module-level `render_via_bridge` harness.

use super::*;

// ── Subcommand-scoped usage (NIGHT-boost-13) ──────────────────────

/// The owner's dead ends: an error inside a subcommand must show that
/// subcommand's usage line — the exact grammar of the command that
/// failed — not the top-level line that says nothing about it. This
/// is what turns the `-- -x` and extra-positional dead ends
/// self-explanatory: the usage names the two slots and nothing more
/// fits.
#[test]
fn subcommand_errors_show_the_subcommand_usage() {
    for argv in [
        vec!["zelynic", "-v", "ss", "brave", "550kb", "-i"],
        vec!["zelynic", "ss", "brave", "550kb", "--", "-x"],
        vec!["zelynic", "ss", "brave", "550kb", "extra"],
        vec!["zelynic", "ss", "brave", "550kb", "-h"],
    ] {
        let rendered = render_via_bridge(&argv);
        assert!(
            rendered.contains("Usage: zelynic strict-single [OPTIONS] <TARGET> [RATE]"),
            "an error inside ss must show the strict-single usage for {argv:?}, got:\n{rendered}"
        );
    }
}

/// A missing required positional keeps its native subcommand usage
/// too — clap already renders the failing command's line there.
#[test]
fn missing_positional_keeps_the_subcommand_usage() {
    let rendered = render_via_bridge(&["zelynic", "unstrict"]);
    assert!(
        rendered.contains("Usage: zelynic unstrict-single <TARGET>"),
        "the native unstrict-single usage must stay, got:\n{rendered}"
    );
}

/// A clap-suggested typo narrows the native usage (the suggested
/// flag renders as if required); the regenerated line must be the
/// FAILING subcommand's full usage — same command, no narrowed flag.
#[test]
fn narrowed_usage_is_regenerated_from_the_failing_command() {
    let rendered = render_via_bridge(&["zelynic", "ss", "brave", "--downlod", "1mb"]);
    assert!(
        rendered.contains("'--download'"),
        "clap's own suggestion must survive, got:\n{rendered}"
    );
    assert!(
        rendered.contains("Usage: zelynic strict-single [OPTIONS] <TARGET> [RATE]"),
        "the narrowed usage must regenerate as the full strict-single line, got:\n{rendered}"
    );
}

/// The walk must not misattribute a top-level death to a subcommand
/// that appears AFTER the failing token: `zelynic --verbos doctor`
/// died at `--verbos` and never reached `doctor` — the top-level
/// usage is the right usage there.
#[test]
fn top_level_errors_keep_the_top_level_usage() {
    for argv in [
        vec!["zelynic", "--verbos", "doctor"],
        vec!["zelynic", "--json", "status"],
        vec!["zelynic", "-Q"],
    ] {
        let rendered = render_via_bridge(&argv);
        assert!(
            rendered.contains("Usage: zelynic [OPTIONS] [COMMAND]"),
            "a top-level death keeps the top-level usage for {argv:?}, got:\n{rendered}"
        );
    }
}
