// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Unit pins for the `--print-json` scope contract (NIGHT-boost-24),
//! kept in the repo's single test/ tree (cosmostrix Pattern C) and
//! #[path]-wired from cli/mod.rs. The contract has two halves that
//! must agree: the NOTE a user reads on stderr when the flag is
//! ignored, and the CLASSIFICATION the dispatcher consults. A surface
//! named in the note must honor the flag, and a surface that honors
//! the flag must never trigger the note — this file pins both
//! directions so the two tables cannot drift apart.

use super::{command_honors_print_json, print_json_ignored_note, Commands};

/// The note's exact shape: the flag name, the word "ignored", the
/// parenthesized surface list. A script owner reads this line once
/// and trusts it, so the wording is pinned as literal text.
#[test]
fn ignored_note_names_the_contract() {
    let note = print_json_ignored_note();
    assert!(
        note.starts_with("--print-json ignored (JSON surface: "),
        "the note must lead with the flag and the verdict, got: {note}"
    );
    assert!(
        note.ends_with(')'),
        "the surface list closes the note, got: {note}"
    );
    // The honoring set is per-build; this suite runs both shapes, so
    // the pin is the shape, and doctor — the always-compiled report —
    // must be present in every build's list.
    assert!(
        note.contains("doctor"),
        "doctor honors the flag in every build, got: {note}"
    );
}

/// Every surface the note names must classify as honoring — and the
/// converse must hold for a representative text surface of each class:
/// the no-subcommand help fallback, an enforcement verb, and the live
/// monitor. If a new report command joins the surface set, adding it
/// to JSON_SURFACE_COMMANDS without the classification (or vice
/// versa) fails here.
#[test]
fn note_and_classification_agree_both_ways() {
    let note = print_json_ignored_note();
    let listed = note
        .trim_start_matches("--print-json ignored (JSON surface: ")
        .trim_end_matches(')');
    assert!(!listed.is_empty(), "the surface list cannot be empty");

    for surface in listed.split(", ") {
        let honors = match surface {
            "status" => command_honors_print_json(Some(&Commands::Status)),
            "list-apps" => command_honors_print_json(Some(&Commands::ListApps)),
            "doctor" => command_honors_print_json(Some(&Commands::Doctor)),
            other => panic!("unknown surface named in the note: {other}"),
        };
        assert!(
            honors,
            "the note names '{surface}', so it must honor the flag"
        );
    }

    // The text surfaces: help fallback, enforcement, monitor.
    assert!(
        !command_honors_print_json(None),
        "the no-subcommand help fallback renders text"
    );
    assert!(
        !command_honors_print_json(Some(&Commands::Recover)),
        "recover renders text"
    );
    assert!(
        !command_honors_print_json(Some(&Commands::EagleEyes {
            targets: None,
            interval: None
        })),
        "the live monitor renders a TUI, not a JSON document"
    );
}

/// The enforcement verbs parse `--print-json` (it is global) and then
/// ignore it — the classification must say false for a strict-family
/// representative, the exact surface class the owner audited.
#[test]
fn enforcement_verbs_do_not_honor_the_flag() {
    let strict = Commands::StrictSingle {
        target: "brave".to_string(),
        rate: None,
        download: None,
        upload: None,
        allow_dangerous: false,
        force: false,
    };
    assert!(
        !command_honors_print_json(Some(&strict)),
        "strict-single renders its branded text report"
    );
}
