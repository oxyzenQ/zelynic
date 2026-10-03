// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-hunt-Z9: the shadowed-positional contract — a positional
//! rate beside -d/-u is parsed (never silently dropped) and named
//! (the ignored-input warn), while the -d/-u semantics decide what
//! applies. The parse side is pinned here pure; the warn itself is
//! a stderr side effect the live battery row observes end to end
//! (v4 stage: the shadowed-positional cases).

use crate::commands::rates::resolve_rates;

/// The old silent drop, refused: a garbage positional beside -d
/// errors with the typo tip BEFORE the root ask — the
/// parse-before-execute ladder the handlers document finally covers
/// this shape too (`ss brave not-a-rate -d 100kb` used to sail to
/// "root required" with the typo unexamined).
#[cfg(feature = "ebpf")]
#[test]
fn shadowed_garbage_positional_surfaces_its_typo() {
    let err = resolve_rates(Some("1MB"), Some("100kb"), None, false)
        .expect_err("a garbage positional must fail even when shadowed");
    let msg = format!("{err}");
    assert!(
        msg.contains("Invalid rate '1MB'"),
        "the shadowed typo must surface, got: {msg}"
    );
    assert!(
        msg.contains("tip: a similar value exists: '1mb'"),
        "the did-you-mean tip must ride along, got: {msg}"
    );
}

/// A VALID shadowed positional parses clean and applies nothing: the
/// -d/-u values decide the spec exactly as before (the warn is
/// stderr-only; stdout, the spec, and exit codes are untouched).
#[cfg(feature = "ebpf")]
#[test]
fn shadowed_valid_positional_resolves_to_the_flags() {
    let rates = resolve_rates(Some("100kb"), Some("50kb"), None, false)
        .expect("a valid shadowed positional must not fail");
    assert_eq!(rates.download, Some(50_000), "-d decides download");
    assert_eq!(rates.upload, None, "no -u means no upload limit");
}

/// Both direction flags plus a positional: the flags win both slots.
#[cfg(feature = "ebpf")]
#[test]
fn shadowed_positional_with_both_flags_resolves_to_both_flags() {
    let rates = resolve_rates(Some("1mb"), Some("50kb"), Some("500kb"), false)
        .expect("valid inputs must resolve");
    assert_eq!(rates.download, Some(50_000));
    assert_eq!(rates.upload, Some(500_000));
}

/// The unshadowed shapes are unchanged: a positional alone still
/// means BOTH directions (the documented priority rule's other half).
#[cfg(feature = "ebpf")]
#[test]
fn unshadowed_positional_still_means_both_directions() {
    let rates =
        resolve_rates(Some("100kb"), None, None, false).expect("a plain positional must resolve");
    assert_eq!(rates.download, Some(100_000));
    assert_eq!(rates.upload, Some(100_000));
}

/// Nothing specified: the empty spec the handlers refuse with their
/// own "No rate specified" verdict (unchanged).
#[cfg(feature = "ebpf")]
#[test]
fn no_rates_still_yields_the_empty_spec() {
    let rates = resolve_rates(None, None, None, false).expect("empty input resolves");
    assert_eq!(rates.download, None);
    assert_eq!(rates.upload, None);
}
