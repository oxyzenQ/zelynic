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

// ── The zero refusal on the limit verb (night-peak-lts FIX-2) ─────────
//
// `validate_rate` deliberately lets 0 pass (the BPF schema's BLOCK
// verdict), and the `block` verb writes that shape directly. The
// LIMIT verb must not reach it silently: `s brave 0kb` used to
// apply a full block under the strict surface, past the docs' own
// 1kb minimum. These pins hold the refusal, the pointer to the verb
// that owns the intent, and the --force-this escape hatch.

#[cfg(feature = "ebpf")]
#[test]
fn strict_zero_rate_is_refused_with_the_block_pointer() {
    let err = resolve_rates(Some("0kb"), None, None, false)
        .expect_err("0kb on the limit verb must be refused without the override");
    let msg = format!("{err}");
    assert!(
        msg.contains("rate must be at least 1kb (1000 B/s)"),
        "the minimum must be named, got: {msg}"
    );
    assert!(
        msg.contains("use 'zelynic block <target>'"),
        "the block intent must be pointed at its own verb, got: {msg}"
    );
}

#[cfg(feature = "ebpf")]
#[test]
fn strict_bare_zero_and_fractional_zero_are_refused_too() {
    for shape in ["0", "0b", "0.0kb"] {
        let err = resolve_rates(Some(shape), None, None, false)
            .expect_err("every zero spelling must be refused on the limit verb");
        let msg = format!("{err}");
        // Two refusal classes, both honest: the plain-zero shapes hit
        // the limit-verb refusal (the block pointer), a fractional
        // zero like 0.0kb is caught earlier by the parser's own
        // rounds-to-zero guard (pass '0' if you mean block). Either
        // way nothing silently applies.
        assert!(
            msg.contains("rate must be at least 1kb") || msg.contains("rounds to zero bytes/s"),
            "{shape} must be refused, got: {msg}"
        );
    }
}

#[cfg(feature = "ebpf")]
#[test]
fn force_this_keeps_zero_as_the_documented_escape_hatch() {
    let rates = resolve_rates(Some("0kb"), None, None, true)
        .expect("--force-this is the yes-really-zero hatch the docs pin");
    assert_eq!(rates.download, Some(0));
    assert_eq!(rates.upload, Some(0));
}

#[cfg(feature = "ebpf")]
#[test]
fn per_direction_zero_is_refused_on_both_flags() {
    let err = resolve_rates(None, Some("0kb"), None, false)
        .expect_err("-d 0kb must hit the same refusal");
    assert!(format!("{err}").contains("use 'zelynic block <target>'"));

    let err = resolve_rates(None, None, Some("0kb"), false)
        .expect_err("-u 0kb must hit the same refusal");
    assert!(format!("{err}").contains("use 'zelynic block <target>'"));

    let rates = resolve_rates(None, Some("0kb"), Some("0kb"), true)
        .expect("--force-this covers the per-direction hatch too");
    assert_eq!(rates.download, Some(0));
    assert_eq!(rates.upload, Some(0));
}
