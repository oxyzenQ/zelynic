// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The JSON error lane's parity pins and the version door
//! (night-cafe-1): the contract door reads the error AFTER the
//! enrichment chain (H1+H2), so the machine lane carries the prose
//! facts, and a verbatim -V/--version riding a missing-positional
//! death is a version request (F7). Split from ux_tests.rs at the
//! 600-LOC cap pressure — one theme, one file, the usage_tests
//! lineage.

use super::*;
use crate::cli::argv::version_requested_in_argv;
use clap::Parser;

// ── The JSON error lane's prose parity (night-cafe-1, H1+H2) ────────

/// The contract door reads the error AFTER the enrichment chain, so
/// the JSON tip carries the same facts the prose render does. The
/// retired-verb redirect rides: `snapshot`'s JSON tip names the
/// successor `status` (the prose lane's exact redirect), never clap's
/// raw fuzzy candidate.
#[test]
fn json_lane_carries_the_removed_verb_redirect() {
    use crate::cli::json_error::clap_parts;
    let mut err = Cli::try_parse_from(["zelynic", "snapshot"]).expect_err("must fail");
    let mut cmd = Cli::command();
    let argv: Vec<std::ffi::OsString> = vec!["zelynic".into(), "snapshot".into()];
    enrich_error(&mut err, &mut cmd, &argv);
    let (_message, tip) = clap_parts(&err);
    assert_eq!(
        tip, "a similar subcommand exists: 'status'",
        "the JSON tip names the redirect successor, got: '{tip}'"
    );
}

/// The hidden-vocabulary filter runs before the JSON door: the probe
/// pair never surfaces as machine-readable tips — the same leak class
/// hunt-Z9 closed on the prose lane, closed here on the machine lane.
#[test]
fn json_lane_never_leaks_the_hidden_probe_pair() {
    use crate::cli::json_error::clap_parts;
    let mut err = Cli::try_parse_from(["zelynic", "__probe-serve"]).expect_err("must fail");
    let mut cmd = Cli::command();
    let argv: Vec<std::ffi::OsString> = vec!["zelynic".into(), "__probe-serve".into()];
    enrich_error(&mut err, &mut cmd, &argv);
    let (_message, tip) = clap_parts(&err);
    assert_eq!(
        tip, "",
        "the filter leaves the honest dead end, got: '{tip}'"
    );
}

/// The flag rescues ride the JSON lane too: `--print-json --verbos`
/// names `--verbose`, the same tip the prose lane renders (C08 vs
/// D29 parity).
#[test]
fn json_lane_carries_the_flag_rescue() {
    use crate::cli::json_error::clap_parts;
    let mut err = Cli::try_parse_from(["zelynic", "--verbos", "doctor"]).expect_err("must fail");
    let mut cmd = Cli::command();
    let argv: Vec<std::ffi::OsString> = vec!["zelynic".into(), "--verbos".into(), "doctor".into()];
    enrich_error(&mut err, &mut cmd, &argv);
    let (message, tip) = clap_parts(&err);
    assert_eq!(message, "unexpected argument '--verbos' found");
    assert!(
        tip.contains("--verbose"),
        "the JSON tip carries the rescue, got: '{tip}'"
    );
}

// ── The version door (night-cafe-1, F7) ─────────────────────────────

/// `-V`/`--version` parse at every level (the global flag's own doc),
/// but a verb with required positionals died MissingRequiredArgument
/// before main could read the field — `zelynic s -V` rendered a usage
/// error naming a --version flag the verb never declares. The door's
/// predicate: the missing-positional kind AND the verbatim token
/// before any `--`.
#[test]
fn version_door_fires_on_verbatim_tokens_at_required_positionals() {
    use clap::Parser;
    let mk = |argv: &[&str]| {
        let err = Cli::try_parse_from(argv).expect_err("must fail");
        let owned: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
        version_requested_in_argv(&err, &owned)
    };
    assert!(
        mk(&["zelynic", "s", "-V"]),
        "the A10 shape is a version request"
    );
    assert!(
        mk(&["zelynic", "strict", "--version"]),
        "the long spelling rides the same door"
    );
    assert!(
        mk(&["zelynic", "-V", "strict"]),
        "the token before the verb is still a request"
    );
    assert!(
        !mk(&["zelynic", "s", "brave", "550kb", "--", "-V"]),
        "an escaped -V is a VALUE — the escape hatch owns that lane"
    );
    assert!(
        !mk(&["zelynic", "strict"]),
        "a missing positional without the token stays a usage error"
    );
    // The wrong error kind never fires the door: an unknown flag with
    // -V elsewhere is a typo death, not a request.
    assert!(!mk(&["zelynic", "--verbos", "-V"]));
}
