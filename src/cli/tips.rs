// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI value-suggestion tips — the rate/duration typo rescue engine.
//!
//! Split out of `cli/ux.rs` at NIGHT-blade-4 (the retired-`--info`
//! vocabulary entry pushed that file past the 500-LOC cap; the same
//! cap-pressure split that gave `cli/styles.rs` to `cli/mod.rs` at
//! NIGHT-master-1). The section moved verbatim — the tip LINE format,
//! the two rescue rules, and the fractional-aware split are the
//! ux_tests-pinned contract, unchanged.
//!
//! Owns the value-side suggestions (rates and durations); the
//! flag-side suggestion machinery (Jaro flag matching, the rescue
//! tables) stays in `cli/ux.rs` and `cli/suggestion.rs`. The engine
//! core (`edit_distance`, `closest_value_match`) lives in
//! `cli/suggestion.rs` and is shared by both families.

// Every tip below is ebpf-gated (the value grammar lives in the
// limiter), so the engine import rides the same gate — a featureless
// build compiles this module empty.
#[cfg(feature = "ebpf")]
use crate::cli::suggestion::closest_value_match;

/// Canonical value-suggestion tip line.
///
/// `  tip: a similar value exists: '<value>'` — the same wording clap
/// uses for its built-in ValueEnum suggestions, so the custom engine
/// and clap's engine render identically. The leading `\n` + two-space
/// indent matches clap's tip composition; the line-aware labeled
/// renderer paints it white.
#[cfg(feature = "ebpf")]
pub(crate) fn value_tip(suggestion: &str) -> String {
    format!("\n  tip: a similar value exists: '{suggestion}'")
}

/// Suggest a corrected rate string for a rejected rate input.
///
/// Two rescue rules, cheapest first:
/// 1. Exact lowercase twin — `1MB` parses fine as `1mb` (the units are
///    lowercase-only by contract, and uppercase is the classic typo).
/// 2. Near-miss unit suffix — the numeric prefix is valid and the unit
///    suffix is within edit distance 2 of a real unit (`1kib` -> `1kb`,
///    `10mbps` -> `10mb`).
///
/// NIGHT-boost-15: the numeric prefix includes the decimal point —
/// the rate grammar is fractional now, so `5.5xb` must suggest
/// `5.5kb`, not slice the number at the dot and suggest nonsense.
#[cfg(feature = "ebpf")]
pub(crate) fn rate_tip(input: &str) -> Option<String> {
    // Multi-char units first: on an edit-distance tie, `1xb` should
    // suggest `1kb` (the common fat-finger), not `1b`.
    const UNITS: [&str; 5] = ["kb", "mb", "gb", "tb", "b"];
    let trimmed = input.trim();

    let lower = trimmed.to_ascii_lowercase();
    if lower != trimmed && crate::ebpf::limiter::parse_rate(&lower).is_ok() {
        return Some(value_tip(&lower));
    }

    // Split into numeric prefix + unit suffix at the first character
    // that is neither a digit nor a decimal point (NIGHT-boost-15:
    // the rate value grammar is fractional; NIGHT-hunt-31 extended
    // the same to durations, so both tips split identically).
    let i = trimmed.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (prefix, suffix) = (&trimmed[..i], &trimmed[i..]);
    if prefix.is_empty() || suffix.is_empty() {
        return None;
    }
    let unit = closest_value_match(suffix, &UNITS)?;
    if unit == suffix.to_ascii_lowercase() {
        return None; // already a valid unit — the number itself is bad
    }
    let fixed = format!("{prefix}{unit}");
    if crate::ebpf::limiter::parse_rate(&fixed).is_ok() {
        Some(value_tip(&fixed))
    } else {
        None
    }
}

/// Suggest a corrected duration string for a rejected duration input
/// (`3min` -> `3m`, `10sec` -> `10s`, `5.5min` -> `5.5m`, uppercase
/// twins) — the fractional-aware split (NIGHT-hunt-31) keeps the
/// number whole while the unit gets its near-miss match.
#[cfg(feature = "ebpf")]
pub(crate) fn duration_tip(input: &str) -> Option<String> {
    const UNITS: [&str; 3] = ["s", "m", "h"];
    let trimmed = input.trim();

    let lower = trimmed.to_ascii_lowercase();
    if lower != trimmed && crate::ebpf::limiter::parse_time_duration(&lower).is_ok() {
        return Some(value_tip(&lower));
    }

    let i = trimmed.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (prefix, suffix) = (&trimmed[..i], &trimmed[i..]);
    if prefix.is_empty() || suffix.is_empty() {
        return None;
    }
    let unit = closest_value_match(suffix, &UNITS)?;
    if unit == suffix.to_ascii_lowercase() {
        return None;
    }
    let fixed = format!("{prefix}{unit}");
    if crate::ebpf::limiter::parse_time_duration(&fixed).is_ok() {
        Some(value_tip(&fixed))
    } else {
        None
    }
}
