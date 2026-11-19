// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The reproducible build-stamp helpers (the pure move out of
//! build.rs: the LOC cap's no-mercy era caught the D4 digest-stamp
//! growth, and the stamp family is the coherent unit — the wall-clock
//! fallback, the SOURCE_DATE_EPOCH pin's acceptance rule, and the
//! minute-precision formatter with their standalone test suite).

/// The build-time stamp: `SOURCE_DATE_EPOCH`-derived when the build
/// environment pins it, the wall clock when it does not.
pub(crate) fn format_build_time_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // night-depth-hardening-Z1 (the D4 reproducible-release chain): the
    // stamp must be a function of the build INPUTS, never the wall
    // clock. When the build environment pins SOURCE_DATE_EPOCH (the
    // reproducible-builds.org standard: seconds since the Unix epoch),
    // the stamp derives from the pin — two hosts building the same
    // commit with the same pin stamp identically, and the binaries are
    // byte-identical (the stamp rides the -V report and the depth
    // matrix's masked words, so one drifting second poisons every
    // provenance layer). The value is derived from the commit being
    // built (`git log -1 --format=%ct`) by the release lane and by the
    // two-host verification lane that cmp-proves the equality
    // (.github/workflows/reproducible.yml). Unset or malformed pins
    // fall back to the wall clock: a dev build keeps its honest
    // freshness stamp, and a malformed pin degrades to the old
    // behavior instead of breaking the build — the stamp is
    // provenance, never a correctness input.
    if let Some(total_secs) = pinned_epoch_secs(std::env::var("SOURCE_DATE_EPOCH").ok().as_deref())
    {
        return format_unix_secs_as_build_time(total_secs);
    }

    let Ok(secs) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unknown".to_string();
    };
    let total_secs: i64 = i64::try_from(secs.as_secs()).unwrap_or(0);
    format_unix_secs_as_build_time(total_secs)
}

/// night-depth-hardening-Z1: parse the SOURCE_DATE_EPOCH pin value —
/// whitespace-trimmed, strict i64, no other leniency. Split out of
/// [`format_build_time_utc`] so the acceptance rule is unit-testable
/// without touching process state (this suite runs standalone via
/// `rustc --test build.rs`, and `std::env::set_var` is unsafe in
/// edition 2024 — the pure-function split keeps the suite unsafe-free
/// against the LTS-14 gate).
fn pinned_epoch_secs(value: Option<&str>) -> Option<i64> {
    value.and_then(|v| v.trim().parse::<i64>().ok())
}

/// Pure formatting function — takes unix-epoch seconds and returns
/// `YYYY-MM-DD HH:MMZ` (ISO 8601, UTC; night-pro-1 aligns the stamp
/// with the flagship's format, replacing the US-ambiguous
/// `M/D/YYYY HH:MM (UTC)` shape). Separated from `format_build_time_utc` so
/// the algorithm is unit-testable without depending on the wall clock.
///
/// Algorithm: split `total_secs` into days + seconds-of-day, then use
/// Howard Hinnant's `civil_from_days` algorithm
/// (http://howardhinnant.github.io/date_algorithms.html) to convert
/// days-since-epoch to (year, month, day). All arithmetic is on `i64`
/// to avoid unsigned-underflow issues when subtracting the 719468-day
/// shift constant.
fn format_unix_secs_as_build_time(total_secs: i64) -> String {
    let days_since_epoch = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;

    // Howard Hinnant's civil_from_days: converts days-since-1970-01-01
    // to (year, month, day) in the proleptic Gregorian calendar.
    // http://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_date_epoch_pin_parses_strict_and_trimmed() {
        // night-depth-hardening-Z1: the pin acceptance rule. Strict i64
        // after whitespace trim — a malformed pin must fall back to the
        // wall clock (never panic, never half-parse).
        assert_eq!(pinned_epoch_secs(Some("1709210040")), Some(1_709_210_040));
        // Whitespace tolerance: shell exports can carry a trailing
        // newline; the stamp contract is minute-precision, not bytes.
        assert_eq!(
            pinned_epoch_secs(Some(" 1709210040\n")),
            Some(1_709_210_040)
        );
        assert_eq!(pinned_epoch_secs(Some("garbage")), None);
        assert_eq!(pinned_epoch_secs(Some("")), None);
        assert_eq!(pinned_epoch_secs(None), None);
        // Pre-epoch pins are valid timestamps too (the formatter owns
        // the proleptic-Gregorian handling, pinned by its own test).
        assert_eq!(pinned_epoch_secs(Some("-60")), Some(-60));
    }

    #[test]
    fn build_time_format_matches_known_unix_epochs() {
        // All constants verified against `date -u -d @<epoch>` (not from
        // memory): the cosmostrix reference build.rs carried two wrong
        // constants here (1_709_210_440 asserted as "12:34" but is
        // 12:40:40; 1_787_930_200 asserted as "8/4 15:30" but is
        // 8/28 15:16:40) — latent because `cargo test` never executes
        // build-script tests. This suite runs standalone via
        // `rustc --edition 2024 --test build.rs` (the crate's edition
        // since NIGHT-improve-67; preflight.rs's env-mutation test grew
        // the unsafe blocks the edition demands), so the constants must
        // be real ground truth.

        // UNIX epoch: 1970-01-01 00:00:00 UTC.
        assert_eq!(format_unix_secs_as_build_time(0), "1970-01-01 00:00Z");

        // 2000-01-01 00:00:00 UTC = 946_684_800 seconds since epoch.
        // Computed via: date -u -d '2000-01-01 00:00:00' +%s
        assert_eq!(
            format_unix_secs_as_build_time(946_684_800),
            "2000-01-01 00:00Z"
        );

        // 2024-02-29 12:34:00 UTC = 1_709_210_040 seconds since epoch.
        // Leap-day boundary check — Feb 29 must not roll to Mar 1.
        // Computed via: date -u -d '2024-02-29 12:34:00' +%s
        assert_eq!(
            format_unix_secs_as_build_time(1_709_210_040),
            "2024-02-29 12:34Z"
        );

        // 2026-08-04 15:30:00 UTC = 1_785_857_400 seconds since epoch.
        // Computed via: date -u -d '2026-08-04 15:30:00' +%s
        assert_eq!(
            format_unix_secs_as_build_time(1_785_857_400),
            "2026-08-04 15:30Z"
        );
    }

    #[test]
    fn build_time_format_truncates_sub_minute_seconds() {
        // 1_709_210_440 = 2024-02-29 12:40:40 UTC: the 40 sub-minute
        // seconds are dropped (minute precision, matching the cosmostrix
        // ISO 8601 `%Y-%m-%d %H:%M` Z-suffixed format contract), never
        // rounded up.
        assert_eq!(
            format_unix_secs_as_build_time(1_709_210_440),
            "2024-02-29 12:40Z"
        );
    }

    #[test]
    fn build_time_format_handles_negative_seconds_gracefully() {
        // Pre-epoch timestamps (negative seconds) should still produce
        // a valid proleptic Gregorian date via the algorithm's signed
        // arithmetic, not panic or underflow.
        // 1969-12-31 23:59:00 UTC = -60 seconds.
        let result = format_unix_secs_as_build_time(-60);
        assert!(
            result.ends_with('Z'),
            "negative-epoch result should still be Z-suffixed: {result}"
        );
        assert!(
            result.contains("1969"),
            "negative-epoch result should land in 1969: {result}"
        );
    }
}
