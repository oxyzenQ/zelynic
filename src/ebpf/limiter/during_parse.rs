// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The --during grammar family (night-during, schema v23 — the
//! parse.rs discipline one feature over): one flag, three shapes,
//! UTC everywhere, PURE so the whole family is rootless-pinned in
//! test/ebpf/limiter/during_user_tests.rs. The past-date refusal
//! takes the wall clock as a parameter (the parse never reads a
//! clock itself); the translation and the map plumbing live in the
//! during sibling. The grammar (the owner decision, the design
//! brief section 8 record):
//!
//!   --during 09:00-17:00   a recurring daily window, wrapping
//!                           midnight (22:00-06:00 is the bedtime
//!                           shape) — seconds-of-day
//!   --during 2026-10-15    the whole named UTC day: the row
//!                           sleeps until it arrives, expires at
//!                           00:00 the next day; a fully-past date
//!                           is refused at parse time
//!   --during 2h / 20d      a duration from apply: s m h d mn y,
//!                           1s floor, 10y ceiling, one value one
//!                           unit; months are 30 days and years
//!                           365 — the fixed-calendar translation a
//!                           daemonless CLI can make with no tzdata
//!                           engine, stated as the contract, not
//!                           hidden

use anyhow::{anyhow, bail, Result};

// ━━ The grammar ━━

/// Duration floor: 1 second (the owner's grammar bound).
pub const DURING_MIN_NS: u64 = 1_000_000_000;

/// Duration ceiling: 10 years (the owner's grammar bound) — ten
/// fixed 365-day years, the same calendar the units below use.
pub const DURING_MAX_NS: u64 = 10 * 365 * 86_400 * 1_000_000_000;

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;
pub(super) const NS_PER_DAY: u64 = 86_400 * NS_PER_SEC;

/// One parsed --during argument. The parse is PURE (the past-date
/// refusal takes the wall clock as a parameter) so the whole
/// grammar family is rootless-pinned in during_user_tests.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuringSpec {
    /// `--during 09:00-17:00` — seconds-of-day UTC, wrapping
    /// midnight when start > end.
    Daily { start_s: u32, end_s: u32 },
    /// `--during 2026-10-15` — the whole UTC day, as an absolute
    /// wall span [start, end).
    Span {
        start_wall_ns: u64,
        end_wall_ns: u64,
    },
    /// `--during 2h` — from the apply instant; translated to a span
    /// at write time.
    Duration { ns: u64 },
}

/// The grammar error's did-you-mean block, shared by every parse
/// family so one spelling teaches the whole flag (pure, pinned).
fn grammar_help() -> &'static str {
    "the --during grammar is: HH:MM-HH:MM (UTC daily window, may wrap midnight), \
     YYYY-MM-DD (whole UTC day), or <N><unit> (s, m, h, d, mn, y; 1s..10y)"
}

/// Parse one --during argument against the wall clock `wall_now_ns`
/// (the past-date refusal needs it). Pure; every family's refusal
/// carries the grammar block.
pub fn parse_during(spec: &str, wall_now_ns: u64) -> Result<DuringSpec> {
    let s = spec.trim();
    if s.is_empty() {
        bail!(
            "Invalid --during '' (empty): {}\n  tip: months are 'mn' — 'm' is minutes",
            grammar_help()
        );
    }
    // Shape disambiguation on characters alone (the design brief
    // section 8 law): ':' selects the window family, '-' without
    // ':' the date family, digits-then-letters the duration.
    if s.contains(':') {
        parse_daily_window(s)
    } else if s.contains('-') {
        parse_date_day(s, wall_now_ns)
    } else {
        parse_duration(s)
    }
}

/// `09:00-17:00` — both edges HH:MM (UTC), equal edges refused (a
/// zero-width window is a user error, never "all day").
fn parse_daily_window(s: &str) -> Result<DuringSpec> {
    let (start, end) = match s.split_once('-') {
        Some(pair) => pair,
        None => bail!(
            "Invalid --during '{s}': {}\n  tip: the window form is two HH:MM edges joined by '-'",
            grammar_help()
        ),
    };
    let start_s = parse_hhmm(start)
        .map_err(|e| anyhow!("Invalid --during '{s}': {e}\n  tip: {}", grammar_help()))?;
    let end_s = parse_hhmm(end)
        .map_err(|e| anyhow!("Invalid --during '{s}': {e}\n  tip: {}", grammar_help()))?;
    if start_s == end_s {
        bail!(
            "Invalid --during '{s}': a zero-width window (equal edges) is never active — \
             name two different edges; '00:00-24:00' spelling is not in the grammar \
             (use 00:00-23:59 for the whole day minus its last second)\n  tip: {}",
            grammar_help()
        );
    }
    Ok(DuringSpec::Daily { start_s, end_s })
}

/// `HH:MM` to seconds-of-day; the parse family's own error carries
/// the value it refused.
fn parse_hhmm(edge: &str) -> Result<u32> {
    let (hh, mm) = edge
        .split_once(':')
        .ok_or_else(|| anyhow!("'{edge}' is not an HH:MM edge"))?;
    if hh.len() != 2
        || mm.len() != 2
        || !hh.bytes().all(|b| b.is_ascii_digit())
        || !mm.bytes().all(|b| b.is_ascii_digit())
    {
        bail!("'{edge}' is not an HH:MM edge (two digits, a colon, two digits)");
    }
    let h: u32 = hh
        .parse()
        .map_err(|_| anyhow!("'{edge}' hour is not a number"))?;
    let m: u32 = mm
        .parse()
        .map_err(|_| anyhow!("'{edge}' minute is not a number"))?;
    if h > 23 || m > 59 {
        bail!("'{edge}' is outside the day (HH <= 23, MM <= 59)");
    }
    Ok(h * 3600 + m * 60)
}

/// `2026-10-15` — the whole named UTC day, [00:00, next 00:00).
/// A day whose end is at or before the wall now is already past
/// and refused (the honest one-shot: never apply a corpse).
fn parse_date_day(s: &str, wall_now_ns: u64) -> Result<DuringSpec> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3
        || parts[0].len() != 4
        || parts[1].len() != 2
        || parts[2].len() != 2
        || !parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
    {
        bail!(
            "Invalid --during '{s}': the date form is exactly YYYY-MM-DD (UTC)\n  tip: {}",
            grammar_help()
        );
    }
    let year: i64 = parts[0]
        .parse()
        .map_err(|_| anyhow!("Invalid --during '{s}': the year is not a number"))?;
    let month: u32 = parts[1]
        .parse()
        .map_err(|_| anyhow!("Invalid --during '{s}': the month is not a number"))?;
    let day: u32 = parts[2]
        .parse()
        .map_err(|_| anyhow!("Invalid --during '{s}': the day is not a number"))?;
    if !(1..=12).contains(&month) {
        bail!("Invalid --during '{s}': the month is outside 01..12");
    }
    let dim = days_in_month(year, month);
    if !(1..=dim).contains(&day) {
        bail!(
            "Invalid --during '{s}': day {day} is outside {month:02}/{year} \
             ({dim} days)"
        );
    }
    let start_days = days_from_civil(year, month, day);
    let end_days = start_days + 1;
    if start_days < 0 {
        bail!("Invalid --during '{s}': dates before 1970-01-01 are refused");
    }
    // The u128 belt: a four-digit year's ns can exceed u64 (year
    // 9999 is ~2.5e20), and the span math must never wrap — a date
    // whose day cannot be REPRESENTED is refused, not clamped (a
    // clamp would silently promise the wrong century).
    let start_wall = u128::from(start_days as u64) * u128::from(NS_PER_DAY);
    let end_wall = u128::from(end_days as u64) * u128::from(NS_PER_DAY);
    if end_wall > u128::from(u64::MAX) {
        bail!(
            "Invalid --during '{s}': the date is beyond the wall clock's range — \
             dates past the representable horizon are refused"
        );
    }
    let (start_wall, end_wall) = (start_wall as u64, end_wall as u64);
    if end_wall <= wall_now_ns {
        bail!(
            "Invalid --during '{s}': that day is already over (UTC) — a past \
             window would apply a corpse; the duration form ('2h') starts now"
        );
    }
    Ok(DuringSpec::Span {
        start_wall_ns: start_wall,
        end_wall_ns: end_wall,
    })
}

/// `2h` / `20d` / `6mn` / `45s` / `10y` — one value, one unit,
/// bounds 1s..10y. `mn` is checked before `m` (month vs minute);
/// combined units (`1h30m`) are refused — the grammar stays one
/// token wide, the masterclass simplicity the owner asked for.
fn parse_duration(s: &str) -> Result<DuringSpec> {
    let digits_len = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits_len == 0 || digits_len >= s.len() {
        let help = grammar_help();
        bail!(
            "Invalid --during '{s}': the duration form is a number then a unit \
             (2h, 20d, 6mn)\n  tip: {help}"
        );
    }
    let (num, unit) = s.split_at(digits_len);
    let value: u64 = num
        .parse()
        .map_err(|_| anyhow!("Invalid --during '{s}': the value is not a number"))?;
    let unit_ns: u64 = match unit {
        "s" => NS_PER_SEC,
        "m" => 60 * NS_PER_SEC,
        "h" => 3600 * NS_PER_SEC,
        "d" => NS_PER_DAY,
        "mn" => 30 * NS_PER_DAY,
        "y" => 365 * NS_PER_DAY,
        _ => {
            bail!(
                "Invalid --during '{s}': unit '{unit}' is not in the grammar \
                 (s, m, h, d, mn, y — months are 'mn', 'm' is minutes)\n  tip: {}",
                grammar_help()
            );
        }
    };
    let ns = value
        .checked_mul(unit_ns)
        .ok_or_else(|| anyhow!("Invalid --during '{s}': the duration overflows"))?;
    if ns < DURING_MIN_NS {
        bail!(
            "Invalid --during '{s}': the floor is 1s — a shorter promise \
             rounds to \"not limited\""
        );
    }
    if ns > DURING_MAX_NS {
        bail!(
            "Invalid --during '{s}': the ceiling is 10y — a longer promise \
             is a forever-limit wearing a date"
        );
    }
    Ok(DuringSpec::Duration { ns })
}

/// Fixed-calendar days in one month (leap years honored — the
/// grammar's dates are real calendar dates, only the DURATION
/// units use the fixed 30/365 translation).
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's
/// days_from_civil, the standard portable form). Pure, pinned by
/// round-trip against civil_from_days.
pub(super) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse: civil date for days since epoch (Hinnant's
/// civil_from_days). Pure, pinned by the round-trip; pub(super)
/// because the during sibling's wall-clock renderer shares it.
pub(super) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
