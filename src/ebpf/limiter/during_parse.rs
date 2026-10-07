// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The --during grammar family (night-during, schema v23; the
//! owner's duration-only revision — the parse.rs discipline one
//! feature over): one flag, ONE shape, PURE so the whole family
//! is rootless-pinned in test/ebpf/limiter/during_user_tests.rs.
//! The parse never reads a clock (a duration needs no wall); the
//! translation and the map plumbing live in the during siblings.
//! The grammar (the owner's revision of the design brief's
//! section 8 record):
//!
//!   --during 2h / 20d      a duration from apply: s m h d mn y,
//!                           1s floor, 10y ceiling, one value one
//!                           unit; months are 30 days and years
//!                           365 — the fixed-calendar translation a
//!                           daemonless CLI can make with no tzdata
//!                           engine, stated as the contract, not
//!                           hidden
//!
//! THE SHAPES THAT ARE GONE (the owner's call, the simplicity
//! ask): `09:00-17:00` (the recurring daily window) and
//! `2026-10-15` (the whole UTC day) are refused at parse time,
//! the wording naming the shape that replaced them. The
//! DuringSpec variants that carried them are NOT gone: the
//! RESTORE lane still re-translates both out of a state file's
//! wall form (a row an older build promised keeps its promise),
//! so the enum stays the restore family's vocabulary — only the
//! FLAG can no longer create them.

use anyhow::{anyhow, bail, Result};

// ━━ The grammar ━━

/// Duration floor: 1 second (the owner's grammar bound).
pub const DURING_MIN_NS: u64 = 1_000_000_000;

/// Duration ceiling: 10 years (the owner's grammar bound) — ten
/// fixed 365-day years, the same calendar the units below use.
pub const DURING_MAX_NS: u64 = 10 * 365 * 86_400 * 1_000_000_000;

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;
pub(super) const NS_PER_DAY: u64 = 86_400 * NS_PER_SEC;

/// One parsed --during argument. The parse is PURE (no clock read)
/// and yields ONLY the duration shape — the flag's one shape since
/// the owner's duration-only revision. The restore lane's
/// Span/Daily re-translation vocabulary went with the snapshot
/// pair when NIGHT-improve-55 retired the feature whole (the
/// legacy span/daily MAP rows an older build pinned are honored at
/// the window_active/window_state level, never re-translated
/// through this enum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuringSpec {
    /// `--during 2h` — from the apply instant; translated to a span
    /// at write time. The flag's only shape (the owner's
    /// duration-only revision).
    Duration { ns: u64 },
}

/// The grammar error's did-you-mean block, shared by every parse
/// family so one spelling teaches the whole flag (pure, pinned).
fn grammar_help() -> &'static str {
    "the --during grammar is: <N><unit> — a duration from the apply instant \
     (units s, m, h, d, mn, y; bounds 1s..10y)"
}

/// Parse one --during argument. Pure (no clock read — a duration
/// needs no wall); every family's refusal carries the grammar
/// block. The removed shapes refuse with the wording that names
/// what replaced them, on the same character disambiguation the
/// three-shape grammar rode: ':' selects the removed window
/// family, '-' without ':' the removed date family, and anything
/// else the duration parse.
pub fn parse_during(spec: &str) -> Result<DuringSpec> {
    let s = spec.trim();
    if s.is_empty() {
        bail!(
            "Invalid --during '' (empty): {}\n  tip: months are 'mn' — 'm' is minutes",
            grammar_help()
        );
    }
    if s.contains(':') {
        bail!(
            "Invalid --during '{s}': the window form (HH:MM-HH:MM) is gone — \
             --during takes a duration from the apply instant (2h, 20d, 6mn)\n  tip: {}",
            grammar_help()
        );
    }
    if s.contains('-') {
        bail!(
            "Invalid --during '{s}': the date form (YYYY-MM-DD) is gone — \
             --during takes a duration from the apply instant (2h, 20d, 6mn)\n  tip: {}",
            grammar_help()
        );
    }
    parse_duration(s)
}

/// `2h` / `20d` / `6mn` / `45s` / `10y` — one value, one unit,
/// bounds 1s..10y. `mn` is checked before `m` (month vs minute);
/// combined units (`1h30m`) are refused — the grammar stays one
/// token wide, the masterclass simplicity the owner asked for.
/// The flag's only shape.
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

/// The inverse: civil date for days since epoch (Hinnant's
/// civil_from_days). Pure, pinned on the known instants the
/// wall-clock renderer's own pins carry; pub(super) because the
/// during sibling's wall-clock renderer shares it.
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
