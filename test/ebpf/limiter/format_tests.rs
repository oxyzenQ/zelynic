// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Format-layer pins (rate/duration parsing, SI formatting) — moved
//! out of src/ebpf/limiter/format.rs by NIGHT-boost-15 when the
//! fractional rate layer pushed that file past the owner's 500-line
//! LOC cap. The #[path] wiring inside format.rs places this module
//! back inside the format module, so `use super::*` reaches the same
//! items the inline `mod tests` did — a pure move, zero behavioral
//! drift, the same Pattern C discipline as the limiter's math,
//! policy, and reclaim pins.

use super::*;

#[test]
fn test_parse_rate_plain_number() {
    assert_eq!(parse_rate("1000000").unwrap(), 1_000_000);
}

#[test]
fn test_parse_rate_kb() {
    assert_eq!(parse_rate("1kb").unwrap(), 1_000);
    assert_eq!(parse_rate("500kb").unwrap(), 500_000);
}

#[test]
fn test_parse_rate_mb() {
    assert_eq!(parse_rate("1mb").unwrap(), 1_000_000);
    assert_eq!(parse_rate("5mb").unwrap(), 5_000_000);
}

#[test]
fn test_parse_rate_gb() {
    assert_eq!(parse_rate("1gb").unwrap(), 1_000_000_000);
}

#[test]
fn test_parse_rate_bytes() {
    assert_eq!(parse_rate("500b").unwrap(), 500);
}

#[test]
fn test_parse_rate_rejects_uppercase() {
    assert!(parse_rate("1KB").is_err());
    assert!(parse_rate("1MB/s").is_err());
    assert!(parse_rate("1GB").is_err());
}

#[test]
fn test_parse_rate_uppercase_error_suggests_lowercase_twin() {
    // Flagship typo rescue: the error must carry a tip line pointing
    // at the lowercase twin (NIGHT-hunt-5).
    let err_msg = format!("{}", parse_rate("1MB").unwrap_err());
    assert!(
        err_msg.contains("tip: a similar value exists: '1mb'"),
        "error must suggest the lowercase twin, got: {err_msg}"
    );
}

#[test]
fn test_parse_rate_near_miss_unit_suggestion() {
    let err_msg = format!("{}", parse_rate("1kib").unwrap_err());
    assert!(
        err_msg.contains("tip: a similar value exists: '1kb'"),
        "error must suggest the near-miss unit, got: {err_msg}"
    );
}

#[test]
fn test_parse_rate_invalid() {
    assert!(parse_rate("abc").is_err());
    assert!(parse_rate("1xb").is_err());
    assert!(parse_rate("").is_err());
}

#[test]
fn test_parse_rate_overflow_detects_and_shows_input() {
    // 1e17 × 1000 = 1e20, overflows u64 (max ~1.8e19).
    // Must return Err, NOT saturate to u64::MAX.
    let result = parse_rate("100000000000000000kb");
    assert!(result.is_err());

    let err_msg = format!("{}", result.unwrap_err());
    // Error must show the original input, not the wrapped u64::MAX value.
    assert!(
        err_msg.contains("100000000000000000kb"),
        "error should show original input, got: {err_msg}"
    );
    // Must name the overflow plainly. The old message carried a
    // bogus "Maximum is 1gb" from a pre-100gb era and a misleading
    // "Warning:" prefix on a hard error (NIGHT-hunt-5).
    assert!(
        err_msg.contains("overflows 64-bit math"),
        "error should name the overflow, got: {err_msg}"
    );
    // Must NOT show the wrapped u64::MAX value.
    assert!(
        !err_msg.contains("18446744073709551615"),
        "error must not show u64::MAX wrapped value, got: {err_msg}"
    );
}

#[test]
fn test_parse_rate_max_gb_does_not_overflow() {
    // 1gb = 1e9, should parse fine.
    assert_eq!(parse_rate("1gb").unwrap(), 1_000_000_000);
    // 1000gb = 1e12, still fits u64.
    assert_eq!(parse_rate("1000gb").unwrap(), 1_000_000_000_000);
}

#[test]
fn test_parse_rate_tb_suffix_matches_new_ceiling() {
    // NIGHT-research-1 option B: the 1 TB/s ceiling is expressible
    // ergonomically; the old gb spelling parses identically.
    assert_eq!(parse_rate("1tb").unwrap(), 1_000_000_000_000);
    assert_eq!(parse_rate("500gb").unwrap(), 500_000_000_000);
    assert_eq!(parse_rate("1000gb").unwrap(), parse_rate("1tb").unwrap());
    assert!(validate_rate(parse_rate("1tb").unwrap()).is_ok());
}

#[test]
fn test_validate_rate_minimum() {
    assert!(validate_rate(512).is_err());
    assert!(validate_rate(1000).is_ok());
    assert!(validate_rate(1024).is_ok());
}

#[test]
fn test_validate_rate_minimum_harmonized_with_parser() {
    // NIGHT-hunt-5 harmonization: MIN_RATE is decimal SI (1000 B/s),
    // matching parse_rate where 1kb = 1000. The documented minimum
    // "1 KB/s" must accept the documented input "1kb" — before the
    // fix, MIN_RATE was 1024 and `strict-single brave 1kb` was
    // rejected as below-minimum, contradicting every doc.
    let rate = parse_rate("1kb").unwrap();
    assert_eq!(rate, 1000);
    assert!(validate_rate(rate).is_ok());
}

#[test]
fn test_validate_rate_maximum() {
    // Owner-approved option B (NIGHT-research-1): the ceiling is
    // 1 TB/s; 100 GB/s remains valid far below it.
    assert!(validate_rate(2_000_000_000_000).is_err());
    assert!(validate_rate(1_000_000_000_000).is_ok());
    assert!(validate_rate(200_000_000_000).is_ok());
    assert!(validate_rate(100_000_000_000).is_ok());
}

#[test]
fn test_default_burst_normal() {
    assert_eq!(default_burst(1_000_000), 1_000_000);
}

#[test]
fn test_default_burst_minimum() {
    assert_eq!(default_burst(100), 4096);
}

#[test]
fn test_default_burst_maximum() {
    assert_eq!(default_burst(1_000_000_000_000), 100_000_000);
}

#[test]
fn test_format_bytes_decimal_si() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(999), "999 B");
    assert_eq!(format_bytes(1000), "1.0 KB");
    assert_eq!(format_bytes(1500), "1.5 KB");
    assert_eq!(format_bytes(100_000), "100.0 KB");
    // improve-13 promotion: 999_999 KB-rounds to 1000.0, so it
    // renders as the next unit.
    assert_eq!(format_bytes(999_999), "1.0 MB");
    assert_eq!(format_bytes(1_000_000), "1.0 MB");
    assert_eq!(format_bytes(1_500_000), "1.5 MB");
    // One decimal on every tier, TB tier included — and improve-13
    // promotion: the threshold is inclusive (999_949 stays KB,
    // 999_950 IS 1.0 MB), the forms never carry four digits.
    assert_eq!(format_bytes(1_000_000_000), "1.0 GB");
    assert_eq!(format_bytes(1_500_000_000), "1.5 GB");
    assert_eq!(format_bytes(999_949_999_999), "999.9 GB");
    assert_eq!(format_bytes(999_950_000_000), "1.0 TB");
    assert_eq!(format_bytes(1_000_000_000_000), "1.0 TB");
    assert_eq!(format_bytes(1_500_000_000_000), "1.5 TB");
    // NIGHT-boost-22 LTS ladder: PB and EB carry the same contract.
    assert_eq!(format_bytes(1_000_000_000_000_000), "1.0 PB");
    assert_eq!(format_bytes(1_500_000_000_000_000), "1.5 PB");
    assert_eq!(format_bytes(1_000_000_000_000_000_000), "1.0 EB");
}

/// Tier-boundary promotion (improve-13): values that would round
/// to a thousands digit render in the next unit. Every tier edge
/// is pinned at its exact threshold.
#[test]
fn test_format_bytes_promotes_at_rounding_boundary() {
    // Just under each edge: the three-digit form holds.
    assert_eq!(format_bytes(999_949), "999.9 KB");
    assert_eq!(format_bytes(999_949_999), "999.9 MB");
    assert_eq!(format_bytes(999_949_999_999), "999.9 GB");
    // At/over the edge (the value that ROUNDS to 1000.0): promoted.
    assert_eq!(format_bytes(999_950), "1.0 MB");
    assert_eq!(format_bytes(999_950_999), "1.0 GB");
    assert_eq!(format_bytes(999_950_999_999), "1.0 TB");
    // Rate cells fit the 10-column monitor budget after promotion.
    assert_eq!(format_rate(999_949).chars().count(), 10);
    assert_eq!(format_rate(999_950).chars().count(), 8);
}

/// The LTS ceiling audit (NIGHT-boost-22): the ladder answers in PB
/// and EB to the u64 edge — the old TB-terminal note claimed
/// u64::MAX was ~18.4 TERABYTES, but 2^64 is ~18.4 EXABYTES, and a
/// saturated 10G server crosses 999.95 TB in ~9.5 days. Past the TB
/// edge the old formatter broke its own promotion contract
/// ("18446.7 TB", five digits, 10 columns); the extended ladder
/// holds the three-digit form on every tier it can reach.
#[test]
fn test_format_bytes_lts_ceiling_pb_eb() {
    // The TB -> PB edge, pinned at its exact threshold like every
    // other tier: 999.949e15 stays PB, 999.95e15 promotes to EB.
    assert_eq!(format_bytes(999_949_999_999_999_999), "999.9 PB");
    assert_eq!(format_bytes(999_950_000_000_000_000), "1.0 EB");
    // The u64 ceiling: 18,446,744,073,709,551,615 B = ~18.4 EB —
    // the honest saturated display of a saturated u64 accumulator
    // (NIGHT-boost-16's saturating sums land here, never a wrap).
    assert_eq!(format_bytes(u64::MAX), "18.4 EB");
    // Zettabytes stay unreachable: 1e21 needs 71 bits; u64::MAX
    // (~1.8e19) cannot express it — no eighth tier exists to lie
    // about, and the ladder's terminal tier is honest.
    assert!(u128::from(u64::MAX) < 1_000_000_000_000_000_000_000u128);
    // Max-length mitigation (the owner's ask): every tier from KB to
    // PB renders at most 8 columns across the whole u64 domain, and
    // the saturated rate cell stays inside the monitor's fixed
    // 10-column budget ("/s" + the two-character unit).
    for &probe in &[
        999_949u64,
        999_949_999,
        999_949_999_999,
        999_949_999_999_999,
        999_949_999_999_999_999,
    ] {
        assert!(
            format_bytes(probe).chars().count() <= 8,
            "byte cell must cap at 8 columns, got {} for {probe}",
            format_bytes(probe)
        );
    }
    assert_eq!(format_rate(u64::MAX), "18.4 EB/s");
    assert!(format_rate(u64::MAX).chars().count() <= 10);
}

#[test]
fn test_format_rate_with_suffix() {
    assert_eq!(format_rate(0), "BLOCKED");
    assert_eq!(format_rate(100_000), "100.0 KB/s");
    assert_eq!(format_rate(1_000_000), "1.0 MB/s");
    assert_eq!(format_rate(1_000_000_000), "1.0 GB/s");
    // The input-output symmetry pin: the CLI accepts "1tb" and
    // the status row now answers in the same unit.
    assert_eq!(format_rate(1_000_000_000_000), "1.0 TB/s");
}

#[test]
fn test_parse_rate_consistent_with_format() {
    // Round-trip: parse("100kb") → 100000 → format → "100.0 KB/s"
    let rate = parse_rate("100kb").unwrap();
    assert_eq!(rate, 100_000);
    assert_eq!(format_rate(rate), "100.0 KB/s");

    let rate = parse_rate("1mb").unwrap();
    assert_eq!(rate, 1_000_000);
    assert_eq!(format_rate(rate), "1.0 MB/s");

    // The max-rate twin (status-style audit): parse("1tb") is the
    // parser's ceiling; the formatter must answer in TB, not in a
    // four-digit GB figure.
    let rate = parse_rate("1tb").unwrap();
    assert_eq!(rate, 1_000_000_000_000);
    assert_eq!(format_rate(rate), "1.0 TB/s");
}

// ── NIGHT-improve-10: duration overflow pins ────────────────────

#[test]
fn test_parse_time_duration_plain_and_units() {
    assert_eq!(parse_time_duration("30").unwrap(), 30);
    assert_eq!(parse_time_duration("30s").unwrap(), 30);
    assert_eq!(parse_time_duration("5m").unwrap(), 300);
    assert_eq!(parse_time_duration("2h").unwrap(), 7200);
}

#[test]
fn test_parse_time_duration_overflow_errors_not_saturates() {
    // 1e17 × 3600 (h) overflows u64 (max ~1.8e19). Must return Err
    // naming the overflow with the original input — never a silent
    // u64::MAX saturation that consumers would treat as "infinity".
    let result = parse_time_duration("100000000000000000h");
    assert!(result.is_err());

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("100000000000000000h"),
        "error should show original input, got: {err_msg}"
    );
    assert!(
        err_msg.contains("overflows 64-bit math"),
        "error should name the overflow, got: {err_msg}"
    );
    assert!(
        !err_msg.contains("18446744073709551615"),
        "error must not show a saturated u64::MAX value, got: {err_msg}"
    );
}

// ── NIGHT-boost-15 / hunt-30: fractional rate pins ──────────────────

/// The owner-approved case: `5.5mb` is exactly 5,500,000 bytes/s —
/// integer mantissa and decimal scale, no f64 anywhere in the path,
/// every tier exact to the byte.
#[test]
fn test_parse_rate_fractional_exact() {
    assert_eq!(parse_rate("5.5mb").unwrap(), 5_500_000);
    assert_eq!(parse_rate("0.5mb").unwrap(), 500_000);
    assert_eq!(parse_rate("2.5kb").unwrap(), 2_500);
    assert_eq!(parse_rate("1.5gb").unwrap(), 1_500_000_000);
    assert_eq!(parse_rate("0.75tb").unwrap(), 750_000_000_000);
    assert_eq!(parse_rate("0.0005mb").unwrap(), 500);
    // Leading zeros are digits: the grammar is `[0-9]+(.[0-9]+)?`.
    assert_eq!(parse_rate("05.5mb").unwrap(), 5_500_000);
    assert_eq!(parse_rate("0005.5mb").unwrap(), 5_500_000);
}

/// Rounding is half-away-from-zero at the FINAL byte only (the
/// rate_bps precedent): sub-byte precision is meaningless for a rate,
/// but intermediate rounding would compound across the mantissa.
#[test]
fn test_parse_rate_fractional_rounds_half_away_at_the_byte() {
    // 0.5 B/s rounds up to 1.
    assert_eq!(parse_rate("0.5b").unwrap(), 1);
    // 1.25 B/s rounds down to 1; 1.5 B/s rounds up to 2.
    assert_eq!(parse_rate("1.25b").unwrap(), 1);
    assert_eq!(parse_rate("1.5b").unwrap(), 2);
    // Deep-precision exactness: 1e-9 GB/s is exactly 1 B/s — the
    // u128 ladder carries ten fractional digits without drift.
    assert_eq!(parse_rate("0.000000001gb").unwrap(), 1);
}

/// A fractional input that rounds to zero is rejected: 0 is the BPF
/// schema's BLOCK verdict, and a user who typed `0.4b` meant a tiny
/// rate, not a silent block. The error says which to pass.
#[test]
fn test_parse_rate_fractional_zero_is_rejected_with_block_hint() {
    for input in ["0.4b", "0.0004kb", "0.2b"] {
        let err_msg = format!("{}", parse_rate(input).unwrap_err());
        assert!(
            err_msg.contains("rounds to zero bytes/s"),
            "'{input}' must name the zero rounding, got: {err_msg}"
        );
        assert!(
            err_msg.contains("block verdict"),
            "'{input}' must explain the 0 semantics, got: {err_msg}"
        );
    }
    // The integer zero stays the block verdict, untouched.
    assert_eq!(parse_rate("0").unwrap(), 0);
    assert_eq!(parse_rate("0b").unwrap(), 0);
}

/// Strict grammar: leading dot, trailing dot, double dot, and signs
/// are usage errors naming the invalid number, never silent zeros.
#[test]
fn test_parse_rate_fractional_grammar_is_strict() {
    for input in [".5mb", "5.mb", "5.5.5mb", "-5.5mb", "+5.5mb", "5..5kb"] {
        let err_msg = format!("{}", parse_rate(input).unwrap_err());
        assert!(
            err_msg.contains("Invalid number in rate"),
            "'{input}' must fail as an invalid number, got: {err_msg}"
        );
    }
}

/// Fractional overflow: a value that crosses the u64 boundary errors
/// with the ORIGINAL input shown — never the wrapped value — the same
/// contract the integer overflow path pins.
#[test]
fn test_parse_rate_fractional_overflow_errors_not_wraps() {
    // 18446744073709551615.5 b rounds to 18446744073709551616 >
    // u64::MAX: must error, not wrap to 0.
    let result = parse_rate("18446744073709551615.5b");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("18446744073709551615.5b"),
        "error should show the original input, got: {err_msg}"
    );
    assert!(
        err_msg.contains("overflows 64-bit math"),
        "error should name the overflow, got: {err_msg}"
    );
    assert!(
        !err_msg.contains("18446744073709551616"),
        "error must not show the wrapped value, got: {err_msg}"
    );

    // The boundary twin: 18446744073709551614.5 rounds to exactly
    // u64::MAX and is accepted — the edge itself is legal.
    assert_eq!(parse_rate("18446744073709551614.5b").unwrap(), u64::MAX);
}

/// Typo rescue keeps working on fractional values: the uppercase
/// twin and the near-miss unit both surface their tips (the tip
/// engine's numeric prefix includes the decimal point).
#[test]
fn test_parse_rate_fractional_typo_tips() {
    let upper = format!("{}", parse_rate("5.5MB").unwrap_err());
    assert!(
        upper.contains("tip: a similar value exists: '5.5mb'"),
        "uppercase fractional twin must be suggested, got: {upper}"
    );
    let near_miss = format!("{}", parse_rate("5.5kib").unwrap_err());
    assert!(
        near_miss.contains("tip: a similar value exists: '5.5kb'"),
        "near-miss fractional unit must be suggested, got: {near_miss}"
    );
}

/// The duration grammar is FRACTIONAL (NIGHT-hunt-31, the
/// owner-approved hunt extending boost-15's rate layer to its twin
/// surface): `5.5h` parses to 19,800 seconds — exact u128
/// mantissa/scale math, rounded half-away-from-zero at the final
/// second; the integer inputs keep their byte-identical results.
#[test]
fn test_duration_grammar_fractional() {
    assert_eq!(parse_time_duration("5.5h").unwrap(), 19_800);
    assert_eq!(parse_time_duration("1.5m").unwrap(), 90);
    assert_eq!(parse_time_duration("2.25h").unwrap(), 8_100);
    // Half-away-from-zero at the final second: 0.5s rounds up.
    assert_eq!(parse_time_duration("0.5s").unwrap(), 1);
    // The integers the strict CLI was built on keep their results.
    assert_eq!(parse_time_duration("30").unwrap(), 30);
    assert_eq!(parse_time_duration("2h").unwrap(), 7_200);
}

/// Fractional durations still keep the strict grammar and the two
/// hard contracts: malformed numbers fail with the reason, overflow
/// errors (never saturates, NIGHT-improve-10), and a fractional
/// input that rounds to ZERO is rejected because 0 means infinity —
/// the exact opposite of what `0.4s` meant, never a silent flip.
#[test]
fn test_fractional_duration_edges() {
    for bad in ["1.s", ".5h", "5.5.5h", "-1.5h"] {
        let err_msg = format!("{}", parse_time_duration(bad).unwrap_err());
        assert!(
            err_msg.contains("Invalid number in duration"),
            "'{bad}' must fail as an invalid number, got: {err_msg}"
        );
    }
    let overflow = format!(
        "{}",
        parse_time_duration("18446744073709551615.5h").unwrap_err()
    );
    assert!(
        overflow.contains("too large"),
        "fractional overflow must error, got: {overflow}"
    );
    let zero = format!("{}", parse_time_duration("0.4s").unwrap_err());
    assert!(
        zero.contains("rounds to zero seconds"),
        "zero-rounding must be named for what it would mean, got: {zero}"
    );
    assert!(
        zero.contains("0 means infinity"),
        "the infinity contract must be spelled out, got: {zero}"
    );
}

/// Round-trip symmetry with the formatter: `5.5mb` parses to the
/// same bytes/s that format_rate renders for 5,500,000.
#[test]
fn test_fractional_parse_format_round_trip() {
    let rate = parse_rate("5.5mb").unwrap();
    assert_eq!(rate, 5_500_000);
    assert_eq!(format_rate(rate), "5.5 MB/s");
    let rate = parse_rate("0.75tb").unwrap();
    assert_eq!(format_rate(rate), "750.0 GB/s");
}
