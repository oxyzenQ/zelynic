// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI suggestion ENGINE — the closest-match core (cosmostrix
//! `cli/suggestion.rs` lineage, ported in NIGHT-hunt-5).
//!
//! Owns the shared edit-distance machinery (`edit_distance`,
//! `closest_value_match`) and the case-insensitive Jaro flag matcher
//! (`jaro_ci`, `closest_long_flag_ci`). Presentation (the canonical
//! "tip:" line format) lives in `cli/ux.rs` — the CLI UX contract
//! module.
//!
//! The edit-distance family serves the ebpf-gated rate/duration tip
//! engine; the Jaro family serves the always-compiled clap flag rescue
//! (`cli::ux::enrich_unknown_arg_suggestion`).

/// Levenshtein edit distance (shared engine for value suggestions).
#[cfg(feature = "ebpf")]
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Closest candidate within edit distance 2 (case-insensitive), or `None`.
///
/// Distance <= 2 catches typos (transposition = distance 2 in plain
/// Levenshtein, single edit = distance 1) without suggesting unrelated
/// values. Ties resolve to the FIRST candidate at the best distance
/// (deterministic given a stable candidate order).
#[cfg(feature = "ebpf")]
pub(crate) fn closest_value_match(input: &str, candidates: &[&str]) -> Option<String> {
    let input_lower = input.trim().to_ascii_lowercase();
    if input_lower.is_empty() {
        return None;
    }
    let mut best: Option<(String, usize)> = None;
    for candidate in candidates {
        let dist = edit_distance(&input_lower, candidate);
        if dist > 2 {
            continue;
        }
        match &best {
            None => best = Some(((*candidate).to_string(), dist)),
            Some((_, d)) if dist < *d => best = Some(((*candidate).to_string(), dist)),
            _ => {}
        }
    }
    best.map(|(name, _)| name)
}

/// Jaro similarity (clap's own flag-suggestion metric), case-insensitive.
///
/// clap 4's did-you-mean engine scores flag candidates with plain Jaro
/// at a > 0.7 confidence threshold, comparing case-SENSITIVELY — so
/// `--VERBOS` (zero matching chars against `--verbose`) renders
/// tip-less. Lowercasing both sides first lets a case-variant prefix
/// of a known flag still score; for already-lowercase input the score
/// is IDENTICAL to clap's own engine, which is what makes the fallback
/// in `cli::ux::enrich_unknown_arg_suggestion` safe: it only fires
/// where clap was silent, and can never suggest a flag clap itself
/// would have rejected for the same lowercase input.
fn jaro_ci(a: &str, b: &str) -> f64 {
    let lower = |s: &str| -> Vec<char> { s.chars().flat_map(char::to_lowercase).collect() };
    let a = lower(a);
    let b = lower(b);
    let (a_len, b_len) = (a.len(), b.len());
    if a_len == 0 && b_len == 0 {
        return 1.0;
    }
    if a_len == 0 || b_len == 0 {
        return 0.0;
    }
    if a_len == 1 && b_len == 1 {
        return if a[0] == b[0] { 1.0 } else { 0.0 };
    }
    let search_range = (a_len.max(b_len) / 2).saturating_sub(1);
    let mut b_consumed = vec![false; b_len];
    let mut matches = 0.0_f64;
    let mut transpositions = 0.0_f64;
    let mut b_match_index = 0_usize;
    for (i, &a_elem) in a.iter().enumerate() {
        let min_bound = i.saturating_sub(search_range);
        let max_bound = (b_len - 1).min(i + search_range);
        if min_bound > max_bound {
            continue;
        }
        for (j, &b_elem) in b.iter().enumerate() {
            if min_bound <= j && j <= max_bound && a_elem == b_elem && !b_consumed[j] {
                b_consumed[j] = true;
                matches += 1.0;
                if j < b_match_index {
                    transpositions += 1.0;
                }
                b_match_index = j;
                break;
            }
        }
    }
    if matches == 0.0 {
        0.0
    } else {
        (1.0 / 3.0)
            * ((matches / a_len as f64)
                + (matches / b_len as f64)
                + ((matches - transpositions) / matches))
    }
}

/// Closest long-flag name by case-insensitive Jaro (clap's > 0.7
/// confidence threshold), or `None`. Input and candidates are BARE
/// names (no leading dashes).
///
/// Used ONLY as the fallback when clap's own case-sensitive engine
/// found nothing (see `cli::ux::enrich_unknown_arg_suggestion`). Ties
/// resolve to the LAST candidate in declaration order — clap's own
/// engine inserts equal-confidence candidates in iteration order and
/// pops the last, so the lowercase twin of a rescued typo suggests the
/// same flag clap would have suggested.
pub(crate) fn closest_long_flag_ci(input: &str, candidates: &[&str]) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut best: Option<(String, f64)> = None;
    for candidate in candidates {
        let confidence = jaro_ci(trimmed, candidate);
        if confidence <= 0.7 {
            continue;
        }
        match &best {
            // `>=` not `>`: later candidates win ties, mirroring
            // clap's ascending-sort-then-pop tie-break.
            None => best = Some(((*candidate).to_string(), confidence)),
            Some((_, c)) if confidence >= *c => {
                best = Some(((*candidate).to_string(), confidence));
            }
            _ => {}
        }
    }
    best.map(|(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "ebpf")]
    #[test]
    fn closest_value_match_catches_single_typos() {
        let candidates = ["b", "kb", "mb", "gb"];
        assert_eq!(
            closest_value_match("kib", &candidates),
            Some("kb".to_string())
        );
        assert_eq!(
            closest_value_match("MB", &candidates),
            Some("mb".to_string())
        );
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn closest_value_match_ignores_distant_values() {
        let candidates = ["s", "m", "h"];
        assert_eq!(closest_value_match("fortnights", &candidates), None);
        assert_eq!(closest_value_match("", &candidates), None);
    }

    #[test]
    fn jaro_ci_rescues_case_variants_case_sensitive_jaro_misses() {
        // Case-sensitive Jaro("VERBOS", "verbose") = 0.0 (no char
        // matches); the case-insensitive pass scores like the lowercase
        // twin.
        assert!(jaro_ci("VERBOS", "verbose") > 0.7);
        assert_eq!(jaro_ci("VERBOS", "verbose"), jaro_ci("verbos", "verbose"));
    }

    #[test]
    fn jaro_ci_zero_for_unrelated_and_short() {
        assert_eq!(jaro_ci("zzzzqqqq", "verbose"), 0.0);
        assert_eq!(jaro_ci("x", "verbose"), 0.0);
        assert_eq!(jaro_ci("", "help"), 0.0);
        assert_eq!(jaro_ci("x", "x"), 1.0);
        assert_eq!(jaro_ci("x", "y"), 0.0);
    }

    #[test]
    fn closest_long_flag_ci_suggests_verbose_for_verbos() {
        let candidates = ["version", "check-update", "verbose", "print-json", "help"];
        assert_eq!(
            closest_long_flag_ci("VERBOS", &candidates),
            Some("verbose".to_string())
        );
        assert_eq!(
            closest_long_flag_ci("verbos", &candidates),
            Some("verbose".to_string())
        );
    }

    #[test]
    fn closest_long_flag_ci_stays_silent_for_distant_input() {
        let candidates = ["version", "check-update", "verbose", "print-json", "help"];
        assert_eq!(closest_long_flag_ci("zzzzqqqq", &candidates), None);
        assert_eq!(closest_long_flag_ci("x", &candidates), None);
        assert_eq!(closest_long_flag_ci("", &candidates), None);
    }
}
