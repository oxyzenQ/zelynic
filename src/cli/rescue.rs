// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The flag-rescue family (split from cli/ux.rs by NIGHT-improve-42,
//! the owner's 500-line cap): the tables and matchers that turn an
//! unknown flag into the tip the user needs — the top-level
//! authorities (flags that parse at the ROOT only, redirected to
//! their top-level spelling), the cross-tool vocabulary (spellings
//! from other CLIs the fuzzy engine cannot bridge by distance), and
//! the shadowed-suggestion rescue (the supermassive v4 depth
//! battery's own catch: clap's subcommand-local suggestion pool can
//! shadow a much closer root-flag typo). Presentation and the
//! enrichment chain stay in cli/ux.rs; this module owns WHAT to
//! suggest, never how it renders.

use clap::error::{ContextKind, ContextValue};

/// Top-level-authority flags (NIGHT-boost-12, generalizing the
/// NIGHT-improve-3 help rescue): names whose subcommand-position or
/// `--`-escaped appearance must tip the TOP-LEVEL spelling instead of
/// the fuzzy rescue.
///
/// The `-V` incident that generalized this table: the fuzzy rescue
/// scored jaro_ci("V", "verbose") = 0.714 — one matching char against
/// a 7-char candidate clears the 0.7 bar — and "version" tied at
/// 0.714, declaration order breaking the tie toward `--verbose`. A
/// lone `V` is intent-ambiguous to the fuzzy engine; this table is not.
///
/// `--check-update` rides the same contract: the fuzzy rescue would
/// suggest the very flag the user typed (a no-op tip), and the update
/// check is deliberately top-level-only.
const TOP_LEVEL_FLAG_RESCUES: &[(&str, &str)] = &[
    ("help", "zelynic --help"),
    ("h", "zelynic --help"),
    ("version", "zelynic -V"),
    ("V", "zelynic -V"),
    ("check-update", "zelynic --check-update"),
    ("check-updated", "zelynic --check-update"),
];

/// The top-level spelling a typed flag name must be redirected to,
/// or `None` when it is not a top-level authority.
pub(super) fn top_level_flag_rescue(typed: &str) -> Option<&'static str> {
    TOP_LEVEL_FLAG_RESCUES
        .iter()
        .find(|(name, _)| *name == typed)
        .map(|(_, authority)| *authority)
}

/// The shadowed-suggestion rescue (NIGHT-improve-42, the supermassive
/// v4 depth battery's own catch): clap's UnknownArgument tip fired
/// from the SUBCOMMAND's flag pool — a pool the root-level flags
/// never join — so a typo of a root flag can be answered with a
/// much-farther subcommand flag that happened to clear clap's 0.7
/// Jaro-Winkler bar. The live catch: `ss brave 1mb --check-updat`
/// answered `--ceil-upload` (0.78 plain-Jaro confidence) once the
/// improve-40-b bracket family put `--ceil-upload` in strict-single's
/// pool — shadowing the 0.97 `--check-update` the silent-fallback
/// path would have given. The rescue re-scores BOTH candidates with
/// the one case-insensitive Jaro metric and keeps the better tip:
/// the root pool's winner replaces clap's only when it scores
/// STRICTLY higher (a tie keeps clap's own — its pool knows the
/// subcommand's flags), and a winner that is a top-level authority
/// redirects to the top-level spelling (`check-update` parses at the
/// ROOT only; a bare `--check-update` tip at subcommand position
/// would point at a position where the flag still fails).
pub(super) fn rescue_shadowed_suggestion(e: &mut clap::Error, cmd: &clap::builder::Command) {
    let typed = match e.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(s)) => s.trim_start_matches('-').to_string(),
        _ => return,
    };
    if typed.is_empty() {
        return;
    }
    let clap_tip = match e.get(ContextKind::SuggestedArg) {
        Some(ContextValue::String(s)) => s.trim_start_matches('-').to_string(),
        _ => return,
    };
    // The root pool — the same candidate set the silent fallback
    // scores (every non-hidden long flag the root command carries).
    let candidates: Vec<&str> = cmd
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .filter_map(|arg| arg.get_long())
        .collect();
    let mut best: Option<(&str, f64)> = None;
    for candidate in &candidates {
        let confidence = crate::cli::suggestion::jaro_ci(&typed, candidate);
        if confidence <= 0.7 {
            continue;
        }
        match best {
            None => best = Some((candidate, confidence)),
            Some((_, c)) if confidence > c => best = Some((candidate, confidence)),
            _ => {}
        }
    }
    let (name, score) = match best {
        Some(b) => b,
        None => return,
    };
    let clap_score = crate::cli::suggestion::jaro_ci(&typed, &clap_tip);
    // STRICTLY greater: a tie keeps clap's own tip (its engine wins
    // ties — the pool that knows the subcommand's flags is the
    // right authority when both readings are equally close).
    if score <= clap_score {
        return;
    }
    let replacement = match top_level_flag_rescue(name) {
        Some(authority) => authority.to_string(),
        None => format!("--{name}"),
    };
    e.remove(ContextKind::Suggested);
    e.insert(ContextKind::SuggestedArg, ContextValue::String(replacement));
}

/// Cross-tool flag vocabulary (NIGHT-boost-13): spellings users bring
/// from other CLIs, mapped to the zelynic flag that answers them —
/// intent-clear names whose jaro distance to the real flag sits far
/// under the 0.7 fuzzy bar, which would otherwise leave a tip-less
/// dead end (`--json` scores 0.394 against `--print-json`). These
/// rescues run after the top-level authority table and before the
/// fuzzy fallback; like every rescue that injects a suggestion they
/// drop the native trailing escape-hatch tip first (one tip, the
/// right one).
///
/// `allow-dangerous` (NIGHT-improve-30): the retired spelling, redirected to the unified `--force-this`.
///
/// `info` (NIGHT-blade-4): the retired eagle-eyes `--depth` alias —
/// one spelling, `--depth` (the single-spelling contract the
/// subcommand surface carries). The rescue lands the old muscle
/// memory on the flag that answers it: jaro_ci("info", "depth") is
/// 0.0 and every other live flag sits under the 0.7 bar (interval
/// 0.583, print-json 0.567), so without the table the old spelling
/// died tip-less (the allow-dangerous contract, one tip, the right
/// one).
const FLAG_VOCABULARY_RESCUES: &[(&str, &str)] = &[
    ("json", "--print-json"),
    ("allow-dangerous", "--force-this"),
    ("info", "--depth"),
];

/// The zelynic flag a typed name answers to by cross-tool vocabulary,
/// or `None` when it is not in the table.
pub(super) fn flag_vocabulary_rescue(typed: &str) -> Option<&'static str> {
    FLAG_VOCABULARY_RESCUES
        .iter()
        .find(|(name, _)| *name == typed)
        .map(|(_, flag)| *flag)
}
