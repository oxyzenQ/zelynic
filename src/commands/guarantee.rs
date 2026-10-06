// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! improve-40 (schema v24) / improve-40-b (the per-direction
//! spellings): the guarantee bracket's CLI resolution — the six
//! bracket flags parsed on the rate family's own ladder, then
//! validated against the resolved rates BEFORE the root ask (the
//! parse-before-execute contract every strict handler documents: a
//! contradictory bracket surfaces its wording with the numbers it
//! would have policed, never a privileged round-trip later).
//!
//! THE ONE-FLAG LAW: one `--floor` (or `--ceil`) sets BOTH
//! directions' rows — the `--during` shape, the positional rate's
//! own posture — and validates against EVERY direction the spec
//! sets (a direction the invocation removes is not consulted; the
//! improve-29 law owns that removal). improve-40-b adds the
//! per-direction spellings for the asymmetric link:
//! `--floor-download`/`--floor-upload` and the `--ceil-` twins set
//! ONE direction's pair. ONE SPELLING PER SIDE — the both-directions
//! flag and its per-direction twin refuse together (a combined
//! `--floor 100kb --floor-download 200kb` is a mis-typed rate, not
//! a wider guarantee), and a per-direction side whose direction the
//! invocation REMOVES (no `-d` rate, so no download row) refuses
//! outright: a guarantee for a row that will not exist is a
//! mistake the ladder names before the root ask.
//!
//! THE VALIDATION LADDER, fail-fast in the order the owner would
//! mis-type it:
//!   * the scope call — the bracket polices the cgroup's subprocess
//!     LEAVES (the DRR fair-share lane); the per-socket lane polices
//!     each connection at the full rate, and the combination is not
//!     a thing the bracket family does;
//!   * the one-spelling call — `--floor` vs `--floor-download`/
//!     `--floor-upload` (and the ceil twins), never both;
//!   * the removed-direction call — a per-direction side needs its
//!     direction's row to exist;
//!   * the grammar — the rate family's parser and its 1kb floor
//!     (a typo'd bracket gets the did-you-mean tip, a sub-1kb one
//!     asks --force-this, exactly like a rate);
//!   * the contradiction — a floor above a ceiling is unkeepable in
//!     any arithmetic that respects the cap, judged per direction;
//!   * the never-binding sides — a bracket side above the rate can
//!     never bind (the pool refills at the rate), judged per SET
//!     direction.

// Dormant-mode discipline: the resolver is ebpf-gated, so its
// anyhow imports ride the same gate (a module-level unused import
// breaks the no-default-features leg's -D warnings).
#[cfg(feature = "ebpf")]
use anyhow::{bail, Result};

// improve-40: the wording pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired exactly like the rates
// shadow family one sibling over.
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/cli/guarantee_resolve_tests.rs"]
mod guarantee_resolve_tests;

/// The six bracket flags exactly as clap hands them over — one
/// struct so the resolver's signature stays narrow and every strict
/// handler reads the same field names the CLI declares (the
/// both-directions pair, then the per-direction spellings).
/// ebpf-gated like the resolver it feeds (the dormant leg never
/// constructs it).
#[cfg(feature = "ebpf")]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BracketFlags<'a> {
    /// `--floor` — both directions' floor.
    pub floor: Option<&'a str>,
    /// `--ceil` — both directions' ceiling.
    pub ceil: Option<&'a str>,
    /// `--floor-download` — the download row's floor.
    pub floor_download: Option<&'a str>,
    /// `--floor-upload` — the upload row's floor.
    pub floor_upload: Option<&'a str>,
    /// `--ceil-download` — the download row's ceiling.
    pub ceil_download: Option<&'a str>,
    /// `--ceil-upload` — the upload row's ceiling.
    pub ceil_upload: Option<&'a str>,
}

#[cfg(feature = "ebpf")]
impl BracketFlags<'_> {
    /// True when any bracket flag is set (the scope call's question).
    fn any_set(&self) -> bool {
        self.floor.is_some()
            || self.ceil.is_some()
            || self.floor_download.is_some()
            || self.floor_upload.is_some()
            || self.ceil_download.is_some()
            || self.ceil_upload.is_some()
    }
}

/// Resolve the guarantee bracket for one strict invocation: parse
/// every set side on the rate family's ladder, walk the validation
/// ladder above, and return the per-direction pairs the apply family
/// writes on the rows — the zero sentinel for an unset side.
///
/// The imports live inside the function (the rates.rs dormant-mode
/// discipline): the whole resolver is ebpf-gated, and a
/// module-level import of the limiter tree would break the
/// no-default-features leg's compile.
#[cfg(feature = "ebpf")]
pub(crate) fn resolve_guarantee(
    flags: BracketFlags<'_>,
    rates: &crate::ebpf::limiter::RateSpec,
    force_this: bool,
    per_socket: bool,
) -> Result<crate::ebpf::limiter::BracketSpec> {
    use crate::ebpf::limiter::{parse_rate, validate_rate, BracketPair, BracketSpec};

    // The scope call first (before any parsing: the combination is
    // rejected whatever the values would have been — the
    // per-direction spellings are the same family, the same call).
    if per_socket && flags.any_set() {
        bail!(
            "--floor/--ceil police the target's subprocess leaves (the fair-share lane) \
             and are not offered beside --per-socket (every connection its own budget \
             at the full rate).\n\
             Drop one: --per-socket for the server shape, --floor/--ceil for the \
             subprocess shape."
        );
    }

    // The one-spelling call, per side: the both-directions flag and
    // its per-direction twins never combine.
    if flags.floor.is_some() && (flags.floor_download.is_some() || flags.floor_upload.is_some()) {
        bail!(
            "--floor and --floor-download/--floor-upload are one spelling apart: \
             --floor 100kb sets BOTH directions' rows, --floor-download 100kb only \
             the download row.\n\
             Pick one spelling per side; combining them is a mis-typed rate, not a \
             wider guarantee."
        );
    }
    if flags.ceil.is_some() && (flags.ceil_download.is_some() || flags.ceil_upload.is_some()) {
        bail!(
            "--ceil and --ceil-download/--ceil-upload are one spelling apart: \
             --ceil 300kb caps BOTH directions' rows, --ceil-download 300kb only \
             the download row.\n\
             Pick one spelling per side; combining them is a mis-typed rate, not a \
             tighter cap."
        );
    }

    // The removed-direction call: a per-direction side needs its
    // direction's row to exist (the improve-29 law — a direction
    // the rate spec does not set is REMOVED, not left stale).
    if (flags.floor_download.is_some() || flags.ceil_download.is_some()) && rates.download.is_none()
    {
        bail!(
            "--floor-download/--ceil-download police the download row, but this \
             invocation sets no download rate (-d/--download absent — a direction \
             the spec does not set is REMOVED, not left stale).\n\
             Set the direction first: add a download rate, then bracket it."
        );
    }
    if (flags.floor_upload.is_some() || flags.ceil_upload.is_some()) && rates.upload.is_none() {
        bail!(
            "--floor-upload/--ceil-upload police the upload row, but this \
             invocation sets no upload rate (-u/--upload absent — a direction \
             the spec does not set is REMOVED, not left stale).\n\
             Set the direction first: add an upload rate, then bracket it."
        );
    }

    // The grammar, on the rate family's own ladder.
    let parse_side = |s: &str| -> Result<u64> {
        let rate = parse_rate(s)?;
        if !force_this {
            validate_rate(rate)?;
        }
        Ok(rate)
    };

    // The one-flag law's resolution: a per-direction spelling wins
    // its own direction, the both-directions flag fills the rest
    // (the one-spelling call above guarantees at most one is set).
    let dl_floor = match flags.floor_download.or(flags.floor) {
        Some(s) => parse_side(s)?,
        None => 0,
    };
    let ul_floor = match flags.floor_upload.or(flags.floor) {
        Some(s) => parse_side(s)?,
        None => 0,
    };
    let dl_ceil = match flags.ceil_download.or(flags.ceil) {
        Some(s) => parse_side(s)?,
        None => 0,
    };
    let ul_ceil = match flags.ceil_upload.or(flags.ceil) {
        Some(s) => parse_side(s)?,
        None => 0,
    };
    let download = BracketPair {
        floor_bps: dl_floor,
        ceil_bps: dl_ceil,
    };
    let upload = BracketPair {
        floor_bps: ul_floor,
        ceil_bps: ul_ceil,
    };

    // The contradiction and the never-binding sides, judged PER SET
    // DIRECTION (a direction the invocation removes is not consulted
    // — the improve-29 law; a per-direction bracket already proved
    // its direction set above).
    for (label, rate, pair) in [
        ("download", rates.download, download),
        ("upload", rates.upload, upload),
    ] {
        let Some(rate) = rate else {
            continue;
        };
        if pair.floor_bps != 0 && pair.ceil_bps != 0 && pair.floor_bps > pair.ceil_bps {
            bail!(
                "floor {} exceeds ceil {} on the {} row — a guarantee above the cap is a \
                 contradiction.\n\
                 The cap is the safety law; raise the ceiling or lower the floor.",
                pair.floor_bps,
                pair.ceil_bps,
                label
            );
        }
        if pair.ceil_bps != 0 && pair.ceil_bps > rate {
            bail!(
                "ceil {} exceeds the {} rate {} — the pool refills at the rate, \
                 so a ceiling above it never binds.\n\
                 Raise the rate or lower the ceiling.",
                pair.ceil_bps,
                label,
                rate
            );
        }
        if pair.floor_bps != 0 && pair.floor_bps > rate {
            bail!(
                "floor {} exceeds the {} rate {} — the pool never refills that fast, \
                 so the guarantee could never bind.\n\
                 Over-subscribed floors (many leaves, each floored) are the datapath's \
                 documented degradation; one leaf floored above its own pool is a \
                 mis-typed rate.",
                pair.floor_bps,
                label,
                rate
            );
        }
    }

    Ok(BracketSpec { download, upload })
}
