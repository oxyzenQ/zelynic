// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI argv forensics — re-deriving parser state the error lost.
//!
//! A clap error names the rejected token but not the state around
//! it: whether the failing command still had positional slots open,
//! which subcommand the parser was inside when it died. The bridge
//! in `cli/ux.rs` needs both to keep its tips honest
//! (NIGHT-boost-13):
//!
//! - [`escape_hatch_is_honest`] — clap injects the escape-hatch tip
//!   ("to pass '-i' as a value, use '-- -i'") whenever the failing
//!   command merely HAS positionals; it cannot see that the slots
//!   are already full. The owner followed that tip twice
//!   (`zelynic ss brave 550kb -- -i`, `-- -x`) and hit "unexpected
//!   argument" both times — advice that fails when followed. The
//!   probe rebuilds argv with the advised splice and re-parses: the
//!   tip survives only where following it actually parses, the same
//!   proof-before-printing discipline the NIGHT-boost-8 harness
//!   brought to the headline claims.
//! - [`drop_dishonest_escape_hatch`] — the render-side gate that
//!   runs the probe and removes the tip it disproves.
//!
//! Pure functions over `(argv, token)`; a probe result is never
//! dispatched — only its Ok/Err shape is read.

use std::ffi::OsString;

use clap::error::{ContextKind, ContextValue};
use clap::Parser;

use crate::cli::Cli;

/// Indexes (into the full argv) of every argv[1..] occurrence equal
/// to `token`; the binary name at argv[0] never matches by position.
fn token_positions(argv: &[OsString], token: &str) -> Vec<usize> {
    argv.iter()
        .enumerate()
        .skip(1)
        .filter(|(_, arg)| arg.as_os_str() == std::ffi::OsStr::new(token))
        .map(|(i, _)| i)
        .collect()
}

/// Does following the escape-hatch advice actually parse?
///
/// The advice is "splice `--` before the token". The probe rebuilds
/// argv with that exact splice at every occurrence of the token and
/// re-parses: any success means the advice leads somewhere real, so
/// the tip is honest and stays. Only when every splice still fails is
/// the tip a lie — and dropped by the caller.
///
/// A token clap REPORTS but argv does not contain verbatim (a short
/// cluster like `-vi` reports `-i`; `--flag=value` reports the flag
/// part) is unprovable either way, so the probe declines to judge
/// and reports honest — matching the bridge contract that a tip is
/// removed only when disproven, never on an inability to prove.
fn escape_hatch_is_honest(argv: &[OsString], token: &str) -> bool {
    let positions = token_positions(argv, token);
    if positions.is_empty() {
        return true;
    }
    positions.iter().any(|&at| {
        let mut probe: Vec<OsString> = argv[..at].to_vec();
        probe.push(OsString::from("--"));
        probe.extend(argv[at..].iter().cloned());
        Cli::try_parse_from(probe).is_ok()
    })
}

/// Remove the escape-hatch tip the probe disproves.
///
/// Fires only for UnknownArgument errors that still carry the
/// escape-hatch tip (a rescue-injected suggestion already replaced
/// it — the one-tip contract — and clap's other `Suggested` content,
/// the unnecessary-double-dash "remove the '--'" advice, is honest
/// by construction and never touched). The tip is identified by its
/// canonical wording ("... as a value, use '-- ...'") inside the
/// styled suggestion, and the InvalidArg context supplies the token
/// the probe splices.
pub(crate) fn drop_dishonest_escape_hatch(e: &mut clap::Error, argv: &[OsString]) {
    if e.kind() != clap::error::ErrorKind::UnknownArgument {
        return;
    }
    if e.get(ContextKind::SuggestedArg).is_some() {
        return;
    }
    let carries_escape_hatch = match e.get(ContextKind::Suggested) {
        Some(ContextValue::StyledStrs(tips)) => tips
            .iter()
            .any(|tip| tip.to_string().contains("as a value, use")),
        _ => return,
    };
    if !carries_escape_hatch {
        return;
    }
    let Some(ContextValue::String(token)) = e.get(ContextKind::InvalidArg).cloned() else {
        return;
    };
    if escape_hatch_is_honest(argv, &token) {
        return;
    }
    e.remove(ContextKind::Suggested);
}

// The argv-forensics pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired exactly like the ux tests.
#[cfg(test)]
#[path = "../../test/cli/argv_tests.rs"]
mod argv_tests;
