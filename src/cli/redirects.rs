// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The redirect family (night-netrunner-5, the 600-line cap split
//! that took the renamed-verb tables out of the ux bridge — the same
//! one-concern-one-module move the tips and rescue files rode):
//! everything that answers a DEAD spelling with its successor.
//! `ux.rs` keeps the enrichment chain and the render; this module
//! owns the three redirect surfaces it drives — the removed-verb
//! table, the subcommand-to-flag redirect, and the hidden-vocabulary
//! filter — so the bridge cannot outgrow its cap again while the
//! vocabulary keeps growing.

use clap::error::{ContextKind, ContextValue};

/// Removed-subcommand redirects (NIGHT-boost-1): the observe/top
/// pair merged into eagle-eyes — old muscle memory gets the
/// successor named instead of a dead end (the same redirect
/// contract --help-all got when the help tiers merged,
/// NIGHT-improve-3). Exact-match only: a fuzzy suggestion for a
/// removed name is overridden, never supplemented — one tip, the
/// right one.
///
/// NIGHT-improve-25: the singular `eagle-eye` alias is removed with
/// the short-alias surface (one canonical name, one short form 'ee')
/// — it joins the redirect table so the old spelling lands on the
/// successor tip, the exact contract observe/top carry.
///
/// NIGHT-blade-2: limit-all/la renamed strict-all/sa (strict-family
/// symmetry) — both old spellings join the redirect table's contract.
///
/// NIGHT-improve-54 (the sweep merge): strict-all, block-all, and
/// unstrict-all are LANES of their family verbs now (`s --all`,
/// `b --all`, `u --all`) — the six retired spellings (canonical +
/// short alias each) join the table, and the blade-2 pair above
/// repoints at `strict` with them: every one lands on its family's
/// successor verb.
///
/// NIGHT-improve-53 (the masterclass unification): strict-single +
/// strict-multi, block-single + block-multi, and unstrict-single +
/// unstrict-multi merged into one verb per family (strict / block /
/// unstrict — 's'/'b'/'u' the short forms, '::' the list separator).
/// Twelve retired spellings join the table — every one of them
/// lands on its family's successor verb.
const REMOVED_SUBCOMMAND_REDIRECTS: &[(&str, &str)] = &[
    ("observe", "eagle-eyes"),
    ("top", "eagle-eyes"),
    ("eagle-eye", "eagle-eyes"),
    // NIGHT-improve-54: repointed with the sweep merge — strict-all
    // itself is retired into strict's --all lane, so the blade-2
    // spellings land on the sweep spelling like every -all after
    // them. The successor string names WHAT TO TYPE (verb + flag):
    // a bare 'strict' tip would strand the sweep-seeker on the
    // TARGET-required rung one keystroke later.
    ("limit-all", "strict --all"),
    ("la", "strict --all"),
    // NIGHT-improve-53: the masterclass retirees.
    ("strict-single", "strict"),
    ("strict-multi", "strict"),
    ("ss", "strict"),
    ("sm", "strict"),
    ("block-single", "block"),
    ("block-multi", "block"),
    ("bs", "block"),
    ("bm", "block"),
    ("unstrict-single", "unstrict"),
    ("unstrict-multi", "unstrict"),
    ("us", "unstrict"),
    ("um", "unstrict"),
    // NIGHT-improve-54: the sweep retirees — the -all verbs are
    // --all lanes of the family verbs now (the sa/ba/ua short
    // aliases with them, the short-alias surface's own law). The
    // successors name the runnable spelling (verb + flag), the
    // limit-all contract one entry up.
    ("strict-all", "strict --all"),
    ("sa", "strict --all"),
    ("block-all", "block --all"),
    ("ba", "block --all"),
    ("unstrict-all", "unstrict --all"),
    ("ua", "unstrict --all"),
    // NIGHT-improve-55: the persistence pair is retired whole —
    // the owner's live-test verdict was that neither half earned
    // its keep (remembering to dump before a reboot is a workflow
    // the operator's own script already owns, and the state-file
    // apply did not change that). Both spellings land on the
    // vocabulary tip, the same contract every retired verb rides.
    ("snapshot", "status"),
    ("restore", "status"),
];

/// Inject the successor for a removed subcommand as clap's OWN
/// SuggestedSubcommand context, so the tip renders in clap's
/// canonical position and `valid` (white) style.
///
/// No-op for every error kind except InvalidSubcommand and every
/// typed name outside the redirect table.
pub(super) fn enrich_removed_subcommand_redirect(e: &mut clap::Error) {
    if e.kind() != clap::error::ErrorKind::InvalidSubcommand {
        return;
    }
    let typed = match e.get(ContextKind::InvalidSubcommand) {
        Some(ContextValue::String(s)) => s.as_str(),
        _ => return,
    };
    for (gone, successor) in REMOVED_SUBCOMMAND_REDIRECTS {
        if typed == *gone {
            // Override any fuzzy suggestion clap already attached:
            // for an exact removed name the redirect is strictly
            // more correct than a near-miss candidate.
            e.remove(ContextKind::Suggested);
            e.insert(
                ContextKind::SuggestedSubcommand,
                ContextValue::String((*successor).to_string()),
            );
            return;
        }
    }
}

/// Subcommand spellings whose successor is a top-level FLAG, not
/// another subcommand (NIGHT-boost-13).
///
/// `help` is the muscle memory every clap tool trains — clap's own
/// auto-generated `help` subcommand would answer it — but zelynic
/// runs the single-tier help surface (NIGHT-improve-3: `--help` is
/// the one reference, the auto-generated help subcommand is disabled
/// at every level), so `zelynic help` died as an unrecognized
/// subcommand with no tip: the owner's terminal showed a dead end
/// for the most natural spelling in the vocabulary. The redirect
/// lands that muscle memory on the flag that succeeds it — the same
/// contract the removed-subcommand table above gives observe/top.
const SUBCOMMAND_FLAG_REDIRECTS: &[(&str, &str)] = &[("help", "zelynic --help")];

/// Inject the flag successor for a subcommand spelling in the table
/// above as a canonical `tip:` line.
///
/// The plain `Suggested` context is the only render slot that can
/// carry a non-subcommand successor: `SuggestedSubcommand` renders
/// "a similar subcommand exists" (and there is no help subcommand to
/// name), `SuggestedArg` renders "a similar argument exists" (and
/// `help` was typed as a subcommand). The successor renders in the
/// `valid` (white) style, matching every other tip's highlighted
/// command.
pub(super) fn enrich_subcommand_flag_redirect(e: &mut clap::Error, cmd: &clap::builder::Command) {
    use std::fmt::Write as _;
    if e.kind() != clap::error::ErrorKind::InvalidSubcommand {
        return;
    }
    let typed = match e.get(ContextKind::InvalidSubcommand) {
        Some(ContextValue::String(s)) => s.as_str(),
        _ => return,
    };
    let Some(&(_, successor)) = SUBCOMMAND_FLAG_REDIRECTS
        .iter()
        .find(|(name, _)| *name == typed)
    else {
        return;
    };
    // Override any fuzzy suggestion clap already attached — for an
    // exact vocabulary spelling the redirect is strictly more
    // correct than a near-miss candidate.
    e.remove(ContextKind::SuggestedSubcommand);
    e.remove(ContextKind::Suggested);
    let valid = cmd.get_styles().get_valid();
    let mut tip = clap::builder::StyledStr::new();
    let _ = write!(
        tip,
        "to see the reference, run '{valid}{successor}{valid:#}'"
    );
    e.insert(ContextKind::Suggested, ContextValue::StyledStrs(vec![tip]));
}

/// Strip hidden subcommands from clap's typo suggestions
/// (NIGHT-hunt-Z9).
///
/// clap's `did_you_mean` engine scores candidates from
/// `all_subcommand_names()` — hidden ones included — so a near-miss of
/// an internal role (`zelynic __probe-serve`) rendered "some similar
/// subcommands exist: '__probe-client', '__probe-server'": the
/// vocabulary the help hides surfaced as a tip, teaching the operator
/// to run the probe server (an unauthenticated loopback data blast)
/// by hand. The flag-side rescue below already filters
/// `is_hide_set()` candidates; this is the subcommand-side twin —
/// the same one-vocabulary contract, both doors.
///
/// Pure filter over the `SuggestedSubcommand` context (clap stores
/// its candidates there as `Strings`): every candidate that resolves
/// to a hidden subcommand is dropped. When candidates remain, the
/// trimmed list replaces the context (a visible suggestion survives
/// beside a hidden one being removed); when NONE remain the context
/// is removed entirely, leaving the unrecognized-subcommand verdict,
/// the usage line, and the footer — the same honest dead end any
/// no-candidate typo already owns. No-op for every other error kind
/// and for errors carrying no suggestion.
pub(super) fn drop_hidden_subcommand_suggestions(
    e: &mut clap::Error,
    cmd: &clap::builder::Command,
) {
    if e.kind() != clap::error::ErrorKind::InvalidSubcommand {
        return;
    }
    let Some(ContextValue::Strings(candidates)) = e.get(ContextKind::SuggestedSubcommand) else {
        return;
    };
    let candidates = candidates.clone();
    let visible: Vec<String> = candidates
        .iter()
        .filter(|name| {
            cmd.find_subcommand(name.as_str())
                .is_none_or(|sub| !sub.is_hide_set())
        })
        .cloned()
        .collect();
    if visible.len() == candidates.len() {
        return; // nothing hidden — clap's own suggestion stands
    }
    if visible.is_empty() {
        e.remove(ContextKind::SuggestedSubcommand);
    } else {
        e.insert(
            ContextKind::SuggestedSubcommand,
            ContextValue::Strings(visible),
        );
    }
}
