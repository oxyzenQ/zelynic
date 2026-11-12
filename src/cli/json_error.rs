// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The JSON error contract (night-netrunner-5) — one shape for every
//! fatal CLI error a `--print-json` consumer can hit:
//!
//! ```text
//! {"error": "<message>", "tip": "<tip>"}
//! ```
//!
//! on STDOUT, exit 1. The contract's reason: the JSON surfaces
//! (status, list-apps, eagle-eyes --depth, doctor) promise a parseable
//! stream, but the two doors every failure walks — clap's usage bridge
//! (`cli::ux::exit_clap_error`) and the runtime chain in `main` —
//! rendered prose, so one typo in a cron line put plain text where a
//! JSON parser was listening. The contract closes both doors:
//!
//! - the clap door dies BEFORE the parsed field exists (a usage error
//!   never reaches `main`), so the contract asks the raw argv
//!   (`cli::argv::print_json_requested` — the color-mode seed's
//!   pre-parse discipline) and renders the error's own context back:
//!   the message from the InvalidArg/InvalidSubcommand/InvalidValue
//!   context, the tip from the Suggested family — the same facts the
//!   prose render carries, without the usage block and the footer a
//!   JSON consumer cannot use;
//! - the runtime door already holds the branded chain
//!   (`format_error_chain`), so the split is the embedded `tip:` line
//!   the branded convention carries — the error body and its tip
//!   travel one string today, the contract books them in their own
//!   fields.
//!
//! Exit 1 on this lane is the contract's own clause (the prose lane's
//! codes are untouched: clap's usage 2, runtime 1). The object rides
//! the broken-pipe-safe writer — `zelynic --print-json s brave 1kb |
//! head -1` truncates instead of panicking, the same law every other
//! stdout surface answers to. The escape law is the shared writer's
//! (`crate::json::write_string`): no hand-rolled quoting, the lanes
//! cannot drift.

use clap::error::{ContextKind, ContextValue};

use crate::json::write::write_string;

/// Render the contract object and exit.
///
/// One renderer so the two doors cannot drift on the bytes: both hand
/// over a message and a tip, the writer owns everything after. Exit 1
/// is the contract's code on BOTH doors (the prose lane keeps its own
/// codes — usage 2, runtime 1).
pub(crate) fn exit_json(message: &str, tip: &str) -> ! {
    let mut doc = String::from("{\"error\": ");
    write_string(&mut doc, message);
    doc.push_str(", \"tip\": ");
    write_string(&mut doc, tip);
    doc.push('}');
    println_safe!("{doc}");
    std::process::exit(1);
}

/// The contract door for a clap usage/parse error.
///
/// Called at the top of `cli::ux::exit_clap_error` when the raw argv
/// carried `--print-json`, BEFORE the prose enrichment chain — a JSON
/// consumer gets the machine shape, the styled render and the footer
/// are prose-lane furniture. DisplayHelp/DisplayVersion never reach
/// this module (both flags are disabled crate-wide; the curated
/// reference and the subcommand local help print through their own
/// doors with exit 0).
pub(crate) fn exit_clap_json(e: &clap::Error) -> ! {
    let (message, tip) = clap_parts(e);
    exit_json(&message, &tip)
}

/// The message and tip a clap error carries, in contract form.
///
/// The message rebuilds the verdict from the error's own context (the
/// same sentence the prose render opens with, minus the usage block
/// and the footer); the tip joins the Suggested family into one line —
/// the plain text of every suggestion clap attached (an
/// escape-hatch note, a similar-argument name, a removed-verb
/// redirect), semicolon-joined when several survive. No suggestion
/// means an empty tip: the contract never fabricates advice, the key
/// stays present so a consumer can index both fields blindly.
pub(crate) fn clap_parts(e: &clap::Error) -> (String, String) {
    let message = message_for_kind(e);
    let mut tips: Vec<String> = Vec::new();
    match e.get(ContextKind::SuggestedArg) {
        Some(ContextValue::String(s)) => {
            tips.push(format!("a similar argument exists: '{s}'"));
        }
        Some(ContextValue::Strings(list)) => {
            for s in list {
                tips.push(format!("a similar argument exists: '{s}'"));
            }
        }
        _ => {}
    }
    match e.get(ContextKind::SuggestedSubcommand) {
        Some(ContextValue::String(s)) => {
            tips.push(format!("a similar subcommand exists: '{s}'"));
        }
        Some(ContextValue::Strings(list)) => {
            for s in list {
                tips.push(format!("a similar subcommand exists: '{s}'"));
            }
        }
        _ => {}
    }
    if let Some(ContextValue::String(s)) = e.get(ContextKind::SuggestedCommand) {
        tips.push(format!("a similar command exists: '{s}'"));
    }
    if let Some(ContextValue::StyledStrs(list)) = e.get(ContextKind::Suggested) {
        for styled in list {
            let text = styled.to_string();
            if !text.trim().is_empty() {
                tips.push(text);
            }
        }
    }
    (message, tips.join("; "))
}

/// The verdict sentence for the error's kind, rebuilt from its
/// context — the prose render's opening line, contract-shaped.
fn message_for_kind(e: &clap::Error) -> String {
    let invalid_arg = || match e.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(s)) => Some(s.clone()),
        _ => None,
    };
    match e.kind() {
        clap::error::ErrorKind::UnknownArgument => match invalid_arg() {
            Some(tok) => format!("unexpected argument '{tok}' found"),
            None => e
                .kind()
                .as_str()
                .unwrap_or("unexpected argument")
                .to_string(),
        },
        clap::error::ErrorKind::InvalidSubcommand => match e.get(ContextKind::InvalidSubcommand) {
            Some(ContextValue::String(s)) => format!("unrecognized subcommand '{s}'"),
            _ => e
                .kind()
                .as_str()
                .unwrap_or("unrecognized subcommand")
                .to_string(),
        },
        clap::error::ErrorKind::MissingRequiredArgument => match e.get(ContextKind::InvalidArg) {
            Some(ContextValue::Strings(missing)) => format!(
                "the following required arguments were not provided: {}",
                missing.join(", ")
            ),
            _ => e
                .kind()
                .as_str()
                .unwrap_or("a required argument was not provided")
                .to_string(),
        },
        clap::error::ErrorKind::InvalidValue | clap::error::ErrorKind::ValueValidation => {
            let value = match e.get(ContextKind::InvalidValue) {
                Some(ContextValue::String(s)) => Some(s.clone()),
                _ => None,
            };
            match (invalid_arg(), value) {
                // night-total-hardening-1 (the owner's "leaks bug"):
                // a value-taking flag with NO value is clap's empty-
                // value shape — the prose render says "a value is
                // required ... but none was supplied", and the JSON
                // surface said "invalid value ''" instead (a
                // machine-facing lie about what the user typed: they
                // omitted the value, they did not pass an empty
                // string). The contract renders the same verdict the
                // prose lane renders, byte-for-clap.
                (Some(arg), Some(val)) if val.is_empty() => {
                    format!("a value is required for '{arg}' but none was supplied")
                }
                (Some(arg), Some(val)) => format!("invalid value '{val}' for '{arg}'"),
                _ => e.kind().as_str().unwrap_or("invalid value").to_string(),
            }
        }
        clap::error::ErrorKind::ArgumentConflict => {
            let prior = match e.get(ContextKind::PriorArg) {
                Some(ContextValue::String(s)) => Some(s.clone()),
                Some(ContextValue::Strings(list)) => list.first().cloned(),
                _ => None,
            };
            match (invalid_arg(), prior) {
                (Some(arg), Some(prior)) => {
                    format!("the argument '{arg}' cannot be used with '{prior}'")
                }
                _ => e
                    .kind()
                    .as_str()
                    .unwrap_or("conflicting arguments")
                    .to_string(),
            }
        }
        _ => e
            .kind()
            .as_str()
            .unwrap_or("command line parse failed")
            .to_string(),
    }
}

/// The contract door for the runtime chain (`main`'s anyhow path).
///
/// The branded chain carries its tip embedded — the convention every
/// parse-family error writes as a `\n  tip: ` line
/// (`eprintln_error_labeled` paints grey on the prose lane). The
/// split is the contract's field booking: everything before the first
/// `tip:` line is the error, every later segment joins the tip field
/// (space-joined — one tip, one line, the way the prose render reads).
/// No embedded tip means an empty one, the no-fabrication law above.
pub(crate) fn chain_parts(formatted: &str) -> (String, String) {
    const MARKER: &str = "\n  tip: ";
    match formatted.split_once(MARKER) {
        None => (formatted.to_string(), String::new()),
        Some((body, tail)) => {
            let tip = tail.split(MARKER).collect::<Vec<_>>().join(" ");
            (body.to_string(), tip)
        }
    }
}

// The contract's pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired exactly like the ux and argv tests.
#[cfg(test)]
#[path = "../../test/cli/json_error_tests.rs"]
mod json_error_tests;
