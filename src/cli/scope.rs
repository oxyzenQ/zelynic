// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The --print-json scope contract (NIGHT-private-research-3's
//! LOC-cap split of cli/mod.rs — the second split after styles, one
//! theme, one concern): which commands honor the JSON flag, the
//! ignored-flag note, and the stderr warning. The re-export surface
//! in cli/mod.rs is unchanged, so every consumer import (commands,
//! main, the pin family) resolves identically.

use super::Commands;

// ── --print-json scope contract (NIGHT-boost-24) ───────────────────
//
// The owner audit question: "is --print-json useless because it only
// works with status?" It is not — THREE surfaces honor it — but the
// flag was a SILENT no-op everywhere else (strict, block, unstrict,
// recover, eagle-eyes, -h, -V, --check-update): a user asking for
// machine-readable output got text with no signal why. The cosmostrix
// honesty contract (its ignored-flag warns, e.g. "--json ignored
// (--bench-frames emits the text BENCH: format)") closes the gap: one
// stderr line names the JSON surfaces whenever the flag rides a
// surface that ignores it. stderr only, never stdout — scripts
// parsing `status --print-json` output are untouched, and the exit
// codes never move.

/// The commands that honor `--print-json` in THIS build: the ebpf
/// feature carries status, list-apps, and the eagle-eyes --depth
/// one-shot report; doctor is always compiled (the capability probe
/// needs no BPF). A featureless build answers with its honest
/// smaller set.
#[cfg(feature = "ebpf")]
const JSON_SURFACE_COMMANDS: &str = "status, list-apps, eagle-eyes --depth, doctor";
#[cfg(not(feature = "ebpf"))]
const JSON_SURFACE_COMMANDS: &str = "doctor";

/// Does the dispatched command honor `--print-json`? `None` is the
/// no-subcommand help fallback — text, like every non-report surface.
#[must_use]
pub(crate) fn command_honors_print_json(command: Option<&Commands>) -> bool {
    match command {
        Some(Commands::Doctor) => true,
        #[cfg(feature = "ebpf")]
        Some(Commands::Status | Commands::ListApps) => true,
        // NIGHT-master-1: only the one-shot depth report is a JSON
        // surface — the live TUI monitor stays text (its interactive
        // gate is the pipe's answer).
        #[cfg(feature = "ebpf")]
        Some(Commands::EagleEyes { depth: true, .. }) => true,
        _ => false,
    }
}

/// The ignored-flag note (pure, so the exact wording is unit-pinnable
/// — it is the contract a script owner reads once and trusts).
#[must_use]
pub(crate) fn print_json_ignored_note() -> String {
    format!("--print-json ignored (JSON surface: {JSON_SURFACE_COMMANDS})")
}

/// Emit the ignored-flag note on stderr: warn yellow, one line, the
/// same broken-pipe-safe write path every diagnostic uses.
pub(crate) fn warn_print_json_ignored() {
    eprintln_safe!("{}", crate::output::warn_bold(&print_json_ignored_note()));
}
