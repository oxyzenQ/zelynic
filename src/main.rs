// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//! zelynic — per-app network rate limiter for Linux
//!
//! Rate-limit and monitor any app's network speed. Pure eBPF, no
//! daemon.

// output must be declared first: the broken-pipe-safe print macros
// (println_safe! / eprintln_safe!) are macro_rules! with textual
// scoping, so every module below sees them without imports.
#[macro_use]
mod output;

mod capabilities;
mod cli;
mod commands;
mod ebpf;
mod info;
// night-dragon-maintenance-T1 (S1): the std-only JSON lane — the
// writer helpers every document lane shares (doctor's report_json
// rides them in EVERY build flavor) and — under the ebpf graph —
// the parse tree (the docker lane's foreign-bytes deserializer +
// the tests' assertion lens). No serde, no serde_json: the
// peak-lean dependency law.
mod json;
#[cfg(feature = "ebpf")]
mod terminal;
// NIGHT-hunt-31: the emergency terminal reset compiles in EVERY
// build (a crate-root module, not a child of the ebpf-gated terminal
// tree — the rescue owns no BPF machinery, and a featureless binary
// must still rescue a terminal some other app broke; see
// src/term_reset/mod.rs for the placement rationale).
mod term_reset;
mod update;

use anyhow::Result;
use clap::Parser;

use cli::Cli;

fn main() {
    if let Err(e) = try_main() {
        // Night-netrunner-5, the JSON error contract's runtime door:
        // the raw argv carried --print-json, so the branded chain
        // renders as the contract object on stdout (exit 1) — the
        // error body and its embedded tip line book into their own
        // fields, the shape a JSON consumer parses without the prose
        // lane's labels.
        let msg = format_error_chain(&e);
        if cli::argv::print_json_requested() {
            let (err, tip) = cli::json_error::chain_parts(&msg);
            cli::json_error::exit_json(&err, &tip);
        }
        // Single branded render + explicit exit 1 (runtime failure —
        // distinct from clap usage errors, which exit 2 inside
        // cli::ux::exit_clap_error). The line-aware renderer paints the
        // "error:" label bold red and the body red; passive "tip:"
        // lines render grey (NIGHT-improve-73 — the same tier the clap
        // surface paints its suggestion candidates), while tips that
        // quote a command to run render green (NIGHT-dinner-12 — the
        // "this is what you type" tier, so the way out of a red block
        // reads as an action).
        // NIGHT-hunt-28: the render carries the FULL cause chain —
        // `format!("{e}")` shows only the outermost context, which
        // turned a load failure into a bare "Failed to load BPF
        // object" while the actual diagnosis (which map, which
        // syscall, which errno) sat invisible in the dropped chain.
        output::eprintln_error_labeled(&msg);
        std::process::exit(1);
    }
}

/// Render an error as its message plus every cause below it, one
/// `caused by:` line per hop (NIGHT-hunt-28).
///
/// anyhow's plain `Display` (what `format!("{e}")` produces) shows only
/// the outermost context — every `.context(...)`/`bail!` layer added
/// along the way is retained on the error but never printed. The
/// labeled renderer is line-aware, so a chain renders as a red block
/// with white `tip:` lines — each hop becomes one line:
///
/// ```text
/// error: Failed to load BPF object
/// caused by: failed to create map `cgroup_limiter_stats` with code -22
/// ```
///
/// Pure function over `anyhow::Error`'s `std::error::Error` source
/// chain, so the shape is unit-pinned below without touching the
/// exit path.
fn format_error_chain(e: &anyhow::Error) -> String {
    let mut msg = format!("{e}");
    let mut source: Option<&dyn std::error::Error> = std::error::Error::source(&**e);
    while let Some(hop) = source {
        msg.push_str("\ncaused by: ");
        msg.push_str(&hop.to_string());
        source = hop.source();
    }
    msg
}

fn try_main() -> Result<()> {
    // NIGHT-improve-73: the forced capability seeds from raw argv
    // BEFORE the parser runs — a usage error exits through
    // `cli::ux::exit_clap_error` before the parsed `--color-mode`
    // field exists, and the clap-rendered error must obey the same
    // capability ladder as every other surface. The scan mirrors
    // clap's assignment (last valid occurrence wins, `--` ends the
    // scan); invalid values never seed here, so `main`'s
    // authoritative check below still owns the grammar error.
    cli::argv::seed_forced_color_mode();

    // Parse through the branded bridge: usage errors get the
    // case-insensitive typo rescue, the real usage line, clap's brand
    // styles, and the canonical help footer — all with exit 2. The
    // top-level --help request goes to stdout with exit 0 through the
    // broken-pipe-safe writer (`zelynic --help | head` truncates
    // instead of panicking). clap generates no help flag of its own
    // (single-tier help surface, NIGHT-improve-3): subcommand-level
    // `--help` is an unknown argument and exits 2 with a suggestion.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => cli::ux::exit_clap_error(e),
    };

    // The diagnostic trace lane (night-dragon-maintenance-xenric-1):
    // arm `-v` once, straight after the parse, before any command
    // surface runs — every later verbose call site reads the output
    // group's static flag instead of threading a bool through the
    // dispatch tree (the zejtron verbose law, one door). Gated like
    // the lane's module: every trace call site lives under the ebpf
    // graph, so the dormant build never arms what it never reads.
    #[cfg(feature = "ebpf")]
    output::verbose::init(cli.verbose);

    // NIGHT-boost-23: --color-mode seeds the forced capability before
    // any output renders — help, errors, and the monitor all answer
    // to one ladder depth. Invalid values die at the input boundary
    // with the allowed grammar, the same exit-2 shape as clap usage
    // errors. (The pre-parse scan in cli::argv already set the same
    // value for the error lane; the OnceLock keeps this authoritative
    // seed idempotent — NIGHT-improve-73.)
    if let Some(mode) = &cli.color_mode {
        match output::parse_color_mode(mode) {
            Ok(cap) => output::set_forced_capability(cap),
            Err(reason) => {
                // Night-netrunner-5: a usage-class input error — the
                // JSON error contract's door rides the same argv scan
                // the clap bridge uses (exit 1 there, the prose lane
                // keeps its own 2).
                if cli::argv::print_json_requested() {
                    cli::json_error::exit_json(&reason, "");
                }
                output::eprintln_error_labeled(&reason);
                std::process::exit(2);
            }
        }
    }

    // NIGHT-boost-24: the early-return surfaces (help, version,
    // check-update, reset-terminal) never render JSON — the flag's
    // honesty note rides stderr BEFORE them, so `zelynic --print-json
    // -V` says why the output is text. stdout and the exit code are
    // untouched.
    if cli.print_json && (cli.help || cli.version || cli.check_update || cli.reset_terminal) {
        cli::warn_print_json_ignored();
    }

    // --help: print the end-to-end reference and exit 0. Checked
    // before every other early return so `zelynic --help` works no
    // matter what follows it (parse errors still fire first — clap
    // must finish parsing before this field can be read).
    if cli.help {
        commands::help::print_help();
        return Ok(());
    }

    if cli.version {
        info::print_version_report();
        return Ok(());
    }

    // NIGHT-hunt-31: --reset-terminal — the emergency five-layer
    // terminal reset (the cosmostrix skill transfer). Early return,
    // before check-update and every command surface: a broken
    // terminal is the one state where the user cannot read anything
    // else this binary might print, and the rescue must not ask for
    // privileges, parse targets, or touch BPF — it touches only the
    // caller's own terminal (ANSI bytes out, termios via ioctl; and
    // under sudo's interposed pty, NIGHT-improve-31, the user's real
    // terminal discovered through the sudo monitor — see
    // src/term_reset/mod.rs for the layer-by-layer contract: the
    // in-process termios restore FIRST — NIGHT-improve-30, the
    // maturity the first port owed — then the ANSI restore, the
    // ANSI reset, `stty sane`, `reset`/`tput reset`). Silent by
    // design: the shell prompt returning on a clean screen is the
    // feedback.
    if cli.reset_terminal {
        term_reset::reset_terminal_emergency();
        return Ok(());
    }

    if cli.check_update {
        update::check_update(info::VERSION).map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    commands::dispatch(cli)
}

#[cfg(test)]
mod tests {
    use super::format_error_chain;
    use anyhow::{Context, Result};

    /// NIGHT-hunt-28: the chain render must show every context layer,
    /// one `caused by:` line per hop — the exact blind spot that hid
    /// the owner's load-failure diagnosis behind a context string.
    #[test]
    fn error_chain_renders_every_cause_hop() {
        let root = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "operation not permitted (os error 1)",
        );
        let layered: Result<()> = Err(root).context("failed to create map `events`");
        let e = layered
            .expect_err("layered error")
            .context("Failed to load BPF object");

        let msg = format_error_chain(&e);
        assert!(
            msg.starts_with("Failed to load BPF object\ncaused by: "),
            "each hop gets its own caused-by line, got: {msg}"
        );
        assert!(
            msg.contains("failed to create map `events`"),
            "the middle context must survive, got: {msg}"
        );
        assert!(
            msg.contains("operation not permitted"),
            "the root cause must survive, got: {msg}"
        );
        assert_eq!(
            msg.matches("caused by:").count(),
            2,
            "two hops under the top context, got: {msg}"
        );
    }

    /// A bare error (no context layers) renders unchanged — no
    /// dangling "caused by:" line, byte-identical to the old shape.
    #[test]
    fn bare_error_renders_without_chain_lines() {
        let e: anyhow::Error = anyhow::anyhow!("cgroup v2 not found at /sys/fs/cgroup");
        assert_eq!(
            format_error_chain(&e),
            "cgroup v2 not found at /sys/fs/cgroup"
        );
    }
}
