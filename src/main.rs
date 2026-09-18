// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! zelynic — Per-app network rate limiter and traffic monitor for Linux
//!
//! Limit and observe any app's download/upload speed using eBPF.
//! Pure kernel enforcement.

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
#[cfg(feature = "ebpf")]
mod terminal;
mod update;

use anyhow::Result;
use clap::Parser;

use cli::Cli;

fn main() {
    if let Err(e) = try_main() {
        // Single branded render + explicit exit 1 (runtime failure —
        // distinct from clap usage errors, which exit 2 inside
        // cli::ux::exit_clap_error). The line-aware renderer paints the
        // "error:" label bold red and embedded "tip:" lines white.
        let msg = format!("{e}");
        output::eprintln_error_labeled(&msg);
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
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

    if cli.check_update {
        update::check_update(info::VERSION).map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    commands::dispatch(cli)
}
