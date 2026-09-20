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
        // NIGHT-hunt-28: the render carries the FULL cause chain —
        // `format!("{e}")` shows only the outermost context, which
        // turned a load failure into a bare "Failed to load BPF
        // object" while the actual diagnosis (which map, which
        // syscall, which errno) sat invisible in the dropped chain.
        let msg = format_error_chain(&e);
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
