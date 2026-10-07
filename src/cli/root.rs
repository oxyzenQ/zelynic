// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the Cli struct and its globals live here since
// the 600-line cap split — the root invocation (globals, version,
// help interception) is one concern; the command surface (the
// Commands enum) is another (surface.rs). Same split discipline as
// styles.rs and scope.rs before it: every consumer import resolves
// identically through the mod.rs re-export.

use clap::Parser;

// The command surface the subcommand field below feeds — the enum
// lives in surface.rs since the 600-line split, re-exported at the
// parent so crate::cli::Commands resolves as it always did.
use crate::cli::surface::Commands;

// The brand styling the #[command(styles = ...)] attribute below
// references — the parent's re-exported theme (ux.rs's docs link the
// same path), the pre-split file's own shape.
use super::clap_styles;

/// zelynic — Per-app network rate limiter and traffic monitor for Linux
///
/// Limit and observe any app's download/upload speed using eBPF —
/// pure kernel enforcement.
#[derive(Parser, Debug)]
#[command(
    name = "zelynic",
    version,
    author = "rezky_nightky (oxyzenQ)",
    about = env!("CARGO_PKG_DESCRIPTION"),
    long_about = None,
    disable_version_flag = true,
    disable_help_flag = true,
    disable_help_subcommand = true,
    propagate_version = true,
    arg_required_else_help = false,
    styles = clap_styles(),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Print the end-to-end reference (usage, commands, examples)
    ///
    /// Single-tier help surface (NIGHT-improve-3): the former
    /// `--help-all` reference and the top-level help are one flag.
    /// `disable_help_flag`/`disable_help_subcommand` above stop clap
    /// from auto-generating its own `--help`/`-h`/`help`
    /// subcommand at every level — this field is the only help surface,
    /// intercepted in `main` to print the curated reference.
    #[arg(short = 'h', long = "help", global = false)]
    pub help: bool,

    /// Print complete version and build information
    ///
    /// Global since NIGHT-boost-12: `-V`/`--version` parse at every
    /// level (`zelynic s brave 550kb -V` prints the banner), closing
    /// the ambiguous usage where a subcommand-position `-V` died on a
    /// misleading `--verbose` tip — the rescue engine's jaro_ci ties
    /// "V" to verbose and version at exactly 0.714 and broke the tie
    /// wrong. Intercepted in `main` before any command dispatch, so
    /// the command never runs.
    #[arg(short = 'V', long = "version", global = true)]
    pub version: bool,

    /// Check the latest upstream GitHub release
    ///
    /// Network surface (NIGHT-hunt-11): the check shells out to curl,
    /// so it must never ride root privileges — `update::check_update`
    /// refuses euid 0 with a "re-run without sudo" tip before any
    /// network I/O happens.
    #[arg(long = "check-update", alias = "check-updated", global = false)]
    pub check_update: bool,

    /// Emergency terminal reset (rescue a broken terminal)
    ///
    /// NIGHT-hunt-31 (the cosmostrix skill transfer, hardened in
    /// NIGHT-improve-30): a terminal left broken by a violent TUI
    /// death (kill -9 outliving every restore path, a stuck sync
    /// mode, a dead app's mouse/kitty modes) is recovered in place —
    /// five defense-in-depth layers: the in-process termios restore
    /// FIRST (the kernel-side raw mode no escape byte reaches, an
    /// ioctl that always completes, applied to /dev/tty when stdin
    /// is redirected), the ANSI restore sequence (every optional
    /// mode off), the ANSI reset (clear screen + scrollback),
    /// `stty sane`, and `reset`/`tput reset` — the ANSI bytes riding
    /// a non-blocking best-effort write so a jammed PTY cannot wedge
    /// the rescue. No privileges required: the rescue touches only
    /// the caller's own terminal. Works blind-typed when the
    /// terminal shows nothing: `zelynic --reset-terminal` + Enter.
    #[arg(long = "reset-terminal", global = true)]
    pub reset_terminal: bool,

    /// Diagnostic trace for enforcement internals
    ///
    /// stderr-only trace of what the engine actually decided (NIGHT-hunt-9):
    /// /proc target resolution (pids → cgroups), every policy write
    /// (rate + burst), BPF lifecycle (pin reuse, schema migration, link
    /// mode), and the monitor loader steps. JSON output stays clean.
    ///
    /// NIGHT-boost-6 hardened it into debugging infrastructure: both
    /// loader paths also trace object size, kernel release, load and
    /// attach timings, and the loaded map inventory (id, type,
    /// key/value size, max_entries — the bpftool facts) — on the
    /// stderr side, without leaving the command that failed.
    #[arg(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,

    /// Output as JSON: status, list-apps, eagle-eyes --depth, doctor
    ///
    /// The scripting surface set (NIGHT-boost-24 audit, extended by
    /// NIGHT-master-1): the report commands emit one compact JSON
    /// document each (the stable v11 scripting API, docs/USAGE.md
    /// JSON reference). Every other surface — the enforcement verbs,
    /// the live eagle-eyes monitor, this help, -V, --check-update —
    /// renders text, and the flag answers that honestly: one stderr
    /// note names the honoring surfaces whenever the dispatched
    /// command ignores it (stdout and exit codes are untouched, so
    /// JSON scripts stay clean).
    #[arg(long, global = true)]
    pub print_json: bool,

    /// Force the terminal color depth (default: auto-detect)
    ///
    /// NIGHT-boost-23 (the cosmostrix --color-mode contract): the
    /// capability ladder auto-falls-back per terminal — truecolor
    /// where the environment reports it, the xterm-256 cube, the
    /// classic 16 palette, or mono. Env probes cannot verify
    /// RENDERING though: the classic liar is an inherited COLORTERM
    /// (SSH SendEnv into a terminal that is not truecolor, tmux
    /// passthrough without Tc) — the environment says truecolor, the
    /// terminal garbles the RGB escapes. This flag forces the depth
    /// the terminal actually honors; every surface (errors, help,
    /// the monitor's frame and gradient rails) answers to it.
    /// Allowed: 0 (mono), 16, 8/256 (xterm cube), 24/32 (truecolor).
    #[arg(long = "color-mode", global = true, value_name = "MODE")]
    pub color_mode: Option<String>,
}
