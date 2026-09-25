// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use clap::{Parser, Subcommand};

pub(crate) mod argv;
pub(crate) mod suggestion;
pub(crate) mod ux;

/// zelynic — Per-app network rate limiter and traffic monitor for Linux
///
/// Limit and observe any app's download/upload speed using eBPF. Pure
/// kernel enforcement, no tc/nft. Requires kernel 5.13+ and root.
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
    /// Single-tier help surface (NIGHT-improve-3, cosmostrix v30-simplify
    /// lineage): the former `--help-all` reference and the top-level help
    /// are one flag. `disable_help_flag`/`disable_help_subcommand` above
    /// stop clap from auto-generating its own `--help`/`-h`/`help`
    /// subcommand at every level — this field is the only help surface,
    /// intercepted in `main` to print the curated reference.
    #[arg(short = 'h', long = "help", global = false)]
    pub help: bool,

    /// Print complete version and build information
    ///
    /// Global since NIGHT-boost-12: `-V`/`--version` parse at every
    /// level (`zelynic ss brave 550kb -V` prints the banner), closing
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

    /// Output as JSON: status, list-apps, doctor
    ///
    /// The scripting surface set (NIGHT-boost-24 audit): the three
    /// report commands emit one compact JSON document each (the
    /// stable v11 scripting API, docs/USAGE.md JSON reference). Every
    /// other surface — the enforcement verbs, the eagle-eyes monitor,
    /// this help, -V, --check-update — renders text, and the flag
    /// answers that honestly: one stderr note names the honoring
    /// surfaces whenever the dispatched command ignores it (stdout
    /// and exit codes are untouched, so JSON scripts stay clean).
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
/// feature carries status and list-apps; doctor is always compiled
/// (the capability probe needs no BPF). A featureless build answers
/// with its honest smaller set.
#[cfg(feature = "ebpf")]
const JSON_SURFACE_COMMANDS: &str = "status, list-apps, doctor";
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

// ── Clap brand styling (cosmostrix contract, NIGHT-hunt-5) ─────────────────
//
// Purple brand identity: section headings (Usage, Commands, Options)
// render in bold truecolor purple #A855F7 — the same RGB as the
// [`crate::output`] brand layer, so every purple element in --help,
// -V, and errors uses the exact same value. Literals render bold;
// placeholders stay in the terminal default color.
//
// Style harmony (owner mandate): clap's default styles leave error
// labels plain red and tip/suggestion lines GREEN — hues that disagree
// with the branded error path (error red #FF5A5A, suggestion white
// #DCEBFF, warn yellow #FFEB3C). These entries align clap's error
// rendering with the output-layer semantic palette so both surfaces
// (clap-rendered and ux-rendered) look identical.

use clap::builder::styling::{Color, Effects, RgbColor, Style};
use clap::builder::Styles;

#[must_use]
pub(crate) fn clap_styles() -> Styles {
    Styles::styled()
        .header(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(168, 85, 247)))),
        )
        .usage(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(168, 85, 247)))),
        )
        .literal(Style::new().effects(Effects::BOLD))
        .placeholder(Style::new())
        .error(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(255, 90, 90)))),
        )
        .valid(Style::new().fg_color(Some(Color::Rgb(RgbColor(220, 235, 255)))))
        .invalid(Style::new().fg_color(Some(Color::Rgb(RgbColor(255, 235, 60)))))
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Limit a single app's network speed
    ///
    /// 'strict' is the shorthand for this command (NIGHT-hunt-10: the
    /// missing bare verb made owners type `zelynic strict brave` into
    /// an unrecognized-subcommand error). 'ss' is the short alias
    /// (NIGHT-improve-25 — the ten two-letter aliases cover every
    /// enforcement verb).
    ///
    /// Examples:
    ///   zelynic strict-single brave 100kb              # both dl+ul = 100kb
    ///   zelynic strict-single brave -d 100kb           # download only
    ///   zelynic strict-single brave -u 500kb           # upload only
    ///   zelynic strict-single firefox -d 1mb -u 500kb  # both, different rates
    ///   zelynic strict brave -d 1mb                    # shorthand form
    ///   zelynic ss brave 100kb                         # short alias form
    #[command(name = "strict-single", alias = "strict", alias = "ss")]
    StrictSingle {
        /// Target: process name (e.g., brave) or cgroup ID (e.g., 73386,
        /// or cg:73386 — the prefix every display surface prints round-trips)
        target: String,

        /// Rate for both download+upload (e.g., 100kb, 5.5mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (e.g., 100kb, 5.5mb)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (e.g., 100kb, 5.5mb)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Override every safety guard: rates below 1kb and the
        /// dangerous/system target blocklist (root, systemd, kthreadd, etc.)
        ///
        /// NIGHT-improve-30 (the unified safety override): the former
        /// `--allow-dangerous` (rate bounds) and `--force` (blocklist)
        /// pair is ONE flag with the same function — one spelling for
        /// "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,
    },

    /// Limit multiple apps sharing one rate (group limit)
    ///
    /// All apps in the group collectively share the rate limit.
    /// If one app downloads at full rate, others get nothing.
    ///
    /// Examples:
    ///   zelynic strict-multi brave:curl:pacman 1mb              # both dl+ul = 1mb
    ///   zelynic strict-multi brave:curl -d 1mb -u 500kb         # per-direction
    ///   zelynic sm brave:curl:pacman 1mb                        # short alias form
    #[command(name = "strict-multi", alias = "sm")]
    StrictMulti {
        /// Targets separated by colons (e.g., brave:curl:pacman)
        targets: String,

        /// Rate for both download+upload (e.g., 5.5mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (shared across all targets)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (shared across all targets)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Override every safety guard: rates below 1kb and the
        /// dangerous/system target blocklist (root, systemd, kthreadd, etc.)
        ///
        /// NIGHT-improve-30 (the unified safety override): the former
        /// `--allow-dangerous` (rate bounds) and `--force` (blocklist)
        /// pair is ONE flag with the same function — one spelling for
        /// "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,
    },

    /// Limit ALL user apps from list-apps
    ///
    /// Applies the same rate to all non-system apps.
    /// System apps (root, systemd, kthreadd, etc.) are excluded by default.
    /// Use --force-this to include system apps.
    ///
    /// Examples:
    ///   zelynic limit-all 500kb              # limit all user apps
    ///   zelynic limit-all -d 1mb -u 500kb    # per-direction
    ///   zelynic la 500kb                     # short alias form
    #[command(name = "limit-all", alias = "la")]
    LimitAll {
        /// Rate for both download+upload (e.g., 500kb, 5.5mb)
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Override every safety guard: rates below 1kb and the
        /// dangerous/system target blocklist (root, systemd, kthreadd, etc.)
        ///
        /// NIGHT-improve-30 (the unified safety override): the former
        /// `--allow-dangerous` (rate bounds) and `--force` (blocklist)
        /// pair is ONE flag with the same function — one spelling for
        /// "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,
    },

    /// Block multiple apps from the internet entirely
    ///
    /// Example: zelynic block-multi brave:curl:pacman
    #[command(name = "block-multi", alias = "bm")]
    BlockMulti {
        /// Targets separated by colons (e.g., brave:curl:pacman)
        targets: String,

        /// Force block on dangerous/system targets (root, systemd,
        /// kthreadd, etc.) — the NIGHT-improve-30 unified override
        /// spelling (the former `--force`).
        #[arg(long = "force-this")]
        force_this: bool,
    },

    /// Block ALL user apps from the internet
    ///
    /// System apps excluded by default. Use --force-this to include.
    #[command(name = "block-all", alias = "ba")]
    BlockAll {
        /// Include system/dangerous targets (root, systemd,
        /// kthreadd, etc.) — the NIGHT-improve-30 unified override
        /// spelling (the former `--force`).
        #[arg(long = "force-this")]
        force_this: bool,
    },

    /// Block an app from accessing the internet entirely
    ///
    /// Example: zelynic block-single brave
    #[command(name = "block-single", alias = "bs")]
    BlockSingle {
        /// Target: process name or cgroup ID (cg: prefix accepted)
        target: String,

        /// Force block on dangerous/system targets (root, systemd,
        /// kthreadd, etc.) — the NIGHT-improve-30 unified override
        /// spelling (the former `--force`).
        #[arg(long = "force-this")]
        force_this: bool,
    },

    /// Remove rate limit(s) from a target
    ///
    /// 'unstrict' is the shorthand that mirrors the strict / strict-single
    /// pair (NIGHT-hunt-10 introduced the alias; NIGHT-hunt-16 flipped the
    /// canonical to unstrict-single so the strict and unstrict families
    /// read symmetrically: canonical always carries the -single suffix).
    /// 'us' is the short alias (NIGHT-improve-25).
    ///
    /// Example: zelynic unstrict-single brave
    #[command(name = "unstrict-single", alias = "unstrict", alias = "us")]
    Unstrict {
        /// Target: process name or cgroup ID (cg: prefix accepted)
        target: String,
    },

    /// Remove rate limits from multiple apps at once
    ///
    /// Mirrors strict-multi's colon syntax (NIGHT-hunt-10): the unstrict
    /// family previously had no multi form, so bulk removal meant either
    /// repeated single calls or the unstrict-all sledgehammer.
    ///
    /// Example: zelynic unstrict-multi brave:curl:pacman
    #[command(name = "unstrict-multi", alias = "um")]
    UnstrictMulti {
        /// Targets separated by colons (e.g., brave:curl:pacman)
        targets: String,
    },

    /// Remove ALL rate limits (emergency reset)
    #[command(name = "unstrict-all", alias = "ua")]
    UnstrictAll,

    /// Recover from crash — clean orphaned BPF pins
    ///
    /// If zelynic was killed (SIGKILL, OOM, power loss) mid-operation,
    /// orphaned pin files may remain. This command detects and removes
    /// them. Safe to run anytime — does nothing if state is clean.
    #[command(name = "recover")]
    Recover,

    /// Show active limits and watchdog status
    #[command(name = "status")]
    Status,

    /// List apps with their cgroup IDs
    #[command(name = "list-apps")]
    ListApps,

    /// The unified live monitor (NIGHT-boost-1: observe + top merged)
    ///
    /// One surface, three depths — the former `observe` and `top`
    /// pair was two views of the same observer; eagle-eyes is both,
    /// chosen automatically:
    /// - no targets: every app RANKED by session accumulation
    ///   highest first. The row count follows the terminal height
    ///   (no --limit): a short window shows the top few, a tall one
    ///   spans the list low to high.
    /// - one target: the deep focus view — per-direction deltas,
    ///   rate, lifetime, and every socket endpoint inside the
    ///   cgroup.
    /// - slash-separated targets: the ranked table filtered to that
    ///   set of apps/cgroups.
    ///
    /// Each target is autodetected (same rule as strict/block):
    /// all digits = cgroup ID (find one with list-apps), the
    /// display prefix cg:73386 round-trips, anything
    /// else = process name — `eagle-eyes 12345/brave/firefox`
    /// watches all three at once.
    ///
    /// Always live (NIGHT-hunt-12): the box refreshes until you
    /// quit. Exit with q (the only quit key, NIGHT-hunt-16).
    /// `--interval` (NIGHT-hunt-7) is the refresh cadence, 1s..60s,
    /// default 1s — realtime precision.
    ///
    /// 'ee' is the short alias (NIGHT-improve-25). The former
    /// singular 'eagle-eye' alias is REMOVED — one canonical name,
    /// one short form — and typing it lands on the redirect tip
    /// pointing here (same contract observe/top got when they
    /// merged in).
    ///
    /// Examples:
    ///   zelynic eagle-eyes                        # all apps, ranked, q to quit
    ///   zelynic eagle-eyes brave                  # watch one app (deep view)
    ///   zelynic eagle-eyes 12345/brave/firefox    # watch specific targets
    ///   zelynic eagle-eyes --interval 3s          # calmer cadence
    ///   zelynic ee brave --interval 1s            # short alias form
    #[command(name = "eagle-eyes", alias = "ee")]
    EagleEyes {
        /// Targets: process names or cgroup IDs, slash-separated
        /// (e.g., brave, 73386, cg:73386, 12345/brave/firefox).
        /// Omit to watch all.
        #[arg(value_name = "TARGETS")]
        targets: Option<String>,

        /// Refresh interval: 1s to 60s (default: 1s)
        #[arg(long)]
        interval: Option<String>,
    },

    /// Check if your machine supports eBPF
    #[command(name = "doctor")]
    Doctor,
}

// NIGHT-boost-24: the --print-json scope pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// argv and ux tests.
#[cfg(test)]
#[path = "../../test/cli/print_json_tests.rs"]
mod print_json_tests;
