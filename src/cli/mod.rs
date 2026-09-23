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

    /// Output as JSON (where applicable)
    #[arg(long, global = true)]
    pub print_json: bool,
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
        /// Target: process name (e.g., brave) or cgroup ID (e.g., 73386)
        target: String,

        /// Rate for both download+upload (e.g., 100kb, 1mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (e.g., 100kb, 1mb)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (e.g., 100kb, 1mb)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Allow rates below 1kb (dangerous)
        #[arg(long)]
        allow_dangerous: bool,

        /// Force limit on dangerous/system targets (root, systemd, kthreadd, etc.)
        #[arg(long)]
        force: bool,
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

        /// Rate for both download+upload (e.g., 1mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (shared across all targets)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (shared across all targets)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Allow rates below 1kb (dangerous)
        #[arg(long)]
        allow_dangerous: bool,

        /// Force limit on dangerous/system targets (root, systemd, kthreadd, etc.)
        #[arg(long)]
        force: bool,
    },

    /// Limit ALL user apps from list-apps
    ///
    /// Applies the same rate to all non-system apps.
    /// System apps (root, systemd, kthreadd, etc.) are excluded by default.
    /// Use --force to include system apps.
    ///
    /// Examples:
    ///   zelynic limit-all 500kb              # limit all user apps
    ///   zelynic limit-all -d 1mb -u 500kb    # per-direction
    ///   zelynic la 500kb                     # short alias form
    #[command(name = "limit-all", alias = "la")]
    LimitAll {
        /// Rate for both download+upload (e.g., 500kb, 1mb)
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// Allow rates below 1 kb (dangerous)
        #[arg(long)]
        allow_dangerous: bool,

        /// Include system/dangerous targets (root, systemd, kthreadd, etc.)
        #[arg(long)]
        force: bool,
    },

    /// Block multiple apps from the internet entirely
    ///
    /// Example: zelynic block-multi brave:curl:pacman
    #[command(name = "block-multi", alias = "bm")]
    BlockMulti {
        /// Targets separated by colons (e.g., brave:curl:pacman)
        targets: String,

        /// Force block on dangerous/system targets
        #[arg(long)]
        force: bool,
    },

    /// Block ALL user apps from the internet
    ///
    /// System apps excluded by default. Use --force to include.
    #[command(name = "block-all", alias = "ba")]
    BlockAll {
        /// Include system/dangerous targets
        #[arg(long)]
        force: bool,
    },

    /// Block an app from accessing the internet entirely
    ///
    /// Example: zelynic block-single brave
    #[command(name = "block-single", alias = "bs")]
    BlockSingle {
        /// Target: process name or cgroup ID
        target: String,

        /// Force block on dangerous/system targets
        #[arg(long)]
        force: bool,
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
        /// Target: process name or cgroup ID
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
    /// all digits = cgroup ID (find one with list-apps), anything
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
        /// (e.g., brave, 73386, 12345/brave/firefox). Omit to watch all.
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
