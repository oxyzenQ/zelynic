// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
// LOC_EXEMPT: the Commands enum is one clap surface by design — split twice already (styles, scope moved out); the enum itself and the Cli struct it feeds are the irreducible CLI declaration, and the persistence pair's help docs plus the night-during --during family (six subcommands) pushed the cohesive unit over the 500 cap
use clap::{Parser, Subcommand};

pub(crate) mod argv;
pub(crate) mod styles;
pub(crate) mod suggestion;
pub(crate) mod tips;
pub(crate) mod ux;

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

// The clap brand-styling block lives in cli/styles.rs since
// NIGHT-master-1 (the depth surface's docs pushed this file past the
// 500-line cap) — one theme, one concern, re-exported for the
// `#[command(styles = ...)]` attribute below.
pub(crate) use styles::clap_styles;

// The --print-json scope contract lives in cli/scope.rs since
// NIGHT-private-research-3 (the --focus field's docs pushed this file
// past the cap again) — same split discipline, same re-export shape:
// every consumer import resolves identically.
mod scope;
pub(crate) use scope::{command_honors_print_json, warn_print_json_ignored};

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Limit a single app's network speed
    ///
    /// 'strict' is the shorthand (NIGHT-hunt-10: the missing bare
    /// verb made owners type `zelynic strict brave` into an error).
    /// 'ss' is the short alias (NIGHT-improve-25 — the ten two-letter
    /// aliases cover every enforcement verb).
    ///
    /// Examples:
    ///   zelynic strict-single brave 100kb              # both dl+ul = 100kb
    ///   zelynic strict-single brave -d 100kb           # download only
    ///   zelynic strict-single brave -u 500kb           # upload only
    ///   zelynic strict-single firefox -d 1mb -u 500kb  # both, different rates
    ///   zelynic ss docker://nginx 100kb                # container target
    ///   zelynic strict-single nginx 500kb --per-socket # each connection 500kb
    ///   zelynic strict brave -d 1mb                    # shorthand form
    ///   zelynic ss brave 100kb                         # short alias form
    #[command(name = "strict-single", alias = "strict", alias = "ss")]
    StrictSingle {
        /// Target: process name (brave), cgroup ID (73386 or cg:73386 —
        /// the display prefix round-trips), or container (docker://nginx)
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
        /// dangerous/system target blocklist (root, systemd, ...)
        ///
        /// NIGHT-improve-30: the former `--allow-dangerous` (rate
        /// bounds) and `--force` (blocklist) pair is ONE flag — one
        /// spelling for "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,

        /// Skip the post-apply enforcement probe
        ///
        /// charger-core-1-b (the self-proving enforcement): the
        /// apply is verified with a short measured loopback flow
        /// (~3s, the VERIFIED verdict) — this flag keeps the
        /// apply-only shape for scripted use.
        #[arg(long = "no-probe")]
        no_probe: bool,

        /// Enforce per SOCKET, not per cgroup (charger-core-3b):
        /// every connection gets its own bucket at the rate — the
        /// server shape (one process, many sockets; the cgroup total
        /// is rate x concurrent sockets, NOT rate).
        #[arg(long = "per-socket")]
        per_socket: bool,

        /// Auto-expire or schedule this row (night-during, schema
        /// v23): `--during 09:00-17:00` (UTC daily window, wraps
        /// midnight), `--during 2026-10-15` (the whole UTC day),
        /// or `--during 2h` (duration; units s, m, h, d, mn, y;
        /// bounds 1s..10y)
        ///
        /// The KERNEL decides when the window is over — no daemon,
        /// no cron; every zelynic visit re-stamps the clock bridge.
        #[arg(long = "during", value_name = "WINDOW")]
        during: Option<String>,

        /// Per-LEAF guaranteed minimum (improve-40, schema v24):
        /// every subprocess under the target is guaranteed at
        /// least RATE of the shared budget — however greedy its
        /// siblings. `--floor 100kb`
        ///
        /// A PRIORITY, not a reservation: idle leaves lend their
        /// unspent share back (the pool's own accumulation is the
        /// lender). Over-subscribed floors degrade gracefully to
        /// the fair split (the pool never creates budget).
        #[arg(long = "floor", value_name = "RATE")]
        floor: Option<String>,

        /// Per-LEAF maximum (improve-40, schema v24): no subprocess
        /// may exceed RATE even when its siblings are idle and the
        /// pool is rich. `--ceil 300kb`
        ///
        /// Binds even a lone subprocess (a cap that folds when
        /// siblings appear is not a cap); the banking bound
        /// tightens to the ceiling's own quantum.
        #[arg(long = "ceil", value_name = "RATE")]
        ceil: Option<String>,
    },

    /// Limit multiple apps sharing one rate (group limit)
    ///
    /// All apps collectively share the rate: if one downloads at
    /// full rate, the others get nothing.
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
        /// dangerous/system target blocklist (root, systemd, ...)
        ///
        /// NIGHT-improve-30: `--allow-dangerous` + `--force` are ONE
        /// flag — one spelling for "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,

        /// Auto-expire or schedule this row (night-during, schema
        /// v23): a UTC daily window (`09:00-17:00`), a whole UTC
        /// day (`2026-10-15`), or a duration (`2h`; s m h d mn y,
        /// 1s..10y) — the kernel expires it, no daemon.
        #[arg(long = "during", value_name = "WINDOW")]
        during: Option<String>,

        /// Per-LEAF guaranteed minimum, shared across the group's
        /// targets (improve-40, schema v24): every subprocess under
        /// every member is guaranteed at least RATE. `--floor 100kb`
        ///
        /// A PRIORITY, not a reservation: idle leaves lend their
        /// unspent share back (the pool's own accumulation is the
        /// lender). Over-subscribed floors degrade gracefully to
        /// the fair split (the pool never creates budget).
        #[arg(long = "floor", value_name = "RATE")]
        floor: Option<String>,

        /// Per-LEAF maximum, shared across the group's targets
        /// (improve-40, schema v24): no subprocess may exceed RATE
        /// even when its siblings are idle. `--ceil 300kb`
        ///
        /// Binds even a lone subprocess (a cap that folds when
        /// siblings appear is not a cap); the banking bound
        /// tightens to the ceiling's own quantum.
        #[arg(long = "ceil", value_name = "RATE")]
        ceil: Option<String>,
    },

    /// Limit ALL user apps from list-apps
    ///
    /// Applies the same rate to all non-system apps. System apps
    /// (root, systemd, ...) are excluded by default; --force-this
    /// includes them.
    ///
    /// NIGHT-blade-2: renamed from limit-all/la — the strict family
    /// reads symmetrically end to end (strict-single/ss,
    /// strict-multi/sm, strict-all/sa), the same triple block-all/ba
    /// and unstrict-all/ua carry; the old spellings redirect here
    /// (cli::ux removed-subcommand table).
    ///
    /// Examples:
    ///   zelynic strict-all 500kb              # limit all user apps
    ///   zelynic strict-all -d 1mb -u 500kb    # per-direction
    ///   zelynic sa 500kb                      # short alias form
    #[command(name = "strict-all", alias = "sa")]
    StrictAll {
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
        /// dangerous/system target blocklist (root, systemd, ...)
        ///
        /// NIGHT-improve-30: the former `--allow-dangerous` (rate
        /// bounds) and `--force` (blocklist) pair is ONE flag — one
        /// spelling for "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,

        /// Auto-expire or schedule every row this apply writes
        /// (night-during, schema v23): a UTC daily window
        /// (`09:00-17:00`), a whole UTC day (`2026-10-15`), or a
        /// duration (`2h`; s m h d mn y, 1s..10y).
        #[arg(long = "during", value_name = "WINDOW")]
        during: Option<String>,

        /// Per-LEAF guaranteed minimum, shared across the group's
        /// targets (improve-40, schema v24): every subprocess under
        /// every member is guaranteed at least RATE. `--floor 100kb`
        ///
        /// A PRIORITY, not a reservation: idle leaves lend their
        /// unspent share back (the pool's own accumulation is the
        /// lender). Over-subscribed floors degrade gracefully to
        /// the fair split (the pool never creates budget).
        #[arg(long = "floor", value_name = "RATE")]
        floor: Option<String>,

        /// Per-LEAF maximum, shared across the group's targets
        /// (improve-40, schema v24): no subprocess may exceed RATE
        /// even when its siblings are idle. `--ceil 300kb`
        ///
        /// Binds even a lone subprocess (a cap that folds when
        /// siblings appear is not a cap); the banking bound
        /// tightens to the ceiling's own quantum.
        #[arg(long = "ceil", value_name = "RATE")]
        ceil: Option<String>,
    },

    /// Block multiple apps from the internet entirely
    ///
    /// Example: zelynic block-multi brave:curl:pacman
    #[command(name = "block-multi", alias = "bm")]
    BlockMulti {
        /// Targets separated by colons (e.g., brave:curl:pacman)
        targets: String,

        /// Force block on dangerous/system targets (root, systemd,
        /// ...) — the improve-30 unified override spelling.
        #[arg(long = "force-this")]
        force_this: bool,

        /// Auto-expire or schedule the block (night-during, schema
        /// v23): a UTC daily window (`22:00-06:00` is the bedtime
        /// shape), a whole UTC day, or a duration (s m h d mn y,
        /// 1s..10y) — the block lifts itself, no daemon.
        #[arg(long = "during", value_name = "WINDOW")]
        during: Option<String>,
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

        /// Auto-expire or schedule every block this apply writes
        /// (night-during, schema v23): a UTC daily window, a whole
        /// UTC day, or a duration (s m h d mn y, 1s..10y).
        #[arg(long = "during", value_name = "WINDOW")]
        during: Option<String>,
    },

    /// Block an app from accessing the internet entirely
    ///
    /// Example: zelynic block-single brave
    #[command(name = "block-single", alias = "bs")]
    BlockSingle {
        /// Target: process name or cgroup ID (cg: prefix accepted)
        target: String,

        /// Force block on dangerous/system targets (root, systemd,
        /// ...) — the improve-30 unified override spelling.
        #[arg(long = "force-this")]
        force_this: bool,

        /// Auto-expire or schedule the block (night-during, schema
        /// v23): a UTC daily window (`22:00-06:00` is the bedtime
        /// shape), a whole UTC day, or a duration (s m h d mn y,
        /// 1s..10y) — the block lifts itself, no daemon.
        #[arg(long = "during", value_name = "WINDOW")]
        during: Option<String>,
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
        /// Target: process name, cgroup ID (cg: accepted), or container
        /// reference (docker://nginx) — strict-single's grammar
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

    /// Serialize every live limit to the state file (survives reboot)
    ///
    /// The pins already survive process exit; what they cannot survive
    /// is a reboot — bpffs starts empty, and with it every policy. This
    /// verb writes the policy census (who, which direction, what rate,
    /// grouping, per-socket) to /var/lib/zelynic/limits.json, keyed by
    /// NAME (cgroup IDs change across reboots).
    ///
    /// Examples:
    ///   sudo zelynic snapshot                # write the state file
    ///   sudo zelynic snapshot --print-json   # same, plus the document on stdout
    #[command(name = "snapshot")]
    Snapshot,

    /// Re-apply every limit from the state file (idempotent)
    ///
    /// The reboot companion to snapshot: reads the state file and
    /// re-applies every policy through the strict family's own apply
    /// machinery (the rollback ledger, memo invalidation, the whole
    /// ladder). Best-effort with an honest report — a name that is
    /// not running yet (containers start late) is listed as skipped,
    /// never silently missed; re-run restore after it starts to pick
    /// it up. Pairs with a systemd oneshot unit an operator wires —
    /// zelynic ships the verbs, not a daemon.
    ///
    /// Examples:
    ///   sudo zelynic restore                # apply the state file
    ///   sudo zelynic restore --print-json   # machine-readable report
    #[command(name = "restore")]
    Restore,

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
    /// NIGHT-master-1 — `--depth`: the one-shot deep inspection
    /// (the `--info` alias is retired in NIGHT-blade-4 — one
    /// spelling; typing the old flag lands on the vocabulary tip
    /// pointing here). `zelynic ee cg:1234 --depth` prints the full
    /// report — package id and name, the user it runs as, the cgroup
    /// path, the enforcement verdict, the per-process census (type,
    /// permissions, threads, memory, exe path, start time), and the
    /// live sockets — then exits. No TUI, no interactive-stdio gate:
    /// pipe-friendly, and `--print-json` emits the machine-readable
    /// document.
    ///
    /// NIGHT-blade-5 (the depth peak upgrade): a limited target
    /// carries its enforcement ACCOUNTING — what the kernel let
    /// through and dropped, with the drop share; the cgroup
    /// controller's own resource view (resident memory, accumulated
    /// CPU time) rides the summary; the census shows per-process
    /// thread counts and resident memory; and every block ends with
    /// the act-on-this tail — copy-paste limit/block/watch commands
    /// keyed to the exact cgroup the report just dissected.
    ///
    /// Examples:
    ///   zelynic eagle-eyes                        # all apps, ranked, q to quit
    ///   zelynic eagle-eyes brave                  # watch one app (deep view)
    ///   zelynic eagle-eyes 12345/brave/firefox    # watch specific targets
    ///   zelynic eagle-eyes --interval 3s          # calmer cadence
    ///   zelynic ee brave --interval 1s            # short alias form
    ///   zelynic ee cg:1234 --depth                # one-shot deep report
    ///   zelynic ee cg:1234 --depth --focus 5s     # deep report, 5s traffic window
    ///   zelynic ee 12345 --depth --print-json     # the report as JSON
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

        /// The network-traffic focus window for --depth
        /// (NIGHT-private-research-3): 1s to 30s, default 3s — the
        /// report measures what moved per endpoint for this many
        /// seconds. Ignored (one stderr note) on the live monitor.
        /// Full contract: docs/USAGE.md, eagle-eyes --depth.
        #[arg(long = "focus", value_name = "SECONDS")]
        focus: Option<String>,

        /// One-shot deep inspection (NIGHT-master-1): print the full
        /// report — package id/name, user, cgroup path, enforcement
        /// state and its accounting ledger, the cgroup controller's
        /// resource view, the per-process census (type, permissions
        /// with the special bits, state, threads, memory, exe path
        /// with the deleted-on-disk marker), the network-traffic
        /// focus section (NIGHT-private-research-3), and the
        /// act-on-this tail — then exit. No TUI: pipe-friendly,
        /// JSON-capable via --print-json.
        /// NIGHT-blade-4: the '--info' alias is retired — '--depth'
        /// is the only spelling (the vocabulary rescue redirects it here).
        #[arg(long = "depth")]
        depth: bool,
    },

    /// Check host eBPF support and this binary's build flavor (full-life / half-life).
    #[command(name = "doctor")]
    Doctor,

    /// Internal: the enforcement-probe server role. Hidden — spawned
    /// by strict-single's verification window, never typed by hand.
    #[command(name = "__probe-server", hide = true)]
    ProbeServer {
        /// Port to bind (0 = ephemeral; announced on stdout).
        port: u16,

        /// "dl" blasts / "ul" drains and reports (NIGHT-hunt-Z1).
        mode: String,
    },

    /// Internal: the enforcement-probe client role. Hidden — spawned
    /// by strict-single's verification window, never typed by hand.
    #[command(name = "__probe-client", hide = true)]
    ProbeClient {
        /// The server to connect to (host:port).
        addr: String,

        /// Direction: "dl" (receive and count) or "ul" (send and count).
        mode: String,

        /// The window in seconds.
        secs: u64,
    },
}

// NIGHT-boost-24: the --print-json scope pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// argv and ux tests.
#[cfg(test)]
#[path = "../../test/cli/print_json_tests.rs"]
mod print_json_tests;
