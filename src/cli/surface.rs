// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Limit an app's network speed — one target, a shared group, or
    /// the whole fleet
    ///
    /// NIGHT-improve-53 (the masterclass unification): strict-single
    /// and strict-multi are ONE verb. The single ':' stays INSIDE a
    /// target (the cg: display prefix, the container URIs
    /// docker://nginx and k8s://prod/web-abc) — which is exactly why
    /// the list separator doubles it. The target grammar picks the
    /// lane:
    /// - one target (brave, cg:73386, docker://nginx): the single
    ///   lane, --per-socket's per-connection shape included
    /// - a '::' list (brave::steam::discord): the group lane — one
    ///   shared bucket for every member
    /// - --all (NIGHT-improve-54): the sweep lane — the former
    ///   strict-all verb, every user app at one rate
    ///
    /// Examples:
    ///   zelynic strict brave 100kb                    # both dl+ul = 100kb
    ///   zelynic strict brave -d 100kb -u 500kb        # per-direction
    ///   zelynic strict brave::steam::discord 100kb    # a group sharing one rate
    ///   zelynic s cg:1234::1245 100kb                 # cgroup ids, list form
    ///   zelynic s docker://nginx 100kb                # container target
    ///   zelynic strict nginx 500kb --per-socket       # each connection 500kb
    ///   zelynic s --all 500kb                         # the sweep (see Pro mode)
    ///   zelynic s brave 100kb                         # short alias form
    #[command(name = "strict", alias = "s")]
    Strict {
        /// Target: a process name (brave), cgroup ID (73386 or
        /// cg:73386 — the display prefix round-trips), or container
        /// (docker://nginx) — or a '::'-separated list for the group
        /// lane (brave::steam::discord, cg:1234::1245). Omit it only
        /// on the --all sweep, where a lone positional is the RATE
        /// (zelynic s --all 500kb).
        #[arg(value_name = "TARGET", required_unless_present = "all")]
        target: Option<String>,

        /// Rate for both download+upload (e.g., 100kb, 5.5mb). Use -d/-u for per-direction.
        #[arg(value_name = "RATE")]
        rate: Option<String>,

        /// Download rate limit (e.g., 100kb, 5.5mb; shared across a list)
        #[arg(short = 'd', long = "download")]
        download: Option<String>,

        /// Upload rate limit (e.g., 100kb, 5.5mb; shared across a list)
        #[arg(short = 'u', long = "upload")]
        upload: Option<String>,

        /// The fleet sweep (NIGHT-improve-54): limit EVERY user app
        /// from list-apps at one rate — the former strict-all verb,
        /// now a lane of this one (system apps stay behind
        /// --force-this's guard by default).
        #[arg(long = "all")]
        all: bool,

        /// Override every safety guard: rates below 1kb and the
        /// dangerous/system target blocklist (root, systemd, ...)
        ///
        /// NIGHT-improve-30: the former `--allow-dangerous` (rate
        /// bounds) and `--force` (blocklist) pair is ONE flag — one
        /// spelling for "I know, force this".
        #[arg(long = "force-this")]
        force_this: bool,

        /// Skip the post-apply enforcement test
        ///
        /// charger-core-1-b (the self-proving enforcement): the
        /// apply is verified with a short measured loopback flow
        /// (~3s, the VERIFIED verdict) — this flag keeps the
        /// apply-only shape for scripted use. The test rides every
        /// lane (the list lane measures the first member —
        /// NIGHT-hunt-30's parity find; the sweep measures the first
        /// applied app, standing down honestly when saturated).
        /// NIGHT-improve-54: the flag is --no-test (the former
        /// --no-probe spelling redirects here).
        #[arg(long = "no-test")]
        no_test: bool,

        /// Enforce per SOCKET, not per cgroup (charger-core-3b):
        /// every connection gets its own bucket at the rate — the
        /// server shape (one process, many sockets; the cgroup total
        /// is rate x concurrent sockets, NOT rate). The single lane
        /// only: a '::' list shares one group bucket, so the flag is
        /// refused there (NIGHT-improve-53's routing law).
        #[arg(long = "per-socket")]
        per_socket: bool,

        /// Auto-expire this row (night-during, schema v23; the
        /// owner's duration-only revision): `--during 2h` — a
        /// duration from the apply instant (units s, m, h, d, mn,
        /// y; bounds 1s..5y). After the duration the row lifts
        /// itself.
        ///
        /// The KERNEL decides when the window is over — no daemon,
        /// no cron; every zelynic visit re-stamps the clock bridge.
        #[arg(long = "during", value_name = "DURATION")]
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

        /// Per-DOWNLOAD spelling of --floor (improve-40-b, the
        /// asymmetric link): `--floor-download 100kb` brackets
        /// only the download row. `--floor` sets both; the two
        /// spellings refuse together.
        #[arg(long = "floor-download", value_name = "RATE")]
        floor_download: Option<String>,

        /// Per-UPLOAD spelling of --floor (improve-40-b):
        /// `--floor-upload 50kb` brackets only the upload row.
        #[arg(long = "floor-upload", value_name = "RATE")]
        floor_upload: Option<String>,

        /// Per-DOWNLOAD spelling of --ceil (improve-40-b, the
        /// asymmetric link): `--ceil-download 300kb` caps only
        /// the download row. `--ceil` caps both; the two
        /// spellings refuse together.
        #[arg(long = "ceil-download", value_name = "RATE")]
        ceil_download: Option<String>,

        /// Per-UPLOAD spelling of --ceil (improve-40-b):
        /// `--ceil-upload 200kb` caps only the upload row.
        #[arg(long = "ceil-upload", value_name = "RATE")]
        ceil_upload: Option<String>,
    },

    /// Block an app from the internet — one target, a list, or the
    /// whole fleet
    ///
    /// NIGHT-improve-53 (the masterclass unification): block-single
    /// and block-multi are ONE verb, same routing law as strict —
    /// '::' is the list separator, a single ':' stays inside a
    /// target (the cg: prefix).
    ///
    /// NIGHT-improve-54: --all is the sweep lane (the former
    /// block-all verb) — every user app blocked at once.
    ///
    /// Examples:
    ///   zelynic block brave
    ///   zelynic block brave::curl::pacman
    ///   zelynic b --all                        # the sweep (see Pro mode)
    ///   zelynic b brave
    #[command(name = "block", alias = "b")]
    Block {
        /// Target: a process name, cgroup ID (cg: prefix accepted)
        /// — or a '::'-separated list (brave::curl::pacman). Omit it
        /// only on the --all sweep (which takes no target at all).
        #[arg(value_name = "TARGET", required_unless_present = "all")]
        target: Option<String>,

        /// The fleet sweep (NIGHT-improve-54): block EVERY user app
        /// from the internet — the former block-all verb, now a lane
        /// of this one (system apps stay behind --force-this's guard
        /// by default).
        #[arg(long = "all")]
        all: bool,

        /// Force block on dangerous/system targets (root, systemd,
        /// ...) — the improve-30 unified override spelling.
        #[arg(long = "force-this")]
        force_this: bool,

        /// Auto-expire the block (night-during, schema v23; the
        /// owner's duration-only revision): a duration from the
        /// apply instant (s m h d mn y, 1s..5y) — the block
        /// lifts itself, no daemon.
        #[arg(long = "during", value_name = "DURATION")]
        during: Option<String>,
    },

    /// Remove rate limit(s) — one target, a list, or the whole
    /// fleet
    ///
    /// NIGHT-improve-53 (the masterclass unification): unstrict-single
    /// and unstrict-multi are ONE verb, same routing law as strict —
    /// '::' is the list separator. The container references strict
    /// accepts round-trip here too (docker://nginx).
    ///
    /// NIGHT-improve-54: --all is the emergency reset (the former
    /// unstrict-all verb) — every limit on the machine, gone.
    ///
    /// Examples:
    ///   zelynic unstrict brave
    ///   zelynic unstrict brave::curl::pacman
    ///   zelynic u --all                        # emergency reset (see Pro mode)
    ///   zelynic u brave
    #[command(name = "unstrict", alias = "u")]
    Unstrict {
        /// Target: process name, cgroup ID (cg: accepted), or
        /// container reference (docker://nginx) — or a
        /// '::'-separated list (brave::curl::pacman). Omit it only
        /// on the --all reset (which takes no target at all).
        #[arg(value_name = "TARGET", required_unless_present = "all")]
        target: Option<String>,

        /// The emergency reset (NIGHT-improve-54): remove EVERY
        /// limit on the machine — the former unstrict-all verb, now
        /// a lane of this one (exits 0 on an already-clean system).
        #[arg(long = "all")]
        all: bool,
    },

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

    /// Check host eBPF support and this binary's build facts.
    ///
    /// The flavor verdict (full-life / half-life) and the eBPF lane
    /// lead; since night-improve-66 the BUILD block follows —
    /// version, commit, variant, build time, the rustc that
    /// compiled this binary, and the optimization profile.
    #[command(name = "doctor")]
    Doctor,

    /// Internal: the enforcement-probe server role. Hidden — spawned
    /// by strict's verification window, never typed by hand.
    #[command(name = "__probe-server", hide = true)]
    ProbeServer {
        /// Port to bind (0 = ephemeral; announced on stdout).
        port: u16,

        /// "dl" blasts / "ul" drains and reports (NIGHT-hunt-Z1).
        mode: String,
    },

    /// Internal: the enforcement-probe client role. Hidden — spawned
    /// by strict's verification window, never typed by hand.
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
