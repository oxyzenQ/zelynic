// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum Commands {
    // The operator-facing voice (night-cafe-1, F10 — the owner's
    // call): the long help speaks plain operator English (the
    // eagle-eyes surface's own voice) and the example rails keep
    // their line structure (verbatim_doc_comment — clap no longer
    // re-wraps the block into one paragraph). The lineage lives here
    // and in docs/tests, never in the operator's terminal:
    // NIGHT-improve-53 (the masterclass unification) made
    // strict-single and strict-multi ONE verb — the single ':' stays
    // INSIDE a target (the cg: display prefix, the container URIs
    // docker://nginx and k8s://prod/web-abc), which is exactly why
    // the list separator doubles it. NIGHT-improve-54 merged the
    // strict-all verb into the --all lane.
    /// Limit an app's network speed — one target, a shared group, or the whole fleet
    ///
    /// The target picks the lane:
    ///
    ///   one target (brave, cg:73386, docker://nginx) — the single
    ///   lane, --per-socket's per-connection shape included
    ///
    ///   a '::' list (brave::steam::discord) — the group lane, one
    ///   shared bucket for every member
    ///
    ///   --all — the sweep lane, every user app at one rate
    ///
    /// Examples:
    ///
    ///   zelynic strict brave 100kb                   both dl+ul = 100kb
    ///   zelynic strict brave -d 100kb -u 500kb       per-direction
    ///   zelynic strict brave::steam::discord 100kb   a group sharing one rate
    ///   zelynic s cg:1234::1245 100kb                cgroup ids, list form
    ///   zelynic s docker://nginx 100kb               container target
    ///   zelynic strict nginx 500kb --per-socket      each connection 500kb
    ///   zelynic s --all 500kb                        the sweep
    ///   zelynic s brave 100kb                        short alias form
    #[command(name = "strict", alias = "s", verbatim_doc_comment)]
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

        // NIGHT-improve-54 lineage: the fleet sweep lane (the former
        // strict-all verb) — the codename stays in code, the help
        // speaks operator English (the F10 voice law).
        /// The fleet sweep: limit EVERY user app from list-apps at
        /// one rate (system apps stay behind --force-this's guard by
        /// default).
        #[arg(long = "all")]
        all: bool,

        // NIGHT-improve-30 lineage: the former --allow-dangerous
        // (rate bounds) and --force (blocklist) pair is ONE flag —
        // the codename stays in code, the help speaks operator
        // English.
        /// Override every safety guard: rates below 1kb and the
        /// dangerous/system target blocklist (root, systemd, ...).
        /// The retired --allow-dangerous and --force spellings error
        /// with a tip naming --force-this — one spelling for "I know,
        /// force this".
        #[arg(long = "force-this")]
        force_this: bool,

        // charger-core-1-b lineage (the self-proving enforcement);
        // NIGHT-hunt-30 measured the parity find; NIGHT-improve-54
        // renamed the flag --no-test (the former --no-probe spelling
        // is retired — it errors with a tip naming the new spelling).
        // The codenames stay in code.
        /// Skip the post-apply enforcement test
        ///
        /// The apply is verified with a short measured loopback flow
        /// (~3s, the VERIFIED verdict) — this flag keeps the
        /// apply-only shape for scripted use. The test rides every
        /// lane (the list lane measures the first member; the sweep
        /// measures the first applied app, standing down honestly
        /// when saturated). The retired --no-probe spelling errors
        /// with a tip naming --no-test.
        #[arg(long = "no-test")]
        no_test: bool,

        // charger-core-3b lineage: the per-socket enforcement shape.
        // NIGHT-improve-53: the list lane's routing law. The voice
        // law F10 lands: the lineage lives here, the help speaks
        // operator English.
        /// Enforce per SOCKET, not per cgroup: every connection
        /// gets its own bucket at the rate — the server shape (one
        /// process, many sockets; the cgroup total is rate x
        /// concurrent sockets, NOT rate). The single lane only: a
        /// '::' list shares one group bucket, so the flag is refused
        /// there (the list lane's routing law); the --all sweep is
        /// refused too — one group row per app, no per-connection
        /// shape fleet-wide.
        #[arg(long = "per-socket")]
        per_socket: bool,

        // night-during (schema v23) lineage: the owner's duration-only
        // revision — the codename stays in code.
        /// Auto-expire this row: `--during 2h` — a duration from
        /// the apply instant (units s, m, h, d, mn, y; bounds
        /// 1s..5y). After the duration the row lifts itself.
        ///
        /// The KERNEL decides when the window is over — no daemon,
        /// no cron; every zelynic visit re-stamps the clock bridge.
        #[arg(long = "during", value_name = "DURATION")]
        during: Option<String>,

        /// Per-LEAF guaranteed minimum: every subprocess under the
        /// target is guaranteed at least RATE of the shared budget
        /// — however greedy its siblings. `--floor 100kb`
        ///
        /// A PRIORITY, not a reservation: idle leaves lend their
        /// unspent share back (the pool's own accumulation is the
        /// lender). Over-subscribed floors degrade gracefully to
        // improve-40 (schema v24) lineage: the per-leaf bracket
        // family — the codename stays in code (the F10 voice law).
        /// the fair split (the pool never creates budget).
        #[arg(long = "floor", value_name = "RATE")]
        floor: Option<String>,

        /// Per-LEAF maximum: no subprocess may exceed RATE even
        /// when its siblings are idle and the pool is rich.
        /// `--ceil 300kb`
        ///
        /// Binds even a lone subprocess (a cap that folds when
        /// siblings appear is not a cap); the banking bound
        // improve-40 (schema v24) lineage: the per-leaf bracket
        // family — the codename stays in code (the F10 voice law).
        /// tightens to the ceiling's own quantum.
        #[arg(long = "ceil", value_name = "RATE")]
        ceil: Option<String>,

        /// Per-DOWNLOAD spelling of --floor: `--floor-download
        /// 100kb` brackets only the download row. `--floor` sets
        /// both; the two spellings refuse together.
        // improve-40-b lineage: the asymmetric link spellings — the
        // codename stays in code (the F10 voice law).
        #[arg(long = "floor-download", value_name = "RATE")]
        floor_download: Option<String>,

        /// Per-UPLOAD spelling of --floor: `--floor-upload 50kb`
        /// brackets only the upload row.
        // improve-40-b lineage: the asymmetric link spellings.
        #[arg(long = "floor-upload", value_name = "RATE")]
        floor_upload: Option<String>,

        /// Per-DOWNLOAD spelling of --ceil: `--ceil-download 300kb`
        /// caps only the download row. `--ceil` caps both; the two
        /// spellings refuse together.
        // improve-40-b lineage: the asymmetric link spellings.
        #[arg(long = "ceil-download", value_name = "RATE")]
        ceil_download: Option<String>,

        /// Per-UPLOAD spelling of --ceil: `--ceil-upload 200kb`
        /// caps only the upload row.
        // improve-40-b lineage: the asymmetric link spellings.
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
    /// Targets ride the same grammar strict carries: the single lane
    /// accepts a container reference (docker://nginx,
    /// k8s://prod/web-abc, netns://sandbox, iface://red) exactly
    /// like strict's apply — the container gets its own block.
    ///
    /// Examples:
    ///   zelynic block brave
    ///   zelynic block brave::curl::pacman
    ///   zelynic b docker://nginx               # container target
    ///   zelynic b --all                        # the sweep (see Pro mode)
    ///   zelynic b brave
    #[command(name = "block", alias = "b")]
    Block {
        /// Target: a process name, cgroup ID (cg: prefix accepted),
        /// or container reference (docker://nginx) — or a
        /// '::'-separated list (brave::curl::pacman). Omit it
        /// only on the --all sweep (which takes no target at all).
        #[arg(value_name = "TARGET", required_unless_present = "all")]
        target: Option<String>,

        /// The fleet sweep: block EVERY user app from the internet
        /// — the former block-all verb, now a lane of this one
        /// (system apps stay behind --force-this's guard by
        /// default).
        ///
        /// NIGHT-improve-54: the fleet sweep lane (the former
        /// block-all verb).
        #[arg(long = "all")]
        all: bool,

        /// Force block on dangerous/system targets (root, systemd,
        /// ...) — the unified override spelling.
        ///
        /// NIGHT-improve-30: the unified override spelling (the
        /// former --allow-dangerous/--force pair).
        #[arg(long = "force-this")]
        force_this: bool,

        /// Auto-expire the block: a duration from the apply instant
        /// (s m h d mn y, 1s..5y) — the block lifts itself, no
        /// daemon.
        ///
        /// night-during, schema v23: the owner's duration-only
        /// revision.
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

        /// The emergency reset: remove EVERY limit on the machine
        /// — the former unstrict-all verb, now a lane of this one
        /// (exits 0 on an already-clean system).
        ///
        /// NIGHT-improve-54: the emergency reset lane (the former
        /// unstrict-all verb).
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

    /// Show active limits and watchdog status (--print-json for the
    /// JSON line)
    #[command(name = "status")]
    Status,

    /// List apps with their cgroup IDs (--print-json for the JSON
    /// line)
    #[command(name = "list-apps")]
    ListApps,

    /// The unified live monitor — every app ranked, one app in
    /// focus, or a filtered set. Always live; q to quit.
    ///
    /// One surface, three depths, chosen by the targets: with no
    /// targets every app is ranked by session traffic, highest
    /// first (the row count follows the terminal height); a single
    /// target opens the deep focus view — per-direction rates,
    /// lifetime, and every socket endpoint inside the cgroup;
    /// several slash-separated targets filter the ranked table to
    /// that set.
    ///
    /// Targets autodetect like strict/block: all digits (or the
    /// cg:<id> display prefix) are a cgroup ID, anything else a
    /// process name — `eagle-eyes 12345/brave/firefox` watches all
    /// three at once.
    ///
    /// --depth switches to the one-shot deep inspection: the full
    /// report (package, user, cgroup path, enforcement accounting,
    /// the per-process census, the live sockets, the traffic
    /// window) prints once and exits — pipe-friendly, --print-json
    /// for the machine-readable document.
    ///
    /// Keys: q quits (the only quit key), t cycles the theme, the
    /// arrows scroll. Full contract: docs/USAGE.md, "eagle-eyes".
    #[command(name = "eagle-eyes", alias = "ee")]
    EagleEyes {
        /// Targets: app names or cgroup IDs, slash-separated
        /// (brave, 73386, cg:73386, 12345/brave/firefox)
        ///
        /// A name carrying '/' cannot ride the slash list — kernel
        /// threads are named that way (napi/phy0-0) — so watch one by
        /// its cg:<id> from list-apps.
        #[arg(value_name = "TARGETS")]
        targets: Option<String>,

        /// Refresh interval: 1s to 60s (default: 1s)
        #[arg(long)]
        interval: Option<String>,

        /// The traffic window for --depth: 1s to 30s (default: 3s)
        ///
        /// Ignored on the live monitor (one stderr note). Full
        /// contract: docs/USAGE.md, "eagle-eyes --depth".
        #[arg(long = "focus", value_name = "SECONDS")]
        focus: Option<String>,

        /// One-shot deep inspection: print the full report, then
        /// exit
        ///
        /// No TUI, no interactive gate: pipe-friendly, JSON-capable
        /// via --print-json. Full contract: docs/USAGE.md,
        /// "eagle-eyes --depth".
        #[arg(long = "depth")]
        depth: bool,

        /// Deep figures on the live monitor: per-row rtt ± jitter
        /// and the retransmit share
        ///
        /// The figures refresh on the walk's 3s TTL — snapshot truth
        /// at the cadence it is honest at; UDP renders
        /// [encrypted/quic], raw [no l4 truth], never a fabricated
        /// zero. Orthogonal to --depth (the one-shot report) and
        /// --focus (the depth window).
        #[arg(long = "deep")]
        deep: bool,
    },

    /// Check host eBPF support and this binary's build facts
    /// (--print-json for the JSON line).
    ///
    /// The flavor verdict (full-life / half-life) and the eBPF lane
    /// lead; since night-improve-66 the BUILD block follows —
    /// version, commit, variant, build time, the rustc that
    /// compiled this binary, and the optimization profile.
    #[command(name = "doctor")]
    Doctor,

    /// Render the provenance depth matrix — the six-depth signature
    /// report over the masked identity layers, the embedded kernel
    /// objects, and the build's commit-signature binding.
    ///
    /// night-signature-advanced-1 (the cosmostrix `sig` shape, the
    /// owner's cross-tool contract): D0 runtime-identity, D1
    /// embedded-marker, D2 anchor-integrity (the blake3 seal), D3
    /// binary-self-hash (the fingerprint to compare against a
    /// published release hash), plus zelynic's own D4 object-integrity
    /// (night-depth-hardening-Z2: the embedded eBPF objects re-hashed
    /// against their build-time digest stamps) and D5
    /// commit-signature (night-solid-defense-2: the claimed commit
    /// verified GPG-signed by the pinned maintainer key at build
    /// time). Exits 1 when any depth fails, so a script can gate on
    /// the verdict.
    #[command(name = "sig")]
    Sig,

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
