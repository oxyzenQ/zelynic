// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The single help authority for `zelynic --help` and `zelynic man`
//! (NIGHT-improve-3: the former `--help-all` reference and the top-level
//! help merged into one flag, cosmostrix v30-simplify lineage).
//!
//! Both renderers below must stay in sync — same commands, same flags,
//! same examples. The integration tests pin this: every subcommand the
//! CLI exposes must appear in both outputs, so adding a command without
//! updating this module fails the suite.

use crate::output::brand_bold;

/// Print the end-to-end reference: usage, commands, flags, formats,
/// safety guards, and examples.
///
/// Brand identity (cosmostrix help format): the banner and every section
/// heading render in brand purple #A855F7 (bold); all command syntax,
/// examples, and body text stay in the terminal default color so the
/// reference remains readable and diff-friendly when piped.
pub(crate) fn print_help() {
    println_safe!(
        "{}",
        brand_bold("━━━ zelynic — Per-app Network Rate Limiter & Monitor ━━━")
    );
    println_safe!();
    println_safe!("Limit and observe any app's download/upload speed using eBPF.");
    println_safe!("Pure kernel enforcement — no tc, no nft. Requires kernel 5.13+ and root.");
    println_safe!();
    println_safe!("{}", brand_bold("Commands:"));
    println_safe!();
    println_safe!(
        "  zelynic strict-single <target> [rate] [-d <rate>] [-u <rate>] — Limit a single app"
    );
    println_safe!("    sudo zelynic strict-single brave 100kb              # both dl+ul = 100kb");
    println_safe!("    sudo zelynic strict-single brave -d 100kb           # download only");
    println_safe!("    sudo zelynic strict-single brave -u 500kb           # upload only");
    println_safe!(
        "    sudo zelynic strict-single firefox -d 1mb -u 500kb  # both, different rates"
    );
    println_safe!();
    println_safe!("  zelynic strict-multi <a:b:c> [rate] [-d <rate>] [-u <rate>] — Limit multiple apps sharing one rate (group limit)");
    println_safe!("    sudo zelynic strict-multi brave:curl:pacman 1mb");
    println_safe!("    sudo zelynic strict-multi brave:firefox -d 1mb -u 500kb");
    println_safe!("    (all apps collectively share the rate — if one downloads at full");
    println_safe!("     rate, others get nothing)");
    println_safe!();
    println_safe!(
        "  zelynic limit-all [rate] [-d <rate>] [-u <rate>] — Limit ALL user apps from list-apps"
    );
    println_safe!("    sudo zelynic limit-all 500kb              # limit all user apps");
    println_safe!("    sudo zelynic limit-all -d 1mb -u 500kb    # per-direction");
    println_safe!("  zelynic unstrict <target> — Remove limit from one app");
    println_safe!("    sudo zelynic unstrict brave");
    println_safe!();
    println_safe!("  zelynic unstrict-all — Remove ALL limits (emergency reset)");
    println_safe!();
    println_safe!("  zelynic block-single <target> — Block an app from the internet entirely");
    println_safe!("    sudo zelynic block-single brave");
    println_safe!("  zelynic block-multi <a:b:c> — Block multiple apps from internet");
    println_safe!("    sudo zelynic block-multi brave:curl:pacman");
    println_safe!("  zelynic block-all — Block ALL user apps from internet");
    println_safe!("    sudo zelynic block-all                   # all user apps");
    println_safe!("    sudo zelynic block-all --force            # include system apps");
    println_safe!("  zelynic recover — Recover from crash (clean orphaned pins)");
    println_safe!();
    println_safe!("  zelynic status — Show active limits + watchdog status");
    println_safe!("  zelynic list-apps — List apps with cgroup IDs");
    println_safe!("  zelynic observe [--live <dur>] [--cgroup <id>] [--interval <1s-60s>] — Real-time traffic monitor (box mode, in-place)");
    println_safe!("    sudo zelynic observe                    # live forever, q/ESC to quit");
    println_safe!("    sudo zelynic observe --live 3m           # live for 3 minutes");
    println_safe!("    sudo zelynic observe --cgroup 8066       # filter to one cgroup");
    println_safe!("    sudo zelynic observe --interval 5s       # calmer cadence + rate column");
    println_safe!("  zelynic top [--duration <dur>] [--live <dur>] [--limit N] [--interval <1s-60s>] — Find top bandwidth consumers");
    println_safe!("    sudo zelynic top                        # 10s snapshot, top 10");
    println_safe!("    sudo zelynic top --duration 30s         # 30s snapshot");
    println_safe!("    sudo zelynic top --live 5m              # live box mode for 5 min");
    println_safe!("    sudo zelynic top --live 0 --interval 2s # live forever, 2s refresh");
    println_safe!("  zelynic doctor — Check eBPF support");
    println_safe!("  zelynic man — Print the man page (troff, for man/zelynic.1)");
    println_safe!();
    println_safe!("{}", brand_bold("Global flags:"));
    println_safe!("  -h, --help       This end-to-end reference (usage, commands, examples)");
    println_safe!("  -V, --version    Version and build information");
    println_safe!("  --check-update   Check the latest upstream GitHub release");
    println_safe!("  -v, --verbose    Debug output");
    println_safe!("  --print-json     JSON output (where applicable)");
    println_safe!();
    println_safe!("{}", brand_bold("Rate formats:"));
    println_safe!("  500b    1kb    500kb    1mb    1gb    100gb    (lowercase only)");
    println_safe!("  Min: 1kb (1000 b/s, decimal SI)    Max: 100gb (100,000,000,000 b/s)");
    println_safe!("  Both bounds overridable with --allow-dangerous");
    println_safe!("  Color output is always on — set NO_COLOR=1 to disable");
    println_safe!();
    println_safe!("{}", brand_bold("Target formats:"));
    println_safe!("  <process_name>  e.g., brave, firefox, curl");
    println_safe!("  <cgroup_id>     e.g., 73386 (use 'zelynic list-apps' to find)");
    println_safe!();
    println_safe!("{}", brand_bold("Safety:"));
    println_safe!("  • Min-rate guard: rejects < 1kb (use --allow-dangerous)");
    println_safe!(
        "  • Dangerous target warning: {} system processes blocked by default",
        crate::commands::safety::DANGEROUS_TARGETS.len()
    );
    println_safe!("    (use --force to override)");
    println_safe!("  • Fail-safe: BPF returns allow on any error path");
    println_safe!();
    println_safe!("{}", brand_bold("Examples:"));
    println_safe!("  # Limit brave to 100kb/s (both download + upload)");
    println_safe!("  sudo zelynic strict-single brave 100kb");
    println_safe!();
    println_safe!("  # Limit brave download only to 100kb/s");
    println_safe!("  sudo zelynic strict-single brave -d 100kb");
    println_safe!();
    println_safe!("  # Limit download tools to share 1mb/s total");
    println_safe!("  sudo zelynic strict-multi curl:pacman:aria2c 1mb");
    println_safe!();
    println_safe!("  # Limit firefox both directions, different rates");
    println_safe!("  sudo zelynic strict-single firefox -d 1mb -u 500kb");
    println_safe!();
    println_safe!("  # Check what's limited");
    println_safe!("  sudo zelynic status");
    println_safe!();
    println_safe!("  # JSON output (for scripts)");
    println_safe!("  sudo zelynic status --print-json | jq '.limits[]'");
    println_safe!();
    println_safe!("  # Monitor traffic in box mode (UL + DL)");
    println_safe!("  sudo zelynic observe --live 5m");
    println_safe!();
    println_safe!("  # Find what's eating your bandwidth");
    println_safe!("  sudo zelynic top --live 0");
    println_safe!();
    println_safe!("  # Recover from crash (clean orphaned pins)");
    println_safe!("  sudo zelynic recover");
    println_safe!();
    println_safe!("  # Emergency: remove all limits");
    println_safe!("  sudo zelynic unstrict-all");
}

/// Print the zelynic man page in troff format (exit 0, stdout).
///
/// The release pipeline pipes this into `man/zelynic.1` for the release
/// tarballs. Content mirrors [`print_help`] — the integration tests pin
/// both to the same command set. Plain ASCII roff: dashes escaped where
/// roff demands (`\\-`), no brand color (man renders through the user's
/// pager, not the terminal detection layer). The `.TH` date field stays
/// empty so builds from the same source are byte-reproducible.
pub(crate) fn print_man_page() {
    println_safe!(
        ".TH ZELYNIC 1 \"\" \"zelynic {}\" \"zelynic Manual\"",
        crate::info::VERSION
    );
    println_safe!(".SH NAME");
    println_safe!("zelynic \\- per-app network rate limiter and traffic monitor for Linux");
    println_safe!(".SH SYNOPSIS");
    println_safe!(".B zelynic");
    println_safe!(".RI [ global\\ flags ]");
    println_safe!(".I command");
    println_safe!(".RI [ command\\ args ]");
    println_safe!(".SH DESCRIPTION");
    println_safe!("Limit and observe any app's download/upload speed using eBPF. Pure");
    println_safe!("kernel enforcement \\- no tc, no nft. Requires kernel 5.13+ and root.");
    println_safe!(".SH COMMANDS");
    man_cmd(
        "strict-single <target> [rate] [-d <rate>] [-u <rate>]",
        "Limit a single app's network speed. \\fBbrave 100kb\\fR limits both \
         download and upload; \\fB\\-d\\fR/\\fB\\-u\\fR set per-direction rates.",
    );
    man_cmd(
        "strict-multi <a:b:c> [rate] [-d <rate>] [-u <rate>]",
        "Limit multiple apps sharing one rate (group limit). All apps in the \
         group collectively share the rate limit; if one downloads at full \
         rate, the others get nothing.",
    );
    man_cmd(
        "limit-all [rate] [-d <rate>] [-u <rate>]",
        "Limit ALL user apps from list-apps. System apps are excluded by \
         default; \\fB\\-\\-force\\fR includes them.",
    );
    man_cmd(
        "block-single <target>",
        "Block an app from accessing the internet entirely.",
    );
    man_cmd(
        "block-multi <a:b:c>",
        "Block multiple apps from the internet entirely.",
    );
    man_cmd(
        "block-all",
        "Block ALL user apps from the internet. System apps are excluded by \
         default; \\fB\\-\\-force\\fR includes them.",
    );
    man_cmd("unstrict <target>", "Remove rate limit from one app.");
    man_cmd("unstrict-all", "Remove ALL rate limits (emergency reset).");
    man_cmd(
        "recover",
        "Recover from crash: detect and remove orphaned BPF pins left by a \
         killed zelynic. Safe to run anytime.",
    );
    man_cmd("status", "Show active limits and watchdog status.");
    man_cmd("list-apps", "List apps with their cgroup IDs.");
    man_cmd(
        "observe [--live <dur>] [--cgroup <id>] [--interval <1s\\-60s>]",
        "Real-time traffic monitor (box mode, in-place refresh). Exit with \
         q, ESC, or Ctrl+C.",
    );
    man_cmd(
        "top [--duration <dur>] [--live <dur>] [--limit N] [--interval <1s\\-60s>]",
        "Find top bandwidth consumers. Default: 10s snapshot, top 10. Use \
         \\fB\\-\\-live\\fR for continuous tracking.",
    );
    man_cmd("doctor", "Check if your machine supports eBPF.");
    man_cmd(
        "man",
        "Print this man page in troff format (the release tarball ships it \
         as man/zelynic.1).",
    );
    println_safe!(".SH GLOBAL FLAGS");
    man_flag(
        "\\-h, \\-\\-help",
        "Print the end-to-end reference (this text).",
    );
    man_flag(
        "\\-V, \\-\\-version",
        "Print complete version and build information.",
    );
    man_flag(
        "\\-\\-check\\-update",
        "Check the latest upstream GitHub release.",
    );
    man_flag("\\-v, \\-\\-verbose", "Verbose/debug output.");
    man_flag("\\-\\-print\\-json", "Output as JSON (where applicable).");
    println_safe!(".SH RATE FORMATS");
    println_safe!("500b, 1kb, 500kb, 1mb, 1gb, 100gb (lowercase only). Minimum 1kb");
    println_safe!("(1000 b/s, decimal SI), maximum 100gb (100,000,000,000 b/s); both");
    println_safe!("bounds overridable with \\fB\\-\\-allow\\-dangerous\\fR.");
    println_safe!(".SH TARGET FORMATS");
    println_safe!("\\fIprocess_name\\fR (e.g., brave, firefox, curl) or \\fIcgroup_id\\fR");
    println_safe!("(e.g., 73386; find it with \\fBzelynic list\\-apps\\fR).");
    println_safe!(".SH SAFETY");
    println_safe!("Min-rate guard rejects rates below 1kb unless");
    println_safe!("\\fB\\-\\-allow\\-dangerous\\fR is set. Dangerous/system targets (root,");
    println_safe!("systemd, kthreadd, ...) are blocked by default; \\fB\\-\\-force\\fR");
    println_safe!("overrides. Fail-safe: BPF returns allow on any error path.");
    println_safe!(".SH EXAMPLES");
    println_safe!(".nf");
    println_safe!("# Limit brave to 100kb/s (both download + upload)");
    println_safe!("sudo zelynic strict-single brave 100kb");
    println_safe!();
    println_safe!("# Limit firefox both directions, different rates");
    println_safe!("sudo zelynic strict-single firefox -d 1mb -u 500kb");
    println_safe!();
    println_safe!("# Limit download tools to share 1mb/s total");
    println_safe!("sudo zelynic strict-multi curl:pacman:aria2c 1mb");
    println_safe!();
    println_safe!("# Monitor traffic in box mode, then find the top talkers");
    println_safe!("sudo zelynic observe --live 5m");
    println_safe!("sudo zelynic top --live 0");
    println_safe!();
    println_safe!("# Emergency: remove all limits");
    println_safe!("sudo zelynic unstrict-all");
    println_safe!(".fi");
    println_safe!(".SH SEE ALSO");
    println_safe!("Full reference: \\fBzelynic \\-\\-help\\fR. Project documentation:");
    println_safe!("https://github.com/oxyzenQ/zelynic");
}

/// One `.TP` command entry: bold synopsis, indented description.
fn man_cmd(synopsis: &str, description: &str) {
    println_safe!(".TP");
    println_safe!(".B {}", synopsis);
    // roff fills and hyphenates automatically, so the description is a
    // single logical line regardless of terminal width.
    println_safe!("{}", description);
}

/// One `.TP` flag entry: bold flag list, indented summary.
fn man_flag(flags: &str, summary: &str) {
    println_safe!(".TP");
    println_safe!(".B {}", flags);
    println_safe!("{}", summary);
}
