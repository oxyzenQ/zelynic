// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The single help authority for `zelynic --help` (NIGHT-improve-3:
//! the former `--help-all` reference and the top-level help merged
//! into one flag, cosmostrix v30-simplify lineage; NIGHT-hunt-12: the
//! `man` subcommand and its troff renderer are gone — `--help` is the
//! only reference surface).
//!
//! The integration tests pin this module: every subcommand the CLI
//! exposes must appear in the output, and it must carry the verb
//! group headings (NIGHT-improve-5: strict / limit / block / unstrict,
//! plus monitor and system), so adding a command or reshuffling a
//! group without updating this module fails the suite.

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
    // NIGHT-improve-5: commands grouped by verb (strict / limit /
    // block / unstrict, plus monitor and system) so the 15-command
    // surface (NIGHT-hunt-12: man removed) scans as six chunks
    // instead of one flat wall. Group
    // headings carry the same brand purple as section headings; each
    // synopsis sits on its own line with the description and examples
    // indented below — no more 120-char mixed lines.
    println_safe!("  {}", brand_bold("strict — apply rate limits"));
    println_safe!();
    println_safe!("  zelynic strict-single <target> [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit one app's network speed ('strict' is the shorthand).");
    println_safe!("    sudo zelynic strict-single brave 100kb              # both dl+ul = 100kb");
    println_safe!("    sudo zelynic strict-single brave -d 100kb           # download only");
    println_safe!("    sudo zelynic strict-single brave -u 500kb           # upload only");
    println_safe!(
        "    sudo zelynic strict-single firefox -d 1mb -u 500kb  # both, different rates"
    );
    println_safe!("    sudo zelynic strict brave 100kb                     # shorthand form");
    println_safe!();
    println_safe!("  zelynic strict-multi <a:b:c> [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit multiple apps sharing ONE rate (group limit).");
    println_safe!("    All apps collectively share the rate — if one downloads at full");
    println_safe!("    rate, the others get nothing.");
    println_safe!("    sudo zelynic strict-multi brave:curl:pacman 1mb");
    println_safe!("    sudo zelynic strict-multi brave:firefox -d 1mb -u 500kb");
    println_safe!();
    println_safe!("  {}", brand_bold("limit — bulk rate limits"));
    println_safe!();
    println_safe!("  zelynic limit-all [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit ALL user apps (system apps excluded; --force includes them).");
    println_safe!("    sudo zelynic limit-all 500kb              # limit all user apps");
    println_safe!("    sudo zelynic limit-all -d 1mb -u 500kb    # per-direction");
    println_safe!();
    println_safe!("  {}", brand_bold("block — cut internet access"));
    println_safe!();
    println_safe!("  zelynic block-single <target>");
    println_safe!("    Block one app from the internet entirely.");
    println_safe!("    sudo zelynic block-single brave");
    println_safe!();
    println_safe!("  zelynic block-multi <a:b:c>");
    println_safe!("    Block multiple apps from the internet.");
    println_safe!("    sudo zelynic block-multi brave:curl:pacman");
    println_safe!();
    println_safe!("  zelynic block-all");
    println_safe!("    Block ALL user apps (--force includes system apps).");
    println_safe!("    sudo zelynic block-all                   # all user apps");
    println_safe!("    sudo zelynic block-all --force            # include system apps");
    println_safe!();
    println_safe!("  {}", brand_bold("unstrict — remove limits & recover"));
    println_safe!();
    println_safe!("  zelynic unstrict <target>");
    println_safe!("    Remove the rate limit from one app ('unstrict-single' is an alias).");
    println_safe!("    sudo zelynic unstrict brave");
    println_safe!();
    println_safe!("  zelynic unstrict-multi <a:b:c>");
    println_safe!("    Remove rate limits from multiple apps at once.");
    println_safe!("    sudo zelynic unstrict-multi brave:curl:pacman");
    println_safe!();
    println_safe!("  zelynic unstrict-all");
    println_safe!("    Remove ALL limits (emergency reset).");
    println_safe!();
    println_safe!("  zelynic recover");
    println_safe!("    Clean orphaned BPF pins after a crash (SIGKILL, OOM, power loss).");
    println_safe!("    Safe to run anytime — does nothing if state is clean.");
    println_safe!();
    println_safe!("  {}", brand_bold("monitor — traffic visibility"));
    println_safe!();
    println_safe!("  zelynic status");
    println_safe!("    Show active limits and watchdog status.");
    println_safe!();
    println_safe!("  zelynic list-apps");
    println_safe!("    List apps with their cgroup IDs.");
    println_safe!();
    println_safe!("  zelynic observe [--cgroup <id>] [--interval <1s-60s>]");
    println_safe!("    Live traffic monitor (box mode, in-place refresh).");
    println_safe!("    Exit with q (Ctrl+C also quits).");
    println_safe!("    sudo zelynic observe                    # live box, q to quit");
    println_safe!("    sudo zelynic observe --cgroup 8066       # filter to one cgroup");
    println_safe!("    sudo zelynic observe --interval 5s       # calmer cadence + rate column");
    println_safe!();
    println_safe!("  zelynic top [--limit N] [--interval <1s-60s>]");
    println_safe!("    Live top bandwidth consumers (box mode, top 10 by default).");
    println_safe!("    sudo zelynic top                        # live box, 5s refresh, q to quit");
    println_safe!("    sudo zelynic top --limit 20             # show top 20 talkers");
    println_safe!("    sudo zelynic top --interval 2s          # 2s refresh");
    println_safe!();
    println_safe!("  {}", brand_bold("system — support"));
    println_safe!();
    println_safe!("  zelynic doctor");
    println_safe!("    Check if your machine supports eBPF.");
    println_safe!();
    println_safe!("{}", brand_bold("Global flags:"));
    println_safe!("  -h, --help       This end-to-end reference (usage, commands, examples)");
    println_safe!("  -V, --version    Version and build information");
    println_safe!("  --check-update   Check the latest upstream GitHub release (refuses sudo)");
    println_safe!(
        "  -v, --verbose    Diagnostic trace: target resolution, policy writes, BPF lifecycle"
    );
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
    println_safe!("  # Monitor live traffic in box mode (UL + DL) — q to quit");
    println_safe!("  sudo zelynic observe");
    println_safe!();
    println_safe!("  # Find what's eating your bandwidth (live top talkers)");
    println_safe!("  sudo zelynic top");
    println_safe!();
    println_safe!("  # Recover from crash (clean orphaned pins)");
    println_safe!("  sudo zelynic recover");
    println_safe!();
    println_safe!("  # Emergency: remove all limits");
    println_safe!("  sudo zelynic unstrict-all");
}
