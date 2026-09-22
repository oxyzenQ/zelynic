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
//!
//! Example layout (NIGHT-boost-4, owner mandate): every runnable
//! example is an annotated PAIR — the `#` note on its own line ABOVE
//! the command, the command itself in status green. The old inline
//! right-side comments drifted out of alignment across examples and
//! read as visual noise. The [`example`] helper below is the one
//! place that renders the pair, so the layout cannot drift per
//! section.

use crate::output::{brand_bold, ok};

/// Print the end-to-end reference: usage, commands, flags, formats,
/// safety guards, and examples.
///
/// Brand identity (cosmostrix help format): the banner and every
/// section heading render in brand purple #A855F7 (bold); command
/// syntax and body text stay in the terminal default color so the
/// reference remains readable and diff-friendly when piped.
/// Runnable example lines are the one deliberate exception
/// (NIGHT-boost-4): they render in status green #50FA7B — the
/// affirmative "this is what you type" tier, one step below the
/// headings in the visual hierarchy.
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
    // block / unstrict, plus monitor and system) so the 14-command
    // surface (NIGHT-boost-1: observe + top merged into eagle-eyes)
    // scans as six chunks instead of one flat wall. Group
    // headings carry the same brand purple as section headings; each
    // synopsis sits on its own line with the description and
    // examples indented below — no more 120-char mixed lines.
    println_safe!("  {}", brand_bold("strict — apply rate limits"));
    println_safe!();
    println_safe!("  zelynic strict-single <target> [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit one app's network speed ('strict' is the shorthand).");
    example(
        "both dl+ul = 100kb",
        "sudo zelynic strict-single brave 100kb",
    );
    example("download only", "sudo zelynic strict-single brave -d 100kb");
    example("upload only", "sudo zelynic strict-single brave -u 500kb");
    example(
        "both, different rates",
        "sudo zelynic strict-single firefox -d 1mb -u 500kb",
    );
    example("shorthand form", "sudo zelynic strict brave 100kb");
    println_safe!();
    println_safe!("  zelynic strict-multi <a:b:c> [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit multiple apps sharing ONE rate (group limit).");
    println_safe!("    All apps collectively share the rate — if one downloads at full");
    println_safe!("    rate, the others get nothing.");
    example(
        "both dl+ul = 1mb",
        "sudo zelynic strict-multi brave:curl:pacman 1mb",
    );
    example(
        "per-direction",
        "sudo zelynic strict-multi brave:firefox -d 1mb -u 500kb",
    );
    println_safe!();
    println_safe!("  {}", brand_bold("limit — bulk rate limits"));
    println_safe!();
    println_safe!("  zelynic limit-all [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit ALL user apps (system apps excluded; --force includes them).");
    example("limit all user apps", "sudo zelynic limit-all 500kb");
    example("per-direction", "sudo zelynic limit-all -d 1mb -u 500kb");
    println_safe!();
    println_safe!("  {}", brand_bold("block — cut internet access"));
    println_safe!();
    println_safe!("  zelynic block-single <target>");
    println_safe!("    Block one app from the internet entirely.");
    example("cut one app off", "sudo zelynic block-single brave");
    println_safe!();
    println_safe!("  zelynic block-multi <a:b:c>");
    println_safe!("    Block multiple apps from the internet.");
    example(
        "cut a whole group",
        "sudo zelynic block-multi brave:curl:pacman",
    );
    println_safe!();
    println_safe!("  zelynic block-all");
    println_safe!("    Block ALL user apps (--force includes system apps).");
    example("all user apps", "sudo zelynic block-all");
    example("include system apps", "sudo zelynic block-all --force");
    println_safe!();
    println_safe!("  {}", brand_bold("unstrict — remove limits & recover"));
    println_safe!();
    println_safe!("  zelynic unstrict-single <target>");
    println_safe!("    Remove the rate limit from one app ('unstrict' is the shorthand).");
    example(
        "remove one app's limit",
        "sudo zelynic unstrict-single brave",
    );
    example("shorthand form", "sudo zelynic unstrict brave");
    println_safe!();
    println_safe!("  zelynic unstrict-multi <a:b:c>");
    println_safe!("    Remove rate limits from multiple apps at once.");
    example(
        "bulk removal",
        "sudo zelynic unstrict-multi brave:curl:pacman",
    );
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
    println_safe!("  zelynic eagle-eyes [targets] [--interval <1s-60s>]");
    println_safe!("    The unified live monitor (NIGHT-boost-1: observe + top merged;");
    println_safe!("    'eagle-eye' is the shorthand).");
    println_safe!("    Apps ranked by consumption — rank 1 eats the internet right now.");
    println_safe!("    Rows follow the terminal height (no --limit): raise the window");
    println_safe!("    to see more, the list runs high to low.");
    println_safe!("    Exit with q (the only quit key).");
    println_safe!("    Targets are autodetected: digits = cgroup ID (see list-apps),");
    println_safe!("    a name = process — one target opens the deep focus view");
    println_safe!("    (per-direction deltas, rate, lifetime, socket endpoints).");
    example("all apps, ranked", "sudo zelynic eagle-eyes");
    example("one app, deep view", "sudo zelynic eagle-eyes brave");
    example(
        "watch specific targets",
        "sudo zelynic eagle-eyes 12345/brave/firefox",
    );
    example("calmer cadence", "sudo zelynic eagle-eyes --interval 3s");
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
    println_safe!("  500b    1kb    500kb    1mb    1gb    1tb    (lowercase only)");
    println_safe!("  Min: 1kb (1000 b/s, decimal SI)    Max: 1tb (1,000,000,000,000 b/s)");
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
    // NIGHT-hunt-15: the command blocks above each carry their own
    // examples (NIGHT-improve-5) — this section holds ONLY the three
    // workflows whose blocks have no example lines, so every example
    // appears exactly once on the surface. Same annotated-pair format
    // as the group blocks (NIGHT-boost-4), at the section's own
    // two-space indent.
    println_safe!("  # Check what's limited (JSON for scripts)");
    println_safe!(
        "  {}",
        ok("sudo zelynic status --print-json | jq '.limits[]'")
    );
    println_safe!();
    println_safe!("  # Recover from a crash (clean orphaned pins)");
    println_safe!("  {}", ok("sudo zelynic recover"));
    println_safe!();
    println_safe!("  # Emergency: remove all limits");
    println_safe!("  {}", ok("sudo zelynic unstrict-all"));
}

/// One runnable example: the `#` annotation on its own line ABOVE,
/// the command line in status green below (NIGHT-boost-4 owner
/// mandate — the old right-side comments misaligned across examples
/// and read as visual noise; the pair format is enforced here so it
/// cannot drift per section).
fn example(note: &str, cmd: &str) {
    println_safe!("    # {note}");
    println_safe!("    {}", ok(cmd));
}
