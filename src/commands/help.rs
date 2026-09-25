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
//! group headings (NIGHT-improve-5: strict / block / unstrict, plus
//! monitor and system — NIGHT-blade-2 dissolved the one-command
//! "limit" group when limit-all joined the strict family), so adding
//! a command or reshuffling a group without updating this module
//! fails the suite.
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
    // NIGHT-improve-5: commands grouped by verb (strict / block /
    // unstrict, plus monitor and system) so the 14-command surface
    // (NIGHT-boost-1: observe + top merged into eagle-eyes)
    // scans as chunks instead of one flat wall. Group
    // headings carry the same brand purple as section headings; each
    // synopsis sits on its own line with the description and
    // examples indented below — no more 120-char mixed lines.
    // NIGHT-blade-2: strict-all rides the strict group (the former
    // one-command "limit" group dissolved with the rename — the
    // strict family now reads single/multi/all like block and
    // unstrict already did).
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
    example("short alias form", "sudo zelynic ss brave 100kb");
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
    println_safe!("  zelynic strict-all [rate] [-d <rate>] [-u <rate>]");
    println_safe!("    Limit ALL user apps (system apps excluded; --force-this includes them).");
    example("limit all user apps", "sudo zelynic strict-all 500kb");
    example("per-direction", "sudo zelynic strict-all -d 1mb -u 500kb");
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
    println_safe!("    Block ALL user apps (--force-this includes system apps).");
    example("all user apps", "sudo zelynic block-all");
    example("include system apps", "sudo zelynic block-all --force-this");
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
    println_safe!("    'ee' is the short alias, NIGHT-improve-25).");
    println_safe!("    Apps ranked by consumption — rank 1 eats the internet right now.");
    println_safe!("    Rows follow the terminal height (no --limit): raise the window");
    println_safe!("    to see more, the list runs high to low.");
    println_safe!("    Exit with q (the only quit key).");
    println_safe!("    Targets are autodetected: digits = cgroup ID (see list-apps),");
    println_safe!("    the display prefix cg:73386 round-trips, a name = process —");
    println_safe!("    one target opens the deep focus view");
    println_safe!("    (per-direction deltas, rate, lifetime, socket endpoints).");
    example("all apps, ranked", "sudo zelynic eagle-eyes");
    example("one app, deep view", "sudo zelynic eagle-eyes brave");
    example(
        "watch specific targets",
        "sudo zelynic eagle-eyes 12345/brave/firefox",
    );
    example("calmer cadence", "sudo zelynic eagle-eyes --interval 3s");
    example("short alias form", "sudo zelynic ee brave --interval 1s");
    println_safe!();
    println_safe!("  {}", brand_bold("system — support"));
    println_safe!();
    println_safe!("  zelynic doctor");
    println_safe!("    Check if your machine supports eBPF.");
    println_safe!();
    // NIGHT-improve-25: the ten two-letter aliases — every
    // enforcement verb plus the monitor in two keystrokes. Documented
    // as a compact table after the command groups, so the canonical
    // names stay the vocabulary of the reference and the short forms
    // read as the typing shortcut they are.
    // NIGHT-boost-29 (tidy data): one alias per line in the explicit
    // `alias = canonical` form. The old three-column packing leaned
    // on column alignment alone — no separator between the pair, so
    // the eye had to count gaps to tell which short form belonged to
    // which verb (the owner's "asymmetric tidy data" audit). The
    // equals sign is the one-glance contract every row now carries,
    // and a wide label column needs no alignment guesswork. The same
    // `=` pairing is the format README and docs/USAGE.md already
    // teach, so the reference and the docs read identically.
    println_safe!("{}", brand_bold("Short aliases:"));
    println_safe!("  ss = strict-single");
    println_safe!("  sm = strict-multi");
    println_safe!("  sa = strict-all");
    println_safe!("  bs = block-single");
    println_safe!("  bm = block-multi");
    println_safe!("  ba = block-all");
    println_safe!("  us = unstrict-single");
    println_safe!("  um = unstrict-multi");
    println_safe!("  ua = unstrict-all");
    println_safe!("  ee = eagle-eyes");
    println_safe!();
    println_safe!("{}", brand_bold("Global flags:"));
    println_safe!("  -h, --help       This end-to-end reference (usage, commands, examples)");
    println_safe!("  -V, --version    Version and build information");
    println_safe!("  --reset-terminal Emergency terminal reset: recover a screen broken by");
    println_safe!("                   a kill -9 TUI death (sudo-safe, works blind-typed)");
    println_safe!("  --check-update   Check the latest upstream GitHub release (refuses sudo)");
    println_safe!(
        "  -v, --verbose    Diagnostic trace: target resolution, policy writes, BPF lifecycle"
    );
    println_safe!("  --print-json     JSON output for status, list-apps, doctor");
    println_safe!("  --color-mode M   Force color depth: 0 mono, 16, 8/256 cube, 24/32 truecolor");
    println_safe!(
        "                   (default auto-fallback; for terminals whose truecolor claim lies)"
    );
    println_safe!();
    println_safe!("{}", brand_bold("Rate formats:"));
    println_safe!("  500b    1kb    500kb    1mb    1gb    1tb    (lowercase only)");
    println_safe!("  Min: 1kb (1000 b/s, decimal SI)    Max: 1tb (1,000,000,000,000 b/s)");
    // NIGHT-improve-30: the unified safety override. The section
    // used to name the two retired spellings (--allow-dangerous for
    // the min-rate guard, --force for the blocklist); the owner
    // mandate is ONE flag, same function, one line at the end of the
    // section that says exactly that.
    println_safe!("  Both bounds overridable with --force-this");
    println_safe!("  Color output is always on — set NO_COLOR=1 to disable");
    println_safe!();
    println_safe!("{}", brand_bold("Target formats:"));
    println_safe!("  <process_name>  e.g., brave, firefox, curl");
    println_safe!("  <cgroup_id>     e.g., 73386 (use 'zelynic list-apps' to find)");
    println_safe!();
    println_safe!("{}", brand_bold("Safety:"));
    println_safe!("  • Min-rate guard: rejects < 1kb");
    println_safe!(
        "  • Dangerous target warning: {} system processes blocked by default",
        crate::commands::safety::DANGEROUS_TARGETS.len()
    );
    println_safe!("  • Fail-safe: BPF returns allow on any error path");
    println_safe!("  • One flag lifts every guard: --force-this");
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
    println_safe!();
    println_safe!("  # Rescue a terminal broken by a kill -9 TUI death");
    println_safe!("  {}", ok("zelynic --reset-terminal"));
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
