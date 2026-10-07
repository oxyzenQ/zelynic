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
    println_safe!(
        "Limit and observe any app's download/upload speed using eBPF — pure kernel enforcement."
    );
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
    // NIGHT-blade-2: strict-all rode the strict group (the former
    // one-command "limit" group dissolved with the rename).
    // NIGHT-improve-53 (the masterclass unification): each family is
    // ONE verb now — strict, block, unstrict — with the '::' list
    // grammar riding the same spelling. The single/multi/-single/
    // -multi spellings are retired (the redirect table owns them).
    // NIGHT-improve-54: the -all sweeps retired too — --all is a
    // lane of each family verb, documented in the Pro mode section.
    println_safe!("  {}", brand_bold("strict — apply rate limits"));
    println_safe!();
    println_safe!("  zelynic strict <target> [rate] [-d <rate>] [-u <rate>] [--per-socket]");
    println_safe!("    Limit one app's network speed, or a '::'-separated list sharing");
    println_safe!("    ONE rate (group limit: if one member downloads at full rate,");
    println_safe!("    the others get nothing). 's' is the short alias.");
    println_safe!("    --per-socket caps every connection at the rate (the single");
    println_safe!("    target's server shape); --no-test skips the post-apply");
    println_safe!("    verification loop for scripted use.");
    example("both dl+ul = 100kb", "sudo zelynic strict brave 100kb");
    example("download only", "sudo zelynic strict brave -d 100kb");
    example("upload only", "sudo zelynic strict brave -u 500kb");
    example(
        "both, different rates",
        "sudo zelynic strict firefox -d 1mb -u 500kb",
    );
    example(
        "per-connection cap (server)",
        "sudo zelynic s nginx --per-socket 500kb",
    );
    example(
        "a group sharing one rate",
        "sudo zelynic s brave::curl::pacman 1mb",
    );
    example(
        "cgroup ids, list form",
        "sudo zelynic s cg:1234::1245 100kb",
    );
    example("short alias form", "sudo zelynic s brave 100kb");
    example("docker container", "sudo zelynic s docker://nginx 100kb");
    example("kubernetes pod", "sudo zelynic s k8s://prod/web-abc 1mb");
    println_safe!();
    println_safe!("  Container targets resolve to the workload's cgroup:");
    println_safe!("  docker://<name> (or id prefix) via the Engine API,");
    println_safe!("  k8s://<namespace>/<pod> via the kubelet's pod log dirs.");
    println_safe!("  unstrict accepts the same references.");
    println_safe!();
    println_safe!("  {}", brand_bold("block — cut internet access"));
    println_safe!();
    println_safe!("  zelynic block <target>");
    println_safe!("    Block one app from the internet entirely, or a");
    println_safe!("    '::'-separated list. 'b' is the short alias.");
    example("cut one app off", "sudo zelynic block brave");
    example("cut a whole group", "sudo zelynic b brave::curl::pacman");
    println_safe!();
    println_safe!("  {}", brand_bold("unstrict — remove limits & recover"));
    println_safe!();
    println_safe!("  zelynic unstrict <target>");
    println_safe!("    Remove the rate limit from one app or a '::'-separated list.");
    println_safe!("    'u' is the short alias.");
    example("remove one app's limit", "sudo zelynic unstrict brave");
    example("bulk removal", "sudo zelynic u brave::curl::pacman");
    println_safe!();
    println_safe!("  zelynic recover");
    println_safe!("    Clean orphaned BPF pins after a crash (SIGKILL, OOM, power loss).");
    println_safe!("    Safe to run anytime — does nothing if state is clean.");
    println_safe!();
    println_safe!("  {}", brand_bold("monitor — traffic visibility"));
    println_safe!();
    println_safe!("  zelynic status");
    println_safe!("    Show active limits and watchdog status.");
    // NIGHT-dinner-11: the owner read "allowed 3.4gb / dropped 4.4 mb"
    // as a mystery — the pair's semantics belong ON the surface he
    // was looking at, not only in docs/USAGE.md. Three lines, the
    // full contract: units, window, reset.
    println_safe!("    allowed / dropped: cumulative BYTES per cgroup since the limit");
    println_safe!("    was set — allowed passed the budget, dropped exceeded it (the");
    println_safe!("    sender retries); removing the limit clears both.");
    println_safe!();
    println_safe!("  zelynic list-apps");
    println_safe!("    List apps with their cgroup IDs.");
    println_safe!();
    println_safe!("  zelynic eagle-eyes [targets] [--interval <1s-60s>]");
    println_safe!("    The unified live monitor (observe + top merged;");
    println_safe!("    'ee' is the short alias).");
    println_safe!("    Apps ranked by consumption — rank 1 eats the internet right now.");
    println_safe!("    Rows follow the terminal height (no --limit): raise the window");
    println_safe!("    to see more, the list runs high to low.");
    println_safe!("    Exit with q (the only quit key).");
    println_safe!("    Targets are autodetected: digits = cgroup ID (see list-apps),");
    println_safe!("    the display prefix cg:73386 round-trips, a name = process —");
    println_safe!("    one target opens the deep focus view");
    println_safe!("    (per-direction deltas, rate, lifetime, socket endpoints).");
    println_safe!("    One-shot deep inspection: --depth prints the");
    println_safe!("    full report — package id/name, user, cgroup path, enforcement,");
    println_safe!("    per-process census (type, perms, path, start time), the");
    println_safe!("    network-traffic focus section — window totals plus");
    println_safe!("    per-endpoint bytes, movers ranked first — then exits.");
    println_safe!("    Pipe-friendly: --depth is the only spelling;");
    println_safe!("    --print-json emits the machine-readable document;");
    println_safe!("    --focus <1s-30s> tunes the traffic window (default 3s).");
    example("all apps, ranked", "sudo zelynic eagle-eyes");
    example("one app, deep view", "sudo zelynic eagle-eyes brave");
    example(
        "watch specific targets",
        "sudo zelynic eagle-eyes 12345/brave/firefox",
    );
    example("calmer cadence", "sudo zelynic eagle-eyes --interval 3s");
    example("short alias form", "sudo zelynic ee brave --interval 1s");
    example("deep report, one shot", "sudo zelynic ee cg:1234 --depth");
    example(
        "deep report, 5s traffic window",
        "sudo zelynic ee cg:1234 --depth --focus 5s",
    );
    example(
        "the report as JSON",
        "sudo zelynic ee 12345 --depth --print-json",
    );
    println_safe!();
    println_safe!("  {}", brand_bold("system — support"));
    println_safe!();
    println_safe!("  zelynic doctor");
    println_safe!(
        "    Check host eBPF support and this binary's build flavor (full-life / half-life)."
    );
    println_safe!();
    // NIGHT-improve-25: the two-letter aliases — every enforcement
    // verb plus the monitor in two keystrokes. Documented as a
    // compact table after the command groups, so the canonical
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
    // NIGHT-improve-53: the single/multi pairs collapsed into one
    // verb per family. NIGHT-improve-54: the -all sweeps retired
    // into the --all lanes — four aliases now (the sweeps' sa/ba/ua
    // died with their verbs, the redirect table owns them).
    println_safe!("{}", brand_bold("Short aliases:"));
    println_safe!("  s = strict");
    println_safe!("  b = block");
    println_safe!("  u = unstrict");
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
    println_safe!(
        "  --print-json     JSON output for status, list-apps, eagle-eyes --depth, doctor,"
    );
    println_safe!("                   restore");
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
    // NIGHT-improve-45: the Pro mode section — the owner's ask:
    // every hidden and advanced flag documented COMPLETELY on the
    // one reference surface, grouped by the verb family that owns
    // each flag. The globals already carry their own section above;
    // this one is the per-verb advanced family: the --all sweeps
    // (NIGHT-improve-54, zero mentions before this section), the
    // --during grammar (zero mentions before this section), the
    // guarantee brackets (zero mentions), the enforcement shape and
    // the guard override, and the eagle-eyes inspection knobs.
    // help_pins.rs pins every spelling below so the section can
    // never silently thin back to hidden.
    println_safe!("{}", brand_bold("Pro mode:"));
    println_safe!(
        "  The hidden and advanced flags, complete — grouped by the verbs that own them."
    );
    println_safe!();
    // NIGHT-improve-54 (the owner's ask): the fleet sweeps live
    // HERE — --all is a lane of each family verb, and the Pro mode
    // section is its one documented home (the retired -all verbs'
    // redirects name the family verbs).
    println_safe!("  Fleet sweeps (strict + block + unstrict):");
    println_safe!("    --all          the lane that owns every user app at once: limit");
    println_safe!("                  them all, block them all, or tear every limit down.");
    println_safe!("                  System apps stay behind --force-this's guard by");
    println_safe!("                  default; the target is omitted (a lone positional on");
    println_safe!("                  strict is the RATE: 'zelynic s --all 500kb').");
    example(
        "limit every user app at 500kb",
        "sudo zelynic s --all 500kb",
    );
    example(
        "per-direction, whole fleet",
        "sudo zelynic s --all -d 1mb -u 500kb",
    );
    example("block every user app", "sudo zelynic b --all");
    example("emergency reset, every limit gone", "sudo zelynic u --all");
    println_safe!();
    println_safe!("  Time windows (strict family + block family):");
    println_safe!("    --during DUR   auto-expire: the limit tears itself down when the window");
    println_safe!("                  passes. Units: s, m, h, d, mn, y — min 1s, max 10y");
    println_safe!("                  (20d = twenty days; months 30d, years 365d).");
    println_safe!("                  Duration only, one shape, no schedules.");
    // NIGHT-improve-52: the Pro mode block carried every flag's
    // spelling but ZERO runnable examples — the one discovery path
    // a user copies from was missing for the whole hidden family.
    // The examples live HERE (not in the command blocks above)
    // because --all, --during, the guarantee brackets, and --no-test
    // are Pro-mode vocabulary: each example appears exactly once on
    // the surface (NIGHT-hunt-15's no-duplicate law), paired
    // note-above /command-below via the shared example() helper.
    example(
        "auto-expire after two hours",
        "sudo zelynic s brave 1mb --during 2h",
    );
    example(
        "block a group for 30 minutes",
        "sudo zelynic b brave::curl --during 30m",
    );
    println_safe!();
    println_safe!("  Guaranteed share (strict family):");
    println_safe!("    --floor RATE   the fair-share floor: a shaped cgroup's slice never falls");
    println_safe!("                  below it while it demands traffic (a priority, not a");
    println_safe!("                  reservation — absent leaves cost nothing).");
    println_safe!("    --ceil RATE    the slice's hard cap, binding even a lone drawer; the");
    println_safe!("                  ladder is floor <= ceil <= rate.");
    println_safe!("    --floor-download, --floor-upload, --ceil-download, --ceil-upload");
    println_safe!("                    per-direction spellings, one per side: the");
    println_safe!("                    both-directions flag and its twin refuse together.");
    example(
        "guaranteed floor under the cap",
        "sudo zelynic s firefox 1mb --floor 100kb",
    );
    example(
        "per-direction brackets",
        "sudo zelynic s curl 1mb --floor-download 50kb --ceil-upload 200kb",
    );
    println_safe!();
    println_safe!("  Enforcement shape (strict):");
    println_safe!("    --per-socket   cap every connection at the rate (the server shape:");
    println_safe!("                  one process, many sockets).");
    println_safe!("    --no-test      skip the post-apply verification loop (scripted use;");
    println_safe!("                  the former --no-probe spelling redirects here).");
    example(
        "scripted apply, no verification loop",
        "sudo zelynic s nginx 500kb --no-test",
    );
    println_safe!();
    println_safe!("  Guard override (strict family + block family):");
    println_safe!("    --force-this   lift every guard in one flag: the min-rate floor and the");
    println_safe!("                  dangerous-target blocklist (system processes stay");
    println_safe!("                  behind it by default — lifting is a choice).");
    println_safe!();
    println_safe!("  Deep inspection (eagle-eyes):");
    println_safe!("    --depth        one-shot full report, no TUI: per-process census, the");
    println_safe!("                  enforcement ledger, the traffic focus (JSON via");
    println_safe!("                  --print-json).");
    println_safe!("    --focus SEC    the --depth traffic window: 1s..30s, default 3s (one");
    println_safe!("                  stderr note when ignored on the live monitor).");
    println_safe!("    --interval SEC live monitor refresh: 1s..60s, default 1s.");
    println_safe!();
    println_safe!("{}", brand_bold("Target formats:"));
    println_safe!("  <process_name>  e.g., brave, firefox, curl");
    println_safe!("  <cgroup_id>     e.g., 73386 (use 'zelynic list-apps' to find)");
    // NIGHT-dinner-10: the display prefix is a real third form, not a
    // decoration — every output surface prints cgroups as `cg:73386`
    // (the status table, the eagle-eyes footer, the unstrict echo),
    // and the eagle-eyes footer's suggested command carries it
    // verbatim. The grammar section must list what the tool itself
    // tells users to paste (NIGHT-boost-37's round-trip contract).
    println_safe!("  cg:<cgroup_id>  the display prefix every surface prints (cg:73386) —");
    println_safe!("                  paste it back: the same direct target as the bare ID");
    // NIGHT-improve-53: the masterclass list law — '::' separates
    // the members of a list (strict / block / unstrict all route on
    // it); the single ':' belongs to the target's own grammar (the
    // cg: display prefix, the container URIs), which is why the
    // list separator doubles it.
    println_safe!("  <a>::<b>[::...]  list members for the group lane — the '::' separator");
    println_safe!("                  cannot collide with the single ':' the cg: prefix and");
    println_safe!("                  the container URIs own");
    // NIGHT-dinner-11: the no-match contract rides the grammar
    // section — the forms above are what a target must resolve to,
    // and one that resolves to nothing is rejected, not soft-exited
    // (the eBPF-verifier lineage the owner specced for the CLI).
    println_safe!("  A target that matches nothing is a hard error (exit 1) — never a");
    println_safe!("  silent no-op; the --all reset on an already-clean system exits 0.");
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
    println_safe!("  {}", ok("sudo zelynic u --all"));
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
