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
//!
//! NIGHT-hunt-35 (the masterclass tidy, owner mandate — symmetric,
//! compact, simple): the synopsis lines are their own tier — every
//! command usage line renders through the [`synopsis`] helper in
//! calm grey, one tier below the purple headings and one above the
//! default prose (white usage lines strained the eyes; grey says
//! "grammar, not content", the same tier law the eagle-eyes footer
//! rides). Each synopsis carries the WHOLE grammar on one line —
//! both lanes of the target (`<target> or <target::target::target>`)
//! plus the ONE pointer token `[flags — see Pro mode]` instead of an
//! in-synopsis flag enumeration; Pro mode owns every flag's
//! spelling, and the help_pins ADVANCED_FLAGS fence holds that
//! completeness. Flag tables render ONE description column per
//! section (continuations aligned to it), and since NIGHT-hunt-39
//! the whole flag estate — Global flags, Rate formats, Pro mode,
//! the flag_row tier-and-column law — lives in help_flags.rs (the
//! 600-line no-mercy cap's split: every spelling surface, one
//! module): every flag spelling renders in the same calm grey the
//! synopses ride, span-exact, with the examples staying solid
//! green and NO_COLOR=1 staying default.

use crate::output::{brand_bold, grey, ok};

/// Print the end-to-end reference: usage, commands, flags, formats,
/// safety guards, and examples.
///
/// Brand identity (cosmostrix help format): the banner and every
/// section heading render in brand purple #A855F7 (bold); body text
/// stays in the terminal default color so the reference remains
/// readable and diff-friendly when piped. Three deliberate
/// exceptions shape the visual hierarchy: every command synopsis
/// renders in calm grey #8B8B8B (NIGHT-hunt-35 — the white usage
/// lines strained the owner's eyes; grammar is context, not
/// content), every flag spelling renders in the same calm grey
/// (NIGHT-hunt-39 — the owner's mandate: flags are grammar wherever
/// they appear, table columns and inline mentions alike), and every
/// runnable example line renders in status green #50FA7B
/// (NIGHT-boost-4 — the affirmative "this is what you type" tier).
/// Purple headings, grey grammar — synopses whole-line, flag
/// spellings token-wise — default prose, green examples: four tiers,
/// one law each.
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
    // NIGHT-hunt-35 (the synopsis law): one line, the whole grammar —
    // both lanes of the target, the rate slots, and the ONE pointer
    // token. The flag spellings live in Pro mode (their complete,
    // pinned home); the old --per-socket-only enumeration was neither
    // complete nor simple.
    synopsis(
        "zelynic strict <target> or <target::target::target> [rate] [-d <rate>] [-u <rate>] [flags — see Pro mode]",
    );
    println_safe!("    Limit one app's network speed, or a '::'-separated list sharing");
    println_safe!("    ONE rate (group limit: if one member downloads at full rate,");
    println_safe!("    the others get nothing). 's' is the short alias.");
    // NIGHT-hunt-35 (compact): every example teaches exactly one
    // thing — the -u-alone pair died (the both-rates example already
    // types -u), and the short-alias pair died below (four other
    // examples already type 's').
    example("both dl+ul = 100kb", "sudo zelynic strict brave 100kb");
    example("download only", "sudo zelynic strict brave -d 100kb");
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
    example("docker container", "sudo zelynic s docker://nginx 100kb");
    example("kubernetes pod", "sudo zelynic s k8s://prod/web-abc 1mb");
    println_safe!();
    // NIGHT-hunt-35: the container note nests INSIDE the strict
    // block (indent 4, the description column) — it is strict-family
    // content, not a stray block at the section margin.
    println_safe!("    Container targets resolve to the workload's cgroup:");
    println_safe!("    docker://<name> (or id prefix) via the Engine API,");
    println_safe!("    k8s://<namespace>/<pod> via the kubelet's pod log dirs.");
    println_safe!("    unstrict accepts the same references.");
    println_safe!();
    println_safe!("  {}", brand_bold("block — cut internet access"));
    println_safe!();
    synopsis("zelynic block <target> or <target::target::target> [flags — see Pro mode]");
    println_safe!("    Block one app from the internet entirely, or a");
    println_safe!("    '::'-separated list. 'b' is the short alias.");
    example("cut one app off", "sudo zelynic block brave");
    example("cut a whole group", "sudo zelynic b brave::curl::pacman");
    println_safe!();
    println_safe!("  {}", brand_bold("unstrict — remove limits & recover"));
    println_safe!();
    synopsis("zelynic unstrict <target> or <target::target::target> [flags — see Pro mode]");
    println_safe!("    Remove the rate limit from one app or a '::'-separated list.");
    println_safe!("    'u' is the short alias.");
    example("remove one app's limit", "sudo zelynic unstrict brave");
    example("bulk removal", "sudo zelynic u brave::curl::pacman");
    println_safe!();
    synopsis("zelynic recover");
    println_safe!("    Clean orphaned BPF pins after a crash (SIGKILL, OOM, power loss).");
    println_safe!("    Safe to run anytime — does nothing if state is clean.");
    println_safe!();
    println_safe!("  {}", brand_bold("monitor — traffic visibility"));
    println_safe!();
    synopsis("zelynic status");
    println_safe!("    Show active limits and watchdog status.");
    // NIGHT-dinner-11: the owner read "allowed 3.4gb / dropped 4.4 mb"
    // as a mystery — the pair's semantics belong ON the surface he
    // was looking at, not only in docs/USAGE.md. Three lines, the
    // full contract: units, window, reset.
    println_safe!("    allowed / dropped: cumulative BYTES per cgroup since the limit");
    println_safe!("    was set — allowed passed the budget, dropped exceeded it (the");
    println_safe!("    sender retries); removing the limit clears both.");
    println_safe!();
    synopsis("zelynic list-apps");
    println_safe!("    List apps with their cgroup IDs.");
    println_safe!();
    synopsis("zelynic eagle-eyes [targets] [flags — see Pro mode]");
    // NIGHT-hunt-35 (compact): the same contracts, four lines
    // lighter — every pinned needle (the q-only quit key, --depth's
    // single spelling, the one-shot report inventory) rides tighter
    // prose, and the retired-vocabulary parentheticals stay gone.
    println_safe!("    The unified live monitor (observe + top merged; 'ee' is the short");
    println_safe!("    alias). Apps ranked by session accumulation — rank 1 eats the");
    println_safe!("    internet right now; rows follow the terminal height, high to");
    println_safe!("    low. Exit with q (the only quit key).");
    println_safe!("    Targets are autodetected: digits = cgroup ID (see list-apps), the");
    println_safe!("    display prefix cg:73386 round-trips, a name = process — one");
    println_safe!("    target opens the deep focus view (per-direction deltas, rate,");
    println_safe!("    lifetime, socket endpoints).");
    // NIGHT-hunt-39: the inline flag mentions ride the grey tier
    // too — the law is the spelling, wherever it appears on the
    // surface.
    println_safe!(
        "    One-shot deep inspection: {} prints the full report —",
        grey("--depth")
    );
    println_safe!("    package id/name, user, cgroup path, enforcement, per-process");
    println_safe!("    census, the traffic focus section — then exits. Pipe-friendly:");
    println_safe!(
        "    {} is the only spelling; {} emits the",
        grey("--depth"),
        grey("--print-json")
    );
    println_safe!(
        "    machine-readable document; {} tunes the traffic",
        grey("--focus <1s-30s>")
    );
    println_safe!("    window (default 3s).");
    example("all apps, ranked", "sudo zelynic eagle-eyes");
    example("one app, deep view", "sudo zelynic eagle-eyes brave");
    example(
        "watch specific targets",
        "sudo zelynic eagle-eyes 12345/brave/firefox",
    );
    example("calmer cadence", "sudo zelynic eagle-eyes --interval 3s");
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
    synopsis("zelynic doctor");
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
    // NIGHT-hunt-39: the flag estate (Global flags, Rate formats,
    // Pro mode) lives in help_flags.rs -- the 600-line no-mercy
    // cap's split: one concern, one module -- every spelling
    // surface together, the flag_row law included.
    crate::commands::help_flags::print_flag_tables();
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
    // list separator doubles it. NIGHT-hunt-35: the token re-spells
    // to the concrete three-member shape (the synopsis' own
    // <target::target::target>) so it sits in the section's one
    // description column.
    println_safe!("  <a>::<b>::<c>   list members for the group lane — the '::' separator");
    println_safe!("                  cannot collide with the single ':' the cg: prefix and");
    println_safe!("                  the container URIs own");
    // NIGHT-dinner-11: the no-match contract rides the grammar
    // section — the forms above are what a target must resolve to,
    // and one that resolves to nothing is rejected, not soft-exited
    // (the eBPF-verifier lineage the owner specced for the CLI).
    println_safe!("  A target that matches nothing is a hard error (exit 1) — never a");
    println_safe!(
        "  silent no-op; the {} reset on an already-clean system exits 0.",
        grey("--all")
    );
    println_safe!();
    println_safe!("{}", brand_bold("Safety:"));
    println_safe!("  • Min-rate guard: rejects < 1kb");
    println_safe!(
        "  • Dangerous target warning: {} system processes blocked by default",
        crate::commands::safety::DANGEROUS_TARGETS.len()
    );
    println_safe!("  • Fail-safe: BPF returns allow on any error path");
    println_safe!("  • One flag lifts every guard: {}", grey("--force-this"));
    println_safe!();
    println_safe!("{}", brand_bold("Examples:"));
    // NIGHT-hunt-15: the command blocks above each carry their own
    // examples (NIGHT-improve-5) — this section holds ONLY the three
    // workflows whose blocks have no example lines, so every example
    // appears exactly once on the surface. Same annotated-pair format
    // as the group blocks (NIGHT-boost-4), at the section's own
    // two-space indent. NIGHT-hunt-35: the 'u --all' pair died here —
    // improve-54 had already given the sweep its Pro mode example,
    // and one command teaches exactly once (the no-duplicate law
    // restored after the merge drifted past it).
    println_safe!("  # Check what's limited (JSON for scripts)");
    println_safe!(
        "  {}",
        ok("sudo zelynic status --print-json | jq '.limits[]'")
    );
    println_safe!();
    println_safe!("  # Recover from a crash (clean orphaned pins)");
    println_safe!("  {}", ok("sudo zelynic recover"));
    println_safe!();
    println_safe!("  # Rescue a terminal broken by a kill -9 TUI death");
    println_safe!("  {}", ok("zelynic --reset-terminal"));
}

/// One runnable example: the `#` annotation on its own line ABOVE,
/// the command line in status green below (NIGHT-boost-4 owner
/// mandate — the old right-side comments misaligned across examples
/// and read as visual noise; the pair format is enforced here so it
/// cannot drift per section).
pub(crate) fn example(note: &str, cmd: &str) {
    println_safe!("    # {note}");
    println_safe!("    {}", ok(cmd));
}

/// One command synopsis: the usage line in calm grey (NIGHT-hunt-35,
/// the owner's eye-strain call — the white usage lines strained;
/// grammar is context, not content, the same tier law the eagle-eyes
/// footer rides). One helper so every verb's synopsis carries the
/// same indent and the same tier, and the `[flags — see Pro mode]`
/// pointer token rides the same law on every flag-owning verb —
/// the synopsis teaches the grammar and points, Pro mode owns every
/// flag's spelling.
fn synopsis(line: &str) {
    println_safe!("  {}", grey(line));
}
