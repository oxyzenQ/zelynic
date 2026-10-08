// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The flag estate of the --help reference (NIGHT-hunt-39: the
//! split the 600-line no-mercy cap demanded, the cli/styles
//! precedent -- one concern, one module). Every surface that
//! documents a flag spelling lives here: Global flags, Rate
//! formats, Pro mode, and the [`flag_row`] tier-and-column law
//! they all render through. The tier law (the owner's mandate):
//! every spelling renders in the calm-grey grammar tier the
//! synopses ride -- table columns AND inline prose mentions;
//! flags are grammar. The hunt-39 peak extension (owner
//! approved) carries the same tier to the target grammar's own
//! spellings -- help.rs's target_row and its inline container
//! URIs -- so every grammar token on the reference rides one
//! grey law. The grey span covers the spelling exactly
//! (a value hint like DUR or SEC rides inside it; the padding, a
//! possessive 's, and the surrounding prose never do), so piped
//! output keeps its plain bytes. Boundaries: the runnable
//! examples stay the solid green tier (NIGHT-boost-4 -- one
//! tier, no mixed inline paint; the Pro sections' example pairs
//! render through the shared example() helper in help.rs), and
//! NO_COLOR=1 stays default (an environment variable, not a
//! flag). The geometry law: ONE description column, 19, across
//! both tables and their continuations -- hunt-35's one-column
//! claim was 18/19-mixed in the rendered truth (--interval SEC,
//! --per-socket, and --force-this sat one wide of their own
//! continuations); flag_row computes the column so it cannot
//! drift per row, and the masterclass_pins flag-tier pin holds
//! it closed.

use super::help::example;
use crate::output::{brand_bold, grey};

/// Print the flag estate: Global flags, Rate formats, and Pro
/// mode -- the reference's three spelling surfaces, in the order
/// print_help walks them (between the Short aliases table and
/// the Target formats grammar; the sections sit contiguously
/// there, which is why they split out whole). Every spelling
/// rides the grey grammar tier via flag_row; every runnable
/// example pair rides the green tier via the shared helper.
pub(crate) fn print_flag_tables() {
    println_safe!("{}", brand_bold("Global flags:"));
    // NIGHT-hunt-39: every flag table row renders through flag_row
    // — the spelling column in the grey grammar tier, the
    // description in default prose, one computed description column
    // (19) shared by both flag tables so the geometry cannot drift
    // per row.
    flag_row(
        "  ",
        "-h, --help",
        "This end-to-end reference (usage, commands, examples)",
    );
    flag_row("  ", "-V, --version", "Version and build information");
    flag_row(
        "  ",
        "--reset-terminal",
        "Emergency terminal reset: recover a screen broken by",
    );
    println_safe!("                   a kill -9 TUI death (sudo-safe, works blind-typed)");
    flag_row(
        "  ",
        "--check-update",
        "Check the latest upstream GitHub release (refuses sudo)",
    );
    flag_row(
        "  ",
        "-v, --verbose",
        "Diagnostic trace: target resolution, policy writes, BPF lifecycle",
    );
    // NIGHT-total-lts-9: the surface list ends at doctor. Restore
    // rode this line as the pair's fifth JSON surface and left with
    // the pair (NIGHT-improve-55, the total retirement); the scope
    // contract's own list (cli/scope.rs JSON_SURFACE_COMMANDS) is
    // the single truth this line mirrors — the lts-9 dragon hunt
    // found the stale continuation and closed it.
    flag_row(
        "  ",
        "--print-json",
        &format!(
            "JSON output for status, list-apps, eagle-eyes {}, doctor",
            grey("--depth")
        ),
    );
    flag_row(
        "  ",
        "--color-mode M",
        "Force color depth: 0 mono, 16, 8/256 cube, 24/32 truecolor",
    );
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
    println_safe!("  Both bounds overridable with {}", grey("--force-this"));
    // NO_COLOR=1 stays default prose: an environment variable, not
    // a flag — the tier law's one deliberate boundary (hunt-39).
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
    // NIGHT-hunt-35 (the column law, the owner's own --all find): one
    // description column for the whole Pro mode estate — the
    // --interval SEC width (flag + one space), continuations aligned
    // to it. No mixed 19/20 drift beside the 18-law lines.
    // NIGHT-hunt-39: the law is now COMPUTED — every row rides
    // flag_row — and the 18/19 wobble the comment above claimed
    // closed is closed for real: rows and continuations all sit at
    // 19 (hunt-35's literals had drifters one wide of their own
    // continuations; three rows sat one wide of the estate).
    flag_row(
        "    ",
        "--all",
        "the lane that owns every user app at once: limit",
    );
    println_safe!("                   them all, block them all, or tear every limit down.");
    println_safe!(
        "                   System apps stay behind {}'s guard by",
        grey("--force-this")
    );
    println_safe!("                   default; the target is omitted (a lone positional on");
    println_safe!(
        "                   strict is the RATE: 'zelynic s {} 500kb').",
        grey("--all")
    );
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
    flag_row(
        "    ",
        "--during DUR",
        "auto-expire: the limit tears itself down when the window",
    );
    println_safe!("                   passes. Units: s, m, h, d, mn, y — min 1s, max 10y");
    println_safe!("                   (20d = twenty days; months 30d, years 365d).");
    println_safe!("                   Duration only, one shape, no schedules.");
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
    flag_row(
        "    ",
        "--floor RATE",
        "the fair-share floor: a shaped cgroup's slice never falls",
    );
    println_safe!("                   below it while it demands traffic (a priority, not a");
    println_safe!("                   reservation — absent leaves cost nothing).");
    flag_row(
        "    ",
        "--ceil RATE",
        "the slice's hard cap, binding even a lone drawer; the",
    );
    println_safe!("                   ladder is floor <= ceil <= rate.");
    // The per-direction family: one line of pure spellings, so the
    // whole line rides the grey tier (NIGHT-hunt-39) — the
    // continuation below describes at the same column as every
    // other row's prose.
    println_safe!(
        "    {}",
        grey("--floor-download, --floor-upload, --ceil-download, --ceil-upload")
    );
    println_safe!("                   per-direction spellings, one per side: the");
    println_safe!("                   both-directions flag and its twin refuse together.");
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
    flag_row(
        "    ",
        "--per-socket",
        "cap every connection at the rate (the server shape:",
    );
    println_safe!("                   one process, many sockets).");
    flag_row(
        "    ",
        "--no-test",
        "skips the post-apply verification loop (scripted use;",
    );
    println_safe!(
        "                   the former {} spelling redirects here).",
        grey("--no-probe")
    );
    example(
        "scripted apply, no verification loop",
        "sudo zelynic s nginx 500kb --no-test",
    );
    println_safe!();
    println_safe!("  Guard override (strict family + block family):");
    flag_row(
        "    ",
        "--force-this",
        "lift every guard in one flag: the min-rate floor and the",
    );
    println_safe!("                   dangerous-target blocklist (system processes stay");
    println_safe!("                   behind it by default — lifting is a choice).");
    println_safe!();
    println_safe!("  Deep inspection (eagle-eyes):");
    flag_row(
        "    ",
        "--depth",
        "one-shot full report, no TUI: per-process census, the",
    );
    println_safe!("                   enforcement ledger, the traffic focus (JSON via");
    println_safe!("                   {}).", grey("--print-json"));
    flag_row(
        "    ",
        "--focus SEC",
        &format!(
            "the {} traffic window: 1s..30s, default 3s (one",
            grey("--depth")
        ),
    );
    println_safe!("                   stderr note when ignored on the live monitor).");
    flag_row(
        "    ",
        "--interval SEC",
        "live monitor refresh: 1s..60s, default 1s.",
    );
}

/// One flag table row (NIGHT-hunt-39, the flag tier): the spelling —
/// with its value hint when it carries one (DUR, RATE, SEC) —
/// renders in the calm-grey grammar tier the synopses ride, the
/// description in default prose; flags are grammar, wherever they
/// appear. One helper so the tier and the column cannot drift per
/// row: the description column is 19 in BOTH flag tables — the
/// longest spelling plus one space at either table's indent
/// (Global's --reset-terminal at 2, Pro mode's --interval SEC at
/// 4). Hunt-35's one-column claim was 18/19-mixed in the rendered
/// truth (--interval SEC, --per-socket, and --force-this sat one
/// wide of their own continuations); the column is computed here
/// now, not trusted to each literal's spacing — a spelling that
/// would overrun still keeps one separating space, and the
/// column pin in masterclass_pins fails the same hour. The grey
/// span covers the spelling exactly: padding and prose stay
/// default, so piped output keeps its plain bytes.
fn flag_row(indent: &str, flag: &str, desc: &str) {
    let pad = 19usize.saturating_sub(indent.len() + flag.len()).max(1);
    println_safe!("{indent}{}{}{}", grey(flag), " ".repeat(pad), desc);
}
