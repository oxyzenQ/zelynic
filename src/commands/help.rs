// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Help text for `zelynic --help-all`.

use crate::output::brand_bold;

/// Print comprehensive help with all commands and examples.
///
/// Brand identity (cosmostrix help format): the banner and every section
/// heading render in brand purple #A855F7 (bold); all command syntax,
/// examples, and body text stay in the terminal default color so the
/// reference remains readable and diff-friendly when piped.
pub(crate) fn print_help_all() {
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
    println_safe!();
    println_safe!("{}", brand_bold("Global flags:"));
    println_safe!("  -V, --version    Version and build information");
    println_safe!("  --check-update   Check the latest upstream GitHub release");
    println_safe!("  -v, --verbose    Debug output");
    println_safe!("  --print-json     JSON output (where applicable)");
    println_safe!("  --help-all       This comprehensive reference");
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
