// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
// LOC_EXEMPT: the dispatch match is one surface by design — every command's ebpf/dormant cfg dance lives in its arm; the persistence pair's arms pushed the cohesive unit over the 500 cap (the split precedents moved handlers OUT, and they already are)

//! Command handlers for zelynic CLI (Cosmic Dragon Architecture — pure eBPF).

#[cfg(feature = "ebpf")]
pub(crate) mod block;
// The safety blocklist is pure data (no eBPF dependency) — always
// compiled so --help can count it in every build. The rate and
// strict handler modules are eBPF-only surfaces.
#[cfg(feature = "ebpf")]
pub(crate) mod cleanup;
#[cfg(feature = "ebpf")]
pub(crate) mod eagle;
pub(crate) mod guarantee;
pub(crate) mod help;
#[cfg(feature = "ebpf")]
pub(crate) mod list_apps;
#[cfg(feature = "ebpf")]
pub(crate) mod monitor;
#[cfg(feature = "ebpf")]
pub(crate) mod persist;
// night-during's LOC-cap split: the snapshot/restore verbs moved out
// of persist.rs when the --during fields crossed the 500-line cap.
#[cfg(feature = "ebpf")]
pub(crate) mod persist_run;
#[cfg(feature = "ebpf")]
pub(crate) mod probe;
#[cfg(feature = "ebpf")]
pub(crate) mod probe_report;
#[cfg(feature = "ebpf")]
pub(crate) mod probe_role;
#[cfg(feature = "ebpf")]
pub(crate) mod rates;
// NIGHT-dinner-11: recover split from cleanup (the LOC-cap push —
// crash repair is a different concern from user-initiated removal).
#[cfg(feature = "ebpf")]
pub(crate) mod recover;
pub(crate) mod safety;
#[cfg(feature = "ebpf")]
pub(crate) mod strict;
// night-during's LOC-cap split: the strict-all handler moved out of
// strict.rs when the --during threading crossed the 500-line cap.
#[cfg(feature = "ebpf")]
pub(crate) mod strict_all;

#[cfg(not(feature = "ebpf"))]
use anyhow::Result;
#[cfg(feature = "ebpf")]
use anyhow::Result;

use crate::cli::{Cli, Commands};

#[cfg(feature = "ebpf")]
use crate::ebpf::pin::unpin_all;

/// Legacy PID file (kept for cleanup of old installations).
#[cfg(feature = "ebpf")]
const PID_FILE: &str = "/tmp/zelynic.pid";

// ── The apply-verb success epilogue (NIGHT-improve-28) ──────────────
//
// The owner's verbosity audit: the apply verbs (strict-single and its
// siblings) answered with a two-line report that restated the request
// ("Limiting 'cg:48181' to 10.0 KB/s + 10.0 KB/s (2 policies, active
// in background)") before the follow-up line. The pro contract is the
// affirmative-verdict grammar: a green "OK." (the #50FA7B tier that
// affirmative verdicts already own) plus the follow-up commands in
// the runnable-example green tier — the same "this is what you type"
// color the --help examples render in (NIGHT-boost-4). The request
// echo lives in the shell history, the enforced facts (rates, policy
// counts) live in 'zelynic status', and the success surface stays
// one glance.
//
// The follow-up must ROUND-TRIP: each caller passes the exact unstrict
// form that reverses what it applied. The former shared suggestion
// was wrong advice on two shapes — 'zelynic unstrict brave:curl'
// does not split colon lists (unstrict-single takes one target), and
// 'zelynic unstrict 3 apps' is not a target at all — so the multi and
// all verbs now suggest 'unstrict-multi <list>' / 'unstrict-all'.

/// The pure line builder behind the apply-verb epilogue (pinned in
/// test/cli/apply_epilogue_tests.rs): line 1 is the affirmative
/// verdict, line 2 the follow-up with both runnable commands wrapped
/// in the green tier. Pure so the exact wording — including the
/// 'or' the owner specced — is a contract, not an accident.
#[cfg(feature = "ebpf")]
#[must_use]
pub(crate) fn apply_success_lines(unstrict_cmd: &str, action: &str) -> [String; 2] {
    [
        crate::output::ok("OK."),
        format!(
            "Run '{}' to {action}, or '{}' to check.",
            crate::output::ok(unstrict_cmd),
            crate::output::ok("zelynic status")
        ),
    ]
}

/// Print the apply-verb success epilogue (NIGHT-improve-28): green
/// "OK." on its own line, then the follow-up commands in green —
/// `action` names what the unstrict form does ("remove" for the
/// strict family, "restore access" for the block family).
#[cfg(feature = "ebpf")]
pub(crate) fn apply_success_epilogue(unstrict_cmd: &str, action: &str) {
    for line in apply_success_lines(unstrict_cmd, action) {
        eprintln_safe!("{line}");
    }
}

/// Shared root guard — one clean branded error instead of the old
/// double print (a plain "requires root" line followed by a second
/// duplicated "root required" error from the anyhow path).
///
/// The tip line renders white via the line-aware error renderer.
/// ebpf-gated: every caller is an eBPF-surface command handler.
#[cfg(feature = "ebpf")]
pub(crate) fn ensure_root() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "root required — eBPF operations need CAP_BPF\n  \
             tip: re-run with sudo"
        ))
    }
}

// ── The no-match hard-error contract (NIGHT-dinner-11) ──────────────
//
// The owner's eBPF-verifier lineage mandate, applied to the CLI
// surface: a target that resolves to nothing is REJECTED, never
// soft-exited. The old paths printed a plain stderr line
// ("No cgroup found for 'cg8401'. Nothing to limit.") and returned
// Ok — exit 0 — so a typo'd target was indistinguishable from an
// enforced limit to every script (and to a skimming human: the
// owner's own transcript showed `ss cg8401` reading as calm
// success). The kernel's verifier rejects a program it cannot
// prove instead of loading it half-working; the CLI now holds the
// same line: a command that NAMES a target must find it, or fail.
//
// Every conversion below returns `Err` on purpose — main's single
// exit-adjacent renderer paints the branded block (bold red
// `error:` label, red body, white `tip:` lines — green when the tip
// quotes a command to run, NIGHT-dinner-12) and exits 1.
// The one carve-out: `unstrict-all` on an already-clean system
// keeps its exit 0 — the requested state already holds, the same
// clean-state precedent `recover`'s clean path owns.

/// The discovery tip every no-match error carries: the live-target
/// surface (one command away from the correct spelling).
#[cfg(feature = "ebpf")]
pub(crate) const TIP_LIST_APPS: &str = "try 'zelynic list-apps' to see live targets";

/// The state tip the unstrict family's no-match errors carry: the
/// surface that lists what is actually limited.
#[cfg(feature = "ebpf")]
pub(crate) const TIP_STATUS: &str = "try 'zelynic status' to see active limits";

/// Build the anyhow payload for a no-match refusal (NIGHT-dinner-11):
/// `head` carries the verdict, every tip rides its own indented
/// `tip:` line — the shape the line-aware labeled renderer paints
/// (bold red label, red body, white tips; a tip that quotes a command
/// like 'zelynic list-apps' renders green — NIGHT-dinner-12, the
/// "this is what you type" tier) before exit 1. Pure, so
/// the exact contract is pinned rootlessly in
/// test/cli/no_match_tests.rs.
#[cfg(feature = "ebpf")]
pub(crate) fn target_no_match_error(head: String, tips: &[String]) -> anyhow::Error {
    let mut msg = head;
    for tip in tips {
        msg.push_str("\n  tip: ");
        msg.push_str(tip);
    }
    anyhow::anyhow!("{msg}")
}

/// Shared error for commands compiled without the `ebpf` feature:
/// a single actionable message instead of the old eprintln + Err pair,
/// which printed the failure twice. Since NIGHT-ask-2 made `ebpf` the
/// default, this path is the explicit opt-out (`--no-default-features`)
/// — the message names both ways out: the default crate (full build)
/// and the source rebuild. The wording keeps the two substrings the
/// integration test pins (test/integration/privilege.rs: "eBPF not
/// compiled" + "cargo build --features ebpf").
#[cfg(not(feature = "ebpf"))]
fn ebpf_disabled() -> Result<()> {
    Err(anyhow::anyhow!(
        "eBPF not compiled into this build (built with --no-default-features)\n  \
         tip: cargo install zelynic ships the full build, or rebuild from \
         source with 'cargo build --features ebpf'"
    ))
}

/// Top-level CLI dispatch.
pub(crate) fn dispatch(cli: Cli) -> Result<()> {
    // NIGHT-boost-24: --print-json riding a non-JSON surface is a
    // silent no-op no more — one stderr note names the surfaces that
    // honor it. Dispatch-level, so every arm (including the
    // no-subcommand help fallback) is covered exactly once; the JSON
    // surfaces themselves pass the gate silently.
    if cli.print_json && !crate::cli::command_honors_print_json(cli.command.as_ref()) {
        crate::cli::warn_print_json_ignored();
    }
    match cli.command {
        Some(Commands::StrictSingle {
            target,
            rate,
            download,
            upload,
            force_this,
            no_probe,
            per_socket,
            floor,
            ceil,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_single(
                    &target,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    force_this,
                    no_probe,
                    per_socket,
                    floor.as_deref(),
                    ceil.as_deref(),
                    during.as_deref(),
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                // per_socket joins the tuple with the other payload
                // fields: the dormant-mode build destructures every
                // strict-single flag here so -D warnings never sees an
                // unused binding (the CI build leg's -D warnings ride
                // the no-default-features leg; the field is read only
                // on the ebpf side, so the dormant arm silences it).
                let _ = (
                    target,
                    rate,
                    download,
                    upload,
                    force_this,
                    no_probe,
                    per_socket,
                    floor,
                    ceil,
                    during,
                    cli.verbose,
                );
                ebpf_disabled()
            }
        }

        Some(Commands::StrictMulti {
            targets,
            rate,
            download,
            upload,
            force_this,
            floor,
            ceil,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict::handle_strict_multi(
                    &targets,
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    force_this,
                    floor.as_deref(),
                    ceil.as_deref(),
                    during.as_deref(),
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    targets,
                    rate,
                    download,
                    upload,
                    force_this,
                    floor,
                    ceil,
                    during,
                    cli.verbose,
                );
                ebpf_disabled()
            }
        }

        Some(Commands::StrictAll {
            rate,
            download,
            upload,
            force_this,
            floor,
            ceil,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                strict_all::handle_strict_all(
                    rate.as_deref(),
                    download.as_deref(),
                    upload.as_deref(),
                    force_this,
                    floor.as_deref(),
                    ceil.as_deref(),
                    during.as_deref(),
                    cli.verbose,
                )
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (
                    rate,
                    download,
                    upload,
                    force_this,
                    floor,
                    ceil,
                    during,
                    cli.verbose,
                );
                ebpf_disabled()
            }
        }

        Some(Commands::BlockSingle {
            target,
            force_this,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_single(&target, force_this, during.as_deref(), cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, force_this, during, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::BlockMulti {
            targets,
            force_this,
            during,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_multi(&targets, force_this, during.as_deref(), cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, force_this, during, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::BlockAll { force_this, during }) => {
            #[cfg(feature = "ebpf")]
            {
                block::handle_block_all(force_this, during.as_deref(), cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (force_this, during, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::Unstrict { target }) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict(&target, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::UnstrictMulti { targets }) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict_multi(&targets, cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::UnstrictAll) => {
            #[cfg(feature = "ebpf")]
            {
                cleanup::handle_unstrict_all(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::Recover) => {
            #[cfg(feature = "ebpf")]
            {
                recover::handle_recover(cli.verbose)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::Snapshot) => {
            #[cfg(feature = "ebpf")]
            {
                persist_run::handle_snapshot(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::Restore) => {
            #[cfg(feature = "ebpf")]
            {
                persist_run::handle_restore(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::Status) => {
            #[cfg(feature = "ebpf")]
            {
                monitor::handle_status(cli.verbose, cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::ListApps) => {
            #[cfg(feature = "ebpf")]
            {
                list_apps::handle_list_apps(cli.print_json)
            }
            #[cfg(not(feature = "ebpf"))]
            {
                ebpf_disabled()
            }
        }

        Some(Commands::EagleEyes {
            targets,
            interval,
            focus,
            depth,
        }) => {
            #[cfg(feature = "ebpf")]
            {
                if depth {
                    // The one-shot mode has no refresh loop: the
                    // live-only cadence flag answers with the same
                    // honesty the --print-json ignored-note carries —
                    // one stderr line, stdout and exit codes
                    // untouched (NIGHT-master-1).
                    if interval.is_some() {
                        eprintln_safe!(
                            "{}",
                            crate::output::warn_bold(
                                "--interval ignored (--depth prints one report and exits)"
                            )
                        );
                    }
                    eagle::handle_eagle_eyes_depth(
                        targets.as_deref(),
                        focus.as_deref(),
                        cli.print_json,
                        cli.verbose,
                    )
                } else {
                    // NIGHT-private-research-3: the mirror image of
                    // the --interval note above — --focus is the
                    // one-shot report's traffic window, and the live
                    // monitor needs no window (its frames ARE one).
                    // One stderr note, stdout and exit codes
                    // untouched (the ignored-note contract).
                    if focus.is_some() {
                        eprintln_safe!(
                            "{}",
                            crate::output::warn_bold(
                                "--focus ignored (the live monitor is already continuous — it owns --depth's traffic-window job)"
                            )
                        );
                    }
                    monitor::handle_eagle_eyes(targets.as_deref(), interval.as_deref(), cli.verbose)
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (targets, interval, focus, depth, cli.verbose);
                ebpf_disabled()
            }
        }

        Some(Commands::Doctor) => crate::capabilities::run_doctor(cli.print_json),

        // NIGHT-upgrade-charger-core-1-b: the enforcement probe's hidden child
        // roles — spawned by the probe orchestrator, never typed by hand.
        #[cfg(feature = "ebpf")]
        Some(Commands::ProbeServer { port, mode }) => probe_role::run_server_role(port, &mode),
        #[cfg(not(feature = "ebpf"))]
        Some(Commands::ProbeServer { .. }) => ebpf_disabled(),
        #[cfg(feature = "ebpf")]
        Some(Commands::ProbeClient { addr, mode, secs }) => {
            probe_role::run_client_role(&addr, &mode, secs)
        }
        #[cfg(not(feature = "ebpf"))]
        Some(Commands::ProbeClient { .. }) => ebpf_disabled(),

        None => {
            // No subcommand: print the end-to-end reference — the same
            // single help surface as `zelynic --help`, written through
            // the broken-pipe-safe stdout path (exit 0).
            help::print_help();
            Ok(())
        }
    }
}

// ━━ Command handlers (ebpf feature) ━━

/// Remove ALL BPF pin files + directory. Full cleanup.
/// Delegates to `limiter::unpin_all()` which iterates the pin directory
/// and removes every file, then removes the directory. Also removes the
/// legacy PID file if present.
#[cfg(feature = "ebpf")]
pub(crate) fn unpin_all_bpf() -> Result<()> {
    unpin_all()?;
    // Remove legacy PID file if present (from old serve-child versions).
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}

// NIGHT-improve-28: the apply-verb epilogue pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// print-json scope pins in cli/mod.rs.
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/cli/apply_epilogue_tests.rs"]
mod apply_epilogue_tests;

// NIGHT-dinner-11: the no-match hard-error pins — same single-test-tree
// wiring (the shape is a contract now, not a formatting accident).
#[cfg(test)]
#[cfg(feature = "ebpf")]
#[path = "../../test/cli/no_match_tests.rs"]
mod no_match_tests;
